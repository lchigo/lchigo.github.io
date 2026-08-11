"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

if (!globalThis.crypto) Object.defineProperty(globalThis, "crypto", { value: webcrypto });
globalThis.btoa ??= (value) => Buffer.from(value, "binary").toString("base64");
globalThis.atob ??= (value) => Buffer.from(value, "base64").toString("binary");

const vault = require("./app.js");
const toolDirectory = __dirname;

const PASSWORD = "correct horse battery staple";

function randomBytes(length) {
    return webcrypto.getRandomValues(new Uint8Array(length));
}

function exactBuffer(bytes) {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function fakeCredential(rawId, prf, transports = ["internal"]) {
    return {
        type: "public-key",
        rawId: exactBuffer(rawId),
        response: { getTransports: () => [...transports] },
        getClientExtensionResults: () => ({ prf })
    };
}

async function makeFixture() {
    const vaultIdBytes = randomBytes(16);
    const vaultId = vault.encodeBase64Url(vaultIdBytes);
    vaultIdBytes.fill(0);
    const dekBytes = randomBytes(32);
    const dekKey = await vault.importVaultDek(dekBytes, webcrypto);
    const passwordSlot = await vault.createPasswordUnlockSlot(PASSWORD, dekBytes, vaultId, webcrypto);
    const prfInput = randomBytes(32);
    const prfOutput = randomBytes(32);
    const credentialIdBytes = randomBytes(32);
    const credential = {
        credentialId: vault.encodeBase64Url(credentialIdBytes),
        rpId: "example.test",
        transports: ["internal"]
    };
    credentialIdBytes.fill(0);
    const prfSlot = await vault.createPrfUnlockSlot(
        credential,
        prfOutput,
        prfInput,
        dekBytes,
        vaultId,
        webcrypto
    );
    const slots = [passwordSlot, prfSlot];
    const plaintext = JSON.stringify({ schema: 2, accounts: [] });
    const payload = await vault.encryptVaultPayload(plaintext, dekKey, 1, vaultId, slots, webcrypto);
    const record = vault.buildVaultRecord(vaultId, 1, payload, slots);
    return { record, dekBytes, dekKey, prfInput, prfOutput, plaintext, prfSlot };
}

function clearFixture(fixture) {
    fixture.dekBytes.fill(0);
    fixture.prfInput.fill(0);
    fixture.prfOutput.fill(0);
}

test("v2 password and WebAuthn PRF slots unlock the same payload", async () => {
    const fixture = await makeFixture();
    try {
        const byPassword = await vault.decryptVaultRecord(fixture.record, PASSWORD, webcrypto);
        const byPrf = await vault.decryptVaultRecordWithPrf(
            fixture.record,
            fixture.prfSlot.slotId,
            fixture.prfOutput,
            webcrypto
        );
        assert.equal(byPassword.plaintext, fixture.plaintext);
        assert.equal(byPrf.plaintext, fixture.plaintext);
        assert.deepEqual(byPassword.dekBytes, fixture.dekBytes);
        assert.deepEqual(byPrf.dekBytes, fixture.dekBytes);
        assert.equal(byPassword.key.extractable, false);
        assert.equal(byPrf.key.extractable, false);
        byPassword.dekBytes.fill(0);
        byPrf.dekBytes.fill(0);
        const persisted = JSON.stringify(fixture.record);
        assert.equal(persisted.includes(PASSWORD), false);
        assert.equal(persisted.includes(vault.encodeBase64Url(fixture.prfOutput)), false);
        assert.equal(persisted.includes(vault.encodeBase64Url(fixture.dekBytes)), false);
    } finally {
        clearFixture(fixture);
    }
});

test("wrong password, wrong PRF and authenticated metadata tampering are rejected", async () => {
    const fixture = await makeFixture();
    try {
        const wrongPrf = new Uint8Array(fixture.prfOutput);
        wrongPrf[0] ^= 0xff;
        await assert.rejects(vault.decryptVaultRecord(fixture.record, "wrong password with enough length", webcrypto));
        await assert.rejects(vault.decryptVaultRecordWithPrf(
            fixture.record,
            fixture.prfSlot.slotId,
            wrongPrf,
            webcrypto
        ));
        wrongPrf.fill(0);

        const tamperedCredential = structuredClone(fixture.record);
        const credentialBytes = vault.decodeBase64Url(tamperedCredential.unlockSlots[1].credentialId);
        credentialBytes[0] ^= 0x01;
        tamperedCredential.unlockSlots[1].credentialId = vault.encodeBase64Url(credentialBytes);
        credentialBytes.fill(0);
        await assert.rejects(vault.decryptVaultRecord(tamperedCredential, PASSWORD, webcrypto));

        const tamperedRevision = structuredClone(fixture.record);
        tamperedRevision.recordRevision += 1;
        await assert.rejects(vault.decryptVaultRecord(tamperedRevision, PASSWORD, webcrypto));

        const tamperedCiphertext = structuredClone(fixture.record);
        const ciphertext = vault.decodeBase64Url(tamperedCiphertext.payload.ciphertext);
        ciphertext[0] ^= 0x01;
        tamperedCiphertext.payload.ciphertext = vault.encodeBase64Url(ciphertext);
        ciphertext.fill(0);
        await assert.rejects(vault.decryptVaultRecord(tamperedCiphertext, PASSWORD, webcrypto));

        const removedSlot = structuredClone(fixture.record);
        removedSlot.unlockSlots.pop();
        await assert.rejects(vault.decryptVaultRecord(removedSlot, PASSWORD, webcrypto));

        const reorderedSlots = structuredClone(fixture.record);
        reorderedSlots.unlockSlots.reverse();
        await assert.rejects(vault.decryptVaultRecord(reorderedSlots, PASSWORD, webcrypto));

        const unknownField = structuredClone(fixture.record);
        unknownField.unbound = true;
        assert.throws(() => vault.validateVaultRecord(unknownField), /未知或缺失字段/);
    } finally {
        clearFixture(fixture);
    }
});

test("payload revisions use fresh IVs while wrapped DEK slots remain unchanged", async () => {
    const fixture = await makeFixture();
    try {
        const slotsSnapshot = structuredClone(fixture.record.unlockSlots);
        const payload = await vault.encryptVaultPayload(
            fixture.plaintext,
            fixture.dekKey,
            2,
            fixture.record.vaultId,
            fixture.record.unlockSlots,
            webcrypto
        );
        const updated = vault.buildVaultRecord(
            fixture.record.vaultId,
            2,
            payload,
            fixture.record.unlockSlots
        );
        assert.notEqual(updated.payload.cipher.iv, fixture.record.payload.cipher.iv);
        assert.deepEqual(updated.unlockSlots, slotsSnapshot);
        const byPassword = await vault.decryptVaultRecord(updated, PASSWORD, webcrypto);
        const byPrf = await vault.decryptVaultRecordWithPrf(updated, fixture.prfSlot.slotId, fixture.prfOutput, webcrypto);
        assert.equal(byPassword.plaintext, fixture.plaintext);
        assert.equal(byPrf.plaintext, fixture.plaintext);
        byPassword.dekBytes.fill(0);
        byPrf.dekBytes.fill(0);
    } finally {
        clearFixture(fixture);
    }
});

test("v1 records are rejected instead of migrated", () => {
    assert.throws(() => vault.validateVaultRecord({
        format: vault.VAULT_FORMAT,
        version: 1,
        recordRevision: 1
    }), /不支持的加密存储版本/);
});

test("TOTP and Google Authenticator migration parsing still pass known vectors", async () => {
    const secret = new TextEncoder().encode("12345678901234567890");
    const result = await vault.generateTotp(secret, 59000, {
        algorithm: "SHA1",
        digits: 8,
        period: 30
    }, webcrypto);
    secret.fill(0);
    assert.equal(result.code, "94287082");

    const base64 = "CioKCkhlbGxvId6tvu8SDUV4YW1wbGU6YWxpY2UaB0V4YW1wbGUgASgBMAIQARgBIAAoAQ==";
    const bytes = Buffer.from(base64, "base64");
    const versionTag = bytes.lastIndexOf(Buffer.from([0x10, 0x01, 0x18, 0x01]));
    assert.notEqual(versionTag, -1);
    bytes[versionTag + 1] = 0x02;
    const uri = `otpauth-migration://offline?data=${encodeURIComponent(bytes.toString("base64"))}`;
    const migration = vault.parseMigrationUri(uri);
    assert.equal(migration.version, 2);
    assert.equal(migration.accounts.length, 1);
    assert.equal(migration.accounts[0].secret, "JBSWY3DPEHPK3PXP");
    bytes.fill(0);
});

test("HTML wiring keeps every required DOM id and the strict CSP", () => {
    const html = fs.readFileSync(path.join(toolDirectory, "index.html"), "utf8");
    const app = fs.readFileSync(path.join(toolDirectory, "app.js"), "utf8");
    const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]));
    const referencedIds = [...app.matchAll(/getElementById\("([^"]+)"\)/g)].map((match) => match[1]);
    assert.deepEqual(referencedIds.filter((id) => !ids.has(id)), []);
    const csp = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)?.[1] || "";
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /script-src 'self'/);
    assert.match(csp, /connect-src 'none'/);
    assert.match(csp, /require-trusted-types-for 'script'/);
    assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|https?:/);
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i);
    assert.match(html, /id="vault-password"[^>]*autocomplete="off"[^>]*readonly/);
    assert.doesNotMatch(html, /vault-confirm/);
    assert.doesNotMatch(app, /current-password|new-password|vaultConfirm/);
});

test("PRF registration accepts enabled output and builds strict options", async () => {
    const rawId = randomBytes(32);
    const prfInput = randomBytes(32);
    const prfOutput = randomBytes(32);
    let captured;
    const navigatorSource = {
        credentials: {
            create: async (options) => {
                captured = options;
                return fakeCredential(rawId, { enabled: true, results: { first: exactBuffer(prfOutput) } });
            }
        }
    };
    const result = await vault.registerWebAuthnPrf({
        rpId: "example.test",
        prfInput
    }, navigatorSource, webcrypto);
    try {
        assert.equal(result.credentialId, vault.encodeBase64Url(rawId));
        assert.deepEqual(result.prfOutput, prfOutput);
        assert.equal(captured.publicKey.rp.id, "example.test");
        assert.equal(captured.publicKey.attestation, "none");
        assert.equal(captured.publicKey.authenticatorSelection.userVerification, "required");
        assert.equal(captured.publicKey.authenticatorSelection.residentKey, "preferred");
        assert.equal(captured.publicKey.extensions.prf.eval.first, prfInput);
    } finally {
        rawId.fill(0);
        prfInput.fill(0);
        prfOutput.fill(0);
        result.prfOutput.fill(0);
    }
});

test("PRF registration falls back to assertion and rejects mismatched credentials", async () => {
    const rawId = randomBytes(32);
    const otherRawId = randomBytes(32);
    const prfInput = randomBytes(32);
    const prfOutput = randomBytes(32);
    let getCalls = 0;
    const navigatorSource = {
        credentials: {
            create: async () => fakeCredential(rawId, { enabled: true }),
            get: async () => {
                getCalls += 1;
                return fakeCredential(rawId, { results: { first: exactBuffer(prfOutput) } });
            }
        }
    };
    const result = await vault.registerWebAuthnPrf({ rpId: "example.test", prfInput }, navigatorSource, webcrypto);
    assert.equal(getCalls, 1);
    result.prfOutput.fill(0);

    navigatorSource.credentials.get = async () => fakeCredential(otherRawId, {
        results: { first: exactBuffer(prfOutput) }
    });
    await assert.rejects(vault.evaluateWebAuthnPrf({
        rpId: "example.test",
        credentialId: vault.encodeBase64Url(rawId),
        transports: ["internal"],
        prfInput
    }, navigatorSource, webcrypto), /非预期/);

    rawId.fill(0);
    otherRawId.fill(0);
    prfInput.fill(0);
    prfOutput.fill(0);
});

test("PRF adapter rejects disabled, short and aborted results", async () => {
    const rawId = randomBytes(32);
    const prfInput = randomBytes(32);
    const shortOutput = randomBytes(31);
    const disabledNavigator = {
        credentials: {
            create: async () => fakeCredential(rawId, { enabled: false })
        }
    };
    await assert.rejects(vault.registerWebAuthnPrf({
        rpId: "example.test",
        prfInput
    }, disabledNavigator, webcrypto), /不支持 WebAuthn PRF/);

    const shortNavigator = {
        credentials: {
            get: async () => fakeCredential(rawId, { results: { first: exactBuffer(shortOutput) } })
        }
    };
    await assert.rejects(vault.evaluateWebAuthnPrf({
        rpId: "example.test",
        credentialId: vault.encodeBase64Url(rawId),
        prfInput
    }, shortNavigator, webcrypto), /长度无效/);

    const controller = new AbortController();
    const abortingNavigator = {
        credentials: {
            get: ({ signal }) => new Promise((resolve, reject) => {
                signal.addEventListener("abort", () => {
                    const error = new Error("Aborted");
                    error.name = "AbortError";
                    reject(error);
                }, { once: true });
            })
        }
    };
    const pending = vault.evaluateWebAuthnPrf({
        rpId: "example.test",
        credentialId: vault.encodeBase64Url(rawId),
        prfInput,
        signal: controller.signal
    }, abortingNavigator, webcrypto);
    controller.abort();
    await assert.rejects(pending, { name: "AbortError" });

    const ignoredController = new AbortController();
    const ignoredSignalNavigator = {
        credentials: {
            get: async () => {
                ignoredController.abort();
                return fakeCredential(rawId, { results: { first: exactBuffer(randomBytes(32)) } });
            }
        }
    };
    await assert.rejects(vault.evaluateWebAuthnPrf({
        rpId: "example.test",
        credentialId: vault.encodeBase64Url(rawId),
        prfInput,
        signal: ignoredController.signal
    }, ignoredSignalNavigator, webcrypto), { name: "AbortError" });

    const registrationController = new AbortController();
    let fallbackCalls = 0;
    const ignoredCreateSignalNavigator = {
        credentials: {
            create: async () => {
                registrationController.abort();
                return fakeCredential(rawId, { enabled: true });
            },
            get: async () => {
                fallbackCalls += 1;
                return fakeCredential(rawId, { results: { first: exactBuffer(randomBytes(32)) } });
            }
        }
    };
    await assert.rejects(vault.registerWebAuthnPrf({
        rpId: "example.test",
        prfInput,
        signal: registrationController.signal
    }, ignoredCreateSignalNavigator, webcrypto), { name: "AbortError" });
    assert.equal(fallbackCalls, 0);

    rawId.fill(0);
    prfInput.fill(0);
    shortOutput.fill(0);
});
