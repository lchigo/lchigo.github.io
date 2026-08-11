"use strict";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const DEFAULT_ALGORITHM = "SHA1";
const DEFAULT_DIGITS = 6;
const DEFAULT_PERIOD = 30;
const MIN_PERIOD = 1;
const MAX_PERIOD = 300;
const MAX_SECRET_INPUT_LENGTH = 4096;
const MAX_MIGRATION_URI_LENGTH = 200000;
const MAX_MIGRATION_BYTES = 128 * 1024;
const MAX_MIGRATION_ACCOUNTS = 500;
const MAX_IMPORTED_ACCOUNTS = 200;
const MAX_PENDING_MIGRATION_BATCHES = 4;
const MAX_QR_IMAGE_FILES = 50;
const MAX_QR_IMAGE_FILE_BYTES = 20 * 1024 * 1024;
const MAX_QR_SOURCE_DIMENSION = 16384;
const MAX_QR_SOURCE_PIXELS = 64 * 1024 * 1024;
const MAX_QR_SCAN_DIMENSION = 1400;
const VAULT_FORMAT = "lchigo.google-auth-2fa.vault";
const VAULT_VERSION = 2;
const VAULT_PAYLOAD_VERSION = 2;
const VAULT_DB_NAME = "lchigo-google-auth-2fa";
const VAULT_DB_VERSION = 2;
const VAULT_STORE_NAME = "vaults";
const VAULT_RECORD_KEY = "primary";
const VAULT_KDF_ITERATIONS = 600000;
const VAULT_ID_BYTES = 16;
const VAULT_SLOT_ID_BYTES = 16;
const VAULT_SALT_BYTES = 16;
const VAULT_PRF_INPUT_BYTES = 32;
const VAULT_HKDF_SALT_BYTES = 32;
const VAULT_DEK_BYTES = 32;
const VAULT_IV_BYTES = 12;
const VAULT_TAG_BITS = 128;
const VAULT_WRAPPED_DEK_BYTES = VAULT_DEK_BYTES + (VAULT_TAG_BITS / 8);
const VAULT_KEY_BITS = 256;
const VAULT_PRF_INFO = "lchigo.google-auth-2fa.prf-kek.v2";
const VAULT_PASSWORD_SLOT = "password";
const VAULT_PRF_SLOT = "webauthn-prf";
const MAX_VAULT_UNLOCK_SLOTS = 2;
const MAX_CREDENTIAL_ID_BYTES = 1024;
const WEBAUTHN_CHALLENGE_BYTES = 32;
const WEBAUTHN_USER_ID_BYTES = 32;
const WEBAUTHN_TIMEOUT_MS = 60000;
const WEBAUTHN_TRANSPORTS = new Set(["ble", "hybrid", "internal", "nfc", "smart-card", "usb"]);
const MIN_VAULT_PASSWORD_CHARACTERS = 12;
const MAX_VAULT_PASSWORD_CHARACTERS = 256;
const MAX_VAULT_CIPHERTEXT_BYTES = 2 * 1024 * 1024;
const MAX_VAULT_PLAINTEXT_BYTES = 1536 * 1024;
const MAX_VAULT_RECORD_SNAPSHOT_CHARACTERS = 4 * 1024 * 1024;
const QR_IMAGE_TYPES = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);
const ALGORITHMS = Object.freeze({
    SHA1: "SHA-1",
    SHA256: "SHA-256",
    SHA512: "SHA-512"
});

function normalizeAlgorithm(value) {
    const normalized = String(value || "").toUpperCase().replace(/-/g, "");
    if (!Object.prototype.hasOwnProperty.call(ALGORITHMS, normalized)) {
        throw new Error("算法仅支持 SHA-1、SHA-256 或 SHA-512");
    }
    return normalized;
}

function validateDigits(value) {
    const normalized = typeof value === "number" ? String(value) : String(value || "");
    if (normalized !== "6" && normalized !== "8") throw new Error("验证码位数只能是 6 或 8");
    return Number(normalized);
}

function validatePeriod(value) {
    const normalized = typeof value === "number" ? String(value) : String(value || "");
    if (!/^\d+$/.test(normalized)) throw new Error("验证码周期必须是整数秒");
    const period = Number(normalized);
    if (!Number.isSafeInteger(period) || period < MIN_PERIOD || period > MAX_PERIOD) {
        throw new Error(`验证码周期必须在 ${MIN_PERIOD}–${MAX_PERIOD} 秒之间`);
    }
    return period;
}

function normalizeBase32(input) {
    if (typeof input !== "string") throw new TypeError("Base32 密钥必须是字符串");
    if (input.length > MAX_SECRET_INPUT_LENGTH) throw new Error("密钥或 URI 过长");

    const compact = input.trim().toUpperCase().replace(/[\s-]/g, "");
    if (!compact) throw new Error("请输入 Base32 密钥");

    const match = /^([A-Z2-7]+)(=*)$/.exec(compact);
    if (!match) throw new Error("Base32 密钥包含无效字符");

    const core = match[1];
    const padding = match[2].length;
    const remainder = core.length % 8;
    const expectedPadding = new Map([[0, 0], [2, 6], [4, 4], [5, 3], [7, 1]]);
    if (!expectedPadding.has(remainder)) throw new Error("Base32 密钥长度无效");
    if (padding > 0 && (padding !== expectedPadding.get(remainder) || compact.length % 8 !== 0)) {
        throw new Error("Base32 填充格式无效");
    }
    return core;
}

function decodeBase32(input) {
    const normalized = normalizeBase32(input);
    const output = [];
    let buffer = 0;
    let bits = 0;

    for (const character of normalized) {
        const value = BASE32_ALPHABET.indexOf(character);
        buffer = (buffer << 5) | value;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            output.push((buffer >>> bits) & 0xff);
            buffer &= bits === 0 ? 0 : (1 << bits) - 1;
        }
    }

    if (bits > 0 && buffer !== 0) throw new Error("Base32 末尾填充位不是规范的零值");
    if (output.length === 0) throw new Error("Base32 密钥为空");
    return Uint8Array.from(output);
}

function encodeBase32(bytes, includePadding = false) {
    if (!(bytes instanceof Uint8Array)) throw new TypeError("待编码密钥必须是 Uint8Array");
    if (bytes.length === 0) return "";

    let output = "";
    let buffer = 0;
    let bits = 0;
    for (const byte of bytes) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            output += BASE32_ALPHABET[(buffer >>> bits) & 31];
            buffer &= bits === 0 ? 0 : (1 << bits) - 1;
        }
    }
    if (bits > 0) output += BASE32_ALPHABET[(buffer << (5 - bits)) & 31];
    if (includePadding) output += "=".repeat((8 - (output.length % 8)) % 8);
    return output;
}

function getSingleQueryParameter(searchParams, name) {
    const values = searchParams.getAll(name);
    if (values.length > 1) throw new Error(`otpauth URI 中存在重复的 ${name} 参数`);
    return values.length === 1 ? values[0] : null;
}

function decodeOtpLabel(pathname) {
    const encodedLabel = pathname.replace(/^\/+/, "");
    if (!encodedLabel) return { issuer: "", account: "" };
    let label;
    try {
        label = decodeURIComponent(encodedLabel);
    } catch {
        throw new Error("otpauth URI 的账号标签编码无效");
    }
    const separator = label.indexOf(":");
    if (separator < 0) return { issuer: "", account: label.trim() };
    return {
        issuer: label.slice(0, separator).trim(),
        account: label.slice(separator + 1).trim()
    };
}

function parseOtpAuthUri(input) {
    if (typeof input !== "string" || input.length > MAX_SECRET_INPUT_LENGTH) {
        throw new Error("otpauth URI 为空或过长");
    }

    let uri;
    try {
        uri = new URL(input.trim());
    } catch {
        throw new Error("otpauth URI 格式无效");
    }
    if (uri.protocol.toLowerCase() !== "otpauth:") throw new Error("仅支持 otpauth:// URI");
    if (uri.hostname.toLowerCase() !== "totp") throw new Error("仅支持基于时间的 TOTP，不支持 HOTP");
    if (uri.username || uri.password || uri.port || uri.hash) {
        throw new Error("otpauth URI 包含不允许的凭据、端口或片段");
    }

    const secretValue = getSingleQueryParameter(uri.searchParams, "secret");
    if (!secretValue) throw new Error("otpauth URI 缺少 secret 参数");
    const secret = normalizeBase32(secretValue);

    const algorithmValue = getSingleQueryParameter(uri.searchParams, "algorithm");
    const digitsValue = getSingleQueryParameter(uri.searchParams, "digits");
    const periodValue = getSingleQueryParameter(uri.searchParams, "period");
    const issuerValue = getSingleQueryParameter(uri.searchParams, "issuer");
    const label = decodeOtpLabel(uri.pathname);
    const issuer = (issuerValue || label.issuer || "").trim();
    const issuerMismatch = Boolean(issuerValue && label.issuer && issuerValue.trim() !== label.issuer);

    return {
        secret,
        algorithm: normalizeAlgorithm(algorithmValue === null ? DEFAULT_ALGORITHM : algorithmValue),
        digits: validateDigits(digitsValue === null ? DEFAULT_DIGITS : digitsValue),
        period: validatePeriod(periodValue === null ? DEFAULT_PERIOD : periodValue),
        issuer,
        account: label.account,
        issuerMismatch
    };
}

function counterToBytes(counter) {
    let value;
    try {
        value = BigInt(counter);
    } catch {
        throw new Error("TOTP 计数器无效");
    }
    if (value < 0n || value > 0xffffffffffffffffn) throw new Error("TOTP 计数器超出 64 位范围");

    const bytes = new Uint8Array(8);
    for (let index = bytes.length - 1; index >= 0; index -= 1) {
        bytes[index] = Number(value & 0xffn);
        value >>= 8n;
    }
    return bytes;
}

function getTimeWindow(timestampMs, periodValue) {
    if (!Number.isFinite(timestampMs) || timestampMs < 0) throw new Error("时间戳无效");
    const period = validatePeriod(periodValue);
    const seconds = timestampMs / 1000;
    const counterNumber = Math.floor(seconds / period);
    if (!Number.isSafeInteger(counterNumber)) throw new Error("TOTP 时间计数器超出安全范围");
    const elapsed = seconds - counterNumber * period;
    return {
        counter: BigInt(counterNumber),
        elapsed,
        remaining: Math.max(0, period - elapsed),
        period
    };
}

async function generateTotp(secretBytes, timestampMs, options = {}, cryptoSource = globalThis.crypto) {
    if (!(secretBytes instanceof Uint8Array) || secretBytes.length === 0) throw new Error("TOTP 密钥为空");
    if (!cryptoSource?.subtle) throw new Error("当前浏览器不支持 Web Crypto API");

    const algorithm = normalizeAlgorithm(options.algorithm ?? DEFAULT_ALGORITHM);
    const digits = validateDigits(options.digits ?? DEFAULT_DIGITS);
    const period = validatePeriod(options.period ?? DEFAULT_PERIOD);
    const window = getTimeWindow(timestampMs, period);
    const key = await cryptoSource.subtle.importKey(
        "raw",
        secretBytes,
        { name: "HMAC", hash: { name: ALGORITHMS[algorithm] } },
        false,
        ["sign"]
    );
    const digest = new Uint8Array(await cryptoSource.subtle.sign(
        "HMAC",
        key,
        counterToBytes(window.counter)
    ));
    const offset = digest[digest.length - 1] & 0x0f;
    if (offset + 3 >= digest.length) throw new Error("HMAC 截断位置无效");
    const binary = ((digest[offset] & 0x7f) * 0x1000000)
        + ((digest[offset + 1] & 0xff) << 16)
        + ((digest[offset + 2] & 0xff) << 8)
        + (digest[offset + 3] & 0xff);
    const code = String(binary % (10 ** digits)).padStart(digits, "0");
    return { code, counter: window.counter, algorithm, digits, period };
}

function formatCode(code) {
    if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
    if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
    return code;
}

function encodeBase64Url(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new TypeError("待编码数据必须是 Uint8Array");
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(input, { expectedLength = null, minLength = 1, maxLength = MAX_VAULT_CIPHERTEXT_BYTES } = {}) {
    if (typeof input !== "string" || input.length === 0 || input.length > Math.ceil(maxLength * 4 / 3) + 4) {
        throw new Error("加密存储包含无效的 Base64URL 数据");
    }
    if (!/^[A-Za-z0-9_-]+$/.test(input) || input.length % 4 === 1) {
        throw new Error("加密存储的 Base64URL 格式无效");
    }
    const standard = input.replace(/-/g, "+").replace(/_/g, "/");
    let binary;
    try {
        binary = atob(standard + "=".repeat((4 - (standard.length % 4)) % 4));
    } catch {
        throw new Error("加密存储的 Base64URL 数据无法解码");
    }
    if (binary.length < minLength || binary.length > maxLength || (expectedLength !== null && binary.length !== expectedLength)) {
        throw new Error("加密存储的数据长度无效");
    }
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    if (encodeBase64Url(bytes) !== input) {
        bytes.fill(0);
        throw new Error("加密存储的 Base64URL 编码不规范");
    }
    return bytes;
}

function normalizeVaultPassword(password) {
    if (typeof password !== "string") throw new TypeError("主密码必须是字符串");
    const normalized = password.normalize("NFC");
    const length = Array.from(normalized).length;
    if (length < MIN_VAULT_PASSWORD_CHARACTERS) {
        throw new Error(`主密码至少需要 ${MIN_VAULT_PASSWORD_CHARACTERS} 个字符`);
    }
    if (length > MAX_VAULT_PASSWORD_CHARACTERS) throw new Error("主密码过长");
    return normalized;
}

function getBoundUnlockSlot(slot) {
    const binding = {
        slotId: slot.slotId,
        type: slot.type,
        wrap: {
            name: slot.wrap.name,
            keyLength: slot.wrap.keyLength,
            iv: slot.wrap.iv,
            tagLength: slot.wrap.tagLength,
            ciphertext: slot.wrap.ciphertext
        }
    };
    if (slot.type === VAULT_PASSWORD_SLOT) {
        binding.kdf = {
            name: slot.kdf.name,
            hash: slot.kdf.hash,
            iterations: slot.kdf.iterations,
            salt: slot.kdf.salt
        };
    } else {
        binding.credentialId = slot.credentialId;
        binding.rpId = slot.rpId;
        binding.transports = [...slot.transports];
        binding.prf = { input: slot.prf.input };
        binding.kdf = {
            name: slot.kdf.name,
            hash: slot.kdf.hash,
            salt: slot.kdf.salt,
            info: slot.kdf.info
        };
    }
    return binding;
}

function getPayloadAdditionalData(recordRevision, vaultId, payload, unlockSlots) {
    return new TextEncoder().encode(JSON.stringify({
        format: VAULT_FORMAT,
        version: VAULT_VERSION,
        vaultId,
        recordRevision,
        purpose: "accounts-payload",
        schema: payload.schema,
        cipher: {
            name: payload.cipher.name,
            keyLength: payload.cipher.keyLength,
            iv: payload.cipher.iv,
            tagLength: payload.cipher.tagLength
        },
        unlockSlots: unlockSlots.map(getBoundUnlockSlot)
    }));
}

function getUnlockSlotAdditionalData(vaultId, slot) {
    const data = {
        format: VAULT_FORMAT,
        version: VAULT_VERSION,
        vaultId,
        purpose: "wrap-dek",
        slotId: slot.slotId,
        type: slot.type,
        wrap: {
            name: slot.wrap.name,
            keyLength: slot.wrap.keyLength,
            iv: slot.wrap.iv,
            tagLength: slot.wrap.tagLength
        }
    };
    if (slot.type === VAULT_PASSWORD_SLOT) {
        data.kdf = {
            name: slot.kdf.name,
            hash: slot.kdf.hash,
            iterations: slot.kdf.iterations,
            salt: slot.kdf.salt
        };
    } else {
        data.credentialId = slot.credentialId;
        data.rpId = slot.rpId;
        data.prf = { input: slot.prf.input };
        data.kdf = {
            name: slot.kdf.name,
            hash: slot.kdf.hash,
            salt: slot.kdf.salt,
            info: slot.kdf.info
        };
    }
    return new TextEncoder().encode(JSON.stringify(data));
}

function assertExactObjectKeys(value, expectedKeys, label) {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label}格式无效`);
    const actual = Object.keys(value).sort();
    const expected = [...expectedKeys].sort();
    if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
        throw new Error(`${label}包含未知或缺失字段`);
    }
}

function isValidVaultRpId(value) {
    if (typeof value !== "string" || value.length < 1 || value.length > 253) return false;
    const labels = value.split(".");
    return labels.every((label) => label.length >= 1 && label.length <= 63
        && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

function validateAesGcmDescriptor(value) {
    if (!value || value.name !== "AES-GCM" || value.keyLength !== VAULT_KEY_BITS || value.tagLength !== VAULT_TAG_BITS) {
        throw new Error("加密存储的 AES-GCM 参数无效");
    }
}

function clearValidatedVaultRecord(decoded) {
    if (!decoded) return;
    decoded.vaultId?.fill(0);
    decoded.payload?.iv?.fill(0);
    decoded.payload?.ciphertext?.fill(0);
    for (const slot of decoded.slots || []) {
        slot.slotId?.fill(0);
        slot.kdfSalt?.fill(0);
        slot.wrapIv?.fill(0);
        slot.wrappedDek?.fill(0);
        slot.credentialId?.fill(0);
        slot.prfInput?.fill(0);
    }
}

function validateVaultRecord(record) {
    if (!record || typeof record !== "object" || Array.isArray(record)) throw new Error("加密存储记录格式无效");
    if (record.format !== VAULT_FORMAT || record.version !== VAULT_VERSION) throw new Error("不支持的加密存储版本");
    assertExactObjectKeys(record, ["format", "version", "vaultId", "recordRevision", "payload", "unlockSlots"], "加密存储记录");
    if (!Number.isSafeInteger(record.recordRevision) || record.recordRevision < 1) throw new Error("加密存储修订号无效");
    if (!record.payload || record.payload.schema !== VAULT_PAYLOAD_VERSION || !record.payload.cipher) {
        throw new Error("加密存储载荷格式无效");
    }
    assertExactObjectKeys(record.payload, ["schema", "cipher", "ciphertext"], "加密存储载荷");
    assertExactObjectKeys(record.payload.cipher, ["name", "keyLength", "iv", "tagLength"], "加密存储载荷算法");
    validateAesGcmDescriptor(record.payload.cipher);
    if (!Array.isArray(record.unlockSlots) || record.unlockSlots.length < 1 || record.unlockSlots.length > MAX_VAULT_UNLOCK_SLOTS) {
        throw new Error("加密存储解锁方式数量无效");
    }

    const decoded = { vaultId: null, payload: null, slots: [] };
    const slotIds = new Set();
    const credentialIds = new Set();
    let passwordSlots = 0;
    try {
        decoded.vaultId = decodeBase64Url(record.vaultId, { expectedLength: VAULT_ID_BYTES, maxLength: VAULT_ID_BYTES });
        decoded.payload = {
            iv: decodeBase64Url(record.payload.cipher.iv, { expectedLength: VAULT_IV_BYTES, maxLength: VAULT_IV_BYTES }),
            ciphertext: decodeBase64Url(record.payload.ciphertext, {
                minLength: VAULT_TAG_BITS / 8,
                maxLength: MAX_VAULT_CIPHERTEXT_BYTES
            })
        };
        for (const slot of record.unlockSlots) {
            if (!slot || typeof slot !== "object" || Array.isArray(slot) || slotIds.has(slot.slotId)) {
                throw new Error("加密存储解锁方式格式无效");
            }
            if (slot.type === VAULT_PASSWORD_SLOT) {
                assertExactObjectKeys(slot, ["slotId", "type", "kdf", "wrap"], "主密码解锁方式");
                assertExactObjectKeys(slot.kdf, ["name", "hash", "iterations", "salt"], "主密码派生参数");
            } else if (slot.type === VAULT_PRF_SLOT) {
                assertExactObjectKeys(slot, ["slotId", "type", "credentialId", "rpId", "transports", "prf", "kdf", "wrap"], "通行密钥解锁方式");
                assertExactObjectKeys(slot.prf, ["input"], "通行密钥 PRF 参数");
                assertExactObjectKeys(slot.kdf, ["name", "hash", "salt", "info"], "通行密钥派生参数");
            } else {
                throw new Error("不支持的加密存储解锁方式");
            }
            assertExactObjectKeys(slot.wrap, ["name", "keyLength", "iv", "tagLength", "ciphertext"], "数据密钥包装参数");
            validateAesGcmDescriptor(slot.wrap);
            const decodedSlot = {
                slot,
                slotId: decodeBase64Url(slot.slotId, { expectedLength: VAULT_SLOT_ID_BYTES, maxLength: VAULT_SLOT_ID_BYTES }),
                kdfSalt: null,
                wrapIv: decodeBase64Url(slot.wrap.iv, { expectedLength: VAULT_IV_BYTES, maxLength: VAULT_IV_BYTES }),
                wrappedDek: decodeBase64Url(slot.wrap.ciphertext, {
                    expectedLength: VAULT_WRAPPED_DEK_BYTES,
                    maxLength: VAULT_WRAPPED_DEK_BYTES
                }),
                credentialId: null,
                prfInput: null
            };
            decoded.slots.push(decodedSlot);
            slotIds.add(slot.slotId);
            if (slot.type === VAULT_PASSWORD_SLOT) {
                passwordSlots += 1;
                if (!slot.kdf || slot.kdf.name !== "PBKDF2" || slot.kdf.hash !== "SHA-256"
                    || slot.kdf.iterations !== VAULT_KDF_ITERATIONS) {
                    throw new Error("主密码密钥派生参数无效");
                }
                decodedSlot.kdfSalt = decodeBase64Url(slot.kdf.salt, {
                    expectedLength: VAULT_SALT_BYTES,
                    maxLength: VAULT_SALT_BYTES
                });
            } else if (slot.type === VAULT_PRF_SLOT) {
                if (!isValidVaultRpId(slot.rpId)) {
                    throw new Error("通行密钥 RP ID 无效");
                }
                if (!slot.prf || !slot.kdf || slot.kdf.name !== "HKDF" || slot.kdf.hash !== "SHA-256"
                    || slot.kdf.info !== VAULT_PRF_INFO) {
                    throw new Error("通行密钥派生参数无效");
                }
                if (!Array.isArray(slot.transports) || slot.transports.length > WEBAUTHN_TRANSPORTS.size
                    || new Set(slot.transports).size !== slot.transports.length
                    || slot.transports.some((item) => !WEBAUTHN_TRANSPORTS.has(item))) {
                    throw new Error("通行密钥传输提示无效");
                }
                if (credentialIds.has(slot.credentialId)) throw new Error("加密存储包含重复通行密钥");
                credentialIds.add(slot.credentialId);
                decodedSlot.credentialId = decodeBase64Url(slot.credentialId, {
                    minLength: 1,
                    maxLength: MAX_CREDENTIAL_ID_BYTES
                });
                decodedSlot.prfInput = decodeBase64Url(slot.prf.input, {
                    expectedLength: VAULT_PRF_INPUT_BYTES,
                    maxLength: VAULT_PRF_INPUT_BYTES
                });
                decodedSlot.kdfSalt = decodeBase64Url(slot.kdf.salt, {
                    expectedLength: VAULT_HKDF_SALT_BYTES,
                    maxLength: VAULT_HKDF_SALT_BYTES
                });
            }
        }
        if (passwordSlots !== 1) throw new Error("加密存储必须保留一个主密码恢复方式");
        return decoded;
    } catch (error) {
        clearValidatedVaultRecord(decoded);
        throw error;
    }
}

async function derivePasswordKek(password, salt, cryptoSource = globalThis.crypto) {
    if (!(salt instanceof Uint8Array) || salt.length !== VAULT_SALT_BYTES) throw new Error("加密存储盐值无效");
    if (!cryptoSource?.subtle) throw new Error("当前浏览器不支持 Web Crypto API");
    const normalizedPassword = normalizeVaultPassword(password);
    const passwordBytes = new TextEncoder().encode(normalizedPassword);
    try {
        const baseKey = await cryptoSource.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveKey"]);
        return await cryptoSource.subtle.deriveKey(
            { name: "PBKDF2", hash: "SHA-256", salt, iterations: VAULT_KDF_ITERATIONS },
            baseKey,
            { name: "AES-GCM", length: VAULT_KEY_BITS },
            false,
            ["encrypt", "decrypt"]
        );
    } finally {
        passwordBytes.fill(0);
    }
}

async function derivePrfKek(prfOutput, salt, cryptoSource = globalThis.crypto) {
    if (!(prfOutput instanceof Uint8Array) || prfOutput.length !== VAULT_PRF_INPUT_BYTES) throw new Error("通行密钥 PRF 输出无效");
    if (!(salt instanceof Uint8Array) || salt.length !== VAULT_HKDF_SALT_BYTES) throw new Error("通行密钥派生盐值无效");
    if (!cryptoSource?.subtle) throw new Error("当前浏览器不支持 Web Crypto API");
    const info = new TextEncoder().encode(VAULT_PRF_INFO);
    try {
        const baseKey = await cryptoSource.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
        return await cryptoSource.subtle.deriveKey(
            { name: "HKDF", hash: "SHA-256", salt, info },
            baseKey,
            { name: "AES-GCM", length: VAULT_KEY_BITS },
            false,
            ["encrypt", "decrypt"]
        );
    } finally {
        info.fill(0);
    }
}

async function importVaultDek(dekBytes, cryptoSource = globalThis.crypto) {
    if (!(dekBytes instanceof Uint8Array) || dekBytes.length !== VAULT_DEK_BYTES) throw new Error("保险库数据密钥无效");
    if (!cryptoSource?.subtle) throw new Error("当前浏览器不支持 Web Crypto API");
    return cryptoSource.subtle.importKey("raw", dekBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptVaultPayload(plaintext, key, recordRevision, vaultId, unlockSlots, cryptoSource = globalThis.crypto) {
    if (typeof plaintext !== "string") throw new TypeError("加密存储载荷必须是字符串");
    if (!Number.isSafeInteger(recordRevision) || recordRevision < 1) throw new Error("加密存储修订号无效");
    if (!cryptoSource?.subtle || !cryptoSource?.getRandomValues) throw new Error("当前浏览器不支持安全加密存储");
    const vaultIdBytes = decodeBase64Url(vaultId, { expectedLength: VAULT_ID_BYTES, maxLength: VAULT_ID_BYTES });
    vaultIdBytes.fill(0);

    const plaintextBytes = new TextEncoder().encode(plaintext);
    if (plaintextBytes.length > MAX_VAULT_PLAINTEXT_BYTES) {
        plaintextBytes.fill(0);
        throw new Error("账户数据超过加密存储容量限制");
    }
    const iv = cryptoSource.getRandomValues(new Uint8Array(VAULT_IV_BYTES));
    const payload = {
        schema: VAULT_PAYLOAD_VERSION,
        cipher: {
            name: "AES-GCM",
            keyLength: VAULT_KEY_BITS,
            iv: encodeBase64Url(iv),
            tagLength: VAULT_TAG_BITS
        },
        ciphertext: ""
    };
    const additionalData = getPayloadAdditionalData(recordRevision, vaultId, payload, unlockSlots);
    try {
        const encrypted = new Uint8Array(await cryptoSource.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData, tagLength: VAULT_TAG_BITS },
            key,
            plaintextBytes
        ));
        try {
            payload.ciphertext = encodeBase64Url(encrypted);
            return payload;
        } finally {
            encrypted.fill(0);
        }
    } finally {
        plaintextBytes.fill(0);
        additionalData.fill(0);
        iv.fill(0);
    }
}

async function encryptWrappedDek(dekBytes, key, vaultId, slot, cryptoSource = globalThis.crypto) {
    if (!(dekBytes instanceof Uint8Array) || dekBytes.length !== VAULT_DEK_BYTES) throw new Error("保险库数据密钥无效");
    const iv = decodeBase64Url(slot.wrap.iv, { expectedLength: VAULT_IV_BYTES, maxLength: VAULT_IV_BYTES });
    const additionalData = getUnlockSlotAdditionalData(vaultId, slot);
    try {
        const encrypted = new Uint8Array(await cryptoSource.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData, tagLength: VAULT_TAG_BITS },
            key,
            dekBytes
        ));
        try {
            if (encrypted.length !== VAULT_WRAPPED_DEK_BYTES) throw new Error("保险库数据密钥包装长度无效");
            return encodeBase64Url(encrypted);
        } finally {
            encrypted.fill(0);
        }
    } finally {
        iv.fill(0);
        additionalData.fill(0);
    }
}

async function decryptWrappedDek(record, decodedSlot, key, cryptoSource = globalThis.crypto) {
    const additionalData = getUnlockSlotAdditionalData(record.vaultId, decodedSlot.slot);
    let decrypted = null;
    try {
        decrypted = new Uint8Array(await cryptoSource.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: decodedSlot.wrapIv,
                additionalData,
                tagLength: VAULT_TAG_BITS
            },
            key,
            decodedSlot.wrappedDek
        ));
        if (decrypted.length !== VAULT_DEK_BYTES) throw new Error("保险库数据密钥长度无效");
        return decrypted;
    } catch (error) {
        decrypted?.fill(0);
        throw error;
    } finally {
        additionalData.fill(0);
    }
}

async function createPasswordUnlockSlot(password, dekBytes, vaultId, cryptoSource = globalThis.crypto) {
    const salt = cryptoSource.getRandomValues(new Uint8Array(VAULT_SALT_BYTES));
    const slotId = cryptoSource.getRandomValues(new Uint8Array(VAULT_SLOT_ID_BYTES));
    const iv = cryptoSource.getRandomValues(new Uint8Array(VAULT_IV_BYTES));
    const slot = {
        slotId: encodeBase64Url(slotId),
        type: VAULT_PASSWORD_SLOT,
        kdf: {
            name: "PBKDF2",
            hash: "SHA-256",
            iterations: VAULT_KDF_ITERATIONS,
            salt: encodeBase64Url(salt)
        },
        wrap: {
            name: "AES-GCM",
            keyLength: VAULT_KEY_BITS,
            iv: encodeBase64Url(iv),
            tagLength: VAULT_TAG_BITS,
            ciphertext: ""
        }
    };
    try {
        const key = await derivePasswordKek(password, salt, cryptoSource);
        slot.wrap.ciphertext = await encryptWrappedDek(dekBytes, key, vaultId, slot, cryptoSource);
        return slot;
    } finally {
        salt.fill(0);
        slotId.fill(0);
        iv.fill(0);
    }
}

async function createPrfUnlockSlot(credential, prfOutput, prfInput, dekBytes, vaultId, cryptoSource = globalThis.crypto) {
    if (!credential || typeof credential.credentialId !== "string" || typeof credential.rpId !== "string") {
        throw new Error("通行密钥凭据信息无效");
    }
    if (!(prfInput instanceof Uint8Array) || prfInput.length !== VAULT_PRF_INPUT_BYTES) throw new Error("通行密钥 PRF 输入无效");
    const kdfSalt = cryptoSource.getRandomValues(new Uint8Array(VAULT_HKDF_SALT_BYTES));
    const slotId = cryptoSource.getRandomValues(new Uint8Array(VAULT_SLOT_ID_BYTES));
    const iv = cryptoSource.getRandomValues(new Uint8Array(VAULT_IV_BYTES));
    const transports = [...new Set(credential.transports || [])].filter((item) => WEBAUTHN_TRANSPORTS.has(item)).sort();
    const slot = {
        slotId: encodeBase64Url(slotId),
        type: VAULT_PRF_SLOT,
        credentialId: credential.credentialId,
        rpId: credential.rpId,
        transports,
        prf: { input: encodeBase64Url(prfInput) },
        kdf: {
            name: "HKDF",
            hash: "SHA-256",
            salt: encodeBase64Url(kdfSalt),
            info: VAULT_PRF_INFO
        },
        wrap: {
            name: "AES-GCM",
            keyLength: VAULT_KEY_BITS,
            iv: encodeBase64Url(iv),
            tagLength: VAULT_TAG_BITS,
            ciphertext: ""
        }
    };
    try {
        const key = await derivePrfKek(prfOutput, kdfSalt, cryptoSource);
        slot.wrap.ciphertext = await encryptWrappedDek(dekBytes, key, vaultId, slot, cryptoSource);
        return slot;
    } finally {
        kdfSalt.fill(0);
        slotId.fill(0);
        iv.fill(0);
    }
}

async function decryptVaultPayload(record, key, validated = null, cryptoSource = globalThis.crypto) {
    const decoded = validated || validateVaultRecord(record);
    const additionalData = getPayloadAdditionalData(record.recordRevision, record.vaultId, record.payload, record.unlockSlots);
    let plaintextBytes = null;
    try {
        plaintextBytes = new Uint8Array(await cryptoSource.subtle.decrypt(
            { name: "AES-GCM", iv: decoded.payload.iv, additionalData, tagLength: VAULT_TAG_BITS },
            key,
            decoded.payload.ciphertext
        ));
        if (plaintextBytes.length > MAX_VAULT_PLAINTEXT_BYTES) throw new Error("解密后的账户数据超过容量限制");
        return new TextDecoder("utf-8", { fatal: true }).decode(plaintextBytes);
    } finally {
        additionalData.fill(0);
        plaintextBytes?.fill(0);
        if (!validated) clearValidatedVaultRecord(decoded);
    }
}

async function decryptVaultRecord(record, password, cryptoSource = globalThis.crypto) {
    const decoded = validateVaultRecord(record);
    let dekBytes = null;
    let adopted = false;
    try {
        const passwordSlot = decoded.slots.find((item) => item.slot.type === VAULT_PASSWORD_SLOT);
        const key = await derivePasswordKek(password, passwordSlot.kdfSalt, cryptoSource);
        dekBytes = await decryptWrappedDek(record, passwordSlot, key, cryptoSource);
        const dekKey = await importVaultDek(dekBytes, cryptoSource);
        const plaintext = await decryptVaultPayload(record, dekKey, decoded, cryptoSource);
        adopted = true;
        return { plaintext, key: dekKey, dekBytes, recordRevision: record.recordRevision };
    } finally {
        if (!adopted) dekBytes?.fill(0);
        clearValidatedVaultRecord(decoded);
    }
}

async function decryptVaultRecordWithPrf(record, slotId, prfOutput, cryptoSource = globalThis.crypto) {
    const decoded = validateVaultRecord(record);
    let dekBytes = null;
    let adopted = false;
    try {
        const prfSlot = decoded.slots.find((item) => item.slot.type === VAULT_PRF_SLOT && item.slot.slotId === slotId);
        if (!prfSlot) throw new Error("通行密钥解锁方式不存在");
        const key = await derivePrfKek(prfOutput, prfSlot.kdfSalt, cryptoSource);
        dekBytes = await decryptWrappedDek(record, prfSlot, key, cryptoSource);
        const dekKey = await importVaultDek(dekBytes, cryptoSource);
        const plaintext = await decryptVaultPayload(record, dekKey, decoded, cryptoSource);
        adopted = true;
        return { plaintext, key: dekKey, dekBytes, recordRevision: record.recordRevision };
    } finally {
        if (!adopted) dekBytes?.fill(0);
        clearValidatedVaultRecord(decoded);
    }
}

function buildVaultRecord(vaultId, recordRevision, payload, unlockSlots) {
    return {
        format: VAULT_FORMAT,
        version: VAULT_VERSION,
        vaultId,
        recordRevision,
        payload,
        unlockSlots: [...unlockSlots]
    };
}

function createPrfError(message, code) {
    const error = new Error(message);
    error.code = code;
    return error;
}

function throwIfWebAuthnAborted(signal) {
    if (!signal?.aborted) return;
    if (typeof signal.throwIfAborted === "function") signal.throwIfAborted();
    const error = new Error("通行密钥操作已取消");
    error.name = "AbortError";
    throw error;
}

function copyWebAuthnBytes(value, label) {
    let view;
    if (value instanceof ArrayBuffer) {
        view = new Uint8Array(value);
    } else if (ArrayBuffer.isView(value)) {
        view = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    } else {
        throw createPrfError(`${label}格式无效`, "PRF_INVALID_RESULT");
    }
    return new Uint8Array(view);
}

function getWebAuthnCredentialId(credential) {
    if (!credential || credential.type !== "public-key") {
        throw createPrfError("浏览器没有返回有效的通行密钥凭据", "PRF_INVALID_RESULT");
    }
    const rawId = copyWebAuthnBytes(credential.rawId, "通行密钥 ID");
    try {
        if (rawId.length < 1 || rawId.length > MAX_CREDENTIAL_ID_BYTES) {
            throw createPrfError("通行密钥 ID 长度无效", "PRF_INVALID_RESULT");
        }
        return encodeBase64Url(rawId);
    } finally {
        rawId.fill(0);
    }
}

function extractWebAuthnPrfOutput(credential, { expectedCredentialId, requireEnabled = false, allowMissing = false } = {}) {
    const credentialId = getWebAuthnCredentialId(credential);
    if (expectedCredentialId && credentialId !== expectedCredentialId) {
        throw createPrfError("浏览器返回了非预期的通行密钥", "PRF_CREDENTIAL_MISMATCH");
    }
    if (typeof credential.getClientExtensionResults !== "function") {
        throw createPrfError("浏览器未返回 WebAuthn 扩展结果", "PRF_UNSUPPORTED");
    }
    const prf = credential.getClientExtensionResults()?.prf;
    if (requireEnabled && prf?.enabled !== true) {
        throw createPrfError("当前通行密钥不支持 WebAuthn PRF", "PRF_UNSUPPORTED");
    }
    if (prf?.results?.first === undefined) {
        if (allowMissing) return null;
        throw createPrfError("通行密钥没有返回 PRF 结果", "PRF_INVALID_RESULT");
    }
    const output = copyWebAuthnBytes(prf.results.first, "通行密钥 PRF 输出");
    if (output.length !== VAULT_PRF_INPUT_BYTES) {
        output.fill(0);
        throw createPrfError("通行密钥 PRF 输出长度无效", "PRF_INVALID_RESULT");
    }
    return output;
}

function getWebAuthnTransports(credential) {
    let values = [];
    try {
        values = credential.response?.getTransports?.() || [];
    } catch {
        values = [];
    }
    return [...new Set(values)].filter((item) => WEBAUTHN_TRANSPORTS.has(item)).sort();
}

async function evaluateWebAuthnPrf({ rpId, credentialId, transports = [], prfInput, signal }, navigatorSource = globalThis.navigator, cryptoSource = globalThis.crypto) {
    if (!navigatorSource?.credentials?.get || !cryptoSource?.getRandomValues) {
        throw createPrfError("当前浏览器不支持 WebAuthn 通行密钥", "PRF_UNSUPPORTED");
    }
    if (!(prfInput instanceof Uint8Array) || prfInput.length !== VAULT_PRF_INPUT_BYTES) {
        throw createPrfError("通行密钥 PRF 输入无效", "PRF_INVALID_INPUT");
    }
    const challenge = cryptoSource.getRandomValues(new Uint8Array(WEBAUTHN_CHALLENGE_BYTES));
    const rawCredentialId = decodeBase64Url(credentialId, { minLength: 1, maxLength: MAX_CREDENTIAL_ID_BYTES });
    const allowedTransports = [...new Set(transports)].filter((item) => WEBAUTHN_TRANSPORTS.has(item));
    const descriptor = { type: "public-key", id: rawCredentialId };
    if (allowedTransports.length > 0) descriptor.transports = allowedTransports;
    try {
        throwIfWebAuthnAborted(signal);
        const credential = await navigatorSource.credentials.get({
            publicKey: {
                challenge,
                rpId,
                allowCredentials: [descriptor],
                userVerification: "required",
                timeout: WEBAUTHN_TIMEOUT_MS,
                extensions: {
                    prf: {
                        evalByCredential: {
                            [credentialId]: { first: prfInput }
                        }
                    }
                }
            },
            signal
        });
        throwIfWebAuthnAborted(signal);
        if (!credential) throw createPrfError("通行密钥操作未返回凭据", "PRF_INVALID_RESULT");
        return {
            credentialId,
            prfOutput: extractWebAuthnPrfOutput(credential, { expectedCredentialId: credentialId })
        };
    } finally {
        challenge.fill(0);
        rawCredentialId.fill(0);
    }
}

async function registerWebAuthnPrf({ rpId, prfInput, excludeCredentialIds = [], signal }, navigatorSource = globalThis.navigator, cryptoSource = globalThis.crypto) {
    if (!navigatorSource?.credentials?.create || !cryptoSource?.getRandomValues) {
        throw createPrfError("当前浏览器不支持 WebAuthn 通行密钥", "PRF_UNSUPPORTED");
    }
    if (!(prfInput instanceof Uint8Array) || prfInput.length !== VAULT_PRF_INPUT_BYTES) {
        throw createPrfError("通行密钥 PRF 输入无效", "PRF_INVALID_INPUT");
    }
    const challenge = cryptoSource.getRandomValues(new Uint8Array(WEBAUTHN_CHALLENGE_BYTES));
    const userId = cryptoSource.getRandomValues(new Uint8Array(WEBAUTHN_USER_ID_BYTES));
    const decodedExcludeIds = [];
    let credentialCreated = false;
    try {
        throwIfWebAuthnAborted(signal);
        const excludeCredentials = excludeCredentialIds.map((credentialId) => {
            const id = decodeBase64Url(credentialId, { minLength: 1, maxLength: MAX_CREDENTIAL_ID_BYTES });
            decodedExcludeIds.push(id);
            return { type: "public-key", id };
        });
        const credential = await navigatorSource.credentials.create({
            publicKey: {
                challenge,
                rp: { id: rpId, name: "lchigo 2FA 保险库" },
                user: {
                    id: userId,
                    name: `local-vault-${encodeBase64Url(userId).slice(0, 12)}`,
                    displayName: "本机 2FA 保险库"
                },
                pubKeyCredParams: [
                    { type: "public-key", alg: -7 },
                    { type: "public-key", alg: -257 }
                ],
                timeout: WEBAUTHN_TIMEOUT_MS,
                excludeCredentials,
                authenticatorSelection: {
                    residentKey: "preferred",
                    userVerification: "required"
                },
                attestation: "none",
                extensions: { prf: { eval: { first: prfInput } } }
            },
            signal
        });
        if (!credential) throw createPrfError("通行密钥创建未返回凭据", "PRF_INVALID_RESULT");
        credentialCreated = true;
        throwIfWebAuthnAborted(signal);
        const credentialId = getWebAuthnCredentialId(credential);
        const transports = getWebAuthnTransports(credential);
        let prfOutput = extractWebAuthnPrfOutput(credential, {
            expectedCredentialId: credentialId,
            requireEnabled: true,
            allowMissing: true
        });
        if (!prfOutput) {
            throwIfWebAuthnAborted(signal);
            const assertion = await evaluateWebAuthnPrf({
                rpId,
                credentialId,
                transports,
                prfInput,
                signal
            }, navigatorSource, cryptoSource);
            prfOutput = assertion.prfOutput;
        }
        return { credentialId, rpId, transports, prfOutput };
    } catch (error) {
        if (credentialCreated && error && typeof error === "object") error.credentialMayExist = true;
        throw error;
    } finally {
        challenge.fill(0);
        userId.fill(0);
        for (const id of decodedExcludeIds) id.fill(0);
    }
}

function decodeBase64Payload(input) {
    if (typeof input !== "string" || input.length === 0) throw new Error("迁移数据为空");
    if (input.length > Math.ceil(MAX_MIGRATION_BYTES * 4 / 3) + 16) throw new Error("迁移数据过大");
    const compact = input.trim().replace(/-/g, "+").replace(/_/g, "/");
    const match = /^([A-Za-z0-9+/]*)(={0,2})$/.exec(compact);
    if (!match) throw new Error("迁移数据不是有效的 Base64");
    const core = match[1];
    const suppliedPadding = match[2].length;
    const remainder = core.length % 4;
    if (remainder === 1) throw new Error("迁移数据 Base64 长度无效");
    const requiredPadding = (4 - remainder) % 4;
    if (suppliedPadding > 0 && (suppliedPadding !== requiredPadding || compact.length % 4 !== 0)) {
        throw new Error("迁移数据 Base64 填充无效");
    }
    const padded = core + "=".repeat(requiredPadding);

    let output;
    try {
        if (typeof atob === "function") {
            const binary = atob(padded);
            output = Uint8Array.from(binary, (character) => character.charCodeAt(0));
        } else if (typeof Buffer !== "undefined") {
            output = new Uint8Array(Buffer.from(padded, "base64"));
        } else {
            throw new Error("当前环境不支持 Base64 解码");
        }
    } catch {
        throw new Error("迁移数据 Base64 解码失败");
    }
    if (output.length === 0 || output.length > MAX_MIGRATION_BYTES) throw new Error("迁移数据为空或过大");

    let canonical;
    if (typeof btoa === "function") {
        let binary = "";
        for (const byte of output) binary += String.fromCharCode(byte);
        canonical = btoa(binary);
    } else if (typeof Buffer !== "undefined") {
        canonical = Buffer.from(output).toString("base64");
    } else {
        output.fill(0);
        throw new Error("当前环境不支持 Base64 校验");
    }
    if (canonical.replace(/=+$/, "") !== core) {
        output.fill(0);
        throw new Error("迁移数据 Base64 编码不规范");
    }
    return output;
}

class ProtobufReader {
    constructor(bytes) {
        if (!(bytes instanceof Uint8Array)) throw new TypeError("protobuf 数据必须是 Uint8Array");
        this.bytes = bytes;
        this.offset = 0;
    }

    get done() {
        return this.offset >= this.bytes.length;
    }

    ensureAvailable(length) {
        if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.bytes.length) {
            throw new Error("迁移 protobuf 数据被截断");
        }
    }

    readVarint() {
        let value = 0n;
        let shift = 0n;
        for (let count = 0; count < 10; count += 1) {
            this.ensureAvailable(1);
            const byte = this.bytes[this.offset];
            this.offset += 1;
            value |= BigInt(byte & 0x7f) << shift;
            if ((byte & 0x80) === 0) {
                if (value > 0xffffffffffffffffn) throw new Error("protobuf varint 超出 64 位范围");
                return value;
            }
            shift += 7n;
        }
        throw new Error("protobuf varint 过长");
    }

    readLength() {
        const lengthValue = this.readVarint();
        if (lengthValue > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("protobuf 字段长度过大");
        const length = Number(lengthValue);
        this.ensureAvailable(length);
        return length;
    }

    readBytes() {
        const length = this.readLength();
        const value = this.bytes.slice(this.offset, this.offset + length);
        this.offset += length;
        return value;
    }

    readString() {
        const bytes = this.readBytes();
        if (bytes.length > 4096) throw new Error("迁移账户名称过长");
        try {
            return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        } catch {
            throw new Error("迁移账户名称不是有效的 UTF-8");
        }
    }

    readTag() {
        const tag = this.readVarint();
        const fieldNumber = Number(tag >> 3n);
        const wireType = Number(tag & 7n);
        if (!Number.isSafeInteger(fieldNumber) || fieldNumber <= 0 || fieldNumber > 0x1fffffff) {
            throw new Error("protobuf 字段编号无效");
        }
        return { fieldNumber, wireType };
    }

    skip(wireType) {
        if (wireType === 0) {
            this.readVarint();
            return;
        }
        if (wireType === 1) {
            this.ensureAvailable(8);
            this.offset += 8;
            return;
        }
        if (wireType === 2) {
            const length = this.readLength();
            this.offset += length;
            return;
        }
        if (wireType === 5) {
            this.ensureAvailable(4);
            this.offset += 4;
            return;
        }
        throw new Error(`不支持的 protobuf wire type：${wireType}`);
    }
}

function expectWireType(actual, expected, fieldName) {
    if (actual !== expected) throw new Error(`迁移字段 ${fieldName} 的 wire type 无效`);
}

function parseMigrationOtpParameters(bytes) {
    const reader = new ProtobufReader(bytes);
    const seenFields = new Set();
    const result = {
        secret: null,
        name: "",
        issuer: "",
        algorithm: 0,
        digits: 0,
        type: 0,
        counter: 0n
    };

    try {
        while (!reader.done) {
            const { fieldNumber, wireType } = reader.readTag();
            if (fieldNumber >= 1 && fieldNumber <= 7) {
                if (seenFields.has(fieldNumber)) throw new Error(`迁移账户字段 ${fieldNumber} 重复`);
                seenFields.add(fieldNumber);
            }
            if (fieldNumber === 1) {
                expectWireType(wireType, 2, "secret");
                result.secret = reader.readBytes();
            } else if (fieldNumber === 2) {
                expectWireType(wireType, 2, "name");
                result.name = reader.readString();
            } else if (fieldNumber === 3) {
                expectWireType(wireType, 2, "issuer");
                result.issuer = reader.readString();
            } else if (fieldNumber === 4) {
                expectWireType(wireType, 0, "algorithm");
                result.algorithm = Number(BigInt.asIntN(32, reader.readVarint()));
            } else if (fieldNumber === 5) {
                expectWireType(wireType, 0, "digits");
                result.digits = Number(BigInt.asIntN(32, reader.readVarint()));
            } else if (fieldNumber === 6) {
                expectWireType(wireType, 0, "type");
                result.type = Number(BigInt.asIntN(32, reader.readVarint()));
            } else if (fieldNumber === 7) {
                expectWireType(wireType, 0, "counter");
                result.counter = reader.readVarint();
            } else {
                reader.skip(wireType);
            }
        }
        if (!(result.secret instanceof Uint8Array) || result.secret.length === 0) {
            throw new Error("迁移账户缺少密钥");
        }
        if (result.secret.length > 128) throw new Error("迁移账户密钥过长");
        return result;
    } catch (error) {
        if (result.secret) result.secret.fill(0);
        throw error;
    }
}

function normalizeMigrationAccount(parameters) {
    const algorithmMap = new Map([[0, "SHA1"], [1, "SHA1"], [2, "SHA256"], [3, "SHA512"]]);
    const digitsMap = new Map([[0, 6], [1, 6], [2, 8]]);
    if (parameters.type === 1) return { skipped: "HOTP" };
    if (parameters.type !== 0 && parameters.type !== 2) return { skipped: "未知 OTP 类型" };
    if (!algorithmMap.has(parameters.algorithm)) {
        return { skipped: parameters.algorithm === 4 ? "MD5" : "未知算法" };
    }
    if (!digitsMap.has(parameters.digits)) return { skipped: "未知验证码位数" };

    let issuer = parameters.issuer.trim();
    let account = parameters.name.trim();
    const separator = account.indexOf(":");
    if (separator >= 0) {
        const labelIssuer = account.slice(0, separator).trim();
        const labelAccount = account.slice(separator + 1).trim();
        if (!issuer) issuer = labelIssuer;
        if (!issuer || issuer === labelIssuer) account = labelAccount;
    }
    return {
        account: {
            secret: encodeBase32(parameters.secret),
            issuer,
            account,
            algorithm: algorithmMap.get(parameters.algorithm),
            digits: digitsMap.get(parameters.digits),
            period: DEFAULT_PERIOD,
            source: "migration"
        }
    };
}

function parseMigrationPayload(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > MAX_MIGRATION_BYTES) {
        throw new Error("迁移 protobuf 数据为空或过大");
    }
    const reader = new ProtobufReader(bytes);
    const rawAccounts = [];
    let version = 0;
    let batchSize = 0;
    let batchIndex = 0;
    let batchId = 0;
    const seenMetadataFields = new Set();

    try {
        while (!reader.done) {
            const { fieldNumber, wireType } = reader.readTag();
            if (fieldNumber === 1) {
                expectWireType(wireType, 2, "otp_parameters");
                if (rawAccounts.length >= MAX_MIGRATION_ACCOUNTS) throw new Error("迁移账户数量过多");
                rawAccounts.push(parseMigrationOtpParameters(reader.readBytes()));
            } else if (fieldNumber >= 2 && fieldNumber <= 5) {
                if (seenMetadataFields.has(fieldNumber)) throw new Error(`迁移批次字段 ${fieldNumber} 重复`);
                seenMetadataFields.add(fieldNumber);
                expectWireType(wireType, 0, `batch_${fieldNumber}`);
                const value = reader.readVarint();
                const signedValue = Number(BigInt.asIntN(32, value));
                if (fieldNumber === 2) version = signedValue;
                if (fieldNumber === 3) batchSize = signedValue;
                if (fieldNumber === 4) batchIndex = signedValue;
                if (fieldNumber === 5) batchId = signedValue;
            } else {
                reader.skip(wireType);
            }
        }

        if (version !== 1 && version !== 2) throw new Error(`不支持的迁移格式版本：${version}`);
        if (batchSize < 1 || batchSize > 100) throw new Error("迁移批次数量无效");
        if (batchIndex < 0 || batchIndex >= batchSize) throw new Error("迁移批次索引无效");
        if (rawAccounts.length === 0) throw new Error("迁移二维码不包含账户");

        const accounts = [];
        const skipped = [];
        for (const parameters of rawAccounts) {
            const normalized = normalizeMigrationAccount(parameters);
            if (normalized.skipped) skipped.push(normalized.skipped);
            if (normalized.account) accounts.push(normalized.account);
        }
        return {
            accounts,
            skipped,
            sourceAccountCount: rawAccounts.length,
            version,
            batchSize,
            batchIndex,
            batchId
        };
    } finally {
        for (const parameters of rawAccounts) parameters.secret?.fill(0);
    }
}

function parseMigrationUri(input) {
    if (typeof input !== "string" || input.length === 0 || input.length > MAX_MIGRATION_URI_LENGTH) {
        throw new Error("迁移 URI 为空或过长");
    }
    const trimmed = input.trim();
    let uri;
    try {
        uri = new URL(trimmed);
    } catch {
        throw new Error("迁移 URI 格式无效");
    }
    if (uri.protocol.toLowerCase() !== "otpauth-migration:" || uri.hostname.toLowerCase() !== "offline") {
        throw new Error("仅支持 Google Authenticator 的 otpauth-migration://offline URI");
    }
    if (uri.username || uri.password || uri.port || uri.hash || (uri.pathname && uri.pathname !== "/")) {
        throw new Error("迁移 URI 包含不允许的凭据、端口、路径或片段");
    }

    const pairs = uri.search.slice(1).split("&");
    let rawData = null;
    for (const pair of pairs) {
        if (!pair) throw new Error("迁移 URI 查询参数格式无效");
        const separator = pair.indexOf("=");
        const rawName = separator < 0 ? pair : pair.slice(0, separator);
        const rawValue = separator < 0 ? "" : pair.slice(separator + 1);
        let name;
        try {
            name = decodeURIComponent(rawName);
        } catch {
            throw new Error("迁移 URI 查询参数编码无效");
        }
        if (name !== "data" || rawData !== null) throw new Error("迁移 URI 必须且只能包含一个 data 参数");
        rawData = rawValue;
    }
    if (rawData === null || rawData === "") throw new Error("迁移 URI 必须包含唯一的 data 参数");
    let data;
    try {
        data = decodeURIComponent(rawData);
    } catch {
        throw new Error("迁移 URI 的 data 参数编码无效");
    }
    const payloadFingerprint = data.trim().replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
    const bytes = decodeBase64Payload(data);
    try {
        return { ...parseMigrationPayload(bytes), payloadFingerprint };
    } finally {
        bytes.fill(0);
    }
}

function getMigrationPartFingerprint(migration) {
    if (migration.payloadFingerprint) return migration.payloadFingerprint;
    return JSON.stringify({
        version: migration.version,
        batchSize: migration.batchSize,
        batchIndex: migration.batchIndex,
        batchId: migration.batchId,
        accounts: migration.accounts,
        skipped: migration.skipped
    });
}

function stageMigrationPart(batches, migration, options = {}) {
    if (!(batches instanceof Map)) throw new TypeError("迁移批次容器必须是 Map");
    const maxPendingBatches = options.maxPendingBatches ?? MAX_PENDING_MIGRATION_BATCHES;
    const maxAccounts = options.maxAccounts ?? MAX_IMPORTED_ACCOUNTS;
    const batchKey = `${migration.version}:${migration.batchId}:${migration.batchSize}`;

    for (const existingBatch of batches.values()) {
        if (existingBatch.batchId === migration.batchId
            && (existingBatch.version !== migration.version || existingBatch.batchSize !== migration.batchSize)) {
            throw new Error("检测到相同批次 ID 但版本或批次数量冲突");
        }
    }

    let batch = batches.get(batchKey);
    const fingerprint = getMigrationPartFingerprint(migration);
    const existing = batch?.parts.get(migration.batchIndex);
    let duplicatePart = false;
    let changed = false;
    if (existing) {
        if (existing.fingerprint !== fingerprint) throw new Error(`迁移批次 ${migration.batchIndex + 1} 与已扫描内容冲突`);
        duplicatePart = true;
    } else {
        const sourceAccountCount = Number.isSafeInteger(migration.sourceAccountCount)
            ? migration.sourceAccountCount
            : migration.accounts.length + migration.skipped.length;
        let stagedAccountCount = sourceAccountCount;
        if (batch) {
            for (const part of batch.parts.values()) stagedAccountCount += part.sourceAccountCount;
        }
        if (stagedAccountCount > maxAccounts) throw new Error(`一次最多导入 ${maxAccounts} 个账户`);

        if (!batch) {
            if (batches.size >= maxPendingBatches) {
                throw new Error("未完成的迁移批次过多，请先清空账户列表后重试");
            }
            batch = {
                version: migration.version,
                batchId: migration.batchId,
                batchSize: migration.batchSize,
                parts: new Map(),
                skipped: []
            };
            batches.set(batchKey, batch);
        }
        batch.parts.set(migration.batchIndex, {
            fingerprint,
            accounts: migration.accounts,
            sourceAccountCount
        });
        batch.skipped.push(...migration.skipped);
        changed = true;
    }

    const missingIndices = [];
    for (let index = 0; index < migration.batchSize; index += 1) {
        if (!batch.parts.has(index)) missingIndices.push(index);
    }
    if (missingIndices.length > 0) {
        return {
            pending: true,
            duplicatePart,
            changed,
            progress: batch.parts.size,
            total: migration.batchSize,
            missingIndices,
            batchKey
        };
    }

    const accounts = [];
    for (let index = 0; index < migration.batchSize; index += 1) {
        accounts.push(...batch.parts.get(index).accounts);
    }
    return {
        pending: false,
        accounts,
        skipped: [...batch.skipped],
        batchKey,
        duplicatePart,
        changed
    };
}

function getQrScanRegions(widthValue, heightValue, options = {}) {
    const width = Math.floor(Number(widthValue));
    const height = Math.floor(Number(heightValue));
    if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width <= 0 || height <= 0) {
        throw new Error("二维码图片尺寸无效");
    }

    const regions = [];
    const regionKeys = new Set();
    const appendRegion = (xValue, yValue, widthValueToAdd, heightValueToAdd) => {
        const region = {
            x: Math.max(0, Math.round(xValue)),
            y: Math.max(0, Math.round(yValue)),
            width: Math.max(1, Math.round(widthValueToAdd)),
            height: Math.max(1, Math.round(heightValueToAdd))
        };
        region.width = Math.min(region.width, width - region.x);
        region.height = Math.min(region.height, height - region.y);
        if (region.width <= 0 || region.height <= 0) return;
        const key = `${region.x}:${region.y}:${region.width}:${region.height}`;
        if (regionKeys.has(key)) return;
        regionKeys.add(key);
        regions.push(region);
    };

    const full = { x: 0, y: 0, width, height };
    const squareSide = Math.min(width, height);
    const centerSquare = {
        x: Math.round((width - squareSide) / 2),
        y: Math.round((height - squareSide) / 2),
        width: squareSide,
        height: squareSide
    };
    const primaryRegions = options.preferCenter ? [centerSquare, full] : [full, centerSquare];
    for (const region of primaryRegions) appendRegion(region.x, region.y, region.width, region.height);

    if (options.extended) {
        const tileWidth = Math.max(1, Math.round(width * 0.72));
        const tileHeight = Math.max(1, Math.round(height * 0.72));
        const right = width - tileWidth;
        const bottom = height - tileHeight;
        const centerX = right / 2;
        const centerY = bottom / 2;
        appendRegion(centerX, centerY, tileWidth, tileHeight);
        appendRegion(0, 0, tileWidth, tileHeight);
        appendRegion(right, 0, tileWidth, tileHeight);
        appendRegion(0, bottom, tileWidth, tileHeight);
        appendRegion(right, bottom, tileWidth, tileHeight);
    }
    return regions;
}

function createConfirmationController({
    dialog,
    title,
    message,
    detail,
    cancelButton,
    acceptButton,
    getActiveElement = () => null
}) {
    let pending = null;
    let suppressedCloseEvents = 0;

    function resetContent() {
        title.textContent = "";
        message.textContent = "";
        detail.textContent = "";
        acceptButton.textContent = "确认";
        delete dialog.dataset.tone;
    }

    function settle(request, accepted, { restoreFocus } = {}) {
        if (!request || pending !== request || request.settled) return false;
        request.settled = true;
        pending = null;
        if (dialog.open) {
            suppressedCloseEvents += 1;
            dialog.close();
        }
        resetContent();

        const shouldRestore = restoreFocus ?? (!accepted || request.restoreFocusOnAccept);
        if (shouldRestore && request.opener?.isConnected !== false && !request.opener?.disabled) {
            request.opener?.focus?.();
        }
        request.resolve(accepted);
        return true;
    }

    function request({
        title: nextTitle,
        message: nextMessage,
        detail: nextDetail = "",
        confirmLabel = "确认",
        tone = "danger",
        opener = getActiveElement(),
        restoreFocusOnAccept = true
    }) {
        if (pending || suppressedCloseEvents > 0) return Promise.resolve(false);

        return new Promise((resolve) => {
            const current = {
                resolve,
                opener,
                restoreFocusOnAccept,
                settled: false
            };
            pending = current;
            title.textContent = String(nextTitle || "请确认操作");
            message.textContent = String(nextMessage || "是否继续？");
            detail.textContent = String(nextDetail || "");
            acceptButton.textContent = String(confirmLabel || "确认");
            dialog.dataset.tone = tone === "warning" ? "warning" : "danger";

            try {
                dialog.showModal();
                cancelButton.focus();
            } catch {
                settle(current, false, { restoreFocus: true });
            }
        });
    }

    function cancelPending({ restoreFocus = false } = {}) {
        return settle(pending, false, { restoreFocus });
    }

    cancelButton.addEventListener("click", () => settle(pending, false));
    acceptButton.addEventListener("click", () => settle(pending, true));
    dialog.addEventListener("cancel", (event) => {
        event.preventDefault();
        settle(pending, false);
    });
    dialog.addEventListener("close", () => {
        if (suppressedCloseEvents > 0) {
            suppressedCloseEvents -= 1;
            return;
        }
        settle(pending, false);
    });

    return {
        request,
        cancelPending,
        hasPending: () => Boolean(pending)
    };
}

function buildOtpAuthUri(input) {
    const secret = normalizeBase32(String(input?.secret || ""));
    if (!secret || !/^[A-Z2-7]+=*$/.test(secret)) {
        throw new Error("账户密钥不是有效的 Base32 内容。");
    }

    const issuer = String(input?.issuer || "").trim();
    const account = String(input?.account || "").trim();
    const algorithm = String(input?.algorithm || DEFAULT_ALGORITHM)
        .replace(/-/g, "")
        .toUpperCase();
    const digits = Number(input?.digits ?? DEFAULT_DIGITS);
    const period = Number(input?.period ?? DEFAULT_PERIOD);

    if (!["SHA1", "SHA256", "SHA512"].includes(algorithm)) {
        throw new Error("账户使用了不支持的验证码算法。");
    }
    if (digits !== 6 && digits !== 8) {
        throw new Error("账户使用了不支持的验证码位数。");
    }
    if (!Number.isSafeInteger(period) || period < 1 || period > 300) {
        throw new Error("账户使用了无效的验证码周期。");
    }

    const label = issuer && account && !issuer.includes(":")
        ? `${issuer}:${account}`
        : account || (issuer.includes(":") ? "TOTP" : issuer) || "TOTP";
    const params = new URLSearchParams();
    params.set("secret", secret);
    if (issuer) {
        params.set("issuer", issuer);
    }
    params.set("algorithm", algorithm);
    params.set("digits", String(digits));
    params.set("period", String(period));

    return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}

if (typeof document !== "undefined") {
    const elements = {
        importToggle: document.getElementById("import-toggle"),
        importDialog: document.getElementById("import-dialog"),
        importClose: document.getElementById("import-close"),
        qrFiles: document.getElementById("qr-files"),
        uploadScanLabel: document.getElementById("upload-scan-label"),
        startCamera: document.getElementById("start-camera"),
        stopCamera: document.getElementById("stop-camera"),
        cameraStage: document.getElementById("camera-stage"),
        cameraPreview: document.getElementById("camera-preview"),
        scanStatus: document.getElementById("scan-status"),
        rawImportValue: document.getElementById("raw-import-value"),
        importRawValue: document.getElementById("import-raw-value"),
        vaultState: document.getElementById("vault-state"),
        vaultDescription: document.getElementById("vault-description"),
        vaultToggle: document.getElementById("vault-toggle"),
        vaultForm: document.getElementById("vault-form"),
        vaultPasswordGroup: document.getElementById("vault-password-group"),
        vaultPassword: document.getElementById("vault-password"),
        vaultPasskey: document.getElementById("vault-passkey"),
        vaultPrimary: document.getElementById("vault-primary"),
        vaultLock: document.getElementById("vault-lock"),
        vaultRemovePasskey: document.getElementById("vault-remove-passkey"),
        vaultDelete: document.getElementById("vault-delete"),
        vaultPasskeyHelp: document.getElementById("vault-passkey-help"),
        vaultStatus: document.getElementById("vault-status"),
        accountsTitle: document.getElementById("accounts-title"),
        accountsCount: document.getElementById("accounts-count"),
        clearAccounts: document.getElementById("clear-accounts"),
        accountsEmpty: document.getElementById("accounts-empty"),
        accountsList: document.getElementById("accounts-list"),
        confirmDialog: document.getElementById("confirm-dialog"),
        confirmTitle: document.getElementById("confirm-title"),
        confirmMessage: document.getElementById("confirm-message"),
        confirmDetail: document.getElementById("confirm-detail"),
        confirmCancel: document.getElementById("confirm-cancel"),
        confirmAccept: document.getElementById("confirm-accept")
    };

    const confirmation = createConfirmationController({
        dialog: elements.confirmDialog,
        title: elements.confirmTitle,
        message: elements.confirmMessage,
        detail: elements.confirmDetail,
        cancelButton: elements.confirmCancel,
        acceptButton: elements.confirmAccept,
        getActiveElement: () => document.activeElement
    });
    let suppressedImportCloseEvents = 0;
    let importBackdropPressed = false;

    const state = {
        accounts: new Map(),
        accountKeys: new Map(),
        migrationBatches: new Map(),
        nextAccountId: 1,
        qrDetector: null,
        cameraStream: null,
        cameraInterval: null,
        cameraDetecting: false,
        cameraSession: 0,
        importGeneration: 0,
        importPanelOpen: false,
        importActivity: null,
        qrDetectorChecked: false,
        cameraSeenValues: new Set(),
        framed: window.top !== window.self,
        cryptoAvailable: Boolean(window.isSecureContext && globalThis.crypto?.subtle && globalThis.crypto?.getRandomValues),
        vault: {
            initialized: false,
            available: typeof globalThis.indexedDB !== "undefined",
            exists: false,
            unlocked: false,
            busy: false,
            key: null,
            dekBytes: null,
            record: null,
            vaultId: null,
            recordRevision: 0,
            recordSnapshot: null,
            recordValid: false,
            temporaryConflict: false,
            session: 0,
            operationId: 0,
            webAuthnAvailable: Boolean(
                window.isSecureContext
                && globalThis.PublicKeyCredential
                && navigator.credentials?.create
                && navigator.credentials?.get
            ),
            webAuthnController: null,
            databasePromise: null,
            mutationQueue: Promise.resolve(),
            channel: null
        }
    };

    function setScanStatus(message, type = "info") {
        elements.scanStatus.textContent = message;
        elements.scanStatus.className = `scan-status status-${type}`;
    }

    function setVaultStatus(message, type = "info") {
        elements.vaultStatus.textContent = message;
        elements.vaultStatus.className = `vault-status status-${type}`;
    }

    function resetVaultPasswordInput() {
        elements.vaultPassword.value = "";
        elements.vaultPassword.readOnly = true;
        const clearLateAutofill = () => {
            if (elements.vaultPassword.readOnly) elements.vaultPassword.value = "";
        };
        window.requestAnimationFrame(clearLateAutofill);
        window.setTimeout(clearLateAutofill, 250);
    }

    function enableVaultPasswordInput() {
        if (!elements.vaultPassword.readOnly || elements.vaultPassword.disabled) return;
        elements.vaultPassword.value = "";
        elements.vaultPassword.readOnly = false;
    }

    function getPreferredVaultControl() {
        const passwordFirst = !state.vault.exists || state.vault.unlocked;
        return [
            ...(passwordFirst
                ? [elements.vaultPassword, elements.vaultPasskey]
                : [elements.vaultPasskey, elements.vaultPassword]),
            elements.vaultPrimary,
            elements.vaultLock,
            elements.vaultRemovePasskey,
            elements.vaultDelete
        ].find((control) => !control.hidden && !control.disabled && !control.closest("[hidden]")) || elements.vaultToggle;
    }

    function setVaultControlsOpen(open, focusControl = false) {
        const shouldOpen = Boolean(open && !elements.vaultToggle.disabled);
        elements.vaultForm.hidden = !shouldOpen;
        elements.vaultToggle.setAttribute("aria-expanded", String(shouldOpen));
        if (!shouldOpen) {
            resetVaultPasswordInput();
        } else if (focusControl) {
            window.requestAnimationFrame(() => getPreferredVaultControl().focus());
        }
        return shouldOpen;
    }

    function isImportUnavailable() {
        const lockedVault = state.vault.initialized && state.vault.exists && !state.vault.unlocked;
        return state.framed || !state.cryptoAvailable || !state.vault.initialized || state.vault.busy || lockedVault;
    }

    function closeImportPanel(restoreFocus = true) {
        state.importPanelOpen = false;
        importBackdropPressed = false;
        elements.importToggle.setAttribute("aria-expanded", "false");
        elements.importToggle.setAttribute("aria-label", "打开账户导入工具");
        state.importGeneration += 1;
        state.importActivity = null;
        stopCamera(false);
        elements.qrFiles.value = "";
        elements.uploadScanLabel.removeAttribute("aria-busy");
        elements.rawImportValue.value = "";
        if (elements.importDialog.open) {
            suppressedImportCloseEvents += 1;
            try {
                elements.importDialog.close();
            } catch (error) {
                suppressedImportCloseEvents -= 1;
                throw error;
            }
        }
        if (restoreFocus && elements.importToggle.isConnected && !elements.importToggle.disabled) {
            elements.importToggle.focus();
        }
    }

    function closeImportPanelAfterSuccess(addedCount) {
        if (addedCount <= 0 || !state.importPanelOpen || state.migrationBatches.size > 0) return false;
        closeImportPanel(false);
        window.requestAnimationFrame(() => {
            if (!document.hidden) elements.accountsTitle.focus();
        });
        return true;
    }

    function openImportPanel() {
        if (isImportUnavailable() || suppressedImportCloseEvents > 0) return false;
        try {
            if (!elements.importDialog.open) elements.importDialog.showModal();
        } catch {
            setVaultStatus("当前浏览器无法打开导入面板，请更新浏览器后重试。", "error");
            return false;
        }
        state.importPanelOpen = true;
        elements.importToggle.setAttribute("aria-expanded", "true");
        elements.importToggle.setAttribute("aria-label", "关闭账户导入工具");
        renderImportAvailability();
        window.requestAnimationFrame(() => {
            if (state.importPanelOpen && elements.importDialog.open && !elements.qrFiles.disabled) {
                elements.uploadScanLabel.focus();
            }
        });
        return true;
    }

    function handleImportToggle() {
        if (suppressedImportCloseEvents > 0) return;
        if (state.importPanelOpen) {
            closeImportPanel(true);
            return;
        }
        if (openImportPanel()) return;
        const lockedVault = state.vault.initialized && state.vault.exists && !state.vault.unlocked;
        if (lockedVault) {
            setVaultControlsOpen(true, true);
            setVaultStatus("请先解锁本机加密存储，再添加账户。", "warning");
        } else {
            setVaultStatus(state.vault.busy ? "本机加密存储正在处理，请稍后再试。" : "当前环境暂时无法添加账户。", "warning");
            elements.accountsTitle.focus();
        }
    }

    function renderImportAvailability() {
        const importUnavailable = isImportUnavailable();
        if (importUnavailable && state.importPanelOpen) closeImportPanel(false);
        const panelControlsDisabled = importUnavailable || !state.importPanelOpen || Boolean(state.importActivity);
        const lockedVault = state.vault.initialized && state.vault.exists && !state.vault.unlocked;
        const hardDisabled = state.framed || !state.cryptoAvailable || !state.vault.initialized || state.vault.busy;
        elements.importToggle.disabled = hardDisabled;
        elements.importToggle.setAttribute("aria-disabled", String(hardDisabled));
        elements.importToggle.classList.toggle("is-disabled", hardDisabled);
        elements.importToggle.classList.toggle("requires-unlock", lockedVault && !hardDisabled);
        elements.importToggle.setAttribute("aria-label", importUnavailable
            ? (lockedVault ? "解锁本机加密存储后添加账户" : "当前无法添加账户")
            : (state.importPanelOpen ? "关闭账户导入工具" : "打开账户导入工具"));
        elements.qrFiles.disabled = panelControlsDisabled;
        elements.startCamera.disabled = panelControlsDisabled;
        elements.rawImportValue.disabled = panelControlsDisabled;
        elements.importRawValue.disabled = panelControlsDisabled;
        if (panelControlsDisabled) {
            elements.uploadScanLabel.setAttribute("aria-disabled", "true");
            elements.uploadScanLabel.tabIndex = -1;
        } else {
            elements.uploadScanLabel.removeAttribute("aria-disabled");
            elements.uploadScanLabel.tabIndex = 0;
        }
        elements.clearAccounts.disabled = state.framed || !state.vault.initialized || state.vault.busy
            || (state.accounts.size === 0 && state.migrationBatches.size === 0);
        for (const button of elements.accountsList.querySelectorAll("button[data-action]")) {
            const account = state.accounts.get(Number(button.dataset.accountId));
            button.disabled = importUnavailable || !account || (button.dataset.action === "copy" && !account.currentCode);
        }
    }

    function getVaultPrfSlots(record = state.vault.record) {
        return Array.isArray(record?.unlockSlots)
            ? record.unlockSlots.filter((slot) => slot?.type === VAULT_PRF_SLOT)
            : [];
    }

    function renderVaultState() {
        const vault = state.vault;
        const locked = vault.exists && !vault.unlocked;
        const hasPrf = vault.recordValid && getVaultPrfSlots().length > 0;
        const recordUnavailable = vault.exists && !vault.recordValid;
        const canOfferPasskey = vault.initialized && vault.available && state.cryptoAvailable
            && vault.webAuthnAvailable && !recordUnavailable && !vault.temporaryConflict;
        const showPasskeyAction = canOfferPasskey && (
            !vault.exists
            || (locked && hasPrf)
            || (vault.unlocked && !hasPrf && Boolean(vault.dekBytes))
        );

        elements.vaultPasswordGroup.hidden = vault.unlocked;
        elements.vaultPrimary.hidden = vault.unlocked;
        elements.vaultPasskey.hidden = !showPasskeyAction;
        elements.vaultLock.hidden = !vault.unlocked;
        elements.vaultRemovePasskey.hidden = !(vault.unlocked && hasPrf);
        elements.vaultDelete.hidden = !vault.exists;
        elements.vaultPassword.autocomplete = "off";

        if (!vault.initialized) {
            elements.vaultState.textContent = "检查中";
            elements.vaultState.className = "vault-badge";
            elements.vaultDescription.textContent = "正在检查此浏览器中是否已有加密账户。";
        } else if (!vault.available) {
            elements.vaultState.textContent = "不可用";
            elements.vaultState.className = "vault-badge is-locked";
            elements.vaultDescription.textContent = "当前浏览器禁止使用本机数据库，账户只能保留在页面内存中。";
        } else if (vault.unlocked) {
            elements.vaultState.textContent = hasPrf ? "已解锁 · 通行密钥已启用" : "已解锁 · 自动保存";
            elements.vaultState.className = "vault-badge is-unlocked";
            elements.vaultDescription.textContent = hasPrf
                ? "账户会使用独立数据密钥加密保存；主密码和当前域名的通行密钥均可解锁。"
                : (vault.dekBytes
                    ? "账户会使用独立数据密钥加密保存；可继续添加通行密钥作为便捷解锁方式。"
                    : "账户会使用独立数据密钥加密保存；锁定后用主密码重新解锁，即可再次添加通行密钥。");
        } else if (locked) {
            elements.vaultState.textContent = "已锁定";
            elements.vaultState.className = "vault-badge is-locked";
            elements.vaultDescription.textContent = hasPrf
                ? "可使用通行密钥或主密码解锁并恢复账户。解锁前，扫描和导入功能保持关闭。"
                : "输入主密码解锁并恢复账户。解锁前，扫描和导入功能保持关闭。";
        } else {
            elements.vaultState.textContent = "未启用";
            elements.vaultState.className = "vault-badge";
            elements.vaultDescription.textContent = "当前账户只保留在页面内存中。创建保险库后，可用主密码并按需添加通行密钥解锁。";
        }

        if (vault.busy) elements.vaultState.textContent = "处理中";
        const vaultControlsDisabled = !vault.initialized || vault.busy || !vault.available || !state.cryptoAvailable || state.framed;
        elements.vaultPassword.disabled = vaultControlsDisabled || vault.temporaryConflict || recordUnavailable;
        elements.vaultPrimary.disabled = vaultControlsDisabled || vault.temporaryConflict || recordUnavailable;
        elements.vaultPasskey.disabled = vaultControlsDisabled;
        elements.vaultLock.disabled = vaultControlsDisabled;
        elements.vaultRemovePasskey.disabled = vaultControlsDisabled;
        elements.vaultDelete.disabled = vaultControlsDisabled;
        elements.vaultToggle.disabled = vaultControlsDisabled;
        const vaultToggleLabel = !vault.initialized
            ? "检查中"
            : (!vault.available || !state.cryptoAvailable || state.framed
                ? "不可用"
                : (recordUnavailable
                    ? "处理问题"
                    : (locked ? "解锁" : (vault.unlocked ? "管理" : "启用"))));
        elements.vaultToggle.textContent = vaultToggleLabel;
        const vaultToggleAriaLabels = {
            检查中: "正在检查本机加密存储",
            不可用: "本机加密存储不可用",
            处理问题: "处理本机加密存储问题",
            解锁: "解锁本机加密存储",
            管理: "管理本机加密存储",
            启用: "启用本机加密存储"
        };
        elements.vaultToggle.setAttribute("aria-label", vaultToggleAriaLabels[vaultToggleLabel]);
        elements.vaultPrimary.textContent = vault.exists ? "使用主密码解锁" : "仅使用主密码创建";
        elements.vaultPasskey.textContent = !vault.exists
            ? "使用通行密钥创建"
            : (vault.unlocked ? "添加通行密钥解锁" : "使用通行密钥解锁");
        elements.vaultPasskeyHelp.textContent = vault.webAuthnAvailable
            ? "通行密钥通过 WebAuthn PRF 在本机派生解锁密钥；凭据只适用于创建它的域名，主密码始终可独立解锁。"
            : "当前浏览器或地址不支持 WebAuthn 通行密钥；仍可使用主密码加密保存和解锁。";
        renderImportAvailability();
    }

    function updateClock() {
        updateImportedAccounts(Date.now());
    }

  function encodeQrText(value, qrNamespace = globalThis.qrcodegen) {
    const QrCode = qrNamespace?.QrCode;
    if (!QrCode?.encodeText || !QrCode?.Ecc) {
      throw new Error("本地二维码生成组件未加载。");
    }

    try {
      return QrCode.encodeText(value, QrCode.Ecc.MEDIUM);
    } catch {
      return QrCode.encodeText(value, QrCode.Ecc.LOW);
    }
  }

  function drawQrToCanvas(canvas, value) {
    const qr = encodeQrText(value);
    const quietZone = 4;
    const moduleSpan = qr.size + quietZone * 2;
    const scale = Math.max(2, Math.floor(512 / moduleSpan));
    const pixelSize = moduleSpan * scale;
    const context = canvas.getContext("2d", { alpha: false });
    if (!context) {
      throw new Error("当前浏览器无法绘制二维码。");
    }

    canvas.width = pixelSize;
    canvas.height = pixelSize;
    context.imageSmoothingEnabled = false;
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, pixelSize, pixelSize);
    context.fillStyle = "#000000";
    for (let y = 0; y < qr.size; y += 1) {
      for (let x = 0; x < qr.size; x += 1) {
        if (qr.getModule(x, y)) {
          context.fillRect(
            (x + quietZone) * scale,
            (y + quietZone) * scale,
            scale,
            scale,
          );
        }
      }
    }

    return { moduleCount: qr.size, pixelSize };
  }

  async function copyText(value, feedbackButton) {
        if (!value) return;
        try {
            if (!navigator.clipboard?.writeText) throw new Error("Clipboard API unavailable");
            await navigator.clipboard.writeText(value);
            if (feedbackButton) {
                feedbackButton.textContent = "已复制";
                window.setTimeout(() => {
                    if (feedbackButton.isConnected) feedbackButton.textContent = "复制";
                }, 1200);
            }
        } catch {
            setScanStatus("无法访问剪贴板，请手动选择并复制。", "error");
        }
    }

    function createElement(tagName, className, text) {
        const element = document.createElement(tagName);
        if (className) element.className = className;
        if (text !== undefined) element.textContent = text;
        return element;
    }

    function getAccountKey(account) {
        return [
            account.secret,
            account.issuer,
            account.account,
            account.algorithm,
            account.digits,
            account.period
        ].join("\u001f");
    }

    function normalizeImportedAccount(input) {
        const secret = normalizeBase32(String(input.secret || ""));
        const issuer = String(input.issuer || "").trim();
        const account = String(input.account || "").trim();
        if (issuer.length > 512 || account.length > 1024) throw new Error("导入账户名称过长");
        const unsafeNameCharacters = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/;
        if (unsafeNameCharacters.test(issuer) || unsafeNameCharacters.test(account)) {
            throw new Error("导入账户名称包含不可安全显示的控制字符");
        }
        const validationBytes = decodeBase32(secret);
        validationBytes.fill(0);
        return {
            secret,
            issuer,
            account,
            algorithm: normalizeAlgorithm(input.algorithm || DEFAULT_ALGORITHM),
            digits: validateDigits(input.digits ?? DEFAULT_DIGITS),
            period: validatePeriod(input.period ?? DEFAULT_PERIOD),
            source: input.source || "import"
        };
    }

    function openVaultDatabase() {
        if (state.vault.databasePromise) return state.vault.databasePromise;
        state.vault.databasePromise = new Promise((resolve, reject) => {
            let request;
            try {
                request = globalThis.indexedDB.open(VAULT_DB_NAME, VAULT_DB_VERSION);
            } catch (error) {
                reject(error);
                return;
            }
            request.onupgradeneeded = (event) => {
                const database = request.result;
                if (event.oldVersion < VAULT_DB_VERSION && database.objectStoreNames.contains(VAULT_STORE_NAME)) {
                    database.deleteObjectStore(VAULT_STORE_NAME);
                }
                if (!database.objectStoreNames.contains(VAULT_STORE_NAME)) database.createObjectStore(VAULT_STORE_NAME);
            };
            request.onsuccess = () => {
                const database = request.result;
                database.onversionchange = () => database.close();
                resolve(database);
            };
            request.onerror = () => reject(request.error || new Error("无法打开本机加密存储"));
            request.onblocked = () => reject(new Error("本机加密存储正被其他页面占用"));
        });
        state.vault.databasePromise.catch(() => {
            state.vault.databasePromise = null;
        });
        return state.vault.databasePromise;
    }

    async function readVaultRecord() {
        const database = await openVaultDatabase();
        return new Promise((resolve, reject) => {
            const transaction = database.transaction(VAULT_STORE_NAME, "readonly");
            const request = transaction.objectStore(VAULT_STORE_NAME).openCursor(VAULT_RECORD_KEY);
            request.onsuccess = () => resolve(request.result
                ? { exists: true, value: request.result.value }
                : { exists: false, value: undefined });
            request.onerror = () => reject(request.error || new Error("无法读取本机加密存储"));
            transaction.onabort = () => reject(transaction.error || new Error("读取本机加密存储已中止"));
        });
    }

    function getVaultRecordSnapshot(record) {
        const seen = new WeakSet();
        let budget = 0;
        let nodes = 0;
        const consume = (amount) => {
            budget += amount;
            if (budget > MAX_VAULT_RECORD_SNAPSHOT_CHARACTERS) throw new Error("加密存储记录过大");
        };
        const encode = (value, depth = 0) => {
            nodes += 1;
            if (nodes > 10000) throw new Error("加密存储记录结构过大");
            consume(1);
            if (depth > 16) throw new Error("加密存储记录嵌套过深");
            if (value === null) return ["null"];
            const type = typeof value;
            if (type === "string") {
                consume(value.length);
                return ["string", value];
            }
            if (type === "boolean" || type === "undefined") return [type, String(value)];
            if (type === "number") {
                const normalized = Number.isNaN(value) ? "NaN"
                    : (value === Infinity ? "+Infinity" : (value === -Infinity ? "-Infinity" : (Object.is(value, -0) ? "-0" : String(value))));
                return ["number", normalized];
            }
            if (type === "bigint") return ["bigint", value.toString()];
            if (type !== "object" || seen.has(value)) throw new Error("加密存储记录包含不支持的数据");
            seen.add(value);
            if (Array.isArray(value)) return ["array", value.map((item) => encode(item, depth + 1))];
            const prototype = Object.getPrototypeOf(value);
            if (prototype !== Object.prototype && prototype !== null) throw new Error("加密存储记录包含不支持的对象");
            const entries = [];
            for (const key of Object.keys(value).sort()) {
                consume(key.length);
                entries.push([key, encode(value[key], depth + 1)]);
            }
            return ["object", entries];
        };
        try {
            const snapshot = JSON.stringify(encode(record));
            return snapshot && snapshot.length <= MAX_VAULT_RECORD_SNAPSHOT_CHARACTERS ? snapshot : null;
        } catch {
            return null;
        }
    }

    async function writeVaultRecord(record, expectedVaultId, expectedRevision) {
        const database = await openVaultDatabase();
        return new Promise((resolve, reject) => {
            let conflict = false;
            const transaction = database.transaction(VAULT_STORE_NAME, "readwrite");
            const store = transaction.objectStore(VAULT_STORE_NAME);
            const request = store.openCursor(VAULT_RECORD_KEY);
            request.onsuccess = () => {
                const currentExists = Boolean(request.result);
                const currentValue = request.result?.value;
                const currentVaultId = currentValue?.vaultId || null;
                const currentRevision = currentValue?.recordRevision || 0;
                const identityMatches = expectedVaultId === null
                    ? !currentExists && expectedRevision === 0
                    : currentExists && currentVaultId === expectedVaultId && currentRevision === expectedRevision;
                if (!identityMatches) {
                    conflict = true;
                    transaction.abort();
                    return;
                }
                store.put(record, VAULT_RECORD_KEY);
            };
            request.onerror = () => {
                // The unhandled request error aborts the transaction automatically.
            };
            transaction.oncomplete = () => resolve();
            transaction.onerror = () => {
                // onabort reports the final transaction error.
            };
            transaction.onabort = () => reject(conflict
                ? new Error("加密存储已在另一标签页中更新，请重新解锁")
                : (transaction.error || new Error("无法写入本机加密存储")));
        });
    }

    async function deleteVaultRecord(expectedVaultId, expectedRevision, expectedSnapshot = null) {
        const database = await openVaultDatabase();
        return new Promise((resolve, reject) => {
            let conflict = false;
            const transaction = database.transaction(VAULT_STORE_NAME, "readwrite");
            const store = transaction.objectStore(VAULT_STORE_NAME);
            const request = store.openCursor(VAULT_RECORD_KEY);
            request.onsuccess = () => {
                const currentExists = Boolean(request.result);
                const currentValue = request.result?.value;
                const currentVaultId = currentValue?.vaultId || null;
                const currentRevision = currentValue?.recordRevision || 0;
                const identityMatches = expectedSnapshot !== null
                    ? currentExists && getVaultRecordSnapshot(currentValue) === expectedSnapshot
                    : currentExists && currentVaultId === expectedVaultId && currentRevision === expectedRevision;
                if (!identityMatches) {
                    conflict = true;
                    transaction.abort();
                    return;
                }
                store.delete(VAULT_RECORD_KEY);
            };
            transaction.oncomplete = () => resolve();
            transaction.onerror = () => {
                // onabort reports the final transaction error.
            };
            transaction.onabort = () => reject(conflict
                ? new Error("加密存储已在另一标签页中更新，请重新加载")
                : (transaction.error || new Error("无法删除本机加密存储")));
        });
    }

    function getSerializableAccount(account) {
        return {
            secret: account.secret,
            issuer: account.issuer,
            account: account.account,
            algorithm: account.algorithm,
            digits: account.digits,
            period: account.period
        };
    }

    function getSerializableAccounts() {
        return [...state.accounts.values()].map(getSerializableAccount);
    }

    function serializeVaultPayload(accounts) {
        return JSON.stringify({
            schema: VAULT_PAYLOAD_VERSION,
            accounts: accounts.map(getSerializableAccount)
        });
    }

    function parseVaultPayload(plaintext) {
        let payload;
        try {
            payload = JSON.parse(plaintext);
        } catch {
            throw new Error("加密存储中的账户数据格式无效");
        }
        if (!payload || typeof payload !== "object" || Array.isArray(payload)
            || payload.schema !== VAULT_PAYLOAD_VERSION || !Array.isArray(payload.accounts)) {
            throw new Error("不支持的账户存储格式");
        }
        if (payload.accounts.length > MAX_IMPORTED_ACCOUNTS) throw new Error("加密存储中的账户数量超过限制");
        const accounts = [];
        const keys = new Set();
        for (const input of payload.accounts) {
            const normalized = normalizeImportedAccount({ ...input, source: "vault" });
            const key = getAccountKey(normalized);
            if (keys.has(key)) throw new Error("加密存储中包含重复账户");
            keys.add(key);
            accounts.push(normalized);
        }
        return accounts;
    }

    function broadcastVaultChange(type, vaultId = state.vault.vaultId, revision = state.vault.recordRevision) {
        try {
            state.vault.channel?.postMessage({ type, vaultId, revision });
        } catch {
            // Cross-tab notification is best-effort; revision checks still prevent overwrite.
        }
    }

    function isSameVaultRecord(left, right) {
        if (!left || !right) return false;
        const leftSnapshot = getVaultRecordSnapshot(left);
        return leftSnapshot !== null && leftSnapshot === getVaultRecordSnapshot(right);
    }

    function enqueueAccountMutation(operation) {
        const queued = state.vault.mutationQueue.then(operation);
        state.vault.mutationQueue = queued.catch(() => undefined);
        return queued;
    }

    function assertAccountMutationAllowed() {
        if (!state.vault.initialized || state.vault.busy) throw new Error("本机加密存储正在处理，请稍后重试");
        if (state.vault.exists && !state.vault.unlocked) throw new Error("请先解锁本机加密存储");
    }

    async function persistVaultAccounts(accounts) {
        if (!state.vault.exists) return;
        if (!state.vault.unlocked || !state.vault.key || !state.vault.vaultId
            || !state.vault.recordValid || !state.vault.record) {
            throw new Error("请先解锁本机加密存储");
        }
        if (accounts.length > MAX_IMPORTED_ACCOUNTS) throw new Error(`一次最多保存 ${MAX_IMPORTED_ACCOUNTS} 个账户`);
        if (state.vault.recordRevision >= Number.MAX_SAFE_INTEGER) throw new Error("加密存储修订号已达上限");
        const session = state.vault.session;
        const vaultId = state.vault.vaultId;
        const expectedRevision = state.vault.recordRevision;
        const nextRevision = expectedRevision + 1;
        const unlockSlots = state.vault.record.unlockSlots;
        const plaintext = serializeVaultPayload(accounts);
        let committed = false;
        try {
            const payload = await encryptVaultPayload(plaintext, state.vault.key, nextRevision, vaultId, unlockSlots);
            const record = buildVaultRecord(vaultId, nextRevision, payload, unlockSlots);
            if (session !== state.vault.session || !state.vault.unlocked) throw new Error("加密存储会话已结束");
            await writeVaultRecord(record, vaultId, expectedRevision);
            committed = true;
            broadcastVaultChange("updated", vaultId, nextRevision);
            if (session !== state.vault.session || !state.vault.unlocked) {
                const error = new Error("账户更改已写入加密存储，页面将在下次解锁时同步");
                error.vaultCommitted = true;
                throw error;
            }
            state.vault.record = record;
            state.vault.recordRevision = nextRevision;
            state.vault.recordSnapshot = getVaultRecordSnapshot(record);
            state.vault.recordValid = true;
            state.vault.temporaryConflict = false;
            setVaultStatus(`已加密保存 ${accounts.length} 个账户。`, "success");
        } catch (error) {
            if (!committed && session === state.vault.session) {
                setVaultStatus("加密保存失败，账户更改未应用。请重试后再锁定页面。", "error");
            }
            throw error;
        }
    }

  const exportElements = {
    dialog: document.getElementById("export-dialog"),
    identity: document.getElementById("export-identity"),
    qr: document.getElementById("export-qr"),
    uri: document.getElementById("export-uri"),
    secret: document.getElementById("export-secret"),
    status: document.getElementById("export-status"),
    close: document.getElementById("export-close"),
    downloadQr: document.getElementById("export-download-qr"),
    copyUri: document.getElementById("export-copy-uri"),
    copySecret: document.getElementById("export-copy-secret"),
  };
  let exportAccountId = null;
  let exportOpener = null;
  let exportGeneration = 0;
  let exportClosing = false;

  function setExportStatus(message, type = "info") {
    exportElements.status.textContent = message;
    exportElements.status.className = `export-status status-${type}`;
  }

  function resetExportCanvas() {
    exportElements.qr.width = 1;
    exportElements.qr.height = 1;
  }

  function resetAccountExport() {
    exportGeneration += 1;
    exportAccountId = null;
    exportOpener = null;
    exportElements.identity.textContent = "";
    exportElements.uri.value = "";
    exportElements.secret.value = "";
    exportElements.copyUri.textContent = "复制链接";
    exportElements.copySecret.textContent = "复制密钥";
    exportElements.copyUri.disabled = true;
    exportElements.copySecret.disabled = true;
    exportElements.downloadQr.disabled = true;
    resetExportCanvas();
    setExportStatus("导出内容已从页面清除。", "info");
  }

  function closeAccountExport(restoreFocus = true) {
    const opener = exportOpener;
    exportClosing = true;
    if (exportElements.dialog.open) {
      exportElements.dialog.close();
    }
    exportClosing = false;
    resetAccountExport();
    if (restoreFocus && opener?.isConnected) {
      opener.focus();
    }
  }

  async function openAccountExport(account, opener) {
    const accessibleName = [account.issuer, account.account].filter(Boolean).join(" / ") || "未命名账户";
    const confirmed = await confirmation.request({
      title: "显示完整认证密钥？",
      message: `即将显示“${accessibleName}”的二维码、认证链接和 Base32 密钥。`,
      detail: "任何获得这些内容的人都可以生成该账户的验证码。请只在可信设备和私密环境中继续。",
      confirmLabel: "继续导出",
      tone: "warning",
      opener,
      restoreFocusOnAccept: false
    });
    if (!confirmed) return false;

    const currentAccount = state.accounts.get(account.id);
    if (currentAccount !== account || state.vault.busy) {
      if (opener?.isConnected && !opener.disabled) opener.focus();
      setScanStatus("账户状态已发生变化，请重新选择导出。", "error");
      return false;
    }
    let uri;
    try {
      closeAccountExport(false);
      uri = buildOtpAuthUri(currentAccount);
      exportElements.dialog.showModal();
    } catch (error) {
      closeAccountExport(false);
      if (opener?.isConnected && !opener.disabled) opener.focus();
      throw error;
    }
    exportAccountId = currentAccount.id;
    exportOpener = opener;
    exportGeneration += 1;
    exportElements.identity.textContent = `${currentAccount.issuer || "未命名服务"} · ${currentAccount.account || "未命名账户"}`;
    exportElements.uri.value = uri;
    exportElements.secret.value = currentAccount.secret;
    exportElements.copyUri.disabled = false;
    exportElements.copySecret.disabled = false;
    exportElements.downloadQr.disabled = true;

    try {
      drawQrToCanvas(exportElements.qr, uri);
      exportElements.downloadQr.disabled = false;
      setExportStatus("二维码、链接和密钥包含同一份认证密钥。使用后请清空剪贴板和下载文件。", "warning");
    } catch {
      resetExportCanvas();
      setExportStatus("二维码内容过长或生成组件不可用；仍可复制链接或密钥。", "error");
    }

    exportElements.close.focus();
    return true;
  }

  async function copyExportValue(value, button, successMessage) {
    if (!value || !navigator.clipboard?.writeText) {
      setExportStatus("复制失败，请检查浏览器剪贴板权限。", "error");
      return;
    }

    const generation = exportGeneration;
    const originalLabel = button.textContent;
    try {
      await navigator.clipboard.writeText(value);
      if (generation !== exportGeneration || !exportElements.dialog.open) {
        return;
      }
      button.textContent = "已复制";
      setExportStatus(`${successMessage}，使用后请清空剪贴板。`, "success");
      window.setTimeout(() => {
        if (generation === exportGeneration && button.isConnected) {
          button.textContent = originalLabel;
        }
      }, 1200);
    } catch {
      if (generation === exportGeneration) {
        setExportStatus("复制失败，请检查浏览器剪贴板权限。", "error");
      }
    }
  }

  function getExportFileName(account) {
    const base = `${account.issuer || "totp"}-${account.account || "account"}`
      .normalize("NFKC")
      .replace(/[<>:"/\\|?*\u0000-\u001F]/g, "-")
      .replace(/\s+/g, "-")
      .replace(/-+/g, "-")
      .replace(/^[-.]+|[-.]+$/g, "")
      .slice(0, 80);
    return `${base || "totp-account"}-qr.png`;
  }

  function downloadExportQr() {
    const account = state.accounts.get(exportAccountId);
    if (!account || !exportElements.dialog.open || exportElements.downloadQr.disabled) {
      setExportStatus("账户已不可用，请重新打开导出窗口。", "error");
      return;
    }

    const generation = exportGeneration;
    const accountId = account.id;
    exportElements.qr.toBlob((blob) => {
      if (!blob || generation !== exportGeneration || accountId !== exportAccountId) {
        return;
      }
      const objectUrl = URL.createObjectURL(blob);
      let link = null;
      try {
        link = document.createElement("a");
        link.href = objectUrl;
        link.download = getExportFileName(account);
        link.rel = "noopener";
        document.body.append(link);
        link.click();
      } catch {
        setExportStatus("二维码下载失败，请检查浏览器下载权限。", "error");
        return;
      } finally {
        link?.remove();
        window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
      }
      setExportStatus("二维码 PNG 已下载；请像保护密码一样保护该文件。", "success");
    }, "image/png");
  }

  function createAccountRow(account) {
        const row = createElement("li", "account-row");
        row.dataset.accountId = String(account.id);

        const identity = createElement("div", "account-identity");
        identity.append(
            createElement("strong", "", account.issuer || "未命名服务"),
            createElement("small", "", account.account || "未命名账号"),
            createElement("span", "", `${ALGORITHMS[account.algorithm]} · ${account.digits} 位 · ${account.period}s`)
        );

        const codeBox = createElement("div", "account-code-box");
        const codeLine = createElement("div", "account-code-line");
        const code = createElement("span", "account-code", account.digits === 8 ? "———— ————" : "——— ———");
        const remaining = createElement("span", "account-remaining", "— 秒");
        codeLine.append(code, remaining);
        const progress = document.createElement("progress");
        progress.max = account.period;
        progress.value = 0;
        progress.setAttribute("aria-label", `${account.issuer || account.account || "账户"} 验证码剩余有效时间`);
        codeBox.append(codeLine, progress);

        const actions = createElement("div", "account-actions");
        const accessibleName = [account.issuer, account.account].filter(Boolean).join(" / ") || "未命名账户";
        const copyButton = createElement("button", "", "复制");
        copyButton.type = "button";
        copyButton.disabled = true;
        copyButton.dataset.action = "copy";
        copyButton.dataset.accountId = String(account.id);
        copyButton.setAttribute("aria-label", `复制 ${accessibleName} 的验证码`);
        const exportButton = createElement("button", "", "导出");
        exportButton.type = "button";
        exportButton.dataset.action = "export";
        exportButton.dataset.accountId = String(account.id);
        exportButton.setAttribute("aria-label", `导出 ${accessibleName} 的认证配置`);
        const removeButton = createElement("button", "", "删除");
        removeButton.type = "button";
        removeButton.dataset.action = "remove";
        removeButton.dataset.accountId = String(account.id);
        removeButton.setAttribute("aria-label", `从列表删除 ${accessibleName}`);
        actions.append(copyButton, exportButton, removeButton);
        row.append(identity, codeBox, actions);

        account.elements = { row, code, remaining, progress, copyButton };
        return row;
    }

    function renderAccountsState() {
        const count = state.accounts.size;
        const pending = state.migrationBatches.size;
        elements.accountsCount.textContent = `${count} 个账户${pending ? ` · ${pending} 个待完成批次` : ""}`;
        elements.clearAccounts.disabled = count === 0 && pending === 0
            || state.framed || !state.vault.initialized || state.vault.busy;
        elements.accountsEmpty.hidden = count > 0;
        elements.accountsList.hidden = count === 0;
    }

    async function refreshImportedAccount(account, force = false, timestampMs = Date.now()) {
        const window = getTimeWindow(timestampMs, account.period);
        if (!force && account.lastCounter === window.counter) return;
        const requestVersion = ++account.requestVersion;
        account.lastCounter = window.counter;
        const secretSnapshot = account.secretBytes.slice();
        try {
            const result = await generateTotp(secretSnapshot, timestampMs, account);
            if (!state.accounts.has(account.id) || requestVersion !== account.requestVersion) return;
            account.currentCode = result.code;
            account.elements.code.textContent = formatCode(result.code);
            account.elements.copyButton.disabled = false;
        } catch (error) {
            if (!state.accounts.has(account.id) || requestVersion !== account.requestVersion) return;
            account.currentCode = "";
            if (!globalThis.crypto?.subtle) {
                account.elements.code.textContent = "需要 HTTPS";
                setScanStatus("当前地址不是安全上下文，无法生成验证码。请使用 HTTPS，或在本机通过 localhost / 127.0.0.1 打开。", "error");
            } else if (error?.name === "NotSupportedError") {
                account.elements.code.textContent = "算法不支持";
            } else {
                account.elements.code.textContent = "生成失败";
            }
            account.elements.copyButton.disabled = true;
        } finally {
            secretSnapshot.fill(0);
        }
    }

    function updateImportedAccounts(timestampMs) {
        for (const account of state.accounts.values()) {
            try {
                const window = getTimeWindow(timestampMs, account.period);
                account.elements.progress.max = window.period;
                account.elements.progress.value = window.remaining;
                account.elements.progress.setAttribute("aria-valuetext", `${Math.max(1, Math.ceil(window.remaining))} 秒后失效`);
                account.elements.remaining.textContent = `${Math.max(1, Math.ceil(window.remaining))} 秒`;
                if (account.lastCounter !== window.counter) void refreshImportedAccount(account, false, timestampMs);
            } catch {
                account.elements.remaining.textContent = "参数错误";
            }
        }
    }

    function addNormalizedImportedAccount(normalized) {
        const key = getAccountKey(normalized);
        const account = {
            ...normalized,
            id: state.nextAccountId,
            secretBytes: decodeBase32(normalized.secret),
            currentCode: "",
            lastCounter: null,
            requestVersion: 0,
            elements: null
        };
        state.nextAccountId += 1;
        state.accounts.set(account.id, account);
        state.accountKeys.set(key, account.id);
        elements.accountsList.append(createAccountRow(account));
        renderAccountsState();
        void refreshImportedAccount(account, true);
        return account;
    }

    function addImportedAccounts(inputs) {
        assertAccountMutationAllowed();
        return enqueueAccountMutation(async () => {
            assertAccountMutationAllowed();
            const pending = [];
            const pendingKeys = new Set();
            const addedAccounts = [];
            let duplicates = 0;
            let invalid = 0;
            for (const input of inputs) {
                try {
                    const normalized = normalizeImportedAccount(input);
                    const key = getAccountKey(normalized);
                    if (state.accountKeys.has(key) || pendingKeys.has(key)) {
                        duplicates += 1;
                    } else {
                        pendingKeys.add(key);
                        pending.push(normalized);
                    }
                } catch {
                    invalid += 1;
                }
            }
            if (state.accounts.size + pending.length > MAX_IMPORTED_ACCOUNTS) {
                throw new Error(`一次最多导入 ${MAX_IMPORTED_ACCOUNTS} 个账户，请先清理列表`);
            }
            if (pending.length > 0) await persistVaultAccounts([...getSerializableAccounts(), ...pending]);
            for (const normalized of pending) addedAccounts.push(addNormalizedImportedAccount(normalized));
            return { addedAccounts, duplicates, invalid };
        });
    }

    function removeImportedAccountFromMemory(accountId) {
        if (exportAccountId === accountId) {
            closeAccountExport(false);
        }
        const account = state.accounts.get(accountId);
        if (!account) return false;
        account.requestVersion += 1;
        account.secretBytes.fill(0);
        state.accounts.delete(accountId);
        state.accountKeys.delete(getAccountKey(account));
        account.secret = "";
        account.currentCode = "";
        account.elements.code.textContent = "";
        account.elements.copyButton.disabled = true;
        account.elements.row.remove();
        account.elements = null;
        renderAccountsState();
        return true;
    }

    async function removeImportedAccount(accountId, opener = document.activeElement) {
        const previewAccount = state.accounts.get(accountId);
        if (!previewAccount) return false;
        const accessibleName = [previewAccount.issuer, previewAccount.account].filter(Boolean).join(" / ") || "未命名账户";
        const confirmed = await confirmation.request({
            title: "删除此账户？",
            message: `将删除“${accessibleName}”及其当前验证码。`,
            detail: state.vault.unlocked
                ? "确认后，该账户也会从本机加密存储中永久删除。此操作无法撤销。"
                : "确认后，该账户会从当前页面内存中删除。此操作无法撤销。",
            confirmLabel: "删除账户",
            tone: "danger",
            opener,
            restoreFocusOnAccept: false
        });
        if (!confirmed) return false;

        if (opener?.isConnected && "disabled" in opener) opener.disabled = true;
        try {
            assertAccountMutationAllowed();
            const removed = await enqueueAccountMutation(async () => {
                assertAccountMutationAllowed();
                const account = state.accounts.get(accountId);
                if (!account || account !== previewAccount) return false;
                const remaining = [...state.accounts.values()]
                    .filter((candidate) => candidate.id !== accountId)
                    .map(getSerializableAccount);
                await persistVaultAccounts(remaining);
                return removeImportedAccountFromMemory(accountId);
            });
            if (!removed && opener?.isConnected && "disabled" in opener) {
                opener.disabled = false;
                opener.focus();
            }
            return removed;
        } catch (error) {
            if (opener?.isConnected && "disabled" in opener) {
                opener.disabled = false;
                opener.focus();
            }
            throw error;
        }
    }

    async function clearImportedAccounts() {
        if (!state.vault.initialized || state.vault.busy) return;
        const confirmedAccountIds = [...state.accounts.keys()];
        const confirmedBatchKeys = [...state.migrationBatches.keys()];
        const confirmedVaultId = state.vault.vaultId;
        const confirmedVaultExists = state.vault.exists;
        const confirmedVaultUnlocked = state.vault.unlocked;
        const accountCount = state.accounts.size;
        const pendingBatchCount = state.migrationBatches.size;
        if (accountCount === 0 && pendingBatchCount === 0) return;
        const scope = [
            accountCount > 0 ? `${accountCount} 个账户` : "",
            pendingBatchCount > 0 ? `${pendingBatchCount} 个未完成迁移批次` : ""
        ].filter(Boolean).join("和");
        const confirmedScopeIsCurrent = () => {
            const accountSetUnchanged = state.accounts.size === confirmedAccountIds.length
                && confirmedAccountIds.every((accountId) => state.accounts.has(accountId));
            const batchSetUnchanged = state.migrationBatches.size === confirmedBatchKeys.length
                && confirmedBatchKeys.every((batchKey) => state.migrationBatches.has(batchKey));
            const vaultStateUnchanged = state.vault.vaultId === confirmedVaultId
                && state.vault.exists === confirmedVaultExists
                && state.vault.unlocked === confirmedVaultUnlocked;
            return accountSetUnchanged && batchSetUnchanged && vaultStateUnchanged;
        };
        const confirmed = await confirmation.request({
            title: "清空全部账户？",
            message: `将清空${scope}。`,
            detail: state.vault.unlocked
                ? "所有账户会同时从本机加密存储中永久删除，未完成的迁移进度也会丢失。此操作无法撤销。"
                : "账户和未完成的迁移进度会从当前页面内存中删除。此操作无法撤销。",
            confirmLabel: "清空全部",
            tone: "danger",
            opener: elements.clearAccounts,
            restoreFocusOnAccept: false
        });
        if (!confirmed) return;
        if (!state.vault.initialized || state.vault.busy) {
            (elements.clearAccounts.disabled ? elements.accountsTitle : elements.clearAccounts).focus();
            return;
        }
        if (!confirmedScopeIsCurrent()) {
            setScanStatus("账户或迁移进度已发生变化，请重新确认清空操作。", "error");
            (elements.clearAccounts.disabled ? elements.accountsTitle : elements.clearAccounts).focus();
            return;
        }

        elements.clearAccounts.disabled = true;
        state.importGeneration += 1;
        stopCamera(false);
        setScanStatus("正在清空账户…", "info");
        let cleared = false;
        try {
            await enqueueAccountMutation(async () => {
                if (!confirmedScopeIsCurrent()) {
                    throw new Error("账户或迁移进度已发生变化，请重新确认清空操作。");
                }
                if (!state.vault.exists || state.vault.unlocked) {
                    await persistVaultAccounts([]);
                }
                for (const account of [...state.accounts.values()]) removeImportedAccountFromMemory(account.id);
                state.migrationBatches.clear();
                state.vault.temporaryConflict = false;
                elements.rawImportValue.value = "";
                renderAccountsState();
            });
            cleared = true;
            setScanStatus(state.vault.unlocked ? "账户已从页面和加密存储中清除。" : "账户列表及未完成的迁移批次已从内存中清除。", "info");
        } catch (error) {
            setScanStatus(error.message || "无法清空账户，加密存储未被修改。", "error");
        } finally {
            renderImportAvailability();
            if (cleared || elements.clearAccounts.disabled) {
                elements.accountsTitle.focus();
            } else {
                elements.clearAccounts.focus();
            }
        }
    }

    async function processImportedValue(rawValue) {
        assertAccountMutationAllowed();
        const value = String(rawValue || "").trim();
        if (!value) throw new Error("二维码或导入内容为空");

        if (/^otpauth-migration:/i.test(value)) {
            const migration = parseMigrationUri(value);
            const staged = stageMigrationPart(state.migrationBatches, migration);
            renderAccountsState();
            if (staged.pending) {
                const missing = staged.missingIndices.map((index) => index + 1).join("、");
                return {
                    added: 0,
                    message: `迁移批次已读取 ${staged.progress}/${staged.total}，还缺少第 ${missing} 张二维码。`,
                    type: staged.duplicatePart ? "warning" : "info"
                };
            }
            const imported = await addImportedAccounts(staged.accounts);
            state.migrationBatches.delete(staged.batchKey);
            renderAccountsState();
            const skipped = staged.skipped.length + imported.invalid;
            return {
                added: imported.addedAccounts.length,
                message: `批量迁移完成：新增 ${imported.addedAccounts.length} 个，重复 ${imported.duplicates} 个${skipped ? `，跳过 ${skipped} 个` : ""}。`,
                type: imported.addedAccounts.length > 0 ? "success" : "warning"
            };
        }

        if (/^otpauth:/i.test(value)) {
            const parsed = parseOtpAuthUri(value);
            const imported = await addImportedAccounts([{ ...parsed, source: "qr" }]);
            return {
                added: imported.addedAccounts.length,
                message: imported.addedAccounts.length > 0
                    ? (state.vault.unlocked ? "二维码账户已加密保存。" : "二维码账户已加入临时内存列表。")
                    : "该二维码账户已在列表中。",
                type: imported.addedAccounts.length > 0 ? "success" : "warning"
            };
        }
        throw new Error("二维码内容不是受支持的 TOTP 或 Google Authenticator 迁移 URI");
    }

    async function getNativeQrDetector() {
        if (state.qrDetectorChecked) return state.qrDetector;
        state.qrDetectorChecked = true;
        if (typeof globalThis.BarcodeDetector !== "function") return null;
        try {
            if (typeof globalThis.BarcodeDetector.getSupportedFormats === "function") {
                const formats = await globalThis.BarcodeDetector.getSupportedFormats();
                if (!formats.includes("qr_code")) return null;
            }
            state.qrDetector = new globalThis.BarcodeDetector({ formats: ["qr_code"] });
        } catch {
            state.qrDetector = null;
        }
        return state.qrDetector;
    }

    function getSourceDimensions(source) {
        const width = source.videoWidth || source.naturalWidth || source.width;
        const height = source.videoHeight || source.naturalHeight || source.height;
        if (!Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0) {
            throw new Error("二维码图片尺寸无效");
        }
        if (width > MAX_QR_SOURCE_DIMENSION || height > MAX_QR_SOURCE_DIMENSION || width * height > MAX_QR_SOURCE_PIXELS) {
            throw new Error("二维码图片像素尺寸过大");
        }
        return { width, height };
    }

    function createQrScanCanvas(source, region) {
        const dimensions = getSourceDimensions(source);
        const sourceRegion = region || { x: 0, y: 0, width: dimensions.width, height: dimensions.height };
        if (sourceRegion.x < 0 || sourceRegion.y < 0 || sourceRegion.width <= 0 || sourceRegion.height <= 0
            || sourceRegion.x + sourceRegion.width > dimensions.width
            || sourceRegion.y + sourceRegion.height > dimensions.height) {
            throw new Error("二维码扫描区域越界");
        }
        const scale = Math.min(1, MAX_QR_SCAN_DIMENSION / Math.max(sourceRegion.width, sourceRegion.height));
        const width = Math.max(1, Math.round(sourceRegion.width * scale));
        const height = Math.max(1, Math.round(sourceRegion.height * scale));
        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        const context = canvas.getContext("2d", { willReadFrequently: true });
        if (!context) throw new Error("浏览器无法创建二维码解码画布");
        context.imageSmoothingEnabled = true;
        context.imageSmoothingQuality = "high";
        context.drawImage(
            source,
            sourceRegion.x,
            sourceRegion.y,
            sourceRegion.width,
            sourceRegion.height,
            0,
            0,
            width,
            height
        );
        return { canvas, context, width, height };
    }

    function decodeQrWithJsQr(context, width, height) {
        if (typeof globalThis.jsQR !== "function") return [];
        const imageData = context.getImageData(0, 0, width, height);
        try {
            const result = globalThis.jsQR(imageData.data, width, height, { inversionAttempts: "attemptBoth" });
            return result?.data ? [result.data] : [];
        } finally {
            imageData.data.fill(0);
        }
    }

    async function decodeQrSource(source, options = {}) {
        const dimensions = getSourceDimensions(source);
        const detector = await getNativeQrDetector();
        if (detector) {
            try {
                const detections = await detector.detect(source);
                const values = detections.map((item) => item.rawValue).filter(Boolean);
                if (values.length > 0) return values;
            } catch {
                // The local jsQR decoder below is the cross-platform fallback.
            }
        }

        const regions = getQrScanRegions(dimensions.width, dimensions.height, options);
        for (let index = 0; index < regions.length; index += 1) {
            if (options.shouldContinue && !options.shouldContinue()) return [];
            if (index > 0) await new Promise((resolve) => window.setTimeout(resolve, 0));
            if (options.shouldContinue && !options.shouldContinue()) return [];
            const prepared = createQrScanCanvas(source, regions[index]);
            try {
                const values = decodeQrWithJsQr(prepared.context, prepared.width, prepared.height);
                if (values.length > 0) return values;
            } finally {
                prepared.context.clearRect(0, 0, prepared.width, prepared.height);
                prepared.canvas.width = 0;
                prepared.canvas.height = 0;
            }
        }
        return [];
    }

    async function scanImageFiles(fileList) {
        if (!state.importPanelOpen || isImportUnavailable() || state.importActivity) {
            elements.qrFiles.value = "";
            return;
        }
        const files = [...fileList];
        if (files.length === 0) return;
        if (files.length > MAX_QR_IMAGE_FILES) {
            elements.qrFiles.value = "";
            setScanStatus(`一次最多扫描 ${MAX_QR_IMAGE_FILES} 张二维码图片。`, "error");
            return;
        }
        const generation = ++state.importGeneration;
        state.importActivity = "images";
        renderImportAvailability();
        setScanStatus(`正在本地扫描 ${files.length} 张图片…`, "info");
        let detectedCount = 0;
        let addedCount = 0;
        let errorCount = 0;
        let lastError = "";
        const seenValues = new Set();
        elements.uploadScanLabel.setAttribute("aria-busy", "true");
        try {
            for (const file of files) {
                if (generation !== state.importGeneration) return;
                if (!QR_IMAGE_TYPES.has(file.type) || file.size > MAX_QR_IMAGE_FILE_BYTES) {
                    errorCount += 1;
                    lastError = file.size > MAX_QR_IMAGE_FILE_BYTES ? "图片文件超过 20 MiB 限制" : "所选文件不是支持的图片格式";
                    continue;
                }
                let bitmap = null;
                try {
                    if (typeof createImageBitmap !== "function") throw new Error("当前浏览器不支持本地图片解码");
                    bitmap = await createImageBitmap(file);
                    if (generation !== state.importGeneration) return;
                    const values = await decodeQrSource(bitmap, {
                        extended: true,
                        shouldContinue: () => generation === state.importGeneration
                    });
                    if (generation !== state.importGeneration) return;
                    detectedCount += values.length;
                    for (const value of values) {
                        if (seenValues.has(value)) continue;
                        try {
                            const result = await processImportedValue(value);
                            if (generation !== state.importGeneration) return;
                            seenValues.add(value);
                            addedCount += result.added;
                            setScanStatus(result.message, result.type);
                        } catch (error) {
                            if (generation !== state.importGeneration) return;
                            errorCount += 1;
                            lastError = error.message || "二维码内容无法导入";
                        }
                    }
                    if (values.length === 0) errorCount += 1;
                } catch (error) {
                    if (generation !== state.importGeneration) return;
                    errorCount += 1;
                    lastError = error.message || "二维码内容无法导入";
                } finally {
                    bitmap?.close?.();
                }
            }
            if (generation !== state.importGeneration) return;
            if (detectedCount === 0) {
                setScanStatus("未在所选图片中识别到二维码，请使用清晰的原始截图。", "error");
            } else if (addedCount > 0) {
                setScanStatus(`图片扫描完成：识别 ${detectedCount} 个二维码，新增 ${addedCount} 个账户${errorCount ? `，${errorCount} 项未处理` : ""}。`, "success");
            } else if (errorCount > 0) {
                setScanStatus(`已识别 ${detectedCount} 个二维码，但有 ${errorCount} 项无法导入：${lastError}`, "error");
            }
            if (errorCount === 0) closeImportPanelAfterSuccess(addedCount);
        } finally {
            if (generation === state.importGeneration && state.importActivity === "images") {
                state.importActivity = null;
                elements.qrFiles.value = "";
                elements.uploadScanLabel.removeAttribute("aria-busy");
                renderImportAvailability();
            }
        }
    }

    function stopCamera(showStatus = true) {
        state.cameraSession += 1;
        if (state.importActivity === "camera-starting" || state.importActivity === "camera") {
            state.importActivity = null;
        }
        if (state.cameraInterval !== null) {
            window.clearInterval(state.cameraInterval);
            state.cameraInterval = null;
        }
        if (state.cameraStream) {
            for (const track of state.cameraStream.getTracks()) track.stop();
            state.cameraStream = null;
        }
        elements.cameraPreview.srcObject = null;
        elements.cameraStage.hidden = true;
        state.cameraDetecting = false;
        state.cameraSeenValues.clear();
        renderImportAvailability();
        if (showStatus) {
            setScanStatus("摄像头已停止。", "info");
            elements.startCamera.focus();
        }
    }

    async function scanCameraFrame() {
        if (!state.cameraStream || state.cameraDetecting || elements.cameraPreview.readyState < 2) return;
        const session = state.cameraSession;
        state.cameraDetecting = true;
        try {
            const values = await decodeQrSource(elements.cameraPreview, {
                preferCenter: true,
                shouldContinue: () => session === state.cameraSession && Boolean(state.cameraStream)
            });
            if (session !== state.cameraSession || !state.cameraStream) return;
            for (const value of values) {
                if (state.cameraSeenValues.has(value)) continue;
                if (state.cameraSeenValues.size >= MAX_IMPORTED_ACCOUNTS) {
                    throw new Error("本次摄像头会话识别的二维码过多，请停止后重新开始");
                }
                try {
                    const result = await processImportedValue(value);
                    if (session !== state.cameraSession || !state.cameraStream) return;
                    state.cameraSeenValues.add(value);
                    setScanStatus(result.message, result.type);
                    if (closeImportPanelAfterSuccess(result.added)) return;
                } catch (error) {
                    if (session !== state.cameraSession || !state.cameraStream) return;
                    setScanStatus(error.message || "摄像头二维码内容无法导入", "error");
                }
            }
        } catch (error) {
            if (session === state.cameraSession) {
                setScanStatus(error.message || "摄像头二维码识别失败", "error");
            }
        } finally {
            if (session === state.cameraSession) state.cameraDetecting = false;
        }
    }

    async function startCamera() {
        if (!state.importPanelOpen || isImportUnavailable() || state.importActivity) return;
        if (!navigator.mediaDevices?.getUserMedia) {
            setScanStatus("当前浏览器不支持摄像头访问，请选择二维码图片或粘贴 URI。", "error");
            return;
        }
        if (state.cameraStream) return;
        const session = state.cameraSession + 1;
        state.cameraSession = session;
        state.cameraSeenValues.clear();
        state.importActivity = "camera-starting";
        renderImportAvailability();
        try {
            const stream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: { ideal: "environment" } },
                audio: false
            });
            if (session !== state.cameraSession || document.hidden) {
                for (const track of stream.getTracks()) track.stop();
                if (session === state.cameraSession) stopCamera(false);
                return;
            }
            state.cameraStream = stream;
            for (const track of stream.getTracks()) {
                track.addEventListener("ended", () => {
                    if (session !== state.cameraSession) return;
                    stopCamera(false);
                    setScanStatus("摄像头连接已结束，请重新授权或改用图片导入。", "warning");
                }, { once: true });
            }
            elements.cameraPreview.srcObject = state.cameraStream;
            elements.cameraStage.hidden = false;
            await elements.cameraPreview.play();
            if (session !== state.cameraSession || state.cameraStream !== stream || document.hidden) {
                if (state.cameraStream === stream) {
                    stopCamera(false);
                } else {
                    for (const track of stream.getTracks()) track.stop();
                }
                return;
            }
            state.cameraInterval = window.setInterval(() => void scanCameraFrame(), 650);
            state.importActivity = "camera";
            renderImportAvailability();
            setScanStatus("摄像头已启动，二维码只在当前设备上解码。", "success");
            elements.stopCamera.focus();
        } catch {
            if (session !== state.cameraSession) return;
            stopCamera(false);
            setScanStatus("无法打开摄像头，请检查 HTTPS 环境、浏览器权限或改用图片导入。", "error");
        }
    }

    async function importRawValues() {
        if (!state.importPanelOpen || isImportUnavailable() || state.importActivity) return;
        const values = elements.rawImportValue.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
        if (values.length === 0) {
            setScanStatus("请先粘贴 TOTP 或迁移 URI。", "error");
            return;
        }
        const generation = ++state.importGeneration;
        state.importActivity = "raw";
        renderImportAvailability();
        try {
            let added = 0;
            let failed = 0;
            let lastResult = null;
            let lastError = "";
            for (const value of values) {
                if (generation !== state.importGeneration) return;
                try {
                    lastResult = await processImportedValue(value);
                    if (generation !== state.importGeneration) return;
                    added += lastResult.added;
                } catch (error) {
                    if (generation !== state.importGeneration) return;
                    failed += 1;
                    lastError = error.message || "内容格式无效";
                }
            }
            if (values.length === 1 && lastResult && failed === 0) {
                setScanStatus(lastResult.message, lastResult.type);
            } else {
                const errorDetail = failed && values.length === 1 ? `：${lastError}` : "";
                setScanStatus(`导入完成：新增 ${added} 个账户${failed ? `，${failed} 条内容无效${errorDetail}` : ""}。`, added > 0 ? "success" : (failed ? "error" : "warning"));
            }
            if (failed === 0) elements.rawImportValue.value = "";
            if (failed === 0) closeImportPanelAfterSuccess(added);
        } finally {
            if (generation === state.importGeneration && state.importActivity === "raw") {
                state.importActivity = null;
                renderImportAvailability();
            }
        }
    }

    function clearRuntimeSensitiveState() {
        confirmation.cancelPending({ restoreFocus: false });
        closeAccountExport(false);
        closeImportPanel(false);
        setVaultControlsOpen(false, false);
        for (const account of state.accounts.values()) {
            account.requestVersion += 1;
            account.secretBytes.fill(0);
            account.secret = "";
            account.currentCode = "";
            if (account.elements) {
                account.elements.code.textContent = "";
                account.elements.copyButton.disabled = true;
            }
            account.elements = null;
        }
        state.accounts.clear();
        state.accountKeys.clear();
        state.migrationBatches.clear();
        state.vault.temporaryConflict = false;
        elements.accountsList.replaceChildren();
        renderAccountsState();
    }

    function abortVaultWebAuthn() {
        const controller = state.vault.webAuthnController;
        state.vault.webAuthnController = null;
        try {
            controller?.abort();
        } catch {
            // Abort is best-effort; the operation generation still rejects late results.
        }
    }

    function createVaultWebAuthnSignal(operationId) {
        assertVaultOperation(operationId);
        abortVaultWebAuthn();
        const controller = new AbortController();
        state.vault.webAuthnController = controller;
        return controller.signal;
    }

    function beginVaultOperation() {
        abortVaultWebAuthn();
        const operationId = state.vault.operationId + 1;
        state.vault.operationId = operationId;
        state.vault.busy = true;
        renderVaultState();
        return operationId;
    }

    function isCurrentVaultOperation(operationId) {
        return operationId === state.vault.operationId;
    }

    function assertVaultOperation(operationId) {
        if (isCurrentVaultOperation(operationId)) return;
        const error = new Error("本机加密存储操作已取消");
        error.name = "AbortError";
        throw error;
    }

    function finishVaultOperation(operationId) {
        if (!isCurrentVaultOperation(operationId)) return false;
        state.vault.webAuthnController = null;
        state.vault.busy = false;
        renderVaultState();
        return true;
    }

    function releaseVaultSession(invalidateOperation = true) {
        abortVaultWebAuthn();
        if (invalidateOperation) state.vault.operationId += 1;
        state.vault.session += 1;
        state.vault.key = null;
        state.vault.dekBytes?.fill(0);
        state.vault.dekBytes = null;
        state.vault.unlocked = false;
        resetVaultPasswordInput();
    }

    function adoptLockedVaultRecord(recordExists, record) {
        let invalidRecord = false;
        state.vault.exists = recordExists;
        state.vault.unlocked = false;
        state.vault.key = null;
        state.vault.dekBytes?.fill(0);
        state.vault.dekBytes = null;
        state.vault.record = null;
        state.vault.vaultId = typeof record?.vaultId === "string" ? record.vaultId : null;
        state.vault.recordRevision = Number.isSafeInteger(record?.recordRevision) ? record.recordRevision : 0;
        state.vault.recordSnapshot = recordExists ? getVaultRecordSnapshot(record) : null;
        state.vault.recordValid = false;
        if (recordExists) {
            try {
                const decoded = validateVaultRecord(record);
                clearValidatedVaultRecord(decoded);
                state.vault.recordValid = true;
                state.vault.record = record;
            } catch {
                invalidRecord = true;
            }
        }
        return invalidRecord;
    }

    function getCurrentRpId() {
        const rpId = window.location.hostname.toLowerCase();
        if (!isValidVaultRpId(rpId)) {
            throw createPrfError("当前地址不能用作 WebAuthn RP ID", "PRF_UNSUPPORTED");
        }
        return rpId;
    }

    function adoptUnlockedVault(record, decrypted, accounts) {
        for (const account of accounts) addNormalizedImportedAccount(account);
        state.vault.session += 1;
        state.vault.exists = true;
        state.vault.unlocked = true;
        state.vault.key = decrypted.key;
        state.vault.dekBytes?.fill(0);
        if (getVaultPrfSlots(record).length === 0) {
            state.vault.dekBytes = decrypted.dekBytes;
        } else {
            decrypted.dekBytes.fill(0);
            state.vault.dekBytes = null;
        }
        state.vault.record = record;
        state.vault.vaultId = record.vaultId;
        state.vault.recordRevision = decrypted.recordRevision;
        state.vault.recordSnapshot = getVaultRecordSnapshot(record);
        state.vault.recordValid = true;
        state.vault.temporaryConflict = false;
    }

    async function createVault(password, operationId, prfRegistration = null, prfInput = null) {
        assertVaultOperation(operationId);
        const normalizedPassword = normalizeVaultPassword(password);
        const vaultIdBytes = globalThis.crypto.getRandomValues(new Uint8Array(VAULT_ID_BYTES));
        const vaultId = encodeBase64Url(vaultIdBytes);
        const dekBytes = globalThis.crypto.getRandomValues(new Uint8Array(VAULT_DEK_BYTES));
        vaultIdBytes.fill(0);
        let adopted = false;
        try {
            const key = await importVaultDek(dekBytes);
            assertVaultOperation(operationId);
            const unlockSlots = [await createPasswordUnlockSlot(normalizedPassword, dekBytes, vaultId)];
            assertVaultOperation(operationId);
            if (prfRegistration) {
                unlockSlots.push(await createPrfUnlockSlot(
                    prfRegistration,
                    prfRegistration.prfOutput,
                    prfInput,
                    dekBytes,
                    vaultId
                ));
                assertVaultOperation(operationId);
            }
            const payload = await encryptVaultPayload(
                serializeVaultPayload(getSerializableAccounts()),
                key,
                1,
                vaultId,
                unlockSlots
            );
            assertVaultOperation(operationId);
            const record = buildVaultRecord(vaultId, 1, payload, unlockSlots);
            await writeVaultRecord(record, null, 0);
            broadcastVaultChange("updated", vaultId, 1);
            assertVaultOperation(operationId);
            state.vault.session += 1;
            state.vault.exists = true;
            state.vault.unlocked = true;
            state.vault.key = key;
            if (prfRegistration) {
                dekBytes.fill(0);
                state.vault.dekBytes = null;
            } else {
                state.vault.dekBytes = dekBytes;
            }
            state.vault.record = record;
            state.vault.vaultId = vaultId;
            state.vault.recordRevision = 1;
            state.vault.recordSnapshot = getVaultRecordSnapshot(record);
            state.vault.recordValid = true;
            state.vault.temporaryConflict = false;
            adopted = true;
            try {
                const request = navigator.storage?.persist?.();
                request?.catch?.(() => undefined);
            } catch {
                // Persistent-storage permission is optional; the encrypted record already exists.
            }
            setVaultStatus(prfRegistration
                ? `已创建保险库并保存 ${state.accounts.size} 个账户；主密码和通行密钥均可解锁。`
                : `已创建保险库并加密保存 ${state.accounts.size} 个账户。`, "success");
        } finally {
            if (!adopted) dekBytes.fill(0);
        }
    }

    async function unlockVaultWithPassword(password, operationId) {
        assertVaultOperation(operationId);
        const session = state.vault.session;
        const storedRecord = await readVaultRecord();
        assertVaultOperation(operationId);
        if (!storedRecord.exists) {
            adoptLockedVaultRecord(false, undefined);
            throw new Error("本机加密存储已不存在");
        }
        const record = storedRecord.value;
        const decrypted = await decryptVaultRecord(record, password);
        let adopted = false;
        try {
            assertVaultOperation(operationId);
            const accounts = parseVaultPayload(decrypted.plaintext);
            const currentRecord = await readVaultRecord();
            assertVaultOperation(operationId);
            if (session !== state.vault.session || !currentRecord.exists || !isSameVaultRecord(record, currentRecord.value)) {
                throw new Error("加密存储已在解锁期间发生变化");
            }
            if (state.accounts.size > 0 || state.migrationBatches.size > 0) {
                throw new Error("页面中已有未保存账户，请刷新后重新解锁");
            }
            adoptUnlockedVault(record, decrypted, accounts);
            adopted = true;
            setVaultStatus(`已使用主密码解锁并恢复 ${accounts.length} 个账户。`, "success");
            setScanStatus(accounts.length > 0 ? "加密账户已恢复，可以继续扫描或导入。" : "加密存储为空，可以开始扫描或导入。", "success");
        } finally {
            if (!adopted) decrypted.dekBytes.fill(0);
        }
    }

    async function unlockVaultWithPasskey(operationId) {
        assertVaultOperation(operationId);
        const session = state.vault.session;
        const record = state.vault.record;
        const recordSnapshot = state.vault.recordSnapshot;
        const slot = getVaultPrfSlots(record)[0];
        if (!state.vault.recordValid || !record || !recordSnapshot || !slot) {
            throw new Error("当前加密存储未配置通行密钥解锁");
        }
        const rpId = getCurrentRpId();
        if (slot.rpId !== rpId) throw new Error("此通行密钥不属于当前网站域名");
        const prfInput = decodeBase64Url(slot.prf.input, {
            expectedLength: VAULT_PRF_INPUT_BYTES,
            maxLength: VAULT_PRF_INPUT_BYTES
        });
        let assertion = null;
        let decrypted = null;
        let adopted = false;
        try {
            assertion = await evaluateWebAuthnPrf({
                rpId,
                credentialId: slot.credentialId,
                transports: slot.transports,
                prfInput,
                signal: createVaultWebAuthnSignal(operationId)
            });
            assertVaultOperation(operationId);
            decrypted = await decryptVaultRecordWithPrf(record, slot.slotId, assertion.prfOutput);
            assertVaultOperation(operationId);
            const accounts = parseVaultPayload(decrypted.plaintext);
            const currentRecord = await readVaultRecord();
            assertVaultOperation(operationId);
            if (session !== state.vault.session || !currentRecord.exists
                || recordSnapshot !== getVaultRecordSnapshot(currentRecord.value)) {
                throw new Error("加密存储已在解锁期间发生变化");
            }
            if (state.accounts.size > 0 || state.migrationBatches.size > 0) {
                throw new Error("页面中已有未保存账户，请刷新后重新解锁");
            }
            adoptUnlockedVault(record, decrypted, accounts);
            adopted = true;
            setVaultStatus(`已使用通行密钥解锁并恢复 ${accounts.length} 个账户。`, "success");
            setScanStatus(accounts.length > 0 ? "加密账户已恢复，可以继续扫描或导入。" : "加密存储为空，可以开始扫描或导入。", "success");
        } finally {
            prfInput.fill(0);
            assertion?.prfOutput?.fill(0);
            if (!adopted) decrypted?.dekBytes?.fill(0);
        }
    }

    function describePasskeyError(error, fallback = "通行密钥操作失败。") {
        let message;
        if (error?.code === "PRF_UNSUPPORTED" || error?.name === "NotSupportedError") {
            message = "当前浏览器、系统或通行密钥不支持 WebAuthn PRF。";
        } else if (error?.name === "AbortError") {
            message = "通行密钥操作已取消。";
        } else if (error?.name === "NotAllowedError") {
            message = "未完成通行密钥用户验证，或操作已超时。";
        } else if (error?.name === "SecurityError") {
            message = "当前地址不允许使用此通行密钥。";
        } else {
            message = error?.message || fallback;
        }
        if (error?.credentialMayExist) {
            message += " 系统中可能已创建一个未关联的通行密钥，可在系统通行密钥管理中删除。";
        }
        return message;
    }

    async function createVaultWithPasskey(password, operationId) {
        normalizeVaultPassword(password);
        const prfInput = globalThis.crypto.getRandomValues(new Uint8Array(VAULT_PRF_INPUT_BYTES));
        let registration = null;
        try {
            registration = await registerWebAuthnPrf({
                rpId: getCurrentRpId(),
                prfInput,
                signal: createVaultWebAuthnSignal(operationId)
            });
            assertVaultOperation(operationId);
            await state.vault.mutationQueue;
            assertVaultOperation(operationId);
            await createVault(password, operationId, registration, prfInput);
        } catch (error) {
            if (registration) error.credentialMayExist = true;
            throw error;
        } finally {
            prfInput.fill(0);
            registration?.prfOutput?.fill(0);
        }
    }

    async function addVaultPasskey(operationId) {
        assertVaultOperation(operationId);
        if (!state.vault.unlocked || !state.vault.dekBytes || !state.vault.recordValid || !state.vault.record) {
            throw new Error("请先使用主密码解锁保险库");
        }
        if (getVaultPrfSlots().length > 0) throw new Error("当前保险库已启用通行密钥解锁");
        const session = state.vault.session;
        const prfInput = globalThis.crypto.getRandomValues(new Uint8Array(VAULT_PRF_INPUT_BYTES));
        const excludeCredentialIds = getVaultPrfSlots().map((slot) => slot.credentialId);
        let registration = null;
        let committed = false;
        try {
            registration = await registerWebAuthnPrf({
                rpId: getCurrentRpId(),
                prfInput,
                excludeCredentialIds,
                signal: createVaultWebAuthnSignal(operationId)
            });
            assertVaultOperation(operationId);
            await state.vault.mutationQueue;
            assertVaultOperation(operationId);
            if (session !== state.vault.session || !state.vault.unlocked || !state.vault.key
                || !state.vault.dekBytes || !state.vault.record) {
                throw new Error("保险库会话已结束");
            }
            if (state.vault.recordRevision >= Number.MAX_SAFE_INTEGER) throw new Error("加密存储修订号已达上限");
            const expectedRevision = state.vault.recordRevision;
            const vaultId = state.vault.vaultId;
            const slot = await createPrfUnlockSlot(
                registration,
                registration.prfOutput,
                prfInput,
                state.vault.dekBytes,
                vaultId
            );
            assertVaultOperation(operationId);
            const unlockSlots = [...state.vault.record.unlockSlots, slot];
            const nextRevision = expectedRevision + 1;
            const payload = await encryptVaultPayload(
                serializeVaultPayload(getSerializableAccounts()),
                state.vault.key,
                nextRevision,
                vaultId,
                unlockSlots
            );
            assertVaultOperation(operationId);
            const record = buildVaultRecord(vaultId, nextRevision, payload, unlockSlots);
            await writeVaultRecord(record, vaultId, expectedRevision);
            committed = true;
            broadcastVaultChange("updated", vaultId, nextRevision);
            assertVaultOperation(operationId);
            state.vault.record = record;
            state.vault.recordRevision = nextRevision;
            state.vault.recordSnapshot = getVaultRecordSnapshot(record);
            state.vault.recordValid = true;
            state.vault.dekBytes.fill(0);
            state.vault.dekBytes = null;
            setVaultStatus("通行密钥解锁已启用；主密码仍可作为恢复方式。", "success");
        } catch (error) {
            if (registration && !committed) error.credentialMayExist = true;
            throw error;
        } finally {
            prfInput.fill(0);
            registration?.prfOutput?.fill(0);
        }
    }

    async function removeVaultPasskey(operationId) {
        await state.vault.mutationQueue;
        assertVaultOperation(operationId);
        if (!state.vault.unlocked || !state.vault.key || !state.vault.recordValid || !state.vault.record) {
            throw new Error("请先解锁保险库");
        }
        const unlockSlots = state.vault.record.unlockSlots.filter((slot) => slot.type !== VAULT_PRF_SLOT);
        if (unlockSlots.length === state.vault.record.unlockSlots.length) throw new Error("当前保险库未配置通行密钥");
        if (state.vault.recordRevision >= Number.MAX_SAFE_INTEGER) throw new Error("加密存储修订号已达上限");
        const session = state.vault.session;
        const vaultId = state.vault.vaultId;
        const expectedRevision = state.vault.recordRevision;
        const nextRevision = expectedRevision + 1;
        const payload = await encryptVaultPayload(
            serializeVaultPayload(getSerializableAccounts()),
            state.vault.key,
            nextRevision,
            vaultId,
            unlockSlots
        );
        assertVaultOperation(operationId);
        if (session !== state.vault.session || !state.vault.unlocked) throw new Error("保险库会话已结束");
        const record = buildVaultRecord(vaultId, nextRevision, payload, unlockSlots);
        await writeVaultRecord(record, vaultId, expectedRevision);
        broadcastVaultChange("updated", vaultId, nextRevision);
        assertVaultOperation(operationId);
        state.vault.record = record;
        state.vault.recordRevision = nextRevision;
        state.vault.recordSnapshot = getVaultRecordSnapshot(record);
        state.vault.recordValid = true;
        setVaultStatus("已移除保险库中的通行密钥解锁权限；系统凭据需另行删除。若要重新添加，请锁定后用主密码解锁。", "info");
    }

    async function handleVaultPasskey() {
        if (state.vault.busy || !state.vault.available || !state.cryptoAvailable
            || !state.vault.webAuthnAvailable || state.framed) return;
        const creating = !state.vault.exists;
        const adding = state.vault.unlocked;
        const operationId = beginVaultOperation();
        state.importGeneration += 1;
        stopCamera(false);
        setVaultStatus(creating
            ? "正在等待系统创建通行密钥并验证 PRF 支持…"
            : (adding ? "正在等待系统创建通行密钥…" : "正在等待通行密钥用户验证…"), "info");
        try {
            if (creating) {
                await createVaultWithPasskey(elements.vaultPassword.value, operationId);
            } else if (adding) {
                await addVaultPasskey(operationId);
            } else {
                await unlockVaultWithPasskey(operationId);
            }
        } catch (error) {
            if (isCurrentVaultOperation(operationId)) {
                setVaultStatus(describePasskeyError(error), "error");
            }
        } finally {
            if (isCurrentVaultOperation(operationId)) {
                resetVaultPasswordInput();
                finishVaultOperation(operationId);
                if (state.vault.unlocked) {
                    setVaultControlsOpen(false, false);
                    elements.vaultToggle.focus();
                }
            }
        }
    }

    async function handleRemoveVaultPasskey() {
        const initialSlots = getVaultPrfSlots();
        if (state.vault.busy || !state.vault.unlocked || initialSlots.length === 0) return;
        const confirmed = await confirmation.request({
            title: "移除通行密钥解锁？",
            message: `将从保险库中移除 ${initialSlots.length} 个通行密钥解锁方式。`,
            detail: "主密码仍可继续解锁；系统或密码管理器中的通行密钥凭据不会被网页自动删除，需要另行清理。",
            confirmLabel: "确认移除",
            tone: "danger",
            opener: elements.vaultRemovePasskey,
            restoreFocusOnAccept: false
        });
        if (!confirmed) return;
        if (state.vault.busy || !state.vault.unlocked) {
            const fallback = !elements.vaultRemovePasskey.hidden
                ? elements.vaultRemovePasskey
                : elements.vaultLock;
            if (fallback && !fallback.hidden && !fallback.disabled) fallback.focus();
            return;
        }
        const currentSlots = getVaultPrfSlots();
        if (currentSlots.length !== initialSlots.length
            || initialSlots.some((slot) => !currentSlots.some((candidate) => candidate.slotId === slot.slotId))) {
            setVaultStatus("通行密钥配置已发生变化，请重新确认。", "error");
            if (!elements.vaultRemovePasskey.hidden && !elements.vaultRemovePasskey.disabled) {
                elements.vaultRemovePasskey.focus();
            }
            return;
        }
        const operationId = beginVaultOperation();
        state.importGeneration += 1;
        stopCamera(false);
        let removed = false;
        try {
            await removeVaultPasskey(operationId);
            removed = true;
        } catch (error) {
            if (isCurrentVaultOperation(operationId)) {
                setVaultStatus(error.message || "无法移除通行密钥解锁。", "error");
            }
        } finally {
            finishVaultOperation(operationId);
            const focusTarget = removed
                ? (!elements.vaultLock.hidden ? elements.vaultLock : elements.vaultPrimary)
                : (!elements.vaultRemovePasskey.hidden ? elements.vaultRemovePasskey : elements.vaultLock);
            if (focusTarget && !focusTarget.hidden && !focusTarget.disabled) focusTarget.focus();
        }
    }

    async function handleVaultSubmit(event) {
        event.preventDefault();
        if (state.vault.busy || !state.vault.available || !state.cryptoAvailable || state.framed) return;
        const unlocking = state.vault.exists;
        const password = elements.vaultPassword.value;
        const operationId = beginVaultOperation();
        state.importGeneration += 1;
        stopCamera(false);
        try {
            await state.vault.mutationQueue;
            assertVaultOperation(operationId);
            if (unlocking) {
                await unlockVaultWithPassword(password, operationId);
            } else {
                await createVault(password, operationId);
            }
        } catch (error) {
            if (!isCurrentVaultOperation(operationId)) return;
            if (unlocking) {
                setVaultStatus("主密码错误或加密存储已损坏。", "error");
            } else {
                setVaultStatus(error.message || "无法创建本机加密存储。", "error");
            }
        } finally {
            if (isCurrentVaultOperation(operationId)) {
                resetVaultPasswordInput();
                finishVaultOperation(operationId);
                if (state.vault.unlocked) {
                    setVaultControlsOpen(false, false);
                    elements.vaultToggle.focus();
                } else {
                    elements.vaultPassword.focus();
                }
            }
        }
    }

    async function lockVault() {
        if (!state.vault.unlocked || state.vault.busy) return;
        const operationId = beginVaultOperation();
        state.importGeneration += 1;
        stopCamera(false);
        let locked = false;
        try {
            await state.vault.mutationQueue;
            assertVaultOperation(operationId);
            clearRuntimeSensitiveState();
            releaseVaultSession(false);
            locked = true;
            setVaultStatus("加密存储已锁定，解密密钥和账户明文已从页面内存中清除。", "info");
            setScanStatus("请先解锁本机加密存储，再扫描或导入账户。", "info");
        } catch (error) {
            if (isCurrentVaultOperation(operationId)) {
                setVaultStatus(error.message || "无法锁定本机加密存储。", "error");
            }
        } finally {
            finishVaultOperation(operationId);
            if (locked && !elements.vaultToggle.disabled) elements.vaultToggle.focus();
        }
    }

    async function deleteVault() {
        if (!state.vault.exists || state.vault.busy) return;
        const confirmedVaultId = state.vault.vaultId;
        const confirmedRevision = state.vault.recordRevision;
        const confirmedSnapshot = state.vault.recordSnapshot;
        const confirmedRecordValid = state.vault.recordValid;
        const confirmedUnlocked = state.vault.unlocked;
        const confirmedVaultIsCurrent = () => state.vault.exists
            && state.vault.vaultId === confirmedVaultId
            && state.vault.recordRevision === confirmedRevision
            && state.vault.recordSnapshot === confirmedSnapshot
            && state.vault.recordValid === confirmedRecordValid
            && state.vault.unlocked === confirmedUnlocked;
        const confirmed = await confirmation.request({
            title: "删除加密存储？",
            message: "将永久删除此浏览器中的加密账户存储。",
            detail: state.vault.unlocked
                ? "当前已解锁账户会暂时保留在页面内存中，但关闭页面后无法恢复。系统通行密钥不会被网页自动删除。"
                : "存储中的账户将无法再从此浏览器恢复。系统通行密钥不会被网页自动删除。",
            confirmLabel: "删除加密存储",
            tone: "danger",
            opener: elements.vaultDelete,
            restoreFocusOnAccept: false
        });
        if (!confirmed) return;
        if (state.vault.busy || !confirmedVaultIsCurrent()) {
            setVaultStatus("加密存储已发生变化，请重新确认删除。", "error");
            if (!elements.vaultDelete.hidden && !elements.vaultDelete.disabled) elements.vaultDelete.focus();
            return;
        }
        const operationId = beginVaultOperation();
        state.importGeneration += 1;
        stopCamera(false);
        let deleted = false;
        try {
            await state.vault.mutationQueue;
            assertVaultOperation(operationId);
            if (!confirmedVaultIsCurrent()) {
                throw new Error("加密存储已发生变化，请重新确认删除。");
            }
            const expectedVaultId = state.vault.vaultId;
            const expectedRevision = state.vault.recordRevision;
            const expectedSnapshot = state.vault.recordSnapshot;
            const recordValid = state.vault.recordValid;
            if (!recordValid && !expectedSnapshot) {
                throw new Error("损坏的加密存储无法安全核对，请在浏览器站点数据中将其删除");
            }
            await deleteVaultRecord(
                recordValid ? expectedVaultId : null,
                recordValid ? expectedRevision : 0,
                recordValid ? null : expectedSnapshot
            );
            broadcastVaultChange("deleted", expectedVaultId, expectedRevision);
            assertVaultOperation(operationId);
            releaseVaultSession(false);
            state.vault.exists = false;
            state.vault.record = null;
            state.vault.vaultId = null;
            state.vault.recordRevision = 0;
            state.vault.recordSnapshot = null;
            state.vault.recordValid = false;
            state.vault.temporaryConflict = false;
            deleted = true;
            setVaultStatus("本机加密存储已删除；当前账户仅保留在页面内存中。系统通行密钥需在通行密钥管理器中另行删除。", "info");
            setScanStatus("加密存储已删除，当前页面中的账户不会在关闭后保留。", "info");
        } catch (error) {
            if (isCurrentVaultOperation(operationId)) {
                setVaultStatus(error.message || "无法删除本机加密存储。", "error");
            }
        } finally {
            finishVaultOperation(operationId);
            if (deleted) setVaultControlsOpen(false, false);
            const focusTarget = deleted
                ? elements.vaultToggle
                : (!elements.vaultDelete.hidden ? elements.vaultDelete : elements.vaultPrimary);
            if (focusTarget && !focusTarget.hidden && !focusTarget.disabled) focusTarget.focus();
        }
    }

    async function handleExternalVaultChange(event) {
        const message = event.data;
        if (!message || (message.type !== "updated" && message.type !== "deleted")) return;
        const restoreVaultFocus = elements.vaultForm.contains(document.activeElement);
        confirmation.cancelPending({ restoreFocus: false });
        const wasBoundToVault = state.vault.exists || state.vault.unlocked || Boolean(state.vault.vaultId);
        const preserveTemporaryData = state.vault.temporaryConflict
            || (!wasBoundToVault && (state.accounts.size > 0 || state.migrationBatches.size > 0));
        const operationId = beginVaultOperation();
        state.importGeneration += 1;
        stopCamera(false);
        releaseVaultSession(false);
        if (!preserveTemporaryData && wasBoundToVault) clearRuntimeSensitiveState();
        try {
            await state.vault.mutationQueue;
            assertVaultOperation(operationId);
            const storedRecord = await readVaultRecord();
            assertVaultOperation(operationId);
            const invalidRecord = adoptLockedVaultRecord(storedRecord.exists, storedRecord.value);
            state.vault.initialized = true;
            const hasTemporaryData = preserveTemporaryData && (state.accounts.size > 0 || state.migrationBatches.size > 0);
            state.vault.temporaryConflict = Boolean(storedRecord.exists && hasTemporaryData);
            if (hasTemporaryData) {
                setVaultStatus(storedRecord.exists
                    ? "另一标签页已更改加密存储；当前临时账户已保留。清空临时账户后可解锁现有存储。"
                    : "另一标签页已删除加密存储；当前临时账户仍保留在本页内存中。", "warning");
                setScanStatus("检测到跨标签页变更，未保存的临时账户未被清除。", "warning");
            } else if (invalidRecord) {
                setVaultStatus(state.vault.recordSnapshot
                    ? "另一标签页写入了损坏或不受支持的加密存储；可删除后重新创建。"
                    : "另一标签页写入了无法安全核对的损坏记录，请从浏览器站点数据中删除。", "error");
                setScanStatus("检测到跨标签页变更，当前页面已锁定。", "warning");
            } else {
                setVaultStatus(storedRecord.exists
                    ? "加密存储已在另一标签页中更新，请重新解锁。"
                    : "加密存储已在另一标签页中删除。", "warning");
                setScanStatus("检测到另一标签页修改了加密存储，当前页面已安全锁定。", "warning");
            }
        } catch (error) {
            if (isCurrentVaultOperation(operationId)) {
                setVaultStatus(error.message || "无法同步另一标签页的加密存储状态。", "error");
            }
        } finally {
            finishVaultOperation(operationId);
            if (restoreVaultFocus && elements.vaultForm.hidden && !elements.vaultToggle.disabled) {
                elements.vaultToggle.focus();
            }
        }
    }

    async function initializeVault() {
        state.vault.initialized = false;
        const operationId = beginVaultOperation();
        try {
            if (state.framed || !state.cryptoAvailable) {
                setVaultStatus(state.framed
                    ? "嵌入式页面中已禁用加密存储。"
                    : "需要安全上下文和 Web Crypto 才能使用加密存储。", "error");
                return;
            }
            if (!state.vault.available) {
                setVaultStatus("当前浏览器不支持 IndexedDB，账户只能保留在内存中。", "error");
                return;
            }
            const storedRecord = await readVaultRecord();
            assertVaultOperation(operationId);
            const invalidRecord = adoptLockedVaultRecord(storedRecord.exists, storedRecord.value);
            if (!state.vault.channel && typeof globalThis.BroadcastChannel === "function") {
                state.vault.channel = new BroadcastChannel(`${VAULT_DB_NAME}-changes`);
                state.vault.channel.addEventListener("message", handleExternalVaultChange);
            }
            if (invalidRecord) {
                setVaultStatus(state.vault.recordSnapshot
                    ? "检测到损坏或不受支持的加密存储；可删除后重新创建。"
                    : "检测到无法安全核对的损坏记录，请从浏览器站点数据中删除。", "error");
            } else {
                setVaultStatus(storedRecord.exists
                    ? (getVaultPrfSlots().length > 0
                        ? "检测到已加密账户，可使用通行密钥或主密码解锁。"
                        : "检测到已加密账户，请输入主密码解锁。")
                    : "账户仍处于临时内存模式。", "info");
            }
        } catch (error) {
            if (isCurrentVaultOperation(operationId)) {
                state.vault.available = false;
                setVaultStatus(error.message || "无法读取本机加密存储。", "error");
            }
        } finally {
            if (isCurrentVaultOperation(operationId)) {
                state.vault.initialized = true;
                finishVaultOperation(operationId);
            }
        }
    }

    function disposeSensitiveState() {
        clearRuntimeSensitiveState();
        releaseVaultSession();
        state.vault.busy = false;
        renderVaultState();
        setScanStatus("扫描状态已清除。", "info");
    }

    elements.vaultPassword.addEventListener("pointerdown", enableVaultPasswordInput);
    elements.vaultPassword.addEventListener("focus", enableVaultPasswordInput);
    elements.vaultToggle.addEventListener("click", () => {
        const open = elements.vaultToggle.getAttribute("aria-expanded") !== "true";
        setVaultControlsOpen(open, open);
    });
    elements.vaultForm.addEventListener("submit", (event) => void handleVaultSubmit(event));
    elements.vaultPasskey.addEventListener("click", () => void handleVaultPasskey());
    elements.vaultLock.addEventListener("click", () => void lockVault());
    elements.vaultRemovePasskey.addEventListener("click", () => void handleRemoveVaultPasskey());
    elements.vaultDelete.addEventListener("click", () => void deleteVault());
    elements.importToggle.addEventListener("click", handleImportToggle);
    elements.importClose.addEventListener("click", () => closeImportPanel(true));
    elements.importDialog.addEventListener("cancel", (event) => {
        event.preventDefault();
        closeImportPanel(true);
    });
    elements.importDialog.addEventListener("close", () => {
        if (suppressedImportCloseEvents > 0) {
            suppressedImportCloseEvents -= 1;
            return;
        }
        if (state.importPanelOpen) closeImportPanel(true);
    });
    const isImportBackdropPointer = (event) => {
        const bounds = elements.importDialog.getBoundingClientRect();
        return event.clientX < bounds.left || event.clientX > bounds.right
            || event.clientY < bounds.top || event.clientY > bounds.bottom;
    };
    elements.importDialog.addEventListener("pointerdown", (event) => {
        importBackdropPressed = event.isPrimary && event.button === 0 && isImportBackdropPointer(event);
    });
    elements.importDialog.addEventListener("pointerup", (event) => {
        const shouldClose = importBackdropPressed && event.isPrimary && isImportBackdropPointer(event);
        importBackdropPressed = false;
        if (shouldClose) closeImportPanel(true);
    });
    elements.importDialog.addEventListener("pointercancel", () => {
        importBackdropPressed = false;
    });
    elements.qrFiles.addEventListener("change", () => void scanImageFiles(elements.qrFiles.files || []));
    elements.uploadScanLabel.addEventListener("keydown", (event) => {
        if ((event.key === "Enter" || event.key === " ") && !elements.qrFiles.disabled) {
            event.preventDefault();
            elements.qrFiles.click();
        }
    });
    elements.startCamera.addEventListener("click", () => void startCamera());
    elements.stopCamera.addEventListener("click", () => stopCamera());
    elements.importRawValue.addEventListener("click", () => void importRawValues());
    elements.clearAccounts.addEventListener("click", () => void clearImportedAccounts());
    exportElements.close.addEventListener("click", () => closeAccountExport(true));
    exportElements.dialog.addEventListener("close", () => {
        if (exportClosing) return;
        const opener = exportOpener;
        resetAccountExport();
        if (opener?.isConnected) opener.focus();
    });
    exportElements.copyUri.addEventListener("click", () => {
        void copyExportValue(exportElements.uri.value, exportElements.copyUri, "认证链接已复制");
    });
    exportElements.copySecret.addEventListener("click", () => {
        void copyExportValue(exportElements.secret.value, exportElements.copySecret, "Base32 密钥已复制");
    });
    exportElements.downloadQr.addEventListener("click", downloadExportQr);

    elements.accountsList.addEventListener("click", (event) => {
        if (!(event.target instanceof Element)) return;
        const button = event.target.closest("button[data-action][data-account-id]");
        if (!button || !elements.accountsList.contains(button)) return;
        const accountId = Number(button.dataset.accountId);
        if (!Number.isSafeInteger(accountId)) return;
        const account = state.accounts.get(accountId);
        if (!account) return;
        if (button.dataset.action === "copy") {
            void copyText(account.currentCode, button);
        } else if (button.dataset.action === "export") {
            void openAccountExport(account, button).catch((error) => {
                setScanStatus(error.message || "无法导出该账户。", "error");
            });
        } else if (button.dataset.action === "remove") {
            void removeImportedAccount(accountId, button).then((removed) => {
                if (removed) {
                    const nextAction = elements.accountsList.querySelector("button[data-action]");
                    (nextAction || elements.accountsTitle).focus();
                }
                if (removed && state.migrationBatches.size === 0) {
                    setScanStatus(state.vault.unlocked ? "账户已从页面和加密存储中删除。" : "账户已从当前页面内存中删除。", "info");
                }
            }).catch((error) => {
                if (button.isConnected) button.disabled = false;
                setScanStatus(error.message || "无法删除账户，加密存储未被修改。", "error");
            });
        }
    });
    document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
            confirmation.cancelPending({ restoreFocus: false });
            closeAccountExport(false);
            closeImportPanel(false);
            setVaultControlsOpen(false, false);
            return;
        }
        updateClock();
    });
    window.addEventListener("pagehide", disposeSensitiveState);
    window.addEventListener("pageshow", (event) => {
        resetVaultPasswordInput();
        if (event.persisted && !state.framed) void initializeVault();
    });

    resetVaultPasswordInput();
    renderAccountsState();
    renderVaultState();
    if (state.framed) {
        state.vault.initialized = true;
        disposeSensitiveState();
        for (const control of document.querySelectorAll("button, input, select, textarea")) control.disabled = true;
        elements.uploadScanLabel.setAttribute("aria-disabled", "true");
        elements.uploadScanLabel.tabIndex = -1;
        setScanStatus("嵌入式页面中的扫描功能已禁用。", "error");
        setVaultStatus("嵌入式页面中已禁用加密存储。", "error");
    } else {
        updateClock();
        window.setInterval(updateClock, 250);
        if (!state.cryptoAvailable) {
            setScanStatus("当前地址不是安全上下文，无法生成验证码。请在本机使用 localhost / 127.0.0.1，其他设备请使用 HTTPS。", "error");
        }
        void initializeVault();
    }
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        ALGORITHMS,
        BASE32_ALPHABET,
        DEFAULT_ALGORITHM,
        DEFAULT_DIGITS,
        DEFAULT_PERIOD,
        ProtobufReader,
        VAULT_FORMAT,
        VAULT_KDF_ITERATIONS,
        VAULT_VERSION,
        buildVaultRecord,
        counterToBytes,
        createPasswordUnlockSlot,
        createPrfUnlockSlot,
        decodeBase64Url,
        decodeBase64Payload,
        decodeBase32,
        decryptVaultRecord,
        decryptVaultRecordWithPrf,
        derivePasswordKek,
        derivePrfKek,
        encodeBase32,
        encodeBase64Url,
        encryptVaultPayload,
        evaluateWebAuthnPrf,
        extractWebAuthnPrfOutput,
        formatCode,
        generateTotp,
        getMigrationPartFingerprint,
        getQrScanRegions,
        getTimeWindow,
        normalizeAlgorithm,
        normalizeBase32,
        normalizeMigrationAccount,
        normalizeVaultPassword,
        parseMigrationOtpParameters,
        parseMigrationPayload,
        parseMigrationUri,
            createConfirmationController,
            buildOtpAuthUri,
            parseOtpAuthUri,
        registerWebAuthnPrf,
        stageMigrationPart,
        importVaultDek,
        validateVaultRecord,
        validateDigits,
        validatePeriod
    };
}
