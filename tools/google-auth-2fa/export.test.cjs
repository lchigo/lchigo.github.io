"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const app = require("./app.js");
const jsQR = require("./vendor/jsQR-1.4.0.js");

function loadQrEncoder() {
    const source = fs.readFileSync(
        path.join(__dirname, "vendor", "qrcodegen-v1.8.0-es6.js"),
        "utf8"
    );
    const context = {};
    vm.createContext(context);
    vm.runInContext(source, context, { filename: "qrcodegen-v1.8.0-es6.js" });
    return context.qrcodegen;
}

function rasterizeQr(qr, scale = 6, quietZone = 4) {
    const size = (qr.size + quietZone * 2) * scale;
    const rgba = new Uint8ClampedArray(size * size * 4);
    rgba.fill(255);

    for (let y = 0; y < qr.size; y += 1) {
        for (let x = 0; x < qr.size; x += 1) {
            if (!qr.getModule(x, y)) continue;
            const startX = (x + quietZone) * scale;
            const startY = (y + quietZone) * scale;
            for (let py = 0; py < scale; py += 1) {
                for (let px = 0; px < scale; px += 1) {
                    const offset = ((startY + py) * size + startX + px) * 4;
                    rgba[offset] = 0;
                    rgba[offset + 1] = 0;
                    rgba[offset + 2] = 0;
                }
            }
        }
    }

    return { rgba, size };
}

test("otpauth export preserves Unicode labels and all TOTP parameters", () => {
    const uri = app.buildOtpAuthUri({
        secret: "JBSW Y3DP-EHPK3PXP",
        issuer: "示例 /?&+#%",
        account: "alice:测试/+?&#%",
        algorithm: "SHA-256",
        digits: 8,
        period: 45
    });
    const parsed = app.parseOtpAuthUri(uri);

    assert.equal(parsed.secret, "JBSWY3DPEHPK3PXP");
    assert.equal(parsed.issuer, "示例 /?&+#%");
    assert.equal(parsed.account, "alice:测试/+?&#%");
    assert.equal(parsed.algorithm, "SHA256");
    assert.equal(parsed.digits, 8);
    assert.equal(parsed.period, 45);
});

test("otpauth export keeps an issuer containing a colon unambiguous", () => {
    const uri = app.buildOtpAuthUri({
        secret: "JBSWY3DPEHPK3PXP",
        issuer: "Example:Operations",
        account: "alice@example.com",
        algorithm: "SHA1",
        digits: 6,
        period: 30
    });
    const parsed = app.parseOtpAuthUri(uri);

    assert.equal(parsed.issuer, "Example:Operations");
    assert.equal(parsed.account, "alice@example.com");
});

test("locally generated QR decodes to the exact otpauth link", () => {
    const uri = app.buildOtpAuthUri({
        secret: "JBSWY3DPEHPK3PXP",
        issuer: "Example",
        account: "alice@example.com",
        algorithm: "SHA1",
        digits: 6,
        period: 30
    });
    const qrcodegen = loadQrEncoder();
    const qr = qrcodegen.QrCode.encodeText(uri, qrcodegen.QrCode.Ecc.MEDIUM);
    const { rgba, size } = rasterizeQr(qr);
    const decoded = jsQR(rgba, size, size, { inversionAttempts: "dontInvert" });

    assert.ok(decoded, "generated QR should be readable by the bundled decoder");
    assert.equal(decoded.data, uri);
});

test("export keeps the existing strict CSP and local-only scripts", () => {
    const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
    const appSource = fs.readFileSync(path.join(__dirname, "app.js"), "utf8");

    assert.match(html, /script-src 'self'/);
    assert.doesNotMatch(html, /unsafe-inline|unsafe-eval|https?:\/\//i);
    assert.match(html, /src="vendor\/qrcodegen-v1\.8\.0-es6\.js"/);
    assert.doesNotMatch(appSource, /dataset\.(?:secret|uri)\s*=/);
    assert.doesNotMatch(appSource, /innerHTML\s*=/);
});
