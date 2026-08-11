const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = __dirname;
const html = fs.readFileSync(path.join(root, "index.html"), "utf8");
const css = fs.readFileSync(path.join(root, "styles.css"), "utf8");
const app = fs.readFileSync(path.join(root, "app.js"), "utf8");

test("accounts are the single primary panel and contain the compact vault", () => {
    assert.match(html, /<title>2FA Auth 工具<\/title>/);
    assert.match(html, /<h1 id="page-title">2FA Auth<br>工具<\/h1>/);
    assert.equal((html.match(/class="accounts-panel panel"/g) || []).length, 1);
    assert.equal(html.includes("class=\"scanner-panel panel\""), false);
    assert.equal(html.includes("class=\"vault-panel panel\""), false);
    assert.ok(html.indexOf('id="accounts-title"') < html.indexOf('id="vault-toggle"'));
    assert.ok(html.indexOf('id="vault-toggle"') < html.indexOf('id="accounts-list"'));
    assert.match(html, /id="vault-toggle"[^>]+aria-expanded="false"[^>]+aria-controls="vault-form"/);
    assert.match(html, /<form class="vault-form" id="vault-form"[^>]+hidden>/);
});

test("the account importer is opened from one accessible floating action button", () => {
    assert.equal((html.match(/id="import-toggle"/g) || []).length, 1);
    assert.equal((html.match(/id="import-dialog"/g) || []).length, 1);
    assert.match(html, /id="import-toggle"[^>]+aria-haspopup="dialog"[^>]+aria-controls="import-dialog"[^>]+aria-expanded="false"/);
    assert.match(html, /<dialog class="import-dialog" id="import-dialog"/);
    assert.match(css, /\.import-fab\s*\{[^}]*position:\s*fixed;/s);
    assert.match(css, /\.import-dialog:not\(\[open\]\)\s*\{[^}]*display:\s*none;/s);
    assert.match(css, /@media \(max-width: 720px\)[\s\S]*?\.import-dialog \.scanner-grid\s*\{[^}]*grid-template-columns:\s*1fr;/);
});

test("closing the importer cancels local work and clears sensitive draft input", () => {
    const closeStart = app.indexOf("function closeImportPanel(");
    const openStart = app.indexOf("function openImportPanel(", closeStart);
    assert.ok(closeStart >= 0 && openStart > closeStart);
    const closeBody = app.slice(closeStart, openStart);
    assert.match(closeBody, /state\.importGeneration \+= 1/);
    assert.match(closeBody, /state\.importActivity = null/);
    assert.match(closeBody, /stopCamera\(false\)/);
    assert.match(closeBody, /elements\.qrFiles\.value = ""/);
    assert.match(closeBody, /removeAttribute\("aria-busy"\)/);
    assert.match(closeBody, /elements\.rawImportValue\.value = ""/);
    assert.match(app, /visibilitychange[\s\S]*closeImportPanel\(false\)/);
    assert.match(app, /function clearRuntimeSensitiveState\(\)[\s\S]*closeImportPanel\(false\)/);
});

test("backdrop clicks and successful imports close the importer", () => {
    assert.match(app, /getBoundingClientRect\(\)[\s\S]*elements\.importDialog\.addEventListener\("pointerdown"/);
    assert.match(app, /elements\.importDialog\.addEventListener\("pointerup"[\s\S]*isImportBackdropPointer\(event\)[\s\S]*closeImportPanel\(true\)/);
    assert.match(app, /function closeImportPanelAfterSuccess\(addedCount\)[\s\S]*state\.migrationBatches\.size > 0[\s\S]*closeImportPanel\(false\)/);
    assert.match(app, /errorCount === 0[\s\S]*closeImportPanelAfterSuccess\(addedCount\)/);
    assert.match(app, /failed === 0[\s\S]*closeImportPanelAfterSuccess\(added\)/);
    assert.match(app, /closeImportPanelAfterSuccess\(result\.added\)/);
});

test("compact UI keeps the strict local-only CSP", () => {
    const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1] || "";
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /script-src 'self'/);
    assert.match(csp, /style-src 'self'/);
    assert.match(csp, /connect-src 'none'/);
    assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|https?:|data:|blob:/);
});
