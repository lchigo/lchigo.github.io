"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { createConfirmationController } = require("./app.js");

class FakeElement {
    constructor() {
        this.textContent = "";
        this.dataset = {};
        this.disabled = false;
        this.isConnected = true;
        this.focusCount = 0;
        this.listeners = new Map();
    }

    addEventListener(type, listener) {
        const listeners = this.listeners.get(type) || [];
        listeners.push(listener);
        this.listeners.set(type, listeners);
    }

    dispatch(type, event = {}) {
        for (const listener of this.listeners.get(type) || []) listener(event);
    }

    focus() {
        this.focusCount += 1;
    }
}

class FakeDialog extends FakeElement {
    constructor() {
        super();
        this.open = false;
        this.failOpen = false;
    }

    showModal() {
        if (this.failOpen || this.open) throw new Error("dialog unavailable");
        this.open = true;
    }

    close() {
        if (!this.open) return;
        this.open = false;
        this.dispatch("close");
    }
}

class DeferredCloseDialog extends FakeDialog {
    close() {
        if (!this.open) return;
        this.open = false;
        this.closePending = true;
    }

    flushClose() {
        if (!this.closePending) return;
        this.closePending = false;
        this.dispatch("close");
    }
}

function createFixture(dialog = new FakeDialog()) {
    const title = new FakeElement();
    const message = new FakeElement();
    const detail = new FakeElement();
    const cancelButton = new FakeElement();
    const acceptButton = new FakeElement();
    const opener = new FakeElement();
    const controller = createConfirmationController({
        dialog,
        title,
        message,
        detail,
        cancelButton,
        acceptButton,
        getActiveElement: () => opener
    });
    return { controller, dialog, title, message, detail, cancelButton, acceptButton, opener };
}

test("cancel and Escape resolve false, clear copy, and restore focus", async () => {
    const first = createFixture();
    const firstResult = first.controller.request({
        title: "删除账户？",
        message: "动态账户名称",
        detail: "无法撤销",
        confirmLabel: "删除账户"
    });
    assert.equal(first.dialog.open, true);
    assert.equal(first.cancelButton.focusCount, 1);
    first.cancelButton.dispatch("click");
    assert.equal(await firstResult, false);
    assert.equal(first.opener.focusCount, 1);
    assert.equal(first.title.textContent, "");
    assert.equal(first.message.textContent, "");
    assert.equal(first.detail.textContent, "");

    const second = createFixture();
    const secondResult = second.controller.request({ title: "清空？", message: "全部账户" });
    let prevented = false;
    second.dialog.dispatch("cancel", { preventDefault: () => { prevented = true; } });
    assert.equal(await secondResult, false);
    assert.equal(prevented, true);
    assert.equal(second.dialog.open, false);
});

test("confirmation settles once even when accept is activated repeatedly", async () => {
    const fixture = createFixture();
    const resultPromise = fixture.controller.request({
        title: "确认",
        message: "敏感操作",
        restoreFocusOnAccept: false
    });
    fixture.acceptButton.dispatch("click");
    fixture.acceptButton.dispatch("click");

    let operations = 0;
    if (await resultPromise) operations += 1;
    assert.equal(operations, 1);
    assert.equal(fixture.opener.focusCount, 0);
    assert.equal(fixture.controller.hasPending(), false);
});

test("a second request cannot replace an open confirmation", async () => {
    const fixture = createFixture();
    const first = fixture.controller.request({ title: "第一个", message: "保留" });
    const second = fixture.controller.request({ title: "第二个", message: "不得覆盖" });

    assert.equal(await second, false);
    assert.equal(fixture.title.textContent, "第一个");
    fixture.acceptButton.dispatch("click");
    assert.equal(await first, true);
});

test("a deferred old close event cannot cancel a later confirmation", async () => {
    const dialog = new DeferredCloseDialog();
    const fixture = createFixture(dialog);
    const first = fixture.controller.request({ title: "第一个", message: "确认" });
    fixture.acceptButton.dispatch("click");
    assert.equal(await first, true);

    const blockedWhileClosing = await fixture.controller.request({ title: "过早", message: "不得打开" });
    assert.equal(blockedWhileClosing, false);
    dialog.flushClose();

    const next = fixture.controller.request({ title: "第二个", message: "可以打开" });
    assert.equal(dialog.open, true);
    fixture.cancelButton.dispatch("click");
    dialog.flushClose();
    assert.equal(await next, false);
});

test("an external programmatic dialog close cancels the pending request", async () => {
    const fixture = createFixture();
    const result = fixture.controller.request({ title: "删除", message: "等待" });
    fixture.dialog.close();
    assert.equal(await result, false);
    assert.equal(fixture.controller.hasPending(), false);
});

test("lifecycle cancellation never confirms and can suppress focus restoration", async () => {
    const fixture = createFixture();
    const result = fixture.controller.request({ title: "删除", message: "等待确认" });
    assert.equal(fixture.controller.cancelPending({ restoreFocus: false }), true);
    assert.equal(await result, false);
    assert.equal(fixture.opener.focusCount, 0);
    assert.equal(fixture.dialog.open, false);
});

test("dialog failure is fail-closed", async () => {
    const fixture = createFixture();
    fixture.dialog.failOpen = true;
    const result = await fixture.controller.request({ title: "删除", message: "不会执行" });
    assert.equal(result, false);
    assert.equal(fixture.controller.hasPending(), false);
    assert.equal(fixture.message.textContent, "");
});

test("all sensitive entry points use the local CSP-safe confirmation dialog", () => {
    const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
    const source = fs.readFileSync(path.join(__dirname, "app.js"), "utf8");

    assert.match(html, /<dialog class="confirm-dialog" id="confirm-dialog"/);
    assert.match(html, /id="confirm-cancel"/);
    assert.match(html, /id="confirm-accept"/);
    assert.match(html, /script-src 'self'/);
    assert.doesNotMatch(html, /unsafe-inline|unsafe-eval/i);
    assert.doesNotMatch(source, /window\.confirm\s*\(/);
    assert.doesNotMatch(source, /innerHTML\s*=/);
    assert.ok([...source.matchAll(/confirmation\.request\s*\(/g)].length >= 5);
    assert.ok([...source.matchAll(/confirmation\.cancelPending\s*\(/g)].length >= 3);

    const exportStart = source.indexOf("async function openAccountExport");
    const exportConfirmation = source.indexOf("confirmation.request", exportStart);
    const secretWrite = source.indexOf("exportElements.secret.value", exportStart);
    assert.ok(exportStart >= 0 && exportConfirmation > exportStart && secretWrite > exportConfirmation);

    const clearStart = source.indexOf("async function clearImportedAccounts");
    const clearQueue = source.indexOf("enqueueAccountMutation(async () => {", clearStart);
    const queuedRevalidation = source.indexOf("if (!confirmedScopeIsCurrent())", clearQueue);
    const clearPersistence = source.indexOf("await persistVaultAccounts([])", clearQueue);
    assert.ok(clearStart >= 0 && clearQueue > clearStart);
    assert.ok(queuedRevalidation > clearQueue && clearPersistence > queuedRevalidation);
});
