"use strict";

const CHARACTER_SETS = Object.freeze({
    lower: "abcdefghijklmnopqrstuvwxyz",
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    numbers: "0123456789",
    symbols: "!@#$%^&*()-_=+[]{};:,.?"
});

const AMBIGUOUS_CHARACTERS = new Set("Il1O0o|");
const STORAGE_KEY = "password-generator.preferences.v1";
const MIN_LENGTH = 4;
const MAX_LENGTH = 128;
const MIN_QUANTITY = 1;
const MAX_QUANTITY = 10;

function secureRandomInt(maxExclusive, cryptoSource = globalThis.crypto) {
    if (!Number.isInteger(maxExclusive) || maxExclusive < 1 || maxExclusive > 0x100000000) {
        throw new RangeError("随机数范围无效");
    }
    if (!cryptoSource?.getRandomValues) {
        throw new Error("当前浏览器不支持安全随机数生成");
    }

    const range = 0x100000000;
    const limit = range - (range % maxExclusive);
    const buffer = new Uint32Array(1);
    let value;

    do {
        cryptoSource.getRandomValues(buffer);
        value = buffer[0];
    } while (value >= limit);

    return value % maxExclusive;
}

function filterAmbiguousCharacters(characters) {
    return Array.from(characters).filter((character) => !AMBIGUOUS_CHARACTERS.has(character)).join("");
}

function buildCharacterGroups(selectedTypes, excludeAmbiguous) {
    return selectedTypes.map((type) => {
        const characters = CHARACTER_SETS[type];
        if (!characters) throw new Error(`未知字符类型：${type}`);
        return excludeAmbiguous ? filterAmbiguousCharacters(characters) : characters;
    });
}

function secureShuffle(values, cryptoSource = globalThis.crypto) {
    for (let index = values.length - 1; index > 0; index -= 1) {
        const randomIndex = secureRandomInt(index + 1, cryptoSource);
        [values[index], values[randomIndex]] = [values[randomIndex], values[index]];
    }
    return values;
}

function generatePassword(length, characterGroups, ensureEach, cryptoSource = globalThis.crypto) {
    if (!Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
        throw new RangeError(`密码长度必须在 ${MIN_LENGTH} 至 ${MAX_LENGTH} 之间`);
    }
    if (!Array.isArray(characterGroups) || characterGroups.length === 0) {
        throw new Error("请至少选择一种字符类型");
    }
    if (ensureEach && length < characterGroups.length) {
        throw new Error("密码长度不能小于已选择的字符类型数量");
    }

    const pool = characterGroups.join("");
    if (pool.length === 0) throw new Error("可用字符集为空");
    const password = [];

    if (ensureEach) {
        for (const group of characterGroups) {
            password.push(group[secureRandomInt(group.length, cryptoSource)]);
        }
    }

    while (password.length < length) {
        password.push(pool[secureRandomInt(pool.length, cryptoSource)]);
    }

    return secureShuffle(password, cryptoSource).join("");
}

function estimateEntropy(length, poolSize) {
    if (length <= 0 || poolSize <= 1) return 0;
    return length * Math.log2(poolSize);
}

function getStrength(entropy) {
    if (entropy < 40) return { label: "较弱", progress: 25 };
    if (entropy < 60) return { label: "一般", progress: 48 };
    if (entropy < 80) return { label: "较强", progress: 72 };
    return { label: "很强", progress: 100 };
}

if (typeof document !== "undefined") {
    const elements = {};
    let currentPasswords = [];
    let passwordsHidden = false;

    document.addEventListener("DOMContentLoaded", initialize);

    function initialize() {
        elements.form = document.getElementById("settings-form");
        elements.lengthRange = document.getElementById("length-range");
        elements.lengthNumber = document.getElementById("length-number");
        elements.quantity = document.getElementById("quantity");
        elements.excludeAmbiguous = document.getElementById("exclude-ambiguous");
        elements.ensureEach = document.getElementById("ensure-each");
        elements.typeCheckboxes = Array.from(document.querySelectorAll('input[name="character-type"]'));
        elements.presetButtons = Array.from(document.querySelectorAll("[data-length]"));
        elements.passwordList = document.getElementById("password-list");
        elements.status = document.getElementById("status");
        elements.toggleVisibility = document.getElementById("toggle-visibility");
        elements.copyAll = document.getElementById("copy-all");
        elements.regenerate = document.getElementById("regenerate");
        elements.entropyValue = document.getElementById("entropy-value");
        elements.poolSize = document.getElementById("pool-size");
        elements.strengthLabel = document.getElementById("strength-label");
        elements.strengthFill = document.getElementById("strength-fill");

        restorePreferences();
        bindEvents();
        generateAll();
    }

    function bindEvents() {
        elements.form.addEventListener("submit", (event) => {
            event.preventDefault();
            generateAll();
        });

        elements.lengthRange.addEventListener("input", () => {
            setLength(Number(elements.lengthRange.value));
            generateAll();
        });

        elements.lengthNumber.addEventListener("change", () => {
            setLength(clampNumber(elements.lengthNumber.value, MIN_LENGTH, MAX_LENGTH, 20));
            generateAll();
        });

        elements.quantity.addEventListener("change", () => {
            elements.quantity.value = String(clampNumber(elements.quantity.value, MIN_QUANTITY, MAX_QUANTITY, 3));
            generateAll();
        });

        for (const checkbox of [...elements.typeCheckboxes, elements.excludeAmbiguous, elements.ensureEach]) {
            checkbox.addEventListener("change", () => {
                if (elements.typeCheckboxes.every((item) => !item.checked)) {
                    checkbox.checked = true;
                    setStatus("请至少保留一种字符类型。", "error");
                    return;
                }
                generateAll();
            });
        }

        for (const button of elements.presetButtons) {
            button.addEventListener("click", () => {
                setLength(Number(button.dataset.length));
                generateAll();
            });
        }

        elements.regenerate.addEventListener("click", generateAll);
        elements.toggleVisibility.addEventListener("click", togglePasswordVisibility);
        elements.copyAll.addEventListener("click", copyAllPasswords);
        elements.passwordList.addEventListener("click", handlePasswordListClick);
    }

    function clampNumber(rawValue, minimum, maximum, fallback) {
        const value = Number.parseInt(rawValue, 10);
        if (!Number.isFinite(value)) return fallback;
        return Math.min(maximum, Math.max(minimum, value));
    }

    function setLength(length) {
        const safeLength = clampNumber(length, MIN_LENGTH, MAX_LENGTH, 20);
        elements.lengthRange.value = String(safeLength);
        elements.lengthNumber.value = String(safeLength);
        elements.presetButtons.forEach((button) => {
            button.classList.toggle("active", Number(button.dataset.length) === safeLength);
        });
    }

    function getSettings() {
        const selectedTypes = elements.typeCheckboxes
            .filter((checkbox) => checkbox.checked)
            .map((checkbox) => checkbox.value);

        return {
            length: clampNumber(elements.lengthNumber.value, MIN_LENGTH, MAX_LENGTH, 20),
            quantity: clampNumber(elements.quantity.value, MIN_QUANTITY, MAX_QUANTITY, 3),
            selectedTypes,
            excludeAmbiguous: elements.excludeAmbiguous.checked,
            ensureEach: elements.ensureEach.checked
        };
    }

    function generateAll() {
        try {
            const settings = getSettings();
            setLength(settings.length);
            elements.quantity.value = String(settings.quantity);
            const groups = buildCharacterGroups(settings.selectedTypes, settings.excludeAmbiguous);
            currentPasswords = Array.from({ length: settings.quantity }, () => (
                generatePassword(settings.length, groups, settings.ensureEach)
            ));
            renderPasswords();
            updateStrength(settings.length, groups.join("").length);
            savePreferences(settings);
            setStatus(`已安全生成 ${settings.quantity} 个 ${settings.length} 位密码。`, "success");
        } catch (error) {
            currentPasswords = [];
            renderPasswords();
            updateStrength(0, 0);
            setStatus(error.message || "密码生成失败，请检查设置。", "error");
        }
    }

    function renderPasswords() {
        const fragment = document.createDocumentFragment();

        currentPasswords.forEach((password, index) => {
            const row = document.createElement("li");
            const value = document.createElement("code");
            const copyButton = document.createElement("button");

            row.className = "password-row";
            value.className = `password-value${passwordsHidden ? " masked" : ""}`;
            value.textContent = passwordsHidden ? maskPassword(password) : password;
            value.setAttribute("aria-label", passwordsHidden ? `第 ${index + 1} 个密码已隐藏` : `第 ${index + 1} 个密码`);

            copyButton.type = "button";
            copyButton.className = "copy-button";
            copyButton.dataset.index = String(index);
            copyButton.textContent = "复制";
            copyButton.setAttribute("aria-label", `复制第 ${index + 1} 个密码`);

            row.append(value, copyButton);
            fragment.appendChild(row);
        });

        elements.passwordList.replaceChildren(fragment);
        elements.copyAll.disabled = currentPasswords.length === 0;
        elements.toggleVisibility.disabled = currentPasswords.length === 0;
    }

    function maskPassword(password) {
        const visibleLength = Math.min(password.length, 36);
        return `${"•".repeat(visibleLength)}${password.length > visibleLength ? "…" : ""}`;
    }

    function togglePasswordVisibility() {
        passwordsHidden = !passwordsHidden;
        elements.toggleVisibility.setAttribute("aria-pressed", String(passwordsHidden));
        elements.toggleVisibility.textContent = passwordsHidden ? "显示密码" : "隐藏密码";
        renderPasswords();
    }

    async function handlePasswordListClick(event) {
        const button = event.target.closest(".copy-button");
        if (!button) return;
        const index = Number(button.dataset.index);
        const password = currentPasswords[index];
        if (typeof password !== "string") return;

        if (await copyText(password)) {
            const originalText = button.textContent;
            button.textContent = "已复制";
            setStatus(`第 ${index + 1} 个密码已复制到剪贴板。`, "success");
            window.setTimeout(() => { button.textContent = originalText; }, 1200);
        }
    }

    async function copyAllPasswords() {
        if (currentPasswords.length === 0) return;
        if (await copyText(currentPasswords.join("\n"))) {
            setStatus(`${currentPasswords.length} 个密码已全部复制到剪贴板。`, "success");
        }
    }

    async function copyText(text) {
        try {
            if (navigator.clipboard?.writeText) {
                await navigator.clipboard.writeText(text);
            } else {
                const textarea = document.createElement("textarea");
                textarea.value = text;
                textarea.setAttribute("readonly", "");
                textarea.style.position = "fixed";
                textarea.style.opacity = "0";
                document.body.appendChild(textarea);
                textarea.select();
                const copied = document.execCommand("copy");
                textarea.remove();
                if (!copied) throw new Error("copy failed");
            }
            return true;
        } catch {
            setStatus("无法自动复制，请手动选择密码后复制。", "error");
            return false;
        }
    }

    function updateStrength(length, poolSize) {
        const entropy = estimateEntropy(length, poolSize);
        const strength = getStrength(entropy);
        elements.entropyValue.textContent = entropy > 0 ? entropy.toFixed(1) : "—";
        elements.poolSize.textContent = poolSize > 0 ? String(poolSize) : "—";
        elements.strengthLabel.textContent = entropy > 0 ? strength.label : "—";
        elements.strengthFill.style.width = entropy > 0 ? `${strength.progress}%` : "0%";
    }

    function setStatus(message, type) {
        elements.status.textContent = message;
        elements.status.className = `status status-${type}`;
    }

    function savePreferences(settings) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
        } catch {
            // Preferences are optional when browser storage is unavailable.
        }
    }

    function restorePreferences() {
        try {
            const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
            if (!saved) return;

            setLength(clampNumber(saved.length, MIN_LENGTH, MAX_LENGTH, 20));
            elements.quantity.value = String(clampNumber(saved.quantity, MIN_QUANTITY, MAX_QUANTITY, 3));
            elements.excludeAmbiguous.checked = saved.excludeAmbiguous !== false;
            elements.ensureEach.checked = saved.ensureEach !== false;

            const validSavedTypes = Array.isArray(saved.selectedTypes)
                ? saved.selectedTypes.filter((type) => Object.hasOwn(CHARACTER_SETS, type))
                : [];

            if (validSavedTypes.length > 0) {
                elements.typeCheckboxes.forEach((checkbox) => {
                    checkbox.checked = validSavedTypes.includes(checkbox.value);
                });
            }
        } catch {
            // Invalid saved preferences are ignored.
        }
    }
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        AMBIGUOUS_CHARACTERS,
        CHARACTER_SETS,
        buildCharacterGroups,
        estimateEntropy,
        generatePassword,
        getStrength,
        secureRandomInt,
        secureShuffle
    };
}
