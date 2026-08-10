"use strict";

const MAGIC = new TextEncoder().encode("STEGIMG1");
const FORMAT_VERSION = 1;
const PBKDF2_ITERATIONS = 250000;
const MIN_ACCEPTED_ITERATIONS = 100000;
const MAX_ACCEPTED_ITERATIONS = 1000000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const GCM_TAG_LENGTH = 16;
const HEADER_LENGTH = MAGIC.length + 1 + 4 + SALT_LENGTH + IV_LENGTH + 4;
const MAX_PIXELS = 20000000;
const MAX_METADATA_LENGTH = 65536;

function concatBytes(...parts) {
    const length = parts.reduce((total, part) => total + part.length, 0);
    const result = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }
    return result;
}

function buildHeader(iterations, salt, iv, ciphertextLength) {
    const header = new Uint8Array(HEADER_LENGTH);
    const view = new DataView(header.buffer);
    let offset = 0;

    header.set(MAGIC, offset);
    offset += MAGIC.length;
    header[offset] = FORMAT_VERSION;
    offset += 1;
    view.setUint32(offset, iterations, false);
    offset += 4;
    header.set(salt, offset);
    offset += SALT_LENGTH;
    header.set(iv, offset);
    offset += IV_LENGTH;
    view.setUint32(offset, ciphertextLength, false);
    return header;
}

function parseHeader(headerBytes) {
    if (!(headerBytes instanceof Uint8Array) || headerBytes.length < HEADER_LENGTH) {
        throw new Error("图片中没有完整的隐写头部");
    }

    for (let index = 0; index < MAGIC.length; index += 1) {
        if (headerBytes[index] !== MAGIC[index]) throw new Error("未检测到本工具生成的隐写数据");
    }

    const view = new DataView(headerBytes.buffer, headerBytes.byteOffset, headerBytes.byteLength);
    let offset = MAGIC.length;
    const version = headerBytes[offset];
    offset += 1;
    if (version !== FORMAT_VERSION) throw new Error(`不支持的隐写格式版本：${version}`);

    const iterations = view.getUint32(offset, false);
    offset += 4;
    if (iterations < MIN_ACCEPTED_ITERATIONS || iterations > MAX_ACCEPTED_ITERATIONS) {
        throw new Error("隐写数据的密钥派生参数无效");
    }

    const salt = headerBytes.slice(offset, offset + SALT_LENGTH);
    offset += SALT_LENGTH;
    const iv = headerBytes.slice(offset, offset + IV_LENGTH);
    offset += IV_LENGTH;
    const ciphertextLength = view.getUint32(offset, false);

    if (ciphertextLength < GCM_TAG_LENGTH + 4) throw new Error("隐写密文长度无效");
    return { version, iterations, salt, iv, ciphertextLength };
}

function createPlaintext(payloadBytes, metadata) {
    if (!(payloadBytes instanceof Uint8Array)) throw new TypeError("载荷必须是 Uint8Array");
    const normalizedMetadata = {
        kind: metadata.kind,
        name: metadata.name,
        mime: metadata.mime || "application/octet-stream",
        size: payloadBytes.length
    };
    const metadataBytes = new TextEncoder().encode(JSON.stringify(normalizedMetadata));
    if (metadataBytes.length > MAX_METADATA_LENGTH) throw new Error("文件元数据过长");

    const plaintext = new Uint8Array(4 + metadataBytes.length + payloadBytes.length);
    new DataView(plaintext.buffer).setUint32(0, metadataBytes.length, false);
    plaintext.set(metadataBytes, 4);
    plaintext.set(payloadBytes, 4 + metadataBytes.length);
    return plaintext;
}

function parsePlaintext(plaintextBytes) {
    if (!(plaintextBytes instanceof Uint8Array) || plaintextBytes.length < 4) {
        throw new Error("解密数据格式无效");
    }

    const metadataLength = new DataView(
        plaintextBytes.buffer,
        plaintextBytes.byteOffset,
        plaintextBytes.byteLength
    ).getUint32(0, false);

    if (metadataLength < 2 || metadataLength > MAX_METADATA_LENGTH || 4 + metadataLength > plaintextBytes.length) {
        throw new Error("解密数据的元信息无效");
    }

    let metadata;
    try {
        metadata = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(
            plaintextBytes.subarray(4, 4 + metadataLength)
        ));
    } catch {
        throw new Error("无法解析解密数据的元信息");
    }

    const payload = plaintextBytes.slice(4 + metadataLength);
    if (!metadata || !["text", "file"].includes(metadata.kind)) throw new Error("解密内容类型无效");
    if (typeof metadata.name !== "string" || typeof metadata.mime !== "string") throw new Error("解密文件信息无效");
    if (metadata.size !== payload.length) throw new Error("解密内容长度校验失败");
    return { metadata, payload };
}

async function deriveEncryptionKey(password, salt, iterations, usages, cryptoSource = globalThis.crypto) {
    if (!cryptoSource?.subtle || !cryptoSource?.getRandomValues) {
        throw new Error("当前环境不支持 Web Crypto API");
    }

    const passwordBytes = new TextEncoder().encode(password);
    const keyMaterial = await cryptoSource.subtle.importKey(
        "raw",
        passwordBytes,
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return cryptoSource.subtle.deriveKey(
        { name: "PBKDF2", hash: "SHA-256", salt, iterations },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        usages
    );
}

async function encryptContainer(payloadBytes, metadata, password, cryptoSource = globalThis.crypto) {
    if (typeof password !== "string" || password.length < 8) throw new Error("加密密码至少需要 8 位");
    const plaintext = createPlaintext(payloadBytes, metadata);
    const salt = cryptoSource.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = cryptoSource.getRandomValues(new Uint8Array(IV_LENGTH));
    const ciphertextLength = plaintext.length + GCM_TAG_LENGTH;
    const header = buildHeader(PBKDF2_ITERATIONS, salt, iv, ciphertextLength);
    const key = await deriveEncryptionKey(password, salt, PBKDF2_ITERATIONS, ["encrypt"], cryptoSource);
    const ciphertextBuffer = await cryptoSource.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: header, tagLength: 128 },
        key,
        plaintext
    );
    const ciphertext = new Uint8Array(ciphertextBuffer);
    if (ciphertext.length !== ciphertextLength) throw new Error("加密结果长度异常");
    return concatBytes(header, ciphertext);
}

async function decryptContainer(containerBytes, password, cryptoSource = globalThis.crypto) {
    if (typeof password !== "string" || password.length === 0) throw new Error("请输入解密密码");
    const header = containerBytes.slice(0, HEADER_LENGTH);
    const parsedHeader = parseHeader(header);
    const expectedLength = HEADER_LENGTH + parsedHeader.ciphertextLength;
    if (containerBytes.length !== expectedLength) throw new Error("隐写容器长度不匹配");
    const key = await deriveEncryptionKey(
        password,
        parsedHeader.salt,
        parsedHeader.iterations,
        ["decrypt"],
        cryptoSource
    );
    const plaintextBuffer = await cryptoSource.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: parsedHeader.iv,
            additionalData: header,
            tagLength: 128
        },
        key,
        containerBytes.subarray(HEADER_LENGTH)
    );
    return parsePlaintext(new Uint8Array(plaintextBuffer));
}

function getImageCapacity(rgbaPixels) {
    let eligiblePixels = 0;
    for (let index = 3; index < rgbaPixels.length; index += 4) {
        if (rgbaPixels[index] === 255) eligiblePixels += 1;
    }
    return Math.floor((eligiblePixels * 3) / 8);
}

function embedBytes(rgbaPixels, bytes) {
    const capacity = getImageCapacity(rgbaPixels);
    if (bytes.length > capacity) {
        throw new Error(`载体容量不足：需要 ${bytes.length} 字节，可用 ${capacity} 字节`);
    }

    const output = new Uint8ClampedArray(rgbaPixels);
    let bitIndex = 0;
    const totalBits = bytes.length * 8;

    for (let pixelOffset = 0; pixelOffset < output.length && bitIndex < totalBits; pixelOffset += 4) {
        if (output[pixelOffset + 3] !== 255) continue;
        for (let channel = 0; channel < 3 && bitIndex < totalBits; channel += 1) {
            const bit = (bytes[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1;
            output[pixelOffset + channel] = (output[pixelOffset + channel] & 0xfe) | bit;
            bitIndex += 1;
        }
    }

    return output;
}

function extractBytes(rgbaPixels, byteLength) {
    const capacity = getImageCapacity(rgbaPixels);
    if (!Number.isInteger(byteLength) || byteLength < 0 || byteLength > capacity) {
        throw new Error("请求提取的数据长度超出图片容量");
    }

    const output = new Uint8Array(byteLength);
    let bitIndex = 0;
    const totalBits = byteLength * 8;

    for (let pixelOffset = 0; pixelOffset < rgbaPixels.length && bitIndex < totalBits; pixelOffset += 4) {
        if (rgbaPixels[pixelOffset + 3] !== 255) continue;
        for (let channel = 0; channel < 3 && bitIndex < totalBits; channel += 1) {
            output[bitIndex >> 3] |= (rgbaPixels[pixelOffset + channel] & 1) << (7 - (bitIndex & 7));
            bitIndex += 1;
        }
    }

    if (bitIndex !== totalBits) throw new Error("图片中没有足够的可用像素");
    return output;
}

function extractContainer(rgbaPixels) {
    if (getImageCapacity(rgbaPixels) < HEADER_LENGTH) throw new Error("图片尺寸太小，无法包含有效隐写数据");
    const header = extractBytes(rgbaPixels, HEADER_LENGTH);
    const parsedHeader = parseHeader(header);
    const totalLength = HEADER_LENGTH + parsedHeader.ciphertextLength;
    if (totalLength > getImageCapacity(rgbaPixels)) throw new Error("隐写数据长度超过图片容量，文件可能已损坏");
    return extractBytes(rgbaPixels, totalLength);
}

if (typeof document !== "undefined") {
    const elements = {};
    let coverState = null;
    let stegoState = null;
    let coverPreviewUrl = null;
    let outputUrl = null;
    let extractedFileUrl = null;
    let extractedTextValue = "";

    document.addEventListener("DOMContentLoaded", initialize);

    function initialize() {
        elements.tabs = Array.from(document.querySelectorAll("[data-tab]"));
        elements.panels = {
            hide: document.getElementById("hide-panel"),
            extract: document.getElementById("extract-panel")
        };
        elements.hideForm = document.getElementById("hide-form");
        elements.extractForm = document.getElementById("extract-form");
        elements.coverInput = document.getElementById("cover-image");
        elements.coverDropZone = document.getElementById("cover-drop-zone");
        elements.coverSummary = document.getElementById("cover-summary");
        elements.payloadTypes = Array.from(document.querySelectorAll('input[name="payload-type"]'));
        elements.textPayloadField = document.getElementById("text-payload-field");
        elements.filePayloadField = document.getElementById("file-payload-field");
        elements.secretText = document.getElementById("secret-text");
        elements.secretFile = document.getElementById("secret-file");
        elements.secretFileName = document.getElementById("secret-file-name");
        elements.hidePassword = document.getElementById("hide-password");
        elements.hidePasswordConfirm = document.getElementById("hide-password-confirm");
        elements.capacityBox = document.getElementById("capacity-box");
        elements.capacityLabel = document.getElementById("capacity-label");
        elements.capacityFill = document.getElementById("capacity-fill");
        elements.hideButton = document.getElementById("hide-button");
        elements.hideStatus = document.getElementById("hide-status");
        elements.hidePreview = document.getElementById("hide-preview");
        elements.hidePreviewImage = document.getElementById("hide-preview-image");
        elements.hidePreviewEmpty = document.getElementById("hide-preview-empty");
        elements.hideOutputActions = document.getElementById("hide-output-actions");
        elements.outputFileName = document.getElementById("output-file-name");
        elements.outputFileSize = document.getElementById("output-file-size");
        elements.downloadStego = document.getElementById("download-stego");
        elements.stegoInput = document.getElementById("stego-image");
        elements.stegoDropZone = document.getElementById("stego-drop-zone");
        elements.stegoSummary = document.getElementById("stego-summary");
        elements.extractPassword = document.getElementById("extract-password");
        elements.extractButton = document.getElementById("extract-button");
        elements.extractStatus = document.getElementById("extract-status");
        elements.extractResult = document.getElementById("extract-result");
        elements.extractEmpty = document.getElementById("extract-empty");
        elements.textResult = document.getElementById("text-result");
        elements.extractedText = document.getElementById("extracted-text");
        elements.copyExtractedText = document.getElementById("copy-extracted-text");
        elements.fileResult = document.getElementById("file-result");
        elements.extractedFileName = document.getElementById("extracted-file-name");
        elements.extractedFileMeta = document.getElementById("extracted-file-meta");
        elements.downloadExtractedFile = document.getElementById("download-extracted-file");

        bindEvents();
        updatePayloadFields();
        updateCapacity();
    }

    function bindEvents() {
        elements.tabs.forEach((tab) => {
            tab.addEventListener("click", () => activateTab(tab.dataset.tab));
            tab.addEventListener("keydown", handleTabKeydown);
        });
        elements.coverInput.addEventListener("change", () => handleCoverFile(elements.coverInput.files[0]));
        elements.stegoInput.addEventListener("change", () => handleStegoFile(elements.stegoInput.files[0]));
        bindDropZone(elements.coverDropZone, handleCoverFile);
        bindDropZone(elements.stegoDropZone, handleStegoFile);
        elements.payloadTypes.forEach((input) => input.addEventListener("change", () => {
            updatePayloadFields();
            updateCapacity();
        }));
        elements.secretText.addEventListener("input", updateCapacity);
        elements.secretFile.addEventListener("change", () => {
            const file = elements.secretFile.files[0];
            elements.secretFileName.textContent = file ? `${file.name} · ${formatBytes(file.size)}` : "尚未选择文件";
            updateCapacity();
        });
        document.querySelectorAll("[data-password-toggle]").forEach((button) => {
            button.addEventListener("click", () => togglePassword(button));
        });
        elements.hideForm.addEventListener("submit", handleHideSubmit);
        elements.extractForm.addEventListener("submit", handleExtractSubmit);
        elements.copyExtractedText.addEventListener("click", copyExtractedText);
    }

    function activateTab(name) {
        elements.tabs.forEach((tab) => {
            const active = tab.dataset.tab === name;
            tab.classList.toggle("active", active);
            tab.setAttribute("aria-selected", String(active));
            tab.tabIndex = active ? 0 : -1;
        });
        Object.entries(elements.panels).forEach(([panelName, panel]) => {
            panel.hidden = panelName !== name;
        });
    }

    function handleTabKeydown(event) {
        if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
        event.preventDefault();
        const currentIndex = elements.tabs.indexOf(event.currentTarget);
        const direction = event.key === "ArrowRight" ? 1 : -1;
        const nextTab = elements.tabs[(currentIndex + direction + elements.tabs.length) % elements.tabs.length];
        activateTab(nextTab.dataset.tab);
        nextTab.focus();
    }

    function bindDropZone(zone, handler) {
        ["dragenter", "dragover"].forEach((eventName) => {
            zone.addEventListener(eventName, (event) => {
                event.preventDefault();
                zone.classList.add("dragging");
            });
        });
        ["dragleave", "drop"].forEach((eventName) => {
            zone.addEventListener(eventName, (event) => {
                event.preventDefault();
                zone.classList.remove("dragging");
            });
        });
        zone.addEventListener("drop", (event) => handler(event.dataTransfer.files[0]));
    }

    function togglePassword(button) {
        const input = document.getElementById(button.dataset.passwordToggle);
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        button.textContent = show ? "隐藏" : "显示";
        button.setAttribute("aria-label", show ? "隐藏密码" : "显示密码");
    }

    function updatePayloadFields() {
        const type = getPayloadType();
        elements.textPayloadField.hidden = type !== "text";
        elements.filePayloadField.hidden = type !== "file";
    }

    function getPayloadType() {
        return elements.payloadTypes.find((input) => input.checked)?.value || "text";
    }

    async function decodeImageFile(file) {
        if (typeof createImageBitmap === "function") {
            let bitmap;
            try {
                bitmap = await createImageBitmap(file, { imageOrientation: "from-image" });
            } catch {
                bitmap = await createImageBitmap(file);
            }
            return {
                source: bitmap,
                width: bitmap.width,
                height: bitmap.height,
                close: () => bitmap.close()
            };
        }

        const objectUrl = URL.createObjectURL(file);
        const image = new Image();
        image.src = objectUrl;
        try {
            await image.decode();
            return {
                source: image,
                width: image.naturalWidth,
                height: image.naturalHeight,
                close: () => URL.revokeObjectURL(objectUrl)
            };
        } catch (error) {
            URL.revokeObjectURL(objectUrl);
            throw error;
        }
    }

    async function loadImagePixels(file) {
        if (!(file instanceof File) || (file.type && !file.type.startsWith("image/"))) {
            throw new Error("请选择有效的图片文件");
        }
        const decodedImage = await decodeImageFile(file);
        try {
            if (decodedImage.width * decodedImage.height > MAX_PIXELS) {
                throw new Error("图片像素过大，请选择不超过 2000 万像素的图片");
            }
            const canvas = document.createElement("canvas");
            canvas.width = decodedImage.width;
            canvas.height = decodedImage.height;
            const context = canvas.getContext("2d", { willReadFrequently: true });
            context.drawImage(decodedImage.source, 0, 0);
            const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
            return {
                canvas,
                context,
                imageData,
                width: canvas.width,
                height: canvas.height,
                capacity: getImageCapacity(imageData.data)
            };
        } finally {
            decodedImage.close();
        }
    }

    async function handleCoverFile(file) {
        if (!file) return;
        try {
            setStatus(elements.hideStatus, "正在读取图片…", "info");
            coverState = { ...(await loadImagePixels(file)), file };
            elements.coverSummary.hidden = false;
            elements.coverSummary.textContent = `${file.name} · ${coverState.width} × ${coverState.height} · 可用容量 ${formatBytes(coverState.capacity)}`;
            replaceCoverPreview(file);
            resetHideOutput();
            updateCapacity();
            setStatus(elements.hideStatus, "载体图片已就绪，请填写隐藏内容和密码。", "success");
        } catch (error) {
            coverState = null;
            elements.coverSummary.hidden = true;
            updateCapacity();
            setStatus(elements.hideStatus, error.message || "无法读取图片。", "error");
        }
    }

    function replaceCoverPreview(file) {
        if (coverPreviewUrl) URL.revokeObjectURL(coverPreviewUrl);
        coverPreviewUrl = URL.createObjectURL(file);
        elements.hidePreviewImage.src = coverPreviewUrl;
        elements.hidePreviewImage.hidden = false;
        elements.hidePreviewEmpty.hidden = true;
        elements.hidePreview.classList.remove("empty");
    }

    async function handleStegoFile(file) {
        if (!file) return;
        clearExtractResult();
        try {
            setStatus(elements.extractStatus, "正在检查图片…", "info");
            const image = await loadImagePixels(file);
            const container = extractContainer(image.imageData.data);
            stegoState = { ...image, file, container };
            elements.stegoSummary.hidden = false;
            elements.stegoSummary.textContent = `${file.name} · ${image.width} × ${image.height} · 检测到 ${formatBytes(container.length)} 加密数据`;
            setStatus(elements.extractStatus, "检测到有效隐写容器，请输入密码解密。", "success");
        } catch (error) {
            stegoState = null;
            elements.stegoSummary.hidden = false;
            elements.stegoSummary.textContent = file.name;
            setStatus(elements.extractStatus, error.message || "无法读取隐写图片。", "error");
        }
    }

    function getPayloadPreview() {
        const kind = getPayloadType();
        if (kind === "text") {
            const payload = new TextEncoder().encode(elements.secretText.value);
            return {
                kind,
                payload,
                metadata: { kind, name: "message.txt", mime: "text/plain;charset=utf-8" }
            };
        }
        const file = elements.secretFile.files[0];
        return {
            kind,
            payload: null,
            file,
            metadata: file ? { kind, name: file.name, mime: file.type || "application/octet-stream" } : null
        };
    }

    async function getPayloadForEncryption() {
        const preview = getPayloadPreview();
        if (preview.kind === "text") {
            if (preview.payload.length === 0) throw new Error("请输入需要隐藏的文本");
            return preview;
        }
        if (!preview.file) throw new Error("请选择需要隐藏的文件");
        return { ...preview, payload: new Uint8Array(await preview.file.arrayBuffer()) };
    }

    function estimateContainerLength(preview) {
        if (!preview.metadata) return 0;
        const payloadLength = preview.payload?.length ?? preview.file?.size ?? 0;
        const metadataLength = new TextEncoder().encode(JSON.stringify({
            ...preview.metadata,
            size: payloadLength
        })).length;
        return HEADER_LENGTH + GCM_TAG_LENGTH + 4 + metadataLength + payloadLength;
    }

    function updateCapacity() {
        if (!coverState) {
            elements.capacityLabel.textContent = "等待选择图片";
            elements.capacityFill.style.width = "0%";
            elements.capacityBox.classList.remove("over");
            return;
        }
        const estimated = estimateContainerLength(getPayloadPreview());
        const ratio = coverState.capacity > 0 ? estimated / coverState.capacity : 1;
        elements.capacityLabel.textContent = `${formatBytes(estimated)} / ${formatBytes(coverState.capacity)}`;
        elements.capacityFill.style.width = `${Math.min(100, ratio * 100).toFixed(1)}%`;
        elements.capacityBox.classList.toggle("over", ratio > 1);
    }

    async function handleHideSubmit(event) {
        event.preventDefault();
        if (!coverState) {
            setStatus(elements.hideStatus, "请先选择载体图片。", "error");
            return;
        }
        const password = elements.hidePassword.value;
        if (password.length < 8) {
            setStatus(elements.hideStatus, "加密密码至少需要 8 位。", "error");
            return;
        }
        if (password !== elements.hidePasswordConfirm.value) {
            setStatus(elements.hideStatus, "两次输入的密码不一致。", "error");
            return;
        }

        setButtonBusy(elements.hideButton, true, "正在加密并写入…");
        try {
            const payload = await getPayloadForEncryption();
            const container = await encryptContainer(payload.payload, payload.metadata, password);
            if (container.length > coverState.capacity) {
                throw new Error(`图片容量不足：需要 ${formatBytes(container.length)}，可用 ${formatBytes(coverState.capacity)}`);
            }
            const embeddedPixels = embedBytes(coverState.imageData.data, container);
            const outputImageData = new ImageData(embeddedPixels, coverState.width, coverState.height);
            coverState.context.putImageData(outputImageData, 0, 0);
            const blob = await canvasToPngBlob(coverState.canvas);
            showHideOutput(blob, coverState.file.name);
            setStatus(elements.hideStatus, `加密完成，已写入 ${formatBytes(container.length)} 隐写数据。`, "success");
        } catch (error) {
            setStatus(elements.hideStatus, error.message || "隐写加密失败。", "error");
        } finally {
            setButtonBusy(elements.hideButton, false, "加密并写入图片");
        }
    }

    function canvasToPngBlob(canvas) {
        return new Promise((resolve, reject) => {
            canvas.toBlob((blob) => {
                if (blob) resolve(blob);
                else reject(new Error("无法生成 PNG 文件"));
            }, "image/png");
        });
    }

    function showHideOutput(blob, originalName) {
        if (outputUrl) URL.revokeObjectURL(outputUrl);
        outputUrl = URL.createObjectURL(blob);
        const outputName = `${sanitizeFileName(originalName.replace(/\.[^.]+$/, "")) || "image"}-stego.png`;
        elements.hidePreviewImage.src = outputUrl;
        elements.hidePreviewImage.hidden = false;
        elements.hidePreviewEmpty.hidden = true;
        elements.hideOutputActions.hidden = false;
        elements.outputFileName.textContent = outputName;
        elements.outputFileSize.textContent = formatBytes(blob.size);
        elements.downloadStego.href = outputUrl;
        elements.downloadStego.download = outputName;
    }

    function resetHideOutput() {
        if (outputUrl) {
            URL.revokeObjectURL(outputUrl);
            outputUrl = null;
        }
        elements.hideOutputActions.hidden = true;
    }

    async function handleExtractSubmit(event) {
        event.preventDefault();
        if (!stegoState?.container) {
            setStatus(elements.extractStatus, "请先选择包含有效隐写数据的 PNG。", "error");
            return;
        }
        const password = elements.extractPassword.value;
        if (!password) {
            setStatus(elements.extractStatus, "请输入解密密码。", "error");
            return;
        }

        setButtonBusy(elements.extractButton, true, "正在认证并解密…");
        clearExtractResult();
        try {
            const result = await decryptContainer(stegoState.container, password);
            showExtractedResult(result);
            setStatus(elements.extractStatus, `解密成功，已恢复 ${formatBytes(result.payload.length)} 内容。`, "success");
        } catch {
            setStatus(elements.extractStatus, "解密失败：密码错误，或图片中的隐写数据已损坏。", "error");
        } finally {
            setButtonBusy(elements.extractButton, false, "读取并解密内容");
        }
    }

    function showExtractedResult(result) {
        elements.extractEmpty.hidden = true;
        elements.extractResult.classList.remove("empty");
        if (result.metadata.kind === "text") {
            extractedTextValue = new TextDecoder("utf-8", { fatal: true }).decode(result.payload);
            elements.extractedText.textContent = extractedTextValue;
            elements.textResult.hidden = false;
            elements.fileResult.hidden = true;
            return;
        }

        if (extractedFileUrl) URL.revokeObjectURL(extractedFileUrl);
        const blob = new Blob([result.payload], { type: result.metadata.mime || "application/octet-stream" });
        extractedFileUrl = URL.createObjectURL(blob);
        const safeName = sanitizeFileName(result.metadata.name) || "recovered-file.bin";
        elements.extractedFileName.textContent = safeName;
        elements.extractedFileMeta.textContent = `${result.metadata.mime || "未知类型"} · ${formatBytes(blob.size)}`;
        elements.downloadExtractedFile.href = extractedFileUrl;
        elements.downloadExtractedFile.download = safeName;
        elements.fileResult.hidden = false;
        elements.textResult.hidden = true;
    }

    function clearExtractResult() {
        extractedTextValue = "";
        elements.extractEmpty.hidden = false;
        elements.textResult.hidden = true;
        elements.fileResult.hidden = true;
        elements.extractResult.classList.add("empty");
        if (extractedFileUrl) {
            URL.revokeObjectURL(extractedFileUrl);
            extractedFileUrl = null;
        }
    }

    async function copyExtractedText() {
        if (!extractedTextValue) return;
        try {
            await navigator.clipboard.writeText(extractedTextValue);
            setStatus(elements.extractStatus, "文本已复制到剪贴板。", "success");
        } catch {
            setStatus(elements.extractStatus, "无法自动复制，请手动选择文本。", "error");
        }
    }

    function setButtonBusy(button, busy, label) {
        button.disabled = busy;
        button.querySelector("span").textContent = label;
    }

    function setStatus(element, message, type) {
        element.textContent = message;
        element.className = `status status-${type}`;
    }

    function formatBytes(bytes) {
        if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
        const units = ["B", "KB", "MB", "GB"];
        const unitIndex = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
        const value = bytes / (1024 ** unitIndex);
        return `${value >= 10 || unitIndex === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unitIndex]}`;
    }

    function sanitizeFileName(fileName) {
        return String(fileName).replace(/[<>:"/\\|?*\u0000-\u001f]/g, "_").slice(0, 180);
    }
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        FORMAT_VERSION,
        HEADER_LENGTH,
        MAGIC,
        buildHeader,
        concatBytes,
        createPlaintext,
        decryptContainer,
        embedBytes,
        encryptContainer,
        extractBytes,
        extractContainer,
        getImageCapacity,
        parseHeader,
        parsePlaintext
    };
}
