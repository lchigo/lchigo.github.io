(() => {
    "use strict";

    const IMAGE_PATTERN = /\.(?:avif|bmp|gif|jpe?g|png|webp)$/i;
    const ARCHIVE_PATTERN = /\.(?:cbz|zip)$/i;
    const MAX_ARCHIVE_FILE_BYTES = 1.5 * 1024 ** 3;
    const MAX_ARCHIVE_IMAGE_BYTES = 1.5 * 1024 ** 3;
    const MAX_ARCHIVE_IMAGES = 5000;
    const SETTINGS_KEY = "comic-reader-settings-v2";
    const PROGRESS_KEY = "comic-reader-progress-v2";
    const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

    const dom = {
        viewer: document.getElementById("viewer"),
        initialPrompt: document.getElementById("initial-prompt"),
        promptFolderBtn: document.getElementById("prompt-folder-btn"),
        promptArchiveBtn: document.getElementById("prompt-archive-btn"),
        folderInput: document.getElementById("folder-input"),
        archiveInput: document.getElementById("archive-input"),
        folderBtn: document.getElementById("folder-btn"),
        archiveBtn: document.getElementById("archive-btn"),
        sourceName: document.getElementById("source-name"),
        containerLeft: document.getElementById("container-left"),
        containerRight: document.getElementById("container-right"),
        imageLeft: document.getElementById("image-left"),
        imageRight: document.getElementById("image-right"),
        toggleViewBtn: document.getElementById("toggle-view-btn"),
        directionBtn: document.getElementById("direction-btn"),
        fullscreenBtn: document.getElementById("fullscreen-btn"),
        autoplayBtn: document.getElementById("autoplay-btn"),
        intervalInput: document.getElementById("interval-input"),
        countdownDisplay: document.getElementById("countdown-display"),
        prevBtn: document.getElementById("prev-btn"),
        nextBtn: document.getElementById("next-btn"),
        pageStatus: document.getElementById("page-status"),
        pageJumpInput: document.getElementById("page-jump-input"),
        loadingOverlay: document.getElementById("loading-overlay"),
        loadingText: document.getElementById("loading-text"),
        toast: document.getElementById("toast")
    };

    const savedSettings = readStorageJson(SETTINGS_KEY, {});
    const state = {
        pages: [],
        cachedPageIndices: new Set(),
        currentPageIndex: 0,
        viewMode: savedSettings.viewMode === "double" ? "double" : "single",
        readingDirection: savedSettings.readingDirection === "rtl" ? "rtl" : "ltr",
        autoplayInterval: clampInterval(savedSettings.autoplayInterval),
        isAutoplaying: false,
        autoplayTimerId: null,
        countdownTimerId: null,
        autoplayDeadline: 0,
        sourceKey: "",
        sourceLabel: "",
        isBusy: false,
        loadGeneration: 0,
        cancelArchiveLoad: null,
        toastTimerId: null,
        wheelAccumulator: 0,
        wheelResetTimerId: null,
        wheelLockUntil: 0,
        touchStart: null,
        ignoreNextClick: false,
        dragDepth: 0
    };

    initialize();

    function initialize() {
        dom.intervalInput.value = String(state.autoplayInterval);
        bindEvents();
        updateUI();
    }

    function bindEvents() {
        dom.promptFolderBtn.addEventListener("click", () => openFilePicker(dom.folderInput));
        dom.promptArchiveBtn.addEventListener("click", () => openFilePicker(dom.archiveInput));
        dom.folderBtn.addEventListener("click", () => openFilePicker(dom.folderInput));
        dom.archiveBtn.addEventListener("click", () => openFilePicker(dom.archiveInput));
        dom.folderInput.addEventListener("click", resetInputValue);
        dom.archiveInput.addEventListener("click", resetInputValue);
        dom.folderInput.addEventListener("change", handleFolderSelection);
        dom.archiveInput.addEventListener("change", handleArchiveSelection);

        dom.prevBtn.addEventListener("click", prevPage);
        dom.nextBtn.addEventListener("click", nextPage);
        dom.toggleViewBtn.addEventListener("click", toggleViewMode);
        dom.directionBtn.addEventListener("click", toggleReadingDirection);
        dom.fullscreenBtn.addEventListener("click", toggleFullscreen);
        dom.autoplayBtn.addEventListener("click", toggleAutoplay);
        dom.intervalInput.addEventListener("change", applyAutoplayInterval);
        dom.intervalInput.addEventListener("blur", applyAutoplayInterval);

        dom.pageStatus.addEventListener("click", showPageJumpInput);
        dom.pageJumpInput.addEventListener("blur", commitPageJump);
        dom.pageJumpInput.addEventListener("keydown", handlePageJumpKeyDown);

        dom.viewer.addEventListener("click", handleViewerClick);
        dom.viewer.addEventListener("wheel", handleWheel, { passive: false });
        dom.viewer.addEventListener("touchstart", handleTouchStart, { passive: true });
        dom.viewer.addEventListener("touchend", handleTouchEnd, { passive: true });
        dom.viewer.addEventListener("dragenter", handleDragEnter);
        dom.viewer.addEventListener("dragover", handleDragOver);
        dom.viewer.addEventListener("dragleave", handleDragLeave);
        dom.viewer.addEventListener("drop", handleDrop);

        dom.imageLeft.addEventListener("error", handleImageError);
        dom.imageRight.addEventListener("error", handleImageError);
        document.addEventListener("keydown", handleKeyDown);
        document.addEventListener("fullscreenchange", updateUI);
        window.addEventListener("beforeunload", releaseResources);
    }

    function openFilePicker(input) {
        if (!state.isBusy) input.click();
    }

    function resetInputValue(event) {
        event.currentTarget.value = "";
    }

    function handleFolderSelection(event) {
        const files = Array.from(event.target.files || []);
        if (files.length) loadImageFiles(files);
    }

    function handleArchiveSelection(event) {
        const file = event.target.files && event.target.files[0];
        if (file) loadArchiveFile(file);
    }

    function loadImageFiles(files, fallbackLabel = "拖入的图片") {
        const imageFiles = files.filter((file) => isImagePath(file.name));
        if (!imageFiles.length) {
            showToast("没有找到支持的图片文件。", true);
            return;
        }

        const generation = beginLoad("正在整理图片…");
        const pages = imageFiles
            .map((file) => ({
                name: file.name,
                path: normalizePath(file.webkitRelativePath || file.name),
                blob: file,
                url: null
            }))
            .sort(comparePages);

        const relativePath = pages[0].path;
        const sourceLabel = relativePath.includes("/") ? relativePath.split("/")[0] : fallbackLabel;
        const totalBytes = imageFiles.reduce((sum, file) => sum + file.size, 0);
        const newestModified = imageFiles.reduce((latest, file) => Math.max(latest, file.lastModified || 0), 0);
        const sourceKey = `folder:${sourceLabel}:${pages.length}:${totalBytes}:${newestModified}`;

        if (generation !== state.loadGeneration) return;
        setBusy(false);
        replacePages(pages, sourceLabel, sourceKey);
        showToast(`已加载 ${pages.length} 页。`);
    }

    async function loadArchiveFile(file) {
        if (!ARCHIVE_PATTERN.test(file.name)) {
            showToast("请选择 ZIP 或 CBZ 格式的漫画包。", true);
            return;
        }
        if (!window.fflate || typeof window.fflate.unzip !== "function") {
            showToast("压缩包组件加载失败，请确认 vendor/fflate.min.js 存在。", true);
            return;
        }
        if (file.size > MAX_ARCHIVE_FILE_BYTES) {
            showToast("压缩包超过 1.5 GB，浏览器无法安全加载。", true);
            return;
        }

        const generation = beginLoad(`正在读取 ${file.name}…`);
        try {
            const bytes = new Uint8Array(await file.arrayBuffer());
            if (generation !== state.loadGeneration) return;

            setLoadingMessage("正在解压并整理图片…");
            const result = await unzipComicArchive(bytes);
            if (generation !== state.loadGeneration) return;

            const pages = Object.entries(result.files)
                .filter(([path]) => isImagePath(path))
                .map(([path, data]) => ({
                    name: normalizePath(path).split("/").pop(),
                    path: normalizePath(path),
                    blob: new Blob([data], { type: mimeTypeForPath(path) }),
                    url: null
                }))
                .sort(comparePages);

            if (!pages.length) {
                const detail = result.unsupportedCount
                    ? "其中的图片使用了不支持的压缩算法。"
                    : "其中没有找到支持的图片。";
                throw new Error(detail);
            }

            const sourceKey = `archive:${file.name}:${file.size}:${file.lastModified || 0}`;
            setBusy(false);
            replacePages(pages, file.name, sourceKey);

            const skippedMessage = result.unsupportedCount
                ? `，跳过 ${result.unsupportedCount} 个不支持的条目`
                : "";
            showToast(`已从压缩包加载 ${pages.length} 页${skippedMessage}。`);
        } catch (error) {
            if (error && error.name === "AbortError") return;
            if (generation === state.loadGeneration) {
                setBusy(false);
                showToast(`无法打开压缩包：${friendlyErrorMessage(error)}`, true);
            }
        } finally {
            if (generation === state.loadGeneration && state.isBusy) setBusy(false);
        }
    }

    function unzipComicArchive(bytes) {
        return new Promise((resolve, reject) => {
            let settled = false;
            let imageCount = 0;
            let imageBytes = 0;
            let unsupportedCount = 0;
            let limitError = null;
            let terminate = null;
            let cancel = null;

            const options = {
                filter(info) {
                    if (!isImagePath(info.name)) return false;
                    imageCount += 1;

                    if (info.compression !== 0 && info.compression !== 8) {
                        unsupportedCount += 1;
                        return false;
                    }
                    if (imageCount > MAX_ARCHIVE_IMAGES) {
                        limitError = new Error(`图片数量超过 ${MAX_ARCHIVE_IMAGES} 页的安全限制。`);
                        return false;
                    }

                    imageBytes += info.originalSize || 0;
                    if (imageBytes > MAX_ARCHIVE_IMAGE_BYTES) {
                        limitError = new Error("解压后的图片总量超过 1.5 GB 的安全限制。");
                        return false;
                    }
                    return true;
                }
            };

            try {
                terminate = window.fflate.unzip(bytes, options, (error, files) => {
                    if (settled) return;
                    settled = true;
                    if (state.cancelArchiveLoad === cancel) state.cancelArchiveLoad = null;

                    if (error) reject(error);
                    else if (limitError) reject(limitError);
                    else resolve({ files, unsupportedCount });
                });

                cancel = () => {
                    if (settled) return;
                    settled = true;
                    terminate?.();
                    reject(new DOMException("加载已取消", "AbortError"));
                };
                state.cancelArchiveLoad = cancel;
            } catch (error) {
                settled = true;
                reject(error);
            }
        });
    }

    function beginLoad(message) {
        state.loadGeneration += 1;
        state.cancelArchiveLoad?.();
        state.cancelArchiveLoad = null;
        stopAutoplay();
        cancelPageJump();
        setBusy(true, message);
        return state.loadGeneration;
    }

    function setBusy(isBusy, message = "正在加载…") {
        state.isBusy = isBusy;
        dom.loadingOverlay.hidden = !isBusy;
        dom.viewer.setAttribute("aria-busy", String(isBusy));
        if (isBusy) setLoadingMessage(message);
        updateUI();
    }

    function setLoadingMessage(message) {
        dom.loadingText.textContent = message;
    }

    function replacePages(pages, sourceLabel, sourceKey) {
        clearDisplayedImages();
        releasePageUrls(state.pages);
        state.cachedPageIndices.clear();

        state.pages = pages;
        state.sourceLabel = sourceLabel;
        state.sourceKey = sourceKey;
        state.currentPageIndex = restoreProgress(sourceKey, pages.length);
        normalizeCurrentPageForViewMode();

        dom.initialPrompt.hidden = true;
        displayPage();
    }

    function releaseResources() {
        state.cancelArchiveLoad?.();
        clearAutoplayTimers();
        releasePageUrls(state.pages);
        state.cachedPageIndices.clear();
    }

    function releasePageUrls(pages) {
        for (const page of pages) {
            if (!page.url) continue;
            URL.revokeObjectURL(page.url);
            page.url = null;
        }
    }

    function comparePages(a, b) {
        return collator.compare(a.path, b.path);
    }

    function normalizePath(path) {
        return String(path).replaceAll("\\", "/").normalize("NFC");
    }

    function isImagePath(path) {
        return IMAGE_PATTERN.test(normalizePath(path));
    }

    function mimeTypeForPath(path) {
        const extension = normalizePath(path).split(".").pop().toLowerCase();
        const types = {
            avif: "image/avif",
            bmp: "image/bmp",
            gif: "image/gif",
            jpeg: "image/jpeg",
            jpg: "image/jpeg",
            png: "image/png",
            webp: "image/webp"
        };
        return types[extension] || "application/octet-stream";
    }

    function friendlyErrorMessage(error) {
        const message = error && error.message ? error.message : String(error || "未知错误");
        if (/password|encrypt/i.test(message)) return "暂不支持加密或带密码的压缩包。";
        if (/invalid|unexpected|archive|zip/i.test(message)) return "文件不是有效的 ZIP / CBZ，或文件已经损坏。";
        return message;
    }

    function getVisiblePageIndices(index = state.currentPageIndex) {
        const total = state.pages.length;
        if (!total) return [];

        const safeIndex = Math.min(Math.max(0, index), total - 1);
        if (state.viewMode === "single" || safeIndex === 0) return [safeIndex];

        const pairStart = safeIndex % 2 === 1 ? safeIndex : safeIndex - 1;
        return [pairStart, pairStart + 1].filter((pageIndex) => pageIndex < total);
    }

    function canGoNext() {
        const visible = getVisiblePageIndices();
        return visible.length > 0 && visible[visible.length - 1] < state.pages.length - 1;
    }

    function canGoPrevious() {
        return getVisiblePageIndices()[0] > 0;
    }

    function nextPage() {
        if (!canGoNext()) {
            if (state.isAutoplaying) stopAutoplay();
            return;
        }

        if (state.viewMode === "single") {
            state.currentPageIndex += 1;
        } else if (state.currentPageIndex === 0) {
            state.currentPageIndex = 1;
        } else {
            state.currentPageIndex = getVisiblePageIndices()[0] + 2;
        }

        displayPage();
        if (state.isAutoplaying) scheduleAutoplay();
    }

    function prevPage() {
        if (!canGoPrevious()) return;

        if (state.viewMode === "single") {
            state.currentPageIndex -= 1;
        } else {
            const pairStart = getVisiblePageIndices()[0];
            state.currentPageIndex = pairStart <= 1 ? 0 : pairStart - 2;
        }

        displayPage();
        if (state.isAutoplaying) scheduleAutoplay();
    }

    function goToPage(pageIndex) {
        if (!state.pages.length) return;
        state.currentPageIndex = Math.min(Math.max(0, pageIndex), state.pages.length - 1);
        normalizeCurrentPageForViewMode();
        displayPage();
        if (state.isAutoplaying) scheduleAutoplay();
    }

    function normalizeCurrentPageForViewMode() {
        if (state.viewMode === "double" && state.currentPageIndex > 0 && state.currentPageIndex % 2 === 0) {
            state.currentPageIndex -= 1;
        }
    }

    function displayPage() {
        if (!state.pages.length) {
            clearDisplayedImages();
            updateUI();
            return;
        }

        const visible = getVisiblePageIndices();
        clearDisplayedImages();
        const cached = syncPageUrlCache(visible);

        dom.containerLeft.hidden = false;
        dom.containerRight.hidden = false;
        dom.containerLeft.style.justifyContent = "flex-end";
        dom.containerRight.style.justifyContent = "flex-start";

        if (state.viewMode === "single") {
            dom.containerLeft.hidden = true;
            dom.containerRight.style.justifyContent = "center";
            displayImage(dom.imageRight, visible[0]);
        } else if (visible.length === 1 && visible[0] === 0) {
            dom.containerLeft.hidden = true;
            dom.containerRight.style.justifyContent = "center";
            displayImage(dom.imageRight, 0);
        } else if (visible.length === 2) {
            const [first, second] = visible;
            const leftPage = state.readingDirection === "rtl" ? second : first;
            const rightPage = state.readingDirection === "rtl" ? first : second;
            displayImage(dom.imageLeft, leftPage);
            displayImage(dom.imageRight, rightPage);
        } else if (state.readingDirection === "rtl") {
            displayImage(dom.imageRight, visible[0]);
        } else {
            displayImage(dom.imageLeft, visible[0]);
        }

        persistProgress();
        updateUI();
        preloadCachedPages(visible, cached);
    }

    function displayImage(image, pageIndex) {
        const page = state.pages[pageIndex];
        if (!page) return;

        image.dataset.pageIndex = String(pageIndex);
        image.alt = `第 ${pageIndex + 1} 页：${page.path}`;
        image.src = ensurePageUrl(pageIndex);
        image.hidden = false;
    }

    function clearDisplayedImages() {
        for (const image of [dom.imageLeft, dom.imageRight]) {
            image.hidden = true;
            image.removeAttribute("src");
            image.removeAttribute("data-page-index");
            image.alt = "";
        }
    }

    function ensurePageUrl(pageIndex) {
        const page = state.pages[pageIndex];
        if (!page.url) page.url = URL.createObjectURL(page.blob);
        return page.url;
    }

    function syncPageUrlCache(visible) {
        const desired = new Set();
        for (const pageIndex of visible) {
            for (let offset = -2; offset <= 2; offset += 1) {
                const candidate = pageIndex + offset;
                if (candidate >= 0 && candidate < state.pages.length) desired.add(candidate);
            }
        }

        for (const index of state.cachedPageIndices) {
            if (desired.has(index)) continue;
            const page = state.pages[index];
            if (page?.url) URL.revokeObjectURL(page.url);
            if (page) page.url = null;
        }
        for (const index of desired) ensurePageUrl(index);

        state.cachedPageIndices = desired;
        return desired;
    }

    function preloadCachedPages(visible, cached) {
        const visibleSet = new Set(visible);
        for (const index of cached) {
            if (visibleSet.has(index)) continue;
            const page = state.pages[index];
            const preloader = new Image();
            preloader.src = page.url;
            preloader.decode?.().catch(() => {});
        }
    }

    function handleImageError(event) {
        const pageIndex = Number(event.currentTarget.dataset.pageIndex);
        if (Number.isInteger(pageIndex)) {
            showToast(`第 ${pageIndex + 1} 页加载失败：${state.pages[pageIndex]?.path || "未知文件"}`, true);
        }
    }

    function toggleViewMode() {
        state.viewMode = state.viewMode === "single" ? "double" : "single";
        normalizeCurrentPageForViewMode();
        persistSettings();
        displayPage();
    }

    function toggleReadingDirection() {
        state.readingDirection = state.readingDirection === "ltr" ? "rtl" : "ltr";
        persistSettings();
        displayPage();
    }

    async function toggleFullscreen() {
        if (!document.fullscreenEnabled) {
            showToast("当前浏览器不支持网页全屏。", true);
            return;
        }

        try {
            if (document.fullscreenElement) await document.exitFullscreen();
            else await document.documentElement.requestFullscreen();
        } catch {
            showToast("无法进入全屏，请检查浏览器权限。", true);
        }
    }

    function handleViewerClick(event) {
        if (state.ignoreNextClick) {
            state.ignoreNextClick = false;
            return;
        }
        if (!state.pages.length || state.isBusy || event.target.closest("button, label, input, #initial-prompt")) return;

        const clickedLeftHalf = event.clientX < window.innerWidth / 2;
        const shouldGoNext = state.readingDirection === "rtl" ? clickedLeftHalf : !clickedLeftHalf;
        if (shouldGoNext) nextPage();
        else prevPage();
    }

    function handleKeyDown(event) {
        if (!state.pages.length || state.isBusy || isInteractiveTarget(event.target)) return;

        switch (event.key) {
            case "ArrowRight":
                state.readingDirection === "rtl" ? prevPage() : nextPage();
                break;
            case "ArrowLeft":
                state.readingDirection === "rtl" ? nextPage() : prevPage();
                break;
            case "PageDown":
                event.preventDefault();
                nextPage();
                break;
            case "PageUp":
                event.preventDefault();
                prevPage();
                break;
            case "Home":
                event.preventDefault();
                goToPage(0);
                break;
            case "End":
                event.preventDefault();
                goToPage(state.pages.length - 1);
                break;
            case " ":
                event.preventDefault();
                toggleAutoplay();
                break;
            case "f":
            case "F":
                event.preventDefault();
                toggleFullscreen();
                break;
        }
    }

    function isInteractiveTarget(target) {
        return target instanceof Element && Boolean(target.closest("button, input, select, textarea, label, [contenteditable='true']"));
    }

    function handleWheel(event) {
        if (!state.pages.length || state.isBusy || event.ctrlKey || isInteractiveTarget(event.target)) return;

        const dominantDelta = Math.abs(event.deltaY) >= Math.abs(event.deltaX) ? event.deltaY : event.deltaX;
        if (!dominantDelta || Date.now() < state.wheelLockUntil) return;

        state.wheelAccumulator += dominantDelta;
        clearTimeout(state.wheelResetTimerId);
        state.wheelResetTimerId = setTimeout(() => { state.wheelAccumulator = 0; }, 180);

        if (Math.abs(state.wheelAccumulator) < 50) return;
        event.preventDefault();
        state.wheelLockUntil = Date.now() + 260;

        if (state.wheelAccumulator > 0) nextPage();
        else prevPage();
        state.wheelAccumulator = 0;
    }

    function handleTouchStart(event) {
        if (event.touches.length !== 1 || !state.pages.length) return;
        const touch = event.touches[0];
        state.touchStart = { x: touch.clientX, y: touch.clientY };
    }

    function handleTouchEnd(event) {
        if (!state.touchStart || event.changedTouches.length !== 1) return;
        const touch = event.changedTouches[0];
        const deltaX = touch.clientX - state.touchStart.x;
        const deltaY = touch.clientY - state.touchStart.y;
        state.touchStart = null;

        if (Math.abs(deltaX) < 55 || Math.abs(deltaX) <= Math.abs(deltaY) * 1.2) return;
        const swipedLeft = deltaX < 0;
        const shouldGoNext = state.readingDirection === "rtl" ? !swipedLeft : swipedLeft;
        state.ignoreNextClick = true;
        if (shouldGoNext) nextPage();
        else prevPage();
        setTimeout(() => { state.ignoreNextClick = false; }, 400);
    }

    function handleDragEnter(event) {
        if (!hasFileDrag(event)) return;
        event.preventDefault();
        state.dragDepth += 1;
        dom.viewer.classList.add("is-dragging");
    }

    function handleDragOver(event) {
        if (!hasFileDrag(event)) return;
        event.preventDefault();
        event.dataTransfer.dropEffect = "copy";
    }

    function handleDragLeave(event) {
        if (!hasFileDrag(event)) return;
        state.dragDepth = Math.max(0, state.dragDepth - 1);
        if (!state.dragDepth) dom.viewer.classList.remove("is-dragging");
    }

    function handleDrop(event) {
        if (!hasFileDrag(event)) return;
        event.preventDefault();
        state.dragDepth = 0;
        dom.viewer.classList.remove("is-dragging");

        const files = Array.from(event.dataTransfer.files || []);
        if (files.length === 1 && ARCHIVE_PATTERN.test(files[0].name)) loadArchiveFile(files[0]);
        else loadImageFiles(files);
    }

    function hasFileDrag(event) {
        return Array.from(event.dataTransfer?.types || []).includes("Files");
    }

    function toggleAutoplay() {
        if (state.isAutoplaying) {
            stopAutoplay();
            return;
        }

        if (!state.pages.length) return;
        if (!canGoNext()) goToPage(0);
        state.isAutoplaying = true;
        scheduleAutoplay();
        updateUI();
    }

    function scheduleAutoplay() {
        clearAutoplayTimers();
        if (!state.isAutoplaying) return;
        if (!canGoNext()) {
            stopAutoplay();
            return;
        }

        const delay = state.autoplayInterval * 1000;
        state.autoplayDeadline = Date.now() + delay;
        updateCountdown();
        state.countdownTimerId = setInterval(updateCountdown, 250);
        state.autoplayTimerId = setTimeout(nextPage, delay);
    }

    function stopAutoplay() {
        clearAutoplayTimers();
        state.isAutoplaying = false;
        dom.countdownDisplay.textContent = "";
        updateUI();
    }

    function clearAutoplayTimers() {
        clearTimeout(state.autoplayTimerId);
        clearInterval(state.countdownTimerId);
        state.autoplayTimerId = null;
        state.countdownTimerId = null;
    }

    function updateCountdown() {
        const seconds = Math.max(0, Math.ceil((state.autoplayDeadline - Date.now()) / 1000));
        dom.countdownDisplay.textContent = `${seconds}s`;
    }

    function applyAutoplayInterval() {
        state.autoplayInterval = clampInterval(dom.intervalInput.value);
        dom.intervalInput.value = String(state.autoplayInterval);
        persistSettings();
        if (state.isAutoplaying) scheduleAutoplay();
    }

    function clampInterval(value) {
        const parsed = Number.parseInt(value, 10);
        return Math.min(3600, Math.max(1, Number.isFinite(parsed) ? parsed : 30));
    }

    function showPageJumpInput() {
        if (!state.pages.length) return;
        dom.pageStatus.hidden = true;
        dom.pageJumpInput.hidden = false;
        dom.pageJumpInput.max = String(state.pages.length);
        dom.pageJumpInput.value = String(getVisiblePageIndices()[0] + 1);
        dom.pageJumpInput.focus();
        dom.pageJumpInput.select();
    }

    function handlePageJumpKeyDown(event) {
        if (event.key === "Enter") {
            event.preventDefault();
            commitPageJump();
        } else if (event.key === "Escape") {
            event.preventDefault();
            cancelPageJump();
            dom.pageStatus.focus();
        }
    }

    function commitPageJump() {
        if (dom.pageJumpInput.hidden) return;
        const targetPage = Number.parseInt(dom.pageJumpInput.value, 10);
        cancelPageJump();

        if (Number.isInteger(targetPage) && targetPage >= 1 && targetPage <= state.pages.length) {
            goToPage(targetPage - 1);
        } else {
            showToast(`请输入 1 到 ${state.pages.length} 之间的页码。`, true);
        }
    }

    function cancelPageJump() {
        dom.pageJumpInput.hidden = true;
        dom.pageStatus.hidden = false;
    }

    function updateUI() {
        const total = state.pages.length;
        const hasPages = total > 0;
        const disabled = !hasPages || state.isBusy;
        const visible = getVisiblePageIndices();

        dom.prevBtn.disabled = disabled || !canGoPrevious();
        dom.nextBtn.disabled = disabled || !canGoNext();
        dom.toggleViewBtn.disabled = disabled;
        dom.directionBtn.disabled = disabled;
        dom.fullscreenBtn.disabled = disabled || !document.fullscreenEnabled;
        dom.autoplayBtn.disabled = disabled;
        dom.intervalInput.disabled = disabled;
        dom.pageStatus.disabled = disabled;
        dom.folderInput.disabled = state.isBusy;
        dom.archiveInput.disabled = state.isBusy;
        dom.folderBtn.disabled = state.isBusy;
        dom.archiveBtn.disabled = state.isBusy;

        dom.toggleViewBtn.textContent = state.viewMode === "single" ? "双页" : "单页";
        dom.toggleViewBtn.title = state.viewMode === "single" ? "切换到双页模式" : "切换到单页模式";
        dom.directionBtn.textContent = state.readingDirection === "ltr" ? "左 → 右" : "右 → 左";
        dom.directionBtn.title = state.readingDirection === "ltr" ? "当前从左向右阅读" : "当前从右向左阅读";
        dom.fullscreenBtn.textContent = document.fullscreenElement ? "退出全屏" : "⛶ 全屏";
        dom.autoplayBtn.textContent = state.isAutoplaying ? "⏸ 停止" : "▶ 自动";

        if (!hasPages) {
            dom.pageStatus.textContent = "0 / 0";
            dom.pageStatus.setAttribute("aria-label", "尚未加载漫画");
            dom.sourceName.textContent = "尚未打开漫画";
            dom.sourceName.title = "尚未打开漫画";
        } else {
            const range = visible.length === 2
                ? `${visible[0] + 1}–${visible[1] + 1}`
                : String(visible[0] + 1);
            dom.pageStatus.textContent = `${range} / ${total}`;
            dom.pageStatus.setAttribute("aria-label", `当前第 ${range} 页，共 ${total} 页；点击跳转`);
            dom.sourceName.textContent = `${state.sourceLabel} · ${total} 页`;
            dom.sourceName.title = `${state.sourceLabel}，共 ${total} 页`;
        }
    }

    function persistSettings() {
        writeStorageJson(SETTINGS_KEY, {
            viewMode: state.viewMode,
            readingDirection: state.readingDirection,
            autoplayInterval: state.autoplayInterval
        });
    }

    function persistProgress() {
        if (!state.sourceKey || !state.pages.length) return;
        const records = readStorageJson(PROGRESS_KEY, {});
        records[state.sourceKey] = {
            pageIndex: state.currentPageIndex,
            updatedAt: Date.now()
        };

        const trimmedRecords = Object.fromEntries(
            Object.entries(records)
                .sort(([, a], [, b]) => (b.updatedAt || 0) - (a.updatedAt || 0))
                .slice(0, 20)
        );
        writeStorageJson(PROGRESS_KEY, trimmedRecords);
    }

    function restoreProgress(sourceKey, total) {
        const records = readStorageJson(PROGRESS_KEY, {});
        const savedIndex = Number(records[sourceKey]?.pageIndex);
        if (!Number.isInteger(savedIndex)) return 0;
        return Math.min(Math.max(0, savedIndex), Math.max(0, total - 1));
    }

    function readStorageJson(key, fallback) {
        try {
            const value = localStorage.getItem(key);
            return value ? JSON.parse(value) : fallback;
        } catch {
            return fallback;
        }
    }

    function writeStorageJson(key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value));
        } catch {
            // The reader remains usable when storage is disabled or unavailable.
        }
    }

    function showToast(message, isError = false) {
        clearTimeout(state.toastTimerId);
        dom.toast.textContent = message;
        dom.toast.classList.toggle("is-error", isError);
        dom.toast.hidden = false;
        state.toastTimerId = setTimeout(() => {
            dom.toast.hidden = true;
        }, isError ? 5000 : 3000);
    }
})();
