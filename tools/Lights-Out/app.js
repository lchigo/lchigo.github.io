"use strict";

const STORAGE_KEY = "lights-out.state.v2";
const MIN_SIZE = 1;
const MAX_SIZE = 15;
const EXACT_MINIMIZATION_LIMIT = 18;

function createToggleMatrix(rows, cols) {
    const size = rows * cols;
    const matrix = Array.from({ length: size }, () => new Uint8Array(size));
    const offsets = [[0, 0], [-1, 0], [1, 0], [0, -1], [0, 1]];

    for (let row = 0; row < rows; row += 1) {
        for (let col = 0; col < cols; col += 1) {
            const affectedIndex = row * cols + col;

            for (const [rowOffset, colOffset] of offsets) {
                const pressRow = row + rowOffset;
                const pressCol = col + colOffset;

                if (pressRow >= 0 && pressRow < rows && pressCol >= 0 && pressCol < cols) {
                    matrix[affectedIndex][pressRow * cols + pressCol] = 1;
                }
            }
        }
    }

    return matrix;
}

function hammingWeight(vector) {
    let weight = 0;
    for (const value of vector) weight += value;
    return weight;
}

function findMinimumWeightSolution(particular, basisVectors) {
    if (basisVectors.length === 0 || basisVectors.length > EXACT_MINIMIZATION_LIMIT) {
        return {
            solution: particular,
            minimized: basisVectors.length <= EXACT_MINIMIZATION_LIMIT
        };
    }

    const candidate = Uint8Array.from(particular);
    let candidateWeight = hammingWeight(candidate);
    let best = Uint8Array.from(candidate);
    let bestWeight = candidateWeight;
    let previousGrayCode = 0;
    const combinations = 2 ** basisVectors.length;

    for (let index = 1; index < combinations && bestWeight > 0; index += 1) {
        const grayCode = index ^ (index >> 1);
        const changedBits = grayCode ^ previousGrayCode;
        const basisIndex = 31 - Math.clz32(changedBits);
        const basis = basisVectors[basisIndex];

        for (let position = 0; position < candidate.length; position += 1) {
            if (basis[position] === 1) {
                candidate[position] ^= 1;
                candidateWeight += candidate[position] === 1 ? 1 : -1;
            }
        }

        if (candidateWeight < bestWeight) {
            best = Uint8Array.from(candidate);
            bestWeight = candidateWeight;
        }

        previousGrayCode = grayCode;
    }

    return { solution: best, minimized: true };
}

function solveLinearSystemMod2(matrixInput, vectorInput) {
    const rowCount = matrixInput.length;
    const columnCount = matrixInput[0]?.length ?? 0;
    const augmented = matrixInput.map((row, index) => {
        const result = new Uint8Array(columnCount + 1);
        result.set(row);
        result[columnCount] = vectorInput[index];
        return result;
    });
    const pivotColumns = [];
    let pivotRow = 0;

    for (let column = 0; column < columnCount && pivotRow < rowCount; column += 1) {
        let candidateRow = pivotRow;
        while (candidateRow < rowCount && augmented[candidateRow][column] === 0) {
            candidateRow += 1;
        }

        if (candidateRow === rowCount) continue;

        if (candidateRow !== pivotRow) {
            [augmented[pivotRow], augmented[candidateRow]] = [augmented[candidateRow], augmented[pivotRow]];
        }

        for (let row = 0; row < rowCount; row += 1) {
            if (row === pivotRow || augmented[row][column] === 0) continue;
            for (let entry = column; entry <= columnCount; entry += 1) {
                augmented[row][entry] ^= augmented[pivotRow][entry];
            }
        }

        pivotColumns.push(column);
        pivotRow += 1;
    }

    for (let row = pivotRow; row < rowCount; row += 1) {
        let hasCoefficient = false;
        for (let column = 0; column < columnCount; column += 1) {
            if (augmented[row][column] === 1) {
                hasCoefficient = true;
                break;
            }
        }
        if (!hasCoefficient && augmented[row][columnCount] === 1) return null;
    }

    const pivotSet = new Set(pivotColumns);
    const freeColumns = [];
    for (let column = 0; column < columnCount; column += 1) {
        if (!pivotSet.has(column)) freeColumns.push(column);
    }

    const particular = new Uint8Array(columnCount);
    pivotColumns.forEach((column, row) => {
        particular[column] = augmented[row][columnCount];
    });

    const basisVectors = freeColumns.map((freeColumn) => {
        const basis = new Uint8Array(columnCount);
        basis[freeColumn] = 1;
        pivotColumns.forEach((pivotColumn, row) => {
            basis[pivotColumn] = augmented[row][freeColumn];
        });
        return basis;
    });

    const minimizedResult = findMinimumWeightSolution(particular, basisVectors);
    return {
        solution: minimizedResult.solution,
        rank: pivotColumns.length,
        freeVariables: freeColumns.length,
        minimized: minimizedResult.minimized
    };
}

function applyPressVector(stateInput, pressVector, rows, cols) {
    const nextState = Uint8Array.from(stateInput);
    const matrix = createToggleMatrix(rows, cols);

    for (let lightIndex = 0; lightIndex < nextState.length; lightIndex += 1) {
        let toggles = 0;
        for (let pressIndex = 0; pressIndex < pressVector.length; pressIndex += 1) {
            toggles ^= matrix[lightIndex][pressIndex] & pressVector[pressIndex];
        }
        nextState[lightIndex] ^= toggles;
    }

    return nextState;
}

if (typeof document !== "undefined") {
    const elements = {};
    let currentRows = 3;
    let currentCols = 3;
    let boardState = new Uint8Array(9);
    let currentSolution = null;

    document.addEventListener("DOMContentLoaded", initialize);

    function initialize() {
        elements.board = document.getElementById("board-container");
        elements.boardViewport = document.getElementById("board-viewport");
        elements.boardForm = document.getElementById("board-form");
        elements.rowsInput = document.getElementById("rows");
        elements.colsInput = document.getElementById("cols");
        elements.targetSelect = document.getElementById("target-state");
        elements.randomButton = document.getElementById("random-board");
        elements.invertButton = document.getElementById("invert-board");
        elements.clearBoardButton = document.getElementById("clear-board");
        elements.solveButton = document.getElementById("solve-button");
        elements.applyButton = document.getElementById("apply-solution");
        elements.clearSolutionButton = document.getElementById("clear-solution");
        elements.message = document.getElementById("message");
        elements.boardTitle = document.getElementById("board-title");
        elements.litCount = document.getElementById("lit-count");
        elements.pressCount = document.getElementById("press-count");

        elements.boardForm.addEventListener("submit", handleBoardFormSubmit);
        elements.targetSelect.addEventListener("change", handleTargetChange);
        elements.randomButton.addEventListener("click", createSolvableRandomBoard);
        elements.invertButton.addEventListener("click", invertBoard);
        elements.clearBoardButton.addEventListener("click", clearBoard);
        elements.solveButton.addEventListener("click", solvePuzzle);
        elements.applyButton.addEventListener("click", applyCurrentSolution);
        elements.clearSolutionButton.addEventListener("click", () => clearSolutionMarkers(true));
        elements.board.addEventListener("keydown", handleBoardKeydown);
        window.addEventListener("resize", updateBoardSizing, { passive: true });

        const savedState = loadState();
        if (savedState) {
            currentRows = savedState.rows;
            currentCols = savedState.cols;
            boardState = Uint8Array.from(savedState.cells);
            elements.rowsInput.value = String(currentRows);
            elements.colsInput.value = String(currentCols);
            elements.targetSelect.value = String(savedState.target);
        }

        renderBoard();
        setMessage(savedState ? "已恢复上次盘面，可以继续设置或直接求解。" : "点击格子设置盘面，然后开始求解。", "info");
    }

    function parseSize(input) {
        const value = Number.parseInt(input.value, 10);
        return Number.isInteger(value) ? value : Number.NaN;
    }

    function isValidSize(value) {
        return Number.isInteger(value) && value >= MIN_SIZE && value <= MAX_SIZE;
    }

    function handleBoardFormSubmit(event) {
        event.preventDefault();
        const rows = parseSize(elements.rowsInput);
        const cols = parseSize(elements.colsInput);

        if (!isValidSize(rows) || !isValidSize(cols)) {
            setMessage(`行数和列数必须在 ${MIN_SIZE} 至 ${MAX_SIZE} 之间。`, "error");
            return;
        }

        currentRows = rows;
        currentCols = cols;
        boardState = new Uint8Array(rows * cols);
        renderBoard();
        saveState();
        setMessage(`已生成 ${rows} × ${cols} 棋盘，点击格子设置当前状态。`, "info");
    }

    function handleTargetChange() {
        clearSolutionMarkers(false);
        saveState();
        const targetLabel = getTargetState() === 1 ? "全部点亮" : "全部熄灭";
        setMessage(`目标已改为“${targetLabel}”，可以开始求解。`, "info");
    }

    function getTargetState() {
        return Number(elements.targetSelect.value);
    }

    function renderBoard() {
        elements.board.replaceChildren();
        elements.board.style.setProperty("--board-cols", String(currentCols));
        elements.board.setAttribute("aria-label", `${currentRows} 行 ${currentCols} 列点灯棋盘`);
        elements.boardTitle.textContent = `${currentRows} × ${currentCols} 棋盘`;

        const fragment = document.createDocumentFragment();
        for (let index = 0; index < boardState.length; index += 1) {
            const cell = document.createElement("button");
            const row = Math.floor(index / currentCols);
            const col = index % currentCols;
            cell.type = "button";
            cell.className = "cell";
            cell.dataset.index = String(index);
            cell.addEventListener("click", () => toggleCell(index));
            updateCellAppearance(cell, row, col);
            fragment.appendChild(cell);
        }

        elements.board.appendChild(fragment);
        clearSolutionMarkers(false);
        updateBoardSizing();
        updateStats();
    }

    function updateCellAppearance(cell, row, col) {
        const isOn = boardState[Number(cell.dataset.index)] === 1;
        cell.classList.toggle("on", isOn);
        cell.setAttribute("aria-pressed", String(isOn));
        cell.setAttribute("aria-label", `第 ${row + 1} 行，第 ${col + 1} 列：${isOn ? "已点亮" : "已熄灭"}`);
    }

    function toggleCell(index) {
        clearSolutionMarkers(false);
        boardState[index] ^= 1;
        const cell = elements.board.children[index];
        updateCellAppearance(cell, Math.floor(index / currentCols), index % currentCols);
        updateStats();
        saveState();
        setMessage("盘面已更新，点击“求解当前盘面”计算步骤。", "info");
    }

    function setBoardState(nextState, message) {
        boardState = Uint8Array.from(nextState);
        renderBoard();
        saveState();
        setMessage(message, "info");
    }

    function clearBoard() {
        setBoardState(new Uint8Array(currentRows * currentCols), "盘面已全部熄灭。");
    }

    function invertBoard() {
        setBoardState(boardState.map((value) => value ^ 1), "盘面状态已反转。");
    }

    function createSolvableRandomBoard() {
        const target = getTargetState();
        const targetBoard = new Uint8Array(currentRows * currentCols).fill(target);
        const randomPresses = new Uint8Array(targetBoard.length);
        crypto.getRandomValues(randomPresses);
        for (let index = 0; index < randomPresses.length; index += 1) {
            randomPresses[index] &= 1;
        }
        setBoardState(
            applyPressVector(targetBoard, randomPresses, currentRows, currentCols),
            "已生成一个保证有解的随机盘面。"
        );
    }

    function solvePuzzle() {
        clearSolutionMarkers(false);
        const target = getTargetState();
        const requiredChange = boardState.map((value) => value ^ target);
        const matrix = createToggleMatrix(currentRows, currentCols);
        const result = solveLinearSystemMod2(matrix, requiredChange);

        if (!result) {
            setMessage("当前盘面无法通过标准十字规则达到目标状态。", "error");
            return;
        }

        currentSolution = result.solution;
        let pressCount = 0;

        currentSolution.forEach((shouldPress, index) => {
            if (shouldPress === 1) {
                elements.board.children[index].classList.add("solution-press");
                pressCount += 1;
            }
        });

        elements.pressCount.textContent = String(pressCount);
        elements.applyButton.disabled = false;
        elements.clearSolutionButton.disabled = false;

        if (pressCount === 0) {
            setMessage("盘面已经达到目标状态，无需按压。", "success");
        } else if (result.minimized) {
            setMessage(`求解完成：绿色圆环标出了 ${pressCount} 个需要按下的格子。`, "success");
        } else {
            setMessage(`求解完成：找到 ${pressCount} 步可行解。该大棋盘存在较多等价解。`, "success");
        }
    }

    function applyCurrentSolution() {
        if (!currentSolution) return;
        boardState = applyPressVector(boardState, currentSolution, currentRows, currentCols);
        renderBoard();
        saveState();

        const target = getTargetState();
        const solved = boardState.every((value) => value === target);
        setMessage(solved ? "解法已应用，盘面达到目标状态。" : "解法已应用。", solved ? "success" : "info");
    }

    function clearSolutionMarkers(announce) {
        currentSolution = null;
        elements.board?.querySelectorAll(".solution-press").forEach((cell) => {
            cell.classList.remove("solution-press");
        });
        if (elements.pressCount) elements.pressCount.textContent = "—";
        if (elements.applyButton) elements.applyButton.disabled = true;
        if (elements.clearSolutionButton) elements.clearSolutionButton.disabled = true;
        if (announce) setMessage("解法标记已清除，可以继续调整盘面。", "info");
    }

    function updateStats() {
        elements.litCount.textContent = String(hammingWeight(boardState));
    }

    function updateBoardSizing() {
        if (!elements.boardViewport) return;
        const gap = window.innerWidth <= 600 ? 5 : 7;
        const availableWidth = Math.max(220, elements.boardViewport.clientWidth - 56);
        const idealSize = Math.floor((availableWidth - gap * (currentCols - 1)) / currentCols);
        const cellSize = Math.max(18, Math.min(62, idealSize));
        elements.board.style.setProperty("--cell-size", `${cellSize}px`);
        elements.board.style.setProperty("--board-gap", `${gap}px`);
    }

    function handleBoardKeydown(event) {
        const activeCell = event.target.closest(".cell");
        if (!activeCell) return;

        const index = Number(activeCell.dataset.index);
        const row = Math.floor(index / currentCols);
        const col = index % currentCols;
        let nextRow = row;
        let nextCol = col;

        if (event.key === "ArrowUp") nextRow = Math.max(0, row - 1);
        else if (event.key === "ArrowDown") nextRow = Math.min(currentRows - 1, row + 1);
        else if (event.key === "ArrowLeft") nextCol = Math.max(0, col - 1);
        else if (event.key === "ArrowRight") nextCol = Math.min(currentCols - 1, col + 1);
        else if (event.key === "Home") nextCol = 0;
        else if (event.key === "End") nextCol = currentCols - 1;
        else return;

        event.preventDefault();
        elements.board.children[nextRow * currentCols + nextCol]?.focus();
    }

    function setMessage(text, type) {
        elements.message.textContent = text;
        elements.message.className = `message message-${type}`;
    }

    function saveState() {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify({
                rows: currentRows,
                cols: currentCols,
                target: getTargetState(),
                cells: Array.from(boardState)
            }));
        } catch {
            // Storage can be unavailable in private or restricted browser contexts.
        }
    }

    function loadState() {
        try {
            const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
            if (!saved || !isValidSize(saved.rows) || !isValidSize(saved.cols)) return null;
            if (![0, 1].includes(saved.target)) return null;
            if (!Array.isArray(saved.cells) || saved.cells.length !== saved.rows * saved.cols) return null;
            if (saved.cells.some((value) => value !== 0 && value !== 1)) return null;
            return saved;
        } catch {
            return null;
        }
    }
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        applyPressVector,
        createToggleMatrix,
        findMinimumWeightSolution,
        solveLinearSystemMod2
    };
}
