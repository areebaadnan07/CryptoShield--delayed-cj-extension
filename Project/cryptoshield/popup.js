const statusBadge = document.getElementById("status-badge");
const cpuGraph = document.getElementById("cpu-graph");
const cpuValue = document.getElementById("cpu-value");
const cpuNote = document.getElementById("cpu-note");
const blockButton = document.getElementById("block-btn");
const currentUrl = document.getElementById("current-url");
const flagsList = document.getElementById("flags-list");

let activeState = null;

function formatCpu(value) {
    return `${Math.round(Number(value || 0))}%`;
}

function setBadge(text, type = "safe") {
    statusBadge.textContent = text;
    statusBadge.className = type === "safe" ? "" : type;
}

function getActiveState(response) {
    const states = response?.states || [];

    return states.find((state) => state.tabId === response.activeTabId)
        || states.find((state) => state.suspicious)
        || states[0]
        || null;
}

function drawGraph(history) {
    const context = cpuGraph.getContext("2d");
    const width = cpuGraph.width;
    const height = cpuGraph.height;
    const points = history?.length ? history.map((item) => item.cpu) : [0];
    const step = points.length > 1 ? width / (points.length - 1) : width;

    context.clearRect(0, 0, width, height);

    context.strokeStyle = "#d8e2ec";
    context.lineWidth = 1;
    for (let index = 0; index <= 3; index += 1) {
        const y = Math.round((height / 3) * index) + 0.5;
        context.beginPath();
        context.moveTo(0, y);
        context.lineTo(width, y);
        context.stroke();
    }

    const thresholdY = height - 0.15 * height;
    context.setLineDash([6, 5]);
    context.strokeStyle = "#d97706";
    context.lineWidth = 1.5;
    context.beginPath();
    context.moveTo(0, thresholdY);
    context.lineTo(width, thresholdY);
    context.stroke();
    context.setLineDash([]);

    context.beginPath();
    points.forEach((point, index) => {
        const x = points.length > 1 ? index * step : width;
        const y = height - Math.min(100, Math.max(0, point)) / 100 * height;

        if (index === 0) {
            context.moveTo(x, y);
        } else {
            context.lineTo(x, y);
        }
    });

    context.strokeStyle = "#2563eb";
    context.lineWidth = 3;
    context.lineCap = "round";
    context.lineJoin = "round";
    context.stroke();

    const gradient = context.createLinearGradient(0, 0, 0, height);
    gradient.addColorStop(0, "rgba(37, 99, 235, 0.22)");
    gradient.addColorStop(1, "rgba(37, 99, 235, 0.02)");

    context.lineTo(width, height);
    context.lineTo(0, height);
    context.closePath();
    context.fillStyle = gradient;
    context.fill();
}

function flagItem(text, type = "safe") {
    const item = document.createElement("li");
    item.className = type === "safe" ? "" : type;
    item.textContent = text;
    return item;
}

function renderFlags(state) {
    flagsList.replaceChildren();

    if (!state) {
        flagsList.appendChild(flagItem("No tab data available yet.", "warn"));
        return;
    }

    if (state.threatLevel === "THREAT") {
        flagsList.appendChild(flagItem("Threat confirmed: CPU pattern plus Worker/WebSocket evidence.", "danger"));
    } else if (state.threatLevel === "SUSPICIOUS") {
        flagsList.appendChild(flagItem("Suspicious CPU pattern waiting for Worker/WebSocket evidence.", "warn"));
    } else {
        flagsList.appendChild(flagItem("No confirmed cryptojacking signal.", "safe"));
    }

    const systemCpu = state.lastSystemCpu ?? state.lastCpu ?? 0;
    const normalizedCpu = state.lastCpu ?? 0;
    const processorCount = state.processorCount || 1;

    flagsList.appendChild(flagItem(`System CPU usage: ${formatCpu(systemCpu)}`, systemCpu >= 15 ? "warn" : "safe"));
    flagsList.appendChild(flagItem(`Normalized CPU score: ${formatCpu(normalizedCpu)} of one saturated logical thread`, normalizedCpu >= 15 ? "warn" : "safe"));
    flagsList.appendChild(flagItem(`CPU threads used for normalization: ${processorCount}`, "safe"));

    if (state.spikeCount > 0) {
        flagsList.appendChild(flagItem(`CPU spike count: ${state.spikeCount}`, "warn"));
    }

    if (state.runtimeSignals > 0) {
        flagsList.appendChild(flagItem(`Runtime signals: ${state.runtimeSignals}`, "warn"));
    }

    flagsList.appendChild(flagItem(`Worker detected: ${state.workerDetected ? "yes" : "no"}`, state.workerDetected ? "warn" : "safe"));
    flagsList.appendChild(flagItem(`WebSocket detected: ${state.wsDetected ? "yes" : "no"}`, state.wsDetected ? "warn" : "safe"));
    flagsList.appendChild(flagItem(`Worker instances: ${state.workerCount || 0}`, (state.workerCount || 0) > 2 ? "warn" : "safe"));
    flagsList.appendChild(flagItem(`Worker WebSockets: ${state.workerSocketCount || 0}`, (state.workerSocketCount || 0) > 0 ? "warn" : "safe"));
    flagsList.appendChild(flagItem(`Worker socket sends: ${state.workerWsSendCount || 0}`, (state.workerWsSendCount || 0) > 0 ? "warn" : "safe"));
    flagsList.appendChild(flagItem(`Active socket pushers: ${state.activePushingWorkers || 0}`, (state.activePushingWorkers || 0) > 2 ? "danger" : "safe"));
    flagsList.appendChild(flagItem(`Network block: ${state.networkBlocked ? "active" : "inactive"}`, state.networkBlocked ? "danger" : "safe"));

    const hasRecentPeriodicity = Date.now() - (state.lastPeriodicSignalAt || 0) <= 12000;

    if (state.periodicSignals > 0 && hasRecentPeriodicity) {
        flagsList.appendChild(flagItem(`Function periodicity signals: ${state.periodicSignals}`, "warn"));
    }

    if (state.lastSignal?.type) {
        flagsList.appendChild(flagItem(`Latest signal: ${state.lastSignal.type}`, "warn"));
    }
}

function renderStatus(response) {
    activeState = getActiveState(response);

    if (!activeState) {
        setBadge("No Data", "warning");
        currentUrl.textContent = "No active tab found";
        cpuValue.textContent = "0%";
        cpuNote.textContent = "Normalized to one logical thread";
        drawGraph([]);
        renderFlags(null);
        blockButton.disabled = true;
        return;
    }

    const cpu = activeState.lastCpu || 0;
    const isDanger = activeState.threatLevel === "THREAT" || activeState.suspicious;
    const hasRecentPeriodicity = Date.now() - (activeState.lastPeriodicSignalAt || 0) <= 12000;
    const isWarning = activeState.spikeCount > 0 || activeState.runtimeSignals > 0 || (hasRecentPeriodicity && cpu >= 15) || cpu >= 15;

    setBadge(isDanger ? "Blocked Risk" : isWarning ? "Watching" : "Safe", isDanger ? "danger" : isWarning ? "warning" : "safe");
    currentUrl.textContent = activeState.url || "Unknown URL";
    cpuValue.textContent = formatCpu(cpu);
    cpuNote.textContent = `Normalized core/thread score from ${activeState.processorCount || 1} logical CPU threads`;
    drawGraph(activeState.cpuHistory || []);
    renderFlags(activeState);
    blockButton.disabled = !activeState.tabId || (!isDanger && !isWarning);
}

function refreshPopup() {
    chrome.runtime.sendMessage({ type: "CRYPTOSHIELD_GET_STATUS" }, renderStatus);
}

blockButton.addEventListener("click", () => {
    if (!activeState?.tabId) {
        return;
    }

    blockButton.disabled = true;
    blockButton.textContent = "Blocking...";

    chrome.runtime.sendMessage({
        type: "CRYPTOSHIELD_BLOCK_TAB",
        tabId: activeState.tabId
    }, (response) => {
        if (response?.ok) {
            blockButton.textContent = "Blocked";
            setBadge("Blocked", "danger");
            return;
        }

        blockButton.textContent = "Block Tab";
        blockButton.disabled = false;
    });
});

refreshPopup();
setInterval(refreshPopup, 2000);
