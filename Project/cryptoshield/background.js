const tabState = new Map();

const CPU_THRESHOLD_1 = 15;
const CPU_DELTA_THRESHOLD = 30;

const POLL_INTERVAL_MS = 2000;
const HISTORY_LENGTH = 15;

const DELAY_WINDOW_MS = 10000;
const SUSTAINED_SPIKES_REQUIRED = 3;
const PERIODIC_SIGNAL_WINDOW_MS = 12000;
const ALERT_COOLDOWN_MS = 60000;
const BADGE_CLEAR_MS = 8000;

let previousCpuSample = null;
let activeTabId = null;
let pollingTimer = null;

function now() {
    return Date.now();
}

function createTabState(tabId, url = "") {
    const timestamp = now();

    return {
        tabId,
        url,
        createdAt: timestamp,
        updatedAt: timestamp,
        lastActivatedAt: tabId === activeTabId ? timestamp : 0,
        lastCpu: 0,
        lastSystemCpu: 0,
        processorCount: 0,
        cpuHistory: [],
        spikeCount: 0,
        suspicious: false,
        threatLevel: "CLEAN",
        workerDetected: false,
        wsDetected: false,
        workerCount: 0,
        workerIds: new Set(),
        workerSocketIds: new Set(),
        workerSocketSendTimes: new Map(),
        workerWsSendCount: 0,
        activePushingWorkers: 0,
        networkBlocked: false,
        runtimeSignals: 0,
        periodicSignals: 0,
        lastPeriodicSignalAt: 0,
        lastSignal: null,
        lastAlertAt: 0
    };
}

function getOrCreateTabState(tabId, url = "") {
    if (!tabState.has(tabId)) {
        tabState.set(tabId, createTabState(tabId, url));
    }

    const state = tabState.get(tabId);
    if (url) {
        state.url = url;
    }

    return state;
}

function addHistory(state, cpuUsage) {
    state.cpuHistory.push({
        time: now(),
        cpu: Number(cpuUsage.toFixed(2))
    });

    if (state.cpuHistory.length > HISTORY_LENGTH) {
        state.cpuHistory.shift();
    }
}

function averageCpu(history) {
    if (!history.length) {
        return 0;
    }

    const total = history.reduce((sum, item) => sum + item.cpu, 0);
    return total / history.length;
}

function calculateCpuUsage(previous, current) {
    if (!previous || !current) {
        return 0;
    }

    let idleDelta = 0;
    let totalDelta = 0;

    current.processors.forEach((processor, index) => {
        const previousUsage = previous.processors[index].usage;
        const currentUsage = processor.usage;

        const userDelta = currentUsage.user - previousUsage.user;
        const kernelDelta = currentUsage.kernel - previousUsage.kernel;
        const idle = currentUsage.idle - previousUsage.idle;
        const total = userDelta + kernelDelta + idle;

        idleDelta += idle;
        totalDelta += total;
    });

    if (totalDelta <= 0) {
        return 0;
    }

    return ((totalDelta - idleDelta) / totalDelta) * 100;
}

function normalizeCpuUsage(averageUsage, cpuSample) {
    return Math.min(100, averageUsage * cpuSample.processors.length);
}

function isDelayedActivity(state) {
    return now() - state.createdAt >= DELAY_WINDOW_MS;
}

function shouldFlagTab(state, cpuUsage, cpuDelta) {
    if (cpuUsage < CPU_THRESHOLD_1) {
        state.spikeCount = 0;
        state.suspicious = false;
        state.threatLevel = "CLEAN";
        return false;
    }

    const hasRecentPeriodicity = now() - state.lastPeriodicSignalAt <= PERIODIC_SIGNAL_WINDOW_MS;

    if (isDelayedActivity(state) && (cpuDelta >= CPU_DELTA_THRESHOLD || hasRecentPeriodicity)) {
        state.spikeCount += 1;
    } else if (state.spikeCount > 0) {
        state.spikeCount -= 1;
    }

    const hasStep3Evidence = state.workerDetected || state.wsDetected;
    const isThreat = state.spikeCount >= SUSTAINED_SPIKES_REQUIRED && hasStep3Evidence;

    state.threatLevel = isThreat ? "THREAT" : "SUSPICIOUS";
    return isThreat;
}

function setBadge(text, color) {
    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color });
}

function clearBadgeLater() {
    setTimeout(() => chrome.action.setBadgeText({ text: "" }), BADGE_CLEAR_MS);
}

async function saveDetection(state, cpuUsage, cpuDelta) {
    const detection = {
        tabId: state.tabId,
        url: state.url,
        cpuUsage: Number(cpuUsage.toFixed(2)),
        cpuDelta: Number(cpuDelta.toFixed(2)),
        detectedAt: new Date().toISOString(),
        reason: state.networkBlocked
            ? "Worker count exceeded 2 and worker WebSockets were continuously pushing data; network stream blocked"
            : state.periodicSignals > 0
                ? "Sustained CPU activity with repeated hash-like function periodicity"
                : "Sustained delayed CPU spike attributed to the active tab"
    };

    const { detections = [] } = await chrome.storage.local.get("detections");
    detections.unshift(detection);
    await chrome.storage.local.set({
        detections: detections.slice(0, 50),
        lastDetection: detection
    });
}

async function warnTab(state, cpuUsage, cpuDelta) {
    if (now() - state.lastAlertAt < ALERT_COOLDOWN_MS) {
        return;
    }

    state.lastAlertAt = now();
    state.suspicious = true;
    state.threatLevel = "THREAT";

    await saveDetection(state, cpuUsage, cpuDelta);
    setBadge("!", "#c62828");
    clearBadgeLater();

    try {
        await chrome.scripting.executeScript({
            target: { tabId: state.tabId },
            func: (usage, delta) => {
                alert(
                    `CryptoShield warning:\n\nThis tab is showing delayed CPU activity that may indicate cryptojacking.\n\nCPU usage: ${usage}%\nCPU jump: ${delta}%`
                );
            },
            args: [Number(cpuUsage.toFixed(2)), Number(cpuDelta.toFixed(2))]
        });
    } catch (error) {
        console.warn("CryptoShield could not warn tab:", error);
    }
}

async function handleRuntimeSignal(message, sender) {
    if (!sender.tab?.id) {
        return;
    }

    const state = getOrCreateTabState(sender.tab.id, sender.tab.url || "");
    state.runtimeSignals += 1;

    if (["delayed-worker", "suspicious-worker"].includes(message.signal)) {
        state.workerDetected = true;
    }

    if (["delayed-websocket", "suspicious-websocket"].includes(message.signal)) {
        state.wsDetected = true;
    }

    if (["periodic-hash", "suspicious-timer", "wasm-activity"].includes(message.signal)) {
        state.periodicSignals += 1;
        state.lastPeriodicSignalAt = now();
    }

    state.lastSignal = {
        type: message.signal,
        detail: message.detail || "",
        detectedAt: new Date().toISOString()
    };

    if ((state.lastCpu || 0) < CPU_THRESHOLD_1) {
        state.spikeCount = 0;
        state.suspicious = false;
        state.threatLevel = "CLEAN";
    }
}

function countActivePushingWorkers(state) {
    const timestamp = now();
    let activeCount = 0;

    for (const sendTimes of state.workerSocketSendTimes.values()) {
        if (sendTimes.some((sendTime) => timestamp - sendTime <= PERIODIC_SIGNAL_WINDOW_MS)) {
            activeCount += 1;
        }
    }

    return activeCount;
}

async function confirmPocThreat(state, detail = "") {
    if (state.networkBlocked) {
        return;
    }

    state.suspicious = true;
    state.threatLevel = "THREAT";
    state.networkBlocked = true;
    state.lastAlertAt = now();
    state.lastSignal = {
        type: "CRYPTOJACKING_THREAT",
        detail,
        detectedAt: new Date().toISOString()
    };

    await saveDetection(state, state.lastCpu || 0, 0);
    setBadge("!", "#c62828");
    clearBadgeLater();
}

async function handleStep3Signal(message, sender) {
    if (!sender.tab?.id) {
        return false;
    }

    const state = getOrCreateTabState(sender.tab.id, sender.tab.url || "");

    if (message.type === "WORKER_DETECTED") {
        state.workerDetected = true;
        state.workerCount += 1;
    }

    if (message.type === "WS_DETECTED" || message.type === "WORKER_WS_DETECTED") {
        state.wsDetected = true;
    }

    if (message.type === "WORKER_WS_DETECTED") {
        state.workerSocketIds.add(message.workerId || `worker-socket-${state.workerSocketIds.size + 1}`);
    }

    if (message.type === "WORKER_WS_SEND") {
        const workerId = message.workerId || "unknown-worker";
        const sendTimes = state.workerSocketSendTimes.get(workerId) || [];
        const timestamp = now();
        const recentSendTimes = sendTimes.filter((sendTime) => timestamp - sendTime <= PERIODIC_SIGNAL_WINDOW_MS);

        recentSendTimes.push(timestamp);
        state.workerSocketSendTimes.set(workerId, recentSendTimes);
        state.workerWsSendCount += 1;
        state.activePushingWorkers = countActivePushingWorkers(state);

        if (state.workerCount > 2 && state.activePushingWorkers > 2) {
            await confirmPocThreat(
                state,
                `workers=${state.workerCount}; activeWebSocketPushers=${state.activePushingWorkers}; sends=${state.workerWsSendCount}`
            );
        }
    }

    if (message.type === "CRYPTOJACKING_THREAT") {
        await confirmPocThreat(state, message.detail || "Worker WebSocket correlation rule matched");
    }

    state.runtimeSignals += 1;
    state.lastSignal = {
        type: message.type,
        detail: message.detail || "",
        detectedAt: new Date().toISOString()
    };

    return true;
}

async function refreshOpenTabs() {
    const tabs = await chrome.tabs.query({});

    tabs.forEach((tab) => {
        if (tab.id !== undefined) {
            getOrCreateTabState(tab.id, tab.url || "");
        }
    });
}

async function refreshActiveTab() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const activeTab = tabs[0];

    if (activeTab?.id !== undefined) {
        activeTabId = activeTab.id;
        const state = getOrCreateTabState(activeTab.id, activeTab.url || "");
        state.lastActivatedAt = now();
    }
}

async function pollCpu() {
    try {
        await Promise.all([refreshOpenTabs(), refreshActiveTab()]);

        const currentCpuSample = await chrome.system.cpu.getInfo();
        const systemCpuUsage = calculateCpuUsage(previousCpuSample, currentCpuSample);
        const normalizedUsage = normalizeCpuUsage(systemCpuUsage, currentCpuSample);
        const hasPreviousSample = Boolean(previousCpuSample);

        previousCpuSample = currentCpuSample;

        if (!hasPreviousSample || activeTabId === null) {
            return;
        }

        const state = getOrCreateTabState(activeTabId);
        const cpuDelta = normalizedUsage - averageCpu(state.cpuHistory);

        state.lastCpu = normalizedUsage;
        state.lastSystemCpu = systemCpuUsage;
        state.processorCount = currentCpuSample.processors.length;
        state.updatedAt = now();
        addHistory(state, normalizedUsage);

        if (shouldFlagTab(state, normalizedUsage, cpuDelta)) {
            await warnTab(state, normalizedUsage, cpuDelta);
        }
    } catch (error) {
        console.error("CryptoShield CPU polling failed:", error);
    }
}

function startPolling() {
    if (pollingTimer) {
        clearInterval(pollingTimer);
    }

    refreshActiveTab();
    pollingTimer = setInterval(pollCpu, POLL_INTERVAL_MS);
    pollCpu();
}

chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.set({ detections: [] });
    setBadge("", "#c62828");
    startPolling();
});

chrome.runtime.onStartup.addListener(startPolling);

chrome.tabs.onActivated.addListener(({ tabId }) => {
    activeTabId = tabId;
    const state = getOrCreateTabState(tabId);
    state.lastActivatedAt = now();
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    const state = getOrCreateTabState(tabId, tab.url || "");

    if (changeInfo.status === "loading") {
        tabState.set(tabId, createTabState(tabId, tab.url || state.url));
    }

    if (changeInfo.url) {
        state.url = changeInfo.url;
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    tabState.delete(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (["WORKER_DETECTED", "WS_DETECTED", "WORKER_WS_DETECTED", "WORKER_WS_SEND", "CRYPTOJACKING_THREAT"].includes(message?.type)) {
        handleStep3Signal(message, sender)
            .then((handled) => sendResponse({ ok: handled }))
            .catch((error) => {
                console.error("CryptoShield Step 3 signal failed:", error);
                sendResponse({ ok: false, error: error.message });
            });
        return true;
    }

    if (message?.type === "CRYPTOSHIELD_RUNTIME_SIGNAL") {
        handleRuntimeSignal(message, sender);
        sendResponse({ ok: true });
        return true;
    }

    if (message?.type === "CRYPTOSHIELD_GET_STATUS") {
        Promise.all([refreshActiveTab(), refreshOpenTabs()])
            .then(() => {
                const states = [...tabState.values()].map((state) => ({
                    tabId: state.tabId,
                    url: state.url,
                    lastCpu: state.lastCpu,
                    lastSystemCpu: state.lastSystemCpu,
                    processorCount: state.processorCount,
                    cpuHistory: state.cpuHistory,
                    spikeCount: state.spikeCount,
                    suspicious: state.suspicious,
                    threatLevel: state.threatLevel,
                    workerDetected: state.workerDetected,
                    wsDetected: state.wsDetected,
                    workerCount: state.workerCount,
                    workerSocketCount: state.workerSocketIds.size,
                    workerWsSendCount: state.workerWsSendCount,
                    activePushingWorkers: state.activePushingWorkers,
                    networkBlocked: state.networkBlocked,
                    runtimeSignals: state.runtimeSignals,
                    periodicSignals: state.periodicSignals,
                    lastPeriodicSignalAt: state.lastPeriodicSignalAt,
                    lastSignal: state.lastSignal
                }));

                sendResponse({ activeTabId, states });
            })
            .catch((error) => {
                console.error("CryptoShield could not get status:", error);
                sendResponse({ activeTabId, states: [] });
            });

        return true;
    }

    if (message?.type === "CRYPTOSHIELD_BLOCK_TAB") {
        const tabId = Number(message.tabId);

        if (!Number.isFinite(tabId)) {
            sendResponse({ ok: false, error: "Invalid tab id" });
            return true;
        }

        chrome.tabs.remove(tabId)
            .then(() => {
                tabState.delete(tabId);
                sendResponse({ ok: true });
            })
            .catch((error) => {
                console.warn("CryptoShield could not block tab:", error);
                sendResponse({ ok: false, error: error.message });
            });

        return true;
    }

    return false;
});

startPolling();
