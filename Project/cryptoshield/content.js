window.addEventListener("message", (event) => {
    if (event.source !== window || event.data?.source !== "CRYPTOSHIELD_PAGE") {
        return;
    }

    const allowedSignals = new Set([
        "delayed-worker",
        "suspicious-worker",
        "delayed-websocket",
        "suspicious-websocket",
        "periodic-hash",
        "suspicious-timer",
        "wasm-activity",
        "worker-websocket",
        "worker-websocket-send",
        "worker-websocket-blocked",
        "cryptojacking-threat"
    ]);

    if (!allowedSignals.has(event.data.signal)) {
        return;
    }

    if (["delayed-worker", "suspicious-worker"].includes(event.data.signal)) {
        chrome.runtime.sendMessage({
            type: "WORKER_DETECTED",
            signal: event.data.signal,
            detail: event.data.detail
        });
        return;
    }

    if (["delayed-websocket", "suspicious-websocket"].includes(event.data.signal)) {
        chrome.runtime.sendMessage({
            type: "WS_DETECTED",
            signal: event.data.signal,
            detail: event.data.detail
        });
        return;
    }

    if (event.data.signal === "worker-websocket") {
        chrome.runtime.sendMessage({
            type: "WORKER_WS_DETECTED",
            detail: event.data.detail,
            workerId: event.data.workerId
        });
        return;
    }

    if (event.data.signal === "worker-websocket-send") {
        chrome.runtime.sendMessage({
            type: "WORKER_WS_SEND",
            detail: event.data.detail,
            workerId: event.data.workerId
        });
        return;
    }

    if (event.data.signal === "cryptojacking-threat") {
        chrome.runtime.sendMessage({
            type: "CRYPTOJACKING_THREAT",
            detail: event.data.detail
        });
        return;
    }

    chrome.runtime.sendMessage({
        type: "CRYPTOSHIELD_RUNTIME_SIGNAL",
        signal: event.data.signal,
        detail: event.data.detail
    });
});

const script = document.createElement("script");
script.src = chrome.runtime.getURL("injected.js");
script.async = false;
script.onload = () => script.remove();
(document.head || document.documentElement).appendChild(script);
