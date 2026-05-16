(function () {
    const MINING_KEYWORDS = [
        "coinhive",
        "cryptonight",
        "miner",
        "mining",
        "monero",
        "xmr",
        "hash",
        "stratum",
        "pool"
    ];

    const MINING_PORTS = new Set([
        "3333",
        "4444",
        "5555",
        "7777",
        "8888",
        "9999",
        "14444",
        "14433"
    ]);

    const PERIODIC_WINDOW_MS = 10000;
    const PERIODIC_CALL_THRESHOLD = 8;
    const WORKER_CORRELATION_WINDOW_MS = 5000;
    const MIN_WORKERS_FOR_THREAT = 3;
    const periodicCalls = new Map();
    const monitoredWorkers = new Map();
    const workerSocketSends = new Map();
    let workerSequence = 0;
    let networkBlocked = false;
    const manualObservationMode = window.location.pathname.endsWith("/manual-miner-simulation.html");

    function postDetection(type, signal, detail) {
        window.postMessage({
            source: "CRYPTOSHIELD_PAGE",
            type,
            signal,
            workerId: detail?.workerId,
            detail: String(detail || "").slice(0, 300)
        }, "*");
    }

    function postWorkerDetection(signal, workerId, detail) {
        window.postMessage({
            source: "CRYPTOSHIELD_PAGE",
            type: "CS_WORKER_NETWORK_ACTIVITY",
            signal,
            workerId,
            detail: String(detail || "").slice(0, 300)
        }, "*");
    }

    function textHasMiningKeyword(value) {
        const text = String(value || "").toLowerCase();
        return MINING_KEYWORDS.some((keyword) => text.includes(keyword));
    }

    function trackPeriodicCall(key, signal, detail) {
        const timestamp = Date.now();
        const calls = periodicCalls.get(key) || [];
        const recentCalls = calls.filter((callTime) => timestamp - callTime <= PERIODIC_WINDOW_MS);

        recentCalls.push(timestamp);
        periodicCalls.set(key, recentCalls);

        if (recentCalls.length === PERIODIC_CALL_THRESHOLD || recentCalls.length % PERIODIC_CALL_THRESHOLD === 0) {
            postDetection("CS_PERIODIC_ACTIVITY", signal, `${detail}; calls=${recentCalls.length}/${PERIODIC_WINDOW_MS}ms`);
        }
    }

    function getUrlPort(value) {
        try {
            const parsedUrl = new URL(String(value), window.location.href);
            return parsedUrl.port;
        } catch (error) {
            return "";
        }
    }

    function isSuspiciousWebSocketUrl(url) {
        return textHasMiningKeyword(url) || MINING_PORTS.has(getUrlPort(url));
    }

    const OriginalWorker = window.Worker;

    if (typeof OriginalWorker === "function") {
        window.Worker = function (scriptURL, options) {
            const workerId = `worker-${Date.now()}-${workerSequence += 1}`;
            const originalWorkerUrl = new URL(String(scriptURL || ""), window.location.href).href;
            const workerUrl = String(scriptURL || "");
            const signal = textHasMiningKeyword(workerUrl)
                ? "suspicious-worker"
                : "delayed-worker";

            postDetection("CS_WORKER_DETECTED", signal, workerUrl);

            const wrapperSource = `
                (() => {
                    const workerId = ${JSON.stringify(workerId)};
                    const originalUrl = ${JSON.stringify(originalWorkerUrl)};
                    const sockets = new Set();
                    let socketsBlocked = false;

                    function report(signal, detail) {
                        self.postMessage({
                            source: "CRYPTOSHIELD_WORKER",
                            signal,
                            workerId,
                            detail: String(detail || "").slice(0, 300)
                        });
                    }

                    const NativeWebSocket = self.WebSocket;

                    if (typeof NativeWebSocket === "function") {
                        self.WebSocket = function (url, protocols) {
                            report("worker-websocket", url);

                            if (socketsBlocked) {
                                report("worker-websocket-blocked", url);
                                throw new Error("CryptoShield blocked worker WebSocket creation");
                            }

                            const socket = protocols === undefined
                                ? new NativeWebSocket(url)
                                : new NativeWebSocket(url, protocols);

                            sockets.add(socket);
                            const nativeSend = socket.send.bind(socket);

                            socket.send = function (data) {
                                report("worker-websocket-send", typeof data === "string" ? data : "[binary packet]");

                                if (socketsBlocked) {
                                    report("worker-websocket-blocked", "send blocked");
                                    return;
                                }

                                return nativeSend(data);
                            };

                            return socket;
                        };

                        self.WebSocket.prototype = NativeWebSocket.prototype;
                        self.WebSocket.CONNECTING = NativeWebSocket.CONNECTING;
                        self.WebSocket.OPEN = NativeWebSocket.OPEN;
                        self.WebSocket.CLOSING = NativeWebSocket.CLOSING;
                        self.WebSocket.CLOSED = NativeWebSocket.CLOSED;
                    }

                    self.addEventListener("message", (event) => {
                        if (event.data?.__cryptoShieldBlockSockets) {
                            socketsBlocked = true;
                            sockets.forEach((socket) => {
                                try {
                                    socket.close();
                                } catch (error) {
                                    // Socket may already be closing.
                                }
                            });
                            report("worker-websocket-blocked", "all worker sockets closed");
                        }
                    });

                    importScripts(originalUrl);
                })();
            `;
            const wrapperUrl = URL.createObjectURL(new Blob([wrapperSource], { type: "text/javascript" }));
            const worker = new OriginalWorker(wrapperUrl, options);

            URL.revokeObjectURL(wrapperUrl);
            monitoredWorkers.set(workerId, worker);
            worker.addEventListener("message", (event) => {
                if (event.data?.source !== "CRYPTOSHIELD_WORKER") {
                    return;
                }

                postWorkerDetection(event.data.signal, event.data.workerId, event.data.detail);

                if (event.data.signal === "worker-websocket-send") {
                    trackWorkerSocketSend(event.data.workerId);
                }
            });

            return worker;
        };

        window.Worker.prototype = OriginalWorker.prototype;
    }

    function trackWorkerSocketSend(workerId) {
        const timestamp = Date.now();
        const sends = workerSocketSends.get(workerId) || [];
        const recentSends = sends.filter((sendTime) => timestamp - sendTime <= WORKER_CORRELATION_WINDOW_MS);

        recentSends.push(timestamp);
        workerSocketSends.set(workerId, recentSends);

        const activePushingWorkers = [...workerSocketSends.values()]
            .filter((workerSends) => workerSends.some((sendTime) => timestamp - sendTime <= WORKER_CORRELATION_WINDOW_MS))
            .length;

        if (!networkBlocked && monitoredWorkers.size >= MIN_WORKERS_FOR_THREAT && activePushingWorkers >= MIN_WORKERS_FOR_THREAT) {
            networkBlocked = true;
            if (!manualObservationMode) {
                monitoredWorkers.forEach((worker) => {
                    worker.postMessage({ __cryptoShieldBlockSockets: true });
                });
            }
            postWorkerDetection(
                "cryptojacking-threat",
                workerId,
                `workers=${monitoredWorkers.size}; activeWebSocketPushers=${activePushingWorkers}; action=${manualObservationMode ? "manual-observation" : "blocked"}`
            );
        }
    }

    const OriginalWebSocket = window.WebSocket;

    if (typeof OriginalWebSocket === "function") {
        window.WebSocket = function (url, protocols) {
            const socketUrl = String(url || "");

            if (isSuspiciousWebSocketUrl(socketUrl)) {
                postDetection("CS_WEBSOCKET_DETECTED", "suspicious-websocket", socketUrl);
            } else {
                postDetection("CS_WEBSOCKET_DETECTED", "delayed-websocket", socketUrl);
            }

            if (protocols === undefined) {
                return new OriginalWebSocket(url);
            }

            return new OriginalWebSocket(url, protocols);
        };

        window.WebSocket.prototype = OriginalWebSocket.prototype;
        window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
        window.WebSocket.OPEN = OriginalWebSocket.OPEN;
        window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
        window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;
    }

    const originalSetInterval = window.setInterval;
    const originalSetTimeout = window.setTimeout;

    window.setInterval = function (handler, timeout, ...args) {
        if (textHasMiningKeyword(handler) || Number(timeout) <= 250) {
            trackPeriodicCall("timer:interval", "suspicious-timer", `interval=${timeout}`);
        }

        return originalSetInterval.call(this, handler, timeout, ...args);
    };

    window.setTimeout = function (handler, timeout, ...args) {
        if (textHasMiningKeyword(handler) && Number(timeout) <= 1000) {
            trackPeriodicCall("timer:timeout", "suspicious-timer", `timeout=${timeout}`);
        }

        return originalSetTimeout.call(this, handler, timeout, ...args);
    };

    if (window.SubtleCrypto?.prototype?.digest) {
        const originalDigest = window.SubtleCrypto.prototype.digest;

        window.SubtleCrypto.prototype.digest = function (algorithm, data) {
            const algorithmName = typeof algorithm === "string" ? algorithm : algorithm?.name || "unknown";

            trackPeriodicCall(`digest:${algorithmName}`, "periodic-hash", `crypto.subtle.digest(${algorithmName})`);
            return originalDigest.call(this, algorithm, data);
        };
    }

    if (window.WebAssembly) {
        const originalCompile = window.WebAssembly.compile;
        const originalInstantiate = window.WebAssembly.instantiate;

        if (typeof originalCompile === "function") {
            window.WebAssembly.compile = function (...args) {
                trackPeriodicCall("wasm:compile", "wasm-activity", "WebAssembly.compile");
                return originalCompile.apply(this, args);
            };
        }

        if (typeof originalInstantiate === "function") {
            window.WebAssembly.instantiate = function (...args) {
                trackPeriodicCall("wasm:instantiate", "wasm-activity", "WebAssembly.instantiate");
                return originalInstantiate.apply(this, args);
            };
        }
    }
}());
