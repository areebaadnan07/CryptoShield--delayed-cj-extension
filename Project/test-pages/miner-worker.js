let socket = null;
let workerIndex = 0;
let packetId = 0;
let workTimer = null;
let stopped = false;

const ENDPOINTS = [
    "wss://echo.websocket.org",
    "wss://echo.websocket.events"
];

function runHashLikeWork() {
    let value = 0;
    const endAt = Date.now() + 260;

    while (Date.now() < endAt) {
        value = (value + Math.sqrt(Math.random() * 1000003)) % 1000000007;
    }

    return Math.round(value);
}

function sendMiningPacket() {
    if (stopped || !socket || socket.readyState !== WebSocket.OPEN) {
        return;
    }

    const result = runHashLikeWork();
    const packet = `worker=${workerIndex};packet=${packetId};hash=${result};time=${Date.now()}`;

    packetId += 1;
    socket.send(packet);
    self.postMessage({ type: "packet", workerIndex, packetId, result });
}

function connect(endpointIndex = 0) {
    if (stopped || endpointIndex >= ENDPOINTS.length) {
        return;
    }

    socket = new WebSocket(ENDPOINTS[endpointIndex]);

    socket.addEventListener("open", () => {
        workTimer = setInterval(sendMiningPacket, 350);
    });

    socket.addEventListener("close", () => {
        clearInterval(workTimer);

        if (!stopped) {
            self.postMessage({ type: "blocked", workerIndex });
        }
    });

    socket.addEventListener("error", () => {
        clearInterval(workTimer);

        if (!stopped) {
            connect(endpointIndex + 1);
        }
    });
}

function stop() {
    stopped = true;
    clearInterval(workTimer);

    if (socket) {
        socket.close();
        socket = null;
    }
}

self.addEventListener("message", (event) => {
    if (event.data?.type === "start") {
        workerIndex = event.data.workerIndex || 0;
        stopped = false;
        connect();
    }

    if (event.data?.type === "stop") {
        stop();
    }
});
