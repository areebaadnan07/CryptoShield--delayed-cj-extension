let workerIndex = 0;
let stopped = true;
let socket = null;
let packetId = 0;
let loopTimer = null;
let hashSeed = 0x9e3779b9;
let totalRounds = 0;

const LOCAL_STRATUM_ENDPOINT = "ws://127.0.0.1:8080";
const DIGEST_INTERVAL = 8;
const encoder = new TextEncoder();

function rotateRight(value, bits) {
    return (value >>> bits) | (value << (32 - bits));
}

function mixWord(value, round) {
    let mixed = value >>> 0;

    mixed ^= rotateRight(mixed + round + 0x6a09e667, 7);
    mixed = Math.imul(mixed ^ 0xbb67ae85, 0x85ebca6b);
    mixed ^= rotateRight(mixed + 0x3c6ef372, 13);
    mixed = Math.imul(mixed ^ 0xa54ff53a, 0xc2b2ae35);
    mixed ^= mixed >>> 16;

    return mixed >>> 0;
}

function runCryptographicBatch(durationMs) {
    const endAt = performance.now() + durationMs;
    let localSeed = hashSeed;
    let nonce = packetId + workerIndex * 100000;
    let rounds = 0;

    while (!stopped && performance.now() < endAt) {
        let a = (localSeed ^ nonce ^ 0x243f6a88) >>> 0;
        let b = (localSeed + nonce + 0x85a308d3) >>> 0;
        let c = (localSeed ^ 0x13198a2e) >>> 0;
        let d = (nonce + 0x03707344) >>> 0;

        for (let index = 0; index < 192; index += 1) {
            a = mixWord(a + b, index);
            b = mixWord(b ^ c, index + 17);
            c = mixWord(c + d, index + 31);
            d = mixWord(d ^ a, index + 47);
        }

        localSeed = (a ^ b ^ c ^ d ^ nonce) >>> 0;
        nonce += 1;
        rounds += 1;
    }

    hashSeed = localSeed;
    totalRounds += rounds;

    return { result: localSeed, rounds };
}

async function emitDigestSignal(result) {
    const payload = encoder.encode(`worker=${workerIndex};packet=${packetId};hash=${result};rounds=${totalRounds}`);
    const digest = await crypto.subtle.digest("SHA-256", payload);
    const view = new DataView(digest);

    return view.getUint32(0, false).toString(16).padStart(8, "0");
}

function sendLocalPacket(result, digestPreview) {
    const packet = JSON.stringify({
        id: packetId,
        worker: workerIndex,
        method: "submit",
        params: {
            jobId: `local-job-${workerIndex}`,
            nonce: packetId.toString(16),
            result: digestPreview || result.toString(16)
        },
        simulated: true,
        timestamp: Date.now()
    });

    if (socket) {
        try {
            socket.send(packet);
        } catch (error) {
            // Intentionally safe: the localhost socket may not be open, but the send attempt is still a signal.
        }
    }

    self.postMessage({
        type: "packet",
        workerIndex,
        packetId,
        result,
        digestPreview,
        rounds: totalRounds
    });
}

async function mineLoop() {
    if (stopped) {
        return;
    }

    const { result, rounds } = runCryptographicBatch(220);
    packetId += 1;

    let digestPreview = "";
    if (packetId % DIGEST_INTERVAL === 0) {
        try {
            digestPreview = await emitDigestSignal(result);
        } catch (error) {
            digestPreview = "digest-error";
        }
    }

    sendLocalPacket(result, digestPreview);

    const delay = rounds > 0 ? 1 : 8;
    loopTimer = setTimeout(mineLoop, delay);
}

function connectLocalStratumMock() {
    try {
        socket = new WebSocket(LOCAL_STRATUM_ENDPOINT);

        socket.addEventListener("open", () => {
            self.postMessage({ type: "socket-open", workerIndex });
        });

        socket.addEventListener("error", () => {
            self.postMessage({ type: "socket-local-error", workerIndex });
        });

        socket.addEventListener("close", () => {
            if (!stopped) {
                self.postMessage({ type: "socket-closed", workerIndex });
            }
        });
    } catch (error) {
        self.postMessage({ type: "socket-unavailable", workerIndex });
    }
}

function start(index) {
    if (!stopped) {
        return;
    }

    workerIndex = index;
    stopped = false;
    packetId = 0;
    totalRounds = 0;
    hashSeed = (0x9e3779b9 ^ Math.floor(Math.random() * 0xffffffff) ^ index) >>> 0;

    connectLocalStratumMock();
    mineLoop();
}

function stop() {
    stopped = true;
    clearTimeout(loopTimer);
    loopTimer = null;

    if (socket) {
        socket.close();
        socket = null;
    }
}

self.addEventListener("message", (event) => {
    if (event.data?.type === "start") {
        start(event.data.workerIndex || 1);
    }

    if (event.data?.type === "stop") {
        stop();
    }
});
