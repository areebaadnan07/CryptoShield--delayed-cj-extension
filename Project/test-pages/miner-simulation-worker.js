let iterations = 0;
let stopped = false;
const WORK_MS = 900;
const REST_MS = 300;
const LOAD_PERCENT = Math.round((WORK_MS / (WORK_MS + REST_MS)) * 100);
const encoder = new TextEncoder();

function runHashCycle() {
    if (stopped || !self.crypto?.subtle?.digest) {
        return;
    }

    self.crypto.subtle.digest("SHA-256", encoder.encode(`cryptoshield-${iterations}`))
        .finally(() => setTimeout(runHashCycle, 120));
}

function runControlledWork() {
    if (stopped) {
        return;
    }

    const endAt = Date.now() + WORK_MS;
    let value = 0;

    while (Date.now() < endAt) {
        value += Math.sqrt(Math.random());
        iterations += 1;
    }

    postMessage({ iterations, value: Math.round(value), loadPercent: LOAD_PERCENT });
    setTimeout(runControlledWork, REST_MS);
}

self.addEventListener("message", (event) => {
    if (event.data === "stop") {
        stopped = true;
    }
});

runControlledWork();
runHashCycle();
