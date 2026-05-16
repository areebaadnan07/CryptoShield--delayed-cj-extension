# CryptoShield - Delayed Cryptojacking Detection

CryptoShield is a Malware Analysis course project developed for the MS Cyber Security program. The project is based on a research paper assigned in class about **Delayed-CJ**, a delayed cryptojacking attack technique.

The purpose of this work is to understand, present, and extend the ideas from the paper by building a practical browser-based proof of concept. The original paper focuses on delayed cryptojacking behavior, where malicious mining activity does not start immediately after a page loads. Instead, the attack waits for some time or for a user action, making it harder to detect using simple page-load scanning.

This project presents the paper's concept and develops future work in the form of a Chrome extension and controlled test website.

## Developed By

**Areeba Adnan**  
MS Cyber Security  
Malware Analysis Project

## Project Goal

The main goal of CryptoShield is to detect suspicious browser-based cryptojacking behavior by combining multiple signals instead of relying on only one indicator.

CryptoShield observes:

- Delayed CPU activity
- Web Worker creation
- WebSocket creation
- WebSocket traffic from workers
- Repeated hash-like function calls
- Suspicious timer loops
- WebAssembly activity

The extension then correlates these signals to decide whether a tab is safe, suspicious, or a confirmed threat.

## What This Project Contains

```text
Project/
|-- cryptoshield/
|   |-- manifest.json
|   |-- background.js
|   |-- content.js
|   |-- injected.js
|   |-- popup.html
|   `-- popup.js
|
`-- test-pages/
    |-- index.html
    |-- clean-page.html
    |-- safe-page.html
    |-- instant-miner.html
    |-- delayed-miner.html
    |-- delayed-cpu.html
    |-- worker-simulation.html
    |-- websocket-simulation.html
    |-- manual-miner-simulation.html
    |-- realistic-miner-simulation.html
    `-- worker scripts
```

## How The Extension Works

CryptoShield uses a Chrome Extension Manifest V3 architecture.

The extension has four main parts:

- `manifest.json` defines permissions, the popup, the background service worker, and injected resources.
- `background.js` is the main detection engine. It tracks tab state, samples CPU usage, receives runtime signals, stores detections, and updates the extension badge.
- `content.js` runs on webpages and acts as a bridge between the webpage and the extension.
- `injected.js` runs inside the actual webpage context and monitors APIs such as `Worker`, `WebSocket`, timers, crypto digest functions, and WebAssembly.
- `popup.js` displays the current tab status, CPU graph, detection flags, worker counts, WebSocket counts, and block status.

## Detection Logic

CryptoShield uses a staged detection approach:

1. The extension samples CPU activity every 2 seconds.
2. The injected script monitors suspicious browser API usage.
3. The background service worker stores signals per tab.
4. If CPU usage rises after a delay and runtime signals are present, the tab becomes suspicious.
5. If Worker and WebSocket evidence are also present, the tab is marked as a threat.
6. In the Worker WebSocket proof of concept, the extension can block worker WebSocket streams through the injected wrapper.

Important proof-of-concept rule:

```text
workerCount > 2
AND active worker WebSocket pushers > 2
THEN mark as cryptojacking threat
```

## Test Website

The `test-pages` folder contains controlled simulations for demonstration and testing. These pages do not mine cryptocurrency and do not connect to real mining pools. They are designed only to simulate browser behaviors commonly associated with cryptojacking.

Examples include:

- Clean page baseline
- Safe page baseline
- Instant mining-like worker simulation
- Delayed mining-like worker simulation
- Delayed CPU spike simulation
- Worker simulation
- WebSocket simulation
- Realistic Delay-CJ simulation with delayed worker activity

## How To Run The Test Website

Open PowerShell and run:

```powershell
cd "d:\MSCY\malware analysis and detection\Projectcj\Project\test-pages"
python -m http.server 8080 --bind 127.0.0.1
```

Then open this URL in Chrome:

```text
http://127.0.0.1:8080/index.html
```

## How To Load The Chrome Extension

1. Open Chrome.
2. Go to:

```text
chrome://extensions
```

3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select this folder:

```text
Project/cryptoshield
```

6. Open the test website and use the extension popup to monitor detection results.

## Recommended Demo Flow

1. Load the CryptoShield extension in Chrome.
2. Start the local test website.
3. Open the clean or safe page and show that no threat is detected.
4. Open the delayed miner simulation and show that the page stays dormant first.
5. Start or wait for the delayed activity.
6. Open the extension popup and explain CPU, Worker, WebSocket, and runtime signals.
7. Open the WebSocket or realistic simulation page.
8. Show how multiple workers and WebSocket sends are correlated.
9. Explain how the extension moves from safe to watching/suspicious and then to threat.

## Academic Context

This project was created as part of a Malware Analysis course in MS Cyber Security. The assigned research topic was Delayed-CJ, a delayed cryptojacking technique. My task was to study the paper, present its work, and develop future work based on the same idea.

CryptoShield is my future-work implementation. It turns the concept into a working Chrome extension that can monitor controlled browser activity and demonstrate how delayed cryptojacking behavior may be detected using signal correlation.

## Limitations

This is an academic proof of concept, not a production security product.

Current limitations:

- Chrome does not provide exact per-tab CPU usage through `chrome.system.cpu`.
- The extension estimates suspicious tab activity using active-tab correlation.
- The blocking mechanism works through API wrapping in the page/worker context.
- Real malware may use obfuscation, domain rotation, WebAssembly, or evasion techniques.
- The test pages are intentionally readable and controlled for demonstration purposes.

## Future Work

Possible future improvements include:

- More accurate per-tab CPU attribution
- Machine learning based behavior classification
- Stronger WebAssembly analysis
- Better network-layer blocking
- Domain and endpoint reputation checks
- Detection of obfuscated mining scripts
- Improved reporting dashboard
- Exportable detection logs

## Disclaimer

This project is for academic and research purposes only. The test pages simulate mining-like behavior but do not mine cryptocurrency and do not connect to real mining pools.

## Signature

**CryptoShield | Malware Analysis Project | Designed and Developed by Areeba Adnan**
