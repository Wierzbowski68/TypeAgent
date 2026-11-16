# TypeAgent Security Audit Findings

Validated MEDIUM/HIGH/CRITICAL issues with complete attack chains.
Audit date: 2026-11-16. Branch: `cursor/vulnerability-findings-memory-7930`.

---

## CRITICAL-1: Unauthenticated WebSocket service hub exposes privileged browser-agent APIs

**Severity:** CRITICAL  
**Location:** `ts/packages/dispatcher/src/context/system/handlers/serviceHost/service.ts`  
**Title:** Unauthenticated multi-channel WebSocket hub (default `:8080`) with no authn/authz

### Description
The service host starts a `WebSocketServer` with no authentication, no origin checks, and no host binding (defaults to all interfaces). Any peer that connects with `channel` + `role` query params can join a channel and have messages relayed to the opposite role. The shell and CLI enable this hub (`enableServiceHost: true`).

On the `browser` channel, the dispatcher-side handler executes high-privilege methods including `importHtmlFolder`, `searchWebMemories`, knowledge index operations, and `webAgent/*` registration traffic, then returns results to channel clients.

### Impact
LAN/network attackers (and often malicious web pages talking to `ws://localhost:8080`) can:
- Read/import local HTML folders via attacker-chosen paths
- Query and clear indexed web knowledge / memories
- Toggle transient agents and drive discovery/macro APIs
- Impersonate client or dispatcher roles and inject traffic into agent channels

### Attack path
1. Victim runs TypeAgent shell/CLI (service host listens, typically port 8080 on all interfaces).
2. Attacker connects: `ws://<victim>:8080/?channel=browser&role=client`.
3. Attacker sends JSON such as `{ "id": "1", "method": "searchWebMemories", "params": { ... } }` or `{ "method": "importHtmlFolder", "params": { "folderPath": "/home/<user>/Documents" } }`.
4. Hub forwards client → dispatcher; browser agent executes `processBrowserAgentMessage` and `webSocket.send`s the result.
5. Hub forwards dispatcher → all clients; attacker receives the result payload.

### Evidence
- `ts/packages/dispatcher/src/context/system/handlers/serviceHost/service.ts:22-32` — default `ws://localhost:8080`, `WebSocketServer({ port })` with no auth
- `ts/packages/dispatcher/src/context/system/handlers/serviceHost/service.ts:46-125` — connection accepts channel/role only; broadcasts by role
- `ts/packages/shell/src/main/index.ts:316` — `enableServiceHost: true`
- `ts/packages/agents/browser/src/agent/actionHandler.mts:722-915` — privileged method dispatch + result return

### Remediation
- Bind to `127.0.0.1` unless explicitly configured otherwise.
- Require a per-session shared secret / token on connect; reject unauthenticated sockets.
- Enforce origin/client allowlists; do not treat channel role as authorization.
- Minimize methods reachable over the hub; require user confirmation for filesystem operations.

---

## CRITICAL-2: Electron inline-browser preload exposes privileged IPC to untrusted websites

**Severity:** CRITICAL  
**Location:** `ts/packages/shell/src/preload/webView.ts`, `ts/packages/shell/src/main/browserViewManager.ts`, `ts/packages/shell/src/main/index.ts`  
**Title:** Untrusted page origins receive `electronAPI` / `browserConnect` bridging to TypeAgent

### Description
Every inline browser tab loads a privileged preload (`webview` preload, `sandbox: false`) that exposes `window.electronAPI` and `window.browserConnect` to page JavaScript via `contextBridge`. Those APIs call main-process IPC handlers that forward arbitrary messages onto the browser WebSocket channel (same privileged surface as CRITICAL-1). The preload also relays `postMessage` events with `source: "webAgent"` without verifying `event.origin`.

### Impact
A malicious website opened inside the TypeAgent shell browser can invoke backend browser-agent methods (memory search, folder import, knowledge APIs, site-translator toggles) and participate in webAgent messaging—cross-origin compromise of the local assistant.

### Attack path
1. User opens `https://evil.example` in the shell’s inline browser (or follows an agent-opened link).
2. Page JS calls `window.electronAPI.sendBrowserMessage({ method: "searchWebMemories", params: {...} })` or `importHtmlFolder`, etc.
3. Preload → `ipcRenderer.invoke("browser-extension-message")` → main → `BrowserAgentIpc.send` → service hub → browser agent executes and returns results to the page promise.
4. Alternatively, page posts `{ source: "webAgent", method: "webAgent/register", ... }`; preload stamps title/URL and forwards without origin checks (registration still prompts the user, but other methods do not).

### Evidence
- `ts/packages/shell/src/main/browserViewManager.ts:79-84` — preload + `sandbox: false` for all tab URLs
- `ts/packages/shell/src/preload/webView.ts:282-363` — `browserConnect` / `electronAPI` exposed to main world
- `ts/packages/shell/src/preload/webView.ts:365-375` — webAgent `postMessage` relay, no origin check
- `ts/packages/shell/src/main/index.ts:570-642` — IPC forwards arbitrary method/params to browser IPC

### Remediation
- Do not expose privileged APIs to arbitrary web content. Use a separate trusted view for extension UIs.
- If a bridge is required, gate by allowlisted chrome-extension / app origins only.
- Validate `event.origin` on any `postMessage` bridge; never forward arbitrary methods from page context.
- Prefer `sandbox: true` and minimal preload surface for untrusted tabs.

---

## CRITICAL-3: TypeAgent API WebSocket accepts unauthenticated remote commands

**Severity:** CRITICAL (when `ts/packages/api` server is running)  
**Location:** `ts/packages/api/src/webServer.ts`, `ts/packages/api/src/webSocketServer.ts`, `ts/packages/api/src/webDispatcher.ts`  
**Title:** Unauthenticated dispatcher RPC over network-facing HTTP/WS

### Description
`TypeAgentAPIWebServer` listens on port 3000 on all interfaces (`broadcast: true` in `data/config.json`). A WebSocket server is attached with no authentication. Connected clients can send `dispatcher-rpc-call` messages that invoke the full dispatcher, including `processCommand`, which drives all agents (desktop, browser, code, etc.).

### Impact
Any network peer that can reach the host can issue natural-language / command traffic as if they were the local user—leading to desktop automation, browsing, file/knowledge access, and other agent capabilities.

### Attack path
1. Operator starts the API package (`TypeAgentServer.start()`).
2. Attacker opens `ws://<victim-ip>:3000`.
3. Attacker sends `{ "message": "dispatcher-rpc-call", "data": <rpc invoke for processCommand> }`.
4. `createWebDispatcher` routes into `dispatcher.processCommand` / dispatcher RPC server.

### Evidence
- `ts/packages/api/data/config.json` — `"broadcast": true`, port 3000
- `ts/packages/api/src/webServer.ts:97-100` — listens on all local IPs
- `ts/packages/api/src/webSocketServer.ts:14-52` — WS accept with no auth
- `ts/packages/api/src/webDispatcher.ts:70-131` — `processCommand` + dispatcher RPC over WS

### Remediation
- Default bind to loopback; require explicit opt-in for LAN/WAN.
- Authenticate every WS session (token/mTLS); authorize dispatcher RPC separately.
- Do not expose full `processCommand` without strong auth and audit logging.

---

## HIGH-1: Session storage path traversal (no containment)

**Severity:** HIGH  
**Location:** `ts/packages/dispatcher/src/execute/storageImpl.ts`  
**Title:** `getStorage` joins attacker-/agent-controlled paths without verifying base directory containment

### Description
`getFullPath` uses `path.join(baseDir, name, storagePath)` and contains an explicit `REVIEW` comment that validation is missing. Agents already write paths such as `../downloaded_images/...` and `../generated_images/...`. Sufficient `../` segments escape the session/agent directory into the user’s home tree (or beyond). Storage is also exposed to agent processes via agentRpc (`storageRead` / `storageWrite`).

### Impact
A compromised or malicious agent (including a user-approved dynamic web agent), or any code path that passes a controlled `storagePath`, can read/write files outside the intended storage root—credential files, configs, other session data.

### Attack path
1. Attacker gets a dynamic web agent approved, or compromises an agent process, or steers an action that supplies a storage path.
2. Call `storage.read("../../../../.ssh/id_rsa")` / `storage.write("../../../../.config/...", data)` via the Storage shim (`agentRpc` server storage methods → host `getStorage`).
3. Host resolves via unconstrained `path.join` and performs the filesystem operation.

### Evidence
- `ts/packages/dispatcher/src/execute/storageImpl.ts:17-21` — REVIEW + unvalidated join
- `ts/packages/agents/desktop/src/connector.ts:92` — intentional `../downloaded_images/`
- `ts/packages/agents/image/src/imageActionHandler.ts:99` — intentional `../generated_images/`
- `ts/packages/agentRpc/src/server.ts:267-318` — storage RPC forwards `storagePath`

### Remediation
- Resolve the path and require `resolved.startsWith(resolvedRoot + path.sep)`.
- Reject absolute paths and any `..` segments; provide an explicit API for shared dirs instead of `../`.
- Treat storage paths as untrusted at the dispatcher boundary.

---

## HIGH-2: SSRF via wallpaper/image download (`getBlob`)

**Severity:** HIGH  
**Location:** `ts/packages/agents/desktop/src/connector.ts`, `ts/packages/commonUtils/src/image.ts`, `ts/packages/aiclient/src/restClient.ts`  
**Title:** LLM-controlled URL fetched server-side with no scheme/host allowlist

### Description
`setWallpaper` accepts `parameters.url` from the action schema (LLM-produced). That URL is passed to `downloadImage` → `getBlob` → `fetchWithRetry` with no restriction on scheme or destination. Fetched bytes are written into storage (using a `../` path) and applied as the desktop wallpaper. The same helper is used by the image agent.

### Impact
Prompt injection (including from untrusted web content ingested into the assistant) or a malicious user/LLM action can cause the local Node process to request internal HTTP endpoints (cloud metadata, localhost admin ports, intranet services). Responses are persisted on disk; errors/timing can also leak reachability.

### Attack path
1. Attacker injects instructions via page content / chat so the model emits `setWallpaper` with `url: "http://169.254.169.254/..."` or `http://127.0.0.1:<internal>/`.
2. Desktop agent calls `downloadImage` → `getBlob(uri)`.
3. Node `fetch` retrieves the resource; content is written under the TypeAgent data dir and set as wallpaper.

### Evidence
- `ts/packages/agents/desktop/src/actionsSchema.ts:91-97` — `url` parameter
- `ts/packages/agents/desktop/src/connector.ts:82-101` — URL → `downloadImage`
- `ts/packages/commonUtils/src/image.ts:80-91` — `getBlob(uri)` then `storage.write`
- `ts/packages/aiclient/src/restClient.ts:155-168` — unrestricted fetch

### Remediation
- Allow only `https:` to public hosts; block link-local, private, and loopback ranges; block `file:`.
- Enforce size/type limits before write; do not use path traversal for storage locations.

---

## HIGH-3: agentRpc has no authentication; becomes critical when bridged off-host

**Severity:** HIGH  
**Location:** `ts/packages/agentRpc/**` (transport consumers: process fork, webAgent over WS, API dispatcher RPC)  
**Title:** RPC protocol trusts the channel; no auth layer in agentRpc

### Description
`createRpc` / `createAgentRpcServer` authenticate nothing—they invoke handlers for any message on the channel. In-process this is intended for forked agent workers (`child_process.fork` + `createChannelProvider(process)`). The same trust model is reused when channels are bridged across the unauthenticated service-host WebSocket (browser/webAgent) and the API dispatcher WebSocket.

### Impact
Whenever the channel is reachable by an attacker (CRITICAL-1/2/3), agentRpc provides a structured invoke/call surface (including storage and agent lifecycle) without an additional auth boundary.

### Attack path
1. Attacker obtains a message path onto a bridged channel (WS hub client role, Electron preload bridge, or API WS).
2. Attacker sends crafted invoke/call frames understood by `createRpc`.
3. Handlers execute with host privileges of the dispatcher/agent side of the channel.

### Evidence
- `ts/packages/agentRpc/src/rpc.ts:54-94` — dispatches invoke/call with no auth
- `ts/packages/dispatcher/src/agentProvider/process/agentProcess.ts` — RPC over process IPC
- `ts/packages/agents/browser/src/agent/webTypeAgent.mts:110-163` — agentRpc client over WebSocket-backed channels

### Remediation
- Keep agentRpc strictly on authenticated, host-local transports.
- For any network or renderer-facing bridge, terminate RPC behind an authenticated gateway with explicit method allowlists.
- Do not reuse raw agentRpc frames across untrusted websockets.

---

## MEDIUM-1: Shell command injection when launching VS Code

**Severity:** MEDIUM  
**Location:** `ts/packages/agents/code/src/codeActionHandler.ts`  
**Title:** `exec(\`code --new-window "${folder}"\`)` interpolates path into a shell command

### Description
`launchVSCode` reads the last folder URI from VS Code’s `state.vscdb`, converts it with `fileURLToPath`, and embeds it in a double-quoted string passed to `child_process.exec` (shell). A folder path containing `"` (or other shell metacharacters depending on platform) breaks out of the quotes and executes arbitrary commands.

### Impact
Local command execution as the TypeAgent user when VS Code history contains a crafted path and the code agent launches VS Code (user action or LLM `launchVSCode`).

### Attack path
1. Attacker causes a directory with an embedded `"` (and payload) to appear in VS Code’s recently opened folders (e.g., user opens a maliciously named folder/share).
2. Code agent runs `launchVSCode` → `ensureVSCodeProcess`.
3. `exec` runs a shell line where `folder` closes the quote and appends attacker commands.

### Evidence
- `ts/packages/agents/code/src/codeActionHandler.ts:117-165` — path from DB → string interpolation → `exec`
- `ts/packages/agents/code/src/codeActionHandler.ts:266-268` — action triggers launch

### Remediation
- Use `execFile("code", ["--new-window", folder], ...)` (no shell).
- Validate/normalize the path; reject unexpected characters.

---

## Out of scope / not reported as exploitable here

- `greetingCommandHandler` `exec("az ad signed-in-user show")` — fixed command string; no user/LLM interpolation.
- Python `knowpro` `.eval` — query AST evaluation, not OS command execution.
- Hardcoded credential *values* — none validated in this pass (env var *names* only).
- `open-folder` IPC — reachable from trusted chat preload; needs separate XSS in chat to become cross-origin.
- agentRpc over `fork` alone — same local user trust boundary without a network/renderer bridge.
