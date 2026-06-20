// Popup: show whether the native messaging host (and thus the desktop app) is
// reachable, by performing the hello handshake through the background worker.

const api = globalThis.browser ?? globalThis.chrome;

const dot = document.getElementById("dot");
const statusText = document.getElementById("statusText");
const detail = document.getElementById("detail");

api.runtime.sendMessage({ cmd: "hello" }).then((result) => {
  if (result && result.ok && result.response && result.response.type === "hello") {
    const appConnected = !!result.response.app_connected;
    dot.classList.add(appConnected ? "ok" : "bad");
    statusText.textContent = appConnected
      ? `Connected — host v${result.response.version}`
      : `Host v${result.response.version} (app not running)`;
    if (!appConnected) {
      detail.textContent =
        "Native host is installed and responding. Open and unlock the SYBR Passwords desktop app to enable autofill.";
    }
  } else {
    dot.classList.add("bad");
    statusText.textContent = "Native host not found";
    detail.textContent =
      "Install the native messaging host manifest and the vault-native-host binary. See extension/README.md.";
  }
});
