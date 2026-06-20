// Content script: detect login forms and offer autofill.
//
// For each password field on the page we attach a small key badge. Clicking it
// asks the background worker (which relays to the desktop app via the native
// host) for logins matching the current site, and renders a picker. Selecting
// one fills the username + password fields.
//
// Phase 1: detection, badge UI, and the request/response round-trip are wired
// up. The desktop-app bridge is stubbed, so the picker currently shows a
// "desktop app not connected" note instead of credentials.

(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  if (window.__sybrPasswordsInjected) return;
  window.__sybrPasswordsInjected = true;

  /** Find the most likely username field associated with a password input. */
  function findUsernameField(pw) {
    const scope = pw.form ?? document;
    const selector = [
      'input[autocomplete="username"]',
      'input[type="email"]',
      'input[name*="user" i]',
      'input[name*="email" i]',
      'input[id*="user" i]',
      'input[id*="email" i]',
      'input[type="text"]',
    ].join(",");
    const candidates = Array.from(scope.querySelectorAll(selector)).filter(
      (el) => el.offsetParent !== null,
    );
    // Prefer the visible text/email field that appears before the password.
    const before = candidates.filter(
      (el) => pw.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_PRECEDING,
    );
    return before.length ? before[before.length - 1] : candidates[0] ?? null;
  }

  /** Set a value in a way React/Vue/Angular controlled inputs will notice. */
  function setNativeValue(el, value) {
    const proto =
      el.tagName === "TEXTAREA"
        ? window.HTMLTextAreaElement.prototype
        : window.HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
    if (setter) setter.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  let panel = null;
  function closePanel() {
    panel?.remove();
    panel = null;
  }

  function openPanel(anchor, content) {
    closePanel();
    const rect = anchor.getBoundingClientRect();
    panel = document.createElement("div");
    panel.className = "sybr-panel";
    panel.style.top = `${window.scrollY + rect.bottom + 6}px`;
    panel.style.left = `${window.scrollX + rect.left}px`;
    panel.style.width = `${Math.max(rect.width, 240)}px`;
    panel.appendChild(content);
    document.body.appendChild(panel);
  }

  function note(text) {
    const div = document.createElement("div");
    div.className = "sybr-note";
    div.textContent = text;
    return div;
  }

  async function onBadgeClick(pw) {
    const loading = note("Searching your vault…");
    openPanel(pw, loading);

    let result;
    try {
      result = await api.runtime.sendMessage({
        cmd: "listLogins",
        url: location.href,
      });
    } catch (e) {
      openPanel(pw, note(`Extension error: ${String(e)}`));
      return;
    }

    if (!result || !result.ok) {
      openPanel(
        pw,
        note(
          "Can't reach the native host. Is the SYBR Passwords desktop app and native messaging host installed?",
        ),
      );
      return;
    }

    const resp = result.response || {};
    const items = Array.isArray(resp.items) ? resp.items : [];

    if (items.length === 0) {
      openPanel(
        pw,
        note(
          resp.note ||
            (resp.app_connected
              ? "No matching logins for this site."
              : "Desktop app is locked or not running."),
        ),
      );
      return;
    }

    const list = document.createElement("div");
    for (const item of items) {
      const row = document.createElement("button");
      row.className = "sybr-row";
      row.innerHTML = `<span class="sybr-title"></span><span class="sybr-user"></span>`;
      row.querySelector(".sybr-title").textContent = item.title || item.url;
      row.querySelector(".sybr-user").textContent = item.username || "";
      row.addEventListener("click", async () => {
        // Request the actual credential. The desktop app only releases it for a
        // matching origin while unlocked; the password is never in `item`.
        let fill;
        try {
          fill = await api.runtime.sendMessage({
            cmd: "fill",
            id: item.id,
            url: location.href,
          });
        } catch (e) {
          openPanel(pw, note(`Could not fill: ${String(e)}`));
          return;
        }
        const cred = fill && fill.ok ? fill.response : null;
        if (cred && cred.type === "credentials") {
          const username = findUsernameField(pw);
          if (username && cred.username) setNativeValue(username, cred.username);
          if (cred.password) setNativeValue(pw, cred.password);
          closePanel();
        } else {
          openPanel(
            pw,
            note((cred && cred.message) || "Couldn't retrieve the password."),
          );
        }
      });
      list.appendChild(row);
    }
    openPanel(pw, list);
  }

  function attachBadge(pw) {
    if (pw.dataset.sybrAttached) return;
    pw.dataset.sybrAttached = "1";

    const badge = document.createElement("button");
    badge.type = "button";
    badge.className = "sybr-badge";
    badge.title = "Autofill from SYBR Passwords";
    badge.textContent = "🔑";

    const place = () => {
      const rect = pw.getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) {
        badge.style.display = "none";
        return;
      }
      badge.style.display = "flex";
      badge.style.top = `${window.scrollY + rect.top + rect.height / 2 - 12}px`;
      badge.style.left = `${window.scrollX + rect.right - 28}px`;
    };

    badge.addEventListener("mousedown", (e) => e.preventDefault());
    badge.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      onBadgeClick(pw);
    });

    document.body.appendChild(badge);
    place();
    window.addEventListener("scroll", place, { passive: true });
    window.addEventListener("resize", place, { passive: true });
  }

  function scan() {
    document
      .querySelectorAll('input[type="password"]:not([data-sybr-attached])')
      .forEach(attachBadge);
  }

  // Dismiss the picker when clicking elsewhere or pressing Escape.
  document.addEventListener("click", (e) => {
    if (panel && !panel.contains(e.target)) closePanel();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closePanel();
  });

  scan();
  // Watch for dynamically rendered login forms (SPAs).
  new MutationObserver(scan).observe(document.documentElement, {
    childList: true,
    subtree: true,
  });
})();
