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

  // Avoid overlapping queries (each spawns the native host once).
  let querying = false;
  // Only nag once per page that the app is locked, on automatic triggers.
  let lockedHintShown = false;

  /** The first VISIBLE password field on the page, or null. Used to decide, at
      click time, whether an identifier-field pick should also fill a password
      (two-step pages reveal the password field after the identifier step). */
  function visiblePasswordField() {
    return (
      Array.from(document.querySelectorAll('input[type="password"]')).find(
        (el) => el.offsetParent !== null,
      ) ?? null
    );
  }

  // Show matching logins. `auto` = triggered by focus (stay quiet when there's
  // nothing useful); manual (badge click) always gives feedback.
  // `isIdentifier` = the anchor is a username/email field (not a password
  // field). Whether a pick fills only the username or also the password is
  // decided at click time by whether a password field is visible, so a field
  // badged during the identifier step still does a full fill once the password
  // step appears.
  async function showMatches(anchor, auto, isIdentifier = false) {
    if (querying) return;
    querying = true;
    try {
      if (!auto) openPanel(anchor, note("Searching your vault…"));

      let result;
      try {
        result = await api.runtime.sendMessage({
          cmd: "listLogins",
          url: location.href,
        });
      } catch (e) {
        if (!auto) openPanel(anchor, note(`Extension error: ${String(e)}`));
        return;
      }

      if (!result || !result.ok) {
        if (!auto) {
          openPanel(
            anchor,
            note(
              "Can't reach SYBR Passwords. Is the desktop app installed and the extension's native host registered?",
            ),
          );
        }
        return;
      }

      const resp = result.response || {};
      const items = Array.isArray(resp.items) ? resp.items : [];

      if (items.length === 0) {
        if (!resp.app_connected) {
          // Locked / not running. Only nag automatically on password fields
          // (unambiguously a login); an identifier field can be a false
          // positive (newsletter box), so we stay silent there unless the user
          // explicitly clicked the badge.
          const nag = !auto || (!isIdentifier && !lockedHintShown);
          if (nag) {
            if (auto) lockedHintShown = true;
            openPanel(anchor, note("Open and unlock SYBR Passwords to autofill."));
          }
        } else if (!auto) {
          openPanel(anchor, note("No matching logins for this site."));
        } else {
          closePanel();
        }
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
          const pwField = isIdentifier ? visiblePasswordField() : anchor;

          if (isIdentifier && !pwField) {
            // Pure identifier step (no password field yet): fill just the
            // username. It's metadata already in `item`; no credential request
            // is made at all.
            if (item.username) setNativeValue(anchor, item.username);
            closePanel();
            return;
          }

          // Request the actual credential. The desktop app only releases it for
          // a matching origin while unlocked; the password is never in `item`.
          let fill;
          try {
            fill = await api.runtime.sendMessage({
              cmd: "fill",
              id: item.id,
              url: location.href,
            });
          } catch (e) {
            openPanel(anchor, note(`Could not fill: ${String(e)}`));
            return;
          }
          const cred = fill && fill.ok ? fill.response : null;
          if (cred && cred.type === "credentials") {
            const userField = isIdentifier ? anchor : findUsernameField(anchor);
            if (userField && cred.username)
              setNativeValue(userField, cred.username);
            if (pwField && cred.password) setNativeValue(pwField, cred.password);
            closePanel();
          } else {
            openPanel(
              anchor,
              note((cred && cred.message) || "Couldn't retrieve the password."),
            );
          }
        });
        list.appendChild(row);
      }
      openPanel(anchor, list);
    } finally {
      querying = false;
    }
  }

  // Placement callbacks for every attached badge, re-run on scroll/resize AND
  // on DOM mutation so a badge whose field gets hidden (e.g. a two-step page
  // swapping the identifier view for the password view) hides with it instead
  // of floating over the new screen.
  const placements = [];
  const replaceAll = () => placements.forEach((p) => p());

  function attachBadge(field, isIdentifier = false) {
    if (field.dataset.sybrAttached) return;
    field.dataset.sybrAttached = "1";

    const badge = document.createElement("button");
    badge.type = "button";
    badge.className = "sybr-badge";
    badge.title = "Autofill from SYBR Passwords";
    badge.textContent = "🔑";

    const place = () => {
      const rect = field.getBoundingClientRect();
      // Hide when the field is gone or not rendered (offsetParent null covers
      // display:none and detached views).
      if (field.offsetParent === null || (rect.width === 0 && rect.height === 0)) {
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
      showMatches(field, false, isIdentifier); // manual: always give feedback
    });

    document.body.appendChild(badge);
    placements.push(place);
    place();
    window.addEventListener("scroll", place, { passive: true });
    window.addEventListener("resize", place, { passive: true });

    // Suggest automatically when the user focuses the field — like a native
    // autofill prompt.
    field.addEventListener("focus", () => showMatches(field, true, isIdentifier));
    if (isIdentifier) return;

    // For password fields, also suggest from the associated username field —
    // unless that field already carries its own (identifier) badge, which would
    // double-bind the focus handler.
    const userField = findUsernameField(field);
    if (
      userField &&
      !userField.dataset.sybrUserBound &&
      !userField.dataset.sybrAttached
    ) {
      userField.dataset.sybrUserBound = "1";
      userField.addEventListener("focus", () => showMatches(field, true));
    }
  }

  /** Likely username/email inputs on identifier-first pages (Google/Microsoft
      style two-step sign-in). Deliberately requires a strong login signal — an
      explicit `autocomplete=username`, or a login-specific name/id — so plain
      newsletter/contact email boxes don't get badged. */
  function identifierFields() {
    const LOGIN_RE = /(^|[-_.])(user(name)?|login|loginfmt|identifier)([-_.]|$)/i;
    return Array.from(
      document.querySelectorAll(
        'input[type="email"], input[type="text"], input[autocomplete~="username"]',
      ),
    ).filter((el) => {
      if (el.dataset.sybrAttached || el.offsetParent === null) return false;
      if ((el.getAttribute("autocomplete") || "").split(/\s+/).includes("username"))
        return true;
      return LOGIN_RE.test(el.name || "") || LOGIN_RE.test(el.id || "");
    });
  }

  function scan() {
    document
      .querySelectorAll('input[type="password"]:not([data-sybr-attached])')
      .forEach((pw) => attachBadge(pw));

    // Identifier-first pages: only when there's no VISIBLE password field yet
    // (a display:none password field shouldn't suppress the identifier badge).
    if (!visiblePasswordField()) {
      identifierFields().forEach((el) => attachBadge(el, true));
    }
    replaceAll();
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
