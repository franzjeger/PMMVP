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
    // Fixed positioning: viewport coords straight from the rect (no scroll
    // offsets), so offset/transformed page bodies can't displace the panel.
    const rect = anchor.getBoundingClientRect();
    panel = document.createElement("div");
    panel.className = "sybr-panel";
    panel.style.top = `${rect.bottom + 6}px`;
    panel.style.left = `${rect.left}px`;
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

  // Cached match list for the current page, so filtering as the user types
  // doesn't spawn the native host on every keystroke. Keyed by URL; only a
  // non-empty (unlocked) result is cached.
  let cache = null; // { url, items }
  const cachedItems = () =>
    cache && cache.url === location.href ? cache.items : null;

  /** Rank an item against the typed query: username prefix beats username
      substring beats title. -1 = no match. */
  function score(item, q) {
    const u = (item.username || "").toLowerCase();
    const t = (item.title || "").toLowerCase();
    if (u.startsWith(q)) return 0;
    if (u.includes(q)) return 1;
    if (t.startsWith(q)) return 2;
    if (t.includes(q)) return 3;
    return -1;
  }

  /** Filter + rank so the most likely account floats to the top as you type. */
  function rank(items, query) {
    const q = (query || "").trim().toLowerCase();
    if (!q) return items;
    return items
      .map((it) => ({ it, s: score(it, q) }))
      .filter((x) => x.s >= 0)
      .sort(
        (a, b) =>
          a.s - b.s ||
          (a.it.username || a.it.title || "").localeCompare(
            b.it.username || b.it.title || "",
          ),
      )
      .map((x) => x.it);
  }

  /** Build one selectable row for `item`. */
  function buildRow(item, anchor, isIdentifier) {
    const row = document.createElement("button");
    row.className = "sybr-row";
    const isPasskey = item.kind === "passkey";
    row.innerHTML =
      `<span class="sybr-line"><span class="sybr-title"></span>` +
      `<span class="sybr-kind"></span></span><span class="sybr-user"></span>`;
    row.querySelector(".sybr-title").textContent = item.title || item.url;
    row.querySelector(".sybr-user").textContent = item.username || "";
    const kindEl = row.querySelector(".sybr-kind");
    kindEl.textContent = isPasskey ? "Passkey" : "Password";
    kindEl.classList.add(isPasskey ? "sybr-kind-passkey" : "sybr-kind-password");
    row.addEventListener("click", async () => {
      // A passkey isn't typed into a field — it signs in through the site's own
      // passkey ceremony, which Arca approves via the WebAuthn shim. So a passkey
      // row is informational, not a fill action.
      if (isPasskey) {
        openPanel(
          anchor,
          note(
            `Passkey for ${item.title || item.username || "this site"} — choose ` +
              `“Sign in with a passkey” on the page and Arca will approve it.`,
          ),
        );
        return;
      }
      const pwField = isIdentifier ? visiblePasswordField() : anchor;
      if (isIdentifier && !pwField) {
        // Pure identifier step (no password field yet): fill just the username.
        // It's metadata already in `item`; no credential request is made.
        if (item.username) setNativeValue(anchor, item.username);
        closePanel();
        return;
      }
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
        openPanel(anchor, note(`Could not fill: ${String(e)}`));
        return;
      }
      const cred = fill && fill.ok ? fill.response : null;
      if (cred && cred.type === "credentials") {
        const userField = isIdentifier ? anchor : findUsernameField(anchor);
        if (userField && cred.username) setNativeValue(userField, cred.username);
        if (pwField && cred.password) setNativeValue(pwField, cred.password);
        closePanel();
      } else {
        openPanel(
          anchor,
          note((cred && cred.message) || "Couldn't retrieve the password."),
        );
      }
    });
    return row;
  }

  /** Render the (filtered, ranked) picker. On an identifier field, filter by
      what's typed so far; empty result closes the panel. */
  function renderPicker(anchor, items, isIdentifier) {
    const filtered = isIdentifier ? rank(items, anchor.value) : items;
    if (filtered.length === 0) {
      closePanel();
      return;
    }
    const list = document.createElement("div");
    filtered.forEach((it) => list.appendChild(buildRow(it, anchor, isIdentifier)));
    openPanel(anchor, list);
  }

  // Show matching logins. `auto` = triggered by focus (stay quiet when there's
  // nothing useful); manual (badge click) always gives feedback.
  // `isIdentifier` = the anchor is a username/email field (not a password
  // field). Whether a pick fills only the username or also the password is
  // decided at click time by whether a password field is visible, so a field
  // badged during the identifier step still does a full fill once the password
  // step appears.
  async function showMatches(anchor, auto, isIdentifier = false) {
    // Filter from cache without a round-trip when we already have the page's
    // matches (this is the type-ahead path).
    const have = cachedItems();
    if (have) {
      renderPicker(anchor, have, isIdentifier);
      bindTypeAhead(anchor, isIdentifier);
      return;
    }

    // Coalesce automatic (focus) triggers, but never drop a manual badge click:
    // "manual always gives feedback".
    if (querying && auto) return;
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
              "Can't reach Arca. Is the desktop app installed and the extension's native host registered?",
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
            openPanel(anchor, note("Open and unlock Arca to autofill."));
          }
        } else if (!auto) {
          openPanel(anchor, note("No matching logins for this site."));
        } else {
          closePanel();
        }
        return;
      }

      cache = { url: location.href, items };
      renderPicker(anchor, items, isIdentifier);
      bindTypeAhead(anchor, isIdentifier);
    } finally {
      querying = false;
    }
  }

  /** Re-filter the picker as the user types in an identifier/username field. */
  function bindTypeAhead(anchor, isIdentifier) {
    if (!isIdentifier || anchor.dataset.sybrFilterBound) return;
    anchor.dataset.sybrFilterBound = "1";
    anchor.addEventListener("input", () => {
      const items = cachedItems();
      // Only re-render while this field is focused, so filtering never fights
      // typing in another field.
      if (items && document.activeElement === anchor) {
        renderPicker(anchor, items, true);
      }
    });
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
    badge.title = "Autofill from Arca";
    // Inline SVG key (currentColor): renders identically on every platform,
    // unlike the key emoji which falls back to a dark monochrome glyph on
    // Windows. Colors come from content.css (theme-aware).
    badge.innerHTML =
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      '<circle cx="8" cy="15" r="4"/><path d="M10.85 12.15 19 4"/><path d="m18 5 2 2"/><path d="m15 8 2 2"/></svg>';

    const place = () => {
      const rect = field.getBoundingClientRect();
      // Hide when the field is gone or not rendered (offsetParent null covers
      // display:none and detached views).
      if (field.offsetParent === null || (rect.width === 0 && rect.height === 0)) {
        badge.style.display = "none";
        return;
      }
      badge.style.display = "flex";
      // Viewport coords (position: fixed) — no scroll offsets. Vertically
      // centered on the field, tucked just inside its right edge.
      badge.style.top = `${rect.top + rect.height / 2 - 11}px`;
      badge.style.left = `${rect.right - 28}px`;
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
    // double-bind the focus handler. Anchor the picker to the username field
    // itself (so it appears under the focused field) and let the click-time
    // full-fill path fill both, since a visible password field exists here.
    const userField = findUsernameField(field);
    if (
      userField &&
      !userField.dataset.sybrUserBound &&
      !userField.dataset.sybrAttached
    ) {
      userField.dataset.sybrUserBound = "1";
      userField.addEventListener("focus", () => showMatches(userField, true, true));
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

  // (Passkey relay lives in passkey-relay.js, injected at document_start so it's
  // listening before the main-world shim can post an early WebAuthn request.)

  // ---- save-on-submit -----------------------------------------------------
  // Offer to save a new/changed login when the user submits a sign-in form.
  const bareHost = (u) => {
    try {
      return new URL(u, location.href).hostname.replace(/^www\./, "");
    } catch (_e) {
      return "";
    }
  };
  /** Same site (exact host, or a sub/parent-domain relationship). */
  const sameSite = (urlA, urlB) => {
    const a = bareHost(urlA);
    const b = bareHost(urlB);
    return !!a && !!b && (a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`));
  };

  /** Capture credentials from a submitted form — only a single-password form
      (a sign-in, not a signup/change form with two+ password fields) that also
      has a resolvable username. Requiring a username avoids collapsing distinct
      accounts on identifier-first / password-only pages into one "(host, '')"
      entry that would overwrite each other. */
  function captureCandidate(form) {
    const pws = Array.from(
      form.querySelectorAll('input[type="password"]'),
    ).filter((el) => el.value);
    if (pws.length !== 1) return null;
    const userEl = findUsernameField(pws[0]);
    if (!userEl || !userEl.value) return null;
    return { url: location.href, username: userEl.value, password: pws[0].value };
  }

  let saveBar = null;
  function closeSaveBar() {
    saveBar?.remove();
    saveBar = null;
  }
  function showSaveBar(candidate, action) {
    closeSaveBar();
    const host = bareHost(candidate.url);
    saveBar = document.createElement("div");
    saveBar.className = "sybr-savebar";
    const text = document.createElement("span");
    text.className = "sybr-savebar-text";
    text.textContent =
      action === "update"
        ? `Update password for ${host} in Arca?`
        : `Save login for ${host} to Arca?`;
    const yes = document.createElement("button");
    yes.className = "sybr-savebar-yes";
    yes.textContent = action === "update" ? "Update" : "Save";
    const no = document.createElement("button");
    no.className = "sybr-savebar-no";
    no.textContent = "Not now";
    const done = () => {
      api.runtime.sendMessage({ cmd: "clearPending" }).catch(() => {});
      closeSaveBar();
    };
    yes.addEventListener("click", async () => {
      try {
        await api.runtime.sendMessage({ cmd: "saveLogin", ...candidate });
      } catch (_e) {
        /* ignore */
      }
      done();
    });
    no.addEventListener("click", done);
    saveBar.append(text, yes, no);
    document.body.appendChild(saveBar);
  }

  async function offerSave(candidate) {
    if (!candidate || !candidate.password) return;
    let probe;
    try {
      probe = await api.runtime.sendMessage({ cmd: "saveProbe", ...candidate });
    } catch (_e) {
      return;
    }
    const action = probe && probe.ok && probe.response ? probe.response.action : null;
    if (action === "new" || action === "update") showSaveBar(candidate, action);
  }

  // On submit: stash the candidate for after navigation. For SPA logins that
  // DON'T navigate, offer only after a short delay AND only if the login form
  // is gone — a success signal, so a failed/mistyped login can't prompt to
  // overwrite a good stored password. Navigation-based logins tear down this
  // timer; the post-navigation reshow (below) handles those.
  document.addEventListener(
    "submit",
    (e) => {
      const form = e.target;
      if (!(form instanceof HTMLFormElement)) return;
      const candidate = captureCandidate(form);
      if (!candidate) return;
      api.runtime
        .sendMessage({ cmd: "capturePending", ...candidate })
        .catch(() => {});
      setTimeout(() => {
        if (!visiblePasswordField()) void offerSave(candidate);
      }, 1500);
    },
    true,
  );

  // After a navigation: if a login was just submitted and we now appear signed
  // in (same site, no password field), offer to save the stashed candidate.
  (async () => {
    let pending;
    try {
      pending = await api.runtime.sendMessage({ cmd: "consumePending" });
    } catch (_e) {
      return;
    }
    const cand = pending && pending.ok ? pending.candidate : null;
    if (!cand) return;
    if (sameSite(cand.url, location.href) && !visiblePasswordField()) {
      void offerSave(cand);
    }
  })();
})();
