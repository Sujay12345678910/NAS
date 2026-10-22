// Shared helpers for every page: talking to the server, the top bar,
// showing passwords, and copying to the clipboard.

const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^{}";
const CLIPBOARD_CLEAR_MS = 30_000;

export class ApiError extends Error {
  constructor(message, status, data) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

/** Call the pwgen API. Throws ApiError with the server's message on failure. */
export async function api(path, { method = "GET", body } = {}) {
  const options = {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers: { "X-Pwgen": "1" },          // the server refuses API calls without it
  };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }

  let response;
  try {
    response = await fetch(path, options);
  } catch {
    throw new ApiError("Can’t reach the pwgen server.", 0, {});
  }
  let data = {};
  try {
    data = await response.json();
  } catch {
    /* empty or non-JSON body */
  }
  if (response.status === 401 && data.signedOut) {
    window.location.replace("/login");
  }
  if (!response.ok) {
    throw new ApiError(data.error || `Request failed (${response.status})`, response.status, data);
  }
  return data;
}

/** Show or hide an element using the `hidden` attribute. */
export function show(element, visible = true) {
  element.hidden = !visible;
}

/** Put a message into an .alert box (or hide it when message is empty). */
export function setAlert(element, message) {
  const text = element.querySelector(".alert-text") || element;
  text.textContent = message || "";
  show(element, Boolean(message));
}

/**
 * Write a password into `target`, wrapping digits and symbols in
 * <span class="pw-digit"> / <span class="pw-symbol"> so CSS can colour them.
 * Uses text nodes only, never innerHTML.
 */
export function renderPassword(target, password) {
  target.replaceChildren();
  for (const ch of password) {
    if (DIGITS.includes(ch) || SYMBOLS.includes(ch)) {
      const span = document.createElement("span");
      span.className = DIGITS.includes(ch) ? "pw-digit" : "pw-symbol";
      span.textContent = ch;
      target.append(span);
    } else {
      target.append(document.createTextNode(ch));
    }
  }
}

let clearTimer = null;

/**
 * Copy text to the clipboard, then clear the clipboard 30 seconds later.
 * Falls back to the old execCommand route where the Clipboard API is missing
 * (it only exists on HTTPS pages and localhost).
 */
export async function copyText(text) {
  let ok = false;
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch {
      ok = false;
    }
  }
  if (!ok) ok = legacyCopy(text);
  if (ok && navigator.clipboard && window.isSecureContext) {
    clearTimeout(clearTimer);
    clearTimer = setTimeout(() => {
      navigator.clipboard.writeText("").catch(() => {});
    }, CLIPBOARD_CLEAR_MS);
  }
  return ok;
}

function legacyCopy(text) {
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.className = "visually-hidden";
  document.body.append(area);
  area.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  area.remove();
  return ok;
}

/** Briefly switch a copy button to "Copied" (data-copied lets CSS style it). */
export function flashCopied(button, ok, idleLabel = "Copy") {
  const label = button.querySelector(".copy-label");
  label.textContent = ok ? "Copied" : "Copy failed";
  button.dataset.copied = ok ? "true" : "false";
  clearTimeout(button._resetTimer);
  button._resetTimer = setTimeout(() => {
    label.textContent = idleLabel;
    delete button.dataset.copied;
  }, 2000);
}

/** Fill in the top bar from a /api/status response. */
export function updateTopbar(status) {
  const who = document.getElementById("whoami");
  if (who) who.textContent = `${status.username}@nas`;

  const dot = document.getElementById("status-dot");
  const text = document.getElementById("status-text");
  if (!dot || !text) return;

  let state = "ok";
  let message = "Synced with NAS";
  if (status.state === "setup") {
    state = "warn";
    message = "Setup needed";
  } else if (status.state === "keys_changed") {
    state = "warn";
    message = "Check your keys";
  } else if (!status.online || status.pendingSync || status.syncError) {
    state = "warn";
    message = "NAS offline · saving here";
  }
  dot.dataset.state = state;
  text.textContent = message;
}

/** Wire up the Sign out button. */
export function setupSignOut() {
  const button = document.getElementById("sign-out");
  if (!button) return;
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      await api("/api/logout", { method: "POST", body: {} });
    } finally {
      window.location.replace("/login");
    }
  });
}

/** Turn an ISO timestamp into "2026-10-21 18:38" in the viewer's time zone. */
export function formatDate(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso || "";
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Small wrapper so a blocked localStorage never breaks the page. */
export const storage = {
  get(key, fallback) {
    try {
      const raw = window.localStorage.getItem(key);
      return raw === null ? fallback : JSON.parse(raw);
    } catch {
      return fallback;
    }
  },
  set(key, value) {
    try {
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch {
      /* private window or storage disabled */
    }
  },
};
