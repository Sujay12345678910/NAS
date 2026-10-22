import {
  api, show, setAlert, renderPassword, copyText, flashCopied,
  updateTopbar, setupSignOut, storage,
} from "./common.js";

const MAX_COUNT = 50;
const RECENT_LIMIT = 5;

const $ = (id) => document.getElementById(id);

const pageError = $("page-error");
const sections = { setup: $("setup"), keys_changed: $("keys-changed"), ready: $("generator") };

let status = null;
let count = 5;
let length = 15;
let lastBatch = [];

setupSignOut();
start();

async function start() {
  try {
    status = await api("/api/status");
  } catch (error) {
    setAlert(pageError, error.message);
    return;
  }
  render(status);
}

/** Show the right panel for the account's state. */
function render(newStatus) {
  status = newStatus;
  updateTopbar(status);
  for (const [state, element] of Object.entries(sections)) {
    show(element, state === status.state);
  }
  if (status.state === "setup") {
    setAlert($("setup-notice"), status.notice);
    $("recipients").focus();
  } else if (status.state === "keys_changed") {
    renderKeyDiff(status.keyChange);
  } else {
    renderRecentLabels();
  }
}

/* ── first sign-in: save the age public key ─────────────── */

$("setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorBox = $("setup-error");
  setAlert(errorBox, "");
  const button = event.submitter || event.target.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    render(await api("/api/setup", { method: "POST", body: { recipients: $("recipients").value } }));
  } catch (error) {
    setAlert(errorBox, error.message);
  } finally {
    button.disabled = false;
  }
});

/* ── the public keys on the NAS changed ─────────────────── */

function renderKeyDiff(change) {
  const list = $("key-diff");
  list.replaceChildren();
  const add = (keys, kind, sign) => {
    for (const key of keys) {
      const item = document.createElement("li");
      item.className = `key-diff-item key-diff-item--${kind}`;
      const marker = document.createElement("span");
      marker.className = "key-diff-sign";
      marker.textContent = sign;
      const code = document.createElement("code");
      code.className = "code";
      code.textContent = key;
      item.append(marker, code);
      list.append(item);
    }
  };
  add(change.added, "added", "+");
  add(change.removed, "removed", "−");
}

$("accept-keys").addEventListener("click", async () => {
  try {
    render(await api("/api/keys/accept", { method: "POST", body: {} }));
  } catch (error) {
    setAlert(pageError, error.message);
  }
});

$("reject-keys").addEventListener("click", () => $("sign-out").click());

/* ── options ───────────────────────────────────────────── */

function setCount(value) {
  count = Math.min(MAX_COUNT, Math.max(1, value));
  $("count").textContent = String(count);
  $("count-down").disabled = count === 1;
  $("count-up").disabled = count === MAX_COUNT;
  $("gen-text").textContent = `Generate ${count} password${count === 1 ? "" : "s"}`;
}

$("count-down").addEventListener("click", () => setCount(count - 1));
$("count-up").addEventListener("click", () => setCount(count + 1));
setCount(count);

for (const option of document.querySelectorAll(".segmented-option")) {
  option.addEventListener("click", () => {
    length = Number(option.dataset.length);
    for (const other of document.querySelectorAll(".segmented-option")) {
      other.setAttribute("aria-pressed", String(other === option));
    }
  });
}

function recentKey() {
  return `pwgen.recentLabels.${status ? status.username : ""}`;
}

function renderRecentLabels() {
  const box = $("recent-labels");
  box.replaceChildren();
  for (const label of storage.get(recentKey(), [])) {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chip mono";
    chip.textContent = label;
    chip.addEventListener("click", () => {
      $("label").value = label;
      $("label").focus();
    });
    box.append(chip);
  }
  show(box, box.children.length > 0);
}

function rememberLabel(label) {
  if (!label) return;
  const recent = storage.get(recentKey(), []).filter((l) => l !== label);
  storage.set(recentKey(), [label, ...recent].slice(0, RECENT_LIMIT));
  renderRecentLabels();
}

/* ── generate ──────────────────────────────────────────── */

$("gen-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("gen-button");
  const errorBox = $("gen-error");
  setAlert(errorBox, "");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");

  try {
    const result = await api("/api/generate", {
      method: "POST",
      body: { count, length, label: $("label").value },
    });
    showResults(result);
    rememberLabel(result.label);
    updateTopbar(result.status);
  } catch (error) {
    setAlert(errorBox, error.message);
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
});

function showResults(result) {
  lastBatch = result.passwords;
  const n = lastBatch.length;
  $("results-title").textContent = `${n} new password${n === 1 ? "" : "s"}`;

  const labelChip = $("results-label");
  labelChip.textContent = result.label;
  show(labelChip, Boolean(result.label));

  show($("saved-nas"), result.savedToNas);
  show($("saved-offline"), !result.savedToNas);
  $("saved-offline").title = result.error || "";

  const list = $("results-list");
  const template = $("pw-row-template");
  list.replaceChildren();
  lastBatch.forEach((password, i) => {
    const row = template.content.firstElementChild.cloneNode(true);
    row.querySelector(".pw-num").textContent = String(i + 1).padStart(2, "0");
    renderPassword(row.querySelector(".pw"), password);
    const copy = row.querySelector(".copy-btn");
    copy.setAttribute("aria-label", `Copy password ${i + 1}`);
    copy.addEventListener("click", async () => flashCopied(copy, await copyText(password)));
    list.append(row);
  });

  show($("results-empty"), n === 0);
  $("copy-all").disabled = n === 0;
}

$("copy-all").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  flashCopied(button, await copyText(lastBatch.join("\n")), "Copy all");
});

// Don't leave passwords on screen if the page is restored from the back/forward cache.
window.addEventListener("pageshow", (event) => {
  if (event.persisted) {
    lastBatch = [];
    $("results-list").replaceChildren();
    $("results-title").textContent = "No passwords yet";
    show($("results-label"), false);
    show($("saved-nas"), false);
    show($("saved-offline"), false);
    show($("results-empty"), true);
    $("copy-all").disabled = true;
  }
});
