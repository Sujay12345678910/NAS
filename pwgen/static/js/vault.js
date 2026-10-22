// The Vault page. Encrypted records come from the server; they are decrypted
// here, in the browser, with the age key the person picks. The key never
// leaves this page and is forgotten on Lock, on idle, or when the tab closes.

import * as age from "../vendor/age.js";
import {
  api, show, setAlert, renderPassword, copyText, flashCopied,
  updateTopbar, setupSignOut, formatDate,
} from "./common.js";

const IDLE_LOCK_MS = 5 * 60_000;
const $ = (id) => document.getElementById(id);

let decrypter = null;     // age.Decrypter holding the identity, only while unlocked
let entries = [];         // decrypted { id, label, created, password }
let revealed = new Set();
let showAll = false;
let filter = "all";
let pendingFile = null;   // passphrase-protected identity waiting for its passphrase
let idleTimer = null;

setupSignOut();
api("/api/status").then(updateTopbar).catch(() => {});

/* ── picking the key ───────────────────────────────────── */

const fileInput = $("key-file");
const dropzone = $("dropzone");

fileInput.addEventListener("change", () => {
  if (fileInput.files.length) handleKeyFile(fileInput.files[0]);
});

dropzone.addEventListener("dragover", (event) => {
  event.preventDefault();
  dropzone.dataset.dragover = "true";
});
dropzone.addEventListener("dragleave", () => delete dropzone.dataset.dragover);
dropzone.addEventListener("drop", (event) => {
  event.preventDefault();
  delete dropzone.dataset.dragover;
  const file = event.dataTransfer.files[0];
  if (file) handleKeyFile(file);
});

async function handleKeyFile(file) {
  setAlert($("unlock-error"), "");
  if (file.size > 64 * 1024) {
    return fail("That file is too big to be an age key.");
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  const text = new TextDecoder().decode(bytes);

  if (isEncrypted(bytes, text)) {
    // Made with `age -p`: ask for the passphrase, then unlock it here.
    pendingFile = { name: file.name, bytes, text };
    $("key-name").textContent = file.name;
    show($("passphrase-form"), true);
    $("passphrase").value = "";
    $("passphrase").focus();
    return;
  }
  await unlockWith(text);
}

function isEncrypted(bytes, text) {
  const header = new TextDecoder().decode(bytes.slice(0, 21));
  return header === "age-encryption.org/v1" || text.trimStart().startsWith("-----BEGIN AGE ENCRYPTED FILE-----");
}

$("passphrase-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!pendingFile) return;
  const passphrase = $("passphrase").value;
  $("passphrase").value = "";
  progress("Unlocking your key… this takes a few seconds.");
  try {
    const d = new age.Decrypter();
    d.addPassphrase(passphrase);
    const raw = pendingFile.text.trimStart().startsWith("-----BEGIN")
      ? age.armor.decode(pendingFile.text)
      : pendingFile.bytes;
    const identityText = await d.decrypt(raw, "text");
    pendingFile = null;
    show($("passphrase-form"), false);
    await unlockWith(identityText);
  } catch {
    progress("");
    fail("Wrong passphrase, or that file isn’t a passphrase-protected age key.");
    $("passphrase").focus();
  }
});

/* ── decrypting the vault ──────────────────────────────── */

async function unlockWith(identityText) {
  const identities = identityText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith("AGE-SECRET-KEY-"));

  if (identities.length === 0) {
    if (identityText.includes("OPENSSH PRIVATE KEY")) {
      return fail("That’s an SSH key. Choose your age key instead (the file with AGE-SECRET-KEY-1…).");
    }
    return fail("No age key found in that file. It should contain a line starting with AGE-SECRET-KEY-1.");
  }

  const d = new age.Decrypter();
  try {
    for (const identity of identities) d.addIdentity(identity);
  } catch {
    return fail("That age key looks damaged.");
  }

  progress("Fetching your vault…");
  let vault;
  try {
    vault = await api("/api/vault");
  } catch (error) {
    progress("");
    return fail(error.message);
  }

  const result = await decryptAll(d, vault.records);
  progress("");

  if (vault.records.length > 0 && result.entries.length === 0) {
    return fail(`This key can’t open any of your ${vault.records.length} passwords. Is it the right key?`);
  }

  decrypter = d;
  entries = result.entries;
  revealed = new Set();
  showAll = false;
  filter = "all";
  $("search").value = "";
  fileInput.value = "";

  const warnings = [];
  if (vault.source === "cache") warnings.push("The NAS is unreachable, so this is the copy saved on the server.");
  if (result.failed) warnings.push(`${result.failed} password${result.failed === 1 ? "" : "s"} couldn’t be opened with this key.`);
  if (result.mismatched) warnings.push(`${result.mismatched} record${result.mismatched === 1 ? " was" : "s were"} altered and ${result.mismatched === 1 ? "was" : "were"} skipped.`);
  if (vault.damaged) warnings.push(`${vault.damaged} damaged record${vault.damaged === 1 ? " was" : "s were"} skipped (interrupted writes).`);
  setAlert($("vault-warning"), warnings.join(" "));

  show($("locked"), false);
  show($("unlocked"), true);
  renderVault();
  resetIdleTimer();
}

async function decryptAll(d, records) {
  const out = { entries: [], failed: 0, mismatched: 0 };
  for (let i = 0; i < records.length; i++) {
    if (i % 10 === 0) progress(`Decrypting ${i + 1} of ${records.length}…`);
    const record = records[i];
    let data;
    try {
      const plaintext = await d.decrypt(age.armor.decode(record.armored), "text");
      data = JSON.parse(plaintext);
    } catch {
      out.failed++;
      continue;
    }
    // The ID inside the encryption must match the one outside it.
    if (data.id !== record.id) {
      out.mismatched++;
      continue;
    }
    out.entries.push({
      id: record.id,
      label: String(data.label || ""),
      created: String(data.created || ""),
      password: String(data.password || ""),
    });
  }
  out.entries.sort((a, b) => b.created.localeCompare(a.created));
  return out;
}

/* ── showing the vault ─────────────────────────────────── */

function visibleEntries() {
  const query = $("search").value.trim().toLowerCase();
  return entries.filter((e) =>
    (filter === "all" || e.label === filter) && (!query || e.label.toLowerCase().includes(query)));
}

function renderVault() {
  const n = entries.length;
  $("vault-summary").textContent = `${n} password${n === 1 ? "" : "s"}, decrypted in this browser.`;
  $("toggle-all-text").textContent = showAll ? "Hide all" : "Show all";
  $("toggle-all").setAttribute("aria-pressed", String(showAll));
  renderFilters();
  renderRows();
}

function renderFilters() {
  const counts = new Map();
  for (const e of entries) counts.set(e.label, (counts.get(e.label) || 0) + 1);
  const box = $("filters");
  box.replaceChildren();
  const addChip = (value, name, total) => {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chip mono";
    chip.setAttribute("aria-pressed", String(filter === value));
    const label = document.createElement("span");
    label.textContent = name;
    const number = document.createElement("span");
    number.className = "chip-count";
    number.textContent = String(total);
    chip.append(label, number);
    chip.addEventListener("click", () => {
      filter = value;
      renderFilters();
      renderRows();
    });
    box.append(chip);
  };
  addChip("all", "all", entries.length);
  for (const [label, total] of counts) addChip(label, label || "unlabelled", total);
}

function renderRows() {
  const body = $("vault-rows");
  const template = $("vault-row-template");
  const rows = visibleEntries();
  body.replaceChildren();

  for (const entry of rows) {
    const row = template.content.firstElementChild.cloneNode(true);
    const name = entry.label || "unlabelled";
    row.querySelector(".row-label").textContent = name;
    row.querySelector(".row-date").textContent = formatDate(entry.created);

    const pw = row.querySelector(".row-pw");
    const reveal = row.querySelector(".reveal-btn");
    const paint = () => {
      const visible = showAll || revealed.has(entry.id);
      if (visible) {
        renderPassword(pw, entry.password);
        pw.classList.remove("pw--masked");
      } else {
        pw.textContent = "•".repeat(entry.password.length);
        pw.classList.add("pw--masked");
      }
      reveal.setAttribute("aria-pressed", String(visible));
      reveal.setAttribute("aria-label", `${visible ? "Hide" : "Show"} password for ${name}`);
      show(reveal.querySelector(".icon-show"), !visible);
      show(reveal.querySelector(".icon-hide"), visible);
    };
    reveal.addEventListener("click", () => {
      const visible = showAll || revealed.has(entry.id);
      if (showAll) {
        // Leaving "show all" by hiding one: keep the others visible.
        showAll = false;
        revealed = new Set(visibleEntries().map((e) => e.id));
        $("toggle-all-text").textContent = "Show all";
        $("toggle-all").setAttribute("aria-pressed", "false");
      }
      if (visible) revealed.delete(entry.id);
      else revealed.add(entry.id);
      paint();
    });
    paint();

    const copy = row.querySelector(".copy-btn");
    copy.setAttribute("aria-label", `Copy password for ${name}`);
    copy.addEventListener("click", async () => flashCopied(copy, await copyText(entry.password)));

    body.append(row);
  }

  show($("vault-empty"), rows.length === 0);
}

$("search").addEventListener("input", renderRows);

$("toggle-all").addEventListener("click", () => {
  showAll = !showAll;
  revealed = new Set();
  renderVault();
});

$("refresh").addEventListener("click", async (event) => {
  if (!decrypter) return;
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const vault = await api("/api/vault");
    const result = await decryptAll(decrypter, vault.records);
    progress("");
    entries = result.entries;
    renderVault();
  } catch (error) {
    setAlert($("vault-warning"), error.message);
  } finally {
    button.disabled = false;
  }
});

/* ── locking ───────────────────────────────────────────── */

function lock() {
  decrypter = null;
  entries = [];
  revealed = new Set();
  showAll = false;
  pendingFile = null;
  clearTimeout(idleTimer);
  $("vault-rows").replaceChildren();
  $("filters").replaceChildren();
  fileInput.value = "";
  show($("passphrase-form"), false);
  show($("unlocked"), false);
  show($("locked"), true);
  setAlert($("unlock-error"), "");
}

$("lock").addEventListener("click", lock);

function resetIdleTimer() {
  if (!decrypter) return;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(lock, IDLE_LOCK_MS);
}

for (const type of ["pointerdown", "keydown", "scroll", "pointermove"]) {
  window.addEventListener(type, resetIdleTimer, { passive: true });
}

// Never come back from the back/forward cache with passwords still showing.
window.addEventListener("pagehide", lock);

/* ── small helpers ─────────────────────────────────────── */

function fail(message) {
  setAlert($("unlock-error"), message);
  fileInput.value = "";
}

function progress(message) {
  const box = $("unlock-progress");
  box.textContent = message;
  show(box, Boolean(message));
}
