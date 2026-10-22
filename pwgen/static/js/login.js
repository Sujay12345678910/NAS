import { api, setAlert } from "./common.js";

const form = document.getElementById("login-form");
const button = document.getElementById("login-button");
const errorBox = document.getElementById("login-error");
const username = document.getElementById("username");
const password = document.getElementById("password");

// Say which NAS this signs in to.
api("/api/info")
  .then((info) => {
    document.getElementById("nas-host").textContent = info.nas;
  })
  .catch(() => {});

username.focus();

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setAlert(errorBox, "");

  if (!username.value.trim() || !password.value) {
    setAlert(errorBox, "Enter your username and password.");
    (username.value.trim() ? password : username).focus();
    return;
  }

  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  button.textContent = "Signing in…";

  try {
    await api("/api/login", {
      method: "POST",
      body: { username: username.value.trim(), password: password.value },
    });
    password.value = "";
    window.location.replace("/generate");
  } catch (error) {
    let message = error.message;
    const left = error.data && error.data.attemptsLeft;
    if (typeof left === "number") {
      message += left > 0
        ? ` ${left} attempt${left === 1 ? "" : "s"} left before a 15-minute lockout.`
        : " Sign-in is locked for 15 minutes.";
    }
    setAlert(errorBox, message);
    password.value = "";
    password.focus();
    button.disabled = false;
    button.removeAttribute("aria-busy");
    button.textContent = "Sign in";
  }
});
