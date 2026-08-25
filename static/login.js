const password = document.getElementById("password");
const toggle = document.getElementById("toggle-password");
const form = document.getElementById("login-form");
const submitButton = document.getElementById("submit-button");

toggle.addEventListener("click", () => {
  const show = password.type === "password";
  password.type = show ? "text" : "password";
  toggle.setAttribute("aria-label", show ? "Hide password" : "Show password");
  toggle.setAttribute("aria-pressed", String(show));
  password.focus();
});

form.addEventListener("submit", () => {
  submitButton.disabled = true;
  submitButton.classList.add("loading");
  submitButton.querySelector("span").textContent = "Verifying credentials…";
});
