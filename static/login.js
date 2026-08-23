const password = document.getElementById("password");
const toggle = document.getElementById("toggle-password");

toggle.addEventListener("click", () => {
  const show = password.type === "password";
  password.type = show ? "text" : "password";
  toggle.textContent = show ? "Hide" : "Show";
  toggle.setAttribute("aria-label", show ? "Hide password" : "Show password");
  password.focus();
});
