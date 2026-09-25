const post = async (path, body) => {
  const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), cache: "no-store" });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
};

const message = (text, kind = "") => {
  const element = document.querySelector("#login-message");
  element.textContent = text;
  element.className = `form-result ${kind}`;
};

const show = form => {
  for (const id of ["#login-form", "#recovery-form"]) document.querySelector(id).classList.toggle("hidden", id !== form);
  message("");
  document.querySelector(`${form} input`).focus();
};

document.querySelector("#login-form").addEventListener("submit", async event => {
  event.preventDefault();
  const password = document.querySelector("#login-password");
  message("Signing in…");
  try {
    await post("/auth/login", { username: document.querySelector("#login-username").value.trim(), password: password.value });
    location.replace("/");
  } catch (error) {
    password.value = "";
    message(error.message, "bad");
  }
});

document.querySelector("#show-recovery").addEventListener("click", () => show("#recovery-form"));
document.querySelector("#show-login").addEventListener("click", () => show("#login-form"));

document.querySelector("#send-code").addEventListener("click", async event => {
  event.target.disabled = true;
  message("Sending…");
  try {
    const { to } = await post("/auth/recovery/request", {});
    message(`Code emailed to ${to}.`, "good");
    document.querySelector("#recovery-code").focus();
  } catch (error) {
    message(error.message, "bad");
  } finally {
    setTimeout(() => { event.target.disabled = false; }, 60_000);
  }
});

document.querySelector("#recovery-form").addEventListener("submit", async event => {
  event.preventDefault();
  const password = document.querySelector("#recovery-password").value;
  if (password !== document.querySelector("#recovery-confirm").value) return message("The passwords do not match.", "bad");
  message("Resetting…");
  try {
    await post("/auth/recovery/reset", { code: document.querySelector("#recovery-code").value.trim(), newPassword: password });
    location.replace("/");
  } catch (error) {
    message(error.message, "bad");
  }
});
