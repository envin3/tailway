const SERVER_PAGE_SIZE = 25;
const COUNTRY_PAGE_SIZE = 12;
const LOCAL_ROUTE_ID = "__local__";
const DIRECT_ROUTE_ID = "__direct__";
const BUILTIN_ROUTES = new Set([LOCAL_ROUTE_ID, DIRECT_ROUTE_ID]);
const POLICY_LABELS = { block: "Blocked", local: "Local only", direct: "Direct Internet" };
const state = { username: "", consoleAccount: null, accountFormLoaded: false, mailFormLoaded: false, alerts: null, alertFormLoaded: false, revision: 0, csrfToken: "", status: null, servers: [], protonServers: [], protonAccount: null, protonAvailable: true, exits: [], devices: [], selectedServer: null, serverPage: 1, expandedCountry: "", countryServerPage: 1 };
const regionNames = new Intl.DisplayNames(["en"], { type: "region" });

const api = async (path, options = {}) => {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrfToken;
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
  const payload = await response.json().catch(() => ({}));
  if (response.status === 401) {
    location.replace("/login");
    throw new Error("Signed out");
  }
  if (response.status === 403 && payload.error === "invalid CSRF token" && !options.csrfRetried) {
    // The session expired and a new one was issued; fetch its token and retry once.
    state.csrfToken = (await api("/session")).csrfToken;
    return api(path, { ...options, csrfRetried: true });
  }
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
};

const load = async () => {
  try {
    if (!state.csrfToken) {
      const session = await api("/session");
      state.csrfToken = session.csrfToken;
      state.username = session.username;
    }
    const [status, catalog, exits, devices, alerts, consoleAccount] = await Promise.all([
      api("/v1/status"), api("/v1/catalog"), api("/v1/exits"), api("/v1/devices"), api("/v1/alerts"), api("/auth/account")
    ]);
    state.alerts = alerts;
    state.consoleAccount = consoleAccount;
    state.status = status;
    state.servers = catalog.servers || [];
    state.exits = exits.exits || [];
    state.devices = devices || [];
    state.revision = Math.max(status.revision || 0, exits.revision || 0);
    try {
      state.protonAccount = await api("/v1/proton/account");
      state.protonAvailable = true;
      if (state.protonAccount.state === "authenticated") {
        try { state.protonServers = (await api("/v1/proton/servers")).servers || []; }
        catch (_) { state.protonServers = []; }
      } else {
        state.protonServers = [];
      }
    } catch (_) {
      state.protonAvailable = false;
      state.protonAccount = null;
      state.protonServers = [];
    }
    render();
    renderAlerts();
    renderConsoleAccount();
    showAlert([status.lastError, ...activeProblems(status)].filter(Boolean).join(" · "));
  } catch (error) {
    showAlert(error.message);
    document.querySelector("#health-label").textContent = "Unavailable";
    document.querySelector("#health-dot").className = "bad";
  }
};

// Conditions that outlived their grace period (the ones that were notified).
const activeProblems = (status) => (status?.alerts || []).filter((alert) => alert.notified).map((alert) => alert.message);

const render = () => {
  const healthy = state.status?.state === "healthy" && activeProblems(state.status).length === 0;
  document.querySelector("#health-label").textContent = healthy ? "Agent healthy" : "Action required";
  document.querySelector("#health-dot").className = healthy ? "good" : "bad";
  document.querySelector("#metric-state").textContent = state.status?.state || "Unknown";
  document.querySelector("#metric-exits").textContent = state.status?.exitLimit ? `${state.exits.length} / ${state.status.exitLimit}` : state.exits.length;
  document.querySelector("#metric-devices").textContent = state.devices.filter(device => device.exitId && !BUILTIN_ROUTES.has(device.exitId)).length;
  const policy = state.status?.unassignedPolicy || "block";
  document.querySelector("#posture-default-status").textContent = POLICY_LABELS[policy] || policy;
  document.querySelector("#posture-default-status").className = `posture-status ${policy === "direct" ? "warn" : "good"}`;
  document.querySelector("#posture-default-text").textContent = `Nodes without an assignment are ${(POLICY_LABELS[policy] || policy).toLowerCase()} (UNASSIGNED_POLICY=${policy}).`;
  document.querySelector("#metric-revision").textContent = state.revision;
  renderAccount();
  renderServers();
  renderExits();
  renderDevices();
};

const renderServers = () => {
  const query = document.querySelector("#server-search").value.trim().toLowerCase();
  const selectedFeatures = Array.from(document.querySelectorAll("#server-feature-filters input:checked"), input => input.value);
  const discovered = state.protonAccount?.state === "authenticated";
  const source = discovered ? state.protonServers : state.servers;
  const servers = source.filter(server => {
    const features = server.features || [];
    return selectedFeatures.every(feature => features.includes(feature))
      && [server.country, countryName(server.country), server.city, server.name, ...features].join(" ").toLowerCase().includes(query);
  });
  const countries = new Map();
  servers.forEach(server => {
    const country = server.country || "ZZ";
    if (!countries.has(country)) countries.set(country, []);
    countries.get(country).push(server);
  });
  const grouped = Array.from(countries, ([country, countryServers]) => ({ country, name: countryName(country), servers: countryServers }))
    .sort((left, right) => left.name.localeCompare(right.name));
  const pageCount = Math.max(1, Math.ceil(grouped.length / COUNTRY_PAGE_SIZE));
  state.serverPage = Math.min(state.serverPage, pageCount);
  const pageStart = (state.serverPage - 1) * COUNTRY_PAGE_SIZE;
  const page = grouped.slice(pageStart, pageStart + COUNTRY_PAGE_SIZE);
  if (state.expandedCountry && !page.some(group => group.country === state.expandedCountry)) state.expandedCountry = "";
  const addedIds = new Set(state.servers.map(server => server.id));
  document.querySelector("#server-count").textContent = `${servers.length} servers · ${grouped.length} countries`;
  document.querySelector("#server-source").textContent = discovered ? "Live inventory from your Proton account. Add a server to make it available for node routing." : "Sign in to Proton for live discovery, or use imported WireGuard configurations.";
  document.querySelector("#server-list").innerHTML = page.length ? page.map(group => renderCountryGroup(group, discovered, addedIds)).join("") : `<div class="empty">No matching servers.</div>`;
  document.querySelector("#server-page-label").textContent = `${state.serverPage} / ${pageCount}`;
  document.querySelector("#server-page-prev").disabled = state.serverPage === 1;
  document.querySelector("#server-page-next").disabled = state.serverPage === pageCount;
};

const renderCountryGroup = (group, discovered, addedIds) => {
  const expanded = state.expandedCountry === group.country;
  if (!expanded) return `
    <section class="server-country">
      <button class="country-header" data-country-toggle="${escapeHTML(group.country)}" aria-expanded="false">
        <span><strong>${escapeHTML(group.name)}</strong><small>${escapeHTML(group.country)} · ${group.servers.length} servers</small></span><span aria-hidden="true">›</span>
      </button>
    </section>`;
  const serverPageCount = Math.max(1, Math.ceil(group.servers.length / SERVER_PAGE_SIZE));
  state.countryServerPage = Math.min(state.countryServerPage, serverPageCount);
  const start = (state.countryServerPage - 1) * SERVER_PAGE_SIZE;
  const servers = group.servers.slice(start, start + SERVER_PAGE_SIZE);
  return `
    <section class="server-country expanded">
      <button class="country-header" data-country-toggle="${escapeHTML(group.country)}" aria-expanded="true">
        <span><strong>${escapeHTML(group.name)}</strong><small>${escapeHTML(group.country)} · ${group.servers.length} servers</small></span><span aria-hidden="true">⌄</span>
      </button>
      <div class="country-servers">${servers.map(server => `
        <div class="server-row">
          <span><strong>${escapeHTML(server.name)}</strong><br><small>${escapeHTML(server.id)}</small></span>
          <span class="city">${escapeHTML(server.city || "Any city")}</span>
          <span class="features">${(server.features || []).map(feature => `<span class="feature">${escapeHTML(feature)}</span>`).join("") || "Standard"}${server.load !== undefined ? `<br><small>${escapeHTML(server.load)}% load</small>` : ""}</span>
          ${discovered ? `<button data-add-server="${escapeHTML(server.id)}" ${!server.accessible || !server.online ? "disabled" : ""}>${addedIds.has(server.id) ? "Update" : "Add"}</button>` : `<button data-server="${escapeHTML(server.id)}">Create exit</button>`}
        </div>`).join("")}</div>
      ${serverPageCount > 1 ? `<div class="country-pagination"><button class="secondary" data-country-server-page="-1" ${state.countryServerPage === 1 ? "disabled" : ""}>Previous</button><span>${state.countryServerPage} / ${serverPageCount}</span><button class="secondary" data-country-server-page="1" ${state.countryServerPage === serverPageCount ? "disabled" : ""}>Next</button></div>` : ""}
    </section>`;
};

const countryName = country => {
  try { return regionNames.of(country) || country; }
  catch (_) { return country; }
};

const renderAccount = () => {
  const authenticated = state.protonAccount?.state === "authenticated";
  const needsTotp = state.protonAccount?.state === "twoFactorRequired";
  document.querySelector("#proton-login-form").classList.toggle("hidden", !state.protonAvailable || authenticated || needsTotp);
  document.querySelector("#proton-totp-form").classList.toggle("hidden", !state.protonAvailable || !needsTotp);
  document.querySelector("#proton-account-summary").classList.toggle("hidden", !authenticated);
  document.querySelector("#proton-unavailable").classList.toggle("hidden", state.protonAvailable);
  if (!authenticated) return;
  document.querySelector("#proton-account-name").textContent = state.protonAccount.username;
  document.querySelector("#proton-plan").textContent = state.protonAccount.plan;
  document.querySelector("#proton-connections").textContent = state.protonAccount.maxConnections;
  document.querySelector("#proton-core-version").textContent = state.protonAccount.coreVersion;
  const certificate = document.querySelector("#proton-certificate");
  const seconds = state.protonAccount.certificateValidSeconds;
  const refresh = state.protonAccount.backgroundRefresh ? "auto-renewing" : "NOT auto-renewing";
  if (seconds === null || seconds === undefined) certificate.textContent = `Unknown · ${refresh}`;
  else if (seconds <= 0) certificate.textContent = `Expired — tunnels will not pass traffic · ${refresh}`;
  else certificate.textContent = `Valid for ${Math.floor(seconds / 86400)}d ${Math.floor(seconds % 86400 / 3600)}h · ${refresh}`;
  certificate.className = seconds > 0 && state.protonAccount.backgroundRefresh ? "" : "warn-text";
};

const renderExits = () => {
  document.querySelector("#exit-list").innerHTML = state.exits.length ? state.exits.map(exit => `
    <article class="exit-card">
      <header><div><p class="eyebrow">${escapeHTML(exit.country)}${exit.city ? ` · ${escapeHTML(exit.city)}` : ""}</p><h2>${escapeHTML(exit.displayName)}</h2></div><strong class="state" title="${escapeHTML(exit.statusDetail || "")}">${escapeHTML(exit.status)}</strong></header>
      ${exit.statusDetail ? `<p class="status-detail">${escapeHTML(exit.statusDetail)}</p>` : ""}
      <div class="exit-meta"><div><span>Server</span><strong>${escapeHTML(exit.serverId)}</strong></div><div><span>Public IP</span><strong>${escapeHTML(exit.publicIp || "Pending verification")}</strong></div></div>
      <button class="danger" data-delete-exit="${escapeHTML(exit.id)}">Disconnect</button>
    </article>`).join("") : `<div class="empty">No Proton exits are configured. Choose a server to create one.</div>`;
};

const renderDevices = () => {
  const query = document.querySelector("#node-search").value.trim().toLowerCase();
  const devices = state.devices.filter(device => [device.displayName, device.nodeId, ...(device.addresses || [])].join(" ").toLowerCase().includes(query));
  const exitsById = new Map(state.exits.map(exit => [exit.id, exit]));
  document.querySelector("#node-count").textContent = `${devices.length} of ${state.devices.length} nodes`;
  document.querySelector("#device-list").innerHTML = devices.length ? devices.map(device => {
    const selectedExit = exitsById.get(device.exitId);
    const defaultLabel = POLICY_LABELS[state.status?.unassignedPolicy || "block"] || "Blocked";
    if (device.missing) return `
    <tr class="missing"><td><strong>Removed from tailnet</strong><br><small>${escapeHTML(device.nodeId)}</small></td><td>—</td><td>Missing</td><td>—</td><td>
      <button class="secondary" data-clear-node="${escapeHTML(device.nodeId)}">Clear assignment</button>
    </td><td>—</td></tr>`;
    return `
    <tr><td><strong>${escapeHTML(device.displayName || device.nodeId)}</strong><br><small>${escapeHTML(device.nodeId)}</small></td><td>${escapeHTML((device.addresses || []).join(", ") || "No IPv4 address")}</td><td>${device.online ? "Online" : "Offline"}</td><td><span class="activity ${device.active ? "observed" : ""}">${device.active ? "Observed" : device.online ? "Not observed" : "Offline"}</span></td><td>
      <select data-node="${escapeHTML(device.nodeId)}">
        <option value="">Default · ${escapeHTML(defaultLabel)}</option>
        <option value="${DIRECT_ROUTE_ID}" ${device.exitId === DIRECT_ROUTE_ID ? "selected" : ""}>Direct Internet · No VPN</option>
        <option value="${LOCAL_ROUTE_ID}" ${device.exitId === LOCAL_ROUTE_ID ? "selected" : ""}>Local only · No Internet</option>
        ${state.servers.map(server => `<option value="${escapeHTML(server.id)}" ${selectedExit?.serverId === server.id ? "selected" : ""}>${escapeHTML(server.name)} · ${escapeHTML(server.country)}${server.city ? ` · ${escapeHTML(server.city)}` : ""}</option>`).join("")}
      </select>
      ${selectedExit ? `<small>${escapeHTML(selectedExit.status)}</small>` : ""}
    </td><td>${dnsCell(device)}</td></tr>`;
  }).join("") : `<tr><td colspan="6" class="empty">${state.devices.length ? "No matching nodes." : "No Tailscale peers are visible."}</td></tr>`;
};

const dnsCell = device => {
  const dns = device.dns;
  if (!dns) return `<small>Forwarder off</small>`;
  const id = escapeHTML(device.nodeId);
  const onProton = device.exitId && !BUILTIN_ROUTES.has(device.exitId);
  const server = `<input class="dns-server" data-dns-server="${id}" value="${escapeHTML(dns.customServer || "")}" placeholder="${escapeHTML(dns.defaultServer)} (default)" aria-label="DNS server">`;
  if (!onProton) return server;
  const status = { proton: "Proton DNS in tunnel", blocked: "Blocked: tunnel down", server: `Fallback ${escapeHTML(dns.server)}` }[dns.resolution] || escapeHTML(dns.resolution);
  const killSwitch = `<label class="inline-check"><input type="checkbox" data-dns-kill="${id}" ${dns.killSwitch ? "checked" : ""}> Kill switch</label>`;
  return `<small>${status}</small><br>${killSwitch}${dns.killSwitch ? "" : `<br>${server}`}`;
};

const mutate = async (path, method, body = {}) => {
  try {
    const result = await api(path, { method, body: JSON.stringify({ revision: state.revision, ...body }) });
    state.revision = result.revision;
    await load();
  } catch (error) { showAlert(error.message); }
};

document.addEventListener("click", event => {
  const nav = event.target.closest("[data-view]");
  if (nav) {
    document.querySelectorAll(".nav-item,.view").forEach(element => element.classList.remove("active"));
    nav.classList.add("active");
    document.querySelector(`#${nav.dataset.view}`).classList.add("active");
    document.querySelector("#view-title").textContent = nav.textContent;
  }
  const serverButton = event.target.closest("[data-server]");
  if (serverButton) {
    state.selectedServer = state.servers.find(server => server.id === serverButton.dataset.server);
    document.querySelector("#dialog-server").textContent = `${state.selectedServer.name} · ${state.selectedServer.country}`;
    document.querySelector("#exit-name").value = state.selectedServer.city || state.selectedServer.country;
    document.querySelector("#exit-dialog").showModal();
  }
  const addServerButton = event.target.closest("[data-add-server]");
  if (addServerButton) addProtonServer(addServerButton);
  const countryButton = event.target.closest("[data-country-toggle]");
  if (countryButton) {
    state.expandedCountry = state.expandedCountry === countryButton.dataset.countryToggle ? "" : countryButton.dataset.countryToggle;
    state.countryServerPage = 1;
    renderServers();
  }
  const countryPageButton = event.target.closest("[data-country-server-page]");
  if (countryPageButton) {
    state.countryServerPage += Number(countryPageButton.dataset.countryServerPage);
    renderServers();
  }
  const clearButton = event.target.closest("[data-clear-node]");
  if (clearButton) mutate(`/v1/routes/${encodeURIComponent(clearButton.dataset.clearNode)}`, "DELETE");
  const deleteButton = event.target.closest("[data-delete-exit]");
  if (deleteButton && confirm("Disconnect this exit? Assigned devices must be disabled first.")) mutate(`/v1/exits/${encodeURIComponent(deleteButton.dataset.deleteExit)}`, "DELETE");
});

document.querySelector("#server-search").addEventListener("input", () => { state.serverPage = 1; state.expandedCountry = ""; renderServers(); });
document.querySelector("#server-feature-filters").addEventListener("change", () => { state.serverPage = 1; state.expandedCountry = ""; state.countryServerPage = 1; renderServers(); });
document.querySelector("#server-page-prev").addEventListener("click", () => { state.serverPage -= 1; state.expandedCountry = ""; renderServers(); });
document.querySelector("#server-page-next").addEventListener("click", () => { state.serverPage += 1; state.expandedCountry = ""; renderServers(); });
document.querySelector("#node-search").addEventListener("input", renderDevices);
document.querySelector("#refresh").addEventListener("click", load);
document.querySelector("#sign-out").addEventListener("click", async () => {
  try { await api("/auth/logout", { method: "POST", body: "{}" }); } catch (_) { /* already signed out */ }
  location.replace("/login");
});
document.querySelector("#console-account-form").addEventListener("submit", async event => {
  event.preventDefault();
  const result = document.querySelector("#account-result");
  const setResult = (text, kind = "") => { result.textContent = text; result.className = `form-result ${kind}`; };
  const newPassword = document.querySelector("#account-new-password");
  const confirmation = document.querySelector("#account-confirm-password");
  const current = document.querySelector("#account-current-password");
  if (newPassword.value !== confirmation.value) return setResult("The new passwords do not match.", "bad");
  setResult("Saving…");
  try {
    const saved = await api("/auth/account", { method: "PUT", body: JSON.stringify({
      currentPassword: current.value,
      username: document.querySelector("#account-username").value.trim(),
      newPassword: newPassword.value || null
    }) });
    state.consoleAccount = { ...state.consoleAccount, username: saved.username, passwordChangedAt: saved.passwordChangedAt };
    renderConsoleAccount();
    setResult(saved.passwordChanged ? "Saved. Other browsers were signed out." : "Saved.", "good");
  } catch (error) {
    setResult(error.message, "bad");
  } finally {
    for (const input of [newPassword, confirmation, current]) input.value = "";
  }
});
document.querySelector("#mail-form").addEventListener("change", event => {
  if (event.target.id === "mail-enabled") syncMailFields();
  if (event.target.id === "smtp-security") {
    const port = document.querySelector("#smtp-port");
    if (Object.values(SMTP_PORTS).includes(Number(port.value))) port.value = SMTP_PORTS[event.target.value];
  }
});
document.querySelector("#mail-form").addEventListener("submit", async event => {
  event.preventDefault();
  setMailResult("Saving…");
  try { await saveMail(); setMailResult("Saved.", "good"); } catch (error) { setMailResult(error.message, "bad"); }
});
document.querySelector("#mail-test").addEventListener("click", async () => {
  if (!document.querySelector("#mail-form").reportValidity()) return;
  setMailResult("Saving and sending…");
  try {
    await saveMail();
    const { to } = await api("/auth/recovery/test", { method: "POST", body: "{}" });
    setMailResult(`Test email sent to ${to}. Check the inbox (and spam folder).`, "good");
  } catch (error) { setMailResult(error.message, "bad"); }
});
document.querySelector("#alert-form").addEventListener("change", event => {
  if (event.target.matches("#telegram-enabled, #webhook-enabled")) syncAlertChannels();
});
document.querySelector("#alert-form").addEventListener("submit", async event => {
  event.preventDefault();
  setAlertResult("Saving…");
  try { await saveAlerts(); setAlertResult("Saved.", "good"); } catch (error) { setAlertResult(error.message, "bad"); }
});
document.querySelector("#alert-test").addEventListener("click", async () => {
  setAlertResult("Saving and sending…");
  try {
    await saveAlerts();
    const { results } = await api("/v1/alerts/test", { method: "POST", body: "{}" });
    const failed = results.filter(result => !result.ok);
    setAlertResult(results.map(result => `${result.channel}: ${result.ok ? "sent" : result.error}`).join(" · "), failed.length ? "bad" : "good");
  } catch (error) { setAlertResult(error.message, "bad"); }
});
document.querySelector("#telegram-detect").addEventListener("click", async () => {
  const list = document.querySelector("#telegram-chats");
  list.replaceChildren();
  setAlertResult("Looking for chats that messaged the bot…");
  try {
    const { chats } = await api("/v1/alerts/telegram/chats", { method: "POST", body: JSON.stringify({ botToken: document.querySelector("#telegram-token").value.trim() }) });
    if (!chats.length) return setAlertResult("No messages yet. Send the bot a message in Telegram, then try again.", "bad");
    list.innerHTML = chats.map(chat => `<button type="button" class="secondary" data-chat-id="${escapeHTML(chat.id)}">${escapeHTML(chat.name || chat.id)} · ${escapeHTML(chat.kind)}</button>`).join("");
    setAlertResult(chats.length === 1 ? "Found one chat; select it." : `Found ${chats.length} chats; select one.`);
  } catch (error) { setAlertResult(error.message, "bad"); }
});
document.querySelector("#telegram-chats").addEventListener("click", event => {
  const chat = event.target.closest("[data-chat-id]");
  if (!chat) return;
  document.querySelector("#telegram-chat").value = chat.dataset.chatId;
  document.querySelector("#telegram-chats").replaceChildren();
  setAlertResult("Chat selected. Save, or save and send a test.");
});
document.querySelector("#proton-login-form").addEventListener("submit", async event => {
  event.preventDefault();
  const password = document.querySelector("#proton-password");
  try {
    state.protonAccount = await api("/v1/proton/login", { method: "POST", body: JSON.stringify({ username: document.querySelector("#proton-username").value.trim(), password: password.value }) });
    password.value = "";
    await load();
  } catch (error) { password.value = ""; showAlert(error.message); }
});
document.querySelector("#proton-totp-form").addEventListener("submit", async event => {
  event.preventDefault();
  const code = document.querySelector("#proton-totp");
  try {
    state.protonAccount = await api("/v1/proton/totp", { method: "POST", body: JSON.stringify({ code: code.value }) });
    code.value = "";
    await load();
  } catch (error) { code.value = ""; showAlert(error.message); }
});
document.querySelector("#proton-logout").addEventListener("click", async () => {
  try { await api("/v1/proton/logout", { method: "POST", body: "{}" }); await load(); } catch (error) { showAlert(error.message); }
});
document.querySelector("#exit-form").addEventListener("submit", event => {
  if (event.submitter?.value === "cancel") return;
  event.preventDefault();
  document.querySelector("#exit-dialog").close();
  mutate("/v1/exits", "POST", { serverId: state.selectedServer.id, displayName: document.querySelector("#exit-name").value.trim() });
});
document.querySelector("#device-list").addEventListener("change", event => {
  const killSwitch = event.target.closest("[data-dns-kill]");
  if (killSwitch) return mutate(`/v1/dns/${encodeURIComponent(killSwitch.dataset.dnsKill)}`, "PUT", { killSwitch: killSwitch.checked });
  const dnsServer = event.target.closest("[data-dns-server]");
  if (dnsServer) return mutate(`/v1/dns/${encodeURIComponent(dnsServer.dataset.dnsServer)}`, "PUT", { server: dnsServer.value.trim() });
  const selector = event.target.closest("[data-node]");
  if (!selector) return;
  const path = `/v1/routes/${encodeURIComponent(selector.dataset.node)}`;
  mutate(path, selector.value ? "PUT" : "DELETE", selector.value ? { serverId: selector.value } : {});
});

const addProtonServer = async button => {
  button.disabled = true;
  try {
    await api(`/v1/proton/servers/${encodeURIComponent(button.dataset.addServer)}/add`, { method: "POST", body: "{}" });
    await load();
  } catch (error) {
    button.disabled = false;
    showAlert(error.message);
  }
};

// The form is filled once (and after saving) so a refresh never overwrites what is being typed.
const fillAlertForm = settings => {
  const telegram = settings.telegram;
  document.querySelector("#telegram-enabled").checked = Boolean(telegram);
  document.querySelector("#telegram-token").value = "";
  document.querySelector("#telegram-token").placeholder = telegram ? `Saved: ${telegram.botTokenHint}. Leave empty to keep it.` : "123456789:AA…";
  document.querySelector("#telegram-chat").value = telegram?.chatId || "";
  document.querySelector("#webhook-enabled").checked = Boolean(settings.webhook);
  document.querySelector("#webhook-url").value = settings.webhook?.url || "";
  document.querySelector("#webhook-format").value = settings.webhook?.format || "ntfy";
  document.querySelector("#telegram-chats").replaceChildren();
  syncAlertChannels();
  state.alertFormLoaded = true;
};

const syncAlertChannels = () => {
  for (const channel of ["telegram", "webhook"]) {
    const enabled = document.querySelector(`#${channel}-enabled`).checked;
    document.querySelectorAll(`#alert-form [id^="${channel}-"]:not(#${channel}-enabled)`).forEach(element => { element.disabled = !enabled; });
  }
};

const renderAlerts = () => {
  if (!state.alerts) return;
  if (!state.alertFormLoaded) fillAlertForm(state.alerts.settings);
  const active = state.alerts.active || [];
  document.querySelector("#alert-active").innerHTML = active.length
    ? active.map(alert => `<p><strong>${escapeHTML(alert.key)}</strong>${escapeHTML(alert.message)}<br><span class="muted">Since ${escapeHTML(new Date(alert.since * 1000).toLocaleString())}${alert.notified ? " · notified" : " · waiting for the grace period"}</span></p>`).join("")
    : `<p class="muted">No problems right now.</p>`;
};

const renderConsoleAccount = () => {
  const account = state.consoleAccount;
  if (!account) return;
  state.username = account.username;
  document.querySelector("#signed-in-user").textContent = account.username;
  if (!state.accountFormLoaded) {
    document.querySelector("#account-username").value = account.username;
    state.accountFormLoaded = true;
  }
  document.querySelector("#account-recovery").textContent = account.recovery
    ? `A forgotten password can be reset from the sign-in page with a code emailed to ${account.recovery.email}.`
    : "Set up email to reset a forgotten password from the sign-in page. Without it, the password can only be reset on the server with scripts/reset-console-password.sh. With Gmail or iCloud, use an app password.";
  if (!state.mailFormLoaded) fillMailForm(account.recovery);
  document.querySelector("#account-changed").textContent = account.passwordChangedAt
    ? `Password last changed ${new Date(account.passwordChangedAt * 1000).toLocaleString()}.`
    : "";
};

const SMTP_PORTS = { starttls: 587, tls: 465, none: 25 };

// Filled once (and after saving) so a refresh never overwrites what is being typed.
const fillMailForm = recovery => {
  const smtp = recovery?.smtp;
  document.querySelector("#mail-enabled").checked = Boolean(recovery);
  document.querySelector("#mail-email").value = recovery?.email || "";
  document.querySelector("#smtp-host").value = smtp?.host || "";
  document.querySelector("#smtp-port").value = smtp?.port || 587;
  document.querySelector("#smtp-security").value = smtp?.security || "starttls";
  document.querySelector("#smtp-username").value = smtp?.username || "";
  document.querySelector("#smtp-password").value = "";
  document.querySelector("#smtp-password").placeholder = smtp?.passwordSet ? "Saved. Leave empty to keep it." : "";
  document.querySelector("#smtp-from").value = smtp?.from || "";
  syncMailFields();
  state.mailFormLoaded = true;
};

const syncMailFields = () => {
  const enabled = document.querySelector("#mail-enabled").checked;
  document.querySelectorAll("#mail-form input, #mail-form select, #mail-test").forEach(element => {
    if (!["mail-enabled", "mail-current-password"].includes(element.id)) element.disabled = !enabled;
  });
};

const setMailResult = (text, kind = "") => {
  const result = document.querySelector("#mail-result");
  result.textContent = text;
  result.className = `form-result ${kind}`;
};

const saveMail = async () => {
  const value = id => document.querySelector(id).value.trim();
  const username = value("#smtp-username");
  const recovery = document.querySelector("#mail-enabled").checked ? {
    email: value("#mail-email"),
    smtp: {
      host: value("#smtp-host"),
      port: Number(value("#smtp-port")),
      security: value("#smtp-security"),
      username,
      password: document.querySelector("#smtp-password").value,
      from: value("#smtp-from") || value("#mail-email")
    }
  } : null;
  const current = document.querySelector("#mail-current-password");
  try {
    const saved = await api("/auth/account", { method: "PUT", body: JSON.stringify({ currentPassword: current.value, recovery }) });
    state.consoleAccount = { ...state.consoleAccount, recovery: saved.recovery };
    fillMailForm(saved.recovery);
    renderConsoleAccount();
  } finally {
    current.value = "";
  }
};

const setAlertResult = (message, kind = "") => {
  const result = document.querySelector("#alert-result");
  result.textContent = message;
  result.className = `form-result ${kind}`;
};

const saveAlerts = async () => {
  const telegram = document.querySelector("#telegram-enabled").checked
    ? { botToken: document.querySelector("#telegram-token").value.trim(), chatId: document.querySelector("#telegram-chat").value.trim() }
    : null;
  const webhook = document.querySelector("#webhook-enabled").checked
    ? { url: document.querySelector("#webhook-url").value.trim(), format: document.querySelector("#webhook-format").value }
    : null;
  const saved = await api("/v1/alerts", { method: "PUT", body: JSON.stringify({ telegram, webhook }) });
  state.alerts = { ...state.alerts, settings: saved.settings };
  fillAlertForm(saved.settings);
};

const showAlert = message => {
  const alert = document.querySelector("#alert");
  alert.textContent = message;
  alert.classList.toggle("hidden", !message);
};
const escapeHTML = value => String(value).replace(/[&<>'"]/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);

load();
setInterval(load, 15000);