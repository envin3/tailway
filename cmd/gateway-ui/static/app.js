const SERVER_PAGE_SIZE = 25;
const COUNTRY_PAGE_SIZE = 12;
const LOCAL_ROUTE_ID = "__local__";
const DIRECT_ROUTE_ID = "__direct__";
const BUILTIN_ROUTES = new Set([LOCAL_ROUTE_ID, DIRECT_ROUTE_ID]);
const POLICY_LABELS = { block: "Blocked", local: "Local only", direct: "Direct Internet" };
const state = { revision: 0, csrfToken: "", status: null, servers: [], protonServers: [], protonAccount: null, protonAvailable: true, exits: [], devices: [], selectedServer: null, serverPage: 1, expandedCountry: "", countryServerPage: 1 };
const regionNames = new Intl.DisplayNames(["en"], { type: "region" });

const api = async (path, options = {}) => {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrfToken;
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
  const payload = await response.json().catch(() => ({}));
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
    if (!state.csrfToken) state.csrfToken = (await api("/session")).csrfToken;
    const [status, catalog, exits, devices] = await Promise.all([
      api("/v1/status"), api("/v1/catalog"), api("/v1/exits"), api("/v1/devices")
    ]);
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
    showAlert(status.lastError || "");
  } catch (error) {
    showAlert(error.message);
    document.querySelector("#health-label").textContent = "Unavailable";
    document.querySelector("#health-dot").className = "bad";
  }
};

const render = () => {
  const healthy = state.status?.state === "healthy";
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
    </td></tr>`;
    return `
    <tr><td><strong>${escapeHTML(device.displayName || device.nodeId)}</strong><br><small>${escapeHTML(device.nodeId)}</small></td><td>${escapeHTML((device.addresses || []).join(", ") || "No IPv4 address")}</td><td>${device.online ? "Online" : "Offline"}</td><td><span class="activity ${device.active ? "observed" : ""}">${device.active ? "Observed" : device.online ? "Not observed" : "Offline"}</span></td><td>
      <select data-node="${escapeHTML(device.nodeId)}">
        <option value="">Default · ${escapeHTML(defaultLabel)}</option>
        <option value="${DIRECT_ROUTE_ID}" ${device.exitId === DIRECT_ROUTE_ID ? "selected" : ""}>Direct Internet · No VPN</option>
        <option value="${LOCAL_ROUTE_ID}" ${device.exitId === LOCAL_ROUTE_ID ? "selected" : ""}>Local only · No Internet</option>
        ${state.servers.map(server => `<option value="${escapeHTML(server.id)}" ${selectedExit?.serverId === server.id ? "selected" : ""}>${escapeHTML(server.name)} · ${escapeHTML(server.country)}${server.city ? ` · ${escapeHTML(server.city)}` : ""}</option>`).join("")}
      </select>
      ${selectedExit ? `<small>${escapeHTML(selectedExit.status)}</small>` : ""}
    </td></tr>`;
  }).join("") : `<tr><td colspan="5" class="empty">${state.devices.length ? "No matching nodes." : "No Tailscale peers are visible."}</td></tr>`;
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

const showAlert = message => {
  const alert = document.querySelector("#alert");
  alert.textContent = message;
  alert.classList.toggle("hidden", !message);
};
const escapeHTML = value => String(value).replace(/[&<>'"]/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);

load();
setInterval(load, 15000);