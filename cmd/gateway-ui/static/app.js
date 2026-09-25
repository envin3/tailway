"use strict";

const LOCAL = "__local__";
const DIRECT = "__direct__";
const POLICY_LABELS = { block: "Blocked", local: "Local network only", direct: "Direct Internet" };
const REFRESH_MS = 15000;
const PROTON_SERVERS_TTL_MS = 5 * 60 * 1000;
const SMTP_PORTS = { starttls: 587, tls: 465, none: 25 };
const VIEWS = { dashboard: "Dashboard", devices: "Devices", locations: "Locations", settings: "Settings" };
const TABS = ["proton", "notifications", "account"];

const PICKER_PAGE_DEFAULT = 50;
const state = {
  loaded: false,
  loadError: "",
  csrfToken: "",
  revision: 0,
  status: null,
  catalog: [],
  exits: [],
  devices: [],
  alerts: null,
  consoleAccount: null,
  proton: null,
  protonAvailable: true,
  protonServers: [],
  protonServersAt: 0,
  view: "dashboard",
  tab: "proton",
  deviceFilter: "all",
  openDns: new Set(),
  busyDevices: new Set(),
  formsFilled: { alerts: false, account: false, mail: false },
  picker: { country: "", features: new Set(), shown: PICKER_PAGE_DEFAULT },
  lastLoaded: 0
};

/* ---------- helpers ---------- */

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
const escapeHTML = value => String(value ?? "").replace(/[&<>'"]/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);

const ICONS = {
  check: "M9 16.2 4.8 12l-1.4 1.4L9 19 21 7l-1.4-1.4L9 16.2Z",
  warning: "M1 21h22L12 2 1 21Zm12-3h-2v-2h2v2Zm0-4h-2v-4h2v4Z",
  error: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm1 15h-2v-2h2v2Zm0-4h-2V7h2v6Z",
  info: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm1 15h-2v-6h2v6Zm0-8h-2V7h2v2Z",
  shield: "M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Zm-1.2 14.2-3.5-3.5 1.4-1.4 2.1 2.1 4.9-4.9 1.4 1.4-6.3 6.3Z",
  phone: "M16 1H8a2 2 0 0 0-2 2v18a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V3a2 2 0 0 0-2-2Zm-4 21a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3Zm4-4H8V4h8v14Z",
  laptop: "M20 18a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2H0v2h24v-2h-4ZM4 6h16v10H4V6Z",
  desktop: "M21 2H3a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h7v2H8v2h8v-2h-2v-2h7a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2Zm0 14H3V4h18v12Z",
  server: "M3 3h18v8H3V3Zm2 2v4h14V5H5Zm-2 8h18v8H3v-8Zm2 2v4h14v-4H5Zm2-9h2v2H7V6Zm0 10h2v2H7v-2Z",
  tv: "M21 3H3a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h5v2h8v-2h5a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2Zm0 14H3V5h18v12Z",
  block: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20ZM4 12a8 8 0 0 1 12.9-6.3L5.7 16.9A7.9 7.9 0 0 1 4 12Zm8 8a7.9 7.9 0 0 1-4.9-1.7L18.3 7.1A8 8 0 0 1 12 20Z",
  home: "M12 3 2 12h3v8h6v-6h2v6h6v-8h3L12 3Z",
  arrow: "M12 4l-1.4 1.4 5.6 5.6H4v2h12.2l-5.6 5.6L12 20l8-8-8-8Z",
  clock: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm0 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16Zm.5-13H11v6l5.2 3.2.8-1.3-4.5-2.7V7Z",
  globe: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm6.9 6h-3a15.7 15.7 0 0 0-1.4-3.6A8 8 0 0 1 18.9 8ZM12 4c.8 1.2 1.5 2.5 1.9 4h-3.8c.4-1.5 1.1-2.8 1.9-4ZM4.3 14a8.2 8.2 0 0 1 0-4h3.4a16.5 16.5 0 0 0 0 4H4.3Zm.8 2h3a15.7 15.7 0 0 0 1.4 3.6A8 8 0 0 1 5.1 16Zm3-8h-3a8 8 0 0 1 4.4-3.6C8.9 5.5 8.4 6.7 8.1 8ZM12 20c-.8-1.2-1.5-2.5-1.9-4h3.8c-.4 1.5-1.1 2.8-1.9 4Zm2.3-6H9.7a14.7 14.7 0 0 1 0-4h4.6a14.7 14.7 0 0 1 0 4Zm.2 5.6c.6-1.1 1.1-2.3 1.4-3.6h3a8 8 0 0 1-4.4 3.6Zm1.8-5.6a16.5 16.5 0 0 0 0-4h3.4a8.2 8.2 0 0 1 0 4h-3.4Z",
  lock: "M18 8h-1V6a5 5 0 0 0-10 0v2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2ZM9 6a3 3 0 0 1 6 0v2H9V6Zm9 14H6V10h12v10Z",
  plus: "M11 5h2v6h6v2h-6v6h-2v-6H5v-2h6V5Z",
  chevron: "M8.6 16.6 13.2 12 8.6 7.4 10 6l6 6-6 6-1.4-1.4Z"
};
const icon = name => `<svg aria-hidden="true" viewBox="0 0 24 24"><path d="${ICONS[name]}"/></svg>`;

// Some systems report tags Intl rejects (e.g. "en-US@posix"); fall back to English.
const LOCALE = (() => { try { return Intl.getCanonicalLocales(navigator.language)[0] || "en"; } catch (_) { return "en"; } })();
const regionNames = (() => { try { return new Intl.DisplayNames([LOCALE, "en"], { type: "region" }); } catch (_) { return null; } })();
const relativeFormat = new Intl.RelativeTimeFormat(LOCALE, { numeric: "auto" });
const isoCountry = code => (code === "UK" ? "GB" : String(code || "").toUpperCase());
const countryName = code => {
  const iso = isoCountry(code);
  try { return (regionNames && regionNames.of(iso)) || iso || "Unknown"; } catch (_) { return iso || "Unknown"; }
};
const flag = code => {
  const iso = isoCountry(code);
  if (!/^[A-Z]{2}$/.test(iso)) return "🌐";
  return String.fromCodePoint(...Array.from(iso, letter => 127397 + letter.charCodeAt(0)));
};

// ISO 3166-1 codes for the country picker (names come from the browser).
const COUNTRY_CODES = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW".split(" ");
// Recognised from a configuration's file name, e.g. "mullvad-ch-zrh-wg-001.conf".
const PROVIDER_HINTS = { mullvad: "Mullvad", ivpn: "IVPN", airvpn: "AirVPN", windscribe: "Windscribe", proton: "Proton VPN", nord: "NordVPN", surfshark: "Surfshark", pia: "PIA" };
const providerOf = server => server.provider || (server.source === "custom" ? "WireGuard" : "Proton VPN");

const FEATURE_LABELS = { p2p: "P2P", streaming: "Streaming", "secure-core": "Secure Core", tor: "Tor" };
const featureList = features => (features || []).filter(feature => feature !== "ipv6").map(feature => FEATURE_LABELS[feature] || feature);

const relativeTime = date => {
  const seconds = Math.round((new Date(date).getTime() - Date.now()) / 1000);
  if (!Number.isFinite(seconds)) return "";
  if (Math.abs(seconds) < 45) return "just now";
  const units = [["day", 86400], ["hour", 3600], ["minute", 60]];
  for (const [unit, size] of units) if (Math.abs(seconds) >= size) return relativeFormat.format(Math.round(seconds / size), unit);
  return relativeFormat.format(seconds, "second");
};
const duration = seconds => {
  if (seconds >= 86400) return `${Math.floor(seconds / 86400)} d ${Math.floor(seconds % 86400 / 3600)} h`;
  if (seconds >= 3600) return `${Math.floor(seconds / 3600)} h ${Math.floor(seconds % 3600 / 60)} min`;
  return `${Math.max(0, Math.floor(seconds / 60))} min`;
};

/* ---------- API ---------- */

const api = async (path, options = {}) => {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrfToken;
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
  const payload = await response.json().catch(() => ({}));
  if (response.status === 401) {
    location.replace("/login");
    throw new Error("Your session ended. Sign in again.");
  }
  if (response.status === 403 && payload.error === "invalid CSRF token" && !options.csrfRetried) {
    state.csrfToken = (await api("/session")).csrfToken;
    return api(path, { ...options, csrfRetried: true });
  }
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
};

// Changes to routing carry the revision they were based on.
const mutate = async (path, method, body = {}) => {
  const result = await api(path, { method, body: JSON.stringify({ revision: state.revision, ...body }) });
  if (result.revision !== undefined) state.revision = result.revision;
  return result;
};

/* ---------- feedback ---------- */

const toast = (message, kind = "good") => {
  const element = document.createElement("div");
  element.className = `toast ${kind}`;
  element.innerHTML = `${icon(kind === "bad" ? "error" : kind === "info" ? "info" : "check")}<span></span>`;
  $("span", element).textContent = message;
  $("#toasts").append(element);
  setTimeout(() => {
    element.classList.add("leaving");
    // With reduced motion there is no animation to wait for.
    setTimeout(() => element.remove(), 250);
  }, kind === "bad" ? 7000 : 4000);
};

const busy = async (button, work) => {
  button?.classList.add("busy");
  if (button) button.disabled = true;
  try { return await work(); } finally {
    button?.classList.remove("busy");
    if (button) button.disabled = false;
  }
};

const confirmDialog = ({ title, text, confirm = "Confirm", danger = false }) => new Promise(resolve => {
  const dialog = $("#confirm-dialog");
  $("#confirm-title").textContent = title;
  $("#confirm-text").textContent = text;
  const button = $("#confirm-button");
  button.textContent = confirm;
  button.className = danger ? "danger" : "";
  dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), { once: true });
  dialog.returnValue = "";
  dialog.showModal();
});

/* ---------- loading ---------- */

const load = async ({ force = false } = {}) => {
  try {
    if (!state.csrfToken) state.csrfToken = (await api("/session")).csrfToken;
    const [status, catalog, exits, devices, alerts, consoleAccount] = await Promise.all([
      api("/v1/status"), api("/v1/catalog"), api("/v1/exits"), api("/v1/devices"), api("/v1/alerts"), api("/auth/account")
    ]);
    Object.assign(state, {
      status, alerts, consoleAccount,
      catalog: catalog.servers || [],
      exits: exits.exits || [],
      devices: devices || [],
      revision: Math.max(status.revision || 0, exits.revision || 0),
      loadError: ""
    });
    try {
      state.proton = await api("/v1/proton/account");
      state.protonAvailable = true;
    } catch (_) {
      state.proton = null;
      state.protonAvailable = false;
    }
    state.loaded = true;
    state.lastLoaded = Date.now();
  } catch (error) {
    state.loadError = error.message;
  }
  render({ force });
};

const loadProtonServers = async () => {
  if (Date.now() - state.protonServersAt < PROTON_SERVERS_TTL_MS && state.protonServers.length) return;
  state.protonServers = (await api("/v1/proton/servers")).servers || [];
  state.protonServersAt = Date.now();
};

/* ---------- derived data ---------- */

const exitsById = () => new Map(state.exits.map(exit => [exit.id, exit]));
const catalogById = () => new Map(state.catalog.map(server => [server.id, server]));
const protonSignedIn = () => state.proton?.state === "authenticated";
const defaultPolicy = () => state.status?.unassignedPolicy || "block";

const routeOf = device => {
  if (!device.exitId) return { kind: "default" };
  if (device.exitId === DIRECT) return { kind: "direct" };
  if (device.exitId === LOCAL) return { kind: "local" };
  return { kind: "vpn", exit: exitsById().get(device.exitId) };
};

const devicesOn = serverId => state.devices.filter(device => {
  const route = routeOf(device);
  return route.kind === "vpn" && route.exit?.serverId === serverId;
});

const exitHealth = exit => {
  switch (exit?.status) {
    case "healthy": return { tone: "good", label: "Connected" };
    case "degraded": return { tone: "warn", label: "Degraded" };
    case "failed": return { tone: "bad", label: "Down" };
    default: return { tone: "", label: "Connecting" };
  }
};

const problems = () => {
  const list = [];
  if (state.loadError) return [{ tone: "bad", text: `The gateway is not responding: ${state.loadError}` }];
  if (state.status?.lastError) list.push({ tone: "bad", text: `Applying routing failed: ${state.status.lastError}` });
  for (const exit of state.exits) {
    const where = `${exit.displayName} (${countryName(exit.country)})`;
    if (exit.status === "failed") list.push({ tone: "bad", text: `${where} is down. Its devices have no Internet until it recovers.`, link: "#/locations", action: "View" });
    if (exit.status === "degraded") list.push({ tone: "warn", text: `${where} is degraded: ${exit.statusDetail || "slow handshakes"}.`, link: "#/locations", action: "View" });
  }
  for (const alert of state.status?.alerts || []) {
    if (!alert.notified || alert.key.startsWith("exit:")) continue;
    list.push({ tone: "bad", text: alert.message, link: alert.key.startsWith("proton") ? "#/settings/proton" : "", action: "Fix" });
  }
  if (!state.protonAvailable) list.push({ tone: "warn", text: "The Proton account service is not responding.", link: "#/settings/proton", action: "Details" });
  else if (state.proton && !protonSignedIn()) list.push({ tone: "warn", text: "Proton is signed out, so tunnel certificates cannot renew.", link: "#/settings/proton", action: "Sign in" });
  else if (protonSignedIn()) {
    const seconds = state.proton.certificateValidSeconds;
    if (typeof seconds === "number" && seconds < 2 * 86400) list.push({ tone: seconds <= 0 ? "bad" : "warn", text: seconds <= 0 ? "The Proton certificate expired: tunnels pass no traffic." : `The Proton certificate expires in ${duration(seconds)}.`, link: "#/settings/proton", action: "Details" });
  }
  return list;
};

const suggestions = () => {
  const list = [];
  const settings = state.alerts?.settings;
  if (settings && !settings.telegram && !settings.webhook) list.push({ text: "Get notified when something breaks.", link: "#/settings/notifications", action: "Set up notifications" });
  if (state.consoleAccount && !state.consoleAccount.recovery) list.push({ text: "Add a recovery email in case you forget the console password.", link: "#/settings/account", action: "Add recovery email" });
  return list;
};

const customServerIds = () => new Set(state.catalog.filter(server => server.source === "custom").map(server => server.id));
const protonTunnels = () => {
  const custom = customServerIds();
  return state.exits.filter(exit => !custom.has(exit.serverId)).length;
};

const overallTone = list => (list.some(item => item.tone === "bad") ? "bad" : list.length ? "warn" : "good");

/* ---------- rendering ---------- */

const render = ({ force = false } = {}) => {
  renderChrome();
  if (!state.loaded) {
    renderSkeletons();
    return;
  }
  renderDashboard();
  renderDevices({ force });
  renderLocations();
  renderSettings();
};

const renderChrome = () => {
  const list = problems();
  const tone = state.loadError ? "bad" : state.loaded ? overallTone(list) : "";
  const pill = $("#health-pill");
  pill.className = `health-pill ${tone}`;
  $("#health-text").textContent = !state.loaded && !state.loadError ? "Connecting…"
    : state.loadError ? "Unreachable" : tone === "good" ? "All systems normal" : tone === "warn" ? "Needs a look" : "Needs attention";
  const username = state.consoleAccount?.username || "";
  $("#signed-in-user").textContent = username;
  $("#user-avatar").textContent = username.slice(0, 1) || "?";
  $("#nav-device-count").textContent = state.loaded ? String(state.devices.filter(device => !device.missing).length) : "";
};

const renderSkeletons = () => {
  const skeletons = count => Array.from({ length: count }, () => `<div class="skeleton"></div>`).join("");
  $("#hero").innerHTML = state.loadError ? heroHTML("bad", "The gateway is not responding", [{ tone: "bad", text: state.loadError }]) : `<div class="skeleton"></div>`;
  $("#device-list").innerHTML = skeletons(4);
  $("#location-grid").innerHTML = skeletons(3);
};

const heroHTML = (tone, title, items, subtitle = "") => `
  <div class="hero-icon">${icon(tone === "good" ? "shield" : tone === "warn" ? "warning" : "error")}</div>
  <div class="hero-body">
    <h2>${escapeHTML(title)}</h2>
    ${subtitle ? `<p class="muted">${escapeHTML(subtitle)}</p>` : ""}
    ${items.length ? `<ul class="problems">${items.map(item => `<li><span>${escapeHTML(item.text)}</span>${item.link ? `<a href="${escapeHTML(item.link)}">${escapeHTML(item.action || "View")}</a>` : ""}</li>`).join("")}</ul>` : ""}
  </div>`;

const renderDashboard = () => {
  const list = problems();
  const tone = overallTone(list);
  const protectedCount = state.devices.filter(device => routeOf(device).kind === "vpn").length;
  const title = tone === "good" ? "Everything is working" : tone === "warn" ? "Working, with something to check" : "Something needs your attention";
  const subtitle = tone === "good"
    ? `${protectedCount} ${protectedCount === 1 ? "device goes" : "devices go"} through a VPN · checked ${relativeTime(state.lastLoaded)}`
    : `Checked ${relativeTime(state.lastLoaded)}`;
  const hero = $("#hero");
  hero.className = `hero ${tone}`;
  hero.innerHTML = heroHTML(tone, title, tone === "good" ? suggestions() : list, subtitle);

  const counts = { vpn: 0, direct: 0, local: 0, default: 0 };
  for (const device of state.devices) if (!device.missing) counts[routeOf(device).kind] += 1;
  const activeExits = state.exits.length;
  const limit = state.status?.exitLimit;
  $("#stats").innerHTML = [
    ["vpn", "Through VPN", counts.vpn, "devices protected"],
    ["novpn", "Without VPN", counts.direct + counts.local, `${counts.direct} direct · ${counts.local} local only`],
    ["default", "Using the default", counts.default, `${POLICY_LABELS[defaultPolicy()] || defaultPolicy()} for new devices`],
    ["locations", "Active tunnels", activeExits, limit ? `${protonTunnels()} of ${limit} Proton connections in use` : "VPN tunnels running"]
  ].map(([filter, label, value, note]) => `
    <a class="stat" href="${filter === "locations" ? "#/locations" : `#/devices/${filter}`}"><span>${escapeHTML(label)}</span><strong>${escapeHTML(value)}</strong><small>${escapeHTML(note)}</small></a>`).join("");

  $("#dashboard-locations").innerHTML = state.exits.length ? state.exits.map(exit => {
    const health = exitHealth(exit);
    const users = state.devices.filter(device => device.exitId === exit.id).length;
    return `<div class="mini-row"><span class="flag">${flag(exit.country)}</span><span class="grow"><strong>${escapeHTML(exit.displayName)}</strong><small>${escapeHTML([countryName(exit.country), exit.city].filter(Boolean).join(" · "))}${exit.publicIp ? ` · ${escapeHTML(exit.publicIp)}` : ""} · ${users} ${users === 1 ? "device" : "devices"}</small></span><span class="badge ${health.tone}">${health.label}</span></div>`;
  }).join("") : `<p class="muted">No tunnels are running. Pick a VPN location for a device to start one.</p>`;

  const facts = [];
  if (protonSignedIn()) {
    facts.push(["Proton", `${state.proton.plan || "Signed in"} · ${state.proton.username || ""}`, ""]);
    facts.push(certificateFact());
  } else facts.push(["Proton", state.protonAvailable ? "Signed out" : "Service not responding", "warn"]);
  facts.push(["New devices", POLICY_LABELS[defaultPolicy()] || defaultPolicy(), ""]);
  const dns = state.status?.dns;
  if (dns?.enabled) facts.push(["DNS", `The VPN's DNS on VPN routes · ${dns.defaultServer} otherwise`, ""]);
  const channels = [state.alerts?.settings?.telegram && "Telegram", state.alerts?.settings?.webhook && "Webhook"].filter(Boolean);
  facts.push(["Notifications", channels.length ? channels.join(" and ") : "Off", channels.length ? "" : "warn"]);
  $("#dashboard-facts").innerHTML = facts.map(([term, value, tone]) => `<dt>${escapeHTML(term)}</dt><dd class="${tone}">${escapeHTML(value)}</dd>`).join("");
};

const certificateFact = () => {
  const seconds = state.proton?.certificateValidSeconds;
  const renews = state.proton?.backgroundRefresh;
  if (typeof seconds !== "number") return ["Certificate", renews ? "Renews automatically" : "Unknown", renews ? "" : "warn"];
  if (seconds <= 0) return ["Certificate", "Expired", "bad"];
  return ["Certificate", `Valid ${duration(seconds)}${renews ? " · renews automatically" : " · NOT renewing"}`, renews && seconds > 2 * 86400 ? "" : "warn"];
};

/* Devices */

const DEVICE_FILTERS = [
  ["all", "All"], ["online", "Online"], ["exit", "Using this gateway"], ["vpn", "Through VPN"], ["novpn", "Without VPN"], ["default", "Default"]
];

// Whether the device sends its Internet traffic here, i.e. selected this gateway
// as its Tailscale exit node (seen from traffic; Tailscale does not report it).
const usesGateway = device => Boolean(device.exitNode?.inUse);

const deviceMatchesFilter = (device, filter) => {
  const kind = routeOf(device).kind;
  switch (filter) {
    case "online": return device.online;
    case "exit": return usesGateway(device);
    case "vpn": return kind === "vpn";
    case "novpn": return kind === "direct" || kind === "local";
    case "default": return kind === "default";
    default: return true;
  }
};

const osIcon = os => {
  const name = String(os || "").toLowerCase();
  if (name === "ios" || name === "android") return "phone";
  if (name === "macos" || name === "windows") return "laptop";
  if (name === "tvos") return "tv";
  if (name === "linux" || name === "freebsd") return "server";
  return "desktop";
};
const osLabel = os => ({ ios: "iOS", android: "Android", macos: "macOS", windows: "Windows", linux: "Linux", tvos: "tvOS", freebsd: "FreeBSD" })[String(os || "").toLowerCase()] || os || "";

const routeStatus = device => {
  const route = routeOf(device);
  const exitKnown = Boolean(device.exitNode);
  if (exitKnown && device.online && !usesGateway(device) && route.kind !== "default") {
    return { tone: "", icon: "info", text: "Has no effect until this device selects the gateway as its exit node in Tailscale" };
  }
  if (route.kind === "default" && usesGateway(device) && defaultPolicy() === "block") {
    return { tone: "warn", icon: "block", text: "Uses this gateway, but its Internet is blocked: choose a route" };
  }
  if (route.kind === "default") {
    const policy = defaultPolicy();
    if (policy === "block") return { tone: "", icon: "block", text: "No Internet through this gateway until you choose a route" };
    if (policy === "direct") return { tone: "", icon: "arrow", text: "Default: direct Internet, not through the VPN" };
    return { tone: "", icon: "home", text: "Default: local network only" };
  }
  if (route.kind === "direct") return { tone: "", icon: "arrow", text: "Direct Internet: not protected by the VPN" };
  if (route.kind === "local") return { tone: "", icon: "home", text: "Local network only: no Internet" };
  const exit = route.exit;
  if (!exit) return { tone: "", icon: "clock", text: "Starting the tunnel…" };
  const place = countryName(exit.country);
  switch (exit.status) {
    case "healthy": return { tone: "good", icon: "shield", text: `Protected: appears in ${place}${exit.publicIp ? ` as ${exit.publicIp}` : ""}` };
    case "degraded": return { tone: "warn", icon: "warning", text: `Connection degraded${exit.statusDetail ? `: ${exit.statusDetail}` : ""}` };
    case "failed": return { tone: "bad", icon: "error", text: `VPN down, Internet blocked to stay private${exit.statusDetail ? `: ${exit.statusDetail}` : ""}` };
    default: return { tone: "", icon: "clock", text: "Connecting…" };
  }
};

const routeOptions = device => {
  const route = routeOf(device);
  const selectedServer = route.kind === "vpn" ? route.exit?.serverId : "";
  const servers = [...state.catalog];
  if (selectedServer && !servers.some(server => server.id === selectedServer) && route.exit) {
    servers.push({ id: route.exit.serverId, name: route.exit.displayName, country: route.exit.country, city: route.exit.city });
  }
  servers.sort((left, right) => countryName(left.country).localeCompare(countryName(right.country)) || String(left.name).localeCompare(String(right.name)));
  const option = (value, label, selected) => `<option value="${escapeHTML(value)}" ${selected ? "selected" : ""}>${escapeHTML(label)}</option>`;
  const byProvider = new Map();
  for (const server of servers) {
    const provider = providerOf(server);
    if (!byProvider.has(provider)) byProvider.set(provider, []);
    byProvider.get(provider).push(server);
  }
  const groups = [...byProvider].sort(([left], [right]) => (left === "Proton VPN" ? -1 : right === "Proton VPN" ? 1 : left.localeCompare(right)));
  return [
    option("", `Default (${(POLICY_LABELS[defaultPolicy()] || defaultPolicy()).toLowerCase()})`, route.kind === "default"),
    ...groups.map(([provider, list]) => `<optgroup label="${escapeHTML(provider)}">${list.map(server => option(server.id, `${flag(server.country)} ${countryName(server.country)}${server.city ? `, ${server.city}` : ""} · ${server.name}`, server.id === selectedServer)).join("")}</optgroup>`),
    `<optgroup label="Without VPN">${option(DIRECT, "Direct Internet", route.kind === "direct")}${option(LOCAL, "Local network only", route.kind === "local")}</optgroup>`
  ].join("");
};

const dnsSummary = device => {
  const dns = device.dns;
  if (!dns) return "";
  if (routeOf(device).kind === "vpn") {
    if (dns.resolution === "blocked") return "DNS blocked while the VPN is down";
    if (dns.resolution === "server") return `DNS falls back to ${dns.server}`;
    return `VPN DNS${dns.killSwitch ? " · kill switch on" : ""}`;
  }
  return `DNS ${dns.server}${dns.customServer ? "" : " (default)"}`;
};

const dnsPanel = device => {
  const dns = device.dns;
  const id = escapeHTML(device.nodeId);
  const onVpn = routeOf(device).kind === "vpn";
  const custom = dns.customServer !== null && dns.customServer !== undefined || dns.customKillSwitch !== null && dns.customKillSwitch !== undefined;
  const serverField = label => `<label class="field"><span>${label}</span><input data-dns-server value="${escapeHTML(dns.customServer || "")}" placeholder="${escapeHTML(dns.defaultServer)} (default)" inputmode="decimal" autocomplete="off" spellcheck="false"></label>`;
  return `
    <form class="dns-panel" data-dns-form="${id}">
      ${onVpn ? `
        <p>Lookups go through the VPN tunnel to the VPN's resolver, so websites see the VPN, not you.</p>
        <label class="check"><input type="checkbox" data-dns-kill ${dns.killSwitch ? "checked" : ""}><span>Block lookups while the VPN is down<small>Recommended. Otherwise they fall back to the server below, outside the VPN.</small></span></label>
        <div data-dns-fallback ${dns.killSwitch ? "hidden" : ""}>${serverField("Fallback DNS server")}</div>`
      : `<p>This device does not use the VPN, so its lookups go to this server.</p>${serverField("DNS server")}`}
      <div class="actions"><button class="small">Save DNS</button>${custom ? `<button type="button" class="small secondary" data-dns-reset>Use defaults</button>` : ""}</div>
    </form>`;
};

const exitBadge = device => {
  const exit = device.exitNode;
  if (!exit) return "";
  const minutes = Math.round((exit.windowSeconds || 900) / 60);
  if (exit.inUse) {
    const ago = exit.lastTrafficSecondsAgo < 60 ? "just now" : relativeTime(Date.now() - exit.lastTrafficSecondsAgo * 1000);
    return `<span class="badge good" title="Last Internet traffic through this gateway ${escapeHTML(ago)}">${icon("check")}Using this gateway</span>`;
  }
  if (!device.online) return "";
  return `<span class="badge" title="No Internet traffic through this gateway in the last ${minutes} minutes">Exit node not selected</span>`;
};

const renderDevices = ({ force = false } = {}) => {
  const list = $("#device-list");
  // Never replace controls someone is using; the next refresh catches up.
  if (!force && (list.contains(document.activeElement) && document.activeElement !== document.body) && document.activeElement.matches("input, select")) return;
  const query = $("#device-search").value.trim().toLowerCase();
  const present = state.devices.filter(device => !device.missing);
  $("#device-filters").innerHTML = DEVICE_FILTERS.map(([key, label]) => {
    const count = present.filter(device => deviceMatchesFilter(device, key)).length;
    return `<button type="button" class="chip" data-filter="${key}" aria-pressed="${state.deviceFilter === key}">${label} <span class="count">${count}</span></button>`;
  }).join("");
  const devices = present
    .filter(device => deviceMatchesFilter(device, state.deviceFilter))
    .filter(device => [device.displayName, device.nodeId, osLabel(device.os), ...(device.addresses || [])].join(" ").toLowerCase().includes(query))
    .sort((left, right) => Number(right.online) - Number(left.online) || String(left.displayName).localeCompare(String(right.displayName)));

  if (!present.length) {
    list.innerHTML = `<div class="empty">${icon("desktop")}<strong>No devices yet</strong><span>Devices appear here once they join your tailnet.</span></div>`;
  } else if (!devices.length) {
    list.innerHTML = `<div class="empty"><strong>No matching devices</strong><span>Try another search or filter.</span></div>`;
  } else {
    list.innerHTML = devices.map(device => {
      const id = escapeHTML(device.nodeId);
      const status = routeStatus(device);
      const seen = device.online ? "Online" : device.lastSeen ? `Last seen ${relativeTime(device.lastSeen)}` : "Offline";
      const meta = [osLabel(device.os), (device.addresses || [])[0], seen].filter(Boolean).join(" · ");
      const busyNow = state.busyDevices.has(device.nodeId);
      return `
        <article class="device" data-device="${id}">
          <div class="device-main">
            <div class="device-id">
              <span class="device-icon">${icon(osIcon(device.os))}<span class="dot ${device.online ? "good" : ""}" title="${device.online ? "Online" : "Offline"}"></span></span>
              <span class="device-name"><span class="name-line"><strong>${escapeHTML(device.displayName || device.nodeId)}</strong>${exitBadge(device)}</span><small>${escapeHTML(meta)}</small></span>
            </div>
            <div class="route">
              <select data-route aria-label="Route for ${escapeHTML(device.displayName || device.nodeId)}" class="${busyNow ? "busy" : ""}" ${busyNow ? "disabled" : ""}>${routeOptions(device)}</select>
              <span class="route-status ${status.tone}">${icon(status.icon)}<span>${escapeHTML(status.text)}</span></span>
            </div>
          </div>
          ${device.dns ? `<details data-dns ${state.openDns.has(device.nodeId) ? "open" : ""}><summary>${escapeHTML(dnsSummary(device))}</summary>${dnsPanel(device)}</details>` : ""}
        </article>`;
    }).join("");
  }

  const missing = state.devices.filter(device => device.missing);
  $("#missing-devices").innerHTML = missing.length ? `
    <h2 class="subheading">Left the tailnet</h2>
    <p class="muted small-print">These devices were removed from Tailscale but still have settings here.</p>
    <div class="device-list">${missing.map(device => `
      <article class="device missing"><div class="device-main"><div class="device-id"><span class="device-icon">${icon("desktop")}</span><span class="device-name"><strong>${escapeHTML(device.nodeId)}</strong><small>No longer in the tailnet</small></span></div>
      <div class="route"><button type="button" class="secondary small" data-clear="${escapeHTML(device.nodeId)}">Remove settings</button></div></div></article>`).join("")}</div>` : "";
};

/* Locations */

const renderLocations = () => {
  const grid = $("#location-grid");
  const protonServers = new Map(state.protonServers.map(server => [server.id, server]));
  const exitsByServer = new Map(state.exits.map(exit => [exit.serverId, exit]));
  const servers = [...state.catalog];
  for (const exit of state.exits) if (!servers.some(server => server.id === exit.serverId)) servers.push({ id: exit.serverId, name: exit.displayName, country: exit.country, city: exit.city });
  servers.sort((left, right) => Number(exitsByServer.has(right.id)) - Number(exitsByServer.has(left.id)) || countryName(left.country).localeCompare(countryName(right.country)));
  $("#add-location").hidden = !protonSignedIn();
  if (!servers.length) {
    grid.innerHTML = `<div class="empty">${icon("globe")}<strong>No VPN locations yet</strong><span>Import a WireGuard configuration from any provider${protonSignedIn() ? ", or add a Proton server" : ", or sign in to Proton to browse its servers"}.</span><div class="actions"><button type="button" class="secondary" data-open-import>Import WireGuard</button>${protonSignedIn() ? `<button type="button" data-open-picker>${icon("plus")}Add Proton server</button>` : `<a class="link" href="#/settings/proton">Sign in to Proton</a>`}</div></div>`;
    return;
  }
  grid.innerHTML = servers.map(server => {
    const exit = exitsByServer.get(server.id);
    const users = devicesOn(server.id);
    const health = exit ? exitHealth(exit) : { tone: "", label: "Not in use" };
    const live = protonServers.get(server.id);
    const facts = [];
    if (exit?.publicIp) facts.push(["Public IP", exit.publicIp]);
    facts.push(["Devices", users.length ? users.map(device => device.displayName || device.nodeId).join(", ") : "None"]);
    if (live?.load !== undefined) facts.push(["Server load", `${live.load}%`]);
    const features = featureList(server.features);
    return `
      <article class="location">
        <div class="location-head"><span class="flag">${flag(server.country)}</span><span><span class="provider">${escapeHTML(providerOf(server))}</span><h3>${escapeHTML(countryName(server.country))}</h3><small>${escapeHTML([server.city, server.name].filter(Boolean).join(" · "))}</small></span><span class="badge ${health.tone}">${health.label}</span></div>
        ${features.length ? `<div class="chips">${features.map(feature => `<span class="tag">${escapeHTML(feature)}</span>`).join("")}</div>` : ""}
        <dl class="facts">${facts.map(([term, value]) => `<dt>${escapeHTML(term)}</dt><dd>${escapeHTML(value)}</dd>`).join("")}</dl>
        ${exit?.status === "failed" || exit?.status === "degraded" ? `<p class="location-detail">${escapeHTML(exit.statusDetail || "The tunnel is not passing traffic.")}</p>` : ""}
        ${!users.length && (exit || server.source === "custom") ? `<div class="actions">${exit ? `<button type="button" class="small secondary" data-stop-exit="${escapeHTML(exit.id)}">Stop tunnel</button>` : ""}${server.source === "custom" ? `<button type="button" class="small danger-outline" data-remove-custom="${escapeHTML(server.id)}" data-name="${escapeHTML(server.name)}">Remove</button>` : ""}</div>` : ""}
      </article>`;
  }).join("");
};

/* Location picker */

const pickerServers = () => {
  const added = new Set(state.catalog.map(server => server.id));
  const features = state.picker.features;
  const query = $("#location-search").value.trim().toLowerCase();
  return state.protonServers
    .filter(server => [...features].every(feature => (server.features || []).includes(feature)))
    .filter(server => !query || [server.country, countryName(server.country), server.city, server.name].join(" ").toLowerCase().includes(query))
    .map(server => ({ ...server, added: added.has(server.id), usable: server.online && server.accessible }));
};

const loadBar = percent => {
  const tone = percent >= 80 ? "bad" : percent >= 55 ? "warn" : "";
  return `<span class="load"><span>${percent}% load</span><span class="load-bar"><span class="${tone}" data-width="${Math.max(3, Math.min(100, Number(percent) || 0))}"></span></span></span>`;
};

const renderPicker = () => {
  const body = $("#location-body");
  const servers = pickerServers();
  const country = state.picker.country;
  $("#location-back").hidden = !country;
  $("#location-dialog-title").textContent = country ? countryName(country) : "Add a VPN location";
  if (!state.protonServers.length) {
    body.innerHTML = `<div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div>`;
    return;
  }
  if (!country) {
    const groups = new Map();
    for (const server of servers) {
      if (!groups.has(server.country)) groups.set(server.country, []);
      groups.get(server.country).push(server);
    }
    const countries = [...groups].sort(([left], [right]) => countryName(left).localeCompare(countryName(right)));
    body.innerHTML = countries.length ? `<div class="country-list">${countries.map(([code, list]) => {
      const usable = list.filter(server => server.usable);
      const best = usable.reduce((min, server) => Math.min(min, server.load ?? 100), 100);
      return `<button type="button" class="country" data-country="${escapeHTML(code)}"><span class="flag">${flag(code)}</span><span class="grow">${escapeHTML(countryName(code))}<br><small>${list.length} ${list.length === 1 ? "server" : "servers"}${usable.length ? ` · from ${best}% load` : " · none available on your plan"}</small></span>${icon("chevron")}</button>`;
    }).join("")}</div>` : `<div class="empty"><strong>No servers match</strong><span>Try another search or fewer filters.</span></div>`;
    return;
  }
  const list = servers.filter(server => server.country === country)
    .sort((left, right) => Number(right.usable) - Number(left.usable) || (left.load ?? 100) - (right.load ?? 100));
  const fastest = list.find(server => server.usable && !server.added);
  const shown = list.slice(0, state.picker.shown);
  body.innerHTML = `
    <div class="country-intro"><span class="flag">${flag(country)}</span><span><h3>${escapeHTML(countryName(country))}</h3><small>${list.length} ${list.length === 1 ? "server" : "servers"}</small></span>
      ${fastest ? `<button type="button" data-add-server="${escapeHTML(fastest.id)}">${icon("plus")}Add fastest (${escapeHTML(fastest.name)})</button>` : ""}</div>
    ${shown.map(server => {
      const features = featureList(server.features);
      const action = server.added ? `<button type="button" class="small secondary" disabled>${icon("check")}Added</button>`
        : !server.accessible ? `<span class="tag">${icon("lock")} Upgrade</span>`
        : !server.online ? `<span class="tag">Offline</span>`
        : `<button type="button" class="small" data-add-server="${escapeHTML(server.id)}">Add</button>`;
      return `<div class="server"><span><strong>${escapeHTML(server.name)}</strong><small>${escapeHTML([server.city, ...features].filter(Boolean).join(" · "))}</small></span>${server.load !== undefined ? loadBar(server.load) : "<span></span>"}${action}</div>`;
    }).join("")}
    ${list.length > shown.length ? `<div class="more"><button type="button" class="secondary" data-show-more>Show more (${list.length - shown.length} left)</button></div>` : ""}`;
  // The console's CSP forbids inline style attributes; set widths through the CSSOM.
  $$("[data-width]", body).forEach(bar => { bar.style.width = `${bar.dataset.width}%`; });
};

const openPicker = async () => {
  if (!protonSignedIn()) {
    toast("Sign in to Proton first to browse servers.", "info");
    location.hash = "#/settings/proton";
    return;
  }
  state.picker.country = "";
  $("#location-search").value = "";
  $("#location-dialog").showModal();
  renderPicker();
  try {
    await loadProtonServers();
    renderPicker();
  } catch (error) {
    $("#location-body").innerHTML = `<div class="empty"><strong>Could not load Proton servers</strong><span>${escapeHTML(error.message)}</span></div>`;
  }
};

/* Import a WireGuard configuration */

const fillCountries = () => {
  const select = $("#import-country");
  if (select.options.length) return;
  const countries = COUNTRY_CODES.map(code => [code, countryName(code)]).sort(([, left], [, right]) => left.localeCompare(right));
  select.innerHTML = `<option value="">Choose…</option>${countries.map(([code, name]) => `<option value="${code}">${flag(code)} ${escapeHTML(name)}</option>`).join("")}`;
};

const openImport = () => {
  fillCountries();
  $("#import-form").reset();
  $("#import-dialog").showModal();
  $("#import-file").focus();
};

// Suggest a provider, country and name from a file name like "mullvad-ch-zrh-wg-001.conf".
const guessFromFileName = fileName => {
  const base = fileName.replace(/\.conf$/i, "");
  const words = base.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const provider = Object.entries(PROVIDER_HINTS).find(([hint]) => words.some(word => word.startsWith(hint)))?.[1] || "";
  const country = words.map(word => word.toUpperCase()).find(word => word.length === 2 && COUNTRY_CODES.includes(word)) || "";
  return { name: base.slice(0, 48), provider, country };
};

$("#import-location").addEventListener("click", openImport);
// Drop a pasted private key as soon as the dialog is dismissed.
const closeImport = () => {
  $("#import-config").value = "";
  $("#import-file").value = "";
  $("#import-dialog").close();
};
$("#import-close").addEventListener("click", closeImport);
$("#import-cancel").addEventListener("click", closeImport);
$("#import-file").addEventListener("change", async event => {
  const file = event.target.files[0];
  if (!file) return;
  if (file.size > 16384) return toast("That file is too large to be a WireGuard configuration.", "bad");
  $("#import-config").value = await file.text();
  const guess = guessFromFileName(file.name);
  if (!$("#import-name").value) $("#import-name").value = guess.name;
  if (!$("#import-provider").value) $("#import-provider").value = guess.provider;
  if (!$("#import-country").value && guess.country) $("#import-country").value = guess.country;
});
$("#import-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = $("#import-submit");
  await busy(button, async () => {
    try {
      const { server } = await api("/v1/custom-exits", { method: "POST", body: JSON.stringify({
        name: $("#import-name").value.trim(),
        provider: $("#import-provider").value.trim(),
        country: $("#import-country").value,
        city: $("#import-city").value.trim(),
        config: $("#import-config").value
      }) });
      closeImport();
      toast(`${flag(server.country)} ${server.name} (${server.provider}) imported. Choose it for a device on the Devices page.`);
      await load();
    } catch (error) { toast(error.message, "bad"); }
  });
});
// Escape closes the dialog without the buttons; clear it then too.
$("#import-dialog").addEventListener("close", () => { $("#import-config").value = ""; $("#import-file").value = ""; });

/* Settings */

const renderSettings = () => {
  $$(".tabs a").forEach(tab => tab.setAttribute("aria-selected", String(tab.dataset.tab === state.tab)));
  $$(".tab-panel").forEach(panel => panel.classList.toggle("active", panel.dataset.panel === state.tab));
  renderProton();
  renderNotifications();
  renderConsoleAccount();
};

const renderProton = () => {
  const signedIn = protonSignedIn();
  const needsCode = state.proton?.state === "twoFactorRequired";
  $("#proton-unavailable").hidden = state.protonAvailable;
  $("#proton-login-form").hidden = !state.protonAvailable || signedIn || needsCode;
  $("#proton-totp-form").hidden = !state.protonAvailable || !needsCode;
  $("#proton-summary").hidden = !signedIn;
  const badge = $("#proton-badge");
  badge.className = `badge ${signedIn ? "good" : "warn"}`;
  badge.textContent = !state.protonAvailable ? "Unavailable" : signedIn ? "Signed in" : needsCode ? "Waiting for code" : "Signed out";
  if (!signedIn) return;
  const account = state.proton;
  const facts = [
    ["Account", account.username, ""],
    ["Plan", account.plan, ""],
    ["Connections", `${state.exits.length} of ${account.maxConnections ?? "?"} in use`, ""],
    certificateFact(),
    ["Proton library", account.coreVersion, ""]
  ];
  $("#proton-facts").innerHTML = facts.map(([term, value, tone]) => `<dt>${escapeHTML(term)}</dt><dd class="${tone}">${escapeHTML(value ?? "")}</dd>`).join("");
};

const syncChannels = () => {
  for (const channel of ["telegram", "webhook"]) {
    $(`.channel-body[data-channel="${channel}"]`).classList.toggle("off", !$(`#${channel}-enabled`).checked);
  }
  $(`.channel-body[data-channel="mail"]`).classList.toggle("off", !$("#mail-enabled").checked);
  // Nothing to save while recovery is off and was never set up.
  $("#mail-form").hidden = !$("#mail-enabled").checked && !state.consoleAccount?.recovery;
};

const fillAlertForm = settings => {
  const telegram = settings.telegram;
  $("#telegram-enabled").checked = Boolean(telegram);
  $("#telegram-token").value = "";
  $("#telegram-token").placeholder = telegram ? `Saved (${telegram.botTokenHint}). Leave empty to keep it.` : "123456789:AA…";
  $("#telegram-chat").value = telegram?.chatId || "";
  $("#webhook-enabled").checked = Boolean(settings.webhook);
  $("#webhook-url").value = settings.webhook?.url || "";
  $("#webhook-format").value = settings.webhook?.format || "ntfy";
  $("#telegram-chats").replaceChildren();
  syncChannels();
  state.formsFilled.alerts = true;
};

const renderNotifications = () => {
  if (!state.alerts) return;
  if (!state.formsFilled.alerts) fillAlertForm(state.alerts.settings);
  const active = state.alerts.active || [];
  $("#alert-active").innerHTML = active.length
    ? active.map(alert => `<div class="condition"><strong>${escapeHTML(alert.message)}</strong><small>Since ${escapeHTML(relativeTime(alert.since * 1000))} · ${alert.notified ? "notified" : "within its grace period"}</small></div>`).join("")
    : `<p class="muted">No problems right now.</p>`;
};

const fillMailForm = recovery => {
  const smtp = recovery?.smtp;
  $("#mail-enabled").checked = Boolean(recovery);
  $("#mail-email").value = recovery?.email || "";
  $("#smtp-host").value = smtp?.host || "";
  $("#smtp-port").value = smtp?.port || 587;
  $("#smtp-security").value = smtp?.security || "starttls";
  $("#smtp-username").value = smtp?.username || "";
  $("#smtp-password").value = "";
  $("#smtp-password").placeholder = smtp?.passwordSet ? "Saved. Leave empty to keep it." : "For Gmail or iCloud, an app password";
  $("#smtp-from").value = smtp?.from || "";
  syncChannels();
  state.formsFilled.mail = true;
};

const renderConsoleAccount = () => {
  const account = state.consoleAccount;
  if (!account) return;
  if (!state.formsFilled.account) {
    $("#account-username").value = account.username;
    state.formsFilled.account = true;
  }
  if (!state.formsFilled.mail) fillMailForm(account.recovery);
  $("#account-changed").textContent = account.passwordChangedAt ? `Password last changed ${relativeTime(account.passwordChangedAt * 1000)}.` : "";
  $("#account-recovery").textContent = account.recovery
    ? `Forgot your password? The sign-in page can email a reset code to ${account.recovery.email}.`
    : "Without a recovery email, a forgotten password can only be reset on the server.";
};

/* ---------- navigation ---------- */

const route = () => {
  const [view = "dashboard", sub = ""] = location.hash.replace(/^#\/?/, "").split("/");
  state.view = VIEWS[view] ? view : "dashboard";
  if (state.view === "settings") state.tab = TABS.includes(sub) ? sub : state.tab;
  if (state.view === "devices") state.deviceFilter = DEVICE_FILTERS.some(([key]) => key === sub) ? sub : "all";
  $$(".view").forEach(section => section.classList.toggle("active", section.dataset.view === state.view));
  $$(".nav a").forEach(link => {
    if (link.dataset.nav === state.view) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  $("#page-title").textContent = VIEWS[state.view];
  document.title = `${VIEWS[state.view]} · Tailway`;
  closeMenu();
  render({ force: true });
  window.scrollTo(0, 0);
};

const closeMenu = () => {
  $("#sidebar").classList.remove("open");
  $("#scrim").hidden = true;
  $("#menu-button").setAttribute("aria-expanded", "false");
};

/* ---------- actions ---------- */

const deviceName = nodeId => {
  const device = state.devices.find(candidate => candidate.nodeId === nodeId);
  return device?.displayName || nodeId;
};

const setRoute = async (nodeId, value) => {
  state.busyDevices.add(nodeId);
  renderDevices({ force: true });
  try {
    const path = `/v1/routes/${encodeURIComponent(nodeId)}`;
    await mutate(path, value ? "PUT" : "DELETE", value ? { serverId: value } : {});
    const server = catalogById().get(value);
    const where = !value ? "the default route" : value === DIRECT ? "direct Internet" : value === LOCAL ? "the local network only" : `${countryName(server?.country)}${server ? ` (${server.name})` : ""}`;
    toast(`${deviceName(nodeId)} now uses ${where}.`);
  } catch (error) {
    toast(error.message, "bad");
  } finally {
    state.busyDevices.delete(nodeId);
    await load({ force: true });
  }
};

const saveDns = async (form, reset = false) => {
  const nodeId = form.dataset.dnsForm;
  const button = reset ? $("[data-dns-reset]", form) : $("button:not([type])", form);
  await busy(button, async () => {
    try {
      const path = `/v1/dns/${encodeURIComponent(nodeId)}`;
      if (reset) await mutate(path, "DELETE");
      else {
        const body = { server: $("[data-dns-server]", form)?.value.trim() ?? null };
        const kill = $("[data-dns-kill]", form);
        if (kill) body.killSwitch = kill.checked;
        await mutate(path, "PUT", body);
      }
      toast(reset ? `DNS for ${deviceName(nodeId)} is back to the defaults.` : `DNS for ${deviceName(nodeId)} saved.`);
    } catch (error) {
      toast(error.message, "bad");
    }
  });
  await load({ force: true });
};

const addServer = async button => {
  const serverId = button.dataset.addServer;
  await busy(button, async () => {
    try {
      await api(`/v1/proton/servers/${encodeURIComponent(serverId)}/add`, { method: "POST", body: "{}" });
      const server = state.protonServers.find(candidate => candidate.id === serverId);
      toast(`${flag(server?.country)} ${countryName(server?.country)} · ${server?.name || "server"} added. Choose it for a device on the Devices page.`);
      await load();
      renderPicker();
    } catch (error) {
      toast(error.message, "bad");
    }
  });
};

/* ---------- events ---------- */

window.addEventListener("hashchange", route);

$("#menu-button").addEventListener("click", () => {
  const open = !$("#sidebar").classList.contains("open");
  $("#sidebar").classList.toggle("open", open);
  $("#scrim").hidden = !open;
  $("#menu-button").setAttribute("aria-expanded", String(open));
});
$("#scrim").addEventListener("click", closeMenu);

$("#sign-out").addEventListener("click", async () => {
  try { await api("/auth/logout", { method: "POST", body: "{}" }); } catch (_) { /* already signed out */ }
  location.replace("/login");
});

$("#device-search").addEventListener("input", () => renderDevices({ force: true }));
$("#device-filters").addEventListener("click", event => {
  const chip = event.target.closest("[data-filter]");
  if (!chip) return;
  state.deviceFilter = chip.dataset.filter;
  history.replaceState(null, "", state.deviceFilter === "all" ? "#/devices" : `#/devices/${state.deviceFilter}`);
  renderDevices({ force: true });
});

const deviceList = $("#device-list");
deviceList.addEventListener("change", event => {
  const select = event.target.closest("[data-route]");
  if (select) {
    const nodeId = select.closest("[data-device]").dataset.device;
    select.blur();
    setRoute(nodeId, select.value);
    return;
  }
  const kill = event.target.closest("[data-dns-kill]");
  if (kill) $("[data-dns-fallback]", kill.closest("form")).hidden = kill.checked;
});
deviceList.addEventListener("submit", event => {
  const form = event.target.closest("[data-dns-form]");
  if (!form) return;
  event.preventDefault();
  saveDns(form);
});
deviceList.addEventListener("click", event => {
  const reset = event.target.closest("[data-dns-reset]");
  if (reset) saveDns(reset.closest("form"), true);
});
deviceList.addEventListener("toggle", event => {
  const details = event.target.closest("[data-dns]");
  if (!details) return;
  const nodeId = details.closest("[data-device]").dataset.device;
  if (details.open) state.openDns.add(nodeId); else state.openDns.delete(nodeId);
}, true);

$("#missing-devices").addEventListener("click", async event => {
  const button = event.target.closest("[data-clear]");
  if (!button) return;
  await busy(button, async () => {
    try {
      await mutate(`/v1/routes/${encodeURIComponent(button.dataset.clear)}`, "DELETE");
      toast("Settings removed.");
    } catch (error) { toast(error.message, "bad"); }
  });
  await load({ force: true });
});

$("#add-location").addEventListener("click", openPicker);
$("#location-grid").addEventListener("click", async event => {
  if (event.target.closest("[data-open-picker]")) return openPicker();
  if (event.target.closest("[data-open-import]")) return openImport();
  const remove = event.target.closest("[data-remove-custom]");
  if (remove) {
    const ok = await confirmDialog({ title: `Remove ${remove.dataset.name}?`, text: "Its configuration, including the private key, is deleted from the gateway. You can import it again later.", confirm: "Remove", danger: true });
    if (!ok) return;
    await busy(remove, async () => {
      try {
        await mutate(`/v1/custom-exits/${encodeURIComponent(remove.dataset.removeCustom)}`, "DELETE");
        toast(`${remove.dataset.name} removed.`);
      } catch (error) { toast(error.message, "bad"); }
    });
    await load();
    return;
  }
  const stop = event.target.closest("[data-stop-exit]");
  if (!stop) return;
  const ok = await confirmDialog({ title: "Stop this tunnel?", text: "No devices use it. It starts again when a device picks this location.", confirm: "Stop tunnel", danger: true });
  if (!ok) return;
  await busy(stop, async () => {
    try {
      await mutate(`/v1/exits/${encodeURIComponent(stop.dataset.stopExit)}`, "DELETE");
      toast("Tunnel stopped.");
    } catch (error) { toast(error.message, "bad"); }
  });
  await load();
});

$("#location-close").addEventListener("click", () => $("#location-dialog").close());
$("#location-back").addEventListener("click", () => { state.picker.country = ""; renderPicker(); });
$("#location-search").addEventListener("input", () => { state.picker.country = ""; renderPicker(); });
$("#feature-filters").addEventListener("click", event => {
  const chip = event.target.closest("[data-feature]");
  if (!chip) return;
  const pressed = chip.getAttribute("aria-pressed") !== "true";
  chip.setAttribute("aria-pressed", String(pressed));
  if (pressed) state.picker.features.add(chip.dataset.feature); else state.picker.features.delete(chip.dataset.feature);
  renderPicker();
});
$("#location-body").addEventListener("click", event => {
  const country = event.target.closest("[data-country]");
  if (country) {
    state.picker.country = country.dataset.country;
    state.picker.shown = PICKER_PAGE_DEFAULT;
    renderPicker();
    $("#location-body").scrollTop = 0;
    return;
  }
  if (event.target.closest("[data-show-more]")) {
    state.picker.shown += PICKER_PAGE_DEFAULT;
    renderPicker();
    return;
  }
  const add = event.target.closest("[data-add-server]");
  if (add) addServer(add);
});

/* Proton */
$("#proton-login-form").addEventListener("submit", async event => {
  event.preventDefault();
  const password = $("#proton-password");
  await busy(event.submitter, async () => {
    try {
      state.proton = await api("/v1/proton/login", { method: "POST", body: JSON.stringify({ username: $("#proton-username").value.trim(), password: password.value }) });
      toast(state.proton.state === "twoFactorRequired" ? "Enter your two-factor code." : "Signed in to Proton.", state.proton.state === "twoFactorRequired" ? "info" : "good");
    } catch (error) { toast(error.message, "bad"); }
    password.value = "";
  });
  await load();
});
$("#proton-totp-form").addEventListener("submit", async event => {
  event.preventDefault();
  const code = $("#proton-totp");
  await busy(event.submitter, async () => {
    try {
      await api("/v1/proton/totp", { method: "POST", body: JSON.stringify({ code: code.value }) });
      toast("Signed in to Proton.");
    } catch (error) { toast(error.message, "bad"); }
    code.value = "";
  });
  await load();
});
$("#proton-logout").addEventListener("click", async event => {
  const ok = await confirmDialog({ title: "Sign out of Proton?", text: "Running tunnels keep working until their certificates expire, but they can no longer renew and no new servers can be added.", confirm: "Sign out", danger: true });
  if (!ok) return;
  await busy(event.currentTarget, async () => {
    try { await api("/v1/proton/logout", { method: "POST", body: "{}" }); toast("Signed out of Proton."); } catch (error) { toast(error.message, "bad"); }
  });
  await load();
});

/* Notifications */
$("#alert-form").addEventListener("change", event => {
  if (event.target.matches("#telegram-enabled, #webhook-enabled")) syncChannels();
});
const saveAlerts = async () => {
  const telegram = $("#telegram-enabled").checked ? { botToken: $("#telegram-token").value.trim(), chatId: $("#telegram-chat").value.trim() } : null;
  const webhook = $("#webhook-enabled").checked ? { url: $("#webhook-url").value.trim(), format: $("#webhook-format").value } : null;
  const saved = await api("/v1/alerts", { method: "PUT", body: JSON.stringify({ telegram, webhook }) });
  state.alerts = { ...state.alerts, settings: saved.settings };
  fillAlertForm(saved.settings);
};
$("#alert-form").addEventListener("submit", async event => {
  event.preventDefault();
  await busy(event.submitter, async () => {
    try { await saveAlerts(); toast("Notification settings saved."); } catch (error) { toast(error.message, "bad"); }
  });
});
$("#alert-test").addEventListener("click", async event => {
  await busy(event.currentTarget, async () => {
    try {
      await saveAlerts();
      const { results } = await api("/v1/alerts/test", { method: "POST", body: "{}" });
      for (const result of results) toast(result.ok ? `Test sent to ${result.channel}.` : `${result.channel}: ${result.error}`, result.ok ? "good" : "bad");
    } catch (error) { toast(error.message, "bad"); }
  });
});
$("#telegram-detect").addEventListener("click", async event => {
  const list = $("#telegram-chats");
  list.replaceChildren();
  await busy(event.currentTarget, async () => {
    try {
      const { chats } = await api("/v1/alerts/telegram/chats", { method: "POST", body: JSON.stringify({ botToken: $("#telegram-token").value.trim() }) });
      if (!chats.length) return toast("No messages yet. Send your bot a message in Telegram, then try again.", "info");
      list.innerHTML = chats.map(chat => `<button type="button" class="chip" data-chat-id="${escapeHTML(chat.id)}">${escapeHTML(chat.name || chat.id)} <span class="count">${escapeHTML(chat.kind)}</span></button>`).join("");
    } catch (error) { toast(error.message, "bad"); }
  });
});
$("#telegram-chats").addEventListener("click", event => {
  const chat = event.target.closest("[data-chat-id]");
  if (!chat) return;
  $("#telegram-chat").value = chat.dataset.chatId;
  $("#telegram-chats").replaceChildren();
  toast("Chat selected. Save to use it.", "info");
});

/* Account */
$("#console-account-form").addEventListener("submit", async event => {
  event.preventDefault();
  const newPassword = $("#account-new-password");
  const confirmation = $("#account-confirm-password");
  const current = $("#account-current-password");
  if (newPassword.value !== confirmation.value) return toast("The new passwords do not match.", "bad");
  await busy(event.submitter, async () => {
    try {
      const saved = await api("/auth/account", { method: "PUT", body: JSON.stringify({
        currentPassword: current.value,
        username: $("#account-username").value.trim(),
        newPassword: newPassword.value || null
      }) });
      state.consoleAccount = { ...state.consoleAccount, username: saved.username, passwordChangedAt: saved.passwordChangedAt };
      toast(saved.passwordChanged ? "Saved. Other browsers were signed out." : "Saved.");
      renderChrome();
      renderConsoleAccount();
    } catch (error) { toast(error.message, "bad"); }
    for (const input of [newPassword, confirmation, current]) input.value = "";
  });
});
$("#mail-enabled").addEventListener("change", syncChannels);
$("#smtp-security").addEventListener("change", event => {
  const port = $("#smtp-port");
  if (Object.values(SMTP_PORTS).includes(Number(port.value))) port.value = SMTP_PORTS[event.target.value];
});
const saveMail = async () => {
  const value = selector => $(selector).value.trim();
  const recovery = $("#mail-enabled").checked ? {
    email: value("#mail-email"),
    smtp: { host: value("#smtp-host"), port: Number(value("#smtp-port")), security: value("#smtp-security"), username: value("#smtp-username"), password: $("#smtp-password").value, from: value("#smtp-from") || value("#mail-email") }
  } : null;
  const current = $("#mail-current-password");
  try {
    const saved = await api("/auth/account", { method: "PUT", body: JSON.stringify({ currentPassword: current.value, recovery }) });
    state.consoleAccount = { ...state.consoleAccount, recovery: saved.recovery };
    fillMailForm(saved.recovery);
    renderConsoleAccount();
  } finally {
    current.value = "";
  }
};
$("#mail-form").addEventListener("submit", async event => {
  event.preventDefault();
  await busy(event.submitter, async () => {
    try { await saveMail(); toast("Recovery settings saved."); } catch (error) { toast(error.message, "bad"); }
  });
});
$("#mail-test").addEventListener("click", async event => {
  if (!$("#mail-form").reportValidity()) return;
  await busy(event.currentTarget, async () => {
    try {
      await saveMail();
      const { to } = await api("/auth/recovery/test", { method: "POST", body: "{}" });
      toast(`Test email sent to ${to}. Check the inbox (and spam).`);
    } catch (error) { toast(error.message, "bad"); }
  });
});

/* ---------- start ---------- */

document.addEventListener("visibilitychange", () => { if (!document.hidden) load(); });
setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
// Keep relative times ("2 min ago") current between refreshes.
setInterval(() => { if (state.loaded && state.view === "dashboard") renderDashboard(); }, 30000);
route();
load();
