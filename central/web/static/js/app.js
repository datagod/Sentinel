const ACTIVITY_LOG_HIDDEN_KEY = "sentinel-central-activity-log-hidden";
const SETTINGS_SECTIONS_KEY = "sentinel-central-settings-sections";
const VOLUME_KEY = "sentinel-central-alert-volume";

function clampVolume(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 1;
  return Math.max(0, Math.min(1, n));
}

function loadAlertVolume() {
  try {
    const raw = localStorage.getItem(VOLUME_KEY);
    if (raw == null) return 1;
    return clampVolume(Number(raw));
  } catch (_) {
    return 1;
  }
}

let alertVolume = loadAlertVolume();
let currentAlertAudio = null;

function applyAlertVolume(value) {
  alertVolume = clampVolume(value);
  try {
    localStorage.setItem(VOLUME_KEY, String(alertVolume));
  } catch (_) { /* ignore */ }
  const slider = document.getElementById("alert-volume");
  if (slider) slider.value = String(Math.round(alertVolume * 100));
  if (currentAlertAudio) currentAlertAudio.volume = alertVolume;
}

function attachAlertVolume(audio) {
  if (!audio) return audio;
  audio.volume = alertVolume;
  currentAlertAudio = audio;
  const clear = () => {
    if (currentAlertAudio === audio) currentAlertAudio = null;
  };
  audio.addEventListener("ended", clear);
  audio.addEventListener("error", clear);
  return audio;
}

(function setupAlertVolume() {
  const slider = document.getElementById("alert-volume");
  if (!slider) return;
  slider.value = String(Math.round(alertVolume * 100));
  slider.addEventListener("input", () => {
    applyAlertVolume(Number(slider.value) / 100);
  });
})();

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : "{}",
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function setStatus(id, message, ok) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = message;
  el.className = ok ? "status-line" : "status-line error";
}

function ssidButton(ssid) {
  const name = String(ssid || "").trim();
  if (!name) return "—";
  return `<button type="button" class="ssid-link" data-ssid="${escapeHtml(name)}" title="Look up ${escapeHtml(name)} on WiGLE">${escapeHtml(name)}</button>`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function isActivityLogHidden() {
  try {
    return localStorage.getItem(ACTIVITY_LOG_HIDDEN_KEY) === "1";
  } catch (_) {
    return false;
  }
}

function setActivityLogHidden(hidden) {
  document.documentElement.classList.toggle("activity-log-hidden", !!hidden);
  document.body.classList.toggle("activity-log-hidden", !!hidden);
  try {
    localStorage.setItem(ACTIVITY_LOG_HIDDEN_KEY, hidden ? "1" : "0");
  } catch (_) { /* ignore */ }
}

function renderActivityLog(entries) {
  const el = document.getElementById("activity-log");
  if (!el) return;
  if (!entries || !entries.length) {
    el.innerHTML = '<p class="summary-empty" id="activity-log-empty">No activity yet.</p>';
    return;
  }
  el.innerHTML = entries
    .map(
      (e) =>
        `<div class="activity-entry activity-entry--${escapeHtml(e.level)}" data-id="${e.id}">` +
        `<span class="lvl-${escapeHtml(e.level)}">${escapeHtml(e.created_at)}</span> ` +
        `${escapeHtml(e.message)}</div>`
    )
    .join("");
}

async function refreshActivityLog() {
  const el = document.getElementById("activity-log");
  if (!el) return;
  try {
    const res = await fetch("/api/log");
    const data = await res.json();
    renderActivityLog(data.log || []);
  } catch (_) { /* ignore polling errors */ }
}

setActivityLogHidden(isActivityLogHidden());

document.getElementById("btn-hide-activity-log")?.addEventListener("click", () => {
  setActivityLogHidden(true);
});
document.getElementById("btn-show-activity-log")?.addEventListener("click", () => {
  setActivityLogHidden(false);
});
document.getElementById("btn-clear-activity-log")?.addEventListener("click", async () => {
  try {
    await postJSON("/api/log/clear");
    renderActivityLog([]);
  } catch (err) {
    alert(err.message);
  }
});

function applyHeaderStats(stats, interval) {
  const el = document.getElementById("header-status");
  if (!el || !stats) return;
  const every = interval != null ? interval : (el.textContent.match(/ingest every (\d+)s/) || [])[1];
  el.textContent =
    `${stats.packets || 0} packets · ${stats.devices || 0} devices · ${stats.friendly_devices || 0} friendly · ` +
    `${stats.enabled_clients || 0}/${stats.clients || 0} clients · ingest every ${every || "?"}s`;
}

if (document.getElementById("activity-log")) {
  setInterval(refreshActivityLog, 4000);
}

let voiceAlertPlaying = false;
async function pollVoiceAlerts() {
  if (voiceAlertPlaying) return;
  try {
    const res = await fetch("/api/alerts/pending");
    if (!res.ok) return;
    const data = await res.json();
    const next = (data.alerts || [])[0];
    if (!next) return;
    voiceAlertPlaying = true;
    const audio = attachAlertVolume(new Audio(next.audio));
    const done = async () => {
      try {
        await fetch(`/api/alerts/${encodeURIComponent(next.id)}/played`, { method: "POST" });
      } catch (_) { /* ignore */ }
      voiceAlertPlaying = false;
    };
    audio.addEventListener("ended", done);
    audio.addEventListener("error", done);
    try {
      await audio.play();
    } catch (_) {
      await done();
    }
  } catch (_) {
    voiceAlertPlaying = false;
  }
}
setInterval(pollVoiceAlerts, 4000);
pollVoiceAlerts();

document.getElementById("btn-ingest")?.addEventListener("click", async (ev) => {
  const btn = ev.currentTarget;
  btn.disabled = true;
  setStatus("ingest-status", "Pulling new records from clients…", true);
  try {
    const data = await postJSON("/api/ingest");
    const rows = (data.results || []).reduce((n, r) => n + (r.rows_copied || 0), 0);
    const offline = (data.results || []).filter((r) => r.status !== "ok").length;
    setStatus(
      "ingest-status",
      `Copied ${rows} new rows. ${offline} client(s) not ok.`,
      true
    );
    await refreshActivityLog();
    setTimeout(() => location.reload(), 600);
  } catch (err) {
    setStatus("ingest-status", err.message, false);
    btn.disabled = false;
  }
});

function resetClientForm() {
  const id = document.getElementById("client-id");
  const name = document.getElementById("client-name");
  const path = document.getElementById("client-path");
  const notes = document.getElementById("client-notes");
  const smbUser = document.getElementById("client-smb-username");
  const smbPass = document.getElementById("client-smb-password");
  const enabled = document.getElementById("client-enabled");
  const title = document.getElementById("client-form-title");
  const save = document.getElementById("btn-save-client");
  const cancel = document.getElementById("btn-cancel-edit");
  if (!id) return;
  id.value = "";
  if (name) name.value = "";
  if (path) path.value = "";
  if (notes) notes.value = "";
  if (smbUser) smbUser.value = "";
  if (smbPass) {
    smbPass.value = "";
    smbPass.placeholder = "leave blank to keep / guest";
  }
  if (enabled) enabled.checked = true;
  if (title) title.textContent = "Add client";
  if (save) save.textContent = "Add client";
  if (cancel) cancel.hidden = true;
  document.getElementById("client-name")?.focus();
}

function fillClientForm(btn) {
  document.getElementById("client-id").value = btn.dataset.id || "";
  document.getElementById("client-name").value = btn.dataset.name || "";
  document.getElementById("client-path").value = btn.dataset.path || "";
  document.getElementById("client-notes").value = btn.dataset.notes || "";
  document.getElementById("client-smb-username").value = btn.dataset.smbUsername || "";
  const smbPass = document.getElementById("client-smb-password");
  smbPass.value = "";
  smbPass.placeholder = btn.dataset.hasPassword === "1" ? "stored — leave blank to keep" : "leave blank for guest";
  document.getElementById("client-enabled").checked = btn.dataset.enabled === "1";
  document.getElementById("client-form-title").textContent = "Edit client";
  document.getElementById("btn-save-client").textContent = "Save changes";
  document.getElementById("btn-cancel-edit").hidden = false;
  document.getElementById("client-form-title").scrollIntoView({ behavior: "smooth", block: "start" });
  document.getElementById("client-name").focus();
}

document.getElementById("btn-save-client")?.addEventListener("click", async () => {
  const id = document.getElementById("client-id").value.trim();
  const name = document.getElementById("client-name").value.trim();
  const db_path = document.getElementById("client-path").value.trim();
  const notes = document.getElementById("client-notes").value.trim();
  const smb_username = document.getElementById("client-smb-username").value.trim();
  const smb_password = document.getElementById("client-smb-password").value;
  const enabled = document.getElementById("client-enabled").checked;
  const payload = { name, db_path, notes, enabled, smb_username };
  if (smb_password) payload.smb_password = smb_password;
  try {
    if (id) {
      await postJSON(`/api/clients/${id}`, payload);
    } else {
      await postJSON("/api/clients", payload);
    }
    location.reload();
  } catch (err) {
    setStatus("client-status", err.message, false);
  }
});

document.getElementById("btn-cancel-edit")?.addEventListener("click", () => {
  resetClientForm();
  setStatus("client-status", "", true);
});

document.querySelectorAll(".btn-edit").forEach((btn) => {
  btn.addEventListener("click", () => fillClientForm(btn));
});

document.querySelectorAll(".btn-sync").forEach((btn) => {
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      await postJSON(`/api/ingest/${btn.dataset.id}`);
      location.reload();
    } catch (err) {
      alert(err.message);
      btn.disabled = false;
    }
  });
});

document.querySelectorAll(".btn-toggle").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const enabled = btn.dataset.enabled !== "1";
    try {
      await postJSON(`/api/clients/${btn.dataset.id}`, { enabled });
      location.reload();
    } catch (err) {
      alert(err.message);
    }
  });
});

async function setFriendly(mac, friendly, name) {
  const payload = { mac, friendly };
  if (name != null) payload.name = name;
  return postJSON("/api/devices/friendly", payload);
}

async function setTracked(mac, tracked) {
  return postJSON("/api/devices/track", { mac, tracked: !!tracked });
}

document.addEventListener("click", async (ev) => {
  const film = ev.target.closest(".btn-film");
  if (film) {
    const ts = film.dataset.ts;
    if (!ts) return;
    const mac = encodeURIComponent(film.dataset.mac || "");
    window.open(
      `/frigate-media?ts=${encodeURIComponent(ts)}&mac=${mac}`,
      "sentinel-frigate",
      "width=1280,height=900,scrollbars=yes,resizable=yes"
    );
    return;
  }
  const friendlyBtn = ev.target.closest(".btn-set-friendly");
  if (friendlyBtn) {
    const next = friendlyBtn.dataset.friendly !== "1";
    friendlyBtn.disabled = true;
    try {
      await setFriendly(friendlyBtn.dataset.mac, next);
      location.reload();
    } catch (err) {
      alert(err.message);
      friendlyBtn.disabled = false;
    }
    return;
  }
  const remove = ev.target.closest(".tag-remove");
  if (remove) {
    const mac = encodeURIComponent(remove.dataset.mac);
    const tag = encodeURIComponent(remove.dataset.tag);
    try {
      const res = await fetch(`/api/tags?mac=${mac}&tag=${tag}`, { method: "DELETE" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || res.statusText);
      location.reload();
    } catch (err) {
      alert(err.message);
    }
  }
});

document.addEventListener("submit", async (ev) => {
  const form = ev.target.closest(".tag-add");
  if (!form) return;
  ev.preventDefault();
  const input = form.querySelector(".tag-input");
  const tag = (input?.value || "").trim();
  if (!tag) return;
  try {
    await postJSON("/api/tags", { mac: form.dataset.mac, tag });
    location.reload();
  } catch (err) {
    alert(err.message);
  }
});

document.querySelectorAll(".friendly-name-form").forEach((form) => {
  const input = form.querySelector(".name-input");
  const save = async () => {
    const name = (input?.value || "").trim();
    if (!name) return;
    try {
      await setFriendly(form.dataset.mac, form.dataset.friendly === "1", name);
      location.reload();
    } catch (err) {
      alert(err.message);
    }
  };
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    await save();
  });
  input?.addEventListener("blur", () => {
    if (input.value.trim() !== (input.defaultValue || "").trim()) save();
  });
});

function packetRowHtml(p) {
  const mac = p.SourceMAC || "";
  const friendly = Number(p.device_friendly) === 1;
  const name = p.device_name || p.FriendlyName || "";
  const tags = p.tag_list || [];
  const ts = p.unix_ts || "";
  const film = ts
    ? `<button type="button" class="btn-film" title="Frigate footage" data-ts="${escapeHtml(ts)}" data-mac="${escapeHtml(mac)}" aria-label="Open Frigate footage"><img src="/static/img/film-reel.svg" width="18" height="18" alt=""></button>`
    : "";
  const friendlyCell = friendly
    ? `<span class="badge badge-ok"><span class="dot"></span>${escapeHtml(name)}</span>
       <button type="button" class="btn btn-secondary btn-small btn-set-friendly" data-mac="${escapeHtml(mac)}" data-friendly="1">Not friendly</button>`
    : `<span class="badge badge-muted">${escapeHtml(name || "not friendly")}</span>
       <button type="button" class="btn btn-secondary btn-small btn-set-friendly" data-mac="${escapeHtml(mac)}" data-friendly="0">Mark friendly</button>`;
  const tagHtml = tags
    .map(
      (t) =>
        `<span class="tag-chip"><a href="/packets?tag=${encodeURIComponent(t)}">${escapeHtml(t)}</a>
         <button type="button" class="tag-remove" data-mac="${escapeHtml(mac)}" data-tag="${escapeHtml(t)}" title="Remove tag" aria-label="Remove ${escapeHtml(t)}">×</button></span>`
    )
    .join("");
  return `<tr>
    <td>${film}</td>
    <td>${escapeHtml(p.local_time || "—")}</td>
    <td><a href="/details?mac=${encodeURIComponent(mac)}&packet=${encodeURIComponent(p.id || "")}">${escapeHtml(p.device_name || p.FriendlyName || p.DeviceType || "—")}</a></td>
    <td><a href="/details?mac=${encodeURIComponent(mac)}&packet=${encodeURIComponent(p.id || "")}">${escapeHtml(mac)}</a></td>
    <td><div class="friendly-cell">${friendlyCell}</div></td>
    <td>${ssidButton(p.SSID)}</td>
    <td>${escapeHtml(p.DeviceType || p.PacketType || "—")}</td>
    <td>${p.Signal == null || p.Signal === "" ? "—" : escapeHtml(p.Signal)}</td>
    <td><div class="tag-cell">${tagHtml}
      <form class="tag-add" data-mac="${escapeHtml(mac)}">
        <input class="set-input tag-input" list="tag-suggestions" placeholder="add tag" aria-label="Add tag">
        <button type="submit" class="btn btn-secondary btn-small">Add</button>
      </form>
    </div></td>
  </tr>`;
}

(function setupPacketInfiniteScroll() {
  const table = document.getElementById("packet-table");
  const tbody = document.getElementById("packet-tbody");
  const sentinel = document.getElementById("packet-scroll-sentinel");
  const status = document.getElementById("packet-scroll-status");
  if (!table || !tbody || !sentinel) return;

  let offset = Number(table.dataset.offset || 0);
  let hasMore = table.dataset.hasMore === "1";
  let loading = false;
  const pageSize = Number(table.dataset.pageSize || 100);

  async function loadMore() {
    if (loading || !hasMore) return;
    loading = true;
    if (status) {
      status.hidden = false;
      status.textContent = "Loading more packets…";
    }
    const params = new URLSearchParams({
      offset: String(offset),
      limit: String(pageSize),
    });
    if (table.dataset.q) params.set("q", table.dataset.q);
    if (table.dataset.clientId) params.set("client_id", table.dataset.clientId);
    if (table.dataset.tag) params.set("tag", table.dataset.tag);
    try {
      const res = await fetch(`/api/packets?${params.toString()}`);
      const data = await res.json();
      const rows = data.packets || [];
      if (rows.length) {
        tbody.insertAdjacentHTML("beforeend", rows.map(packetRowHtml).join(""));
        offset += rows.length;
        table.dataset.offset = String(offset);
      }
      hasMore = !!data.has_more;
      table.dataset.hasMore = hasMore ? "1" : "0";
      if (status) {
        status.textContent = hasMore ? "Scroll for more packets…" : "End of packets";
        if (!hasMore) status.hidden = false;
      }
    } catch (err) {
      if (status) status.textContent = "Could not load more packets.";
    } finally {
      loading = false;
    }
  }

  const observer = new IntersectionObserver(
    (entries) => {
      if (entries.some((e) => e.isIntersecting)) loadMore();
    },
    { root: null, rootMargin: "400px", threshold: 0 }
  );
  observer.observe(sentinel);
})();

function cameraCountLabel(cameras) {
  const total = cameras.length;
  const enabled = cameras.filter((c) => c.enabled).length;
  if (!total) return "No cameras yet. Save a reachable Frigate URL to load cameras.";
  return `Connected · ${enabled} of ${total} camera${total === 1 ? "" : "s"} included in footage lookup`;
}

document.getElementById("btn-save-frigate")?.addEventListener("click", async (ev) => {
  const btn = ev.currentTarget;
  btn.disabled = true;
  setStatus("frigate-status", "Saving Frigate settings…", true);
  try {
    const data = await postJSON("/api/settings/frigate", {
      base_url: document.getElementById("frigate-url")?.value || "",
      lead_seconds: document.getElementById("frigate-lead")?.value,
      pad_seconds: document.getElementById("frigate-pad")?.value,
    });
    if (data.error) {
      setStatus("frigate-status", data.error, false);
    } else {
      setStatus("frigate-status", cameraCountLabel(data.cameras || []), true);
    }
    await refreshActivityLog();
    setTimeout(() => location.reload(), 400);
  } catch (err) {
    setStatus("frigate-status", err.message, false);
    btn.disabled = false;
  }
});

document.getElementById("btn-refresh-cameras")?.addEventListener("click", async (ev) => {
  const btn = ev.currentTarget;
  btn.disabled = true;
  setStatus("frigate-status", "Refreshing cameras from Frigate…", true);
  try {
    const data = await postJSON("/api/settings/frigate/cameras/refresh");
    if (data.error) {
      setStatus("frigate-status", data.error, false);
    } else {
      setStatus("frigate-status", cameraCountLabel(data.cameras || []), true);
    }
    setTimeout(() => location.reload(), 400);
  } catch (err) {
    setStatus("frigate-status", err.message, false);
    btn.disabled = false;
  }
});

function parseVoiceValue(value) {
  const raw = String(value || "");
  const idx = raw.indexOf(":");
  if (idx < 0) return { voice_mode: "clone", voice: raw };
  return { voice_mode: raw.slice(0, idx), voice: raw.slice(idx + 1) };
}

document.getElementById("btn-save-wigle")?.addEventListener("click", async (ev) => {
  const btn = ev.currentTarget;
  btn.disabled = true;
  setStatus("wigle-status", "Saving WiGLE settings…", true);
  const token = (document.getElementById("wigle-api-token")?.value || "").trim();
  const payload = {
    enabled: !!document.getElementById("wigle-enabled")?.checked,
    base_url: document.getElementById("wigle-url")?.value || "",
    api_name: document.getElementById("wigle-api-name")?.value || "",
  };
  if (token) payload.api_token = token;
  try {
    const data = await postJSON("/api/settings/wigle", payload);
    const w = data.wigle || {};
    setStatus(
      "wigle-status",
      w.enabled
        ? `Enabled · API name ${w.api_name || "—"} · ${w.has_api_token ? "token saved" : "no token"}`
        : "WiGLE lookups disabled.",
      true
    );
    const tokenInput = document.getElementById("wigle-api-token");
    if (tokenInput) tokenInput.value = "";
    await refreshActivityLog();
  } catch (err) {
    setStatus("wigle-status", err.message, false);
  } finally {
    btn.disabled = false;
  }
});

function formatUsageValue(value) {
  if (value == null || value === "") return "—";
  if (typeof value === "number") return value.toLocaleString();
  return String(value);
}

document.getElementById("btn-wigle-usage")?.addEventListener("click", async (ev) => {
  const btn = ev.currentTarget;
  const box = document.getElementById("wigle-usage");
  btn.disabled = true;
  setStatus("wigle-status", "Querying WiGLE account usage…", true);
  try {
    const res = await fetch("/api/wigle/usage");
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText);
    const local = data.local || {};
    const cards = [
      ["User", data.userid],
      ["Rank", data.rank],
      ["Month rank", data.month_rank],
      ["Wi‑Fi discovered", data.discovered_wifi],
      ["Wi‑Fi + GPS", data.discovered_wifi_gps],
      ["Bluetooth discovered", data.discovered_bt],
      ["Wi‑Fi locations", data.total_wifi_locations],
      ["This month", data.month_count],
      ["Last month", data.prev_month_count],
      ["First seen", data.first],
      ["Last upload", data.last],
      ["Dashboard lookups (24h)", local.lookups_24h],
      ["Dashboard lookups (all)", local.lookups_total],
      ["Cached SSIDs", local.cached_ssids],
    ];
    if (box) {
      box.hidden = false;
      box.innerHTML =
        `<p class="hint" style="margin-bottom:0.5rem">WiGLE account stats plus lookups from this dashboard. Daily query limits are not published as a remaining count; they reset at 00:00 US/Pacific.</p>` +
        `<div class="stat-grid">` +
        cards
          .map(
            ([label, value]) =>
              `<div class="stat-card"><div class="label">${escapeHtml(label)}</div>` +
              `<div class="value">${escapeHtml(formatUsageValue(value))}</div></div>`
          )
          .join("") +
        `</div>`;
    }
    setStatus(
      "wigle-status",
      data.userid
        ? `Usage for ${data.userid}` + (data.rank != null ? ` · rank ${data.rank}` : "")
        : "WiGLE usage loaded.",
      true
    );
  } catch (err) {
    setStatus("wigle-status", err.message, false);
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("btn-test-wigle")?.addEventListener("click", async (ev) => {
  const btn = ev.currentTarget;
  btn.disabled = true;
  setStatus("wigle-status", "Testing WiGLE credentials…", true);
  const token = (document.getElementById("wigle-api-token")?.value || "").trim();
  const payload = {
    base_url: document.getElementById("wigle-url")?.value || "",
    api_name: document.getElementById("wigle-api-name")?.value || "",
  };
  if (token) payload.api_token = token;
  try {
    const data = await postJSON("/api/settings/wigle/test", payload);
    setStatus("wigle-status", data.message || "WiGLE credentials work.", true);
  } catch (err) {
    setStatus("wigle-status", err.message, false);
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("btn-save-chatterbox")?.addEventListener("click", async (ev) => {
  const btn = ev.currentTarget;
  btn.disabled = true;
  setStatus("chatterbox-status", "Saving Chatterbox settings…", true);
  const voice = parseVoiceValue(document.getElementById("chatterbox-voice")?.value);
  try {
    await postJSON("/api/settings/chatterbox", {
      enabled: !!document.getElementById("chatterbox-enabled")?.checked,
      base_url: document.getElementById("chatterbox-url")?.value || "",
      voice_mode: voice.voice_mode,
      voice: voice.voice,
      cooldown_seconds: document.getElementById("chatterbox-cooldown")?.value,
      timeout: document.getElementById("chatterbox-timeout")?.value,
    });
    setStatus("chatterbox-status", "Chatterbox settings saved.", true);
    await refreshActivityLog();
    setTimeout(() => location.reload(), 400);
  } catch (err) {
    setStatus("chatterbox-status", err.message, false);
    btn.disabled = false;
  }
});

document.getElementById("btn-test-chatterbox")?.addEventListener("click", async (ev) => {
  const btn = ev.currentTarget;
  btn.disabled = true;
  setStatus("chatterbox-status", "Speaking a test phrase…", true);
  try {
    const res = await fetch("/api/settings/chatterbox/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: "Sentinel Central voice alert test." }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || res.statusText);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const audio = attachAlertVolume(new Audio(url));
    audio.addEventListener("ended", () => URL.revokeObjectURL(url));
    await audio.play();
    setStatus("chatterbox-status", "Played test voice alert.", true);
  } catch (err) {
    setStatus("chatterbox-status", err.message, false);
  } finally {
    btn.disabled = false;
  }
});

async function saveVoiceAlert(id, extra) {
  const row = document.querySelector(`[data-alert-id="${id}"]`);
  const enabled = row?.querySelector(".alert-enable")?.checked;
  const minPackets = row?.querySelector(".alert-min-packets")?.value;
  const windowMinutes = row?.querySelector(".alert-window-minutes")?.value;
  const quietMinutes = row?.querySelector(".alert-quiet-minutes")?.value;
  const template = row?.querySelector(".alert-template")?.value;
  const payload = { id, enabled: !!enabled, ...(extra || {}) };
  if (minPackets != null && minPackets !== "") payload.min_packets = minPackets;
  if (windowMinutes != null && windowMinutes !== "") payload.window_minutes = windowMinutes;
  if (quietMinutes != null && quietMinutes !== "") payload.quiet_minutes = quietMinutes;
  if (template != null) payload.template = template;
  return postJSON("/api/settings/alerts", payload);
}

document.querySelectorAll(".alert-enable").forEach((input) => {
  input.addEventListener("change", async () => {
    input.disabled = true;
    try {
      await saveVoiceAlert(input.dataset.id);
      const enabled = document.querySelectorAll(".alert-enable:checked").length;
      const count = document.getElementById("alert-enabled-count");
      if (count) count.textContent = `${enabled} enabled`;
      setStatus(
        "chatterbox-status",
        `${input.dataset.id} ${input.checked ? "enabled" : "disabled"}`,
        true
      );
      await refreshActivityLog();
    } catch (err) {
      input.checked = !input.checked;
      setStatus("chatterbox-status", err.message, false);
    } finally {
      input.disabled = false;
    }
  });
});

document.querySelectorAll(".alert-min-packets, .alert-window-minutes, .alert-quiet-minutes, .alert-template").forEach((input) => {
  const save = async () => {
    try {
      const data = await saveVoiceAlert(input.dataset.id);
      const alert = data.alert || {};
      let message = "Voice alert saved.";
      if (input.classList.contains("alert-template") && alert.template) {
        message = `Alert phrase set to “${alert.template}”.`;
      } else if (alert.id === "left_premises" && alert.quiet_minutes != null) {
        message = `Tracked devices leave after ${alert.quiet_minutes} minutes without packets.`;
      } else if (alert.quiet_minutes != null && input.classList.contains("alert-quiet-minutes")) {
        message = `Friendly devices announced after ${alert.quiet_minutes} minutes without a detection.`;
      } else if (alert.min_packets != null && alert.window_minutes != null) {
        message = `Intruder alert requires ${alert.min_packets} packets in ${alert.window_minutes} minutes.`;
      }
      setStatus("chatterbox-status", message, true);
      await refreshActivityLog();
    } catch (err) {
      setStatus("chatterbox-status", err.message, false);
    }
  };
  input.addEventListener("change", save);
});

document.querySelectorAll(".device-track").forEach((input) => {
  input.addEventListener("change", async () => {
    const next = input.checked;
    input.disabled = true;
    try {
      await setTracked(input.dataset.mac, next);
      location.reload();
    } catch (err) {
      input.checked = !next;
      alert(err.message);
      input.disabled = false;
    }
  });
});

document.querySelectorAll(".camera-enable").forEach((input) => {
  input.addEventListener("change", async () => {
    const name = input.dataset.name;
    input.disabled = true;
    try {
      await postJSON("/api/settings/frigate/cameras", {
        name,
        enabled: input.checked,
      });
      const enabled = document.querySelectorAll(".camera-enable:checked").length;
      const total = document.querySelectorAll(".camera-enable").length;
      setStatus(
        "frigate-status",
        `${name} ${input.checked ? "enabled" : "disabled"} · ${enabled} of ${total} cameras included in footage lookup`,
        true
      );
      const count = document.getElementById("frigate-enabled-count");
      if (count) count.textContent = `${enabled} enabled`;
      await refreshActivityLog();
    } catch (err) {
      input.checked = !input.checked;
      setStatus("frigate-status", err.message, false);
    } finally {
      input.disabled = false;
    }
  });
});

document.getElementById("btn-import-fing")?.addEventListener("click", async () => {
  const raw = document.getElementById("fing-json").value.trim();
  if (!raw) {
    setStatus("fing-status", "Paste a Fing JSON export first.", false);
    return;
  }
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (err) {
    setStatus("fing-status", "JSON is not valid.", false);
    return;
  }
  try {
    const data = await postJSON("/api/devices/import-fing", payload);
    setStatus(
      "fing-status",
      `Imported ${data.total} devices (${data.inserted} new, ${data.updated} updated). Tagged ${data.packets_tagged} packets.`,
      true
    );
    setTimeout(() => location.reload(), 700);
  } catch (err) {
    setStatus("fing-status", err.message, false);
  }
});

document.querySelectorAll(".btn-delete").forEach((btn) => {
  btn.addEventListener("click", async () => {
    if (!confirm("Delete this client and its copied packets?")) return;
    const res = await fetch(`/api/clients/${btn.dataset.id}`, { method: "DELETE" });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      alert(data.error || res.statusText);
      return;
    }
    location.reload();
  });
});

(function setupAudioAlerts() {
  const tbody = document.getElementById("recordings-tbody");
  if (!tbody) return;

  let recordingsPlayingFilename = null;
  const recordingsSelected = new Set();
  let recordingsListCache = [];

  function formatFileSize(bytes) {
    const n = Number(bytes) || 0;
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  }

  function recordingUrl(filename, download) {
    const q = download ? "?download=1" : "";
    return `/api/recordings/${encodeURIComponent(filename)}${q}`;
  }

  function setRecordingsPlayState(filename, playing) {
    document.querySelectorAll("[data-recording-play]").forEach((btn) => {
      const name = btn.getAttribute("data-recording-play");
      if (name === filename && playing) {
        btn.textContent = "Stop";
        btn.classList.add("is-playing");
      } else {
        btn.textContent = "Play";
        btn.classList.remove("is-playing");
      }
    });
  }

  function stopRecordingPlayback() {
    const player = document.getElementById("recordings-player");
    if (!player) return;
    if (currentAlertAudio === player) currentAlertAudio = null;
    player.pause();
    player.removeAttribute("src");
    player.load();
    setRecordingsPlayState(recordingsPlayingFilename, false);
    recordingsPlayingFilename = null;
  }

  async function playRecording(filename) {
    const player = document.getElementById("recordings-player");
    if (!player || !filename) return;
    if (recordingsPlayingFilename === filename && !player.paused) {
      stopRecordingPlayback();
      return;
    }
    stopRecordingPlayback();
    recordingsPlayingFilename = filename;
    player.src = recordingUrl(filename, false);
    attachAlertVolume(player);
    setRecordingsPlayState(filename, true);
    try {
      await player.play();
    } catch (e) {
      stopRecordingPlayback();
      setStatus("recordings-status", "Playback blocked — interact with the page first.", false);
    }
  }

  function updateRecordingsSelectionUi() {
    const btn = document.getElementById("recordings-delete-btn");
    const selAll = document.getElementById("recordings-select-all");
    const n = recordingsSelected.size;
    if (btn) {
      btn.disabled = n === 0;
      btn.textContent = n ? `Delete selected (${n})` : "Delete selected";
    }
    if (selAll && recordingsListCache.length) {
      const allOnPage = recordingsListCache.every((r) => recordingsSelected.has(r.filename));
      const some = recordingsListCache.some((r) => recordingsSelected.has(r.filename));
      selAll.checked = allOnPage;
      selAll.indeterminate = some && !allOnPage;
    } else if (selAll) {
      selAll.checked = false;
      selAll.indeterminate = false;
    }
  }

  function toggleRecordingSelect(filename, checked) {
    if (!filename) return;
    if (checked) recordingsSelected.add(filename);
    else recordingsSelected.delete(filename);
    updateRecordingsSelectionUi();
  }

  function selectAllRecordings(checked) {
    if (!recordingsListCache.length) return;
    if (checked) {
      recordingsListCache.forEach((r) => {
        if (r.filename) recordingsSelected.add(r.filename);
      });
    } else {
      recordingsListCache.forEach((r) => {
        if (r.filename) recordingsSelected.delete(r.filename);
      });
    }
    document.querySelectorAll("[data-recording-select]").forEach((cb) => {
      cb.checked = checked;
    });
    updateRecordingsSelectionUi();
  }

  function renderRecordings(recordings) {
    recordingsListCache = recordings || [];
    const known = new Set(recordingsListCache.map((r) => r.filename).filter(Boolean));
    Array.from(recordingsSelected).forEach((f) => {
      if (!known.has(f)) recordingsSelected.delete(f);
    });
    if (!recordingsListCache.length) {
      tbody.innerHTML =
        '<tr><td colspan="6" class="summary-empty">No recordings yet. Enable Chatterbox TTS and trigger voice alerts or use Speak above.</td></tr>';
      updateRecordingsSelectionUi();
      return;
    }
    tbody.innerHTML = recordingsListCache
      .map((r) => {
        const when = escapeHtml(r.local_time || "—");
        const msg = escapeHtml(r.message || r.filename || "");
        const voice = escapeHtml(r.voice || "—");
        const size = formatFileSize(r.size_bytes);
        const file = r.filename || "";
        const fileAttr = escapeHtml(file);
        const checked = recordingsSelected.has(file) ? " checked" : "";
        return `<tr>
          <td class="col-check"><input type="checkbox" data-recording-select="${fileAttr}"${checked}></td>
          <td>${when}</td>
          <td>${msg}</td>
          <td>${voice}</td>
          <td>${size}</td>
          <td class="recording-actions">
            <button type="button" class="btn-recording-play" data-recording-play="${fileAttr}">Play</button>
            <a href="${recordingUrl(file, true)}" download="${fileAttr}">Download</a>
          </td>
        </tr>`;
      })
      .join("");
    if (recordingsPlayingFilename) {
      setRecordingsPlayState(recordingsPlayingFilename, true);
    }
    updateRecordingsSelectionUi();
  }

  async function loadRecordings(force) {
    const status = document.getElementById("recordings-status");
    if (status && (force || !status.textContent)) status.textContent = "Loading…";
    try {
      const res = await fetch("/api/recordings");
      const data = await res.json();
      if (!res.ok || !data.ok) {
        throw new Error((data && data.error) || res.statusText);
      }
      renderRecordings(data.recordings || []);
      const sel = recordingsSelected.size;
      if (status) {
        status.textContent = sel
          ? `${data.total || 0} file(s) · ${sel} selected`
          : `${data.total || 0} file(s)`;
        status.className = "panel-count";
      }
    } catch (err) {
      if (status) {
        status.textContent = `Failed: ${err.message || err}`;
        status.className = "status-line error";
      }
      renderRecordings([]);
    }
  }

  async function deleteSelectedRecordings() {
    const names = Array.from(recordingsSelected);
    if (!names.length) return;
    if (!confirm(`Delete ${names.length} recording(s)? This cannot be undone.`)) return;
    const status = document.getElementById("recordings-status");
    const btn = document.getElementById("recordings-delete-btn");
    if (btn) btn.disabled = true;
    if (status) status.textContent = `Deleting ${names.length}…`;
    if (recordingsPlayingFilename && names.includes(recordingsPlayingFilename)) {
      stopRecordingPlayback();
    }
    try {
      const data = await postJSON("/api/recordings/delete", { filenames: names });
      (data.deleted || []).forEach((f) => recordingsSelected.delete(f));
      await loadRecordings(true);
      await refreshActivityLog();
      const errCount = Object.keys(data.errors || {}).length;
      if (status) {
        status.textContent = errCount
          ? `Deleted ${(data.deleted || []).length}; ${errCount} failed`
          : `${data.remaining ?? recordingsListCache.length} file(s)`;
      }
    } catch (err) {
      if (status) {
        status.textContent = `Delete failed: ${err.message || err}`;
        status.className = "status-line error";
      }
      updateRecordingsSelectionUi();
    }
  }

  tbody.addEventListener("change", (ev) => {
    const cb = ev.target.closest("[data-recording-select]");
    if (!cb) return;
    toggleRecordingSelect(cb.getAttribute("data-recording-select"), cb.checked);
  });
  tbody.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-recording-play]");
    if (!btn) return;
    playRecording(btn.getAttribute("data-recording-play"));
  });

  document.getElementById("recordings-select-all")?.addEventListener("change", (ev) => {
    selectAllRecordings(ev.currentTarget.checked);
  });
  document.getElementById("btn-refresh-recordings")?.addEventListener("click", () => {
    loadRecordings(true);
  });
  document.getElementById("recordings-delete-btn")?.addEventListener("click", () => {
    deleteSelectedRecordings();
  });

  const player = document.getElementById("recordings-player");
  if (player) {
    player.addEventListener("ended", () => stopRecordingPlayback());
    player.addEventListener("pause", () => {
      if (player.ended || !player.src) return;
      if (player.currentTime > 0 && player.paused) {
        setRecordingsPlayState(recordingsPlayingFilename, false);
        recordingsPlayingFilename = null;
      }
    });
  }

  document.getElementById("btn-speak-alert")?.addEventListener("click", async (ev) => {
    const btn = ev.currentTarget;
    const input = document.getElementById("speak-text");
    const text = (input?.value || "").trim();
    if (!text) {
      setStatus("speak-status", "Enter text to speak.", false);
      return;
    }
    btn.disabled = true;
    setStatus("speak-status", "Speaking…", true);
    try {
      const res = await fetch("/api/settings/chatterbox/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || res.statusText);
      }
      const fromCache = res.headers.get("X-TTS-Cache") === "hit";
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const audio = attachAlertVolume(new Audio(url));
      audio.addEventListener("ended", () => URL.revokeObjectURL(url));
      await audio.play();
      setStatus(
        "speak-status",
        fromCache ? "Played from cache (no Chatterbox call)." : "Generated and saved to cache.",
        true
      );
      await loadRecordings(true);
      await refreshActivityLog();
    } catch (err) {
      setStatus("speak-status", err.message, false);
    } finally {
      btn.disabled = false;
    }
  });

  loadRecordings(true);
})();

function reportRowHtml(d) {
  const mac = d.mac || "";
  const type = d.device_type || "";
  const mobile = /mobile|phone/i.test(type);
  const ts = d.unix_ts || "";
  const film = ts
    ? `<button type="button" class="btn-film" title="Frigate footage" data-ts="${escapeHtml(ts)}" data-mac="${escapeHtml(mac)}" aria-label="Open Frigate footage"><img src="/static/img/film-reel.svg" width="18" height="18" alt=""></button>`
    : "";
  const ssids = (d.ssid_list || []).map(ssidButton).join(" ") || "—";
  const tags = (d.tag_list || [])
    .map((t) => `<span class="tag-chip"><a href="/devices?tag=${encodeURIComponent(t)}">${escapeHtml(t)}</a></span>`)
    .join("") || "—";
  let signal = "—";
  if (d.strongest_signal != null && d.strongest_signal !== "") {
    signal = escapeHtml(d.strongest_signal);
    if (d.weakest_signal != null && d.weakest_signal !== d.strongest_signal) {
      signal += ` to ${escapeHtml(d.weakest_signal)}`;
    }
  }
  return `<tr class="${mobile ? "row-mobile" : ""}">
    <td>${film}</td>
    <td>${escapeHtml(d.last_seen_local || "—")}</td>
    <td><a href="/packets?q=${encodeURIComponent(mac)}">${escapeHtml(mac)}</a></td>
    <td>${escapeHtml(d.name || "—")}</td>
    <td>${escapeHtml(d.vendor || "—")}</td>
    <td>${escapeHtml(type || "—")}</td>
    <td>${ssids}</td>
    <td>${escapeHtml(d.packets || 0)}</td>
    <td>${signal}</td>
    <td>${escapeHtml(d.clients || "—")}</td>
    <td>${tags}</td>
    <td><button type="button" class="btn btn-secondary btn-small btn-set-friendly" data-mac="${escapeHtml(mac)}" data-friendly="0">Mark friendly</button></td>
  </tr>`;
}

(function setupLivePacketAndReportRefresh() {
  const packetTable = document.getElementById("packet-table");
  const packetTbody = document.getElementById("packet-tbody");
  const reportTable = document.getElementById("report-table");
  const reportTbody = document.getElementById("report-tbody");
  const onPackets = location.pathname === "/packets" || location.pathname === "/packets/";
  const onReports = location.pathname === "/reports" || location.pathname === "/reports/";
  if (!onPackets && !onReports && !document.getElementById("header-status")) return;

  let packetNewest = Number(packetTable?.dataset.newestId || 0);
  let reportNewest = Number(reportTable?.dataset.newestId || 0);
  let inflight = false;

  async function prependNewPackets(afterId) {
    if (!packetTable || !packetTbody) {
      location.reload();
      return 0;
    }
    const params = new URLSearchParams({
      after_id: String(afterId),
      limit: packetTable.dataset.pageSize || "100",
    });
    if (packetTable.dataset.q) params.set("q", packetTable.dataset.q);
    if (packetTable.dataset.clientId) params.set("client_id", packetTable.dataset.clientId);
    if (packetTable.dataset.tag) params.set("tag", packetTable.dataset.tag);
    const res = await fetch(`/api/packets?${params.toString()}`);
    const data = await res.json();
    const rows = data.packets || [];
    if (!rows.length) return 0;
    document.getElementById("packet-empty-row")?.remove();
    packetTbody.insertAdjacentHTML("afterbegin", rows.map(packetRowHtml).join(""));
    const offset = Number(packetTable.dataset.offset || 0) + rows.length;
    packetTable.dataset.offset = String(offset);
    return rows.length;
  }

  async function refreshReports() {
    if (!reportTable || !reportTbody) {
      location.reload();
      return;
    }
    const hours = reportTable.dataset.hours || "24";
    const res = await fetch(`/api/reports?hours=${encodeURIComponent(hours)}`);
    const data = await res.json();
    const rows = data.rows || [];
    const count = document.getElementById("report-count");
    if (count) {
      count.textContent = `${rows.length} device${rows.length === 1 ? "" : "s"}`;
    }
    if (!rows.length) {
      reportTbody.innerHTML = `<tr id="report-empty-row"><td colspan="12" class="summary-empty">No non-friendly devices with traffic in the last ${escapeHtml(hours)} hour${hours === "1" ? "" : "s"}.</td></tr>`;
      return;
    }
    reportTbody.innerHTML = rows.map(reportRowHtml).join("");
  }

  async function pollLive() {
    if (inflight || document.hidden) return;
    inflight = true;
    try {
      const res = await fetch("/api/status");
      if (!res.ok) return;
      const data = await res.json();
      applyHeaderStats(data.stats, data.interval);
      const latest = Number(data.stats?.latest_packet_id || 0);
      if (onPackets && packetTable && latest > packetNewest) {
        await prependNewPackets(packetNewest);
        packetNewest = latest;
        packetTable.dataset.newestId = String(latest);
      }
      if (onReports && reportTable && latest > reportNewest) {
        await refreshReports();
        reportNewest = latest;
        reportTable.dataset.newestId = String(latest);
      }
    } catch (_) {
      /* ignore polling errors */
    } finally {
      inflight = false;
    }
  }

  setInterval(pollLive, 4000);
  pollLive();
})();

(function setupDeviceMap() {
  const el = document.getElementById("device-map");
  const dataEl = document.getElementById("map-data");
  if (!el || !dataEl || typeof L === "undefined") return;
  let data;
  try {
    data = JSON.parse(dataEl.textContent || "{}");
  } catch (_) {
    return;
  }
  const center = data.center;
  if (!center) return;

  const map = L.map(el, { zoomControl: true, attributionControl: true });
  L.tileLayer("/tiles/{z}/{x}/{y}.png", {
    maxZoom: 19,
    attribution:
      '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener">OpenStreetMap</a> contributors',
  }).addTo(map);

  const ftToM = (ft) => ft * 0.3048;
  const rings = data.rings_ft || [50, 100, 200, 300, 500];
  rings.forEach((ft) => {
    const isCamera = ft === 300;
    L.circle([center.lat, center.lon], {
      radius: ftToM(ft),
      color: isCamera ? "#b45309" : "#4b5563",
      weight: isCamera ? 2 : 1,
      dashArray: isCamera ? "6 6" : "2 8",
      fill: false,
      opacity: isCamera ? 0.95 : 0.55,
    }).addTo(map).bindTooltip(`${ft} ft`, { sticky: true, opacity: 0.85 });
  });

  L.circleMarker([center.lat, center.lon], {
    radius: 8,
    color: "#111827",
    weight: 2,
    fillColor: "#f8fafc",
    fillOpacity: 1,
  })
    .addTo(map)
    .bindPopup(
      `<strong>Sensor</strong> ${escapeHtml(center.client_name || "")}<br>` +
        `<span class="map-popup-mac">${center.lat}, ${center.lon}</span><br>` +
        `<span class="map-popup-meta">${escapeHtml(center.captured_at || "")}</span>`
    );

  const bounds = [[center.lat, center.lon]];
  (data.devices || []).forEach((d) => {
    const color = d.friendly ? "#4caf82" : d.mobile ? "#e8d27a" : "#3d9eff";
    const title = d.name || d.device_type || d.mac;
    const marker = L.circleMarker([d.lat, d.lon], {
      radius: d.friendly ? 7 : 6,
      color,
      weight: 1.5,
      fillColor: color,
      fillOpacity: 0.85,
    }).addTo(map);
    const ssid = (d.ssids || []).slice(0, 3).map(ssidButton).join(" ");
    marker.bindPopup(
      `<strong>${escapeHtml(title)}</strong>` +
        (d.friendly ? ' <span class="badge badge-ok">friendly</span>' : "") +
        `<div class="map-popup-mac"><a href="/details?mac=${encodeURIComponent(d.mac)}">${escapeHtml(d.mac)}</a></div>` +
        `<div class="map-popup-meta">` +
        `${escapeHtml(d.device_type || "device")} · ${d.signal} dBm · ${d.band || ""}<br>` +
        `est. ${d.distance_ft} ft (${d.distance_m} m) from sensor<br>` +
        `${d.packets} packet${d.packets === 1 ? "" : "s"} · last ${escapeHtml(d.last_seen || "")}` +
        (ssid ? `<br>SSID ${ssid}` : "") +
        `</div>`
    );
    bounds.push([d.lat, d.lon]);
  });

  const cameraRing = [center.lat + 91.44 / 111320, center.lon];
  bounds.push(cameraRing);
  map.fitBounds(bounds, { padding: [28, 28], maxZoom: 18 });
  setTimeout(() => map.invalidateSize(), 200);
})();

(function setupWigleSsidLookup() {
  const dialog = document.getElementById("wigle-dialog");
  const title = document.getElementById("wigle-dialog-title");
  const body = document.getElementById("wigle-dialog-body");
  const closeBtn = document.getElementById("wigle-dialog-close");
  if (!dialog || !body) return;

  function closeDialog() {
    if (typeof dialog.close === "function") dialog.close();
    else dialog.removeAttribute("open");
  }

  closeBtn?.addEventListener("click", closeDialog);
  dialog.addEventListener("click", (ev) => {
    if (ev.target === dialog) closeDialog();
  });

  function renderLookup(ssid, data) {
    const rows = data.results || [];
    const scope = data.scope === "2 miles"
      ? "within 2 miles of the sensor"
      : data.scope === "10 miles"
        ? "within 10 miles of the sensor"
        : data.scope === "100 miles"
          ? "within 100 miles of the sensor"
          : escapeHtml(data.scope || "near the sensor");
    const cached = data.cached ? " · cached" : "";
    if (!rows.length) {
      body.innerHTML = `<p class="hint">No WiGLE networks named <strong>${escapeHtml(ssid)}</strong> within 100 miles of the sensor${cached}.</p>`;
      return;
    }
    body.innerHTML =
      `<p class="hint">${rows.length} result${rows.length === 1 ? "" : "s"} for <strong>${escapeHtml(ssid)}</strong> (${scope}${cached}). Map data from WiGLE, personal use only.</p>` +
      rows
        .map((r) => {
          const loc = [r.road, r.place, r.postalcode].filter(Boolean).join(", ") || "location unknown";
          const coords =
            r.trilat != null && r.trilong != null
              ? `${Number(r.trilat).toFixed(5)}, ${Number(r.trilong).toFixed(5)}`
              : "";
          const osm =
            coords
              ? ` · <a href="https://www.openstreetmap.org/?mlat=${encodeURIComponent(r.trilat)}&mlon=${encodeURIComponent(r.trilong)}#map=17/${encodeURIComponent(r.trilat)}/${encodeURIComponent(r.trilong)}" target="_blank" rel="noopener">OSM</a>`
              : "";
          return `<article class="wigle-result">
            <div><strong>${escapeHtml(r.ssid || ssid)}</strong> ${escapeHtml(r.encryption || "")}</div>
            <div class="wigle-netid">${escapeHtml(r.netid || "")}${r.channel != null && r.channel !== "" ? " · ch " + escapeHtml(r.channel) : ""}</div>
            <div class="hint">${escapeHtml(loc)}${coords ? " · " + escapeHtml(coords) : ""}${osm}</div>
            <div class="hint">first ${escapeHtml(r.firsttime || "—")} · last ${escapeHtml(r.lasttime || "—")}</div>
          </article>`;
        })
        .join("");
  }

  async function lookupSsid(ssid) {
    if (title) title.textContent = `WiGLE · ${ssid}`;
    body.innerHTML = `<p class="hint">Looking up <strong>${escapeHtml(ssid)}</strong> on WiGLE…</p>`;
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
    try {
      const res = await fetch(`/api/wigle/ssid?ssid=${encodeURIComponent(ssid)}`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const extra = data.settings_url
          ? ` <a href="${escapeHtml(data.settings_url)}">Open Settings</a>`
          : "";
        body.innerHTML = `<p class="status-line error">${escapeHtml(data.error || res.statusText)}</p><p class="hint">${extra}</p>`;
        return;
      }
      renderLookup(ssid, data);
      await refreshActivityLog();
    } catch (err) {
      body.innerHTML = `<p class="status-line error">${escapeHtml(err.message)}</p>`;
    }
  }

  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest(".ssid-link");
    if (!btn) return;
    ev.preventDefault();
    const ssid = (btn.dataset.ssid || "").trim();
    if (ssid) lookupSsid(ssid);
  });
})();

(function setupSettingsSections() {
  const sections = document.querySelectorAll("details.settings-fold[data-section]");
  if (!sections.length) return;

  const load = () => {
    try {
      const raw = localStorage.getItem(SETTINGS_SECTIONS_KEY);
      if (!raw) return {};
      const data = JSON.parse(raw);
      return data && typeof data === "object" ? data : {};
    } catch (_) {
      return {};
    }
  };

  const stored = load();
  sections.forEach((el) => {
    const id = el.dataset.section;
    if (id && Object.prototype.hasOwnProperty.call(stored, id)) {
      el.open = !!stored[id];
    }
    el.addEventListener("toggle", () => {
      const next = load();
      next[el.dataset.section] = el.open;
      try {
        localStorage.setItem(SETTINGS_SECTIONS_KEY, JSON.stringify(next));
      } catch (_) { /* ignore */ }
    });
  });
})();
