const ACTIVITY_LOG_HIDDEN_KEY = "sentinel-central-activity-log-hidden";

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

if (document.getElementById("activity-log")) {
  setInterval(refreshActivityLog, 4000);
}

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
    <td>${escapeHtml(p.client_name || "")}</td>
    <td><a href="/packets?q=${encodeURIComponent(mac)}">${escapeHtml(mac)}</a></td>
    <td><div class="friendly-cell">${friendlyCell}</div></td>
    <td>${escapeHtml(p.SSID || "—")}</td>
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
