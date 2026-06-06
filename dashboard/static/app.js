const panels = document.querySelectorAll(".panel");
const navButtons = document.querySelectorAll(".nav button");

navButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const target = btn.dataset.panel;
    navButtons.forEach((b) => b.classList.toggle("active", b === btn));
    panels.forEach((p) => p.classList.toggle("active", p.id === `panel-${target}`));
  });
});

async function fetchJSON(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function badge(decision) {
  const cls = {
    ALLOW: "badge-allow",
    BLOCK: "badge-block",
    REQUIRE_APPROVAL: "badge-approval",
  }[decision] || "";
  return `<span class="badge ${cls}">${decision}</span>`;
}

function severityBadge(sev) {
  const cls = {
    critical: "badge-critical",
    high: "badge-high",
    low: "badge-low",
  }[sev] || "badge-low";
  return `<span class="badge ${cls}">${sev}</span>`;
}

function formatTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString("de-DE", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function truncate(str, len = 60) {
  if (!str) return "—";
  return str.length > len ? str.slice(0, len) + "…" : str;
}

async function loadStats() {
  const stats = await fetchJSON("/api/stats");
  document.getElementById("stat-total").textContent = stats.total;
  document.getElementById("stat-blocks").textContent = stats.blocks;
  document.getElementById("stat-allows").textContent = stats.allows;
  document.getElementById("stat-approvals").textContent = stats.approvals;

  const max = Math.max(stats.blocks, stats.allows, stats.approvals, 1);
  document.getElementById("bar-blocks").style.width = `${(stats.blocks / max) * 100}%`;
  document.getElementById("bar-allows").style.width = `${(stats.allows / max) * 100}%`;
  document.getElementById("bar-approvals").style.width = `${(stats.approvals / max) * 100}%`;
  document.getElementById("bar-blocks-val").textContent = stats.blocks;
  document.getElementById("bar-allows-val").textContent = stats.allows;
  document.getElementById("bar-approvals-val").textContent = stats.approvals;
}

async function loadEvents() {
  const decision = document.getElementById("filter-decision").value;
  const tool = document.getElementById("filter-tool").value;
  const params = new URLSearchParams({ limit: "100" });
  if (decision) params.set("decision", decision);
  if (tool) params.set("tool", tool);

  const events = await fetchJSON(`/api/events?${params}`);
  const tbody = document.getElementById("events-body");

  if (!events.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty">Keine Events — starte <code>python demo.py</code> oder teste im Evaluator.</td></tr>`;
    return;
  }

  tbody.innerHTML = events
    .map(
      (e) => `
    <tr>
      <td class="mono">${formatTime(e.timestamp)}</td>
      <td class="mono">${e.trace_id || "—"}</td>
      <td>${e.tool}</td>
      <td>${badge(e.decision)}</td>
      <td>${severityBadge(e.severity)}</td>
      <td class="mono">${e.policy_id || "—"}</td>
      <td title="${e.reason || ""}">${truncate(e.reason, 50)}</td>
    </tr>`
    )
    .join("");
}

async function loadPolicies() {
  const policies = await fetchJSON("/api/policies");
  const container = document.getElementById("policy-list");

  if (!policies.length) {
    container.innerHTML = `<div class="empty">Keine Policies geladen.</div>`;
    return;
  }

  container.innerHTML = policies
    .map(
      (p) => `
    <div class="policy-item">
      <div class="policy-id">${p.id}</div>
      <div class="policy-desc">${p.description || ""}</div>
      <div class="policy-meta">
        ${severityBadge(p.severity || "low")}
        <span class="badge badge-${p.action === "block" ? "block" : "approval"}">${p.action}</span>
        <span class="mono">tool: ${(p.when && p.when.tool) || "any"}</span>
      </div>
    </div>`
    )
    .join("");
}

async function evaluateAction() {
  const btn = document.getElementById("eval-btn");
  const resultBox = document.getElementById("eval-result");
  btn.disabled = true;

  let args = {};
  const argsRaw = document.getElementById("eval-args").value.trim();
  if (argsRaw) {
    try {
      args = JSON.parse(argsRaw);
    } catch {
      resultBox.classList.add("visible");
      resultBox.innerHTML = `<h4>Fehler</h4><pre>Args müssen gültiges JSON sein.</pre>`;
      btn.disabled = false;
      return;
    }
  }

  const payload = {
    tool: document.getElementById("eval-tool").value,
    args,
    source_context: document.getElementById("eval-context").value,
    action_type: document.getElementById("eval-type").value,
    raw_output: document.getElementById("eval-output").value,
  };

  try {
    const result = await fetchJSON("/api/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    resultBox.classList.add("visible");
    resultBox.innerHTML = `
      <h4>${badge(result.decision)} ${severityBadge(result.severity)}</h4>
      <pre>${JSON.stringify(result, null, 2)}</pre>`;

    await refresh();
  } catch (err) {
    resultBox.classList.add("visible");
    resultBox.innerHTML = `<h4>Fehler</h4><pre>${err.message}</pre>`;
  } finally {
    btn.disabled = false;
  }
}

async function refresh() {
  try {
    await Promise.all([loadStats(), loadEvents(), loadPolicies()]);
  } catch (err) {
    console.error("Refresh failed:", err);
  }
}

document.getElementById("filter-decision").addEventListener("change", loadEvents);
document.getElementById("filter-tool").addEventListener("change", loadEvents);
document.getElementById("refresh-btn").addEventListener("click", refresh);
document.getElementById("eval-btn").addEventListener("click", evaluateAction);

refresh();
setInterval(refresh, 10000);
