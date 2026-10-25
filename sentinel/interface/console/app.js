


(function () {
  "use strict";


  var ROUTES = [
    "/v1/pilot/setup",
    "/v1/pilot/devices",
    "/v1/pilot/devices/",
    "/v1/pilot/discovery-script",
    "/console/demo.json",
    "/v1/dashboard",
    "/v1/incidents",
    "/v1/incidents/",
    "/v1/inventory/agents",
    "/v1/inventory/agents/",
    "/v1/inventory/reach",
    "/v1/agents/",
    "/v1/graph/sessions/",
    "/v1/graph/coverage",
    "/v1/analysis/mcp-estate",
    "/v1/analysis/blast-radius/",
    "/v1/estate/ai-bom",
    "/v1/estate/exposure",
    "/v1/estate/adoption",
    "/v1/policy/versions",
    "/v1/policy/versions/",
    "/v1/policy/validate",
    "/v1/policy/diff",
    "/v1/executions/binding/coverage",
    "/v1/executions/binding/diff",
    "/v1/executions/binding/",
    "/v1/transparency/root",
    "/v1/transparency/inclusion/",
    "/v1/transparency/consistency",
    "/v1/transparency/published",
    "/v1/protect/bypass-signals",
    "/v1/approvals/",
    "/v1/authorizations",
    "/v1/authorizations/",
    "/v1/executions/operations",
    "/v1/executions/operations/",
    "/v1/containments",
    "/v1/containments/",
    "/v1/orgs/current",
    "/v1/orgs/current/members",
    "/health/diagnostics",
  ];

  if (window.trustedTypes && trustedTypes.createPolicy) {
    try {
      trustedTypes.createPolicy("sentinel-console", {
        createHTML: function () {
          throw new Error("HTML assignment forbidden");
        },
        createScript: function () {
          throw new Error("script assignment forbidden");
        },
        createScriptURL: function (url) {
          if (typeof url === "string" && url.startsWith("/console/")) return url;
          throw new Error("script URL refused");
        },
      });
    } catch (_e) {

    }
  }

  var SVG_NS = "http://www.w3.org/2000/svg";

  var tokenInput = document.getElementById("token");
  var statusEl = document.getElementById("monitor-status");
  var bannerEl = document.getElementById("banner");
  var lastOk = 0;
  var pollTimer = null;
  var currentView = "pilot";
  var agentFilter = "";
  var bindingOnlyMismatched = false;

  var caps = { decide_approval: null, manage_containment: null, manage_policy: null, read_diagnostics: null };

  /* The read-only key the server may publish for a shared link, and whether
     this tab is using it. A demo visitor polls less often, because every
     visitor holds the same key. */
  var demo = null;
  var demoMode = false;

  var containments = [];

  var knownSessions = [];
  var signatures = {};
  var validatedPolicyText = null;



  function el(id) {
    return document.getElementById(id);
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function text(tag, value, className) {
    var node = document.createElement(tag);
    node.textContent = value == null ? "" : String(value);
    if (className) node.className = className;
    return node;
  }

  function box(tag, className, children) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    (children || []).forEach(function (child) {
      if (child) node.appendChild(child);
    });
    return node;
  }


  function show(value) {
    if (value == null) return "";
    if (typeof value === "object") {
      try {
        return JSON.stringify(value);
      } catch (_e) {
        return "(unserialisable)";
      }
    }
    return String(value);
  }

  function num(value) {
    var n = Number(value);
    return isFinite(n) ? n : 0;
  }

  function shortDigest(value) {
    var s = show(value);
    return s.length > 18 ? s.slice(0, 10) + "…" + s.slice(-6) : s;
  }

  function kv(parent, pairs) {
    clear(parent);
    if (!pairs.length) {
      parent.appendChild(text("p", "nothing recorded", "hint"));
      return;
    }
    var wrap = box("div", "kv");
    pairs.forEach(function (pair) {
      wrap.appendChild(text("span", pair[0]));
      var value = pair[1];
      if (value && value.nodeType) wrap.appendChild(box("span", "", [value]));
      else wrap.appendChild(text("span", show(value)));
    });
    parent.appendChild(wrap);
  }

  function pairsOf(object) {
    return Object.keys(object || {}).map(function (key) {
      return [key, object[key]];
    });
  }


  function pill(label, value, kind) {
    var node = box("span", "pill" + (kind ? " " + kind : ""));
    if (value != null) node.appendChild(text("b", value, "num"));
    node.appendChild(text("span", label));
    return node;
  }

  function stat(value, label, kind) {
    return box("div", "stat" + (kind ? " " + kind : ""), [text("b", value, "num"), text("span", label)]);
  }

  function dot(kind) {
    return box("span", "dot" + (kind ? " " + kind : ""));
  }


  function meter(parent, numerator, denominator, label, kind) {
    var fraction = denominator > 0 ? numerator / denominator : 0;
    var bar = box("div", "meter" + (kind ? " " + kind : ""));
    var fill = document.createElement("i");
    fill.style.width = Math.round(Math.min(1, Math.max(0, fraction)) * 100) + "%";
    bar.appendChild(fill);
    parent.appendChild(
      box("div", "meter-label", [
        text("span", label),
        text("span", numerator + " / " + denominator + " (" + (denominator > 0 ? Math.round(fraction * 1000) / 10 + "%" : "no denominator") + ")", "num"),
      ])
    );
    parent.appendChild(bar);
  }

  function table(parent, columns, rows, onRow) {
    clear(parent);
    if (!rows.length) {
      parent.appendChild(text("p", "nothing to list", "empty"));
      return;
    }
    var wrap = box("div", "tablewrap");
    var tbl = document.createElement("table");
    var head = document.createElement("tr");
    columns.forEach(function (col) {
      head.appendChild(text("th", col.label));
    });
    tbl.appendChild(box("thead", "", [head]));
    var body = document.createElement("tbody");
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      if (onRow) {
        tr.className = "clickable";
        tr.tabIndex = 0;
        tr.addEventListener("click", function () {
          onRow(row);
        });
        tr.addEventListener("keydown", function (event) {
          if (event.key === "Enter") onRow(row);
        });
      }
      columns.forEach(function (col) {
        var cell = document.createElement("td");
        var value = col.render ? col.render(row) : row[col.key];
        if (value && value.nodeType) cell.appendChild(value);
        else cell.textContent = show(value);
        if (col.className) cell.className = col.className;
        tr.appendChild(cell);
      });
      body.appendChild(tr);
    });
    tbl.appendChild(body);
    wrap.appendChild(tbl);
    parent.appendChild(wrap);
  }

  function chip(label, on, onClick) {
    var node = text("button", label, "chip" + (on ? " on" : ""));
    node.type = "button";
    node.addEventListener("click", onClick);
    return node;
  }

  function severityClass(value) {
    var n = Number(value);
    if (!isFinite(n) || n <= 0) return "";
    if (n >= 90) return "sev-critical";
    if (n >= 70) return "sev-high";
    if (n >= 40) return "sev-moderate";
    return "sev-low";
  }

  function severityKind(value) {
    var n = Number(value);
    if (!isFinite(n) || n <= 0) return "";
    if (n >= 90) return "crit";
    if (n >= 70) return "bad";
    if (n >= 40) return "warn";
    return "ok";
  }

  function wordKind(word) {
    var w = String(word || "").toLowerCase();
    if (w === "critical") return "crit";
    if (w === "high") return "bad";
    if (w === "moderate" || w === "medium") return "warn";
    if (w === "low") return "ok";
    return "";
  }

  function stateKind(state) {
    var s = String(state || "");
    if (s === "failed") return "bad";
    if (s === "awaiting_approval" || s === "completed_unattested" || s === "attestation_unavailable") return "warn";
    if (s === "attested" || s === "completed_attested" || s === "closed_no_action") return "ok";
    return "";
  }

  function setStatus(kind) {
    statusEl.textContent = kind;
    statusEl.setAttribute("data-status", kind);
  }


  function failed(node, reason, status) {
    clear(node);
    var code = Number(status);
    var lead = code >= 400 && code < 500 ? "refused" : "could not load";
    node.appendChild(text("p", lead + (status ? " (" + status + ")" : "") + ": " + reason, "fail"));
    if (!status) {

      node.firstChild.textContent = "could not load: " + reason;
    }
  }

  function banner(message) {
    bannerEl.hidden = !message;
    bannerEl.textContent = message || "";
  }

  function toast(kind, message) {
    var host = el("toasts");
    var node = text("div", message, "toast " + kind);
    host.appendChild(node);
    setTimeout(function () {
      if (node.parentNode) node.parentNode.removeChild(node);
    }, 7000);
  }


  function showResult(node, kind, title, pairs) {
    clear(node);
    var wrap = box("div", "result " + kind, [text("strong", title)]);
    if (pairs && pairs.length) {
      var inner = document.createElement("div");
      kv(inner, pairs);
      wrap.appendChild(inner);
    }
    node.appendChild(wrap);
  }

  function changed(key, signature) {
    if (signatures[key] === signature) return false;
    signatures[key] = signature;
    return true;
  }

  function ellipsis(value, max) {
    var s = value == null ? "" : String(value);
    return s.length > max ? s.slice(0, max - 1) + "…" : s;
  }



  function authHeaders() {
    return {
      Authorization: "Bearer " + tokenInput.value.trim(),
      Accept: "application/json",
    };
  }


  function describeFailure(res) {
    return res
      .text()
      .then(function (body) {
        var detail = "";
        var raw = null;
        try {
          var parsed = JSON.parse(body);
          raw = parsed && parsed.detail != null ? parsed.detail : null;
          detail = raw != null ? show(raw) : "";
        } catch (_e) {
          detail = String(body || "").split("\n")[0].slice(0, 300);
        }
        var err = new Error(detail || String(res.status));
        err.status = String(res.status);
        err.detail = raw;
        return err;
      })
      .catch(function () {
        var err = new Error(String(res.status));
        err.status = String(res.status);
        return err;
      });
  }

  function request(method, path, body) {
    var options = { method: method, headers: authHeaders() };
    if (body !== undefined) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    return fetch(path, options).then(function (res) {
      if (!res.ok) {
        return describeFailure(res).then(function (err) {
          throw err;
        });
      }
      lastOk = Date.now();
      if (res.status === 204) return {};
      return res.json();
    });
  }

  function api(path) {
    return request("GET", path);
  }

  function post(path, body) {
    return request("POST", path, body || {});
  }

  function del(path) {
    return request("DELETE", path);
  }

  function reasonFor(err) {
    return err.status === "403" ? "not permitted for this role" : err.message;
  }


  function panel(node, path, render, cap) {
    return api(path).then(
      function (data) {
        if (cap) markCap(cap, true);
        render(data);
      },
      function (err) {
        if (cap && err.status === "403") markCap(cap, false);
        failed(node, reasonFor(err), err.status);
      }
    );
  }

  function refreshMonitor() {
    if (document.hidden && lastOk) {
      setStatus("PAUSED");
      return;
    }
    var age = Date.now() - lastOk;
    if (!lastOk) setStatus("DISCONNECTED");
    else if (age > 30000) setStatus("STALE");
    else setStatus("LIVE");
  }



  var GATES = [
    { cap: "decide_approval", gate: "approval-gate", forms: ["decide-form", "approvals"] },
    { cap: "manage_containment", gate: "containment-gate", forms: ["contain-form", "release-form", "containments"] },
    { cap: "manage_policy", gate: "policy-gate", forms: ["activate-form", "diff-form", "sim-form", "policy-validate", "policy-deploy", "activate-confirm"] },
  ];

  function markCap(cap, held) {
    if (caps[cap] === held) return;
    caps[cap] = held;
    renderCaps();
    applyGates();
  }

  function renderCaps() {
    var host = el("caps");
    clear(host);
    Object.keys(caps).forEach(function (cap) {
      var held = caps[cap];
      var kind = held === null ? "unknown" : held ? "ok" : "bad";
      var node = pill((held === false ? "✕ " : held ? "✓ " : "? ") + cap.replace(/_/g, " "), null, kind);
      node.title = held === null ? "not yet observed: no request needing it has been made" : held ? "the server accepted a request needing this capability" : "the server answered 403 to a request needing this capability";
      host.appendChild(node);
    });
  }

  function setDisabled(root, disabled) {
    if (!root) return;
    if (root.tagName === "BUTTON" || root.tagName === "INPUT" || root.tagName === "SELECT" || root.tagName === "TEXTAREA") {
      root.disabled = disabled;
    }
    Array.prototype.forEach.call(root.querySelectorAll("button, input, select, textarea"), function (node) {
      node.disabled = disabled;
    });
  }

  function applyGates() {
    GATES.forEach(function (gate) {
      var refused = caps[gate.cap] === false;
      var host = el(gate.gate);
      host.hidden = !refused;
      host.textContent = refused
        ? "This token's role lacks " + gate.cap + ": the server answered 403. Controls are disabled for this session; reconnect with a token whose role holds it."
        : "";
      gate.forms.forEach(function (id) {
        setDisabled(el(id), refused);
      });
    });
    if (caps.manage_policy !== false) el("policy-deploy").disabled = validatedPolicyText !== el("policy-editor").value;
  }



  function openDrawer(title) {
    var drawer = el("drawer");
    drawer.hidden = false;
    el("drawer-title").textContent = title;
    var body = el("drawer-body");
    clear(body);
    return body;
  }

  function section(title, children) {
    var node = box("section", "", [text("h3", title)]);
    (children || []).forEach(function (child) {
      if (child) node.appendChild(child);
    });
    return node;
  }



  function incidentRows(parent, rows) {
    table(
      parent,
      [
        { label: "incident", key: "incident_id", className: "mono" },
        {
          label: "state",
          render: function (row) {
            return pill(show(row.state), null, stateKind(row.state));
          },
        },
        {
          label: "severity",
          render: function (row) {
            return pill(show(row.priority || ""), show(row.severity), severityKind(row.severity));
          },
        },
        { label: "trust", key: "trust_level" },
        { label: "attestation", key: "attestation_outcome" },
        { label: "updated", key: "updated_at", className: "mono" },
      ],
      rows,
      function (row) {
        openIncident(row.incident_id);
      }
    );
  }

  function openIncident(id) {
    if (!id) return;
    var body = openDrawer("incident " + id);
    var summary = section("Summary");
    var timeline = section("Timeline");
    var report = section("Report");
    body.appendChild(summary);
    body.appendChild(timeline);
    body.appendChild(report);
    var summaryHost = box("div");
    summary.appendChild(summaryHost);
    var timelineHost = box("ul", "rows");
    timeline.appendChild(timelineHost);
    var reportHost = box("div");
    report.appendChild(reportHost);

    api("/v1/incidents/" + encodeURIComponent(id)).then(
      function (inc) {
        kv(summaryHost, [
          ["state", pill(show(inc.state), null, stateKind(inc.state))],
          ["severity", pill(show(inc.priority || ""), show(inc.severity), severityKind(inc.severity))],
          ["trust_level", inc.trust_level],
          ["attestation", inc.attestation_outcome || "unavailable / not yet"],
          ["attestation_detail", inc.attestation_detail],
          ["detector_version", inc.detector_version],
          ["is_terminal", inc.is_terminal],
          ["is_attested", inc.is_attested],
          ["version", inc.version],
          ["updated_at", inc.updated_at],
        ]);
      },
      function (err) {
        failed(summaryHost, err.message === "404" ? "no such incident" : reasonFor(err), err.status);
      }
    );
    api("/v1/incidents/" + encodeURIComponent(id) + "/history").then(
      function (hist) {
        var events = Array.isArray(hist.history) ? hist.history : [];
        clear(timelineHost);
        events.forEach(function (ev) {
          var li = box("li", stateKind(ev.to), [
            text("span", show(ev.seq), "num"),
            text("span", show(ev.from) + " → " + show(ev.to), "mono"),
            text("span", show(ev.actor), "hint"),
            text("span", show(ev.at), "mono"),
          ]);
          timelineHost.appendChild(li);
        });
        if (!events.length) timelineHost.appendChild(text("li", "no transitions recorded", "empty"));
      },
      function (err) {
        failed(timelineHost, reasonFor(err), err.status);
      }
    );
    api("/v1/incidents/" + encodeURIComponent(id) + "/report").then(
      function (data) {
        clear(reportHost);
        if (data.error) {
          reportHost.appendChild(text("p", data.error, "hint"));
          return;
        }
        reportHost.appendChild(text("pre", data.report, "report"));
      },
      function (err) {
        failed(reportHost, reasonFor(err), err.status);
      }
    );
  }



  function loadOverview() {
    var attention = { approvals: null, requests: null, unknown: null, revoked: null, unpinned: null, bypass: null };

    var dashboard = panel(el("incident-states"), "/v1/dashboard", function (data) {
      var states = data.incidents_by_state || {};
      var host = el("incident-states");
      clear(host);
      var total = 0;
      Object.keys(states).forEach(function (state) {
        total += num(states[state]);
      });
      Object.keys(states)
        .sort()
        .forEach(function (state) {
          host.appendChild(pill(state, states[state], stateKind(state)));
        });
      host.appendChild(pill("total incidents", total, "muted"));
      if (!Object.keys(states).length) host.appendChild(text("span", "no incidents recorded", "empty"));

      var att = data.attestation || {};
      var attHost = el("attestation");
      clear(attHost);
      attHost.appendChild(stat(num(att.anchored), "anchored", "ok"));
      attHost.appendChild(stat(num(att.completed_unattested), "completed unattested", num(att.completed_unattested) ? "warn" : ""));
      attHost.appendChild(stat(num(att.awaiting_attestation_retry), "awaiting retry", num(att.awaiting_attestation_retry) ? "warn" : ""));
      attHost.appendChild(text("p", "of " + total + " incidents. Unattested is never presented as attested.", "hint"));

      var dead = el("dead-letters");
      clear(dead);
      dead.appendChild(stat(num(data.dead_letters), "dead-lettered outbox records", num(data.dead_letters) ? "bad" : "ok"));
      dead.appendChild(text("p", "a countable hole in delivery, not a silent one", "hint"));
    });

    var coverage = panel(el("coverage"), "/v1/graph/coverage", function (data) {
      var host = el("coverage");
      clear(host);
      var linked = num(data.linked_nodes);
      var total = num(data.total_nodes);
      var fraction = total ? linked / total : 0;
      meter(host, linked, total, "events placed in a causal chain", fraction >= 0.9 ? "ok" : fraction >= 0.5 ? "warn" : "bad");
      host.appendChild(
        box("div", "pills", [
          pill("sessions", data.sessions, "muted"),
          pill("unlinked events", data.unlinked_nodes, num(data.unlinked_nodes) ? "warn" : "ok"),
        ])
      );
      host.appendChild(text("p", show(data.note), "hint"));
    });

    var bypass = api("/v1/protect/bypass-signals").then(
      function (data) {
        markCap("read_diagnostics", true);
        var host = el("bypass-count");
        clear(host);
        var signals = Array.isArray(data.signals) ? data.signals : [];
        attention.bypass = signals;
        host.appendChild(stat(signals.length, "enrolled agents silent past " + show(data.idle_threshold_seconds) + "s", signals.length ? "warn" : "ok"));
        host.appendChild(text("p", show(data.caveat), "hint"));
      },
      function (err) {
        if (err.status === "403") markCap("read_diagnostics", false);
        failed(el("bypass-count"), reasonFor(err), err.status);
      }
    );

    var agents = api("/v1/inventory/agents").then(
      function (data) {
        attention.revoked = {
          rows: (data.agents || []).filter(function (row) {
            return row.classification === "revoked_but_active";
          }),
          total: num(data.total),
          needs: num(data.needs_attention),
        };
      },
      function () {
        attention.revoked = null;
      }
    );

    var incidents = panel(el("incidents"), "/v1/incidents?limit=50", function (data) {
      var rows = Array.isArray(data.incidents) ? data.incidents : [];
      attention.approvals = {
        rows: rows.filter(function (row) {
          return row.state === "awaiting_approval";
        }),
        total: rows.length,
        more: Boolean(data.next_cursor),
      };
      incidentRows(el("incidents"), rows.slice(0, 15));
    });

    var bom = api("/v1/estate/ai-bom").then(
      function (data) {
        var servers = (data.components || []).filter(function (row) {
          return String(row.kind) === "mcp_server";
        });
        attention.unpinned = {
          rows: servers.filter(function (row) {
            return !row.is_pinned;
          }),
          total: servers.length,
          completeness: data.completeness,
        };
      },
      function () {
        attention.unpinned = null;
      }
    );

    // The OTHER approval queue. An agent asking to act is not an incident, so it
    // never appears in /v1/incidents; without this row an analyst watching the
    // overview would not learn that a change is waiting on them.
    var requests = api("/v1/authorizations").then(
      function (data) {
        attention.requests = { count: (data.authorizations || []).length, quorum: data.approval_quorum };
      },
      function () {
        attention.requests = null;
      }
    );
    var unknown = api("/v1/executions/operations?state=unknown_after_effect&limit=50").then(
      function (data) {
        attention.unknown = { count: (data.operations || []).length };
      },
      function () {
        attention.unknown = null;
      }
    );

    return Promise.all([dashboard, coverage, bypass, agents, incidents, bom, requests, unknown]).then(function () {
      renderAttention(attention);
    });
  }

  function attentionRow(kind, count, label, denominator, view) {
    var li = box("li", (count ? kind : "ok") + " clickable", [
      dot(count ? kind : "ok"),
      text("b", count, "num"),
      text("span", label),
      text("span", denominator, "hint"),
    ]);
    li.tabIndex = 0;
    li.addEventListener("click", function () {
      showView(view);
    });
    li.addEventListener("keydown", function (event) {
      if (event.key === "Enter") showView(view);
    });
    return li;
  }

  function renderAttention(a) {
    var host = el("attention");
    clear(host);
    if (a.approvals) {
      host.appendChild(
        attentionRow("warn", a.approvals.rows.length, "incidents awaiting approval", "of " + a.approvals.total + " incidents on the first page of /v1/incidents" + (a.approvals.more ? " (more pages exist)" : ""), "approvals")
      );
    } else host.appendChild(box("li", "bad", [dot("bad"), text("span", "approvals: /v1/incidents could not be read", "fail")]));
    if (a.requests) {
      host.appendChild(attentionRow("warn", a.requests.count, "agent requests awaiting a decision", "changes an agent asked to make and policy will not allow without a human (/v1/authorizations); " + show(a.requests.quorum) + " approver(s) required", "requests"));
    } else host.appendChild(box("li", "bad", [dot("bad"), text("span", "agent requests: /v1/authorizations could not be read", "fail")]));
    if (a.unknown) {
      host.appendChild(attentionRow("crit", a.unknown.count, "executions with an unknown outcome", "the effect may have happened and automatic reconciliation has not settled it (/v1/executions/operations)", "requests"));
    }

    var active = containments.filter(function (c) {
      return !c.released;
    }).length;
    host.appendChild(attentionRow("warn", active, "containments activated from this tab", "no route lists a tenant's containments; this counts only what this tab did", "containment"));

    if (a.revoked) {
      host.appendChild(attentionRow("crit", a.revoked.rows.length, "revoked-but-active agents", "of " + a.revoked.total + " observed agents; " + a.revoked.needs + " need attention (/v1/inventory/agents)", "agents"));
    } else host.appendChild(box("li", "bad", [dot("bad"), text("span", "agents: /v1/inventory/agents could not be read", "fail")]));

    if (a.unpinned) {
      host.appendChild(attentionRow("warn", a.unpinned.rows.length, "unpinned MCP servers", "of " + a.unpinned.total + " mcp_server components in the AI-BOM (completeness: " + show(a.unpinned.completeness) + ")", "estate"));
    } else host.appendChild(box("li", "bad", [dot("bad"), text("span", "MCP servers: /v1/estate/ai-bom could not be read", "fail")]));

    if (a.bypass) {
      host.appendChild(attentionRow("warn", a.bypass.length, "possible bypass signals", "enrolled agents with no observed events inside the idle window (/v1/protect/bypass-signals)", "governance"));
    } else host.appendChild(box("li", "", [dot(""), text("span", "bypass signals: not readable by this role (read_diagnostics)", "hint")]));
  }




  function parseReport(markdown) {
    var lines = String(markdown || "").split("\n");
    var out = { digest: "", findings: [], proposals: [], description: "" };
    var sectionName = "";
    lines.forEach(function (line) {
      if (line.indexOf("## ") === 0) {
        sectionName = line.slice(3).trim().toLowerCase();
        return;
      }
      var digest = /^- \*\*Evidence digest:\*\* `([^`]+)`/.exec(line);
      if (digest) out.digest = digest[1];
      if (sectionName.indexOf("deterministic") === 0 && line.indexOf("- ") === 0) {
        out.findings.push(line.slice(2).replace(/`/g, ""));
      }
      if (sectionName.indexOf("description") === 0 && line.trim()) out.description += line.trim() + " ";
      if (sectionName.indexOf("proposed actions") === 0) {
        var m = /^- `([^`]+)` \S+ \*\*([^*]+)\*\* on `([^`]*)` \((\w+)\)/.exec(line);
        if (m) out.proposals.push({ id: m[1], action: m[2], target: m[3], state: m[4] });
      }
    });
    return out;
  }

  function decisionControls(approvalId, resultHost) {
    var reason = document.createElement("input");
    reason.type = "text";
    reason.placeholder = "reason (required)";
    reason.required = true;
    var approve = text("button", "Approve", "primary small");
    approve.type = "button";
    var reject = text("button", "Reject", "danger small");
    reject.type = "button";
    function submit(decision) {
      if (!reason.value.trim()) {
        reason.focus();
        toast("warn", "a reason is required for every decision");
        return;
      }
      decide(approvalId, decision, reason.value.trim(), resultHost);
    }
    approve.addEventListener("click", function () {
      submit("approve");
    });
    reject.addEventListener("click", function () {
      submit("reject");
    });
    var row = box("div", "row", [reason, approve, reject]);
    if (caps.decide_approval === false) setDisabled(row, true);
    return row;
  }

  function decide(approvalId, decision, reason, resultHost) {
    return post("/v1/approvals/" + encodeURIComponent(approvalId), { decision: decision, reason: reason }).then(
      function (data) {
        markCap("decide_approval", true);
        var receipt = data.receipt || {};
        showResult(resultHost, "ok", "server accepted: " + show(data.outcome), [
          ["approval_id", data.approval_id],
          ["action", data.action],
          ["executed", data.executed === true ? "yes" : "no"],
          ["receipt id", receipt.receipt_id || receipt.id || receipt.reference || (Object.keys(receipt).length ? show(receipt) : "none returned")],
        ]);
        toast("ok", decision + " " + approvalId + ": " + show(data.outcome) + (data.executed ? ", executed" : ", not executed"));
        signatures.approvals = null;
      },
      function (err) {
        if (err.status === "403") markCap("decide_approval", false);
        var detail = err.detail && typeof err.detail === "object" ? err.detail : null;
        showResult(
          resultHost,
          "bad",
          (err.status === "409" ? "refused" : "failed") + " (" + (err.status || "network") + ")",
          detail ? pairsOf(detail) : [["detail", reasonFor(err)]]
        );
        toast("bad", decision + " " + approvalId + ": " + (detail && detail.outcome ? show(detail.outcome) : reasonFor(err)));
      }
    );
  }

  function timeLeft(seconds) {
    if (!seconds) return "expired";
    if (seconds < 90) return seconds + "s left";
    return Math.round(seconds / 60) + " min left";
  }

  function decideRequest(row, decision, reasonInput, resultHost) {
    var reason = reasonInput.value.trim();
    if (!reason) {
      toast("bad", "a reason is required; it is written to the audit trail");
      return;
    }
    post("/v1/authorizations/" + encodeURIComponent(row.authorization_id) + "/decide", { decision: decision, reason: reason }).then(
      function (data) {
        var remaining = data.approvals ? data.approvals.remaining : 0;
        toast("ok", data.outcome === "approval_recorded" ? "approval recorded; " + remaining + " more approver(s) needed" : "request " + data.outcome);
        signatures.requests = null;
        loadRequests();
      },
      function (err) {
        clear(resultHost);
        resultHost.appendChild(text("p", "not decided: " + reasonFor(err), "fail"));
      }
    );
  }

  function renderRequest(host, row) {
    var change = row.change || {};
    var impact = change.impact || {};
    var card = box("div", "card");
    card.appendChild(
      box("h4", "", [
        text("span", change.headline || row.action + " on " + row.resource),
        pill("impact " + show(impact.tier || "unclassified"), null, severityKind(impact.tier === "critical" || impact.tier === "high" ? "high" : "low")),
        pill(timeLeft(row.expires_in_seconds), null, row.expires_in_seconds < 60 ? "bad" : "muted"),
        row.policy_current ? null : pill("policy changed since evaluation", null, "bad"),
      ])
    );
    var facts = box("div");
    card.appendChild(facts);
    var why = row.why || {};
    var approvals = row.approvals || {};
    kv(facts, [
      ["agent", row.agent],
      ["requested by", row.requester],
      ["tool", row.tool],
      ["resource", row.resource],
      ["approved target version", change.target_precondition ? show(change.target_precondition.uid || "") + " @ " + show(change.target_precondition.resourceVersion || "") : ""],
      ["why approval is needed", show(why.reason) + " (" + (why.matched_rules || []).join(", ") + ")"],
      ["approvals", show(approvals.received) + " of " + show(approvals.required) + ((approvals.approvers || []).length ? " by " + approvals.approvers.join(", ") : "")],
      ["parameter digest", box("span", "mono", [text("span", row.approved_parameter_digest)])],
    ]);
    var fieldsHost = box("div");
    card.appendChild(fieldsHost);
    table(
      fieldsHost,
      ["field", "type", "value"],
      (change.fields || []).map(function (field) {
        return [field.path, field.type, field.value];
      })
    );
    if (change.fields_truncated) card.appendChild(text("p", change.fields_truncated + " more fields are not shown; the digest covers all of them.", "hint"));
    card.appendChild(text("p", show(change.redacted || 0) + " value(s) redacted. What executes is refused unless it matches the digest exactly.", "hint"));
    var reasonInput = document.createElement("input");
    reasonInput.type = "text";
    reasonInput.placeholder = "reason (required, audited)";
    var resultHost = box("div");
    var approve = text("button", "Approve", "primary");
    approve.type = "button";
    approve.disabled = !row.policy_current || row.expired;
    approve.addEventListener("click", function () {
      decideRequest(row, "approve", reasonInput, resultHost);
    });
    var reject = text("button", "Reject", "danger");
    reject.type = "button";
    reject.addEventListener("click", function () {
      decideRequest(row, "reject", reasonInput, resultHost);
    });
    if (caps.decide_approval === false) {
      /* A key that cannot decide is shown the card, not an invitation to a 403. */
      reasonInput.disabled = true;
      approve.disabled = true;
      reject.disabled = true;
      reasonInput.placeholder = demoMode ? "read-only demo: decisions are disabled" : "this token's role cannot decide";
    }
    card.appendChild(box("div", "row", [reasonInput, approve, reject]));
    card.appendChild(resultHost);
    host.appendChild(card);
  }

  function loadUnknownOperations() {
    var host = el("unknown-operations");
    return api("/v1/executions/operations?state=unknown_after_effect&limit=50").then(
      function (data) {
        clear(host);
        var rows = data.operations || [];
        if (!rows.length) {
          host.appendChild(text("p", "no operation has an unknown outcome. Automatic reconciliation asks the target first; only what it cannot settle appears here.", "empty"));
          return;
        }
        table(
          host,
          ["operation", "agent", "tool", "resource", "started", "automatic attempts", "last evidence"],
          rows.map(function (op) {
            var attrs = op.attributes || {};
            return [op.operation_id, op.agent_identity, op.tool_identity, op.target_resource, op.started_at, show(attrs.reconcile_attempts || 0), show(attrs.reconcile_last_note || op.error)];
          })
        );
      },
      function (err) {
        failed(host, reasonFor(err), err.status);
      }
    );
  }

  function loadRequests() {
    var host = el("requests");
    loadUnknownOperations();
    return api("/v1/authorizations").then(
      function (data) {
        var rows = data.authorizations || [];
        var signature = rows
          .map(function (row) {
            return row.authorization_id + "@" + (row.approvals || {}).received + "@" + Math.floor((row.expires_in_seconds || 0) / 30);
          })
          .join(",");
        if (!changed("requests", signature)) return;
        clear(host);
        el("requests-rules").textContent =
          "approvers required: " + show(data.approval_quorum) + "; requester may approve own request: " + (data.separation_of_duties ? "no" : "yes");
        if (!rows.length) {
          host.appendChild(text("p", "no agent request is awaiting a decision. A request appears here when policy answers require_approval for an action an agent asked to take.", "empty"));
          return;
        }
        rows.forEach(function (row) {
          renderRequest(host, row);
        });
      },
      function (err) {
        signatures.requests = null;
        failed(host, reasonFor(err), err.status);
      }
    );
  }

  function loadApprovals() {
    var host = el("approvals");
    return api("/v1/incidents?limit=50").then(
      function (data) {
        var rows = (data.incidents || []).filter(function (row) {
          return row.state === "awaiting_approval";
        });
        var signature = rows
          .map(function (row) {
            return row.incident_id + "@" + row.version;
          })
          .join(",");
        if (!changed("approvals", signature)) return;
        clear(host);
        if (!rows.length) {
          host.appendChild(
            text("p", "no incident is awaiting approval (" + (data.incidents || []).length + " incidents on the first page of /v1/incidents). An approval is proposed only for incident types the planner maps to a catalogue action; an incident with none proposes nothing.", "empty")
          );
          return;
        }
        rows.forEach(function (row) {
          var card = box("div", "card");
          var head = box("h4", "", [
            text("span", row.incident_id, "mono"),
            pill(show(row.priority || ""), show(row.severity), severityKind(row.severity)),
            pill("trust " + show(row.trust_level), null, "muted"),
          ]);
          var open = text("button", "open incident", "link");
          open.type = "button";
          open.addEventListener("click", function () {
            openIncident(row.incident_id);
          });
          head.appendChild(open);
          card.appendChild(head);
          var bodyHost = box("div");
          card.appendChild(bodyHost);
          host.appendChild(card);
          api("/v1/incidents/" + encodeURIComponent(row.incident_id) + "/report").then(
            function (reportData) {
              renderApprovalCard(bodyHost, row, reportData);
            },
            function (err) {
              failed(bodyHost, "report " + reasonFor(err), err.status);
              bodyHost.appendChild(text("p", "Without the report the approval id is unknown here; decide by id below once you have it from the incident record.", "hint"));
            }
          );
        });
      },
      function (err) {
        signatures.approvals = null;
        failed(host, reasonFor(err), err.status);
      }
    );
  }

  function renderApprovalCard(host, row, reportData) {
    clear(host);
    if (reportData.error) {
      host.appendChild(text("p", show(reportData.error), "hint"));
      return;
    }
    var parsed = parseReport(reportData.report);
    var evidence = document.createElement("div");
    kv(evidence, [
      ["evidence digest", parsed.digest ? box("span", "mono", [text("span", parsed.digest)]) : "not in report"],
      ["findings", parsed.findings.length ? parsed.findings.join("; ") : "no policy rule matched; raised by another path"],
      ["description", parsed.description.trim() || "—"],
      ["proposed actions", parsed.proposals.length],
    ]);
    host.appendChild(evidence);
    if (!parsed.proposals.length) {
      host.appendChild(
        text("p", "The report lists no proposed action: it is rendered before proposals are made, so the approval id is not served by any route this console can read. Decide by id below with the id from the incident's pending_approvals fact.", "hint")
      );
      return;
    }
    parsed.proposals.forEach(function (p) {
      var block = box("div", "card", [
        box("h4", "", [
          pill(p.state, null, p.state === "pending" ? "warn" : "muted"),
          text("strong", p.action),
          text("span", "on"),
          text("span", p.target, "mono"),
          text("span", p.id, "mono hint"),
        ]),
      ]);
      var result = box("div");
      block.appendChild(decisionControls(p.id, result));
      block.appendChild(result);
      host.appendChild(block);
    });
  }



  var NODE_W = 240;
  var NODE_H = 56;
  var GAP_Y = 22;
  var GAP_X = 56;

  function svgEl(name, attrs) {
    var node = document.createElementNS(SVG_NS, name);
    Object.keys(attrs || {}).forEach(function (key) {
      node.setAttribute(key, String(attrs[key]));
    });
    return node;
  }


  function layout(nodes) {
    var byId = {};
    nodes.forEach(function (n) {
      byId[n.event_id] = n;
    });
    var depth = {};
    function depthOf(node, guard) {
      if (depth[node.event_id] != null) return depth[node.event_id];
      var parent = node.parent_id ? byId[node.parent_id] : null;

      var value = !parent || guard > 64 ? 0 : depthOf(parent, guard + 1) + 1;
      depth[node.event_id] = value;
      return value;
    }
    var used = {};
    var placed = {};
    nodes.forEach(function (n) {
      var d = depthOf(n, 0);
      used[d] = used[d] || {};
      var parent = n.parent_id && placed[n.parent_id];
      var row = parent ? parent.row : 0;
      while (used[d][row]) row += 1;
      used[d][row] = true;
      placed[n.event_id] = {
        node: n,
        row: row,
        depth: d,
        orphan: Boolean(n.parent_id) && !byId[n.parent_id],
        x: GAP_X + d * (NODE_W + GAP_X),
        y: GAP_Y + row * (NODE_H + GAP_Y),
      };
    });
    return placed;
  }

  function renderHover(n) {
    var host = el("graph-hover");
    kv(host, [
      ["event", n.event_id],
      ["agent", n.agent_id],
      ["kind", n.kind],
      ["action", n.action],
      ["resource", n.resource],
      ["destination", n.destination],
      ["tool", n.tool],
      ["decision", n.decision],
      ["severity", n.severity],
      ["policy", n.policy],
      ["incident", n.incident_id],
      ["approval", n.approval_id],
      ["parent", n.parent_id || "(root)"],
      ["occurred", n.occurred_at],
    ]);
  }

  function drawGraph(nodes, roots) {
    var canvas = el("graph-canvas");
    clear(canvas);
    if (!nodes.length) {
      canvas.appendChild(text("span", "no steps in this session", "empty"));
      return;
    }
    var placed = layout(nodes);
    var maxX = 0;
    var maxY = 0;
    Object.keys(placed).forEach(function (id) {
      maxX = Math.max(maxX, placed[id].x + NODE_W);
      maxY = Math.max(maxY, placed[id].y + NODE_H);
    });
    var svg = svgEl("svg", {
      width: maxX + GAP_X,
      height: maxY + GAP_Y,
      viewBox: "0 0 " + (maxX + GAP_X) + " " + (maxY + GAP_Y),
      role: "img",
    });
    var defs = svgEl("defs", {});
    var marker = svgEl("marker", { id: "arrow", viewBox: "0 0 10 10", refX: "9", refY: "5", markerWidth: "7", markerHeight: "7", orient: "auto-start-reverse" });
    marker.appendChild(svgEl("path", { d: "M 0 0 L 10 5 L 0 10 z", class: "arrow" }));
    defs.appendChild(marker);
    svg.appendChild(defs);

    nodes.forEach(function (n) {
      if (!n.parent_id || !placed[n.parent_id]) return;
      var from = placed[n.parent_id];
      var to = placed[n.event_id];
      var x1 = from.x + NODE_W;
      var y1 = from.y + NODE_H / 2;
      var x2 = to.x;
      var y2 = to.y + NODE_H / 2;
      var mid = (x1 + x2) / 2;
      svg.appendChild(
        svgEl("path", {
          class: "edge",
          "marker-end": "url(#arrow)",
          d: "M " + x1 + " " + y1 + " C " + mid + " " + y1 + ", " + mid + " " + y2 + ", " + x2 + " " + y2,
        })
      );
    });

    var broken = Array.isArray(roots) && roots.length > 1;
    nodes.forEach(function (n) {
      var at = placed[n.event_id];
      var group = svgEl("g", { class: "node", tabindex: "0" });

      var decision = String(n.decision || "").toLowerCase();
      var boxClass = "node-box " + severityClass(n.severity);
      if (decision === "block" || decision === "fired") boxClass += " sev-high";
      if (decision === "require_approval" || decision === "warn") boxClass += " approval";
      if (at.orphan) boxClass += " orphan";
      group.appendChild(svgEl("rect", { class: boxClass, x: at.x, y: at.y, width: NODE_W, height: NODE_H, rx: 3 }));

      var title = svgEl("text", { class: "node-label", x: at.x + 10, y: at.y + 20 });
      title.textContent = ellipsis(n.action || n.kind || n.event_id, 26);
      group.appendChild(title);
      var subtitle = svgEl("text", { class: "node-sub", x: at.x + 10, y: at.y + 36 });
      subtitle.textContent = ellipsis([n.agent_id, n.resource, n.destination ? "→ " + n.destination : ""].filter(Boolean).join(" · "), 40);
      group.appendChild(subtitle);
      var foot = svgEl("text", { class: "node-sub", x: at.x + 10, y: at.y + 49 });
      foot.textContent = ellipsis(show(n.occurred_at), 40);
      group.appendChild(foot);

      if (decision || num(n.severity) > 0) {
        var badge = svgEl("text", { class: "node-badge " + (severityClass(n.severity) || "sev-low"), x: at.x + NODE_W - 8, y: at.y + 18, "text-anchor": "end" });
        badge.textContent = (decision ? decision.toUpperCase() : "") + (num(n.severity) > 0 ? " " + n.severity : "");
        group.appendChild(badge);
      }
      if (at.orphan) {
        var warn = svgEl("text", { class: "broken", x: at.x + NODE_W - 8, y: at.y + 49, "text-anchor": "end" });
        warn.textContent = "⚠ parent " + ellipsis(n.parent_id, 12) + " missing";
        group.appendChild(warn);
      } else if (broken && !n.parent_id) {
        var rootMark = svgEl("text", { class: "broken", x: at.x + NODE_W - 8, y: at.y + 49, "text-anchor": "end" });
        rootMark.textContent = "ROOT (chain broken)";
        group.appendChild(rootMark);
      }
      var tip = svgEl("title", {});
      tip.textContent = [n.event_id, n.agent_id, n.action, n.resource, n.destination, n.decision, n.severity].filter(Boolean).join(" · ");
      group.appendChild(tip);
      group.addEventListener("mouseenter", function () {
        renderHover(n);
      });
      group.addEventListener("focus", function () {
        renderHover(n);
      });
      group.addEventListener("click", function () {
        renderHover(n);
        if (n.incident_id) openIncident(n.incident_id);
      });
      svg.appendChild(group);
    });
    canvas.appendChild(svg);
  }

  function rememberSession(id) {
    if (knownSessions.indexOf(id) === -1) knownSessions.unshift(id);
    var list = el("session-list");
    clear(list);
    knownSessions.slice(0, 20).forEach(function (s) {
      var opt = document.createElement("option");
      opt.value = s;
      list.appendChild(opt);
    });
  }

  function loadSession() {
    var id = el("session-id").value.trim();
    var meta = el("graph-meta");
    if (!id) {
      clear(meta);
      meta.appendChild(text("p", "enter a session id; sessions traced in this tab are offered in the picker (no route lists sessions)", "hint"));
      return Promise.resolve();
    }
    return api("/v1/graph/sessions/" + encodeURIComponent(id)).then(
      function (data) {
        rememberSession(id);
        var nodes = Array.isArray(data.nodes) ? data.nodes : [];
        var roots = Array.isArray(data.roots) ? data.roots : [];
        var maxSev = nodes.reduce(function (m, n) {
          return Math.max(m, num(n.severity));
        }, 0);
        clear(meta);
        meta.appendChild(
          box("div", "pills", [
            pill("steps", data.node_count, "muted"),
            pill("agents", (data.agents || []).length, "muted"),
            pill(roots.length > 1 ? "roots — chain broken" : "root", roots.length, roots.length > 1 ? "bad" : "ok"),
            pill("peak severity", maxSev, severityKind(maxSev) || "muted"),
            pill("sequence findings", (data.sequence_findings || []).length, (data.sequence_findings || []).length ? "bad" : "ok"),
          ])
        );

        if (roots.length > 1) {
          banner("This session has " + roots.length + " roots: steps arrived without the parent that explains them, so the causal chain is incomplete.");
        } else banner("");

        drawGraph(nodes, roots);

        var findings = el("sequence-findings");
        clear(findings);
        (data.sequence_findings || []).forEach(function (match) {
          var li = box("li", wordKind(match.severity_band) || severityKind(match.severity) || "warn", [
            text("strong", show(match.rule)),
            pill(show(match.severity_band), show(match.severity), severityKind(match.severity)),
            text("span", show(match.rationale), "hint"),
            text("span", "matched: " + (match.matched || []).map(function (m) { return m.action; }).join(" → "), "mono hint"),
          ]);
          findings.appendChild(li);
        });
        if (!findings.firstChild) findings.appendChild(text("li", "no sequence rule matched", "empty"));

        table(
          el("graph-steps"),
          [
            { label: "at", key: "occurred_at", className: "mono" },
            { label: "agent", key: "agent_id" },
            { label: "action", key: "action" },
            { label: "resource / destination", render: function (n) { return [n.resource, n.destination].filter(Boolean).join(" → "); } },
            {
              label: "decision",
              render: function (n) {
                return pill(show(n.decision || "—"), num(n.severity) > 0 ? n.severity : null, severityKind(n.severity));
              },
            },
            { label: "incident", key: "incident_id", className: "mono" },
          ],
          nodes,
          function (n) {
            renderHover(n);
            if (n.incident_id) openIncident(n.incident_id);
          }
        );
      },
      function (err) {
        banner("");
        failed(meta, err.status === "404" ? "no such session has been observed" : reasonFor(err), err.status);
        clear(el("graph-canvas"));
        clear(el("sequence-findings"));
        clear(el("graph-steps"));
      }
    );
  }



  function loadBinding() {
    var coverage = panel(el("binding-coverage"), "/v1/executions/binding/coverage", function (data) {
      var host = el("binding-coverage");
      clear(host);
      var receipts = num(data.receipts);
      var comparable = num(data.comparable);
      meter(host, comparable, receipts, "receipts with an approved parameter digest (bound share)", receipts && comparable === receipts ? "ok" : receipts ? "warn" : "bad");
      host.appendChild(
        box("div", "pills", [
          pill("receipts", receipts, receipts ? "muted" : "warn"),
          pill("comparable", comparable, "muted"),
          pill("not comparable", data.not_comparable, num(data.not_comparable) ? "warn" : "ok"),
          pill(data.enforced ? "binding required" : "binding optional", null, data.enforced ? "ok" : "warn"),
        ])
      );
      host.appendChild(text("p", show(data.warning || data.blindness), "hint"));
    });

    var chips = el("binding-filter");
    clear(chips);
    chips.appendChild(
      chip("all receipts", !bindingOnlyMismatched, function () {
        bindingOnlyMismatched = false;
        loadBinding();
      })
    );
    chips.appendChild(
      chip("only mismatched", bindingOnlyMismatched, function () {
        bindingOnlyMismatched = true;
        loadBinding();
      })
    );

    var diff = panel(el("binding-diff"), "/v1/executions/binding/diff" + (bindingOnlyMismatched ? "?only_mismatched=true" : ""), function (data) {
      var host = el("binding-diff");
      clear(host);
      var cov = data.binding_coverage || {};
      host.appendChild(
        box("div", "pills", [
          pill("mismatched", data.mismatched, num(data.mismatched) ? "bad" : "ok"),
          pill("unverifiable", data.unverifiable, num(data.unverifiable) ? "warn" : "ok"),
          pill("of receipts", cov.receipts, "muted"),
        ])
      );
      var rows = Array.isArray(data.entries) ? data.entries : [];
      var tableHost = box("div");
      host.appendChild(tableHost);
      table(
        tableHost,
        [
          { label: "receipt", key: "receipt_id", className: "mono" },
          { label: "occurred", key: "occurred_at", className: "mono" },
          { label: "tool", key: "tool" },
          { label: "outcome", key: "outcome" },
          {
            label: "parameters",
            render: function (row) {
              if (row.parameters_matched === true) return pill("matched", null, "ok");
              if (row.parameters_matched === false) return pill("MISMATCH", null, "bad");
              return pill("unverifiable", null, "warn");
            },
          },
          { label: "approved digest", render: function (row) { return shortDigest(row.approved_parameter_digest); }, className: "mono" },
          { label: "executed digest", render: function (row) { return shortDigest(row.actual_parameter_digest); }, className: "mono" },
          { label: "differing keys", render: function (row) { return (row.differing_keys || []).join(", "); } },
          { label: "defects", render: function (row) { return (row.defects || []).join(", "); } },
        ],
        rows,
        function (row) {
          openReceipt(row.receipt_id);
        }
      );
      host.appendChild(text("p", show(data.disclosure), "hint"));
    });
    return Promise.all([coverage, diff]);
  }

  function openReceipt(receiptId) {
    var body = openDrawer("receipt " + receiptId);
    var host = box("div");
    body.appendChild(host);
    api("/v1/executions/binding/" + encodeURIComponent(receiptId)).then(
      function (data) {
        kv(host, [
          ["bound", pill(data.bound ? "bound" : "UNBOUND", null, data.bound ? "ok" : "bad")],
          ["parameters", data.parameters_matched === true ? pill("matched", null, "ok") : data.parameters_matched === false ? pill("MISMATCH", null, "bad") : pill("unverifiable", null, "warn")],
          ["authorization id", data.authorization_id],
          ["authorization digest", box("span", "mono", [text("span", data.authorization_digest)])],
          ["executed request digest", box("span", "mono", [text("span", data.executed_request_digest)])],
          ["approved parameter digest", box("span", "mono", [text("span", data.approved_parameter_digest)])],
          ["actual parameter digest", box("span", "mono", [text("span", data.actual_parameter_digest)])],
          ["differing keys", (data.differing_keys || []).join(", ") || "none"],
          ["bounded mutations", (data.bounded_mutations || []).join(", ") || "none"],
          ["defects", (data.defects || []).join(", ") || "none"],
          ["delegation", data.delegation_bound ? "bound: " + show(data.delegation_passport_digest) : "not delegation-bound"],
          ["outcome", data.outcome],
          ["execution identity", data.execution_identity],
          ["started", data.started_at],
          ["completed", data.completed_at],
          ["disclosure", data.disclosure],
          ["residual", data.residual],
        ]);
      },
      function (err) {
        failed(host, reasonFor(err), err.status);
      }
    );
  }



  function loadEstate() {
    var report = panel(el("estate-findings"), "/v1/analysis/mcp-estate", function (data) {
      var summary = el("estate-summary");
      clear(summary);
      var findings = Array.isArray(data.findings) ? data.findings : [];
      var byKind = {};
      findings.forEach(function (f) {
        byKind[f.kind] = (byKind[f.kind] || 0) + 1;
      });
      summary.appendChild(pill("enrolled servers", data.enrolled_count, "muted"));
      summary.appendChild(pill("observed servers", data.observed_count, "muted"));
      summary.appendChild(pill("tool collisions", byKind.cross_server_tool_collision || 0, byKind.cross_server_tool_collision ? "bad" : "ok"));
      summary.appendChild(pill("credential sprawl", byKind.credential_sprawl || 0, byKind.credential_sprawl ? "warn" : "ok"));
      summary.appendChild(pill("blocked still used", byKind.blocked_server_still_used || 0, byKind.blocked_server_still_used ? "crit" : "ok"));
      summary.appendChild(pill("shadow servers", byKind.shadow_mcp_server || 0, "unknown"));
      summary.appendChild(pill("unused enrolments", byKind.unused_enrolment || 0, "unknown"));
      el("estate-limits").textContent = show(data.observed_source) + " " + show(data.limits);

      var list = el("estate-findings");
      clear(list);
      findings.forEach(function (f) {
        list.appendChild(
          box("li", wordKind(f.severity) || "warn", [
            text("span", show(f.kind), "tag " + (severityClassFor(f.severity))),
            text("span", show(f.detail)),
            text("span", (f.subjects || []).join(", "), "mono hint"),
          ])
        );
      });
      if (!findings.length) list.appendChild(text("li", "no collision or credential-sprawl finding over " + show(data.enrolled_count) + " enrolled servers; shadow and unused findings cannot be produced by this build (see limits)", "empty"));
    });

    var servers = panel(el("estate-servers"), "/v1/estate/ai-bom", function (data) {
      var rows = (data.components || []).filter(function (row) {
        var kind = String(row.kind);
        return kind === "mcp_server" || kind === "tool";
      });
      var host = el("estate-servers");
      clear(host);
      var unpinned = rows.filter(function (row) {
        return !row.is_pinned;
      }).length;
      host.appendChild(
        box("div", "pills", [
          pill("servers and tools in AI-BOM", rows.length, "muted"),
          pill("unpinned", unpinned, unpinned ? "warn" : "ok"),
          pill("completeness " + show(data.completeness), null, data.completeness === "complete" ? "ok" : "warn"),
        ])
      );
      var drift = (data.findings || []).filter(function (f) {
        return rows.some(function (row) {
          return row.identifier === f.component;
        });
      });
      var tableHost = box("div");
      host.appendChild(tableHost);
      table(
        tableHost,
        [
          { label: "kind", key: "kind" },
          { label: "identifier", key: "identifier", className: "mono" },
          { label: "provenance", key: "provenance" },
          { label: "pinned", render: function (row) { return row.is_pinned ? pill("pinned", null, "ok") : pill("UNPINNED", null, "warn"); } },
          { label: "version / digest", render: function (row) { return [row.version, shortDigest(row.digest)].filter(Boolean).join(" "); }, className: "mono" },
          { label: "used by", render: function (row) { return (row.used_by || []).join(", "); } },
        ],
        rows
      );
      if (drift.length) {
        host.appendChild(text("h3", "drift and provenance findings"));
        var list = box("ul", "rows");
        drift.forEach(function (f) {
          list.appendChild(box("li", "warn", [text("span", show(f.kind), "tag"), text("span", show(f.component), "mono"), text("span", show(f.detail), "hint")]));
        });
        host.appendChild(list);
      }
    });
    return Promise.all([report, servers]);
  }

  function severityClassFor(word) {
    return "sev-" + String(word || "moderate").toLowerCase();
  }



  function renderContainments() {
    var host = el("containments");
    table(
      host,
      [
        { label: "containment", key: "containment_id", className: "mono" },
        { label: "scope", key: "scope" },
        { label: "selector", key: "selector", className: "mono" },
        { label: "reason", key: "reason" },
        { label: "expires", render: function (c) { return c.expires_at || "never"; }, className: "mono" },
        { label: "activated", key: "created_at", className: "mono" },
        {
          label: "state",
          render: function (c) {
            return c.released ? pill("released", null, "muted") : pill("ACTIVE", null, "bad");
          },
        },
        {
          label: "",
          render: function (c) {
            if (c.released) return "";
            var btn = text("button", "Release", "small");
            btn.type = "button";
            btn.addEventListener("click", function () {
              release(c.containment_id, el("release-result"));
            });
            if (caps.manage_containment === false) btn.disabled = true;
            return btn;
          },
        },
      ],
      containments
    );
    if (!containments.length) {
      clear(host);
      host.appendChild(text("p", "nothing activated from this tab yet", "empty"));
    }
  }

  function contain(event) {
    event.preventDefault();
    var scope = el("contain-scope").value;
    var selector = scope === "high_risk_agents" ? "" : el("contain-selector").value.trim();
    var reason = el("contain-reason").value.trim();
    var expires = el("contain-expires").value;
    if (!reason) {
      toast("warn", "a reason is required");
      el("contain-reason").focus();
      return;
    }
    if (scope !== "high_risk_agents" && !selector) {
      toast("warn", "a selector is required for scope " + scope);
      el("contain-selector").focus();
      return;
    }
    var body = { scope: scope, selector: selector, reason: reason, expiresAt: expires ? new Date(expires).toISOString() : "" };
    var result = el("contain-result");
    return post("/v1/containments", body).then(
      function (data) {
        markCap("manage_containment", true);
        containments.unshift({
          containment_id: data.containment_id,
          scope: data.scope,
          selector: data.selector,
          reason: reason,
          expires_at: data.expires_at,
          created_at: new Date().toISOString(),
          released: false,
        });
        renderContainments();
        showResult(result, "ok", "server accepted: " + show(data.outcome), pairsOf(data));
        toast("ok", "contained " + show(data.scope) + " " + show(data.selector) + " (" + show(data.containment_id) + ")");
        el("contain-selector").value = "";
        el("contain-reason").value = "";
      },
      function (err) {
        if (err.status === "403") markCap("manage_containment", false);
        var detail = err.detail && typeof err.detail === "object" ? err.detail : null;
        showResult(result, "bad", "refused (" + (err.status || "network") + ")", detail ? pairsOf(detail) : [["detail", reasonFor(err)]]);
        toast("bad", "containment refused: " + (detail && detail.detail ? show(detail.detail) : reasonFor(err)));
      }
    );
  }

  function release(id, resultHost) {
    return del("/v1/containments/" + encodeURIComponent(id)).then(
      function (data) {
        markCap("manage_containment", true);
        containments.forEach(function (c) {
          if (c.containment_id === id) c.released = true;
        });
        renderContainments();
        showResult(resultHost, "ok", "server accepted: " + show(data.outcome), pairsOf(data));
        toast("ok", "released " + id + ": " + show(data.outcome));
      },
      function (err) {
        if (err.status === "403") markCap("manage_containment", false);
        var detail = err.detail && typeof err.detail === "object" ? err.detail : null;
        showResult(resultHost, "bad", "refused (" + (err.status || "network") + ")", detail ? pairsOf(detail) : [["detail", reasonFor(err)]]);
        toast("bad", "release " + id + ": " + (detail && detail.outcome ? show(detail.outcome) : reasonFor(err)));
      }
    );
  }



  var SAMPLE_POLICY = {
    note: "describe the change",
    rules: [
      {
        name: "block-external-upload",
        effect: "block",
        actions: ["http_post"],
        destinations: ["*"],
        minSeverity: 0,
        description: "example: refuse outbound posts",
      },
    ],
  };

  function loadPolicyVersions() {
    return panel(
      el("policy-versions"),
      "/v1/policy/versions",
      function (data) {
        var rows = Array.isArray(data.versions) ? data.versions : [];
        var host = el("policy-versions");
        clear(host);
        host.appendChild(box("div", "pills", [pill("active version", data.active_version == null ? "none" : data.active_version, data.active_version == null ? "warn" : "ok"), pill("stored", rows.length, "muted")]));
        var tableHost = box("div");
        host.appendChild(tableHost);
        table(
          tableHost,
          [
            { label: "version", render: function (v) { return v.version === data.active_version ? pill("active", v.version, "ok") : text("span", v.version, "num"); } },
            { label: "rules", key: "rule_count", className: "num" },
            { label: "digest", render: function (v) { return shortDigest(v.digest); }, className: "mono" },
            { label: "created by", key: "created_by", className: "mono" },
            { label: "created", key: "created_at", className: "mono" },
            { label: "note", key: "note" },
          ],
          rows,
          function (v) {
            el("sim-version").value = v.version;
            el("activate-version").value = v.version;
            if (data.active_version != null && data.active_version !== v.version) {
              el("diff-base").value = data.active_version;
              el("diff-target").value = v.version;
            }
            toast("ok", "version " + v.version + " selected for diff, simulate and activate");
          }
        );
        if (!rows.length) host.appendChild(text("p", "no policy version stored; deploy one from the editor", "empty"));
      },
      "manage_policy"
    );
  }

  function loadPolicyDiff(event) {
    if (event) event.preventDefault();
    var base = el("diff-base").value.trim();
    var target = el("diff-target").value.trim();
    if (!base || !target) return Promise.resolve();
    return panel(el("diff-summary"), "/v1/policy/diff?base=" + encodeURIComponent(base) + "&target=" + encodeURIComponent(target), function (data) {
      var summary = el("diff-summary");
      clear(summary);
      summary.appendChild(
        box("div", "pills", [
          pill("newly allowed / added", (data.added || []).length, (data.added || []).length ? "warn" : "muted"),
          pill("removed", (data.removed || []).length, (data.removed || []).length ? "warn" : "muted"),
          pill("changed", (data.changed || []).length, (data.changed || []).length ? "warn" : "muted"),
          pill("v" + show(data.from_version) + " → v" + show(data.to_version), null, "muted"),
        ])
      );
      var list = el("diff-rules");
      clear(list);
      [["added", "warn"], ["changed", "warn"], ["removed", "ok"]].forEach(function (pair) {
        (data[pair[0]] || []).forEach(function (rule) {
          list.appendChild(box("li", pair[1], [text("span", pair[0], "tag"), text("span", show(rule), "mono")]));
        });
      });
      if (data.is_empty || !list.firstChild) list.appendChild(text("li", "the two versions are identical by rule name", "empty"));
    }, "manage_policy");
  }

  function loadSimulation(event) {
    if (event) event.preventDefault();
    var version = el("sim-version").value.trim();
    if (!version) return Promise.resolve();
    var path = "/v1/policy/versions/" + encodeURIComponent(version) + "/simulate?days=" + encodeURIComponent(el("sim-days").value.trim() || "7");
    return post(path, {}).then(
      function (data) {
        markCap("manage_policy", true);
        var summary = el("sim-summary");
        clear(summary);
        summary.appendChild(stat(num(data.events_evaluated), "events replayed over " + show(data.window_days) + " days"));
        summary.appendChild(stat(num(data.would_allow), "would allow", "ok"));
        summary.appendChild(stat(num(data.would_warn), "would warn", num(data.would_warn) ? "warn" : ""));
        summary.appendChild(stat(num(data.would_require_approval), "would require approval", num(data.would_require_approval) ? "warn" : ""));
        summary.appendChild(stat(num(data.would_block), "would block", num(data.would_block) ? "bad" : ""));
        summary.appendChild(stat(num(data.potential_false_positives), "potential false positives", num(data.potential_false_positives) ? "bad" : "ok"));
        var byRule = data.matches_by_rule || {};
        var rows = Object.keys(byRule).map(function (name) {
          return { rule: name, matches: byRule[name] };
        });
        var rulesHost = el("sim-rules");
        table(rulesHost, [{ label: "rule", key: "rule", className: "mono" }, { label: "matches", key: "matches", className: "num" }], rows);
        if (!rows.length) {
          clear(rulesHost);
          rulesHost.appendChild(text("p", "no rule matched any recorded event in this window", "empty"));
        }
        var affected = document.createElement("div");
        kv(affected, [
          ["affected agents", (data.affected_agents || []).join(", ") || "none"],
          ["affected workflows", (data.affected_workflows || []).join(", ") || "none"],
          ["is estimate", data.is_estimate ? "yes" : "no"],
        ]);
        rulesHost.appendChild(affected);
        el("sim-limits").textContent = show(data.estimate_caveat) + " A rule that matched nothing here has not been shown to be safe; this window contained nothing it applies to. Simulation activates nothing.";
      },
      function (err) {
        if (err.status === "403") markCap("manage_policy", false);
        failed(el("sim-summary"), reasonFor(err), err.status);
        clear(el("sim-rules"));
        el("sim-limits").textContent = "";
      }
    );
  }

  function askActivate(event) {
    event.preventDefault();
    var version = el("activate-version").value.trim();
    if (!version) return;
    var host = el("activate-confirm");
    clear(host);
    host.hidden = false;
    var confirm = text("button", "Confirm: activate version " + version, "danger");
    confirm.type = "button";
    var cancel = text("button", "Cancel", "");
    cancel.type = "button";
    cancel.addEventListener("click", function () {
      host.hidden = true;
      clear(host);
    });
    confirm.addEventListener("click", function () {
      host.hidden = true;
      clear(host);
      activate(version);
    });
    host.appendChild(box("div", "gate", [text("p", "Activation changes what the estate enforces from the next evaluation. Rolling back is activating the previous number.", "hint"), box("div", "row", [confirm, cancel])]));
  }

  function activate(version) {
    var result = el("activate-result");
    return post("/v1/policy/versions/" + encodeURIComponent(version) + "/activate", {}).then(
      function (data) {
        markCap("manage_policy", true);
        showResult(result, "ok", "activated", pairsOf(data));
        toast("ok", "policy version " + show(data.active_version) + " is now active");
        loadPolicyVersions();
      },
      function (err) {
        if (err.status === "403") markCap("manage_policy", false);
        showResult(result, "bad", "refused (" + (err.status || "network") + ")", [["detail", reasonFor(err)]]);
        toast("bad", "activate " + version + ": " + reasonFor(err));
      }
    );
  }

  function parseEditor() {
    try {
      return JSON.parse(el("policy-editor").value);
    } catch (e) {
      showResult(el("editor-result"), "bad", "not valid JSON", [["detail", e.message]]);
      return null;
    }
  }

  function validatePolicy() {
    var doc = parseEditor();
    if (!doc) return;
    var current = el("policy-editor").value;
    return post("/v1/policy/validate", doc).then(
      function (data) {
        markCap("manage_policy", true);
        validatedPolicyText = current;
        applyGates();
        showResult(el("editor-result"), "ok", "valid: " + show(data.rule_count) + " rule(s); deploy is now enabled for this exact text", pairsOf(data));
        toast("ok", "policy document valid (" + show(data.rule_count) + " rules)");
      },
      function (err) {
        if (err.status === "403") markCap("manage_policy", false);
        validatedPolicyText = null;
        applyGates();
        showResult(el("editor-result"), "bad", "refused (" + (err.status || "network") + ")", [["detail", reasonFor(err)]]);
        toast("bad", "validate: " + reasonFor(err));
      }
    );
  }

  function deployPolicy() {
    var doc = parseEditor();
    if (!doc) return;
    if (validatedPolicyText !== el("policy-editor").value) {
      toast("warn", "validate this exact text before deploying");
      return;
    }
    return post("/v1/policy/versions", doc).then(
      function (data) {
        markCap("manage_policy", true);
        showResult(el("editor-result"), "ok", "stored as version " + show(data.version) + " (not active)", pairsOf(data));
        toast("ok", "policy version " + show(data.version) + " stored; activate it separately");
        validatedPolicyText = null;
        applyGates();
        loadPolicyVersions();
      },
      function (err) {
        if (err.status === "403") markCap("manage_policy", false);
        showResult(el("editor-result"), "bad", "refused (" + (err.status || "network") + ")", [["detail", reasonFor(err)]]);
        toast("bad", "deploy: " + reasonFor(err));
      }
    );
  }



  function verifiability(data) {
    return [
      ["independently verifiable", pill(data.independently_verifiable ? "yes" : "NO", null, data.independently_verifiable ? "ok" : "warn")],
      ["reason", data.reason],
    ];
  }

  function proofList(hashes) {
    var list = box("ul", "proof");
    (hashes || []).forEach(function (h, index) {
      list.appendChild(text("li", index + ": " + show(h)));
    });
    if (!list.firstChild) list.appendChild(text("li", "(empty path)", "empty"));
    return list;
  }

  function loadTransparency() {
    var root = panel(el("tl-root"), "/v1/transparency/root", function (data) {
      kv(el("tl-root"), [["tree size", data.tree_size], ["root", box("span", "mono", [text("span", data.root)])]].concat(verifiability(data)));
    });
    var published = panel(el("tl-published"), "/v1/transparency/published", function (data) {
      var host = el("tl-published");
      clear(host);
      host.appendChild(
        box("div", "pills", [
          pill("independently verifiable", data.independently_verifiable_count, num(data.independently_verifiable_count) ? "ok" : "warn"),
          pill("of published roots", data.total_count, "muted"),
        ])
      );
      var tableHost = box("div");
      host.appendChild(tableHost);
      table(
        tableHost,
        [
          { label: "size", key: "tree_size", className: "num" },
          { label: "root", render: function (r) { return shortDigest(r.root_hash); }, className: "mono" },
          { label: "sink", key: "sink" },
          { label: "reference", key: "external_reference", className: "mono" },
          { label: "verifiable", render: function (r) { return r.is_independently_verifiable ? pill("yes", null, "ok") : pill("no", null, "warn"); } },
          { label: "published", key: "published_at", className: "mono" },
        ],
        Array.isArray(data.published) ? data.published : [],
        function (r) {
          el("consistency-old").value = r.tree_size;
        }
      );
      host.appendChild(text("p", show(data.limits), "hint"));
    });
    return Promise.all([root, published]);
  }

  function loadInclusion(event) {
    event.preventDefault();
    var index = el("inclusion-index").value.trim();
    if (index === "") return;
    return panel(el("tl-inclusion"), "/v1/transparency/inclusion/" + encodeURIComponent(index), function (data) {
      var proof = data.proof || {};
      var host = el("tl-inclusion");
      var pairs = [
        ["entry digest", box("span", "mono", [text("span", data.digest)])],
        ["root", box("span", "mono", [text("span", data.root)])],
        ["index / tree size", show(proof.index) + " / " + show(proof.tree_size)],
        ["path", proofList(proof.path)],
      ].concat(verifiability(data));
      kv(host, pairs);
    });
  }

  function loadConsistency(event) {
    event.preventDefault();
    var old = el("consistency-old").value.trim();
    if (!old) return;
    return panel(el("tl-consistency"), "/v1/transparency/consistency?old_size=" + encodeURIComponent(old), function (data) {
      var host = el("tl-consistency");
      var pairs = [["consistent", pill(data.consistent ? "yes" : "NO — LOG DOES NOT VERIFY", null, data.consistent ? "ok" : "crit")]];
      if (data.consistent) {
        pairs = pairs.concat([
          ["old size / root", show(data.old_size) + " " + shortDigest(data.old_root)],
          ["new size / root", show(data.new_size) + " " + shortDigest(data.new_root)],
          ["proof", proofList(data.proof)],
        ]);
      } else pairs = pairs.concat([["failure", data.failure], ["detail", data.detail], ["sizes", show(data.old_size) + " → " + show(data.new_size)]]);
      kv(host, pairs.concat(verifiability(data)));
    });
  }



  var pilotSetup = null;
  var discoveryReport = null;

  function privateTransportAllowed() {
    return window.location.protocol === "https:" ||
      ["localhost", "127.0.0.1", "[::1]"].indexOf(window.location.hostname) >= 0;
  }

  function updateImportButton() {
    el("discovery-import").disabled = demoMode || !pilotSetup || !pilotSetup.can_import ||
      !discoveryReport || !el("discovery-consent").checked;
  }

  function loadPilot() {
    return api("/v1/pilot/setup").then(function (setup) {
      pilotSetup = setup;
      kv(el("pilot-status"), [["Organisation", setup.tenant], ["Your role", setup.role],
        ["Protection mode", setup.protection_mode], ["MCP proxy", setup.mcp_proxy_enabled ? "Enabled; each server still needs enrollment" : "Not enabled"],
        ["Inventory imports", setup.can_import ? "Permitted" : "Administrator required"]]);
      clear(el("pilot-limits"));
      (setup.limits || []).forEach(function (message) { el("pilot-limits").appendChild(text("li", message)); });
      kv(el("pilot-brain"), [["Policy engine", setup.brain.deterministic_policy],
        ["Model advisor", setup.brain.advisor_configured ? "Configured; connectivity not checked here" : "Not connected"],
        ["Authority", "Advisory only; cannot approve or execute"]]);
      updateImportButton();
      return api("/v1/pilot/devices");
    }).then(function (data) {
      var host = el("pilot-devices");
      clear(host);
      if (!data.devices.length) host.appendChild(text("p", "No device reports imported. This says nothing about how many AI tools exist.", "hint"));
      data.devices.forEach(function (entry) {
        var report = entry.report;
        var card = box("section", "");
        card.appendChild(text("h3", "Device " + report.device_id));
        card.appendChild(text("p", report.platform + " · scanned " + report.scanned_at + " · received " + entry.received_at));
        var rows = report.observations.map(function (item) {
          return {tool: pilotSetup.tools[item.tool] || "Unknown", probe: item.probe, state: item.state, enforcement: "Not established"};
        });
        var grid = box("div", "");
        table(grid, [{label: "Tool", key: "tool"}, {label: "Check", key: "probe"},
          {label: "Presence", key: "state"}, {label: "Enforcement", key: "enforcement"}], rows);
        card.appendChild(grid);
        if (pilotSetup.can_import && !demoMode) {
          var forget = text("button", "Delete report");
          forget.type = "button";
          forget.addEventListener("click", function () {
            if (!window.confirm("Delete this device's stored inventory report?")) return;
            del("/v1/pilot/devices/" + encodeURIComponent(report.device_id)).then(loadPilot,
              function () { toast("warn", "Could not delete the report."); });
          });
          card.appendChild(forget);
        }
        host.appendChild(card);
      });
      if (data.truncated) host.appendChild(text("p", "Showing the 100 most recently received device reports. More reports exist.", "hint"));
    }).catch(function (err) { failed(el("pilot-status"), reasonFor(err), err.status); });
  }

  el("discovery-download").addEventListener("click", function () {
    fetch("/v1/pilot/discovery-script", {headers: authHeaders()}).then(function (res) {
      if (!res.ok) throw new Error("Download refused");
      return res.blob();
    }).then(function (blob) {
      var url = URL.createObjectURL(blob);
      var link = document.createElement("a");
      link.href = url;
      link.download = "sentinel-discover.py";
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    }).catch(function () { toast("warn", "Discovery script could not be downloaded."); });
  });

  el("discovery-file").addEventListener("change", function () {
    discoveryReport = null;
    el("discovery-consent").checked = false;
    updateImportButton();
    var file = this.files[0];
    var preview = el("discovery-preview");
    clear(preview);
    if (!file) return;
    if (file.size > 32768) { preview.appendChild(text("p", "Report exceeds 32 KiB.", "fail")); return; }
    file.text().then(function (raw) {
      var report = JSON.parse(raw);
      var expected = ["consent", "device_id", "observations", "platform", "scanned_at", "schema"];
      if (!report || JSON.stringify(Object.keys(report).sort()) !== JSON.stringify(expected) ||
          report.schema !== "sentinel.device-discovery/v2" || !Array.isArray(report.observations) ||
          report.observations.length > 64 || typeof report.device_id !== "string" ||
          !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(report.device_id) ||
          ["Darwin", "Linux", "Windows", "Other"].indexOf(report.platform) < 0 ||
          typeof report.scanned_at !== "string" || report.scanned_at.length > 40 || isNaN(Date.parse(report.scanned_at)) ||
          !report.consent || JSON.stringify(Object.keys(report.consent).sort()) !== '["app_presence","cli_presence","config_presence"]' ||
          typeof report.consent.app_presence !== "boolean" || typeof report.consent.config_presence !== "boolean" ||
          typeof report.consent.cli_presence !== "boolean") throw new Error("Invalid report");
      report.observations.forEach(function (item) {
        if (!item || JSON.stringify(Object.keys(item).sort()) !== '["probe","state","tool"]' ||
            !pilotSetup || !Object.prototype.hasOwnProperty.call(pilotSetup.tools, item.tool) ||
            typeof item.probe !== "string" || !/^[a-z-]{1,40}$/.test(item.probe) ||
            ["present", "not_found", "inaccessible", "unsupported", "not_consented"].indexOf(item.state) < 0) throw new Error("Invalid observation");
      });
      discoveryReport = report;
      kv(preview, [["Device", report.device_id], ["Platform", report.platform], ["Scanned", report.scanned_at],
        ["Configuration checks approved", report.consent.config_presence], ["App checks approved", report.consent.app_presence], ["Command checks approved", report.consent.cli_presence],
        ["Positive presence checks", report.observations.filter(function (o) { return o.state === "present"; }).length],
        ["Destination organisation", pilotSetup.tenant], ["Trust", "Self-reported; not enforcement evidence"]]);
      var details = box("div", "");
      table(details, [{label: "Tool", key: "tool"}, {label: "Check", key: "probe"}, {label: "State", key: "state"}], report.observations);
      preview.appendChild(details);
      updateImportButton();
    }).catch(function () { discoveryReport = null; preview.appendChild(text("p", "Invalid report. Generate a new report with the discovery script.", "fail")); updateImportButton(); });
  });
  el("discovery-consent").addEventListener("change", updateImportButton);
  el("discovery-import").addEventListener("click", function () {
    if (this.disabled) return;
    this.disabled = true;
    post("/v1/pilot/devices", discoveryReport).then(function () {
      discoveryReport = null;
      el("discovery-file").value = "";
      el("discovery-consent").checked = false;
      clear(el("discovery-preview"));
      el("discovery-result").textContent = "Inventory imported. No tools were enrolled or granted access.";
      return loadPilot();
    }).catch(function () { el("discovery-result").textContent = "Import failed. Check your role and report; no enforcement was enabled."; updateImportButton(); });
  });

  function loadAgents() {
    return panel(el("agents"), "/v1/inventory/agents", function (data) {
      var rows = Array.isArray(data.agents) ? data.agents : [];
      renderAgentFilter(rows, data);
      var shown = rows.filter(function (row) {
        return !agentFilter || String(row.classification) === agentFilter;
      });
      table(
        el("agents"),
        [
          { label: "agent", key: "agent_id", className: "mono" },
          {
            label: "classification",
            render: function (row) {
              var c = String(row.classification);
              return pill(c, null, c === "revoked_but_active" ? "crit" : c === "unmanaged" ? "warn" : "ok");
            },
          },
          {
            label: "trust",
            render: function (row) {
              var t = row.trust || {};
              return t.score == null ? "—" : pill(show(t.band), show(t.score), num(t.score) >= 70 ? "ok" : num(t.score) >= 40 ? "warn" : "bad");
            },
          },
          { label: "events", key: "event_count", className: "num" },
          { label: "ungranted tools", render: function (row) { return (row.ungranted_tools_used || []).length; }, className: "num" },
          { label: "external destinations", render: function (row) { return (row.external_destinations || []).length; }, className: "num" },
          { label: "last seen", key: "last_seen", className: "mono" },
        ],
        shown,
        function (row) {
          openAgent(row.agent_id);
        }
      );
      if (!shown.length) {
        clear(el("agents"));
        el("agents").appendChild(text("p", "no agents match this filter (" + rows.length + " observed)", "empty"));
      }
    });
  }

  function renderAgentFilter(rows, data) {
    var host = el("agent-filter");
    clear(host);
    var kinds = {};
    rows.forEach(function (row) {
      var k = String(row.classification || "unknown");
      kinds[k] = (kinds[k] || 0) + 1;
    });
    host.appendChild(
      chip("all (" + rows.length + ")", agentFilter === "", function () {
        agentFilter = "";
        loadAgents();
      })
    );
    Object.keys(kinds)
      .sort()
      .forEach(function (kind) {
        host.appendChild(
          chip(kind + " (" + kinds[kind] + ")", agentFilter === kind, function () {
            agentFilter = kind;
            loadAgents();
          })
        );
      });
    host.appendChild(pill("need attention", data.needs_attention, num(data.needs_attention) ? "warn" : "ok"));
  }

  function openAgent(agentId) {
    if (!agentId) return;
    var body = openDrawer("agent " + agentId);
    var profileHost = box("div");
    var edgesHost = box("div");
    var baselineHost = box("div");
    var radiusHost = box("div");
    body.appendChild(section("Profile", [profileHost]));
    body.appendChild(section("Observed edges", [edgesHost]));
    body.appendChild(section("Behaviour baseline", [text("p", "established=false means too little history, not normal behaviour.", "hint"), baselineHost]));
    body.appendChild(section("Blast radius", [text("p", "Sensitivity is declared, never inferred: read coverage before score. Declarations are posted, not put in a query string.", "hint"), blastRadiusForm(agentId, radiusHost), radiusHost]));

    api("/v1/inventory/agents/" + encodeURIComponent(agentId)).then(
      function (data) {
        var trust = data.trust || {};
        kv(profileHost, [
          ["classification", pill(show(data.classification), null, data.classification === "revoked_but_active" ? "crit" : data.classification === "unmanaged" ? "warn" : "ok")],
          ["trust score", trust.score == null ? "—" : show(trust.score) + " (" + show(trust.band) + ")"],
          ["trust factors", (trust.factors || []).map(function (f) { return f.name + " −" + f.delta; }).join(", ") || "none"],
          ["events", data.event_count],
          ["first seen", data.first_seen],
          ["last seen", data.last_seen],
          ["granted tools", (data.granted_tools || []).join(", ") || "none"],
          ["observed tools", (data.observed_tools || []).join(", ") || "none"],
          ["ungranted tools used", (data.ungranted_tools_used || []).join(", ") || "none"],
          ["external destinations", (data.external_destinations || []).join(", ") || "none"],
          ["declared", data.declared ? show(data.declared) : "nothing declared"],
        ]);
        table(
          edgesHost,
          [
            { label: "kind", key: "kind" },
            { label: "target", key: "target", className: "mono" },
            { label: "n", key: "occurrences", className: "num" },
            { label: "last seen", key: "last_seen", className: "mono" },
          ],
          Array.isArray(data.edges) ? data.edges : []
        );
      },
      function (err) {
        failed(profileHost, err.status === "404" ? "no agent by this id has been observed" : reasonFor(err), err.status);
      }
    );
    api("/v1/agents/" + encodeURIComponent(agentId) + "/baseline").then(
      function (data) {
        kv(baselineHost, [
          ["established", pill(data.established ? "established" : "NOT established", null, data.established ? "ok" : "warn")],
          ["sessions observed", data.sessions_observed],
          ["tools", (data.tools || []).join(", ") || "none"],
          ["resources", (data.resources || []).join(", ") || "none"],
          ["destinations", (data.destinations || []).join(", ") || "none"],
          ["mcp servers", (data.mcp_servers || []).join(", ") || "none"],
          ["active hours (UTC)", (data.active_hours || []).join(", ") || "none"],
          ["privileged actions", (data.privileged_actions || []).join(", ") || "none"],
          ["steps per session", show(data.mean_steps_per_session) + " mean, " + show(data.max_steps_per_session) + " max"],
          ["note", data.note],
        ]);
      },
      function (err) {
        failed(baselineHost, reasonFor(err), err.status);
      }
    );
  }

  function blastRadiusForm(agentId, resultHost) {
    var declarations = document.createElement("textarea");
    declarations.rows = 4;
    declarations.placeholder = "one declaration per line: asset, sensitivity (public|internal|confidential|restricted|unknown)[, production]\ndb://customers, restricted, production";
    var declaredBy = document.createElement("input");
    declaredBy.type = "text";
    declaredBy.placeholder = "declared by (required when declaring)";
    var run = text("button", "Compute blast radius", "primary small");
    run.type = "button";
    run.addEventListener("click", function () {
      var lines = declarations.value.split("\n").map(function (line) { return line.trim(); }).filter(Boolean);
      var who = declaredBy.value.trim();
      if (lines.length && !who) {
        toast("warn", "declared_by is required when supplying declarations");
        declaredBy.focus();
        return;
      }
      var body = {
        declarations: lines.map(function (line) {
          var parts = line.split(",").map(function (p) { return p.trim(); });
          return { asset: parts[0], sensitivity: (parts[1] || "unknown").toLowerCase(), declared_by: who, production: /^(prod|production|true|yes)$/i.test(parts[2] || "") };
        }),
      };
      loadBlastRadius(agentId, body, resultHost);
    });
    return box("div", "form", [declarations, declaredBy, run]);
  }

  function loadBlastRadius(agentId, body, host) {
    clear(host);
    host.appendChild(text("p", "computing…", "hint"));
    return post("/v1/analysis/blast-radius/" + encodeURIComponent(agentId), body).then(
      function (data) {
        clear(host);
        var coverage = num(data.coverage);
        host.appendChild(
          box("div", "row", [
            stat(show(data.score), "score", coverage === 0 ? "warn" : severityKind(data.score)),
            stat(Math.round(coverage * 100) + "%", "coverage of reachable assets classified", coverage === 0 ? "warn" : coverage < 1 ? "warn" : "ok"),
            stat(num(data.reachable_count), "reachable"),
            stat((data.unclassified || []).length, "unclassified", (data.unclassified || []).length ? "warn" : "ok"),
          ])
        );
        if (coverage === 0) host.appendChild(text("p", "coverage 0: nobody has classified this estate here. The score is not evidence of safety.", "gate"));
        var list = box("ul", "rows");
        (data.critical_paths || []).forEach(function (path) {
          list.appendChild(box("li", path.production ? "crit" : "bad", [text("span", path.asset, "mono"), pill(show(path.sensitivity), null, "bad"), path.production ? pill("production", null, "crit") : null, text("span", "via " + ((path.via || []).join(" → ") || "direct"), "hint")]));
        });
        (data.unclassified || []).forEach(function (asset) {
          list.appendChild(box("li", "warn", [text("span", asset, "mono"), pill("undeclared", null, "warn")]));
        });
        (data.rejected_declarations || []).forEach(function (r) {
          list.appendChild(box("li", "bad", [text("span", r.asset, "mono"), pill("declaration rejected", null, "bad"), text("span", r.reason, "hint")]));
        });
        if (!list.firstChild) list.appendChild(text("li", "nothing reachable from recorded grants", "empty"));
        host.appendChild(list);
        host.appendChild(text("p", show(data.declaration_source) + " " + show(data.limits), "hint"));
      },
      function (err) {
        failed(host, reasonFor(err), err.status);
      }
    );
  }


  function loadReach(event) {
    if (event) event.preventDefault();
    var pattern = el("reach-pattern").value.trim();
    if (!pattern) {
      clear(el("reach"));
      el("reach").appendChild(text("p", "enter a pattern to search the reach graph", "hint"));
      return Promise.resolve();
    }
    return panel(el("reach"), "/v1/inventory/reach?kind=" + encodeURIComponent(el("reach-kind").value) + "&pattern=" + encodeURIComponent(pattern), function (data) {
      var host = el("reach");
      clear(host);
      var agents = Array.isArray(data.agents) ? data.agents : [];
      host.appendChild(box("div", "pills", [pill("agents reaching " + show(data.kind) + " ~ " + show(data.pattern), agents.length, agents.length ? "warn" : "ok")]));
      var list = box("ul", "rows");
      agents.forEach(function (agent) {
        var id = typeof agent === "object" ? agent.agent_id || show(agent) : String(agent);
        var li = box("li", "clickable", [text("span", id, "mono")]);
        li.addEventListener("click", function () {
          openAgent(id);
        });
        list.appendChild(li);
      });
      if (!agents.length) list.appendChild(text("li", "no observed agent reached a target matching this pattern (observed traffic only)", "empty"));
      host.appendChild(list);
    });
  }



  function loadSupplyChain() {
    var bom = panel(el("bom"), "/v1/estate/ai-bom", function (data) {
      var verdict = el("bom-verdict");
      clear(verdict);
      var word = show(data.completeness);
      var line = text("p", "completeness: " + word);
      line.setAttribute("data-verdict", word);
      verdict.appendChild(line);
      if (word === "unusable") verdict.appendChild(text("p", "This document knows nothing about the estate. It is NOT a report that the estate is clean.", "gate"));
      var census = data.provenance_census || {};
      var host = el("bom");
      clear(host);
      host.appendChild(pill("components", data.component_count, "muted"));
      host.appendChild(pill("attested", census.attested, "ok"));
      host.appendChild(pill("observed", census.observed, "muted"));
      host.appendChild(pill("declared", census.declared, "warn"));
      host.appendChild(pill("findings", (data.findings || []).length, (data.findings || []).length ? "warn" : "ok"));
      host.appendChild(pill("sources consulted", (data.sources || []).length, "muted"));
      table(
        el("bom-components"),
        [
          { label: "kind", key: "kind" },
          { label: "identifier", key: "identifier", className: "mono" },
          { label: "provenance", key: "provenance" },
          { label: "pinned", render: function (row) { return row.is_pinned ? pill("pinned", null, "ok") : pill("UNPINNED", null, "warn"); } },
          { label: "sources", render: function (row) { return (row.sources || []).join(", "); } },
        ],
        Array.isArray(data.components) ? data.components : []
      );
      var findings = el("bom-findings");
      clear(findings);
      (data.findings || []).forEach(function (row) {
        findings.appendChild(box("li", "warn", [text("span", show(row.kind), "tag"), text("span", show(row.component), "mono"), text("span", show(row.detail), "hint")]));
      });
      if (!findings.firstChild) findings.appendChild(text("li", "no findings over " + show(data.component_count) + " components (completeness: " + word + ")", "empty"));
    });

    var exposure = panel(el("exposure"), "/v1/estate/exposure", function (data) {
      var coverage = data.coverage || {};
      var host = el("exposure");
      clear(host);
      host.appendChild(
        box("div", "pills", [
          pill("nodes", data.node_count, "muted"),
          pill("edges", data.edge_count, "muted"),
          pill(coverage.is_partial ? "coverage PARTIAL" : "coverage complete", null, coverage.is_partial ? "warn" : "ok"),
          pill("unscanned scopes", (coverage.unscanned || []).length, (coverage.unscanned || []).length ? "warn" : "ok"),
        ])
      );
      (coverage.unscanned || []).forEach(function (u) {
        host.appendChild(text("p", show(u.scope) + ": " + show(u.reason), "hint"));
      });
      var byKind = {};
      (data.edges || []).forEach(function (e) {
        byKind[e.target_kind] = (byKind[e.target_kind] || 0) + 1;
      });
      var pills = box("div", "pills");
      Object.keys(byKind).sort().forEach(function (k) {
        pills.appendChild(pill("edges → " + k, byKind[k], "muted"));
      });
      host.appendChild(pills);
    });

    var adoption = panel(el("adoption"), "/v1/estate/adoption", function (data) {
      var counts = data.counts || {};
      kv(el("adoption"), [
        ["stage", pill(show(data.stage), null, "ok")],
        ["evidence", data.evidence],
        ["blocking next stage", data.blocking_next_stage],
        ["engagement rate", data.engagement_rate == null ? "not quoted: " + show(data.rate_refusal_reason) : data.engagement_rate],
        ["agents / events / incidents", show(counts.agents_observed) + " / " + show(counts.events_ingested) + " / " + show(counts.incidents_raised)],
        ["not measured by this build", (data.counts_not_measured_by_this_build || []).join(" · ")],
      ]);
    });
    return Promise.all([bom, exposure, adoption]);
  }

  function loadGovernance() {
    renderLimits();

    var org = api("/v1/orgs/current").then(
      function (data) {
        kv(el("org"), pairsOf(data));
      },
      function (err) {
        if (err.status === "404" || err.message === "404") {
          clear(el("org"));
          el("org").appendChild(text("p", "no organisation has been created for this tenant", "empty"));
          return;
        }
        failed(el("org"), reasonFor(err), err.status);
      }
    );
    var members = panel(el("members"), "/v1/orgs/current/members", function (data) {
      table(el("members"), [{ label: "user", key: "user_id", className: "mono" }, { label: "role", render: function (m) { return pill(show(m.role), null, "muted"); } }, { label: "email", key: "email" }], Array.isArray(data.members) ? data.members : []);
    });
    var diagnostics = panel(
      el("diagnostics"),
      "/health/diagnostics",
      function (data) {
        var checks = data.checks || {};
        var host = el("diagnostics");
        clear(host);
        host.appendChild(box("div", "pills", [pill(data.ready ? "ready" : "NOT READY", null, data.ready ? "ok" : "bad")]));
        var list = box("ul", "rows");
        Object.keys(checks).forEach(function (key) {
          var value = checks[key];
          var kind = typeof value === "boolean" ? (value ? "ok" : key === "attestation_capable" || key === "enforces" ? "warn" : "bad") : "";
          if (key === "protect_kill_switch" && value === true) kind = "bad";
          list.appendChild(box("li", kind, [dot(kind), text("span", key), text("span", show(value), typeof value === "boolean" ? "" : "hint")]));
        });
        host.appendChild(list);
      },
      "read_diagnostics"
    );
    return Promise.all([org, members, diagnostics]);
  }


  function renderLimits() {
    var list = el("limits");
    clear(list);
    [
      "This console performs no containment, approval, activation or deployment of its own: every such button is one audited server call under the connected token, and a role without the capability is refused by the server.",
      "Protect decisions are advisory unless SENTINEL_PROTECT_ENFORCE is set AND the calling agent honours the response. Sentinel is not an inline network interceptor.",
      "The execution graph shows the events that arrived with a session id. Check trace coverage on Overview before reading a chain as complete.",
      "A baseline with established=false means too little history, not normal behaviour.",
      "No route lists a tenant's containments or pending approvals; the console shows what this tab activated and what the incident reports carry.",
      "Panels a role cannot read say 'not permitted', never render empty.",
    ].forEach(function (line) {
      list.appendChild(box("li", "", [text("span", line)]));
    });
  }



  var LOADERS = {
    pilot: function () {
      return loadPilot();
    },
    overview: function () {
      return loadOverview();
    },
    requests: function () {
      return loadRequests();
    },
    approvals: function () {
      return loadApprovals();
    },
    graph: function () {
      return loadSession();
    },
    binding: function () {
      return loadBinding();
    },
    estate: function () {
      return loadEstate();
    },
    containment: function () {
      renderContainments();
      return Promise.resolve();
    },
    policy: function () {
      return loadPolicyVersions();
    },
    transparency: function () {
      return loadTransparency();
    },
    agents: function () {
      return loadAgents();
    },
    supply: function () {
      return loadSupplyChain();
    },
    governance: function () {
      return loadGovernance();
    },
  };

  function showView(name) {
    currentView = name;
    Array.prototype.forEach.call(document.querySelectorAll(".view"), function (node) {
      node.hidden = node.id !== "view-" + name;
    });
    Array.prototype.forEach.call(document.querySelectorAll("#nav button"), function (node) {
      node.className = node.getAttribute("data-view") === name ? "active" : "";
    });
    if (tokenInput.value.trim()) LOADERS[name]();
  }

  Array.prototype.forEach.call(document.querySelectorAll("#nav button"), function (node) {
    node.addEventListener("click", function () {
      showView(node.getAttribute("data-view"));
    });
  });

  el("drawer-close").addEventListener("click", function () {
    el("drawer").hidden = true;
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") el("drawer").hidden = true;
  });

  el("session-form").addEventListener("submit", function (event) {
    event.preventDefault();
    loadSession();
  });
  el("decide-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var id = el("decide-id").value.trim();
    var reason = el("decide-reason").value.trim();
    if (!id || !reason) {
      toast("warn", "approval id and reason are both required");
      return;
    }
    decide(id, el("decide-decision").value, reason, el("decide-result"));
  });
  el("contain-form").addEventListener("submit", contain);
  el("contain-scope").addEventListener("change", function () {
    var whole = el("contain-scope").value === "high_risk_agents";
    el("contain-selector").disabled = whole;
    if (whole) el("contain-selector").value = "";
  });
  el("release-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var id = el("release-id").value.trim();
    if (!id) return;
    release(id, el("release-result"));
  });
  el("diff-form").addEventListener("submit", loadPolicyDiff);
  el("sim-form").addEventListener("submit", loadSimulation);
  el("activate-form").addEventListener("submit", askActivate);
  el("policy-validate").addEventListener("click", validatePolicy);
  el("policy-deploy").addEventListener("click", deployPolicy);
  el("policy-editor").addEventListener("input", applyGates);
  el("policy-editor").value = JSON.stringify(SAMPLE_POLICY, null, 2);
  el("inclusion-form").addEventListener("submit", loadInclusion);
  el("consistency-form").addEventListener("submit", loadConsistency);
  el("reach-form").addEventListener("submit", loadReach);


  function tick() {
    refreshMonitor();
    if (!tokenInput.value.trim() || document.hidden) return;
    var loading = (LOADERS[currentView] || LOADERS.overview)();
    if (loading && typeof loading.then === "function") loading.then(refreshMonitor, refreshMonitor);
    return loading;
  }

  document.addEventListener("visibilitychange", function () {
    refreshMonitor();
    if (!document.hidden) tick();
  });

  function pollSeconds() {
    return demoMode && demo ? Math.max(15, Number(demo.poll_seconds) || 30) : 5;
  }

  function enterConsole() {
    document.body.className = "";
    var badge = el("session-badge");
    badge.hidden = false;
    badge.textContent = demoMode ? "Demo \u00b7 read-only \u00b7 tenant " + demo.tenant : "Signed in";
    el("signout").hidden = false;
    var note = el("demo-banner");
    note.hidden = !demoMode;
    note.textContent = demoMode
      ? "You are viewing a read-only demonstration of tenant \u201c" + demo.tenant + "\u201d with sample data. Approving, containing and changing policy are disabled for this key."
      : "";
    /* The capability pills diagnose an operator's token. A demo visitor's
       key is read-only by construction and the banner says so. */
    el("caps").hidden = demoMode;
    signatures = {};
    Object.keys(caps).forEach(function (cap) {
      caps[cap] = demoMode ? false : null;
    });
    renderCaps();
    applyGates();
    showView(currentView);
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(tick, pollSeconds() * 1000);
    toast("ok", "refreshing the active view every " + pollSeconds() + "s while this tab is visible");
  }

  function signinError(message) {
    var node = el("signin-error");
    node.hidden = !message;
    node.textContent = message || "";
  }

  function signIn() {
    signinError("");
    if (!demoMode && !privateTransportAllowed()) {
      tokenInput.value = "";
      signinError("Private sign-in requires HTTPS. Use the public demo or ask for the secure URL.");
      return;
    }
    if (!tokenInput.value.trim()) {
      signinError("Enter an API token.");
      return;
    }
    el("connect").disabled = true;
    fetch("/v1/dashboard", { headers: authHeaders() }).then(
      function (res) {
        el("connect").disabled = false;
        if (res.status === 401) {
          demoMode = false;
          signinError("That token was not recognised.");
          return;
        }
        if (res.status === 429) {
          signinError("Too many attempts. Wait a minute and try again.");
          return;
        }
        if (!res.ok) {
          signinError(res.status === 403 ? "This credential cannot open the operator console. Ask for a viewer, analyst or admin Sentinel token." : "Sign-in failed. Try again when the service is healthy.");
          return;
        }
        currentView = demoMode ? "overview" : "pilot";
        enterConsole();
        if (res.ok) lastOk = Date.now();
        refreshMonitor();
      },
      function () {
        el("connect").disabled = false;
        signinError("Sentinel could not be reached.");
      }
    );
  }

  el("signin-form").addEventListener("submit", function (event) {
    event.preventDefault();
    demoMode = false;
    signIn();
  });
  el("demo-enter").addEventListener("click", function () {
    if (!demo) return;
    demoMode = true;
    tokenInput.value = demo.token;
    signIn();
  });
  el("signout").addEventListener("click", function () {
    /* A reload is the only sign-out that provably forgets: the token lives in
       this page's memory and nowhere else. */
    tokenInput.value = "";
    window.location.reload();
  });

  fetch("/console/demo.json", { headers: { Accept: "application/json" } })
    .then(function (res) {
      return res.ok ? res.json() : null;
    })
    .then(
      function (body) {
        if (body && body.enabled === true && typeof body.token === "string" && body.token) {
          demo = body;
          el("demo-entry").hidden = false;
        }
      },
      function () {}
    );

  setStatus("DISCONNECTED");
  if (!privateTransportAllowed()) {
    tokenInput.disabled = true;
    el("connect").disabled = true;
    el("transport-warning").hidden = false;
  }
  renderCaps();
  applyGates();
  renderLimits();


  window.__sentinelConsole = { routes: ROUTES, layout: layout, ellipsis: ellipsis, parseReport: parseReport };
})();
