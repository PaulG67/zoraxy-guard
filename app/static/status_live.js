/**
 * Soft status/memory refresh — GET only, never clears server Memory ring.
 * Browser full-reload would also NOT clear server RAM; this only updates the DOM.
 */
(function () {
  function fmtTs(ts) {
    if (!ts) return "—";
    var d = new Date(ts * 1000);
    var p = function (n) { return n < 10 ? "0" + n : "" + n; };
    return (
      d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " +
      p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds())
    );
  }
  function fmtUptime(sec) {
    sec = Math.max(0, parseInt(sec || 0, 10));
    var h = Math.floor(sec / 3600);
    var m = Math.floor((sec % 3600) / 60);
    var s = sec % 60;
    return h + "h " + m + "m " + s + "s";
  }
  function setText(id, text) {
    var el = document.getElementById(id);
    if (el) el.textContent = text;
  }
  function applyMemory(mem) {
    if (!mem) return;
    var p = mem.process || {};
    var m = mem.memory || {};
    var banner = document.getElementById("memory-banner");
    if (banner) {
      banner.className =
        "card analysis-banner memory-unified analysis-" + (mem.analysis_state || "waiting");
      banner.setAttribute("data-analysis-state", mem.analysis_state || "waiting");
    }
    setText("mem-analysis-label", mem.analysis_label || "—");
    setText("mem-note", (m.note || ""));
    setText("mem-process-started", p.started_at ? fmtTs(p.started_at) : "—");
    setText(
      "mem-process-uptime",
      "Uptime " + fmtUptime(p.uptime_sec) + " · " + (p.lines_processed || 0) + " Log-Zeilen gelesen"
    );
    setText("mem-lines", String(p.lines_processed || 0));
    setText("mem-session-started", m.session_started_at ? fmtTs(m.session_started_at) : "—");
    setText("mem-session-gen", String(m.session_generation || 1));
    setText("mem-fill-label", m.fill_label || m.fill_mode || "—");
    setText("mem-session-recorded", String(m.session_recorded || 0));
    setText("mem-ring-size", String(m.size || 0));
    setText("mem-ring-max", m.max != null ? String(m.max) : "—");
    if (m.size && m.oldest_ts && m.newest_ts) {
      var od = new Date(m.oldest_ts * 1000);
      var nd = new Date(m.newest_ts * 1000);
      var p2 = function (n) { return n < 10 ? "0" + n : "" + n; };
      setText(
        "mem-ring-range",
        "Inhalt " +
          od.getFullYear() + "-" + p2(od.getMonth() + 1) + "-" + p2(od.getDate()) + " " +
          p2(od.getHours()) + ":" + p2(od.getMinutes()) +
          " – " + p2(nd.getHours()) + ":" + p2(nd.getMinutes()) + ":" + p2(nd.getSeconds())
      );
    } else {
      setText("mem-ring-range", "leer — Live-Tail und/oder Reset & laden");
    }
    setText("mem-last-line", p.last_line_at ? fmtTs(p.last_line_at) : "noch keine");
    if (p.last_line_at && mem.now) {
      setText("mem-last-line-age", "vor " + Math.floor(mem.now - p.last_line_at) + "s");
    } else {
      setText("mem-last-line-age", "—");
    }
  }

  function applyStatusStats(snap) {
    setText("stat-lines", String(snap.lines_processed || 0));
    setText("stat-alerts", String(snap.alerts_sent || 0));
    setText("stat-memory", String((snap.memory && snap.memory.size) || 0));
    setText("stat-threats", String(snap.threat_networks || 0));
    setText("stat-min-sev", "Min. Severity: " + (snap.min_severity || "medium"));
    setText(
      "meta-detector-started",
      snap.started_at ? fmtTs(snap.started_at) + " (" + fmtUptime(snap.uptime_sec) + " uptime)" : "—"
    );
    if (snap.memory) {
      setText(
        "meta-memory-session",
        (snap.memory.session_started_at ? fmtTs(snap.memory.session_started_at) : "—") +
          " · " + (snap.memory.fill_label || "")
      );
    }
    setText("meta-reload", snap.last_reload_at ? fmtTs(snap.last_reload_at) : "—");
    setText("meta-watching", snap.watching || "—");
    setText("meta-recorded-total",
      String((snap.history_buffer && snap.history_buffer.recorded_total) || (snap.memory && snap.memory.recorded_total) || 0) +
      " Requests (Ring max. " +
      String((snap.history_buffer && snap.history_buffer.max) || (snap.memory && snap.memory.max) || "—") +
      ")"
    );
    var err = document.getElementById("meta-last-error");
    if (err) {
      if (snap.last_error) {
        err.style.display = "";
        err.textContent = "Letzter Fehler: " + snap.last_error;
      } else {
        err.style.display = "none";
        err.textContent = "";
      }
    }
    var bf = document.getElementById("meta-backfill-row");
    if (bf && snap.backfill) {
      var b = snap.backfill;
      if (b.message || b.running) {
        bf.style.display = "";
        var cell = document.getElementById("meta-backfill");
        if (cell) {
          cell.textContent = b.message || "—";
          cell.className = (b.running ? "is-running" : "") + (b.error ? " err-text" : "");
        }
      } else {
        bf.style.display = "none";
      }
    }
    setText("soft-refresh-stamp", "Anzeige aktualisiert: " + fmtTs(snap.now || Date.now() / 1000) + " (Memory unverändert auf dem Server)");
  }

  function renderAlerts(list) {
    var box = document.getElementById("alerts-live");
    if (!box) return;
    if (!list || !list.length) {
      box.innerHTML =
        '<p class="muted" style="margin-bottom:6px;">Noch keine Alarme in dieser Laufzeit.</p>' +
        '<p class="hint" style="margin:0;">Memory/History laufen weiter (Banner). Kein Full-Reload nötig.</p>';
      return;
    }
    var html = '<div class="alert-list">';
    list.forEach(function (a) {
      var risk = a.risk
        ? '<span class="risk-badge risk-' + (a.risk.level || "") + '" title="' +
          (a.risk.detail || "").replace(/"/g, "&quot;") + '">' +
          (a.risk.title || "") + "</span>"
        : "";
      var rows = "";
      if (a.details) {
        Object.keys(a.details).forEach(function (k) {
          var val = a.details[k];
          if (k === "Log-Zeile") {
            rows += "<tr><th>" + k + '</th><td><code class="logline">' + String(val) + "</code></td></tr>";
          } else {
            rows += "<tr><th>" + k + "</th><td>" + String(val) + "</td></tr>";
          }
        });
      }
      html +=
        '<details class="alert-item"><summary>' +
        '<span class="muted mono">' + fmtTs(a.ts) + "</span>" +
        '<span class="sev ' + (a.severity || "") + '">' + (a.severity || "") + "</span>" +
        risk +
        '<span class="alert-title">' + (a.title || "") + "</span>" +
        '<span class="muted alert-summary">' + (a.summary || a.body || "") + "</span>" +
        "</summary><div class=\"alert-detail\">" +
        (rows ? '<table class="detail-table"><tbody>' + rows + "</tbody></table>" : "<p class=\"muted\">" + (a.body || "") + "</p>") +
        "</div></details>";
    });
    html += "</div>";
    box.innerHTML = html;
  }

  window.zoraxyGuardSoftRefresh = async function (opts) {
    opts = opts || {};
    var statusUrl = opts.statusUrl || "/api/status";
    var btn = document.getElementById("btn-soft-refresh");
    if (btn) btn.disabled = true;
    try {
      var res = await fetch(statusUrl, {
        method: "GET",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (!res.ok) throw new Error("HTTP " + res.status);
      var snap = await res.json();
      applyMemory(snap);
      if (opts.fullStatus !== false && document.getElementById("stat-lines")) {
        applyStatusStats(snap);
        if (opts.alerts !== false) renderAlerts(snap.recent_alerts || []);
      }
      var stamp = document.getElementById("soft-refresh-stamp");
      if (stamp && !document.getElementById("stat-lines")) {
        stamp.textContent =
          "Memory-Anzeige: " + fmtTs(snap.now || Date.now() / 1000) + " (nur Anzeige, Ring unangetastet)";
      }
      return snap;
    } catch (e) {
      var st = document.getElementById("soft-refresh-stamp");
      if (st) st.textContent = "Aktualisierung fehlgeschlagen: " + e.message;
      console.warn("soft refresh", e);
      return null;
    } finally {
      if (btn) btn.disabled = false;
    }
  };
})();
