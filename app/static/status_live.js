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
    setText("stat-min-sev", "Push: " + (snap.notify_summary || ("ab " + (snap.min_severity || "medium"))));
    var muted = !!snap.alerts_muted;
    var muteCb = document.getElementById("alerts-muted-toggle");
    if (muteCb && muteCb !== document.activeElement) muteCb.checked = muted;
    var muteBanner = document.getElementById("mute-banner");
    if (muteBanner) muteBanner.style.display = muted ? "" : "none";
    var muteCard = document.getElementById("mute-card");
    if (muteCard) {
      if (muted) muteCard.classList.add("is-muted");
      else muteCard.classList.remove("is-muted");
    }
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

  function buildCheckUrl(origin, path) {
    origin = (origin || "").trim().replace(/\.$/, "");
    path = (path || "").trim();
    if (!origin || origin === "-") return "";
    var scheme = "https://";
    var host = origin;
    if (/^https?:\/\//i.test(origin)) {
      try {
        var u = new URL(origin);
        scheme = u.protocol + "//";
        host = u.host;
        if (u.pathname && u.pathname !== "/") {
          path = u.pathname + (path && path.charAt(0) === "/" ? path : (path ? "/" + path : ""));
        }
      } catch (e) {
        host = origin.replace(/^https?:\/\//i, "");
      }
    }
    if (!path) path = "/";
    else if (path.charAt(0) !== "/") path = "/" + path;
    return scheme + host + path;
  }

  function escHtml(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
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
    var showOpen = document.getElementById("filter-open-only");
    var onlyOpen = showOpen && showOpen.checked;
    var filtered = list.filter(function (a) {
      if (!onlyOpen) return true;
      return !a.acked && !(a.risk && a.risk.action_needed === false && a.risk.title === "Geprüft");
    });
    // Hide fully acked when only-open: also hide action_needed false that were acked
    filtered = onlyOpen
      ? list.filter(function (a) { return !a.acked && (!a.risk || a.risk.action_needed); })
      : list;
    if (!filtered.length) {
      box.innerHTML =
        '<p class="muted">Keine offenen Alarme' +
        (onlyOpen ? " (Filter: nur ungeprüft)" : "") +
        ".</p>";
      return;
    }
    var html = '<div class="alert-list">';
    filtered.forEach(function (a) {
      var fp = a.fingerprint || (a.details && a.details.Fingerprint) || "";
      var acked = !!a.acked;
      var risk = a.risk
        ? '<span class="risk-badge risk-' + (a.risk.level || "") + '" title="' +
          (a.risk.detail || "").replace(/"/g, "&quot;") + '">' +
          (a.risk.title || "") + "</span>"
        : "";
      if (acked) {
        risk += ' <span class="risk-badge risk-safe">Geprüft</span>';
      }
      var origin = a.origin || "";
      var path = a.path || "/";
      var method = a.method || "";
      var status = a.status;
      var client = a.client || "";
      var checkUrl = a.check_url || buildCheckUrl(origin, path);
      var checkLink = checkUrl
        ? '<a href="' + escHtml(checkUrl) + '" class="btn-check" target="_blank" rel="noopener noreferrer" ' +
          'data-origin="' + escHtml(origin) + '" data-path="' + escHtml(path) + '" ' +
          'title="' + escHtml(checkUrl) + '">Prüfen ↗</a>'
        : "";
      // block_export.js re-ticks these from its own selection map after we
      // replace the list, so no state needs to be carried over here.
      var exportPick = origin
        ? '<label class="exp-pick" title="Für den Sperr-Plugin-Export markieren" onclick="event.stopPropagation();">' +
          '<input type="checkbox" class="exp-check" data-domain="' + escHtml(origin) + '" ' +
          'data-path="' + escHtml(path) + '" ' +
          'data-status="' + (status != null ? status : "") + '" ' +
          'data-method="' + escHtml(method || "GET") + '" ' +
          'data-note="' + escHtml((a.risk && a.risk.title) || a.title || "") + '" ' +
          'data-ts="' + (a.ts || "") + '"><span>Sperren</span></label>'
        : "";
      var statusBadge =
        status != null
          ? '<span class="st-badge st-' + Math.floor(status / 100) + '">HTTP ' + status + "</span>"
          : "";
      var rows = "";
      if (a.details) {
        Object.keys(a.details).forEach(function (k) {
          var val = a.details[k];
          if (k === "Log-Zeile") {
            rows += "<tr><th>" + k + '</th><td><code class="logline">' + escHtml(val) + "</code></td></tr>";
          } else {
            rows += "<tr><th>" + k + "</th><td>" + escHtml(val) + "</td></tr>";
          }
        });
      }
      var actions = "";
      if (fp) {
        if (acked) {
          actions =
            '<div class="alert-actions">' +
            '<button type="button" class="btn-ack-undo" data-fp="' +
            encodeURIComponent(fp) +
            '">Prüfung zurücknehmen</button></div>';
        } else {
          actions =
            '<div class="alert-actions">' +
            '<button type="button" class="primary btn-ack" data-fp="' +
            encodeURIComponent(fp) +
            '" data-title="' +
            encodeURIComponent(a.title || "") +
            '" data-origin="' +
            encodeURIComponent(origin) +
            '" data-path="' +
            encodeURIComponent(path) +
            '">Geprüft</button>' +
            '<span class="hint">Markiert als erledigt (kein erneuter Alert mit diesem Fingerprint).</span></div>';
        }
      }
      var checkUrlBlock = checkUrl
        ? '<div class="alert-check-url"><span class="muted">Prüf-URL:</span> ' +
          '<a href="' + escHtml(checkUrl) + '" target="_blank" rel="noopener noreferrer">' +
          escHtml(checkUrl) + "</a></div>"
        : "";
      html +=
        '<details class="alert-item' + (acked ? " alert-acked" : "") + '"><summary>' +
        '<div class="alert-summary-top">' +
        '<span class="muted mono alert-time">' + fmtTs(a.ts) + "</span>" +
        '<span class="sev ' + (a.severity || "") + '">' + (a.severity || "") + "</span>" +
        risk +
        '<span class="alert-title muted">' + escHtml(a.title || "") + "</span>" +
        (a.review_id ? '<span class="alert-id mono" title="Prüf-ID">' + escHtml(a.review_id) + "</span>" : "") +
        "</div>" +
        '<div class="alert-target-row">' +
        '<span class="alert-origin mono" title="Ziel-Host">' + escHtml(origin || "—") + "</span>" +
        checkLink +
        exportPick +
        "</div>" +
        '<div class="alert-request-row mono">' +
        (method ? '<span class="alert-method">' + escHtml(method) + "</span>" : "") +
        '<span class="alert-path" title="' + escHtml(path) + '">' + escHtml(path) + "</span>" +
        statusBadge +
        (client ? '<span class="muted">von ' + escHtml(client) + "</span>" : "") +
        "</div>" +
        "</summary><div class=\"alert-detail\">" +
        checkUrlBlock +
        (rows ? '<table class="detail-table"><tbody>' + rows + "</tbody></table>" : "<p class=\"muted\">" + escHtml(a.body || "") + "</p>") +
        actions +
        "</div></details>";
    });
    html += "</div>";
    box.innerHTML = html;
    box.querySelectorAll(".btn-ack").forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.preventDefault();
        ev.stopPropagation();
        ackAlert(btn);
      });
    });
    box.querySelectorAll(".btn-ack-undo").forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.preventDefault();
        ev.stopPropagation();
        unackAlert(btn);
      });
    });
  }

  async function ackAlert(btn) {
    var fp = decodeURIComponent(btn.getAttribute("data-fp") || "");
    if (!fp) return;
    btn.disabled = true;
    try {
      var res = await fetch("/api/alerts/ack", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({
          fingerprint: fp,
          title: decodeURIComponent(btn.getAttribute("data-title") || ""),
          origin: decodeURIComponent(btn.getAttribute("data-origin") || ""),
          path: decodeURIComponent(btn.getAttribute("data-path") || ""),
        }),
      });
      if (!res.ok) throw new Error("HTTP " + res.status);
      if (window.zoraxyGuardSoftRefresh) {
        await window.zoraxyGuardSoftRefresh({ fullStatus: true, alerts: true });
      } else {
        window.location.reload();
      }
    } catch (e) {
      alert("Geprüft fehlgeschlagen: " + e.message);
      btn.disabled = false;
    }
  }

  async function unackAlert(btn) {
    var fp = decodeURIComponent(btn.getAttribute("data-fp") || "");
    if (!fp) return;
    btn.disabled = true;
    try {
      var res = await fetch("/api/alerts/unack", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ fingerprint: fp }),
      });
      if (!res.ok) throw new Error("HTTP " + res.status);
      if (window.zoraxyGuardSoftRefresh) {
        await window.zoraxyGuardSoftRefresh({ fullStatus: true, alerts: true });
      } else {
        window.location.reload();
      }
    } catch (e) {
      alert("Zurücknehmen fehlgeschlagen: " + e.message);
      btn.disabled = false;
    }
  }

  function fillOpenReviewIds(items) {
    var sel = document.getElementById("ack-id-select");
    if (!sel) return;
    var prev = sel.value;
    var html = '<option value="">— Offene ID wählen —</option>';
    (items || []).forEach(function (it) {
      var id = it.id || "";
      if (!id) return;
      html += '<option value="' + escHtml(id) + '">' + escHtml(it.label || id) + "</option>";
    });
    html += '<option value="__custom__">Eigene Eingabe…</option>';
    sel.innerHTML = html;
    var keep = false;
    for (var i = 0; i < sel.options.length; i++) {
      if (sel.options[i].value === prev) {
        keep = true;
        break;
      }
    }
    sel.value = keep ? prev : "";
    syncAckIdCustom();
  }

  function syncAckIdCustom() {
    var sel = document.getElementById("ack-id-select");
    var input = document.getElementById("ack-id-input");
    if (!sel || !input) return;
    var custom = sel.value === "__custom__";
    input.hidden = !custom;
    if (custom) input.focus();
  }

  function selectedReviewId() {
    var sel = document.getElementById("ack-id-select");
    var input = document.getElementById("ack-id-input");
    var fromSel = sel ? sel.value : "";
    if (fromSel && fromSel !== "__custom__") return fromSel.trim();
    return ((input && input.value) || "").trim();
  }

  function wireAckById() {
    var form = document.getElementById("ack-by-id-form");
    if (!form || form.getAttribute("data-wired") === "1") return;
    form.setAttribute("data-wired", "1");
    var sel = document.getElementById("ack-id-select");
    if (sel) sel.addEventListener("change", syncAckIdCustom);
    syncAckIdCustom();
    form.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      var input = document.getElementById("ack-id-input");
      var msg = document.getElementById("ack-id-msg");
      var btn = document.getElementById("ack-id-btn");
      var rid = selectedReviewId();
      if (!rid) {
        if (msg) msg.textContent = "Bitte eine offene ID wählen oder eine eigene eingeben.";
        return;
      }
      if (btn) btn.disabled = true;
      try {
        var res = await fetch("/api/alerts/ack", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({ review_id: rid }),
        });
        var data = await res.json().catch(function () { return {}; });
        if (!res.ok) {
          throw new Error(data.error || ("HTTP " + res.status));
        }
        if (input) input.value = "";
        if (sel) sel.value = "";
        syncAckIdCustom();
        if (msg) {
          msg.textContent =
            "Geprüft: " + (data.review_id || rid) +
            (data.ack && data.ack.title ? " — " + data.ack.title : "");
        }
        if (window.zoraxyGuardSoftRefresh) {
          await window.zoraxyGuardSoftRefresh({ fullStatus: true, alerts: true });
        }
      } catch (e) {
        if (msg) msg.textContent = "Nicht gefunden oder Fehler: " + e.message;
      } finally {
        if (btn) btn.disabled = false;
      }
    });
  }
  wireAckById();

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
        fillOpenReviewIds(snap.open_review_ids || []);
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
