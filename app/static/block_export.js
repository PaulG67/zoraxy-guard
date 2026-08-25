/**
 * Shared "export selected entries for the blocker plugin" selection logic.
 *
 * Used by both the History table and the Status alert list. Both pages can
 * re-render their rows underneath us (soft refresh on Status, filter reload on
 * History), so the selection is kept in a Map keyed by domain+path rather than
 * on the checkbox elements themselves, and re-applied whenever rows change.
 */
(function () {
  var selected = new Map();

  function keyOf(el) {
    return (el.dataset.domain || "") + "|" + (el.dataset.path || "/");
  }

  function rowOf(el) {
    return {
      domain: el.dataset.domain || "",
      path: el.dataset.path || "/",
      status: el.dataset.status ? parseInt(el.dataset.status, 10) : null,
      method: el.dataset.method || "GET",
      note: el.dataset.note || "",
      ts: el.dataset.ts ? parseFloat(el.dataset.ts) : null,
    };
  }

  function boxes() {
    return Array.prototype.slice.call(document.querySelectorAll(".exp-check"));
  }

  function refresh() {
    boxes().forEach(function (box) {
      box.checked = selected.has(keyOf(box));
    });
    var btn = document.getElementById("export-submit");
    if (!btn) return;
    var n = selected.size;
    btn.disabled = n === 0;
    btn.textContent = "Markierte für Sperr-Plugin exportieren (" + n + ")";
  }

  document.addEventListener("change", function (ev) {
    var box = ev.target;
    if (!box.classList || !box.classList.contains("exp-check")) return;
    if (box.checked) selected.set(keyOf(box), rowOf(box));
    else selected.delete(keyOf(box));
    refresh();
  });

  document.addEventListener("click", function (ev) {
    var id = ev.target && ev.target.id;
    if (id === "export-select-all") {
      boxes().forEach(function (box) { selected.set(keyOf(box), rowOf(box)); });
      refresh();
    } else if (id === "export-select-none") {
      selected.clear();
      refresh();
    }
  });

  document.addEventListener("submit", function (ev) {
    if (!ev.target || ev.target.id !== "export-form") return;
    var field = document.getElementById("export-payload");
    if (field) field.value = JSON.stringify(Array.from(selected.values()));
  });

  // Status re-renders its alert list every few seconds; without this the ticks
  // would silently disappear while the user is still picking entries.
  var live = document.getElementById("alerts-live");
  if (live && window.MutationObserver) {
    new MutationObserver(refresh).observe(live, { childList: true, subtree: true });
  }

  refresh();
})();
