/**
 * «Prüfen» links: allow the next matching request, then open the real URL.
 * Only that follow-up hit is ignored — later scans still alert.
 */
(function () {
  function expectAndOpen(a) {
    var href = a.getAttribute("href");
    if (!href) return;
    var origin = a.getAttribute("data-origin") || "";
    var path = a.getAttribute("data-path") || "";
    var body = JSON.stringify({ origin: origin, path: path });
    var go = function () {
      window.open(href, "_blank", "noopener,noreferrer");
    };
    fetch("/api/checks/expect", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: body,
    }).then(go, go);
  }

  document.addEventListener(
    "click",
    function (ev) {
      var a = ev.target && ev.target.closest ? ev.target.closest("a.btn-check") : null;
      if (!a) return;
      ev.preventDefault();
      ev.stopPropagation();
      expectAndOpen(a);
    },
    true
  );
})();
