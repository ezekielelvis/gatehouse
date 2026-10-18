// Minimal progressive enhancement for the Gatehouse UI, served locally so the
// strict CSP (script-src 'self') is satisfied. Two jobs: mark the active nav
// link from the current path, and toggle light/dark (persisted), mirroring the
// triage design system's html.dark / html.light scheme.
(function () {
  // Theme: apply the stored preference before paint-sensitive interactions.
  var stored = null;
  try { stored = localStorage.getItem("gh-theme"); } catch (e) {}
  if (stored === "dark") document.documentElement.classList.add("dark");
  if (stored === "light") document.documentElement.classList.add("light");

  function markActive() {
    var path = location.pathname;
    document.querySelectorAll(".side-link").forEach(function (a) {
      var href = a.getAttribute("href");
      var on = href === "/" ? path === "/" : path.indexOf(href) === 0;
      a.classList.toggle("active", on);
    });
  }

  function wireToggle() {
    var btn = document.getElementById("theme-toggle");
    if (!btn) return;
    btn.addEventListener("click", function () {
      var root = document.documentElement;
      var dark = !root.classList.contains("dark") &&
        !(window.matchMedia("(prefers-color-scheme: dark)").matches && !root.classList.contains("light"));
      root.classList.remove("dark", "light");
      root.classList.add(dark ? "dark" : "light");
      try { localStorage.setItem("gh-theme", dark ? "dark" : "light"); } catch (e) {}
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    markActive();
    wireToggle();
  });
})();
