// Small page behaviours; the CSP allows only scripts served by the panel.
(function () {
  // A form with data-confirm asks before it is sent.
  document.addEventListener("submit", function (e) {
    var msg = e.target.getAttribute && e.target.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) e.preventDefault();
  }, true);

  // The update page waits for the panel to restart, then reloads itself.
  var box = document.getElementById("upd-wait");
  if (!box) return;
  var started = Date.parse(box.getAttribute("data-start")) || Date.now();
  var limit = 180 * 1000;
  var timer = box.querySelector(".secs");
  var bar = box.querySelector("progress");
  function tick() {
    var s = Math.max(0, Math.round((Date.now() - started) / 1000));
    if (timer) timer.textContent = s;
    if (bar) bar.value = Math.min(s, 90);
  }
  function poll() {
    tick();
    if (Date.now() - started > limit) {
      box.classList.add("err");
      box.querySelector(".msg").textContent = box.getAttribute("data-timeout");
      return;
    }
    fetch("/update/status", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (st) {
        if (st && st.state && st.state !== "installing") { window.location.reload(); return; }
        setTimeout(poll, 3000);
      })
      .catch(function () { setTimeout(poll, 3000); }); // restarting: not answering yet
  }
  setInterval(tick, 1000);
  setTimeout(poll, 4000);
})();
