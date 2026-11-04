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

// Table columns: drag the right edge of a column header to make it wider or
// narrower. The widths are remembered in this browser for that table on that
// page; a double click on the edge brings the table back to automatic widths.
(function () {
  var MIN = 40;
  function store() { try { return window.localStorage; } catch (e) { return null; } }
  function heads(table) {
    var rows = table.tHead && table.tHead.rows;
    return rows && rows.length ? rows[rows.length - 1].cells : null;
  }
  function keyOf(table, n, cells) {
    return "wafisp.cols:" + location.pathname + ":" + n + ":" + cells.length;
  }
  // Every column but the last gets its width; the last takes what is left
  // but never less than it had, so a wide column makes the table scroll
  // sideways instead of squeezing the last one (often the buttons) away.
  function apply(table, cells, st) {
    table.classList.add("colfixed");
    var total = st.last;
    for (var i = 0; i < cells.length - 1; i++) {
      cells[i].style.width = st.w[i] + "px";
      total += st.w[i];
    }
    table.style.width = total + "px";
    var p = table.parentElement;
    if (p && !p.classList.contains("scroll")) {
      var box = document.createElement("div");
      box.className = "scroll";
      p.insertBefore(box, table);
      box.appendChild(table);
    }
  }
  function widths(cells) {
    var w = [];
    for (var i = 0; i < cells.length - 1; i++) w.push(Math.round(cells[i].getBoundingClientRect().width));
    return w;
  }
  function save(key, st) {
    var s = store();
    if (!s) return;
    try { s.setItem(key, JSON.stringify(st)); } catch (e) { /* full or blocked: widths stay for this visit */ }
  }
  function reset(table, cells, key) {
    table.classList.remove("colfixed");
    table.style.width = "";
    for (var i = 0; i < cells.length; i++) cells[i].style.width = "";
    var s = store();
    if (s) try { s.removeItem(key); } catch (e) { /* ignore */ }
  }
  var tables = document.querySelectorAll("main table");
  for (var n = 0; n < tables.length; n++) (function (table, n) {
    var cells = heads(table);
    if (!cells || cells.length < 2 || table.classList.contains("noresize")) return;
    var key = keyOf(table, n, cells), s = store(), saved = null;
    if (s) try { saved = JSON.parse(s.getItem(key) || "null"); } catch (e) { saved = null; }
    var st = null;
    if (saved && saved.w && saved.w.length === cells.length - 1 && saved.last > 0) apply(table, cells, st = saved);
    for (var i = 0; i < cells.length - 1; i++) (function (th) {
      var grip = document.createElement("span");
      grip.className = "colgrip";
      grip.setAttribute("aria-hidden", "true");
      th.appendChild(grip);
      grip.addEventListener("click", function (e) { e.preventDefault(); e.stopPropagation(); });
      grip.addEventListener("dblclick", function (e) { e.preventDefault(); st = null; reset(table, cells, key); });
      grip.addEventListener("pointerdown", function (e) {
        if (e.button !== 0) return;
        e.preventDefault();
        if (!st) apply(table, cells, st = { w: widths(cells), last: Math.round(cells[cells.length - 1].getBoundingClientRect().width) });
        var idx = Array.prototype.indexOf.call(cells, th);
        var x0 = e.clientX, w0 = st.w[idx];
        grip.setPointerCapture(e.pointerId);
        document.body.classList.add("colresizing");
        function move(ev) {
          st.w[idx] = Math.max(MIN, Math.round(w0 + ev.clientX - x0));
          apply(table, cells, st);
        }
        function up() {
          grip.removeEventListener("pointermove", move);
          grip.removeEventListener("pointerup", up);
          grip.removeEventListener("pointercancel", up);
          document.body.classList.remove("colresizing");
          save(key, st);
        }
        grip.addEventListener("pointermove", move);
        grip.addEventListener("pointerup", up);
        grip.addEventListener("pointercancel", up);
      });
    })(cells[i]);
  })(tables[n], n);
})();
