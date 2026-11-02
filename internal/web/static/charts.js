// Hover layer for the server-rendered SVG charts, the live QPS chart and
// the small page helpers (auto-submit selects, tabs, copy as cURL).
(function () {
  "use strict";

  // One floating tooltip for the whole page. Text only: labels come from
  // log data, so they are never inserted as HTML.
  var tip = document.createElement("div");
  tip.className = "tip";
  tip.hidden = true;
  document.body.appendChild(tip);

  function showTip(x, y, rows, title) {
    tip.replaceChildren();
    if (title) {
      var t = document.createElement("div");
      t.className = "tip-title";
      t.textContent = title;
      tip.appendChild(t);
    }
    rows.forEach(function (r) {
      var row = document.createElement("div");
      row.className = "tip-row";
      if (r.slot !== undefined) {
        var k = document.createElement("i");
        k.className = "key s" + r.slot;
        row.appendChild(k);
      }
      var v = document.createElement("b");
      v.textContent = r.value;
      row.appendChild(v);
      if (r.name) {
        var n = document.createElement("span");
        n.textContent = r.name;
        row.appendChild(n);
      }
      tip.appendChild(row);
    });
    tip.hidden = false;
    var w = tip.offsetWidth, h = tip.offsetHeight;
    var left = Math.min(x + 14, window.innerWidth - w - 8);
    var top = y - h - 12 < 4 ? y + 16 : y - h - 12;
    tip.style.left = left + window.scrollX + "px";
    tip.style.top = top + window.scrollY + "px";
  }
  function hideTip() { tip.hidden = true; }

  var fmt = new Intl.NumberFormat("ru-RU");

  // Area charts: a crosshair snaps to the nearest hour and lists every series.
  document.querySelectorAll("svg.chart.area[data-chart]").forEach(function (svg) {
    var d = JSON.parse(svg.dataset.chart);
    var cross = svg.querySelector(".cross");
    var n = d.labels.length;
    function at(ev) {
      var box = svg.getBoundingClientRect();
      var vb = svg.viewBox.baseVal;
      var x = (ev.clientX - box.left) / box.width * vb.width;
      var i = n === 1 ? 0 : Math.round((x - d.x0) / (d.x1 - d.x0) * (n - 1));
      return Math.max(0, Math.min(n - 1, i));
    }
    svg.addEventListener("pointermove", function (ev) {
      var i = at(ev);
      var cx = n === 1 ? (d.x0 + d.x1) / 2 : d.x0 + i * (d.x1 - d.x0) / (n - 1);
      cross.setAttribute("x1", cx);
      cross.setAttribute("x2", cx);
      cross.setAttribute("visibility", "visible");
      showTip(ev.clientX, ev.clientY, d.series.map(function (s) {
        return { slot: s.slot, value: fmt.format(s.values[i]), name: s.name };
      }), d.labels[i] + (d.labels[i].length <= 2 ? ":00" : ""));
    });
    svg.addEventListener("pointerleave", function () {
      cross.setAttribute("visibility", "hidden");
      hideTip();
    });
  });

  // Marks with their own tooltip: donut slices, bars, list rows.
  function bindTips(root) {
    root.querySelectorAll("[data-tip]").forEach(function (el) {
      if (el.dataset.tipBound) return;
      el.dataset.tipBound = "1";
      el.addEventListener("pointermove", function (ev) {
        showTip(ev.clientX, ev.clientY, [{ value: el.dataset.tip }]);
      });
      el.addEventListener("pointerleave", hideTip);
    });
  }
  bindTips(document);

  document.querySelectorAll("select.autosubmit").forEach(function (s) {
    s.addEventListener("change", function () { s.form.submit(); });
  });

  // Tabs: <div class="tabs"><button data-tab="x">…</button></div> + [data-pane="x"].
  document.querySelectorAll(".tabs").forEach(function (tabs) {
    var scope = tabs.closest(".card") || document;
    tabs.querySelectorAll("[data-tab]").forEach(function (b) {
      b.addEventListener("click", function () {
        tabs.querySelectorAll("[data-tab]").forEach(function (x) { x.classList.toggle("on", x === b); });
        scope.querySelectorAll("[data-pane]").forEach(function (p) { p.hidden = p.dataset.pane !== b.dataset.tab; });
      });
    });
  });

  // Copy as cURL from the raw request kept in a data attribute.
  document.querySelectorAll("[data-curl]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var raw = document.getElementById(btn.dataset.curl).textContent;
      var lines = raw.split(/\r?\n/);
      var first = (lines.shift() || "").split(" ");
      var method = first[0] || "GET", path = first[1] || "/";
      var host = "", headers = [], body = [], inBody = false;
      lines.forEach(function (l) {
        if (inBody) { body.push(l); return; }
        if (l === "") { inBody = true; return; }
        var i = l.indexOf(":");
        if (i < 0) return;
        var k = l.slice(0, i).trim(), v = l.slice(i + 1).trim();
        if (k.toLowerCase() === "host") host = v;
        else if (k.toLowerCase() !== "content-length") headers.push(k + ": " + v);
      });
      var q = function (s) { return "'" + s.replace(/'/g, "'\\''") + "'"; };
      var cmd = "curl -k -X " + method + " " + q((btn.dataset.scheme || "https") + "://" + host + path);
      headers.forEach(function (h) { cmd += " \\\n  -H " + q(h); });
      if (body.join("\n").trim()) cmd += " \\\n  --data-raw " + q(body.join("\n"));
      navigator.clipboard.writeText(cmd).then(function () {
        var t = btn.textContent;
        btn.textContent = btn.dataset.copied || "Copied";
        setTimeout(function () { btn.textContent = t; }, 1500);
      });
    });
  });

  // Live QPS bars on /stats.
  var box = document.getElementById("qps");
  var now = document.getElementById("qps-now");
  if (box) {
    var url = "/stats/qps?instance=" + encodeURIComponent(box.dataset.instance || "");
    var draw = function (bars) {
      var frag = document.createDocumentFragment();
      bars.forEach(function (b) {
        var d = document.createElement("div");
        d.className = "bar";
        d.dataset.tip = b.Label + " — " + b.Value + " " + (box.dataset.unit || "req/s");
        var i = document.createElement("i");
        i.style.setProperty("--h", Math.max(b.Pct, 2) + "%");
        d.appendChild(i);
        frag.appendChild(d);
      });
      box.replaceChildren(frag);
      bindTips(box);
      if (now && bars.length) now.textContent = bars[bars.length - 1].Value;
    };
    setInterval(function () {
      if (document.hidden) return;
      fetch(url, { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (bars) { if (bars) draw(bars); })
        .catch(function () {});
    }, 5000);
  }

  // Allow & Deny editor: operators follow the target, the name field shows
  // only for headers and parameters, and conditions and boxes can be added.
  var groups = document.getElementById("orgroups");
  if (groups) {
    var examples = {
      "src_ip eq": "203.0.113.5", "src_ip not_eq": "203.0.113.5", "src_ip match": "203.0.113.*",
      "src_ip cidr": "203.0.113.0/24", "src_ip not_cidr": "203.0.113.0/24", "src_ip in": "IP group",
      "src_ip not_in": "IP group", "uri prefix": "/admin", "uri_no_query prefix": "/admin",
      "uri eq": "/index.html?a=1", "uri_no_query eq": "/login", "host eq": "shop.example.com",
      "host match": "*.example.com", "method eq": "POST", "method not_eq": "GET", "website eq": "shop.example.com",
      "website not_eq": "shop.example.com"
    };
    var syncRow = function (row) {
      var k = row.querySelector(".ck"), op = row.querySelector(".cop");
      var sub = row.querySelector(".csub"), v = row.querySelector(".cv");
      var first = null;
      Array.prototype.forEach.call(op.options, function (o) {
        var ok = (" " + o.dataset.keys + " ").indexOf(" " + k.value + " ") >= 0;
        o.hidden = !ok;
        o.disabled = !ok;
        if (ok && !first) first = o;
      });
      if (op.selectedOptions[0] && op.selectedOptions[0].disabled && first) op.value = first.value;
      sub.hidden = k.selectedOptions[0].dataset.name !== "name";
      var none = op.value === "exist" || op.value === "not_exist";
      v.hidden = none;
      if (none) v.value = "";
      v.placeholder = examples[k.value + " " + op.value] || v.dataset.ph || v.placeholder;
    };
    var bindRow = function (row) {
      var v = row.querySelector(".cv");
      v.dataset.ph = v.dataset.ph || v.placeholder;
      row.querySelector(".ck").addEventListener("change", function () { syncRow(row); });
      row.querySelector(".cop").addEventListener("change", function () { syncRow(row); });
      row.querySelector(".cdel").addEventListener("click", function () {
        var box = row.closest(".orgroup");
        if (box.querySelectorAll(".condrow").length > 1) row.remove();
        else if (groups.querySelectorAll(".orgroup").length > 1) box.remove();
        else { row.querySelector(".cv").value = ""; row.querySelector(".csub").value = ""; }
      });
      syncRow(row);
    };
    var blankRow = function (g) {
      var row = groups.querySelector(".condrow").cloneNode(true);
      row.querySelector("[name=g]").value = g;
      row.querySelector(".ck").selectedIndex = 0;
      row.querySelector(".cop").selectedIndex = 0;
      row.querySelector(".csub").value = "";
      row.querySelector(".cv").value = "";
      bindRow(row);
      return row;
    };
    var bindBox = function (box) {
      box.querySelector(".addand").addEventListener("click", function (e) {
        e.currentTarget.before(blankRow(box.querySelector("[name=g]").value));
      });
    };
    groups.querySelectorAll(".condrow").forEach(bindRow);
    groups.querySelectorAll(".orgroup").forEach(bindBox);
    groups.querySelector(".addor").addEventListener("click", function (e) {
      var g = String(groups.dataset.next++);
      var box = groups.querySelector(".orgroup").cloneNode(false);
      box.appendChild(groups.querySelector(".orgroup legend").cloneNode(true));
      box.appendChild(blankRow(g));
      box.appendChild(groups.querySelector(".addand").cloneNode(true));
      bindBox(box);
      e.currentTarget.before(box);
    });
    // Notes that apply only to the chosen action.
    var form = groups.closest("form");
    var syncAction = function () {
      var a = form.querySelector("[name=action]:checked");
      form.querySelectorAll("[data-for-action]").forEach(function (el) {
        el.hidden = !a || el.dataset.forAction !== a.value;
      });
    };
    form.querySelectorAll("[name=action]").forEach(function (r) { r.addEventListener("change", syncAction); });
    syncAction();
  }

  // Allow & Deny: ↑/↓ move rows within a list and renumber it; the new
  // order is sent with the list's "Apply order" form.
  document.querySelectorAll("table[data-order-form]").forEach(function (table) {
    var form = document.getElementById(table.dataset.orderForm);
    var note = form && form.querySelector(".pending");
    var body = table.tBodies[0];
    var renumber = function () {
      Array.prototype.forEach.call(body.rows, function (tr, i) {
        var input = tr.querySelector(".orderctl input");
        if (input) input.value = i + 1;
      });
      if (note) note.hidden = false;
    };
    body.addEventListener("click", function (e) {
      var btn = e.target.closest(".orderctl button");
      if (!btn) return;
      var tr = btn.closest("tr");
      if (btn.classList.contains("up") && tr.previousElementSibling) tr.after(tr.previousElementSibling);
      else if (btn.classList.contains("down") && tr.nextElementSibling) tr.before(tr.nextElementSibling);
      else return;
      renumber();
      btn.focus();
    });
    body.addEventListener("input", function (e) {
      if (e.target.closest(".orderctl") && note) note.hidden = false;
    });
  });
})();
