// IDS dashboard pages. Every value from a record is attacker-controlled
// text (a User-Agent, a query, a matched payload), so it is only ever put
// into the page as text: through el(), which uses text nodes, never
// innerHTML. The server's Content-Security-Policy backs this up.
"use strict";

(function () {
  const body = document.body;
  const page = body.dataset.page;
  const poll = (Number(body.dataset.poll) || 5) * 1000;
  const view = document.getElementById("view");
  const nf = new Intl.NumberFormat();
  const SVG = "http://www.w3.org/2000/svg";

  // el builds an element. Strings and numbers become text nodes.
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") node.className = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? "" : String(v));
    }
    append(node, children);
    return node;
  }

  function append(node, children) {
    for (const c of children.flat()) {
      if (c === undefined || c === null || c === false) continue;
      node.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
    }
  }

  function svg(tag, attrs) {
    const node = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, String(v));
    return node;
  }

  function when(iso) {
    if (!iso) return "–";
    const d = new Date(iso);
    return isNaN(d) ? "–" : d.toLocaleString();
  }

  // whenShort is a time for a table: the time alone for today, else the
  // day and the time.
  function whenShort(iso) {
    if (!iso) return "–";
    const d = new Date(iso);
    if (isNaN(d)) return "–";
    const today = new Date().toDateString() === d.toDateString();
    return d.toLocaleString([], today ? { hour: "2-digit", minute: "2-digit", second: "2-digit" }
      : { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  function short(text, n) {
    text = String(text || "");
    return text.length > n ? text.slice(0, n - 1) + "…" : text;
  }

  function bytes(n) {
    if (n < 1024) return nf.format(n) + " B";
    if (n < 1 << 20) return (n / 1024).toFixed(1) + " kB";
    return (n / (1 << 20)).toFixed(1) + " MB";
  }

  // api fetches a JSON answer. Without a login the page goes to the login.
  async function api(path) {
    const res = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (res.status === 401) {
      location.assign("/login");
      throw new Error("login required");
    }
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }

  // last is the previous answer, so that a poll that brings nothing new
  // leaves the page alone: an open table, the focus and a tooltip stay.
  let last = "";

  // same reports whether an answer is the one shown already.
  function same(url, data) {
    const { range, ...rest } = data; // the end of the period moves on every call
    const key = url + "\n" + JSON.stringify(rest);
    if (key === last) {
      done();
      return true;
    }
    last = key;
    return false;
  }

  function replace(node) {
    const table = view.querySelector("details.table-view");
    const open = table !== null && table.open;
    view.replaceChildren(node);
    if (open) {
      const again = view.querySelector("details.table-view");
      if (again) again.open = true;
    }
    done();
  }

  function done() {
    view.classList.remove("loading");
    const updated = document.getElementById("updated");
    if (updated) updated.textContent = "Updated " + new Date().toLocaleTimeString();
  }

  function failed(err) {
    last = ""; // the next answer must replace the message
    view.classList.remove("loading");
    view.replaceChildren(el("p", { class: "error", role: "alert" }, "Could not load the data: ", err.message));
  }

  // every runs load now and then every few seconds (V6). A failed or slow
  // answer keeps the last view on screen.
  function every(load) {
    let busy = false;
    const run = async () => {
      if (busy) return;
      busy = true;
      try { await load(); } catch (err) { if (err.message !== "login required") failed(err); }
      busy = false;
    };
    run();
    setInterval(run, poll);
    return run;
  }

  function badge(rec) {
    return el("span", { class: "badges" },
      rec.alert ? el("span", { class: "badge alert" }, "Alert") : el("span", { class: "badge" }, "Below threshold"),
      rec.incomplete ? el("span", { class: "badge incomplete" }, "Incomplete") : null);
  }

  function chips(list, href) {
    return el("span", { class: "chips" }, (list || []).map((x) =>
      href ? el("a", { class: "chip", href: href(x) }, String(x)) : el("span", { class: "chip" }, String(x))));
  }

  function card(title, ...content) {
    return el("section", { class: "card" }, title ? el("h2", {}, title) : null, ...content);
  }

  function kv(pairs) {
    const dl = el("dl", { class: "kv" });
    for (const [k, v] of pairs) {
      if (v === undefined || v === null || v === "") continue;
      dl.append(el("dt", {}, k), el("dd", {}, v));
    }
    return dl;
  }

  function query(params) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== "" && v !== undefined && v !== null) q.set(k, v);
    return q.toString();
  }

  // ---- Overview ----

  function tile(label, value, note, hero) {
    return el("div", { class: "card tile" + (hero ? " hero" : "") },
      el("div", { class: "label" }, label),
      el("div", { class: "value" }, nf.format(value)),
      note ? el("div", { class: "note" }, note) : null);
  }

  // columns draws records over time: alerts at the bottom, the other
  // records above them, with a tooltip per column and a table twin.
  function columns(series, bucketSeconds) {
    const wrap = el("div", { class: "chart" });
    const W = Math.max(300, Math.round(view.clientWidth - 34)), H = 200, top = 8, left = 40, bottom = 24;
    const plotW = W - left - 8, plotH = H - top - bottom;
    const maxV = Math.max(1, ...series.map((b) => b.records));
    const step = niceStep(maxV);
    const yMax = Math.ceil(maxV / step) * step;
    const y = (v) => top + plotH - (v / yMax) * plotH;
    const band = plotW / series.length;
    const barW = Math.max(2, Math.min(24, band - 2));

    const chart = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Records and alerts over time" });
    for (let v = 0; v <= yMax; v += step) {
      chart.append(svg("line", { class: v === 0 ? "baseline" : "gridline", x1: left, x2: W - 8, y1: y(v), y2: y(v) }));
      const t = svg("text", { class: "tick", x: left - 6, y: y(v) + 4, "text-anchor": "end" });
      t.textContent = compact(v);
      chart.append(t);
    }
    const tip = el("div", { class: "tooltip", hidden: true });
    series.forEach((b, i) => {
      const x = left + i * band + (band - barW) / 2;
      const others = b.records - b.alerts;
      if (b.alerts > 0) chart.append(svg("path", { class: "alerts", d: barPath(x, y(b.alerts), barW, y(0) - y(b.alerts), others === 0) }));
      if (others > 0) {
        const gap = b.alerts > 0 ? 2 : 0; // a 2px surface gap between the two parts
        const h = y(b.alerts) - y(b.records) - gap;
        if (h > 0) chart.append(svg("path", { class: "others", d: barPath(x, y(b.records), barW, h, true) }));
      }
      const hit = svg("rect", { class: "hit", x: left + i * band, y: top, width: band, height: plotH, tabindex: 0,
        "aria-label": `${when(b.start)}: ${b.alerts} alerts, ${others} other records, ${b.analysed} analysed` });
      const show = () => {
        tip.replaceChildren(
          el("div", { class: "when" }, when(b.start)),
          el("div", { class: "line" }, el("span", { class: "key alerts" }), el("strong", {}, nf.format(b.alerts)), "alerts"),
          el("div", { class: "line" }, el("span", { class: "key others" }), el("strong", {}, nf.format(others)), "other records"),
          el("div", { class: "line" }, el("span", { class: "key" }), el("strong", {}, nf.format(b.analysed)), "requests analysed"));
        tip.hidden = false;
        const box = wrap.getBoundingClientRect();
        const px = ((left + (i + 0.5) * band) / W) * box.width;
        tip.style.left = Math.min(Math.max(0, px - 80), box.width - 170) + "px";
        tip.style.top = "0px";
      };
      hit.addEventListener("pointerenter", show);
      hit.addEventListener("focus", show);
      hit.addEventListener("pointerleave", () => { tip.hidden = true; });
      hit.addEventListener("blur", () => { tip.hidden = true; });
      chart.append(hit);
    });
    const labels = W < 560 ? [0, series.length - 1] : [0, Math.floor(series.length / 2), series.length - 1];
    for (const i of labels) {
      const t = svg("text", { class: "tick", x: left + (i + 0.5) * band, y: H - 6, "text-anchor": i === 0 ? "start" : i === series.length - 1 ? "end" : "middle" });
      t.textContent = new Date(series[i].start).toLocaleString([], bucketSeconds >= 86400 ? { month: "short", day: "numeric" } : { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
      chart.append(t);
    }
    wrap.append(chart, tip);

    const rows = series.filter((b) => b.records > 0 || b.analysed > 0);
    const table = el("details", { class: "table-view" }, el("summary", {}, "Show as a table"),
      el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, el("th", {}, "From"), el("th", { class: "num" }, "Analysed"), el("th", { class: "num" }, "Records"), el("th", { class: "num" }, "Alerts"))),
        el("tbody", {}, rows.length ? rows.map((b) => el("tr", {}, el("td", {}, when(b.start)), el("td", { class: "num" }, nf.format(b.analysed)), el("td", { class: "num" }, nf.format(b.records)), el("td", { class: "num" }, nf.format(b.alerts))))
          : el("tr", {}, el("td", { colspan: 4, class: "muted" }, "Nothing in this period."))))));
    return [wrap, table];
  }

  // barPath is a column with 4px rounded corners at its top end only.
  function barPath(x, yTop, w, h, roundTop) {
    const r = roundTop ? Math.min(4, w / 2, h) : 0;
    return `M${x},${yTop + h}V${yTop + r}Q${x},${yTop} ${x + r},${yTop}H${x + w - r}Q${x + w},${yTop} ${x + w},${yTop + r}V${yTop + h}Z`;
  }

  function niceStep(max) {
    const raw = max / 4;
    const p = Math.pow(10, Math.floor(Math.log10(raw)));
    for (const m of [1, 2, 5, 10]) if (raw <= m * p) return Math.max(1, m * p);
    return Math.max(1, 10 * p);
  }

  function compact(v) {
    if (v >= 1e6) return (v / 1e6).toFixed(v % 1e6 ? 1 : 0) + "M";
    if (v >= 1e3) return (v / 1e3).toFixed(v % 1e3 ? 1 : 0) + "K";
    return String(v);
  }

  function toplist(items, label, href) {
    if (!items.length) return el("p", { class: "empty" }, "Nothing in this period.");
    const maxV = Math.max(...items.map((i) => i.count));
    return el("ol", { class: "toplist" }, items.map((it) => {
      const bar = el("div", { class: "bar" });
      bar.style.width = (100 * it.count / maxV).toFixed(1) + "%";
      const content = [el("div", { class: "row" }, el("span", { class: "name" }, label(it)), el("span", { class: "count" }, nf.format(it.count))), el("div", { class: "track" }, bar)];
      return el("li", {}, href ? el("a", { href: href(it) }, content) : content);
    }));
  }

  function overviewPage() {
    const range = document.getElementById("range");
    const load = async () => {
      const url = "/api/overview?" + query({ range: range.value });
      const o = await api(url);
      if (same(url, o)) return;
      const alertsLink = (extra) => "/alerts?" + query({ range: range.value, ...extra });
      const nothing = o.recorded === 0 && o.analysed === 0;
      replace(el("div", { class: "stack" },
        el("div", { class: "tiles" },
          tile("Alerts", o.alerts, "score reached the threshold", true),
          tile("Records", o.recorded, "a finding or an incomplete analysis"),
          tile("Requests analysed", o.analysed, "from the counts of the IDS"),
          tile("Incomplete analyses", o.incomplete, "parts that could not be inspected")),
        card("Records over time",
          el("div", { class: "legend" },
            el("span", { class: "key" }, el("span", { class: "swatch alerts" }), "Alerts"),
            el("span", { class: "key" }, el("span", { class: "swatch others" }), "Records below the threshold")),
          nothing ? el("p", { class: "empty" }, "No records in this period. Run the IDS with records, or choose a longer period.") : columns(o.series, o.bucket_seconds)),
        el("div", { class: "grid-2" },
          card("Rules that fired most", toplist(o.top_rules, (i) => `${i.key} · ${i.label}`, (i) => alertsLink({ kind: "all", rule: i.key }))),
          card("Attack groups", toplist(o.top_groups, (i) => i.key, (i) => alertsLink({ kind: "all", group: i.key }))),
          card("Where in the request", toplist(o.top_locations, (i) => i.key, (i) => alertsLink({ kind: "all", location: i.key }))),
          card("Client IP addresses", toplist(o.top_ips, (i) => i.key, (i) => alertsLink({ kind: "all", ip: i.key }))))));
    };
    const run = every(load);
    range.addEventListener("change", () => { view.classList.add("loading"); run(); });
  }

  // ---- Alerts ----

  const groupNames = ["Method enforcement", "Scanner detection", "Protocol enforcement", "Protocol attack", "Multipart attack",
    "Path traversal and file access", "Remote file inclusion", "Remote command execution", "PHP injection", "Generic attack",
    "Cross-site scripting", "SQL injection", "Session fixation", "Java attack", "Other"];

  function alertsPage() {
    const form = document.getElementById("filters");
    const groupSel = document.getElementById("group");
    for (const g of groupNames) groupSel.append(el("option", { value: g }, g));
    const fields = ["range", "kind", "rule", "group", "ip", "location", "min_score"];
    const params = new URLSearchParams(location.search);
    for (const f of fields) if (params.has(f)) form.elements[f].value = params.get(f);
    let pageNo = Number(params.get("page")) || 1;

    const current = () => {
      const p = {};
      for (const f of fields) p[f] = form.elements[f].value.trim();
      return p;
    };
    const load = async () => {
      const p = current();
      const url = "/api/alerts?" + query({ ...p, page: pageNo });
      const l = await api(url);
      if (l.pages < pageNo && pageNo > 1) { pageNo = l.pages; return load(); }
      if (same(url, l)) return;
      const head = el("tr", {}, ["Time", "Status", "Score", "Client", "Request", "Attack groups", "Rules"].map((h, i) =>
        el("th", { class: i === 2 ? "num" : "" }, h)));
      const rows = l.rows.map((r) => {
        const link = "/alerts/" + encodeURIComponent(r.id);
        return el("tr", { class: "linked", onclick: (e) => { if (e.target.closest("a") === null) location.assign(link); } },
          el("td", { class: "nowrap" }, el("a", { href: link, title: when(r.time) }, whenShort(r.time))),
          el("td", {}, badge(r)),
          el("td", { class: "num" }, nf.format(r.score)),
          el("td", { class: "mono" }, r.ip || "–"),
          el("td", { class: "wrap" }, el("div", {}, el("span", { class: "mono" }, r.method + " "), short((r.host || "") + r.path, 90)),
            r.user_agent ? el("div", { class: "sub" }, short(r.user_agent, 80)) : null),
          el("td", {}, chips(r.groups)),
          el("td", {}, chips(r.rules.filter((id) => Math.floor(id / 1000) !== 949), (id) => "/alerts?" + query({ ...current(), rule: id }))));
      });
      const what = { alerts: "alerts", all: "records", incomplete: "incomplete analyses" }[p.kind] || "records";
      replace(card(null,
        l.total ? el("p", { class: "muted" }, `${nf.format(l.total)} ${what}, newest first.`) : null,
        l.rows.length ? el("div", { class: "table-wrap" }, el("table", { class: "wide" }, el("thead", {}, head), el("tbody", {}, rows)))
          : el("p", { class: "empty" }, `No ${what} match these filters.`),
        l.pages > 1 ? el("div", { class: "pager" },
          el("button", { type: "button", disabled: pageNo <= 1, onclick: () => { pageNo--; sync(); run(); } }, "← Newer"),
          el("span", { class: "muted" }, `Page ${l.page} of ${l.pages}`),
          el("button", { type: "button", disabled: pageNo >= l.pages, onclick: () => { pageNo++; sync(); run(); } }, "Older →")) : null));
    };
    const sync = () => history.replaceState(null, "", "/alerts?" + query({ ...current(), page: pageNo > 1 ? pageNo : "" }));
    const run = every(load);
    form.addEventListener("submit", (e) => { e.preventDefault(); pageNo = 1; sync(); view.classList.add("loading"); run(); });
    form.addEventListener("change", (e) => { if (e.target.tagName === "SELECT") form.requestSubmit(); });
    document.getElementById("clear").addEventListener("click", () => {
      setTimeout(() => { pageNo = 1; sync(); run(); }, 0);
    });
  }

  // ---- One alert ----

  async function alertPage() {
    const id = body.dataset.id;
    let r;
    try {
      r = await api("/api/records/" + encodeURIComponent(id));
    } catch (err) {
      if (err.message !== "login required") failed(err);
      return;
    }
    const req = r.request || {}, a = r.analysis || {}, s = r.score || {}, e = r.engine || {};
    document.title = `${r.alert ? "Alert" : "Record"} ${when(r.time)} · IDS dashboard`;
    const findings = (r.findings || []).map((f) => el("tr", {},
      el("td", {}, el("a", { href: "/alerts?" + query({ kind: "all", rule: f.rule_id, range: "all" }) }, String(f.rule_id))),
      el("td", {}, f.severity || "–"),
      el("td", { class: "mono loc" }, f.location || "–"),
      el("td", { class: "wrap" }, f.matched ? el("code", {}, f.matched) : "–"),
      el("td", { class: "wrap" }, f.message, f.data ? el("div", { class: "sub" }, f.data) : null)));
    const categories = Object.entries(s.categories || {}).map(([k, v]) => `${k.replace(/_/g, " ")} ${v}`).join(", ");
    replace(el("div", { class: "stack" },
      el("div", {}, el("h1", {}, r.alert ? "Alert" : "Record", " · ", when(r.time)), badge({ alert: r.alert, incomplete: !a.complete })),
      el("div", { class: "grid-2" },
        card("Decision", kv([
          ["Score", `${s.total} (threshold ${s.threshold})`],
          ["By attack group", categories],
          ["Decided by", r.decided_by],
          ["Record", el("code", {}, r.id)],
          ["Run", el("code", {}, r.run)]])),
        card("Who and where", kv([
          ["Client IP", r.client && r.client.ip ? el("a", { href: "/alerts?" + query({ kind: "all", ip: r.client.ip, range: "all" }) }, r.client.ip) : "not known"],
          ["Client port", r.client && r.client.port],
          ["Host", r.server && r.server.host],
          ["Server address", r.server && r.server.ip ? `${r.server.ip}${r.server.port ? ":" + r.server.port : ""}` : ""]]))),
      card("Request", kv([
        ["Request line", el("code", { class: "wrap" }, `${req.method} ${req.path}${req.query ? "?" + req.query : ""} ${req.version || ""}`)],
        ["User-Agent", req.user_agent],
        ["Referer", req.referer],
        ["Content type", req.content_type],
        ["Body length", req.body_length !== undefined ? bytes(req.body_length) : ""],
        ["Header names", req.header_names && req.header_names.length ? chips(req.header_names) : ""],
        ["Cookies", req.cookies && req.cookies.length ? chips(req.cookies.map((c) => `${c.name} #${c.hash}`)) : ""]]),
        el("p", { class: "muted" }, "Secret values (passwords, tokens, cookies, Authorization) are masked before a record is written.")),
      card("Analysis", kv([
        ["Complete", a.complete ? "yes" : "no — a clean result does not cover the parts that were not inspected"],
        ["Body", `${a.body}${a.body_format ? " as " + a.body_format : ""}${a.body_reason ? " (" + a.body_reason + ")" : ""}`],
        ["Notes", (a.issues || []).map((i) => `${i.part}: ${i.message}`).join("; ")]])),
      card(`Findings (${(r.findings || []).length})`, el("div", { class: "table-wrap" }, el("table", { class: "wide" },
        el("thead", {}, el("tr", {}, ["Rule", "Severity", "Where", "Matched", "Message"].map((h) => el("th", {}, h)))),
        el("tbody", {}, findings)))),
      card("Engine", kv([
        ["Version", `${e.version}${e.revision ? " (" + e.revision.slice(0, 12) + ")" : ""}`],
        ["Rules", e.crs],
        ["Paranoia level", e.paranoia_level],
        ["Configuration", el("code", { class: "wrap" }, e.config)]])),
      r.full ? card("Full request (full_requests is on)",
        el("div", { class: "table-wrap" }, el("table", {}, el("tbody", {}, r.full.headers.map(([n, v]) => el("tr", {}, el("th", {}, n), el("td", { class: "mono wrap" }, v)))))),
        r.full.body ? el("pre", { class: "block" }, r.full.body) : null) : null));
  }

  // ---- Rules ----

  function rulesPage() {
    const form = document.getElementById("filters");
    let data = null;
    const draw = () => {
      if (!data) return;
      const f = Object.fromEntries(new FormData(form));
      const q = (f.q || "").trim().toLowerCase();
      let rules = data.rules.filter((r) =>
        (f.status === "" || (f.status === "active" && r.active) || (f.status === "excluded" && !r.active) || (f.status === "fired" && r.fired > 0)) &&
        (f.level === "" || String(r.paranoia_level || 0) === f.level) &&
        (q === "" || String(r.id).includes(q) || r.file.toLowerCase().includes(q) || r.group.toLowerCase().includes(q)));
      if (f.sort === "fired") rules = rules.slice().sort((a, b) => b.fired - a.fired || a.id - b.id);
      const active = data.rules.filter((r) => r.active).length;
      replace(card(null,
        el("p", { class: "muted" }, data.run ? `${nf.format(data.rules.length)} rules of ${data.engine.crs} at paranoia level ${data.engine.paranoia_level}: ${nf.format(active)} active, ${nf.format(data.rules.length - active)} excluded. Showing ${nf.format(rules.length)}. From the run that started ${when(data.time)}.` : "No start record has been read yet."),
        rules.length ? el("div", { class: "table-wrap" }, el("table", { class: "wide" },
          el("thead", {}, el("tr", {}, ["Rule", "Attack group", "File", "Phase", "Level", "Status", "Fired"].map((h, i) => el("th", { class: i === 6 ? "num" : "" }, h)))),
          el("tbody", {}, rules.map((r) => el("tr", {},
            el("td", {}, r.fired ? el("a", { href: "/alerts?" + query({ kind: "all", rule: r.id, range: f.range }) }, String(r.id)) : String(r.id)),
            el("td", {}, r.group),
            el("td", { class: "mono nowrap" }, `${r.file}:${r.line}`),
            el("td", {}, String(r.phase)),
            el("td", {}, r.paranoia_level ? String(r.paranoia_level) : "–"),
            el("td", { class: "wrap" }, r.active ? el("span", { class: "badge active" }, "Active") : [el("span", { class: "badge excluded" }, "Excluded"), el("div", { class: "sub" }, r.reason)]),
            el("td", { class: "num" }, nf.format(r.fired)))))))
          : el("p", { class: "empty" }, "No rule matches these filters.")));
    };
    const run = every(async () => {
      const url = "/api/rules?" + query({ range: form.elements.range.value });
      const d = await api(url);
      if (same(url, d)) return;
      data = d;
      draw();
    });
    form.addEventListener("submit", (e) => e.preventDefault());
    form.addEventListener("input", (e) => { if (e.target.name === "range") { view.classList.add("loading"); run(); } else draw(); });
  }

  // ---- Engine ----

  function enginePage() {
    every(async () => {
      const p = await api("/api/engine");
      if (same("/api/engine", p)) return;
      const l = p.latest;
      const runs = p.runs.map((r, i) => {
        const older = p.runs[i + 1];
        const changed = older && older.engine.config !== r.engine.config;
        return el("tr", {},
          el("td", { class: "nowrap" }, when(r.time)),
          el("td", { class: "mono" }, r.run),
          el("td", {}, r.engine.crs),
          el("td", {}, String(r.engine.paranoia_level)),
          el("td", { class: "mono wrap" }, short(r.engine.config, 23), changed ? el("div", { class: "sub" }, "changed since the run before") : null));
      });
      replace(el("div", { class: "stack" },
        l ? card("Running configuration", kv([
          ["Started", when(l.time)],
          ["Run", el("code", {}, l.run)],
          ["Engine", `${l.engine.version}${l.engine.revision ? " (" + l.engine.revision.slice(0, 12) + ")" : ""}`],
          ["Rules", l.engine.crs],
          ["Paranoia level", l.engine.paranoia_level],
          ["Rules active", `${nf.format(p.active_rules)} active, ${nf.format(p.excluded_rules)} excluded (see Rules)`],
          ["Configuration", el("code", { class: "wrap" }, l.engine.config)]])) : card("Running configuration", el("p", { class: "empty" }, "No start record has been read yet.")),
        card("Runs", el("p", { class: "muted" }, "Each start of the IDS. A new configuration fingerprint means the rules or settings changed."),
          el("div", { class: "table-wrap" }, el("table", {},
            el("thead", {}, el("tr", {}, ["Started", "Run", "Rules", "Level", "Configuration"].map((h) => el("th", {}, h)))),
            el("tbody", {}, runs)))),
        card("Record files", kv([
          ["Records kept", nf.format(p.records)],
          ["Oldest", when(p.oldest_record)],
          ["Newest", when(p.newest_record)],
          ["Unreadable lines", p.unreadable_lines ? nf.format(p.unreadable_lines) : "none"]]),
          el("div", { class: "table-wrap" }, el("table", {},
            el("thead", {}, el("tr", {}, el("th", {}, "File"), el("th", { class: "num" }, "Size"), el("th", {}, "Last written"))),
            el("tbody", {}, p.files.map((f) => el("tr", {}, el("td", { class: "mono" }, f.name), el("td", { class: "num" }, bytes(f.size)), el("td", {}, when(f.modified))))))))));
    });
  }

  const pages = { overview: overviewPage, alerts: alertsPage, alert: alertPage, rules: rulesPage, engine: enginePage };
  if (pages[page] && view) pages[page]();
})();
