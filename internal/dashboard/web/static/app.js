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
  const nf = new Intl.NumberFormat("en-US");
  const pf = new Intl.NumberFormat("en-US", { style: "percent", maximumFractionDigits: 1 });
  const SVG = "http://www.w3.org/2000/svg";
  const pageSize = 50; // rows per page of the alerts list, as in query.go

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

  // refill replaces a node's children as append adds them: lists are
  // flattened and null is skipped (replaceChildren would write "null").
  function refill(node, ...children) {
    node.replaceChildren();
    append(node, children);
  }

  function svg(tag, attrs) {
    const node = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, String(v));
    return node;
  }

  // stored and store keep small choices of this browser: the period, the
  // theme, and the list an alert was opened from. Without storage (a
  // private window, blocked site data) the defaults hold.
  function stored(kind, key) {
    try { return window[kind].getItem(key); } catch (e) { return null; }
  }

  function store(kind, key, value) {
    try { window[kind].setItem(key, value); } catch (e) { /* not kept */ }
  }

  // ---- Times (U6): one style everywhere, 24-hour, in the browser's zone ----

  const thisYear = new Date().getFullYear();
  const fmtDay = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric" });
  const fmtDayYear = new Intl.DateTimeFormat("en-US", { year: "numeric", month: "short", day: "numeric" });
  const fmtClock = new Intl.DateTimeFormat("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" });
  const fmtHM = new Intl.DateTimeFormat("en-US", { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });

  function toDate(v) {
    if (!v) return null;
    const d = v instanceof Date ? v : new Date(v);
    return isNaN(d) || d.getFullYear() < 1970 ? null : d;
  }

  function day(d) {
    return (d.getFullYear() === thisYear ? fmtDay : fmtDayYear).format(d);
  }

  // fmtTime writes a moment as "Oct 23, 23:52:48", with the year only when
  // it is not this year.
  function fmtTime(v) {
    const d = toDate(v);
    return d ? `${day(d)}, ${fmtClock.format(d)}` : "–";
  }

  // fmtSpan writes a period: "Oct 24, 00:00–00:30", or "Oct 23, 18:00 –
  // Oct 24, 00:00" across days.
  function fmtSpan(from, to) {
    const a = toDate(from), b = toDate(to);
    if (!a || !b) return "–";
    if (a.toDateString() === b.toDateString()) return `${day(a)}, ${fmtHM.format(a)}–${fmtHM.format(b)}`;
    return `${day(a)}, ${fmtHM.format(a)} – ${day(b)}, ${fmtHM.format(b)}`;
  }

  // ago writes how long ago a moment was: "3 min ago".
  function ago(v) {
    const d = toDate(v);
    if (!d) return "";
    const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
    const days = Math.floor(s / 86400);
    return days === 1 ? "1 day ago" : `${days} days ago`;
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

  function query(params) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== "" && v !== undefined && v !== null) q.set(k, v);
    return q.toString();
  }

  // ---- Attack groups and score categories ----

  // groups mirrors the table in store.go: the attack group of a rule, by
  // the number of its CRS file. A Go test checks that the two agree.
  const groups = {
    901: "Setup", 905: "Common exceptions", 911: "Method enforcement", 913: "Scanner detection",
    920: "Protocol enforcement", 921: "Protocol attack", 922: "Multipart attack",
    930: "Path traversal and file access", 931: "Remote file inclusion", 932: "Remote command execution",
    933: "PHP injection", 934: "Generic attack", 941: "Cross-site scripting", 942: "SQL injection",
    943: "Session fixation", 944: "Java attack", 949: "Anomaly score",
  };
  const notAttacks = [901, 905, 949];
  const attackGroups = Object.entries(groups).filter(([n]) => !notAttacks.includes(Number(n))).map(([, g]) => g).concat("Other");
  const groupOf = (id) => groups[Math.floor(id / 1000)] || "Other";
  const scoring = (id) => Math.floor(id / 1000) === 949;

  // categories names the per-attack scores of CRS after the rule files that
  // raise them in CRS 4.30.0: rce is raised by files 932, 934 and 944, and
  // http_violation by 920 and 921.
  const categories = {
    lfi: "Path traversal and file access", rfi: "Remote file inclusion",
    rce: "Command execution (RCE, generic, Java)", php_injection: "PHP injection",
    xss: "Cross-site scripting", sql_injection: "SQL injection",
    session_fixation: "Session fixation", http_violation: "HTTP protocol violation",
  };

  // ---- Data from the server ----

  // api fetches a JSON answer. Without a login the page goes to the login,
  // which brings it back here (U8).
  async function api(path) {
    const res = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (res.status === 401) {
      location.assign("/login?" + query({ next: location.pathname + location.search }));
      throw new Error("login required");
    }
    let data;
    try {
      data = await res.json();
    } catch (e) {
      throw new Error(res.ok ? "the answer could not be read" : `${res.status} ${res.statusText}`);
    }
    if (!res.ok) {
      const err = new Error(data.error || res.statusText);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  // last is the previous answer, so that a poll that brings nothing new
  // leaves the page alone: an open section, the focus and a tooltip stay.
  let last = "";

  // same reports whether an answer is the one shown already. The end of
  // the period ("range") moves on every call and is left out.
  function same(key, data) {
    const text = key + "\n" + JSON.stringify(data, (k, v) => (k === "range" ? undefined : v));
    if (text === last) return true;
    last = text;
    return false;
  }

  // drawn is true once the view shows data.
  let drawn = false;

  // replace puts a new view on screen. Unless the user just changed what
  // is shown, a section the user opened or closed stays that way.
  function replace(node, keep = true) {
    const was = new Map();
    if (keep) for (const d of view.querySelectorAll("details[data-key]")) was.set(d.dataset.key, d.open);
    view.replaceChildren(node);
    for (const d of view.querySelectorAll("details[data-key]")) {
      if (was.has(d.dataset.key)) d.open = was.get(d.dataset.key);
    }
    fitChips(view);
    drawn = true;
    view.classList.remove("loading");
  }

  // ---- Live updates (V6, U5) ----

  const live = {
    box: document.getElementById("live"),
    text: document.getElementById("updated"),
    button: document.getElementById("pause"),
    notice: document.getElementById("notice"),
    paused: false,
    stale: false,
    at: null,
    run: null,
  };

  function showLive() {
    if (!live.box) return;
    live.box.classList.toggle("paused", live.paused);
    live.box.classList.toggle("stale", live.stale);
    const state = live.paused ? "Paused" : live.stale ? "Not updating" : "Live";
    live.text.textContent = state + (live.at ? " · updated " + fmtClock.format(live.at) : "");
    live.button.textContent = live.paused ? "Resume" : "Pause";
    live.button.setAttribute("aria-pressed", String(live.paused));
  }

  if (live.button) {
    live.button.addEventListener("click", () => {
      live.paused = !live.paused;
      showLive();
      if (!live.paused && live.run) live.run();
    });
  }

  function succeeded() {
    live.at = new Date();
    live.stale = false;
    if (live.notice) live.notice.hidden = true;
    view.classList.remove("loading");
    showLive();
  }

  // failed shows an error. Data already on screen stays there, with a bar
  // above it (P1); only a page that has nothing yet shows the error alone.
  function failed(err) {
    view.classList.remove("loading");
    if (!drawn || !live.notice) {
      last = ""; // the next answer must replace the message
      view.replaceChildren(el("p", { class: "error", role: "alert" }, "Could not load the data: ", err.message));
      return;
    }
    live.stale = true;
    refill(live.notice, `Could not update: ${err.message}. ` +
      (live.at ? `The data below is from ${fmtClock.format(live.at)}. ` : "") +
      `Trying again every ${poll / 1000} seconds.`);
    live.notice.hidden = false;
    showLive();
  }

  // every runs load now and then every few seconds, unless paused. A run
  // asked for while one is under way follows it, so a change the user
  // makes is never lost.
  function every(load) {
    let busy = false, again = false;
    const run = async () => {
      if (busy) { again = true; return; }
      busy = true;
      do {
        again = false;
        try {
          await load();
          succeeded();
        } catch (err) {
          if (err.message !== "login required") failed(err);
        }
      } while (again);
      busy = false;
    };
    live.run = run;
    run();
    setInterval(() => { if (!live.paused) run(); }, poll);
    return run;
  }

  // ---- The period (P5) ----

  const ranges = ["1h", "24h", "7d", "all"];

  // period is the chosen time range: from the address, else the last
  // choice in this browser, else 24 hours.
  const period = {
    value: (() => {
      const v = new URLSearchParams(location.search).get("range") || stored("localStorage", "ids.range");
      return ranges.includes(v) ? v : "24h";
    })(),
    group: document.getElementById("period"),
    show(none) {
      if (!this.group) return;
      for (const b of this.group.querySelectorAll("button")) b.setAttribute("aria-pressed", String(!none && b.dataset.value === this.value));
    },
    onChange(fn) {
      if (!this.group) return;
      this.show();
      this.group.addEventListener("click", (e) => {
        const b = e.target.closest("button[data-value]");
        if (!b) return;
        this.value = b.dataset.value;
        store("localStorage", "ids.range", this.value);
        this.show();
        fn(this.value);
      });
    },
  };

  // segmented wires a group of buttons of which one is pressed.
  function segmented(group, value, pick) {
    const show = (v) => {
      for (const b of group.querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.dataset.value === v));
    };
    show(value);
    group.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-value]");
      if (!b) return;
      show(b.dataset.value);
      pick(b.dataset.value);
    });
  }

  // ---- Small parts ----

  function badge(rec, incomplete = true) {
    return el("span", { class: "badges" },
      rec.alert ? el("span", { class: "badge alert" }, "Alert") : el("span", { class: "badge" }, "Below threshold"),
      incomplete && rec.incomplete ? el("span", { class: "badge incomplete" }, "Incomplete") : null);
  }

  function severity(s) {
    const kind = { CRITICAL: "critical", ERROR: "error", WARNING: "warning", NOTICE: "notice" }[String(s || "").toUpperCase()] || "none";
    return el("span", { class: "sev " + kind }, s || "no severity");
  }

  // chips lists short values. With max, it keeps to one line of at most max
  // chips: fitChips folds the ones that don't fit into a "+N" chip whose
  // tooltip names them.
  function chips(list, href, max) {
    list = (list || []).map(String);
    const one = max !== undefined;
    return el("span", { class: "chips" + (one ? " one" : ""), "data-max": one ? max : null },
      list.map((x) => {
        const title = one ? x : null; // the only chip left may still be cut short
        return href ? el("a", { class: "chip", href: href(x), title }, x) : el("span", { class: "chip", title }, x);
      }),
      one && list.length > 1 ? el("span", { class: "chip more", hidden: true }) : null);
  }

  // fitChips shows each one-line chip list in root with whole chips only
  // (P23): from the end, chips that don't fit their cell go into "+N".
  function fitChips(root) {
    for (const box of root.querySelectorAll(".chips.one")) {
      const items = [...box.children].filter((c) => !c.classList.contains("more"));
      const more = box.querySelector(".chip.more");
      let shown = Math.min(items.length, Number(box.dataset.max) || items.length);
      const show = () => {
        items.forEach((c, i) => { c.hidden = i >= shown; });
        if (!more) return;
        const rest = items.slice(shown).map((c) => c.textContent);
        more.hidden = rest.length === 0;
        more.textContent = `+${rest.length}`;
        more.title = rest.join(", ");
      };
      box.classList.add("measure"); // whole widths: no chip shrinks
      show();
      while (shown > 1 && box.scrollWidth > box.clientWidth + 1) {
        shown--;
        show();
      }
      box.classList.remove("measure");
    }
  }

  let fitting = null;
  window.addEventListener("resize", () => {
    clearTimeout(fitting);
    fitting = setTimeout(() => { if (view) fitChips(view); }, 150);
  });

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

  // copyButton copies text to the clipboard (the page is HTTPS).
  function copyButton(text, what) {
    return el("button", {
      type: "button", class: "copy", title: "Copy " + what, "aria-label": "Copy " + what,
      onclick: async (e) => {
        const b = e.currentTarget;
        try {
          await navigator.clipboard.writeText(text);
          b.textContent = "Copied";
        } catch (err) {
          b.textContent = "Not copied";
        }
        setTimeout(() => { b.textContent = "Copy"; }, 1500);
      },
    }, "Copy");
  }

  // ---- Overview ----

  // tile is a number with a label and notes below it, one line each.
  function tile(label, value, notes, hero) {
    return el("div", { class: "card tile" + (hero ? " hero" : "") },
      el("div", { class: "label" }, label),
      el("div", { class: "value" }, nf.format(value)),
      [].concat(notes).filter(Boolean).map((n) => el("div", { class: "note" }, n)));
  }

  // columns draws records over time: alerts at the bottom, the other
  // records above them, with a tooltip per column and a table twin. A bar
  // whose period has not ended is drawn lighter (P13). The chart is one tab
  // stop: the arrow keys move between bars (P16), and a click or Enter
  // lists the records of a bar (P19).
  function columns(o, pick) {
    const series = o.series, n = series.length, width = o.bucket_seconds * 1000;
    const end = toDate(o.range.to);
    const ends = (b) => new Date(toDate(b.start).getTime() + width);
    const partial = (b) => end !== null && ends(b) > end;

    const wrap = el("div", {
      class: "chart", tabindex: 0, role: "group",
      "aria-label": "Records over time. The arrow keys move between bars; Enter lists the records of a bar.",
    });
    const W = Math.max(300, Math.round(view.clientWidth - 34)), H = 200, top = 8, left = 40, bottom = 24;
    const plotW = W - left - 8, plotH = H - top - bottom;
    const maxV = Math.max(1, ...series.map((b) => b.records));
    const step = niceStep(maxV);
    const yMax = Math.ceil(maxV / step) * step;
    const y = (v) => top + plotH - (v / yMax) * plotH;
    const band = plotW / n;
    const barW = Math.max(2, Math.min(24, band - 2));

    const chart = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Records and alerts over time" });
    for (let v = 0; v <= yMax; v += step) {
      chart.append(svg("line", { class: v === 0 ? "baseline" : "gridline", x1: left, x2: W - 8, y1: y(v), y2: y(v) }));
      const t = svg("text", { class: "tick", x: left - 6, y: y(v) + 4, "text-anchor": "end" });
      t.textContent = compact(v);
      chart.append(t);
    }
    const tip = el("div", { class: "tooltip", hidden: true, "aria-live": "polite" });
    const hits = [];
    let active = -1;

    const show = (i) => {
      const b = series[i], others = b.records - b.alerts;
      if (active >= 0) hits[active].classList.remove("active");
      active = i;
      hits[i].classList.add("active");
      refill(tip,
        el("div", { class: "when" }, fmtSpan(b.start, ends(b)), partial(b) ? " (so far)" : ""),
        el("div", { class: "line" }, el("span", { class: "key alerts" }), el("strong", {}, nf.format(b.alerts)), "alerts"),
        el("div", { class: "line" }, el("span", { class: "key others" }), el("strong", {}, nf.format(others)), "other records"),
        el("div", { class: "line" }, el("span", { class: "key" }), el("strong", {}, nf.format(b.analysed)), "requests analysed"),
        b.records > 0 ? el("div", { class: "hint" }, "Click to list these records") : null);
      tip.hidden = false;
      const box = wrap.getBoundingClientRect();
      const px = ((left + (i + 0.5) * band) / W) * box.width;
      tip.style.left = Math.min(Math.max(0, px - 100), box.width - tip.offsetWidth) + "px";
      tip.style.top = "0px";
    };
    const hide = () => {
      tip.hidden = true;
      if (active >= 0) hits[active].classList.remove("active");
    };

    series.forEach((b, i) => {
      const x = left + i * band + (band - barW) / 2;
      const others = b.records - b.alerts;
      const part = partial(b) ? " partial" : "";
      if (b.alerts > 0) chart.append(svg("path", { class: "alerts" + part, d: barPath(x, y(b.alerts), barW, y(0) - y(b.alerts), others === 0) }));
      if (others > 0) {
        const gap = b.alerts > 0 ? 2 : 0; // a 2px surface gap between the two parts
        const h = y(b.alerts) - y(b.records) - gap;
        if (h > 0) chart.append(svg("path", { class: "others" + part, d: barPath(x, y(b.records), barW, h, true) }));
      }
      const hit = svg("rect", { class: "hit" + (b.records > 0 ? " has" : ""), x: left + i * band, y: top, width: band, height: plotH });
      hit.addEventListener("pointerenter", () => show(i));
      hit.addEventListener("pointerleave", hide);
      hit.addEventListener("click", () => { if (b.records > 0) pick(b.start, ends(b)); });
      hits.push(hit);
      chart.append(hit);
    });
    wrap.addEventListener("keydown", (e) => {
      const moves = { ArrowLeft: -1, ArrowRight: 1 };
      if (e.key in moves || e.key === "Home" || e.key === "End") {
        e.preventDefault();
        const from = active < 0 ? n - 1 : active;
        show(e.key === "Home" ? 0 : e.key === "End" ? n - 1 : Math.min(n - 1, Math.max(0, from + (active < 0 ? 0 : moves[e.key]))));
      } else if (e.key === "Enter" && active >= 0 && series[active].records > 0) {
        pick(series[active].start, ends(series[active]));
      } else if (e.key === "Escape") {
        hide();
      }
    });
    wrap.addEventListener("blur", hide);

    // Time labels at least 110 px apart, on round times of the browser's
    // zone (P15): every 10 minutes, 3 hours, at midnight… Each sits where
    // its moment falls, which may be inside a bar (UTC bars of 6 hours).
    // The day is written at the first label and where it changes; a label
    // at midnight is the day alone.
    const steps = [60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800, 2592000];
    const stepMs = 1000 * (steps.find((s) => s >= o.bucket_seconds && (s / o.bucket_seconds) * band >= 110) || o.bucket_seconds * Math.ceil(110 / band));
    const t0 = toDate(series[0].start).getTime();
    const offset = (ms) => new Date(ms).getTimezoneOffset() * 60000; // UTC minus local
    let prevDay = "";
    for (let local = Math.ceil((t0 - offset(t0)) / stepMs) * stepMs; ; local += stepMs) {
      const ms = local + offset(local);
      if (ms >= t0 + n * width) break;
      const d = new Date(ms), dayText = day(d);
      const midnight = d.getHours() === 0 && d.getMinutes() === 0;
      const text = midnight && stepMs >= 86400000 ? dayText : dayText !== prevDay ? `${dayText}, ${fmtHM.format(d)}` : fmtHM.format(d);
      prevDay = dayText;
      const x = left + ((ms - t0) / width) * band;
      let anchor = "middle";
      if (x - 40 < left) anchor = "start";
      else if (x + 40 > W - 8) anchor = "end";
      const t = svg("text", { class: "tick", x, y: H - 6, "text-anchor": anchor });
      t.textContent = text;
      chart.append(t);
    }
    wrap.append(chart, tip);

    const rows = series.filter((b) => b.records > 0 || b.analysed > 0);
    const table = el("details", { class: "table-view", "data-key": "table" }, el("summary", {}, "Show as a table"),
      el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, el("th", {}, "Period"), el("th", { class: "num" }, "Analysed"), el("th", { class: "num" }, "Records"), el("th", { class: "num" }, "Alerts"))),
        el("tbody", {}, rows.length ? rows.map((b) => el("tr", {},
          el("td", {}, fmtSpan(b.start, ends(b)), partial(b) ? " (so far)" : ""),
          el("td", { class: "num" }, nf.format(b.analysed)), el("td", { class: "num" }, nf.format(b.records)), el("td", { class: "num" }, nf.format(b.alerts))))
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

  // listTable is a table of records, one line each, that opens a record
  // on a click. Its rows are kept for the detail page's back link and
  // steps (P26).
  function listTable(rows, opts) {
    // Fixed column widths (app.css, table.list): a long request or many
    // chips is cut short in its cell instead of pushing the last column
    // out of the card.
    const cols = [["Time", "", "time"], ["Score", "num", "score"]];
    if (opts.status) cols.push(["Status", "", "status"]);
    cols.push(["Client", "", "client"], ["Request", "", "request"], ["Attack groups", "", "groups"]);
    if (opts.rules) cols.push(["Rules", "", "rules"]);
    const remember = () => store("sessionStorage", "ids.list", JSON.stringify({ url: location.pathname + location.search, ids: rows.map((r) => r.id) }));
    return el("div", { class: "table-wrap" }, el("table", { class: "wide rows list" },
      el("colgroup", {}, cols.map(([, , c]) => el("col", { class: c }))),
      el("thead", {}, el("tr", {}, cols.map(([h, c]) => el("th", { class: c }, h)))),
      el("tbody", {}, rows.map((r) => {
        const link = "/alerts/" + encodeURIComponent(r.id);
        const target = `${r.method} ${r.host || ""}${r.path}`;
        return el("tr", { class: "linked", onclick: (e) => { if (e.target.closest("a") === null) { remember(); location.assign(link); } } },
          el("td", {}, el("a", { href: link, onclick: remember }, fmtTime(r.time))),
          el("td", { class: "num" }, r.incomplete ? el("span", { class: "badge incomplete", title: "The analysis could not inspect every part" }, "Incomplete") : null, " ", nf.format(r.score)),
          opts.status ? el("td", {}, badge(r, false)) : null,
          el("td", { class: "mono", title: r.ip || null }, r.ip || "–"),
          el("td", {}, el("span", { class: "clip", title: target + (r.user_agent ? "\nUser-Agent: " + r.user_agent : "") },
            el("span", { class: "mono" }, r.method + " "), (r.host || "") + r.path)),
          el("td", {}, chips(r.groups, null, 3)),
          opts.rules ? el("td", {}, chips(r.rules.filter((id) => !scoring(id)), opts.rules, 3)) : null);
      }))));
  }

  function overviewPage() {
    const load = async () => {
      const range = period.value;
      const url = "/api/overview?" + query({ range });
      const [o, latest] = await Promise.all([api(url), api("/api/alerts?" + query({ range, kind: "alerts" }))]);
      const newest = latest.rows.slice(0, 8);
      if (same(url, { o, newest })) return;
      const alertsLink = (extra) => "/alerts?" + query({ range, ...extra });
      const nothing = o.recorded === 0 && o.analysed === 0;
      const share = (v) => (o.analysed > 0 ? pf.format(v / o.analysed) + " of requests analysed" : "");
      const pick = (from, to) => {
        const start = toDate(o.range.from);
        if (start && start > toDate(from)) from = start; // the first bar starts before the period
        location.assign("/alerts?" + query({ kind: "all", from: toDate(from).toISOString(), to: to.toISOString() }));
      };
      const ruleName = (i) => [el("strong", {}, i.key), " ", i.msg || i.label, i.msg ? el("span", { class: "muted" }, " · " + i.label) : null];
      replace(el("div", { class: "stack" },
        el("div", { class: "tiles" },
          tile("Alerts", o.alerts, o.analysed > 0 || o.last_alert ? [share(o.alerts), o.last_alert ? "last alert " + ago(o.last_alert) : ""] : "score reached the threshold", true),
          tile("Records", o.recorded, "a finding or an incomplete analysis"),
          tile("Requests analysed", o.analysed, "from the counts of the IDS"),
          tile("Incomplete analyses", o.incomplete, share(o.incomplete) || "parts that could not be inspected")),
        card("Records over time",
          el("div", { class: "legend" },
            el("span", { class: "key" }, el("span", { class: "swatch alerts" }), "Alerts"),
            el("span", { class: "key" }, el("span", { class: "swatch others" }), "Records below the threshold"),
            el("span", { class: "key" }, el("span", { class: "swatch partial" }), "Period not over yet")),
          nothing ? el("p", { class: "empty" }, "No records in this period. Run the IDS with records, or choose a longer period.") : columns(o, pick)),
        el("section", { class: "card" },
          el("div", { class: "card-head" }, el("h2", {}, "Latest alerts"), latest.total ? el("a", { href: alertsLink({}) }, `All ${nf.format(latest.total)} alerts →`) : null),
          newest.length ? listTable(newest, {}) : el("p", { class: "empty" }, "No alerts in this period.")),
        el("div", { class: "grid-2x2" },
          card("Rules that fired most", toplist(o.top_rules, ruleName, (i) => alertsLink({ kind: "all", rule: i.key }))),
          card("Attack groups", toplist(o.top_groups, (i) => i.key, (i) => alertsLink({ kind: "all", group: i.key }))),
          card("Where in the request", toplist(o.top_locations, (i) => i.key, (i) => alertsLink({ kind: "all", location: i.key }))),
          card("Client IP addresses", toplist(o.top_ips, (i) => i.key, (i) => alertsLink({ kind: "all", ip: i.key }))))));
    };
    const run = every(load);
    period.onChange((v) => {
      history.replaceState(null, "", "/?" + query({ range: v }));
      view.classList.add("loading");
      run();
    });
  }

  // ---- Alerts ----

  function alertsPage() {
    const form = document.getElementById("filters");
    const fresh = document.getElementById("fresh");
    const activeBox = document.getElementById("active");
    for (const g of attackGroups) form.elements.group.append(el("option", { value: g }, g));
    const params = new URLSearchParams(location.search);
    const state = {
      range: period.value,
      from: params.get("from") || "",
      to: params.get("to") || "",
      kind: ["alerts", "all", "incomplete"].includes(params.get("kind")) ? params.get("kind") : "alerts",
      page: Number(params.get("page")) || 1,
    };
    if (!state.from || !state.to) state.from = state.to = "";
    const fields = ["rule", "group", "ip", "location", "min_score", "sort"];
    for (const f of fields) if (params.has(f)) form.elements[f].value = params.get(f);
    if (!form.elements.sort.value) form.elements.sort.value = "time";

    const current = () => {
      const p = { kind: state.kind };
      if (state.from) Object.assign(p, { from: state.from, to: state.to });
      else p.range = state.range;
      for (const f of fields) p[f] = form.elements[f].value.trim();
      if (p.sort === "time") p.sort = "";
      return p;
    };
    const sync = () => history.replaceState(null, "", "/alerts?" + query({ ...current(), page: state.page > 1 ? state.page : "" }));

    let shown = null;      // the list on screen
    let pending = null;    // a newer answer, waiting for "Show"
    let ownChange = true;  // the next answer follows the user's own change: draw it at once
    const names = { alerts: ["alert", "alerts"], all: ["record", "records"], incomplete: ["incomplete analysis", "incomplete analyses"] };
    const what = (n = 2) => names[state.kind][n === 1 ? 0 : 1];

    // A poll that brings a changed list does not move the rows under the
    // pointer (P25): a bar offers the new list instead.
    const offer = (l) => {
      pending = l;
      const added = l.total - shown.total;
      refill(fresh,
        added > 0 ? `${nf.format(added)} new ${what(added)}.` : "The list has changed.",
        el("button", { type: "button", class: "small", onclick: () => draw(pending) }, "Show"));
      fresh.hidden = false;
    };

    const pager = (l, where) => {
      const first = l.total ? (l.page - 1) * pageSize + 1 : 0, lastN = Math.min(l.total, l.page * pageSize);
      const order = form.elements.sort.value === "score" ? "highest score first" : "newest first";
      const go = (to) => () => {
        state.page = to;
        ownChange = true;
        sync();
        view.classList.add("loading");
        run();
        if (where === "bottom") window.scrollTo(0, 0);
      };
      return el("div", { class: "pager " + where },
        el("span", { class: "muted" }, l.total ? `${nf.format(first)}–${nf.format(lastN)} of ${nf.format(l.total)} ${what()} · ${order}` : ""),
        el("span", { class: "grow" }),
        l.pages > 1 ? [
          el("button", { type: "button", class: "small", disabled: l.page <= 1, onclick: go(l.page - 1) }, "← Newer"),
          el("span", { class: "muted" }, `Page ${l.page} of ${l.pages}`),
          el("button", { type: "button", class: "small", disabled: l.page >= l.pages, onclick: go(l.page + 1) }, "Older →")] : null);
    };

    const draw = (l) => {
      shown = l;
      pending = null;
      fresh.hidden = true;
      const ruleLink = (id) => "/alerts?" + query({ ...current(), rule: id });
      replace(card(null,
        l.rows.length ? [pager(l, "top"), listTable(l.rows, { status: state.kind === "all", rules: ruleLink }), l.pages > 1 ? pager(l, "bottom") : null]
          : el("p", { class: "empty" }, `No ${what()} match these filters.`)), false);
    };

    const load = async () => {
      const url = "/api/alerts?" + query({ ...current(), page: state.page });
      const l = await api(url);
      if (l.pages < state.page && state.page > 1) {
        state.page = l.pages;
        sync();
        return load();
      }
      if (same(url, l)) return;
      if (shown && !ownChange) {
        offer(l);
        return;
      }
      ownChange = false;
      draw(l);
    };

    // The active filters, each with a button that removes it (P22).
    const showActive = () => {
      const items = [];
      if (state.from) items.push([`Period ${fmtSpan(state.from, state.to)}`, () => { state.from = state.to = ""; period.show(); }]);
      const labels = { rule: "Rule", group: "Group", ip: "IP", location: "Location", min_score: "Score at least" };
      for (const [f, label] of Object.entries(labels)) {
        const v = form.elements[f].value.trim();
        if (v) items.push([`${label} ${v}`, () => { form.elements[f].value = ""; }]);
      }
      activeBox.hidden = items.length === 0;
      refill(activeBox,
        items.map(([text, clear]) => el("button", { type: "button", class: "filter-chip", "aria-label": "Remove the filter " + text, onclick: () => { clear(); apply(); } }, text, el("span", { "aria-hidden": "true" }, " ×"))),
        items.length ? el("button", { type: "button", class: "link", onclick: () => { for (const [, clear] of items) clear(); apply(); } }, "Clear filters") : null);
    };

    const apply = () => {
      state.page = 1;
      ownChange = true;
      sync();
      showActive();
      view.classList.add("loading");
      run();
    };

    segmented(document.getElementById("kind"), state.kind, (v) => { state.kind = v; apply(); });
    period.onChange((v) => { state.range = v; state.from = state.to = ""; apply(); });
    period.show(state.from !== "");
    let typing = null;
    form.addEventListener("submit", (e) => { e.preventDefault(); clearTimeout(typing); apply(); });
    form.addEventListener("input", (e) => {
      if (e.target.tagName !== "INPUT") return;
      clearTimeout(typing);
      typing = setTimeout(apply, 400);
    });
    form.addEventListener("change", (e) => { if (e.target.tagName === "SELECT") apply(); });
    showActive();
    const run = every(load);
  }

  // ---- One alert ----

  async function alertPage() {
    const id = body.dataset.id;
    const back = document.getElementById("back");

    // The list this record was opened from: the back link returns to it,
    // with its filters, and the steps go through it (P26, P30).
    let list = null;
    try { list = JSON.parse(stored("sessionStorage", "ids.list") || "null"); } catch (e) { list = null; }
    if (list && Array.isArray(list.ids) && typeof list.url === "string" && list.url.startsWith("/") && !list.url.startsWith("//") && list.ids.includes(id)) {
      back.href = list.url;
      if (list.url.startsWith("/alerts")) back.textContent = "← Back to the list";
      else back.textContent = "← Back";
      const i = list.ids.indexOf(id);
      const step = (a, other) => {
        if (!other) return;
        a.href = "/alerts/" + encodeURIComponent(other);
        a.hidden = false;
      };
      step(document.getElementById("newer"), list.ids[i - 1]);
      step(document.getElementById("older"), list.ids[i + 1]);
    }

    let r;
    try {
      r = await api("/api/records/" + encodeURIComponent(id));
    } catch (err) {
      if (err.message === "login required") return;
      if (err.status === 404) {
        replace(card(null, el("h1", {}, "Record not found"),
          el("p", {}, "This record is no longer kept, or the address is wrong. Record files rotate: when the newest file is full, the oldest is removed.")));
      } else {
        failed(err);
      }
      return;
    }
    const req = r.request || {}, a = r.analysis || {}, s = r.score || {}, e = r.engine || {};
    const findings = r.findings || [];
    const attack = findings.filter((f) => !scoring(f.rule_id));
    const scores = findings.filter((f) => scoring(f.rule_id));
    const hitGroups = [...new Set(attack.map((f) => groupOf(f.rule_id)))];
    const ip = r.client && r.client.ip;
    const line = `${req.method} ${req.path}${req.query ? "?" + req.query : ""} ${req.version || ""}`.trim();
    document.title = `${r.alert ? "Alert" : "Record"} ${fmtTime(r.time)} · IDS dashboard`;

    // One entry per rule, in the order the rules matched; the places it
    // matched open below it (P29). The score rule is not a finding of its
    // own: the score is in the title.
    const byRule = new Map();
    for (const f of attack) {
      if (!byRule.has(f.rule_id)) byRule.set(f.rule_id, []);
      byRule.get(f.rule_id).push(f);
    }
    const openAll = attack.length <= 8;
    const ruleEntries = [...byRule].map(([rule, places]) => {
      const f = places[0];
      return el("details", { class: "finding", "data-key": "rule-" + rule, open: openAll },
        el("summary", {},
          el("a", { href: "/alerts?" + query({ kind: "all", rule, range: "all" }), title: "Every record of this rule" }, String(rule)),
          severity(f.severity),
          el("span", { class: "msg" }, f.message || "–"),
          el("span", { class: "muted" }, groupOf(rule)),
          el("span", { class: "muted nowrap" }, places.length === 1 ? "1 place" : `${places.length} places`),
          f.matched ? el("span", { class: "first" }, f.location + ": ", el("code", {}, short(f.matched, 120))) : null),
        el("div", { class: "table-wrap" }, el("table", {},
          el("thead", {}, el("tr", {}, el("th", {}, "Where"), el("th", {}, "Matched"), el("th", {}, "Rule data"))),
          el("tbody", {}, places.map((p) => el("tr", {},
            el("td", { class: "mono loc" }, p.location || "–"),
            el("td", { class: "wrap" }, p.matched ? el("code", {}, p.matched) : "–", p.message !== f.message ? el("div", { class: "sub" }, p.message) : null),
            el("td", { class: "wrap sub" }, p.data || "–")))))));
    });

    const categoryList = Object.entries(s.categories || {});
    // Some rules add to the total only, so the categories can sum to less:
    // in CRS 4.30.0 the rules of files 911, 913 and 922, and all of 920 but
    // one.
    const uncategorised = (s.total || 0) - categoryList.reduce((n, [, v]) => n + v, 0);
    const json = JSON.stringify(r, null, 2);
    const clientCount = el("span", { class: "muted" }, "…");
    replace(el("div", { class: "stack" },
      el("div", { class: "detail-head" },
        el("h1", { class: "request-title" }, el("span", { class: "method" }, (req.method || "?") + " "), short(`${req.path || ""}${req.query ? "?" + req.query : ""}`, 200)),
        el("p", { class: "summary" },
          badge({ alert: r.alert, incomplete: !a.complete }),
          el("span", {}, fmtTime(r.time)),
          el("span", {}, "from ", ip || "an unknown address"),
          hitGroups.length ? el("span", {}, hitGroups.join(", ")) : null,
          el("span", {}, `score ${s.total} / ${s.threshold}`))),
      el("div", { class: "grid-2" },
        card("Decision", kv([
          ["Score", `${s.total} (threshold ${s.threshold})`],
          ["By category", categoryList.length || uncategorised > 0 ? el("ul", { class: "plain" },
            categoryList.map(([k, v]) =>
              el("li", {}, categories[k] || k, " ", el("strong", {}, String(v)), " ", el("span", { class: "muted" }, `(${k})`))),
            uncategorised > 0 ? el("li", { title: "These rules add to the total score only, such as most protocol rules (CRS files 911, 913, 920 and 922)." },
              "No category ", el("strong", {}, String(uncategorised)), " ", el("span", { class: "muted" }, "(rules that add to the total only)")) : null) : ""],
          ["Decided by", r.decided_by],
          ["Record", [el("code", {}, r.id), copyButton(r.id, "the record ID")]],
          ["Run", el("code", {}, r.run)]])),
        card("Who and where", kv([
          ["Client IP", ip ? [el("a", { href: "/alerts?" + query({ kind: "all", ip, range: "all" }) }, ip), copyButton(ip, "the IP address")] : "not known"],
          ["Last 24 hours", ip ? clientCount : ""],
          ["Client port", r.client && r.client.port],
          ["Host", r.server && r.server.host],
          ["Server address", r.server && r.server.ip ? `${r.server.ip}${r.server.port ? ":" + r.server.port : ""}` : ""]]))),
      card("Request", kv([
        ["Request line", [el("code", { class: "wrap" }, line), copyButton(line, "the request line")]],
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
      el("section", { class: "card" },
        el("h2", {}, `Findings: ${byRule.size} ${byRule.size === 1 ? "rule" : "rules"}, ${attack.length} ${attack.length === 1 ? "place" : "places"}`),
        ruleEntries.length ? el("div", { class: "findings" }, ruleEntries) : el("p", { class: "muted" }, "No rule matched; the record was written because the analysis is incomplete."),
        scores.map((f) => el("p", { class: "muted" }, `Score rule ${f.rule_id}: ${f.message}`))),
      r.full ? card("Full request (full_requests is on)",
        el("div", { class: "table-wrap" }, el("table", {}, el("tbody", {}, r.full.headers.map(([n, v]) => el("tr", {}, el("th", {}, n), el("td", { class: "mono wrap" }, v)))))),
        r.full.body ? el("pre", { class: "block" }, r.full.body) : null) : null,
      el("details", { class: "card", "data-key": "raw" }, el("summary", {}, "The record as JSON"),
        el("div", { class: "raw-tools" }, copyButton(json, "the record as JSON")),
        el("pre", { class: "block" }, json)),
      el("details", { class: "card", "data-key": "engine" }, el("summary", {}, "Engine"), kv([
        ["Version", `${e.version}${e.revision ? " (" + e.revision.slice(0, 12) + ")" : ""}`],
        ["Rules", e.crs],
        ["Paranoia level", e.paranoia_level],
        ["Configuration", el("code", { class: "wrap" }, e.config)]]))));

    // How often this client appears: records and alerts of the last day.
    if (ip) {
      try {
        const [all, alerts] = await Promise.all([
          api("/api/alerts?" + query({ kind: "all", ip, range: "24h" })),
          api("/api/alerts?" + query({ kind: "alerts", ip, range: "24h" }))]);
        clientCount.className = "";
        clientCount.replaceChildren(el("a", { href: "/alerts?" + query({ kind: "all", ip, range: "24h" }) },
          `${nf.format(all.total)} ${all.total === 1 ? "record" : "records"}, ${nf.format(alerts.total)} ${alerts.total === 1 ? "alert" : "alerts"}`));
      } catch (err) {
        clientCount.textContent = "could not be counted";
      }
    }
  }

  // ---- Rules ----

  function rulesPage() {
    const form = document.getElementById("filters");
    let data = null;
    let own = true; // the user changed the filters: sections open as the filters say
    const status = (r, level) => (!r.active ? "excluded" : (r.paranoia_level || 0) > level ? "above" : "runs");

    const statusCell = (r, level) => {
      switch (status(r, level)) {
        case "excluded":
          return [el("span", { class: "badge excluded" }, "Excluded"), el("div", { class: "sub" }, r.reason)];
        case "above":
          return el("span", { class: "badge above", title: `Its paranoia level ${r.paranoia_level} is above the level the rules run at (${level}), so the CRS gate rule skips it.` }, `Above level ${level}`);
        default:
          return el("span", { class: "badge active" }, "Runs");
      }
    };

    const draw = () => {
      if (!data) return;
      if (!data.run) {
        replace(card(null, el("p", { class: "empty" }, "No start record has been read yet.")));
        return;
      }
      const f = Object.fromEntries(new FormData(form));
      const q = (f.q || "").trim().toLowerCase();
      const level = data.engine.paranoia_level;
      const counts = { runs: 0, above: 0, excluded: 0 };
      for (const r of data.rules) counts[status(r, level)]++;
      const match = (r) =>
        (f.status === "" || f.status === status(r, level) || (f.status === "fired" && r.fired > 0)) &&
        (f.level === "" || String(r.paranoia_level || 0) === f.level) &&
        (q === "" || String(r.id).includes(q) || r.file.toLowerCase().includes(q) || r.group.toLowerCase().includes(q) || (r.msg || "").toLowerCase().includes(q));

      // One section per rule file, in load order (U2, P32).
      const files = new Map();
      for (const r of data.rules) {
        if (!files.has(r.file)) files.set(r.file, []);
        files.get(r.file).push(r);
      }
      let sections = [...files].map(([file, rules]) => ({
        file, rules, shown: rules.filter(match),
        fired: rules.filter((r) => r.fired > 0).length,
        times: rules.reduce((n, r) => n + r.fired, 0),
      })).filter((sec) => sec.shown.length > 0);
      if (f.sort === "fired") {
        sections.sort((a, b) => b.times - a.times);
        for (const sec of sections) sec.shown.sort((a, b) => b.fired - a.fired || a.id - b.id);
      }
      const filtering = q !== "" || f.status !== "" || f.level !== "";
      const shownCount = sections.reduce((n, sec) => n + sec.shown.length, 0);

      // Sections start closed, so the page is a list of the files with what
      // fired in each; a filter opens the sections with matching rules.
      const section = (sec) => el("details", { class: "card section", "data-key": "file-" + sec.file, open: filtering },
        el("summary", {},
          el("span", { class: "file mono" }, sec.file),
          el("span", { class: "muted" }, sec.rules[0].group),
          el("span", { class: "counts muted" }, `${sec.rules.length} ${sec.rules.length === 1 ? "rule" : "rules"} · ${sec.fired} fired` +
            (sec.shown.length < sec.rules.length ? ` · ${sec.shown.length} shown` : ""))),
        // The same column widths in every section (app.css, table.rules).
        el("div", { class: "table-wrap" }, el("table", { class: "wide rules" },
          el("colgroup", {}, ["id", "msg", "line", "phase", "level", "status", "fired"].map((c) => el("col", { class: c }))),
          el("thead", {}, el("tr", {}, ["Rule", "Description", "Line", "Phase", "Level", "Status", "Fired"].map((h, i) => el("th", { class: i === 6 ? "num" : "" }, h)))),
          el("tbody", {}, sec.shown.map((r) => el("tr", {},
            el("td", {}, r.fired ? el("a", { href: "/alerts?" + query({ kind: "all", rule: r.id, range: f.range }) }, String(r.id)) : String(r.id)),
            el("td", { class: "wrap" }, r.msg || el("span", { class: "muted" }, "–")),
            el("td", {}, String(r.line)),
            el("td", {}, String(r.phase)),
            el("td", {}, r.paranoia_level ? String(r.paranoia_level) : "–"),
            el("td", { class: "wrap" }, statusCell(r, level)),
            el("td", { class: "num" }, nf.format(r.fired))))))));

      replace(el("div", { class: "stack" },
        el("p", { class: "muted" }, `${nf.format(data.rules.length)} rules of ${data.engine.crs} at paranoia level ${level}: ` +
          `${nf.format(counts.runs)} run, ${nf.format(counts.above)} are above the level and skipped, ${nf.format(counts.excluded)} are excluded. ` +
          `Showing ${nf.format(shownCount)}. From the run that started ${fmtTime(data.time)}.`),
        sections.length ? sections.map(section) : card(null, el("p", { class: "empty" }, "No rule matches these filters."))), !own);
      own = false;
    };

    // The period buttons are outside the form; FormData reads it from here.
    const rangeField = el("input", { type: "hidden", name: "range", value: period.value });
    form.append(rangeField);
    // The filters are kept in the address, as on the alerts page, so that
    // a link or the back button shows the same rules.
    const params = new URLSearchParams(location.search);
    const fields = ["status", "level", "q", "sort"];
    for (const f of fields) if (params.has(f)) form.elements[f].value = params.get(f);
    const sync = () => {
      const p = { range: period.value };
      for (const f of fields) p[f] = form.elements[f].value.trim();
      if (p.sort === "id") p.sort = "";
      history.replaceState(null, "", "/rules?" + query(p));
    };
    const run = every(async () => {
      const url = "/api/rules?" + query({ range: period.value });
      const d = await api(url);
      if (same(url, d)) return;
      data = d;
      draw();
    });
    period.onChange((v) => {
      rangeField.value = v;
      sync();
      view.classList.add("loading");
      run();
    });
    form.addEventListener("submit", (e) => e.preventDefault());
    form.addEventListener("input", () => { own = true; sync(); draw(); });
    const openAll = (open) => () => { for (const d of view.querySelectorAll("details.section")) d.open = open; };
    document.getElementById("open-all").addEventListener("click", openAll(true));
    document.getElementById("close-all").addEventListener("click", openAll(false));
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
          el("td", { class: "nowrap" }, fmtTime(r.time)),
          el("td", { class: "mono" }, r.run),
          el("td", {}, r.engine.crs),
          el("td", {}, String(r.engine.paranoia_level)),
          el("td", { class: "num" }, nf.format(r.analysed)),
          el("td", { class: "num" }, nf.format(r.records)),
          el("td", { class: "num" }, nf.format(r.alerts)),
          el("td", { class: "nowrap" }, el("code", { title: r.engine.config }, short(r.engine.config, 20)), copyButton(r.engine.config, "the fingerprint"),
            changed ? [" ", el("span", { class: "chip changed", title: "The configuration is not the one of the run before" }, "changed")] : null));
      });
      const level = l ? l.engine.paranoia_level : 0;
      replace(el("div", { class: "stack" },
        l ? card("Running configuration", kv([
          ["Started", fmtTime(l.time)],
          ["Run", el("code", {}, l.run)],
          ["Engine", `${l.engine.version}${l.engine.revision ? " (" + l.engine.revision.slice(0, 12) + ")" : ""}`],
          ["Rules", l.engine.crs],
          ["Paranoia level", l.engine.paranoia_level],
          ["Rule status", el("a", { href: "/rules" }, `${nf.format(p.active_rules - p.above_level_rules)} run, ` +
            `${nf.format(p.above_level_rules)} above level ${level}, ${nf.format(p.excluded_rules)} excluded`)],
          ["Configuration", [el("code", { class: "wrap" }, l.engine.config), copyButton(l.engine.config, "the fingerprint")]]]))
          : card("Running configuration", el("p", { class: "empty" }, "No start record has been read yet.")),
        card("Runs", el("p", { class: "muted" }, "Each start of the IDS, newest first. A new configuration fingerprint means the rules or settings changed. Records and alerts count what is still kept."),
          el("div", { class: "table-wrap" }, el("table", { class: "wide" },
            el("thead", {}, el("tr", {}, [["Started", ""], ["Run", ""], ["Rules", ""], ["Level", ""], ["Analysed", "num"], ["Records", "num"], ["Alerts", "num"], ["Configuration", ""]].map(([h, c]) => el("th", { class: c }, h)))),
            el("tbody", {}, runs)))),
        card("Record files", kv([
          ["Records kept", nf.format(p.records)],
          ["Oldest", fmtTime(p.oldest_record)],
          ["Newest", fmtTime(p.newest_record)],
          ["Unreadable lines", p.unreadable_lines ? nf.format(p.unreadable_lines) : "none"]]),
          el("div", { class: "table-wrap" }, el("table", {},
            el("thead", {}, el("tr", {}, el("th", {}, "File"), el("th", { class: "num" }, "Size"), el("th", {}, "Last written"))),
            el("tbody", {}, p.files.map((f) => el("tr", {}, el("td", { class: "mono" }, f.name), el("td", { class: "num" }, bytes(f.size)), el("td", {}, fmtTime(f.modified))))))))));
    });
  }

  // ---- Login ----

  function loginPage() {
    const form = document.getElementById("login");
    if (!form) return;
    const button = form.querySelector("button[type=submit]");
    // The password check takes a moment on purpose (PBKDF2); show it (P10).
    form.addEventListener("submit", () => {
      button.disabled = true;
      button.textContent = "Logging in…";
    });
    // Coming back with the browser's back button shows the form ready again.
    window.addEventListener("pageshow", () => {
      button.disabled = false;
      button.textContent = "Log in";
    });
    const password = form.elements.password, caps = document.getElementById("caps");
    const check = (e) => { if (e.getModifierState) caps.hidden = !e.getModifierState("CapsLock"); };
    password.addEventListener("keydown", check);
    password.addEventListener("keyup", check);
    password.addEventListener("blur", () => { caps.hidden = true; });
  }

  // ---- Every page ----

  const zone = document.getElementById("zone");
  if (zone) {
    const minutes = -new Date().getTimezoneOffset(), m = Math.abs(minutes);
    const utc = `UTC${minutes < 0 ? "−" : "+"}${String(Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;
    let name = "";
    try { name = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (e) { name = ""; }
    zone.textContent = ` · times are in ${name ? `${name} (${utc})` : utc}`;
  }

  // The colour theme (U7): the system's, or one chosen here. theme.js
  // applies a stored choice before the page is drawn.
  const theme = document.getElementById("theme");
  if (theme) {
    theme.value = document.documentElement.dataset.theme || "";
    theme.addEventListener("change", () => {
      if (theme.value) document.documentElement.dataset.theme = theme.value;
      else delete document.documentElement.dataset.theme;
      store("localStorage", "ids.theme", theme.value);
    });
  }

  const pages = { overview: overviewPage, alerts: alertsPage, alert: alertPage, rules: rulesPage, engine: enginePage, login: loginPage };
  if (pages[page] && (view || page === "login")) pages[page]();
})();
