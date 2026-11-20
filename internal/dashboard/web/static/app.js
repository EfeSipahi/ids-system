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
    for (const c of children.flat(Infinity)) {
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

  // hostPort writes an address with its port: "203.0.113.7:443", or
  // "[::1]:443" for IPv6, whose colons would be read as the port's.
  function hostPort(ip, port) {
    if (!ip) return "";
    if (!port) return ip;
    return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
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

  // inputText says where a run's requests came from: live copies, request
  // files, or request files replayed on their own clock (ids-offline
  // -replay), whose records carry the requests' times.
  function inputText(input) {
    if (input && input.kind === "live") return `live: copies from a proxy over ${input.socket || "a Unix socket"} (ids-live)`;
    if (input && input.kind === "replay") return `a replay of request files, done ${fmtTime(input.replayed)}: the records carry the requests' own times, not the time of the analysis (ids-offline -replay)`;
    return "request files (ids-offline)";
  }

  // ---- Small parts ----

  function badge(rec, incomplete = true) {
    return el("span", { class: "badges" },
      rec.alert ? el("span", { class: "badge alert", title: alertBy(rec.alert_by) || null }, "Alert") : el("span", { class: "badge" }, "Below threshold"),
      incomplete && rec.incomplete ? el("span", { class: "badge incomplete" }, "Incomplete") : null);
  }

  // alertBy says what made a record an alert (F6): "by the rules and the
  // profile". It is empty for a run without applications.
  function alertBy(by) {
    const names = { rules: "the rules", profile: "the profile" };
    return by && by.length ? "Alert by " + by.map((b) => names[b] || b).join(" and ") : "";
  }

  // profileBadge says that the profile found something (F9); its tooltip
  // names the kinds of finding.
  function profileBadge(kinds) {
    return kinds && kinds.length ? el("span", { class: "badge profile", title: "Profile findings: " + kinds.join(", ") }, "Profile") : null;
  }

  // Verdicts of marks (G1): their names and a badge for each.
  const verdictNames = {
    not_reviewed: "Not reviewed", real_attack: "Real attack", expected: "Expected",
    false_positive: "False positive", undetermined: "Undetermined",
  };
  const verdictHelp = {
    not_reviewed: "nobody has marked it yet",
    real_attack: "a real attack",
    expected: "real, but allowed: for example your own scanner or a penetration test",
    false_positive: "the rule was wrong about this request",
    undetermined: "looked at, but it can't be told",
  };
  const verdictOrder = ["not_reviewed", "real_attack", "expected", "false_positive", "undetermined"];
  function verdictBadge(v) {
    v = v || "not_reviewed";
    return el("span", { class: "badge verdict " + v.replace("_", "-"), title: verdictHelp[v] || null }, verdictNames[v] || v);
  }
  // analyst is true when the user may mark alerts and use the test tab (G3).
  const analyst = ["analyst", "admin"].includes(body.dataset.role);

  // appName is how an application is named on the pages.
  const appName = (name) => (name === "none" ? "No application" : name);

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

  // banner is a Carbon inline notification: a status mark, a title and a
  // sentence. kind is "error", "warning" or "success".
  function banner(kind, title, text) {
    // Messages from the server start in lower case; here they follow a
    // title, as a sentence of their own.
    if (typeof text === "string" && text) text = text[0].toUpperCase() + text.slice(1);
    return el("div", { class: "banner " + kind, role: kind === "error" ? "alert" : "status" },
      el("span", { class: "mark", "aria-hidden": "true" }, kind === "success" ? "✓" : "!"),
      el("div", {}, el("strong", {}, title), " ", text));
  }

  // The sources and reasons of a gap (docs/records-format.md, section 5.1).
  const gapSources = { copier: "the proxy's copier", ids: "ids-live" };
  const gapReasons = {
    "queue full": "queue full",
    "not connected": "ids-live not reachable",
    "refused by the IDS": "too large for ids-live",
    "IDS stopped": "ids-live stopped before analysing",
  };
  const gapReason = (g) => `${gapReasons[g.reason] || g.reason} (${gapSources[g.source] || g.source})`;

  // liveBanners say when the live input is not working (stage 6): ids-live
  // has written nothing for over two minutes (the user's option A, 18
  // November 2026), or no proxy is connected to it.
  function liveBanners(live) {
    if (!live) return null;
    if (live.stale) {
      const since = live.last_counts || live.start;
      return banner("error", `ids-live has written nothing since ${fmtTime(since)} (${ago(since)}).`,
        "No requests are being analysed: ids-live has stopped, crashed or hangs. It writes counts every minute while it runs.");
    }
    if (live.copiers === 0) {
      return banner("warning", "No copier connected.",
        `In the last minute no proxy was connected to ids-live${live.socket ? " on " + live.socket : ""}, so no copies arrive. Check that Caddy runs with ids_copy.`);
    }
    return null;
  }

  // gapsCard lists what the live input could not analyse (T7, T8).
  function gapsCard(o) {
    return el("section", { class: "card" },
      el("div", { class: "card-head" }, el("h2", {}, "Not analysed"),
        el("span", { class: "muted" }, o.gap_count === 0 ? "" : o.gap_count > o.gaps.length
          ? `the newest ${o.gaps.length} of ${nf.format(o.gap_count)} gaps` : `${o.gap_count} ${o.gap_count === 1 ? "gap" : "gaps"}`)),
      o.gaps.length ? [
        el("ul", { class: "plain" }, o.not_analysed_by.map((m) => el("li", {}, el("strong", {}, nf.format(m.missed)), " ", gapReason(m)))),
        el("div", { class: "table-wrap" }, el("table", {},
          el("thead", {}, el("tr", {}, el("th", {}, "Time span"), el("th", { class: "num" }, "Missed"), el("th", {}, "Reason"))),
          el("tbody", {}, o.gaps.map((g) => el("tr", {},
            el("td", { class: "nowrap" }, g.from === g.to ? fmtTime(g.from) : fmtSpan(g.from, g.to)),
            el("td", { class: "num" }, nf.format(g.missed)),
            el("td", {}, gapReason(g)))))))]
        : el("p", { class: "muted" }, "Every request that reached the proxy in this period was analysed."));
  }

  // unknownAppsCard lists the application names the proxy gave that the
  // configuration does not have (T6).
  function unknownAppsCard(o) {
    return el("section", { class: "card" },
      el("div", { class: "card-head" }, el("h2", {}, "Unknown application names")),
      el("p", { class: "muted" }, "The proxy named these applications, but the configuration has none of these names, so their requests ran as no application: the rules only, without a profile."),
      el("ul", { class: "plain" }, o.unknown_applications.map((i) => el("li", {}, el("code", {}, i.key), " · ", nf.format(i.count), i.count === 1 ? " request" : " requests"))));
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
    const cols = [];
    if (opts.pick) cols.push(["", "", "pick"]);
    cols.push(["Time", "", "time"], ["Score", "num", "score"]);
    if (opts.status) cols.push(["Status", "", "status"]);
    if (opts.verdict) cols.push(["Review", "", "review"]);
    cols.push(["Client", "", "client"]);
    if (opts.apps) cols.push(["Application", "", "app"]);
    // With both Status and Review, the attack groups give their room to
    // the request; the rules still name what matched.
    const groupsCol = !(opts.status && opts.verdict);
    cols.push(["Request", "", "request"]);
    if (groupsCol) cols.push(["Attack groups", "", "groups"]);
    if (opts.rules) cols.push(["Rules", "", "rules"]);
    const remember = () => store("sessionStorage", "ids.list", JSON.stringify({ url: location.pathname + location.search, ids: rows.map((r) => r.id) }));
    // opts.pick is the set of chosen record IDs, with opts.onPick called
    // when it changes; the head's box chooses the whole page.
    const pageBox = opts.pick ? el("input", {
      type: "checkbox", "aria-label": "Choose every record of this page",
      onchange: (e) => { for (const r of rows) { if (e.target.checked) opts.pick.add(r.id); else opts.pick.delete(r.id); } opts.onPick(); },
    }) : null;
    if (pageBox) pageBox.checked = rows.length > 0 && rows.every((r) => opts.pick.has(r.id));
    return el("div", { class: "table-wrap" }, el("table", { class: "wide rows list" + (opts.status && opts.apps ? " many" : "") + (opts.verdict ? " reviewed" : "") + (opts.pick ? " picking" : "") },
      el("colgroup", {}, cols.map(([, , c]) => el("col", { class: c }))),
      el("thead", {}, el("tr", {}, cols.map(([h, c]) => el("th", { class: c }, c === "pick" ? pageBox : h)))),
      el("tbody", {}, rows.map((r) => {
        const link = "/alerts/" + encodeURIComponent(r.id);
        const target = `${r.method} ${r.host || ""}${r.path}`;
        // With the Application column, the application stands for the
        // host, and the cell keeps its room for the path.
        const host = opts.apps && r.application && r.application !== "none" ? "" : r.host || "";
        return el("tr", { class: "linked", onclick: (e) => { if (e.target.closest("a, input, label") === null) { remember(); location.assign(link); } } },
          opts.pick ? el("td", { class: "pick" }, el("input", {
            type: "checkbox", checked: opts.pick.has(r.id), "aria-label": "Choose the record of " + fmtTime(r.time),
            onchange: (e) => { if (e.target.checked) opts.pick.add(r.id); else opts.pick.delete(r.id); opts.onPick(); },
          })) : null,
          el("td", {}, el("a", { href: link, onclick: remember }, fmtTime(r.time))),
          el("td", { class: "num" }, r.incomplete ? el("span", { class: "badge incomplete", title: "The analysis could not inspect every part" }, "Incomplete") : null,
            profileBadge(r.profile_kinds), " ", nf.format(r.score)),
          opts.status ? el("td", {}, badge(r, false)) : null,
          opts.verdict ? el("td", {}, verdictBadge(r.verdict)) : null,
          el("td", { class: "mono", title: r.ip || null }, r.ip || "–"),
          opts.apps ? el("td", { title: appName(r.application || "none") }, appName(r.application || "none")) : null,
          el("td", {}, el("span", { class: "clip", title: target + (r.user_agent ? "\nUser-Agent: " + r.user_agent : "") },
            el("span", { class: "mono" }, r.method + " "), host + r.path)),
          groupsCol ? el("td", {}, chips(r.groups, null, 3)) : null,
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
      // The live input's parts show when the newest run is live, or when
      // the period has gaps from an earlier one.
      const liveInput = o.live || o.not_analysed > 0;
      const missedNote = o.not_analysed_by.slice(0, 2).map((m) => `${nf.format(m.missed)} ${gapReasons[m.reason] || m.reason}`).join(" · ");
      replace(el("div", { class: "stack" },
        liveBanners(o.live),
        el("div", { class: "tiles" },
          tile("Alerts", o.alerts, o.analysed > 0 || o.last_alert ? [share(o.alerts), o.last_alert ? "last alert " + ago(o.last_alert) : "", o.alerts ? `${nf.format(o.not_reviewed)} not reviewed` : ""] : "score reached the threshold", true),
          tile("Records", o.recorded, "a finding or an incomplete analysis"),
          tile("Requests analysed", o.analysed, o.profiled ? ["from the counts of the IDS", `${nf.format(o.no_profile)} of no application: the rules only, no profile`] : "from the counts of the IDS"),
          liveInput ? tile("Not analysed", o.not_analysed, o.not_analysed > 0 ? missedNote : "nothing was dropped") : null,
          tile("Incomplete analyses", o.incomplete, share(o.incomplete) || "parts that could not be inspected")),
        card("Records over time",
          el("div", { class: "legend" },
            el("span", { class: "key" }, el("span", { class: "swatch alerts" }), "Alerts"),
            el("span", { class: "key" }, el("span", { class: "swatch others" }), "Records below the threshold"),
            el("span", { class: "key" }, el("span", { class: "swatch partial" }), "Period not over yet")),
          nothing ? el("p", { class: "empty" }, "No records in this period. Run the IDS with records, or choose a longer period.") : columns(o, pick)),
        el("section", { class: "card" },
          el("div", { class: "card-head" }, el("h2", {}, "Latest alerts"), latest.total ? el("a", { href: alertsLink({}) }, `All ${nf.format(latest.total)} alerts →`) : null),
          newest.length ? listTable(newest, { apps: latest.applications.length > 1, verdict: true }) : el("p", { class: "empty" }, "No alerts in this period.")),
        liveInput || o.unknown_applications.length ? el("div", { class: "grid-2" },
          liveInput ? gapsCard(o) : null,
          o.unknown_applications.length ? unknownAppsCard(o) : null) : null,
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
    // The application filter appears once the records have applications;
    // its choices come with each answer (F9).
    const appField = document.getElementById("app-field");
    let appChoices = null; // not "": the first call, with no names yet, must still add the chosen one
    const showApps = (names) => {
      if (names.join("\n") === appChoices) return;
      appChoices = names.join("\n");
      const chosen = form.elements.app.value || params.get("app") || "";
      refill(form.elements.app, el("option", { value: "" }, "Any"), names.map((n) => el("option", { value: n }, appName(n))));
      if (chosen && !names.includes(chosen)) form.elements.app.append(el("option", { value: chosen }, appName(chosen)));
      form.elements.app.value = chosen;
      appField.hidden = names.length === 0 && !chosen;
    };
    if (params.get("app")) showApps([]);
    const state = {
      range: period.value,
      from: params.get("from") || "",
      to: params.get("to") || "",
      kind: ["alerts", "all", "incomplete"].includes(params.get("kind")) ? params.get("kind") : "alerts",
      page: Number(params.get("page")) || 1,
    };
    if (!state.from || !state.to) state.from = state.to = "";
    const fields = ["rule", "group", "app", "ip", "location", "min_score", "review", "sort"];
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

    // Marking (G2): the records chosen on this page, and the bar that
    // marks them or every record that matches the filters. Only analysts
    // and admins see it (G3).
    const picked = new Set();
    const markNotice = el("div", { "aria-live": "polite" });
    const markVerdict = el("select", { name: "mark-verdict", "aria-label": "Verdict" },
      verdictOrder.filter((v) => v !== "not_reviewed").concat("not_reviewed").map((v) => el("option", { value: v }, verdictNames[v])));
    const markNote = el("input", { name: "mark-note", placeholder: "Note (optional)", maxlength: 1000, autocomplete: "off" });
    const markPicked = el("button", { type: "button", class: "small primary" });
    const markAll = el("button", { type: "button", class: "small" });
    const bar = el("div", { class: "mark-bar" }, el("span", { class: "muted" }, "Mark as"), markVerdict, markNote, markPicked, markAll);
    const showBar = () => {
      markPicked.textContent = `Mark ${nf.format(picked.size)} chosen`;
      markPicked.disabled = picked.size === 0;
      markAll.textContent = shown ? `Mark all ${nf.format(shown.total)} that match` : "Mark all that match";
      markAll.disabled = !shown || shown.total === 0;
    };
    const mark = async (request, count) => {
      const verdict = markVerdict.value;
      try {
        const answer = await send("/api/marks", Object.assign({ verdict, note: markNote.value.trim() }, request));
        refill(markNotice, banner("success", `${nf.format(answer.marked)} ${answer.marked === 1 ? "record" : "records"} marked ${verdictNames[verdict].toLowerCase()}.`, "It is written to the log."));
        picked.clear();
        markNote.value = "";
        ownChange = true;
        view.classList.add("loading");
        run();
      } catch (err) {
        if (err.message !== "login required") refill(markNotice, banner("error", "Not marked.", err.message));
      }
      return count;
    };
    markPicked.addEventListener("click", () => mark({ ids: [...picked] }));
    markAll.addEventListener("click", () => {
      const n = shown ? shown.total : 0;
      if (window.confirm(`Mark all ${nf.format(n)} ${what(n)} that match these filters as ${verdictNames[markVerdict.value].toLowerCase()}?`)) {
        const f = current();
        delete f.sort;
        mark({ filter: query(f) });
      }
    });

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
      showBar();
      replace(el("div", { class: "stack" }, markNotice, card(null,
        analyst && l.rows.length ? bar : null,
        l.rows.length ? [pager(l, "top"), listTable(l.rows, {
          status: state.kind === "all", rules: ruleLink, apps: l.applications.length > 1, verdict: true,
          pick: analyst ? picked : null, onPick: showBar,
        }), l.pages > 1 ? pager(l, "bottom") : null]
          : el("p", { class: "empty" }, `No ${what()} match these filters.`))), false);
    };

    const load = async () => {
      const url = "/api/alerts?" + query({ ...current(), page: state.page });
      const l = await api(url);
      showApps(l.applications);
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
      const labels = { rule: "Rule", group: "Group", app: "Application", ip: "IP", location: "Location", min_score: "Score at least", review: "Review" };
      for (const [f, label] of Object.entries(labels)) {
        const v = form.elements[f].value.trim();
        const text = f === "app" ? appName(v) : f === "review" ? (verdictNames[v] || v).toLowerCase() : v;
        if (v) items.push([`${label} ${text}`, () => { form.elements[f].value = ""; }]);
      }
      activeBox.hidden = items.length === 0;
      refill(activeBox,
        items.map(([text, clear]) => el("button", { type: "button", class: "filter-chip", "aria-label": "Remove the filter " + text, onclick: () => { clear(); apply(); } }, text, el("span", { "aria-hidden": "true" }, " ×"))),
        items.length ? el("button", { type: "button", class: "link", onclick: () => { for (const [, clear] of items) clear(); apply(); } }, "Clear filters") : null);
    };

    const apply = () => {
      state.page = 1;
      picked.clear();
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
    // The review (G1, G5): the verdict, a form for analysts and admins,
    // and the record's marks, filled in below.
    const reviewBox = el("section", { class: "card review" }, el("h2", {}, "Review"), el("p", { class: "muted" }, "…"));

    // What the live input knows besides the request (T5, T10, C6): the
    // proxy's own ID and time, the connection, TLS and the response.
    const proxy = r.proxy, conn = r.connection, tls = r.tls, resp = r.response;
    const addr = (a) => (a ? hostPort(a.ip, a.port) : "");
    const responseNotes = {
      "type not copied": "the body was not copied: the copier copies only some types (text/plain, text/html and text/xml by default)",
      "not finished": "the copy was sent while the response was still running (max_wait)",
      "upgraded": "the connection became another protocol, such as a WebSocket",
      "handler error": "the application returned an error and the proxy wrote the response itself; only the status is known",
    };
    const proxyCard = proxy ? card("Proxy", kv([
      ["Proxy request ID", [el("code", {}, proxy.request_id), copyButton(proxy.request_id, "the proxy's request ID")]],
      ["Received by the proxy", fmtTime(proxy.received)],
      ["Analysed", fmtTime(r.time)],
      ["Connection from", conn ? addr(conn) + (ip && conn.ip !== ip ? " (a proxy in front of it; the client is " + ip + ")" : "") : ""],
      ["TLS", tls ? `${tls.version}, ${tls.cipher}` : "no (plain HTTP)"],
      ["Server name (SNI)", tls && tls.server_name],
      ["Protocol (ALPN)", tls && tls.alpn]])) : null;
    const responseCard = proxy ? card("Response", resp ? [kv([
      ["Status", String(resp.status)],
      ["Content type", resp.content_type],
      ["Encoding", resp.encoding],
      ["Body length", bytes(resp.body_length)],
      ["Copied", resp.body_copied < resp.body_length ? `${bytes(resp.body_copied)} of it` : resp.body_length ? "all of it" : ""],
      ["Note", resp.note ? responseNotes[resp.note] || resp.note : ""]]),
    el("p", { class: "muted" }, "The response body is not analysed yet: the response rules come later.")]
      : el("p", { class: "muted" }, "No response was written when the copy was made: the client went away, or the application had not answered yet.")) : null;

    // The application and its profile's findings (F9), apart from the
    // rule findings and the score (M10).
    const app = r.application, prof = r.profile;
    const modes = { alert: "alert: a profile finding makes the request an alert", monitor: "monitor: profile findings are recorded, not alerts" };
    const profileCard = app ? card("Application and profile", kv([
      ["Application", app.name === "none" ? "No application: only the rules checked this request"
        : el("a", { href: "/alerts?" + query({ kind: "all", app: app.name, range: "all" }), title: "Every record of this application" }, app.name)],
      ["Profile mode", modes[app.mode] || app.mode],
      ["Paranoia level", app.paranoia_level !== e.paranoia_level ? `${app.paranoia_level} (the application's; the configuration's is ${e.paranoia_level})` : String(app.paranoia_level)],
      ["Body checked", prof && !prof.body_checked ? "no — the body was not read to its end, so its parameters were not checked" : ""]]),
    prof ? (prof.findings.length
      ? el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, el("th", {}, "Finding"), el("th", {}, "Where"), el("th", {}, "What"))),
        el("tbody", {}, prof.findings.map((f) => el("tr", {},
          el("td", { class: "nowrap" }, f.kind), el("td", { class: "mono loc" }, f.location), el("td", { class: "wrap" }, f.message))))))
      : el("p", { class: "muted" }, "The request is what the profile allows.")) : null,
    prof && prof.omitted ? el("p", { class: "muted" }, `${nf.format(prof.omitted)} more findings are not kept in the record.`) : null) : null;
    replace(el("div", { class: "stack" },
      el("div", { class: "detail-head" },
        el("h1", { class: "request-title" }, el("span", { class: "method" }, (req.method || "?") + " "), short(`${req.path || ""}${req.query ? "?" + req.query : ""}`, 200)),
        el("p", { class: "summary" },
          badge({ alert: r.alert, alert_by: r.alert_by, incomplete: !a.complete }),
          r.alert_by ? el("span", {}, alertBy(r.alert_by)) : null,
          // "Alert by the profile" already says it.
          prof && prof.findings.length && !(r.alert_by || []).includes("profile") ? profileBadge([...new Set(prof.findings.map((f) => f.kind))]) : null,
          el("span", {}, fmtTime(r.time)),
          el("span", {}, "from ", ip || "an unknown address"),
          hitGroups.length ? el("span", {}, hitGroups.join(", ")) : null,
          el("span", {}, `score ${s.total} / ${s.threshold}`))),
      reviewBox,
      el("div", { class: "grid-2" },
        card("Decision", kv([
          ["Score", `${s.total} (threshold ${s.threshold})`],
          ["By category", categoryList.length || uncategorised > 0 ? el("ul", { class: "plain" },
            categoryList.map(([k, v]) =>
              el("li", {}, categories[k] || k, " ", el("strong", {}, String(v)), " ", el("span", { class: "muted" }, `(${k})`))),
            uncategorised > 0 ? el("li", { title: "These rules add to the total score only, such as most protocol rules (CRS files 911, 913, 920 and 922)." },
              "No category ", el("strong", {}, String(uncategorised)), " ", el("span", { class: "muted" }, "(rules that add to the total only)")) : null) : ""],
          ["Alert by", r.alert_by ? r.alert_by.join(", ") : ""],
          ["Decided by", r.decided_by],
          ["Record", [el("code", {}, r.id), copyButton(r.id, "the record ID")]],
          ["Run", el("code", {}, r.run)]])),
        card("Who and where", kv([
          ["Client IP", ip ? [el("a", { href: "/alerts?" + query({ kind: "all", ip, range: "all" }) }, ip), copyButton(ip, "the IP address")] : "not known"],
          ["Client from", proxy ? "the proxy: the connection, or a trusted proxy's header" : ""],
          ["Last 24 hours", ip ? clientCount : ""],
          ["Client port", r.client && r.client.port],
          ["Host", r.server && r.server.host],
          ["Server address", r.server ? hostPort(r.server.ip, r.server.port) : ""]]))),
      card("Request", kv([
        ["Request line", [el("code", { class: "wrap" }, line), copyButton(line, "the request line")]],
        ["User-Agent", req.user_agent],
        ["Referer", req.referer],
        ["Content type", req.content_type],
        ["Body length", req.body_length !== undefined ? bytes(req.body_length) : ""],
        ["Header names", req.header_names && req.header_names.length ? chips(req.header_names) : ""],
        ["Cookies", req.cookies && req.cookies.length ? chips(req.cookies.map((c) => `${c.name} #${c.hash}`)) : ""]]),
        el("p", { class: "muted" }, "Secret values (passwords, tokens, cookies, Authorization) are masked before a record is written.")),
      proxyCard || responseCard ? el("div", { class: "grid-2" }, proxyCard, responseCard) : null,
      card("Analysis", kv([
        ["Complete", a.complete ? "yes" : "no — a clean result does not cover the parts that were not inspected"],
        ["Body", `${a.body}${a.body_format ? " as " + a.body_format : ""}${a.body_reason ? " (" + a.body_reason + ")" : ""}`],
        ["Notes", (a.issues || []).map((i) => `${i.part}: ${i.message}`).join("; ")]])),
      profileCard,
      el("section", { class: "card" },
        el("h2", {}, `Rule findings: ${byRule.size} ${byRule.size === 1 ? "rule" : "rules"}, ${attack.length} ${attack.length === 1 ? "place" : "places"}`),
        ruleEntries.length ? el("div", { class: "findings" }, ruleEntries)
          : el("p", { class: "muted" }, prof && prof.findings.length ? "No rule matched; the record was written for the profile's findings." : "No rule matched; the record was written because the analysis is incomplete."),
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
        ["Paranoia level", app ? `${app.paranoia_level} for this request; the configuration's is ${e.paranoia_level}` : e.paranoia_level],
        ["Configuration", el("code", { class: "wrap" }, e.config)]]))));

    async function loadReview() {
      let m;
      try {
        m = await api("/api/marks/" + encodeURIComponent(id));
      } catch (err) {
        if (err.message !== "login required") refill(reviewBox, el("h2", {}, "Review"), el("p", { class: "error" }, "The marks could not be loaded: " + err.message));
        return;
      }
      const last = m.history.length ? m.history[m.history.length - 1] : null;
      const notice = el("div", { "aria-live": "polite" });
      let form = null;
      if (analyst) {
        const verdict = el("select", { name: "verdict", "aria-label": "Verdict" },
          verdictOrder.map((v) => el("option", { value: v, selected: v === m.verdict }, verdictNames[v])));
        const note = el("input", { name: "note", placeholder: "Note (optional)", maxlength: 1000, autocomplete: "off", value: last && last.note ? last.note : "" });
        const help = el("span", { class: "muted" }, verdictHelp[m.verdict]);
        verdict.addEventListener("change", () => { help.textContent = verdictHelp[verdict.value]; });
        form = el("form", { class: "mark-bar" }, verdict, note, el("button", { type: "submit", class: "small primary" }, "Save"), help);
        form.addEventListener("submit", async (e) => {
          e.preventDefault();
          try {
            await send("/api/marks", { verdict: verdict.value, note: note.value.trim(), ids: [id] });
            await loadReview();
          } catch (err) {
            if (err.message !== "login required") refill(notice, banner("error", "Not marked.", err.message));
          }
        });
      }
      refill(reviewBox,
        el("div", { class: "card-head" }, el("h2", {}, "Review"), verdictBadge(m.verdict)),
        last ? el("p", {}, `${verdictNames[last.verdict]}, by ${last.user}, ${fmtTime(last.time)}.`, last.note ? [" ", el("span", { class: "muted" }, "Note: "), last.note] : null)
          : el("p", { class: "muted" }, "Nobody has marked this record yet."),
        form, notice,
        m.history.length > 1 ? el("details", { class: "table-view", "data-key": "marks" }, el("summary", {}, `Earlier marks: ${m.history.length - 1}`),
          el("div", { class: "table-wrap" }, el("table", {},
            el("thead", {}, el("tr", {}, el("th", {}, "Time"), el("th", {}, "User"), el("th", {}, "Verdict"), el("th", {}, "Note"))),
            el("tbody", {}, m.history.slice(0, -1).reverse().map((h) => el("tr", {},
              el("td", { class: "nowrap" }, fmtTime(h.time)), el("td", {}, h.user), el("td", {}, verdictBadge(h.verdict)), el("td", { class: "wrap" }, h.note || "–"))))))) : null);
    }
    loadReview();

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
    const status = (r, level) => (!r.active ? "excluded" : r.off ? "off" : (r.paranoia_level || 0) > level ? "above" : "runs");

    // An application's exception of the rule, below its status (F9).
    const exceptionNote = (r) => [
      r.skips ? el("div", { class: "sub" }, "Skips " + r.skips.join(", ") + ": " + r.exception_reason) : null,
      r.no_effect ? el("div", { class: "sub" }, r.no_effect) : null];

    const statusCell = (r, level, app) => {
      switch (status(r, level)) {
        case "excluded":
          return [el("span", { class: "badge excluded" }, "Excluded"), el("div", { class: "sub" }, r.reason), exceptionNote(r)];
        case "off":
          return [el("span", { class: "badge off" }, "Off for " + app), el("div", { class: "sub" }, r.exception_reason), exceptionNote(r)];
        case "above":
          return [el("span", { class: "badge above", title: `Its paranoia level ${r.paranoia_level} is above the level the rules run at (${level}), so the CRS gate rule skips it.` }, `Above level ${level}`), exceptionNote(r)];
        default:
          return [el("span", { class: "badge active" }, "Runs"), exceptionNote(r)];
      }
    };

    // The application selector appears when the run has applications. A
    // choice shows that application's level and exceptions (F11).
    const appField = document.getElementById("app-field");
    let appChoices = "";
    const showApps = (d) => {
      const names = (d.applications || []).map((a) => `${a.name}\t${a.paranoia_level}`).concat(d.applications && d.applications.length ? [`none\t${d.engine.paranoia_level}`] : []);
      if (names.join("\n") === appChoices) return;
      appChoices = names.join("\n");
      const chosen = form.elements.app.value;
      refill(form.elements.app, el("option", { value: "" }, "The run's level"),
        names.map((n) => { const [name, level] = n.split("\t"); return el("option", { value: name }, `${appName(name)} (level ${level})`); }));
      form.elements.app.value = chosen;
      appField.hidden = names.length === 0;
    };

    const are = (n) => `${nf.format(n)} ${n === 1 ? "is" : "are"}`;

    // exceptionText says what an exception changes.
    const exceptionText = (ex) => ex.setting ? `Setting ${ex.setting} = "${ex.value}"` : ex.off ? `Rule ${ex.rule} off` : `Rule ${ex.rule} skips ${ex.skip.join(", ")}`;

    const draw = () => {
      if (!data) return;
      if (!data.run) {
        replace(card(null, el("p", { class: "empty" }, "No start record has been read yet.")));
        return;
      }
      const f = Object.fromEntries(new FormData(form));
      const q = (f.q || "").trim().toLowerCase();
      const level = data.level;
      const chosen = (data.applications || []).find((a) => a.name === data.app);
      // "Off for the application" only means something for an application.
      form.elements.status.querySelector('option[value="off"]').hidden = !chosen;
      const appLabel = data.app ? appName(data.app) : "";
      const counts = { runs: 0, above: 0, excluded: 0, off: 0 };
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
          el("colgroup", {}, ["id", "msg", "line", "phase", "level", "status", "fired", "fp"].map((c) => el("col", { class: c }))),
          el("thead", {}, el("tr", {}, ["Rule", "Description", "Line", "Phase", "Level", "Status", "Fired", "False positive"].map((h, i) => el("th", { class: i >= 6 ? "num" : "", title: i === 7 ? "Records of this rule in the period that someone marked false positive, also records that are no longer kept" : null }, h)))),
          el("tbody", {}, sec.shown.map((r) => el("tr", {},
            el("td", {}, r.fired ? el("a", { href: "/alerts?" + query({ kind: "all", rule: r.id, range: f.range }) }, String(r.id)) : String(r.id)),
            el("td", { class: "wrap" }, r.msg || el("span", { class: "muted" }, "–")),
            el("td", {}, String(r.line)),
            el("td", {}, String(r.phase)),
            el("td", {}, r.paranoia_level ? String(r.paranoia_level) : "–"),
            el("td", { class: "wrap" }, statusCell(r, level, appLabel)),
            el("td", { class: "num" }, nf.format(r.fired)),
            el("td", { class: "num" }, r.false_positives ? el("a", { href: "/alerts?" + query({ kind: "all", rule: r.id, range: f.range, review: "false_positive" }) }, nf.format(r.false_positives)) : "–")))))));

      replace(el("div", { class: "stack" },
        el("p", { class: "muted" }, `${nf.format(data.rules.length)} rules of ${data.engine.crs} at paranoia level ${level}` +
          (data.app ? ` for ${data.app === "none" ? "requests of no application" : "the application " + data.app}` : "") + ": " +
          `${nf.format(counts.runs)} run, ${are(counts.above)} above the level and skipped, ${are(counts.excluded)} excluded` +
          (counts.off ? `, ${are(counts.off)} off for the application` : "") + ". " +
          `Showing ${nf.format(shownCount)}; fired counts ${data.app ? "this application's records only" : "every record"}. From the run that started ${fmtTime(data.time)}.`),
        chosen ? card(`Exceptions of ${chosen.name}`,
          chosen.exceptions.length ? el("ul", { class: "plain" }, chosen.exceptions.map((ex) => el("li", {},
            el("strong", {}, exceptionText(ex)), ": ", ex.reason,
            ex.note ? el("div", { class: "sub" }, ex.note) : null,
            ex.no_effect ? el("div", { class: "sub" }, "No effect now: " + ex.no_effect) : null)))
            : el("p", { class: "muted" }, "This application's profile has no rule exceptions."),
          el("p", { class: "muted" }, `Profile ${chosen.profile}, mode ${chosen.mode}, paranoia level ${chosen.paranoia_level}. ` +
            `Hosts ${chosen.hosts.join(", ")}${chosen.paths ? ", paths " + chosen.paths.join(", ") : ""}.`)) : null,
        sections.length ? sections.map(section) : card(null, el("p", { class: "empty" }, "No rule matches these filters."))), !own);
      own = false;
    };

    // The period buttons are outside the form; FormData reads it from here.
    const rangeField = el("input", { type: "hidden", name: "range", value: period.value });
    form.append(rangeField);
    // The filters are kept in the address, as on the alerts page, so that
    // a link or the back button shows the same rules.
    const params = new URLSearchParams(location.search);
    const fields = ["app", "status", "level", "q", "sort"];
    if (params.get("app")) form.elements.app.append(el("option", { value: params.get("app") }, appName(params.get("app"))));
    for (const f of fields) if (params.has(f)) form.elements[f].value = params.get(f);
    const sync = () => {
      const p = { range: period.value };
      for (const f of fields) p[f] = form.elements[f].value.trim();
      if (p.sort === "id") p.sort = "";
      history.replaceState(null, "", "/rules?" + query(p));
    };
    const run = every(async () => {
      const url = "/api/rules?" + query({ range: period.value, app: form.elements.app.value });
      const d = await api(url);
      showApps(d);
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
    form.addEventListener("input", (e) => {
      own = true;
      sync();
      if (e.target.name !== "app") {
        draw();
        return;
      }
      view.classList.add("loading");
      run();
    });
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
          el("td", { title: r.input && r.input.kind === "replay" ? "Request files replayed on " + fmtTime(r.input.replayed) + "; the records carry the requests' own times" : null },
            r.input && r.input.kind === "live" ? "live" : r.input && r.input.kind === "replay" ? "replay" : "files"),
          el("td", {}, r.engine.crs),
          el("td", {}, String(r.engine.paranoia_level)),
          el("td", { class: "num" }, nf.format(r.analysed)),
          el("td", { class: "num" }, nf.format(r.records)),
          el("td", { class: "num" }, nf.format(r.alerts)),
          el("td", { class: "nowrap" }, el("code", { title: r.engine.config }, short(r.engine.config, 15)), copyButton(r.engine.config, "the fingerprint"),
            changed ? [" ", el("span", { class: "chip changed", title: "The configuration is not the one of the run before" }, "changed")] : null));
      });
      const level = l ? l.engine.paranoia_level : 0;
      replace(el("div", { class: "stack" },
        l ? card("Running configuration", kv([
          ["Started", fmtTime(l.time)],
          ["Run", el("code", {}, l.run)],
          ["Engine", `${l.engine.version}${l.engine.revision ? " (" + l.engine.revision.slice(0, 12) + ")" : ""}`],
          ["Rules", l.engine.crs],
          ["Input", inputText(l.input)],
          ["Paranoia level", p.applications.length ? `${l.engine.paranoia_level} by default; an application may have its own` : l.engine.paranoia_level],
          ["Rule status", el("a", { href: "/rules" }, `${nf.format(p.active_rules - p.above_level_rules)} run, ` +
            `${nf.format(p.above_level_rules)} above level ${level}, ${nf.format(p.excluded_rules)} excluded`)],
          ["Configuration", [el("code", { class: "wrap" }, l.engine.config), copyButton(l.engine.config, "the fingerprint")]]]))
          : card("Running configuration", el("p", { class: "empty" }, "No start record has been read yet.")),
        p.applications.length ? card("Applications",
          el("p", { class: "muted" }, "Each application's requests are checked against its profile and run with its own level and rule exceptions. " +
            (p.require_profile ? "A request of another host gets a no_profile finding (require_profile)." : "A request of another host gets the rules only, at the configuration's level.")),
          el("div", { class: "table-wrap" }, el("table", { class: "wide" },
            el("thead", {}, el("tr", {}, [["Application", ""], ["Hosts", ""], ["Paths", ""], ["Profile", ""], ["Mode", ""], ["Level", ""], ["Exceptions", "num"], ["Notes", ""]].map(([h, c]) => el("th", { class: c }, h)))),
            el("tbody", {}, p.applications.map((a) => el("tr", {},
              el("td", {}, el("a", { href: "/alerts?" + query({ kind: "all", app: a.name }), title: "The records of this application" }, a.name)),
              el("td", { class: "mono nowrap" }, a.hosts.map((h) => el("div", {}, h))),
              el("td", { class: "mono nowrap" }, a.paths ? a.paths.map((x) => el("div", {}, x)) : "every path"),
              el("td", { class: "mono nowrap" }, a.profile),
              el("td", {}, a.mode),
              el("td", {}, String(a.paranoia_level)),
              el("td", { class: "num" }, el("a", { href: "/rules?" + query({ app: a.name }), title: "The rules and exceptions of this application" }, nf.format(a.exceptions.length))),
              el("td", { class: "wrap sub" }, a.notes && a.notes.length ? a.notes.map((n) => el("div", {}, n)) : "–"))))))) : null,
        card("Runs", el("p", { class: "muted" }, "Each start of the IDS, newest first. A new configuration fingerprint means the rules or settings changed. Records and alerts count what is still kept."),
          el("div", { class: "table-wrap" }, el("table", { class: "wide" },
            el("thead", {}, el("tr", {}, [["Started", ""], ["Run", ""], ["Input", ""], ["Rules", ""], ["Level", ""], ["Analysed", "num"], ["Records", "num"], ["Alerts", "num"], ["Configuration", ""]].map(([h, c]) => el("th", { class: c }, h)))),
            el("tbody", {}, runs)))),
        card("Record files", kv([
          ["Records kept", nf.format(p.records)],
          ["Oldest", fmtTime(p.oldest_record)],
          ["Newest", fmtTime(p.newest_record)],
          ["Unreadable lines", p.unreadable_lines ? nf.format(p.unreadable_lines) : "none"],
          ["Other record types", p.skipped_lines ? `${nf.format(p.skipped_lines)} lines skipped: written by a newer version of the IDS` : ""],
          ["Marked records", `${nf.format(p.marks)}, kept also after their record is gone; each keeps the alert's time, rules, path and client address`],
          ["Unreadable mark lines", p.marks_unreadable ? nf.format(p.marks_unreadable) : ""]]),
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
  // ---- Test a request (docs/development-plan-test-tab.md, S1–S4) ----

  // The user writes a request as raw HTTP text; the dashboard analyses it
  // with the IDS's own rules and profiles and keeps nothing of it (C1).
  // The text is not stored in the browser either; only the choices are.
  async function testPage() {
    let info;
    try {
      info = await api("/api/test");
    } catch (err) {
      if (err.message !== "login required") failed(err);
      return;
    }
    if (!info.enabled) {
      replace(card("The test tab is off",
        el("p", {}, "List the product configurations it may analyse with under test_configs in the dashboard's configuration file, and start the dashboard again. For example, in configs/dashboard.json:"),
        el("pre", { class: "block" }, '"test_configs": ["crs-first-engine.json", "csic-shop.json", "../testdata/crs-tests.json"],\n"test_requests_dir": "../testdata/requests/crs"'),
        el("p", { class: "muted" }, "Paths start at the folder of the dashboard's configuration file.")));
      return;
    }
    const remember = (k, v) => store("localStorage", "ids.test." + k, v);
    const recall = (k) => stored("localStorage", "ids.test." + k);
    const encoder = new TextEncoder();
    const configs = info.configs;

    // What was loaded last: an example, perhaps with the rules a CRS test
    // expects, and its text, to tell when the user changed it.
    let loaded = null;

    const text = el("textarea", {
      id: "test-text", class: "editor", rows: 16, spellcheck: "false", autocomplete: "off",
      autocapitalize: "off", wrap: "off", "aria-label": "The request as raw HTTP text",
    });
    const size = el("span", { class: "muted" });
    const lengthNote = el("div", { class: "length-note", hidden: true });
    const runButton = el("button", { type: "button", class: "primary" }, "Analyse");
    const result = el("div", { class: "stack", id: "result", "aria-live": "polite" });

    const field = (label, control, extra) => el("label", { class: extra || null }, label, control);
    const option = (value, label, attrs) => el("option", Object.assign({ value }, attrs || {}), label);

    // Examples: the built-in list, and the picker of example files.
    const exampleSel = el("select", { name: "example" }, option("", "Choose an example…"),
      info.examples.map((ex, i) => option(String(i), ex.name)));
    const fileSel = el("select", { name: "file" }, option("", "Choose a rule…"),
      info.files.map((f) => option(f.name, `${f.name} (${f.tests} ${f.tests === 1 ? "test" : "tests"})`)));
    const caseSel = el("select", { name: "case", disabled: true }, option("", "Choose a test…"));
    let cases = [];

    // The settings of a test.
    const configSel = el("select", { name: "config" }, configs.map((c) =>
      option(String(c.index), c.error ? `${c.name} · can't be loaded` : `${c.name} · level ${c.paranoia_level}${c.newest ? " · the IDS's rules" : ""}`)));
    const levelSel = el("select", { name: "level" });
    const appSel = el("select", { name: "application" });
    const client = el("input", { name: "client", placeholder: "none", autocomplete: "off", spellcheck: "false", inputmode: "text" });
    const crlfSel = el("select", { name: "crlf" },
      option("0", "\\n, as typed"), option("1", "\\r\\n, as multipart needs"));
    const configNote = el("p", { class: "muted config-note" });

    const saved = recall("config");
    if (saved !== null && configs.some((c) => String(c.index) === saved)) configSel.value = saved;

    function current() {
      return configs[Number(configSel.value)] || configs[0];
    }

    function fillChoices() {
      const c = current();
      const level = levelSel.value;
      refill(levelSel, option("0", `As configured${c.paranoia_level ? " (" + c.paranoia_level + ")" : ""}`),
        [1, 2, 3, 4].map((n) => option(String(n), "Level " + n)));
      levelSel.value = ["1", "2", "3", "4"].includes(level) ? level : "0";
      const app = appSel.value;
      refill(appSel, option("", "By Host and path"), c.applications.map((a) => option(a, a)));
      appSel.value = c.applications.includes(app) ? app : "";
      appSel.disabled = c.applications.length === 0;
      refill(configNote,
        c.error ? el("span", { class: "error" }, "This configuration can't be loaded: " + c.error)
          : [c.newest ? "These are the rules of the IDS's newest run." : "These are not the rules of the IDS's newest run: its configuration, a rule file, a profile or the level differs.",
            " Fingerprint ", el("code", {}, short(c.fingerprint, 23))]);
      crsHint();
    }

    // crsHint suggests the configuration CRS's tests are written for, when
    // a CRS test is loaded with another one.
    const hint = el("p", { class: "muted", hidden: true });
    function crsHint() {
      const fit = configs.find((c) => c.name === "crs-tests.json");
      const show = !!(loaded && loaded.expect && fit && current() !== fit);
      hint.hidden = !show;
      if (show) {
        refill(hint, "CRS wrote its tests for its own test setup at paranoia level 4; with another configuration some expected rules don't match. ",
          el("button", { type: "button", class: "link", onclick: () => { configSel.value = String(fit.index); levelSel.value = "0"; changed(); } }, "Use crs-tests.json"));
      }
    }

    function changed() {
      remember("config", configSel.value);
      fillChoices();
    }

    function load(ex, expect) {
      if (!ex.writable) return;
      text.value = ex.text;
      crlfSel.value = ex.body_crlf ? "1" : "0";
      client.value = ex.client || "";
      loaded = { name: ex.name, text: ex.text, expect: expect ? { ids: ex.expect_ids || [], not: ex.no_expect_ids || [] } : null };
      lengthNote.hidden = true;
      measure();
      crsHint();
      text.focus();
    }

    function measure() {
      const n = encoder.encode(text.value).length;
      const over = n > info.max_text;
      refill(size, `${bytes(n)} of ${bytes(info.max_text)}`);
      size.classList.toggle("error", over);
      runButton.disabled = over || !text.value.trim();
    }

    exampleSel.addEventListener("change", () => {
      const ex = info.examples[Number(exampleSel.value)];
      if (exampleSel.value !== "" && ex) load(ex, false);
      fileSel.value = "";
      refill(caseSel, option("", "Choose a test…"));
      caseSel.disabled = true;
    });
    fileSel.addEventListener("change", async () => {
      exampleSel.value = "";
      refill(caseSel, option("", "Choose a test…"));
      caseSel.disabled = true;
      if (!fileSel.value) return;
      try {
        const data = await api("/api/test/files/" + encodeURIComponent(fileSel.value));
        cases = data.examples;
      } catch (err) {
        if (err.message !== "login required") showError("The tests of this rule could not be loaded", err.message);
        return;
      }
      refill(caseSel, option("", `Choose one of ${cases.length} tests…`), cases.map((ex, i) =>
        option(String(i), ex.writable ? ex.name : ex.name + " (can't be written as text)", { disabled: !ex.writable })));
      caseSel.disabled = false;
      const first = cases.findIndex((ex) => ex.writable);
      if (first >= 0) {
        caseSel.value = String(first);
        load(cases[first], true);
      }
    });
    caseSel.addEventListener("change", () => {
      const ex = cases[Number(caseSel.value)];
      if (ex) load(ex, true);
    });
    configSel.addEventListener("change", changed);
    text.addEventListener("input", () => { measure(); lengthNote.hidden = true; });
    text.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        if (!runButton.disabled) run();
      }
    });
    runButton.addEventListener("click", run);

    function showError(title, message) {
      refill(result, banner("error", title + ".", message));
    }

    async function run() {
      runButton.disabled = true;
      result.classList.add("loading");
      const q = query({
        config: configSel.value, level: levelSel.value === "0" ? "" : levelSel.value,
        application: appSel.value, client: client.value.trim(), crlf: crlfSel.value === "1" ? "1" : "",
      });
      const forced = appSel.value;
      let res, data;
      try {
        res = await fetch("/api/test?" + q, {
          method: "POST", credentials: "same-origin", body: text.value,
          headers: { "Content-Type": "text/plain; charset=utf-8", Accept: "application/json" },
        });
        if (res.status === 401) {
          location.assign("/login?" + query({ next: location.pathname }));
          return;
        }
        data = await res.json();
      } catch (err) {
        showError("The request could not be analysed", err.message);
        return;
      } finally {
        result.classList.remove("loading");
        measure();
      }
      if (!res.ok) {
        showError(res.status === 400 ? "The request can't be read" : "The request could not be analysed", data.error || res.statusText);
        return;
      }
      showLength(data.content_length);
      showAnswer(data, forced);
    }

    // showLength says when Content-Length does not give the body's length,
    // and offers to correct it; the IDS itself never does (C6).
    function showLength(cl) {
      lengthNote.hidden = !cl;
      if (!cl) return;
      refill(lengthNote, banner("warning", "Content-Length differs from the body.",
        `It says ${cl.declared}; the body has ${nf.format(cl.body)} bytes. The IDS analyses the body as written, as it would analyse what a client sends.`),
      el("button", { type: "button", class: "small", onclick: () => setLength(cl.body) }, `Set Content-Length to ${cl.body}`));
    }

    function setLength(n) {
      const value = text.value;
      const end = value.indexOf("\n\n");
      const head = end < 0 ? value : value.slice(0, end);
      const rest = end < 0 ? "" : value.slice(end);
      const lines = head.split("\n");
      const i = lines.findIndex((l, k) => k > 0 && /^content-length\s*:/i.test(l));
      if (i < 0) return;
      lines[i] = lines[i].slice(0, lines[i].indexOf(":")) + ": " + n;
      text.value = lines.join("\n") + rest;
      lengthNote.hidden = true;
      measure();
    }

    // showAnswer shows what a test found; forced is the application chosen
    // on the page, or "".
    function showAnswer(a, forced) {
      const r = a.result, s = r.score || {}, an = r.analysis || {}, rd = a.read || {};
      const findings = r.findings || [];
      const attack = findings.filter((f) => !scoring(f.rule_id));
      const scores = findings.filter((f) => scoring(f.rule_id));
      const matched = new Set(findings.map((f) => f.rule_id));
      const hitGroups = [...new Set(attack.map((f) => groupOf(f.rule_id)))];
      const alert = !!s.exceeded || (r.alert_by || []).length > 0;
      const app = r.application, prof = r.profile;
      const line = `${rd.method} ${rd.target}${rd.version ? " " + rd.version : ""}`;

      // The rules a CRS test expects, while its text is unchanged.
      let expectCard = null;
      if (loaded && loaded.expect && (loaded.expect.ids.length || loaded.expect.not.length)) {
        const same = text.value === loaded.text;
        const missing = loaded.expect.ids.filter((id) => !matched.has(id));
        const unwanted = loaded.expect.not.filter((id) => matched.has(id));
        const met = missing.length === 0 && unwanted.length === 0;
        expectCard = card("CRS test: " + loaded.name, kv([
          ["Expected to match", loaded.expect.ids.length ? el("ul", { class: "plain" }, loaded.expect.ids.map((id) =>
            el("li", {}, matched.has(id) ? el("span", { class: "badge active" }, `${id} matched`) : el("span", { class: "badge alert" }, `${id} did not match`)))) : ""],
          ["Must not match", loaded.expect.not.length ? el("ul", { class: "plain" }, loaded.expect.not.map((id) =>
            el("li", {}, matched.has(id) ? el("span", { class: "badge alert" }, `${id} matched`) : el("span", { class: "badge active" }, `${id} did not match`)))) : ""],
          ["Result", met ? "The test's expectation is met." : "The test's expectation is not met."]]),
        !same ? el("p", { class: "muted" }, "The text was changed after the test was loaded, so the expectation may no longer apply.") : null);
      }

      const byCategory = Object.entries(s.categories || {});
      const uncategorised = (s.total || 0) - byCategory.reduce((n, [, v]) => n + v, 0);
      const modes = { alert: "alert: a profile finding makes the request an alert", monitor: "monitor: profile findings are recorded, not alerts" };
      const json = JSON.stringify(a, null, 2);
      // One table of what the engine read: parameters of the query and the
      // body, cookies, and files of a multipart body.
      const read = [...rd.params,
        ...rd.cookies.map((c) => ({ origin: "cookie", name: c.name, value: c.value })),
        ...rd.files.map((f) => ({ origin: "file, field " + f.origin, name: f.name, value: f.value }))];
      const pairs = (list, first) => el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, el("th", {}, first), el("th", {}, "Name"), el("th", {}, "Value"))),
        el("tbody", {}, list.map((p) => el("tr", {},
          el("td", { class: "nowrap" }, p.origin || "–"), el("td", { class: "mono wrap" }, p.name), el("td", { class: "mono wrap" }, p.value))))));

      refill(result,
        el("section", { class: "card verdict" },
          el("h2", {}, alert ? "Alert" : "No alert"),
          el("p", { class: "summary" },
            !an.complete ? el("span", { class: "badge incomplete" }, "Incomplete") : null,
            r.alert_by && r.alert_by.length ? el("span", {}, alertBy(r.alert_by)) : null,
            el("span", {}, `score ${s.total} / ${s.threshold}`),
            hitGroups.length ? el("span", {}, hitGroups.join(", ")) : el("span", {}, "no rule matched"),
            prof && prof.findings.length ? profileBadge([...new Set(prof.findings.map((f) => f.kind))]) : null,
            el("span", {}, `${a.config.name}, level ${a.paranoia_level}`),
            app ? el("span", {}, "application " + appName(app.name)) : null,
            el("span", { title: "How long the rules and the profile took" }, `${a.ms.toFixed(2)} ms`))),
        expectCard,
        el("section", { class: "card" },
          el("h2", {}, `Rule findings: ${new Set(attack.map((f) => f.rule_id)).size} rules, ${attack.length} ${attack.length === 1 ? "place" : "places"}`),
          attack.length ? el("div", { class: "table-wrap" }, el("table", { class: "findings-table" },
            el("thead", {}, el("tr", {}, el("th", {}, "Rule"), el("th", {}, "Severity"), el("th", {}, "Message"), el("th", {}, "Where"), el("th", {}, "Matched"), el("th", {}, "Rule data"))),
            el("tbody", {}, attack.map((f) => el("tr", {},
              el("td", { class: "nowrap", title: groupOf(f.rule_id) }, String(f.rule_id)),
              el("td", { class: "nowrap" }, severity(f.severity)),
              el("td", { class: "wrap" }, f.message || "–"),
              el("td", { class: "mono loc" }, f.location || "–"),
              el("td", { class: "wrap" }, f.value ? el("code", {}, f.value) : "–"),
              el("td", { class: "wrap sub" }, f.data || "–"))))))
            : el("p", { class: "muted" }, an.complete ? "No rule matched." : "No rule matched in what could be inspected; see the analysis below."),
          scores.map((f) => el("p", { class: "muted" }, `Score rule ${f.rule_id}: ${f.message}`))),
        el("div", { class: "grid-2" },
          card("Decision", kv([
            ["Score", `${s.total} (threshold ${s.threshold})`],
            ["By category", byCategory.length || uncategorised > 0 ? el("ul", { class: "plain" },
              byCategory.map(([k, v]) => el("li", {}, categories[k] || k, " ", el("strong", {}, String(v)), " ", el("span", { class: "muted" }, `(${k})`))),
              uncategorised > 0 ? el("li", {}, "No category ", el("strong", {}, String(uncategorised)), " ", el("span", { class: "muted" }, "(rules that add to the total only)")) : null) : ""],
            ["Alert by", r.alert_by && r.alert_by.length ? r.alert_by.join(", ") : ""]])),
          card("Analysis", kv([
            ["Complete", an.complete ? "yes" : "no — a clean result does not cover the parts that were not inspected"],
            ["Body", `${an.body}${an.body_format ? " as " + an.body_format : ""}${an.body_reason ? " (" + an.body_reason + ")" : ""}`],
            ["Notes", (an.issues || []).map((i) => `${i.part}: ${i.message}`).join("; ")]]))),
        app ? card("Application and profile", kv([
          ["Application", app.name === "none" ? "No application: only the rules checked this request" : app.name],
          ["Chosen", forced ? "on this page" : "by Host and path"],
          ["Profile mode", modes[app.mode] || app.mode],
          ["Paranoia level", app.name !== "none" && app.paranoia_level !== a.paranoia_level
            ? `${app.paranoia_level}: the application's own, which it keeps whatever the level above (F11)` : String(app.paranoia_level)],
          ["Body checked", prof && !prof.body_checked ? "no — the body was not read to its end, so its parameters were not checked" : ""]]),
        prof ? (prof.findings.length ? el("div", { class: "table-wrap" }, el("table", {},
          el("thead", {}, el("tr", {}, el("th", {}, "Finding"), el("th", {}, "Where"), el("th", {}, "What"))),
          el("tbody", {}, prof.findings.map((f) => el("tr", {},
            el("td", { class: "nowrap" }, f.kind), el("td", { class: "mono loc" }, f.location), el("td", { class: "wrap" }, f.message))))))
          : el("p", { class: "muted" }, "The request is what the profile allows.")) : null) : null,
        card("What the engine read", kv([
          ["Request line", el("code", { class: "wrap" }, line)],
          ["Path, decoded", el("code", { class: "wrap" }, rd.path || "–")],
          ["Client", rd.client || "none given"],
          ["Headers", nf.format(rd.headers)],
          ["Body", bytes(rd.body_length)]]),
        read.length ? pairs(read, "From") : el("p", { class: "muted" }, "No parameters, cookies or files."),
        rd.not_shown ? el("p", { class: "muted" }, `${nf.format(rd.not_shown)} more are not listed.`) : null),
        el("details", { class: "card", "data-key": "test-json" }, el("summary", {}, "The answer as JSON"),
          el("div", { class: "raw-tools" }, copyButton(json, "the answer as JSON")),
          el("pre", { class: "block" }, json)));
      fitChips(result);
    }

    replace(el("div", { class: "stack" },
      el("section", { class: "card" },
        el("div", { class: "test-bar" },
          field("Example", exampleSel, "wide"),
          info.files.length ? [field("CRS rule", fileSel), field("CRS test", caseSel, "wide")] : null),
        info.files_error ? el("p", { class: "error" }, "The example files can't be listed: " + info.files_error) : null,
        hint,
        text,
        el("div", { class: "test-bar settings" },
          field("Configuration", configSel, "wide"),
          field("Paranoia level", levelSel),
          field("Application", appSel),
          field("Client address", client),
          field("Body line ends", crlfSel)),
        configNote,
        el("div", { class: "test-run" }, runButton, el("span", { class: "muted" }, "or Ctrl+Enter"), size),
        lengthNote),
      result), false);

    fillChoices();
    if (info.examples.length) load(info.examples[0], false);
    measure();
  }

  // ---- Users, your account and the log (docs/development-plan-marks-users.md, G3–G5) ----

  // send posts JSON and returns the answer; an answer that is not OK
  // throws an error with its message and status.
  async function send(path, data) {
    const res = await fetch(path, {
      method: "POST", credentials: "same-origin", body: JSON.stringify(data),
      headers: { "Content-Type": "application/json", Accept: "application/json" },
    });
    if (res.status === 401) {
      location.assign("/login?" + query({ next: location.pathname + location.search }));
      throw new Error("login required");
    }
    let answer = {};
    try { answer = await res.json(); } catch (e) { /* no JSON */ }
    if (!res.ok) {
      const err = new Error(answer.error || `${res.status} ${res.statusText}`);
      err.status = res.status;
      throw err;
    }
    return answer;
  }

  const roleNames = { viewer: "Viewer", analyst: "Analyst", admin: "Admin" };
  const roleText = {
    viewer: "reads every page",
    analyst: "also marks alerts and uses the test tab",
    admin: "also manages users and sees the log",
  };

  // shown is a notification above a page's content: what a change did.
  function shown(box, kind, title, text, ...more) {
    refill(box, el("div", { class: "stack" }, banner(kind, title, text), ...more));
  }

  async function usersPage() {
    const notice = el("div", { "aria-live": "polite" });
    const password = el("input", { type: "password", name: "password", autocomplete: "current-password", placeholder: "Your password" });
    const table = el("div");
    const newName = el("input", { name: "name", autocomplete: "off", spellcheck: "false", placeholder: "for example ayse" });
    const newRole = el("select", { name: "role" }, ["viewer", "analyst", "admin"].map((r) => el("option", { value: r }, roleNames[r])));
    let data;

    async function act(change, done) {
      if (!password.value) {
        shown(notice, "warning", "Your password is needed.", "Every change of users asks for it again.");
        password.focus();
        return;
      }
      try {
        const answer = await send("/api/users", Object.assign({ password: password.value }, change));
        const extra = answer.password ? el("p", {}, "New password for ", el("strong", {}, change.name), " (shown only now): ",
          el("code", {}, answer.password), copyButton(answer.password, "the password")) : null;
        shown(notice, answer.warning ? "warning" : "success", done + ".", answer.warning || "It is written to the log.", extra);
        await load();
      } catch (err) {
        if (err.message !== "login required") shown(notice, "error", "Not changed.", err.message);
      }
    }

    function row(u) {
      const role = el("select", { name: "role-" + u.name, "aria-label": "Role of " + u.name },
        data.roles.map((r) => el("option", { value: r, selected: r === u.role }, roleNames[r] || r)));
      const save = el("button", { type: "button", class: "small", hidden: true }, "Change role");
      role.addEventListener("change", () => { save.hidden = role.value === u.role; });
      save.addEventListener("click", () => act({ action: "role", name: u.name, role: role.value },
        `${u.name} is now ${roleNames[role.value] || role.value}`));
      const you = u.name === data.you;
      return el("tr", {},
        el("td", {}, u.name, you ? el("span", { class: "muted" }, " (you)") : null),
        el("td", {}, el("div", { class: "role-cell" }, role, save)),
        el("td", { class: "nowrap" }, fmtTime(u.created)),
        el("td", { class: "nowrap actions" },
          el("button", { type: "button", class: "small", onclick: () => act({ action: "reset", name: u.name }, `${u.name} has a new password`) }, "Reset password"),
          el("button", {
            type: "button", class: "small danger", onclick: () => {
              if (window.confirm(`Remove the user ${u.name}?${you ? " You will be logged out." : ""}`)) act({ action: "remove", name: u.name }, `${u.name} is removed`);
            },
          }, "Remove")));
    }

    async function load() {
      try {
        data = await api("/api/users");
      } catch (err) {
        if (err.message !== "login required") failed(err);
        return;
      }
      refill(table, el("div", { class: "table-wrap" }, el("table", { class: "users" },
        el("thead", {}, el("tr", {}, el("th", {}, "User"), el("th", {}, "Role"), el("th", {}, "Added"), el("th", {}, ""))),
        el("tbody", {}, data.users.map(row)))));
    }

    replace(el("div", { class: "stack" },
      notice,
      card("Your password", el("div", { class: "test-bar" }, el("label", {}, "Asked again for every change below", password))),
      card("Users", table),
      card("Add a user",
        el("form", { class: "test-bar", onsubmit: (e) => {
          e.preventDefault();
          const name = newName.value.trim();
          act({ action: "add", name, role: newRole.value }, `${name} is added as ${roleNames[newRole.value]}`).then(() => { newName.value = ""; });
        } },
        el("label", {}, "Name", newName), el("label", {}, "Role", newRole),
        el("button", { type: "submit", class: "primary" }, "Add user")),
        el("ul", { class: "plain muted" }, ["viewer", "analyst", "admin"].map((r) => el("li", {}, `${roleNames[r]}: ${roleText[r]}.`))),
        el("p", { class: "muted" }, "The new user's password is made at random and shown here once; pass it on to them. They can change it on their account page."))), false);
    await load();
  }

  async function accountPage() {
    const notice = el("div", { "aria-live": "polite" });
    const field = (name, label, auto) => el("label", {}, label, el("input", { type: "password", name, autocomplete: auto }));
    const form = el("form", { class: "account-form" },
      field("current", "Current password", "current-password"),
      field("new", "New password", "new-password"),
      field("again", "New password again", "new-password"),
      el("div", {}, el("button", { type: "submit", class: "primary" }, "Change password")));
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const v = (n) => form.elements[n].value;
      if (v("new") !== v("again")) {
        shown(notice, "error", "Not changed.", "The two new passwords are not the same.");
        return;
      }
      try {
        const answer = await send("/api/account", { current: v("current"), new: v("new"), again: v("again") });
        form.reset();
        shown(notice, answer.warning ? "warning" : "success", "Your password is changed.", answer.warning || "Your other sessions have ended; this one goes on.");
      } catch (err) {
        if (err.message !== "login required") shown(notice, "error", "Not changed.", err.message);
      }
    });
    const user = document.querySelector(".who");
    const role = body.dataset.role || "";
    replace(el("div", { class: "stack" },
      notice,
      card("You", kv([["User", user ? user.firstChild.textContent.trim() : ""], ["Role", `${roleNames[role] || role}: ${roleText[role] || ""}`]])),
      card("Change your password", form,
        el("p", { class: "muted" }, "At least 15 characters. Any characters count, and there are no rules about mixing kinds: a few unrelated words make a long password that is easy to remember."))), false);
  }

  async function logPage() {
    const params = new URLSearchParams(location.search);
    const kinds = [
      ["", "Everything"], ["change", "Changes"], ["login", "Logins"], ["mark", "Marks"],
      ["user_added", "User added"], ["user_removed", "User removed"], ["role_changed", "Role changed"],
      ["password_reset", "Password reset"], ["password_changed", "Own password changed"],
    ];
    const userSel = el("select", { name: "user" }, el("option", { value: "" }, "Every user"));
    const kindSel = el("select", { name: "kind" }, kinds.map(([v, t]) => el("option", { value: v }, t)));
    const pager = el("div", { class: "pager" });
    const table = el("div");
    let page = Number(params.get("page")) || 1;
    kindSel.value = params.get("kind") || "";

    const verdictNames = { not_reviewed: "not reviewed", real_attack: "real attack", expected: "expected", false_positive: "false positive", undetermined: "undetermined" };
    function what(e) {
      if (e.kind === "login") {
        const results = { ok: "logged in", failed: "wrong password at login", wait: "login refused while waiting", logout: "logged out",
          "confirm ok": "confirmed their password", "confirm failed": "wrong password when confirming a change", "confirm wait": "change refused while waiting" };
        return [results[e.result] || e.result, e.ip ? el("span", { class: "muted" }, " from " + e.ip) : null];
      }
      const c = e.change;
      switch (c.action) {
        case "user_added": return `added the user ${c.target} as ${c.role}`;
        case "user_removed": return `removed the user ${c.target} (${c.role})`;
        case "role_changed": return `changed the role of ${c.target} from ${c.old_role} to ${c.role}`;
        case "password_reset": return `reset the password of ${c.target}`;
        case "password_changed": return "changed their own password";
        case "mark": return [`marked ${nf.format(c.records)} ${c.records === 1 ? "record" : "records"} as ${verdictNames[c.verdict] || c.verdict}`,
          c.note ? el("div", { class: "sub" }, "Note: " + c.note) : null,
          c.filter ? el("div", { class: "sub" }, "All that matched ", el("a", { href: "/alerts?" + c.filter }, c.filter)) : null,
          c.ids && c.ids.length ? el("div", { class: "sub" }, "Records: ", c.ids.slice(0, 10).map((id, i) => [i ? ", " : "", el("a", { href: "/alerts/" + encodeURIComponent(id) }, id.slice(0, 8))]), c.ids.length > 10 ? ` and ${c.ids.length - 10} more` : "") : null,
          c.before ? el("div", { class: "sub" }, "Before: " + Object.entries(c.before).map(([v, n]) => `${nf.format(n)} ${verdictNames[v] || v}`).join(", ")) : null];
      }
      return c.action;
    }

    async function load() {
      let p;
      try {
        p = await api("/api/log?" + query({ user: userSel.value, kind: kindSel.value, page }));
      } catch (err) {
        if (err.message !== "login required") failed(err);
        return;
      }
      const chosen = userSel.value;
      refill(userSel, el("option", { value: "" }, "Every user"), p.users.map((u) => el("option", { value: u }, u)));
      userSel.value = p.users.includes(chosen) ? chosen : "";
      page = p.page;
      history.replaceState(null, "", "/log?" + query({ user: userSel.value, kind: kindSel.value, page: page > 1 ? page : "" }));
      refill(pager, el("span", { class: "muted" }, `${nf.format(p.total)} ${p.total === 1 ? "entry" : "entries"}, page ${p.page} of ${p.pages}`),
        el("button", { type: "button", class: "small", disabled: p.page <= 1, onclick: () => { page--; load(); } }, "Newer"),
        el("button", { type: "button", class: "small", disabled: p.page >= p.pages, onclick: () => { page++; load(); } }, "Older"));
      refill(table, p.entries.length ? el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, el("th", {}, "Time"), el("th", {}, "User"), el("th", {}, "Kind"), el("th", {}, "What"))),
        el("tbody", {}, p.entries.map((e) => el("tr", {},
          el("td", { class: "nowrap" }, fmtTime(e.time)),
          el("td", { class: "nowrap" }, e.user || "–"),
          el("td", { class: "nowrap" }, e.kind === "login" ? "login" : "change"),
          el("td", { class: "wrap" }, what(e)))))))
        : el("p", { class: "empty" }, "Nothing in the log for this choice."),
      p.unreadable ? el("p", { class: "muted" }, `${nf.format(p.unreadable)} lines of the log files could not be read.`) : null);
    }

    userSel.value = params.get("user") || "";
    for (const s of [userSel, kindSel]) s.addEventListener("change", () => { page = 1; load(); });
    replace(el("div", { class: "stack" },
      el("section", { class: "card" },
        el("div", { class: "test-bar" }, el("label", {}, "User", userSel), el("label", {}, "Kind", kindSel)),
        pager, table)), false);
    await load();
  }

  const theme = document.getElementById("theme");
  if (theme) {
    theme.value = document.documentElement.dataset.theme || "";
    theme.addEventListener("change", () => {
      if (theme.value) document.documentElement.dataset.theme = theme.value;
      else delete document.documentElement.dataset.theme;
      store("localStorage", "ids.theme", theme.value);
    });
  }

  const pages = { overview: overviewPage, alerts: alertsPage, alert: alertPage, rules: rulesPage, engine: enginePage, test: testPage, users: usersPage, account: accountPage, log: logPage, login: loginPage };
  if (pages[page] && (view || page === "login")) pages[page]();
})();
