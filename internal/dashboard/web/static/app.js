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
    refill(live.notice, banner("warning", "Could not update.", `${err.message}. ` +
      (live.at ? `The data below is from ${fmtClock.format(live.at)}. ` : "") +
      `Trying again every ${poll / 1000} seconds.`));
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
  // choice in this browser, else 24 hours. Its control is Carbon's content
  // switcher in the page's head; with none, no item is selected (a period
  // of the alerts list chosen on a chart).
  const period = {
    value: (() => {
      const v = new URLSearchParams(location.search).get("range") || stored("localStorage", "ids.range");
      return ranges.includes(v) ? v : "24h";
    })(),
    group: document.getElementById("period"),
    show(none) {
      if (this.group) this.group.value = none ? "" : this.value;
    },
    onChange(fn) {
      if (!this.group) return;
      this.show();
      segmented(this.group, this.value, (v) => {
        if (!ranges.includes(v)) return;
        this.value = v;
        store("localStorage", "ids.range", v);
        fn(v);
      });
    },
  };

  // segmented wires a content switcher: one choice of a few.
  function segmented(group, value, pick) {
    group.value = value;
    group.addEventListener("cds-content-switcher-selected", (e) => pick(e.detail.item.value));
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

  // banner is Carbon's inline notification, low contrast: a status icon,
  // a title and a sentence. kind is "error", "warning", "success" or
  // "info". The title goes into its slot, not the title attribute, which
  // the browser would show as a tooltip.
  function banner(kind, title, text) {
    // Messages from the server start in lower case; here they follow a
    // title, as a sentence of their own.
    if (typeof text === "string" && text) text = text[0].toUpperCase() + text.slice(1);
    return el("cds-inline-notification", { kind, "low-contrast": true, "hide-close-button": true, role: kind === "error" ? "alert" : "status" },
      el("span", { slot: "title" }, title), text ? el("span", { slot: "subtitle" }, text) : null);
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
  // With analysed false the chart leaves out the requests analysed, which
  // the IDS counts for all of its requests only (an application's or a
  // rule's chart).
  function columns(o, pick, analysed = true) {
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
        analysed ? el("div", { class: "line" }, el("span", { class: "key" }), el("strong", {}, nf.format(b.analysed)), "requests analysed") : null,
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

    const rows = series.filter((b) => b.records > 0 || (analysed && b.analysed > 0));
    const table = el("details", { class: "table-view", "data-key": "table" }, el("summary", {}, "Show as a table"),
      el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {}, el("th", {}, "Period"), analysed ? el("th", { class: "num" }, "Analysed") : null, el("th", { class: "num" }, "Records"), el("th", { class: "num" }, "Alerts"))),
        el("tbody", {}, rows.length ? rows.map((b) => el("tr", {},
          el("td", {}, fmtSpan(b.start, ends(b)), partial(b) ? " (so far)" : ""),
          analysed ? el("td", { class: "num" }, nf.format(b.analysed)) : null, el("td", { class: "num" }, nf.format(b.records)), el("td", { class: "num" }, nf.format(b.alerts))))
          : el("tr", {}, el("td", { colspan: analysed ? 4 : 3, class: "muted" }, "Nothing in this period."))))));
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

  // appFilter wires the application filter of a page's filter bar (W1):
  // "All applications" by default, kept in the page's address. Its choices
  // come with the answers; it shows once there are applications. pick is
  // called with the new choice.
  function appFilter(form, chosen, pick) {
    const select = form && form.elements.app;
    let choices = null;
    if (select) {
      select.addEventListener("change", () => pick(select.value));
      form.addEventListener("submit", (e) => e.preventDefault());
    }
    return (names) => {
      if (!select || names.join("\n") === choices) return;
      choices = names.join("\n");
      const value = select.value || chosen;
      refill(select, el("option", { value: "" }, "All applications"), names.map((n) => el("option", { value: n }, appName(n))));
      if (value && !names.includes(value)) select.append(el("option", { value }, appName(value)));
      select.value = value;
      form.hidden = names.length === 0 && !value;
    };
  }

  // appLink is the address of an application's page, or of its tab.
  const appLink = (name, tab) => "/applications/" + encodeURIComponent(name) + (tab ? "/" + tab : "");

  // modeText says what an application's mode means (F6).
  const modeText = (mode) => (mode === "alert" ? "alert: a profile finding makes the request an alert" : "monitor: profile findings are recorded, not alerts");

  // overviewPage is the overview of every request, or of one application
  // chosen in its filter bar (W1). On an application's page it is the
  // Summary tab, with the application fixed and its settings first (W3).
  function overviewPage() {
    const fixed = body.dataset.app || "";
    const form = fixed ? null : document.getElementById("filters");
    let app = fixed || new URLSearchParams(location.search).get("app") || "";
    const address = () => (fixed ? location.pathname : "/") + "?" + query({ range: period.value, app: fixed ? "" : app });
    const showApps = appFilter(form, app, (v) => {
      app = v;
      history.replaceState(null, "", address());
      view.classList.add("loading");
      run();
    });
    const load = async () => {
      const range = period.value;
      const url = "/api/overview?" + query({ range, app });
      const calls = [api(url), api("/api/alerts?" + query({ range, kind: "alerts", app }))];
      if (fixed) calls.push(api("/api/applications/" + encodeURIComponent(fixed) + "?" + query({ range })));
      const [o, latest, info] = await Promise.all(calls);
      showApps(latest.applications);
      const newest = latest.rows.slice(0, 8);
      if (same(url, { o, newest, info })) return;
      const alertsLink = (extra) => "/alerts?" + query({ range, app, ...extra });
      const nothing = o.recorded === 0 && o.analysed === 0;
      const share = (v) => (o.analysed > 0 ? pf.format(v / o.analysed) + " of requests analysed" : "");
      const pick = (from, to) => {
        const start = toDate(o.range.from);
        if (start && start > toDate(from)) from = start; // the first bar starts before the period
        location.assign("/alerts?" + query({ kind: "all", app, from: toDate(from).toISOString(), to: to.toISOString() }));
      };
      const ruleName = (i) => [el("strong", {}, i.key), " ", i.msg || i.label, i.msg ? el("span", { class: "muted" }, " · " + i.label) : null];
      const ruleHref = (i) => "/rules/" + encodeURIComponent(i.key) + "?" + query({ range });
      // The live input's parts show when the newest run is live, or when
      // the period has gaps from an earlier one; they are not kept per
      // application.
      const liveInput = !app && (o.live || o.not_analysed > 0);
      const missedNote = o.not_analysed_by.slice(0, 2).map((m) => `${nf.format(m.missed)} ${gapReasons[m.reason] || m.reason}`).join(" · ");
      const reviewed = o.alerts ? `${nf.format(o.not_reviewed)} not reviewed` : "";
      const tiles = app ? [
        tile("Alerts", o.alerts, [o.last_alert ? "last alert " + ago(o.last_alert) : "", reviewed], true),
        tile("Records", o.recorded, "a finding or an incomplete analysis"),
        tile("Marked false positive", o.false_positives, "records of this period"),
        tile("Incomplete analyses", o.incomplete, "parts that could not be inspected")] : [
        tile("Alerts", o.alerts, o.analysed > 0 || o.last_alert ? [share(o.alerts), o.last_alert ? "last alert " + ago(o.last_alert) : "", reviewed] : "score reached the threshold", true),
        tile("Records", o.recorded, "a finding or an incomplete analysis"),
        tile("Requests analysed", o.analysed, o.profiled ? ["from the counts of the IDS", `${nf.format(o.no_profile)} of no application: the rules only, no profile`] : "from the counts of the IDS"),
        liveInput ? tile("Not analysed", o.not_analysed, o.not_analysed > 0 ? missedNote : "nothing was dropped") : null,
        tile("Incomplete analyses", o.incomplete, share(o.incomplete) || "parts that could not be inspected")];
      replace(el("div", { class: "stack" },
        liveBanners(o.live),
        info ? appSettingsCard(info) : null,
        el("div", { class: "tiles" }, tiles),
        card("Records over time",
          el("div", { class: "legend" },
            el("span", { class: "key" }, el("span", { class: "swatch alerts" }), "Alerts"),
            el("span", { class: "key" }, el("span", { class: "swatch others" }), "Records below the threshold"),
            el("span", { class: "key" }, el("span", { class: "swatch partial" }), "Period not over yet")),
          app && !fixed ? el("p", { class: "muted" }, `The records of ${app === "none" ? "requests of no application" : "the application " + app}. The IDS counts the requests it analysed for all applications together, so they are not shown here.`) : null,
          nothing ? el("p", { class: "empty" }, app ? "No records of this application in this period." : "No records in this period. Run the IDS with records, or choose a longer period.") : columns(o, pick, !app)),
        el("section", { class: "card" },
          el("div", { class: "card-head" }, el("h2", {}, "Latest alerts"), latest.total ? el("a", { href: alertsLink({}) }, `All ${nf.format(latest.total)} alerts →`) : null),
          newest.length ? listTable(newest, { apps: !app && latest.applications.length > 1, verdict: true }) : el("p", { class: "empty" }, "No alerts in this period.")),
        liveInput || o.unknown_applications.length ? el("div", { class: "grid-2" },
          liveInput ? gapsCard(o) : null,
          o.unknown_applications.length ? unknownAppsCard(o) : null) : null,
        el("div", { class: "grid-2x2" },
          card("Rules that fired most", toplist(o.top_rules, ruleName, ruleHref)),
          card("Attack groups", toplist(o.top_groups, (i) => i.key, (i) => alertsLink({ kind: "all", group: i.key }))),
          card("Where in the request", toplist(o.top_locations, (i) => i.key, (i) => alertsLink({ kind: "all", location: i.key }))),
          card("Client IP addresses", toplist(o.top_ips, (i) => i.key, (i) => alertsLink({ kind: "all", ip: i.key })))),
        info ? card("Paths with the most records", toplist(info.top_paths, (i) => el("span", { class: "mono" }, i.key))) : null));
    };
    const run = every(load);
    period.onChange(() => {
      history.replaceState(null, "", address());
      view.classList.add("loading");
      run();
    });
  }

  // appSettingsCard is an application's settings, first on its Summary
  // tab (W3).
  function appSettingsCard(info) {
    const a = info.application;
    if (!a.running) {
      return card(`Settings of ${a.name}`, banner("warning", "Not in the running configuration.",
        `The newest run, started ${fmtTime(info.run_time)}, has no application ${a.name}; its records are older. Its settings are no longer known.`));
    }
    return card(`Settings of ${a.name}`, kv([
      ["Hosts", el("span", { class: "mono" }, a.hosts.join(", "))],
      ["Paths", a.paths && a.paths.length ? el("span", { class: "mono" }, a.paths.join(", ")) : "every path of its hosts"],
      ["Profile file", el("code", {}, a.profile)],
      ["Mode", modeText(a.mode)],
      ["Paranoia level", a.paranoia_level === info.default_level ? `${a.paranoia_level} (the default is ${info.default_level})` : `${a.paranoia_level}, its own (the default is ${info.default_level})`],
      ["Rule exceptions", el("a", { href: appLink(a.name, "rules") }, a.exceptions.length ? `${a.exceptions.length} on its Rules tab` : "none; its Rules tab shows every rule")],
      ["Notes", a.notes && a.notes.length ? a.notes.map((n) => el("div", { class: "sub" }, n)) : ""]]));
  }

  // ---- Applications (W1–W3) ----

  function applicationsPage() {
    const addNotice = el("div", { "aria-live": "polite" });
    const newName = el("input", { name: "name", placeholder: "shop-2", maxlength: 64, autocomplete: "off", spellcheck: "false" });
    const newHosts = el("input", { name: "hosts", placeholder: "shop.example.com, shop.example.com:8443", autocomplete: "off", spellcheck: "false" });
    const newPaths = el("input", { name: "paths", placeholder: "every path", autocomplete: "off", spellcheck: "false" });
    const addForm = card("Add an application",
      el("p", { class: "muted" }, "It starts in monitor mode with a profile that allows every path, at the default level, until its profile is written. The change is pending under Settings for every application, where it is applied with its preview."),
      el("div", { class: "inline-form" }, formRow("Name", newName), formRow("Hosts", newHosts), formRow("Paths", newPaths),
        el("button", { type: "button", class: "small", onclick: async () => {
          const ch = await addChange("global", { kind: "add_app", name: newName.value.trim(), hosts: lines(newHosts.value), paths: lines(newPaths.value) }, addNotice);
          if (ch) { append(addNotice.firstChild, [" ", el("a", { href: "/settings" }, "Apply it under Settings →")]); newName.value = newHosts.value = newPaths.value = ""; }
        } }, "Add the application, pending")));
    const run = every(async () => {
      const range = period.value;
      const url = "/api/applications?" + query({ range });
      const p = await api(url);
      if (same(url, p)) return;
      const alerts = (name, extra) => "/alerts?" + query({ range, app: name, ...extra });
      const count = (n, href) => (n ? el("a", { href }, nf.format(n)) : "0");
      const row = (a, none) => el("tr", {},
        el("td", {}, none ? el("a", { href: alerts("none", { kind: "all" }) }, "Requests of no application")
          : el("a", { href: appLink(a.name) }, a.name), !none && !a.running ? el("div", { class: "sub" }, "not in the running configuration") : null),
        el("td", { class: "mono" }, none ? el("span", { class: "muted" }, "every other host and path") : a.hosts.map((h) => el("div", {}, h + (a.paths && a.paths.length ? " " + a.paths.join(", ") : "")))),
        el("td", {}, none ? el("span", { class: "muted" }, "rules only") : a.running ? a.mode : "–"),
        el("td", {}, a.running ? String(a.paranoia_level) : "–"),
        el("td", { class: "num" }, none || !a.running ? "–" : el("a", { href: appLink(a.name, "rules") }, nf.format(a.exceptions.length))),
        el("td", { class: "num" }, count(a.alerts, alerts(a.name, {}))),
        el("td", { class: "num" }, count(a.not_reviewed, alerts(a.name, { review: "not_reviewed" }))),
        el("td", { class: "num" }, count(a.false_positives, alerts(a.name, { kind: "all", review: "false_positive" }))),
        el("td", { class: "nowrap" }, a.last_alert ? ago(a.last_alert) : "–"));
      const head = [["Application", ""], ["Hosts", ""], ["Mode", ""], ["Level", ""], ["Exceptions", "num"], ["Alerts", "num"], ["Not reviewed", "num"], ["False positives", "num"], ["Last alert", ""]];
      replace(el("div", { class: "stack" },
        addNotice,
        el("p", { class: "lead muted" }, "Each application has its own profile, paranoia level and rule exceptions, on its own page. " +
          `Requests of no application run at the default level ${p.default_level}, with the rules only` +
          (p.require_profile ? ", and get a no_profile finding (require_profile)." : ".")),
        p.applications.length ? card(null, el("div", { class: "table-wrap" }, el("table", { class: "wide apps" },
          el("thead", {}, el("tr", {}, head.map(([h, c]) => el("th", { class: c }, h)))),
          el("tbody", {}, p.applications.map((a) => row(a, false)), row(p.none, true)))))
          : card(null, el("p", { class: "empty" }, "The running configuration has no applications. An application is named with its hosts and a profile file under \"applications\" in the product configuration."),
            p.none.records ? el("p", {}, el("a", { href: alerts("none", { kind: "all" }) }, `${nf.format(p.none.records)} records of no application in this period →`)) : null),
        adminRole ? addForm : null));
    });
    period.onChange(() => {
      history.replaceState(null, "", "/applications?" + query({ range: period.value }));
      view.classList.add("loading");
      run();
    });
  }

  // applicationPage is one application's page: its Summary tab, the
  // overview of its records, its Rules tab or its History tab (W3). Its
  // pending changes are above every tab (W7).
  function applicationPage() {
    const object = "app:" + body.dataset.app;
    changesPanel(object, document.getElementById("changes"));
    if (body.dataset.tab === "rules") rulesPage();
    else if (body.dataset.tab === "history") historyPage(object);
    else if (body.dataset.tab === "settings") appSettingsTab(object, body.dataset.app);
    else if (body.dataset.tab === "profile") profileTab(object, body.dataset.app);
    else overviewPage();
  }

  // ---- Settings: one application's (W3), and every application's (W4) ----

  // formRow is a label, its control and a line of help.
  const formRow = (label, control, help) => el("label", { class: "form-row" }, el("span", { class: "field-label" }, label), control, help ? el("span", { class: "help" }, help) : null);
  // lines splits a list typed one per line, or with commas.
  const lines = (text) => text.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

  function appSettingsTab(object, name) {
    const notice = el("div", { "aria-live": "polite" });
    every(async () => {
      const url = "/api/applications/" + encodeURIComponent(name) + "/settings";
      const a = await api(url);
      if (same(url, a)) return;
      if (!a.configured || a.error) {
        replace(card(null, banner("warning", "The settings can't be shown.", a.error)));
        return;
      }
      const can = adminRole;
      const add = (label, make, who) => (who === undefined ? can : who) ? el("button", { type: "button", class: "small", onclick: () => { const ch = make(); if (ch) addChange(object, ch, notice); } }, label) : null;
      const mode = el("select", { name: "mode", disabled: !can }, ["monitor", "alert"].map((m) => el("option", { value: m }, modeText(m))));
      mode.value = a.mode;
      const level = el("select", { name: "level", disabled: !can }, el("option", { value: "0" }, `The default (${a.default_level})`), [1, 2, 3, 4].map((n) => el("option", { value: String(n) }, `Level ${n}`)));
      level.value = String(a.level);
      const hosts = el("textarea", { name: "hosts", rows: 3, disabled: !can, spellcheck: "false" }, a.hosts.join("\n"));
      const paths = el("textarea", { name: "paths", rows: 2, disabled: !can, spellcheck: "false", placeholder: "every path of its hosts" }, a.paths.join("\n"));
      const crs = a.exceptions.filter((ex) => ex.setting);
      const rulesExcepted = a.exceptions.filter((ex) => ex.rule).length;
      const setName = el("select", { name: "setting" }, a.settings.map((st) => el("option", { value: st.name }, `${st.name} (${st.kind === "flag" ? "0 or 1" : st.kind})`)));
      const setValue = el("input", { name: "value", placeholder: "Its value for " + name, autocomplete: "off", spellcheck: "false" });
      const setReason = el("input", { name: "setting-reason", placeholder: "Why? It is shown with the setting", maxlength: 1000, autocomplete: "off" });
      const block = `ids_copy {\n    application ${a.name}\n    socket ${a.socket || "/run/ids/copy.sock"}\n}`;
      replace(el("div", { class: "stack" }, notice,
        card(`How ${name}'s requests are analysed`,
          el("div", { class: "form-grid" },
            formRow("Mode", mode, "In alert mode a profile finding makes the request an alert; in monitor mode it is recorded only."),
            add(`Set the mode for ${name}`, () => ({ kind: "mode", mode: mode.value })),
            formRow("Paranoia level", level, `For ${name} only. The default is set for every application under Settings.`),
            add(`Set the level for ${name}`, () => ({ kind: "level", level: Number(level.value) }))),
          el("p", { class: "muted" }, `Rule exceptions: ${rulesExcepted} ${rulesExcepted === 1 ? "rule is" : "rules are"} off or skip places for ${name}; each is changed on `, el("a", { href: appLink(name, "rules") }, "its Rules tab"), ".")),
        card(`Which requests are ${name}'s`,
          el("div", { class: "form-grid" },
            formRow("Hosts", hosts, "The Host values of its requests, one per line, with the port when they carry one."),
            add(`Set the hosts of ${name}`, () => ({ kind: "hosts", hosts: lines(hosts.value) })),
            formRow("Paths", paths, "Path prefixes, one per line, for applications that share a host; empty for every path."),
            add(`Set the paths of ${name}`, () => ({ kind: "paths", paths: lines(paths.value) })))),
        card(`CRS settings for ${name}`,
          el("p", { class: "muted" }, `A profile may change some of CRS's settings for its application only, such as the methods it allows or the longest argument. Each needs a reason.`),
          crs.length ? el("ul", { class: "plain" }, crs.map((ex) => el("li", {}, el("code", {}, `${ex.setting} = "${ex.value}"`), " · ", ex.reason, " ",
            add("Back to the default for " + name, () => ({ kind: "setting_remove", setting: ex.setting }))))) : el("p", { class: "muted" }, `${name} has CRS's default for every setting.`),
          analyst ? el("div", { class: "inline-form" }, formRow("Setting", setName), formRow("Value", setValue), formRow("Reason", setReason),
            add(can ? `Add for ${name}` : `Propose for ${name}`, () => ({ kind: "setting", setting: setName.value, value: setValue.value.trim(), reason: setReason.value.trim() }), true)) : null),
        card("The proxy's side (Caddy)",
          el("p", { class: "muted" }, `Caddy's copier says which application each copy belongs to. In the Caddyfile, put this in ${name}'s site block, beside reverse_proxy, and reload Caddy. The dashboard does not change Caddy itself (W18).`),
          el("pre", { class: "block" }, block), el("div", {}, copyButton(block, "the ids_copy block")),
          a.socket ? null : el("p", { class: "muted" }, "The configuration has no live socket, so the one shown is an example; use the socket ids-live listens on.")),
        card(null, kv([["Profile file", el("code", {}, a.profile)]]),
          el("p", { class: "muted" }, "Its endpoints, parameters, cookies and headers are on ", el("a", { href: appLink(name, "profile") }, "its Profile tab"), "."),
          can ? el("button", { type: "button", class: "small danger", onclick: () => {
            if (window.confirm(`Remove the application ${name}? Once applied, its requests run as requests of no application. Its profile file is kept.`)) addChange(object, { kind: "remove_app" }, notice);
          } }, `Remove the application ${name}…`) : null)));
    });
  }

  // profileTab is an application's Profile tab (W15, W16): suggestions
  // from its records, and its profile as JSON, checked as one types, for
  // what the forms of the Settings and Rules tabs don't cover: endpoints,
  // parameters, cookies and headers.
  async function profileTab(object, name) {
    const notice = el("div", { "aria-live": "polite" });
    const status = el("p", { class: "muted check-status", "aria-live": "polite" });
    const editor = el("textarea", { class: "editor profile-editor", rows: 28, spellcheck: "false", autocomplete: "off", autocapitalize: "off", wrap: "off", readonly: !adminRole, "aria-label": `The profile of ${name}, as JSON` });
    let p;
    try {
      p = await api("/api/applications/" + encodeURIComponent(name) + "/profile");
    } catch (err) {
      if (err.message !== "login required") failed(err);
      return;
    }
    if (!p.configured || (p.error && !p.text)) {
      replace(card(null, banner("warning", "The profile can't be shown.", p.error)));
      return;
    }
    editor.value = p.text;
    let timer = null;
    const check = async () => {
      try {
        const r = await send("/api/applications/" + encodeURIComponent(name) + "/profile/check", { text: editor.value });
        refill(status, r.ok ? `It reads correctly: ${r.endpoints} ${r.endpoints === 1 ? "endpoint" : "endpoints"}, mode ${r.mode}, ${r.exceptions} ${r.exceptions === 1 ? "exception" : "exceptions"}.${editor.value === p.text ? " It is the file as it is." : " Changed, not added yet."}`
          : el("span", { class: "error" }, "It does not read: " + r.error));
        return r.ok;
      } catch (err) {
        if (err.message !== "login required") refill(status, el("span", { class: "error" }, "Not checked: " + err.message));
        return false;
      }
    };
    editor.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(check, 400); });

    // A suggestion goes into the editor's text, where it can be read and
    // corrected before the profile is added to the pending changes.
    const addToEditor = (sg, types) => {
      let doc;
      try { doc = JSON.parse(editor.value); } catch (e) {
        refill(notice, banner("error", "The editor's text is not JSON.", "Correct it first; the check below says where."));
        return;
      }
      if (sg.only_alerts && !window.confirm(`Every record of ${sg.method} ${sg.path} is an alert of the rules: it is more likely an attack than a part of ${name}. Allow it in the profile all the same?`)) return;
      doc.endpoints = doc.endpoints || [];
      let ep = sg.endpoint ? doc.endpoints.find((x) => x.path === sg.endpoint && (x.method === sg.method || (x.methods || []).includes(sg.method))) : null;
      if (!ep) {
        ep = { note: `Added from the records on ${fmtTime(new Date())}`, method: sg.method, path: sg.path };
        doc.endpoints.push(ep);
      }
      const params = sg.params.filter((prm) => types[prm.name] && types[prm.name].on);
      if (params.length) {
        ep.params = ep.params || {};
        for (const prm of params) ep.params[prm.name] = { in: prm.in, type: types[prm.name].type };
      }
      editor.value = JSON.stringify(doc, null, 2) + "\n";
      check();
      refill(notice, banner("success", "Added to the editor.", `${sg.method} ${sg.path}${params.length ? " with " + params.map((x) => x.name).join(", ") : ""}. Read it in the editor below, then add the profile to the pending changes.`));
    };
    const typeNames = { string: "text", integer: "integer", number: "number", boolean: "true or false" };
    // maxParams is how many parameters a row shows before "more".
    const maxParams = 8;
    const rows = p.suggestions.map((sg) => {
      const chosen = {};
      const lines = sg.params.map((prm) => {
        chosen[prm.name] = { on: !prm.only_alerts, type: "string" };
        const box = el("input", { type: "checkbox", checked: !prm.only_alerts, "aria-label": `Add ${prm.name}`, onchange: (e) => { chosen[prm.name].on = e.target.checked; } });
        const sel = el("select", { "aria-label": `Type of ${prm.name}`, onchange: (e) => { chosen[prm.name].type = e.target.value; } }, Object.entries(typeNames).map(([v, t]) => el("option", { value: v }, t)));
        return el("div", { class: "param" + (prm.only_alerts ? " attack" : "") }, adminRole ? box : null, el("code", { class: "clip", title: prm.name }, prm.name),
          el("span", { class: "muted" }, ` ${prm.in}, ${nf.format(prm.seen)}×`), prm.only_alerts ? el("span", { class: "badge alert", title: "Every record that sent it is an alert of the rules: more likely an attack's own parameter" }, "only in alerts") : null, adminRole ? sel : null);
      });
      const shownParams = lines.length > maxParams ? [lines.slice(0, maxParams), el("details", {}, el("summary", {}, `${lines.length - maxParams} more`), lines.slice(maxParams))] : lines;
      return el("tr", {},
        el("td", { class: "mono" }, sg.method),
        el("td", { class: "mono wrap" }, sg.path),
        el("td", { class: "num" }, nf.format(sg.seen), sg.files ? el("div", { class: "sub" }, `${nf.format(sg.files)} in files`) : null),
        el("td", { class: "wrap" }, sg.endpoint ? el("code", {}, sg.endpoint) : el("span", { class: "muted" }, "no endpoint takes it")),
        el("td", { class: "wrap" }, lines.length ? shownParams : el("span", { class: "muted" }, "–")),
        el("td", {}, sg.only_alerts && sg.seen ? el("span", { class: "badge alert", title: "Every record of it is an alert of the rules: more likely an attack than a part of the application" }, "Only in alerts") : sg.seen ? `${nf.format(sg.alerts)} of ${nf.format(sg.seen)}` : "–"),
        adminRole ? el("td", {}, el("button", { type: "button", class: "small", onclick: () => addToEditor(sg, chosen) }, "Add to the editor")) : null);
    });
    replace(el("div", { class: "stack" }, notice,
      card(`Seen in ${name}'s traffic, not in its profile`,
        el("p", { class: "muted" }, "From the records: a request is recorded when it has a finding, so these are the paths and parameters the profile found unknown, and paths the rules found something in. A path seen only in alerts is marked: it is more likely an attack than a part of the application. " +
          (p.files && p.files.length ? `The requests of the last analysis in Analyse files (${p.files.join(", ")}) are counted too, with their bodies' parameters.` : "Request files analysed in Analyse files add their requests, with the bodies' parameters.")),
        rows.length ? el("div", { class: "table-wrap" }, el("table", { class: "wide suggestions" },
          el("thead", {}, el("tr", {}, ["Method", "Path", "Records", "Endpoint in the profile", "Parameters it doesn't take", "Alerts", adminRole ? "" : null].filter((h) => h !== null).map((h, i) => el("th", { class: i === 2 ? "num" : "" }, h)))),
          el("tbody", {}, rows))) : el("p", { class: "empty" }, "Nothing: every path and parameter in the records is in the profile.")),
      card(`The profile of ${name}`,
        el("p", { class: "muted" }, "Its file is ", el("code", {}, p.file), `. The mode, the level and the exceptions have forms on the Settings and Rules tabs; endpoints, parameters, cookies and headers are written here, as docs/profile-format.md describes. ` +
          (adminRole ? "The whole profile is added to the pending changes, with the same preview and undo as any change." : "An admin changes it.")),
        editor, status,
        adminRole ? el("div", { class: "form-actions" },
          el("button", { type: "button", class: "primary", onclick: async () => { if (await check()) addChange(object, { kind: "profile", text: editor.value }, notice); } }, `Add this profile of ${name} to the pending changes`), " ",
          el("button", { type: "button", onclick: () => { editor.value = p.text; check(); } }, "Back to the file as it is")) : null)), false);
    check();
  }

  // ---- Tools › Analyse files (W14) ----

  async function analysePage() {
    let info;
    try {
      info = await api("/api/analyse");
    } catch (err) {
      if (err.message !== "login required") failed(err);
      return;
    }
    const params = new URLSearchParams(location.search);
    const notice = el("div", { "aria-live": "polite" });
    const option = (value, label) => el("option", { value }, label);
    const source = el("select", { name: "source" }, option("upload", "Files from this computer"), info.folder.length ? option("folder", "Files of the example folder") : null);
    const files = el("input", { type: "file", name: "files", multiple: true, accept: ".json,application/json" });
    const folder = el("select", { name: "folder", multiple: true, size: 8 }, option("*", `All ${info.folder.length} files`), info.folder.map((f) => option(f.name, `${f.name} (${f.tests} ${f.tests === 1 ? "request" : "requests"})`)));
    const configSel = el("select", { name: "config" }, info.configs.map((c) => option(String(c.index), c.name + (c.ids ? " · the IDS's own" : ""))));
    const levelSel = el("select", { name: "level" }, option("0", "As configured"), [1, 2, 3, 4].map((n) => option(String(n), "Level " + n)));
    const appSel = el("select", { name: "application" });
    const fillApps = () => {
      const c = info.configs[Number(configSel.value)] || { applications: [] };
      refill(appSel, option("", "By Host and path"), c.applications.map((a) => option(a, a)));
    };
    configSel.addEventListener("change", fillApps);
    fillApps();
    const writeSel = info.write ? el("select", { name: "write" }, option("", "Nothing: show the result only"), option("records", "A run of records, at the time of the analysis"), option("replay", "A replay: records at the requests' own times")) : null;
    const fileRow = formRow("Request files", files, `JSON files in ids-offline's format, ${Math.round(info.max_bytes / (1 << 20))} MB at most together.`);
    const folderRow = formRow("Example files", folder, "Hold Ctrl to choose several.");
    const showSource = () => { fileRow.hidden = source.value !== "upload"; folderRow.hidden = source.value !== "folder"; };
    source.addEventListener("change", showSource);
    showSource();
    const start = el("button", { type: "button", class: "primary" }, "Analyse");
    const status = el("div", { "aria-live": "polite" });
    const resultBox = el("div", { class: "stack" });

    start.addEventListener("click", async () => {
      const form = new FormData();
      form.append("config", configSel.value);
      form.append("level", levelSel.value);
      form.append("application", appSel.value);
      if (writeSel) form.append("write", writeSel.value);
      if (source.value === "upload") for (const f of files.files) form.append("files", f, f.name);
      else for (const o of folder.selectedOptions) form.append("folder", o.value);
      start.disabled = true;
      try {
        const res = await fetch("/api/analyse", { method: "POST", body: form, credentials: "same-origin", headers: { Accept: "application/json" } });
        const answer = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(answer.error || res.statusText);
        refill(notice);
        watch();
      } catch (err) {
        refill(notice, banner("error", "Not started.", err.message));
        start.disabled = false;
      }
    });

    let timer = null;
    const watch = () => { clearTimeout(timer); timer = setTimeout(load, 700); };
    const expText = (e) => !e ? "" : e.met ? "met" : [e.missing && e.missing.length ? "missing " + e.missing.join(", ") : "", e.unwanted && e.unwanted.length ? "unwanted " + e.unwanted.join(", ") : "", e.missing_log ? "log missing" : "", e.unwanted_log ? "unwanted log" : ""].filter(Boolean).join("; ");
    let shownJob = "";
    const load = async () => {
      let p;
      try { p = await api("/api/analyse"); } catch (err) { return; }
      const j = p.job;
      start.disabled = !!(j && j.running);
      if (!j) return;
      if (j.running) {
        const bar = el("div", { class: "progress" }, el("div", { class: "bar" }));
        bar.firstChild.style.width = (j.total ? (100 * j.done / j.total).toFixed(1) : 0) + "%";
        refill(status, card(null, el("p", {}, `Analysing ${nf.format(j.done)} of ${nf.format(j.total)} requests of ${j.files.length} ${j.files.length === 1 ? "file" : "files"}, with ${j.config}…`), bar,
          el("button", { type: "button", class: "small", onclick: async () => { try { await send("/api/analyse/stop", {}); } catch (err) { /* it ended */ } } }, "Stop")));
        watch();
        return;
      }
      refill(status);
      const key = j.id + j.ended;
      if (key === shownJob) return;
      shownJob = key;
      drawResult(j);
    };

    const drawResult = (j) => {
      const prof = j.profiled;
      const total = j.summary.reduce((t, g) => {
        for (const k of ["tests", "flagged", "passed", "failed", "not_inspected"]) t[k] += g[k];
        if (prof) for (const k of ["findings", "unknown_endpoints", "alerts", "no_application"]) t.profile[k] += g.profile[k];
        return t;
      }, { tests: 0, flagged: 0, passed: 0, failed: 0, not_inspected: 0, profile: { findings: 0, unknown_endpoints: 0, alerts: 0, no_application: 0 } });
      const head = ["File", "Rule", "Requests", "Flagged", "Passed", "Failed", "Not inspected"].concat(prof ? ["Profile", "Unknown path", "P. alerts", "No app"] : []);
      const line = (name, status, g, strong) => el("tr", { class: strong ? "total" : null },
        el("td", { class: "mono" }, name), el("td", {}, status || "–"),
        [g.tests, g.flagged, g.passed, g.failed, g.not_inspected].map((v) => el("td", { class: "num" }, nf.format(v))),
        prof ? [g.profile.findings, g.profile.unknown_endpoints, g.profile.alerts, g.profile.no_application].map((v) => el("td", { class: "num" }, nf.format(v))) : null);
      const filter = el("select", { name: "rows" }, option("all", "Every request"), option("alerts", "Alerts"), option("unmet", "Expectations not met"));
      const table = el("div");
      let limit = 50;
      const drawRows = () => {
        const rows = j.rows.filter((r) => filter.value === "all" || (filter.value === "alerts" ? r.alert : r.expectation && !r.expectation.met));
        refill(table, rows.length ? el("div", { class: "table-wrap" }, el("table", { class: "wide analysed" },
          el("thead", {}, el("tr", {}, ["#", "File", "Request", "Application", "Score", "Rules", "Expectation"].map((h, i) => el("th", { class: i === 4 ? "num" : "" }, h)))),
          el("tbody", {}, rows.slice(0, limit).map((r) => el("tr", {},
            el("td", { class: "num" }, String(r.index)),
            el("td", { class: "mono" }, r.source),
            el("td", {}, el("span", { class: "clip", title: (r.name ? r.name + "\n" : "") + r.method + " " + r.path }, el("span", { class: "mono" }, r.method + " "), r.path)),
            el("td", {}, r.application ? appName(r.application) : "–"),
            el("td", { class: "num" }, r.alert ? el("span", { class: "badge alert" }, String(r.score)) : String(r.score)),
            el("td", {}, chips(r.rules.filter((id) => !scoring(id)), (id) => "/rules/" + id, 4)),
            el("td", { class: r.expectation && !r.expectation.met ? "error" : "" }, expText(r.expectation) || "–"))))))
          : el("p", { class: "empty" }, "No request is shown with this choice."),
          rows.length > limit ? el("p", {}, el("span", { class: "muted" }, `${nf.format(limit)} of ${nf.format(rows.length)} shown${j.rows.length < j.requests ? `; the result keeps the first ${nf.format(j.rows.length)} requests one by one, the summary counts all ${nf.format(j.requests)}` : ""}. `),
            el("button", { type: "button", class: "small", onclick: () => { limit += 50; drawRows(); } }, "Show 50 more")) : null);
        fitChips(table);
      };
      filter.addEventListener("change", () => { limit = 50; drawRows(); });
      // Trying the pending changes on these requests (W8).
      const tryNotice = el("div", { "aria-live": "polite" });
      const objectSel = el("select", { name: "object" }, option("global", "Every application"));
      api("/api/applications?range=all").then((a) => {
        append(objectSel, a.applications.filter((x) => x.running).map((x) => option("app:" + x.name, x.name)));
        if (params.get("try")) objectSel.value = params.get("try");
      }).catch(() => {});
      const tryIt = async () => {
        refill(tryNotice, el("p", { class: "muted" }, "Running the requests twice: with the configuration as it is, and with the pending changes…"));
        try {
          const t = await send("/api/analyse/try", { object: objectSel.value });
          refill(tryNotice, el("div", { class: "preview stack" },
            el("p", {}, `Of the ${nf.format(t.requests)} requests ${t.reach === "every application" ? "" : "of " + t.reach + " "}in these files, `,
              el("strong", {}, nf.format(t.alerts_before)), " are alerts now and ", el("strong", {}, nf.format(t.alerts_after)), " would be with the pending changes for ", t.reach, ": ",
              `${nf.format(t.added)} more, ${nf.format(t.removed)} fewer.`),
            t.examples.length ? el("div", { class: "table-wrap" }, el("table", { class: "wide" },
              el("thead", {}, el("tr", {}, ["File", "Request", "Score now", "Score after", "", "Rules"].map((h) => el("th", {}, h)))),
              el("tbody", {}, t.examples.map((x) => el("tr", {}, el("td", { class: "mono" }, x.source), el("td", { class: "mono wrap" }, x.path), el("td", {}, String(x.before)), el("td", {}, String(x.after)),
                el("td", {}, x.alert ? "becomes an alert" : "no longer an alert"), el("td", {}, chips(x.rules, (id) => "/rules/" + id, 4))))))) : null));
        } catch (err) {
          if (err.message !== "login required") refill(tryNotice, banner("error", "Not tried.", err.message));
        }
      };
      refill(resultBox,
        j.error ? banner("error", "The analysis did not finish.", j.error) : null,
        j.stopped ? banner("warning", "Stopped.", `${nf.format(j.requests)} of ${nf.format(j.total)} requests were analysed before the stop.`) : null,
        card(`${j.files.length} ${j.files.length === 1 ? "file" : "files"}, ${nf.format(j.requests)} requests, with ${j.config}`,
          kv([["Started", `${fmtTime(j.started)} by ${j.user}`], ["Level", j.level ? String(j.level) : "as configured"], ["Application", j.application || "by Host and path"],
            ["Alerts", nf.format(j.alerts)], ["Expectations not met", nf.format(j.unmet)],
            ["Records", j.record_run ? [`${nf.format(j.written)} written as run `, el("code", {}, j.record_run.slice(0, 8)), j.write === "replay" ? ", a replay on the requests' own times" : ", at the time of the analysis"] : "none written"]]),
          j.summary.length ? el("div", { class: "table-wrap" }, el("table", { class: "wide summary" },
            el("thead", {}, el("tr", {}, head.map((h, i) => el("th", { class: i >= 2 ? "num" : "" }, h)))),
            el("tbody", {}, j.summary.map((g) => line(g.source, g.rule_status, g)), j.summary.length > 1 ? line("total", "", total, true) : null))) : null,
          el("p", { class: "muted" }, "Flagged: the score reached the threshold. Failed: a CRS test's expectation was not met although the whole request was inspected; not inspected: the body could not be read." +
            (prof ? " Profile: requests with a profile finding; unknown path: of these, paths no endpoint takes; p. alerts: alerts because of a profile in alert mode; no app: requests of no application." : ""))),
        card("Each request", el("div", { class: "inline-form" }, formRow("Show", filter)), table),
        card("Try pending changes on these requests",
          el("p", { class: "muted" }, "The preview of a change works it out from the records; a change that adds detection (a higher level, a rule back on, new CRS settings) needs requests. Here these requests run with the configuration as it is and as the pending changes would make it."),
          el("div", { class: "inline-form" }, formRow("Pending changes for", objectSel), el("button", { type: "button", class: "small", onclick: tryIt }, "Try them")), tryNotice));
      drawRows();
    };

    replace(el("div", { class: "stack" }, notice,
      card("What to analyse",
        el("div", { class: "form-grid analyse-form" },
          formRow("From", source), fileRow, folderRow,
          formRow("Configuration", configSel), formRow("Paranoia level", levelSel), formRow("Application", appSel, "By Host and path, as the IDS decides, or every request as one application's."),
          writeSel ? formRow("Write into the records", writeSel, "A run of records appears on every page, for everyone; ids-live must not be running, as one program writes the records folder at a time.") : null),
        el("div", { class: "form-actions" }, start)),
      status, resultBox), false);
    load();
  }

  // ---- Monitor › Clients and Endpoints (W23) ----

  // listPage runs a list page with the period and the application filter
  // (W1); draw turns the answer into the view.
  function listPage(path, draw) {
    const form = document.getElementById("filters");
    let app = new URLSearchParams(location.search).get("app") || "";
    const address = () => location.pathname + "?" + query({ range: period.value, app });
    const showApps = appFilter(form, app, (v) => { app = v; history.replaceState(null, "", address()); view.classList.add("loading"); run(); });
    const run = every(async () => {
      const url = path + "?" + query({ range: period.value, app });
      const d = await api(url);
      showApps(d.applications || []);
      if (same(url, d)) return;
      draw(d, { range: period.value, app });
    });
    period.onChange(() => { history.replaceState(null, "", address()); view.classList.add("loading"); run(); });
  }

  function clientsPage() {
    listPage("/api/clients", (d, f) => {
      const alerts = (ip, extra) => "/alerts?" + query({ range: f.range, app: f.app, ip, ...extra });
      replace(el("div", { class: "stack" },
        el("p", { class: "lead muted" }, "Every address that sent a recorded request in this period, the most alerts first. A client's page has everything it sent; it is where blocking an address will start (K4)."),
        card(null, d.rows.length ? [el("div", { class: "table-wrap" }, el("table", { class: "wide" },
          el("thead", {}, el("tr", {}, [["Client", ""], ["Alerts", "num"], ["Records", "num"], ["First", ""], ["Last", ""], ["Applications", ""], ["Attack groups", ""], ["Marked", ""]].map(([h, c]) => el("th", { class: c }, h)))),
          el("tbody", {}, d.rows.map((c) => el("tr", {},
            el("td", { class: "mono" }, el("a", { href: "/clients/" + encodeURIComponent(c.ip) + "?" + query({ range: f.range }) }, c.ip)),
            el("td", { class: "num" }, c.alerts ? el("a", { href: alerts(c.ip, {}) }, nf.format(c.alerts)) : "0"),
            el("td", { class: "num" }, el("a", { href: alerts(c.ip, { kind: "all" }) }, nf.format(c.records))),
            el("td", { class: "nowrap" }, fmtTime(c.first)),
            el("td", { class: "nowrap" }, ago(c.last)),
            el("td", {}, c.applications.map(appName).join(", ")),
            el("td", {}, chips(c.groups, null, 2)),
            el("td", { class: "nowrap" }, [c.real_attacks ? `${nf.format(c.real_attacks)} real attack` : "", c.false_positives ? `${nf.format(c.false_positives)} false positive` : ""].filter(Boolean).join(", ") || "–")))))),
          d.total > d.rows.length ? el("p", { class: "muted" }, `The first ${d.rows.length} of ${nf.format(d.total)} addresses.`) : null]
          : el("p", { class: "empty" }, "No recorded request has a client address in this period."))));
    });
  }

  function endpointsPage() {
    listPage("/api/endpoints", (d, f) => {
      replace(el("div", { class: "stack" },
        el("p", { class: "lead muted" }, "The paths of recorded requests, the most alerts first, per application: where a site is attacked, or where its false alarms come from."),
        card(null, d.rows.length ? [el("div", { class: "table-wrap" }, el("table", { class: "wide" },
          el("thead", {}, el("tr", {}, [["Request", ""], ["Application", ""], ["Alerts", "num"], ["Records", "num"], ["Clients", "num"], ["Attack groups", ""], ["False positives", "num"], ["Last", ""]].map(([h, c]) => el("th", { class: c }, h)))),
          el("tbody", {}, d.rows.map((e) => el("tr", {},
            el("td", {}, el("span", { class: "clip", title: e.method + " " + e.path }, el("span", { class: "mono" }, e.method + " "), e.path)),
            el("td", {}, e.application === "none" ? appName("none") : el("a", { href: appLink(e.application) }, e.application)),
            el("td", { class: "num" }, nf.format(e.alerts)),
            el("td", { class: "num" }, nf.format(e.records)),
            el("td", { class: "num" }, nf.format(e.clients)),
            el("td", {}, chips(e.groups, null, 2)),
            el("td", { class: "num" }, nf.format(e.false_positives)),
            el("td", { class: "nowrap" }, ago(e.last))))))),
          d.total > d.rows.length ? el("p", { class: "muted" }, `The first ${d.rows.length} of ${nf.format(d.total)}.`) : null]
          : el("p", { class: "empty" }, "Nothing recorded in this period."))));
    });
  }

  function clientPage() {
    const ip = body.dataset.id;
    const run = every(async () => {
      const range = period.value;
      const url = "/api/clients/" + encodeURIComponent(ip) + "?" + query({ range });
      const c = await api(url);
      if (same(url, c)) return;
      const alerts = (extra) => "/alerts?" + query({ range, ip, kind: "all", ...extra });
      const pick = (from, to) => location.assign("/alerts?" + query({ kind: "all", ip, from: toDate(from).toISOString(), to: to.toISOString() }));
      replace(el("div", { class: "stack" },
        el("div", { class: "tiles" },
          tile("Alerts", c.alerts, c.last ? "last " + ago(c.last) : "", true),
          tile("Records", c.records, c.first ? "since " + fmtTime(c.first) : ""),
          tile("Marked real attack", c.verdicts.real_attack || 0, ""),
          tile("Marked false positive", c.verdicts.false_positive || 0, "")),
        card("Records over time",
          el("div", { class: "legend" }, el("span", { class: "key" }, el("span", { class: "swatch alerts" }), "Alerts"), el("span", { class: "key" }, el("span", { class: "swatch others" }), "Records below the threshold")),
          c.records ? columns(c, pick, false) : el("p", { class: "empty" }, "Nothing from this address in this period."),
          c.records ? el("p", {}, el("a", { href: alerts({}) }, `All ${nf.format(c.records)} records of ${ip} →`)) : null),
        c.records ? el("div", { class: "grid-2x2" },
          card("Paths", toplist(c.top_paths, (i) => el("span", { class: "mono" }, i.key))),
          card("Rules", toplist(c.top_rules, (i) => [el("strong", {}, i.key), " ", i.label], (i) => "/rules/" + i.key)),
          card("Attack groups", toplist(c.top_groups, (i) => i.key, (i) => alerts({ group: i.key }))),
          card("Applications", toplist(c.applications, (i) => appName(i.key), (i) => alerts({ app: i.key })))) : null,
        c.user_agents.length ? card("User-Agents", toplist(c.user_agents, (i) => el("span", { class: "mono" }, i.key))) : null));
    });
    period.onChange(() => { history.replaceState(null, "", location.pathname + "?" + query({ range: period.value })); view.classList.add("loading"); run(); });
  }

  // ---- System › Records (W19) ----

  function recordsPage() {
    const notice = el("div", { "aria-live": "polite" });
    every(async () => {
      const p = await api("/api/records-page");
      if (same("/api/records-page", p)) return;
      const total = p.files.reduce((n, f) => n + f.size, 0);
      const runSel = el("select", { name: "run" }, p.runs.map((r) => el("option", { value: r.run }, `${r.run.slice(0, 8)} · ${r.kind} · started ${fmtTime(r.started)} · ${nf.format(r.records)} records`)));
      const before = el("input", { type: "date", name: "before" });
      const reason = el("input", { name: "reason", placeholder: "Why? The change log keeps it", maxlength: 1000, autocomplete: "off" });
      const password = el("input", { type: "password", name: "password", placeholder: "Your password", autocomplete: "current-password" });
      const del = async (what) => {
        const label = what.run ? `the run ${what.run.slice(0, 8)}` : `every record older than ${what.before}`;
        if (!window.confirm(`Delete ${label}? Deleted records can't be brought back.`)) return;
        try {
          const a = await send("/api/records/delete", Object.assign({ reason: reason.value.trim(), password: password.value }, what.run ? { run: what.run } : { before: new Date(what.before + "T00:00:00").toISOString() }));
          password.value = "";
          refill(notice, banner("success", `${nf.format(a.lines)} lines deleted.`, "The change log keeps the deletion."));
        } catch (err) {
          if (err.message !== "login required") refill(notice, banner("error", "Nothing was deleted.", err.message));
        }
      };
      const st = p.settings;
      replace(el("div", { class: "stack" }, notice,
        card("Kept now", kv([
          ["Folder", el("code", {}, p.dir)],
          ["Files", `${p.files.length}, ${bytes(total)} together`],
          ["Runs", nf.format(p.runs.length)],
          ["How long records are kept", st ? `files of ${st.max_file_mb} MB, the newest ${st.keep_files} kept` + (st.max_age_days ? `; full files closed more than ${st.max_age_days} days ago are deleted` : "; no age limit") : "the IDS's configuration is not known to the dashboard"],
          ["How long marks are kept", p.marks_max_age_days ? `the marks of alerts older than ${p.marks_max_age_days} days are dropped once a day` : `forever: ${nf.format(p.marks)} marked records, each keeping its alert's client address (C6)`]]),
          el("p", { class: "muted" }, "Records are kept by size and age under Settings for every application, where ids-live applies them; the marks' age is a setting of the dashboard."),
          el("div", { class: "table-wrap" }, el("table", {},
            el("thead", {}, el("tr", {}, el("th", {}, "File"), el("th", { class: "num" }, "Size"), el("th", {}, "Last written"))),
            el("tbody", {}, p.files.map((f) => el("tr", {}, el("td", { class: "mono" }, f.name), el("td", { class: "num" }, bytes(f.size)), el("td", {}, fmtTime(f.modified)))))))),
        card("Runs", el("div", { class: "table-wrap" }, el("table", { class: "wide" },
          el("thead", {}, el("tr", {}, [["Run", ""], ["Kind", ""], ["Started", ""], ["Records", "num"], ["Alerts", "num"], ["Oldest record", ""], ["Newest record", ""]].map(([h, c]) => el("th", { class: c }, h)))),
          el("tbody", {}, p.runs.map((r) => el("tr", {},
            el("td", { class: "mono" }, r.run.slice(0, 8)),
            el("td", {}, r.kind),
            el("td", { class: "nowrap" }, fmtTime(r.started)),
            el("td", { class: "num" }, nf.format(r.records)),
            el("td", { class: "num" }, nf.format(r.alerts)),
            el("td", { class: "nowrap" }, r.oldest ? fmtTime(r.oldest) : "–"),
            el("td", { class: "nowrap" }, r.newest ? fmtTime(r.newest) : "–"))))))),
        card("Export", el("p", { class: "muted" }, "Every record kept, or those the alerts list's filters choose, with the Export links there."),
          el("p", {}, el("a", { class: "button small", href: "/api/export?" + query({ format: "csv", kind: "all", range: "all" }) }, "All records as CSV"), " ",
            el("a", { class: "button small", href: "/api/export?" + query({ format: "jsonl", kind: "all", range: "all" }) }, "All records as JSON Lines"))),
        adminRole ? card("Delete records",
          p.busy ? banner("warning", "ids-live is running.", "It writes the records folder, so nothing can be deleted while it runs: stop it first with scripts/ids-live-ctl stop.") : null,
          el("p", { class: "muted" }, "Deleting can't be undone. Marks of deleted records stay, with their alert's summary, until their age runs out."),
          el("div", { class: "form-grid" }, formRow("Reason", reason), formRow("Your password", password)),
          p.runs.length ? el("div", { class: "inline-form" }, formRow("A run", runSel), el("button", { type: "button", class: "small danger", onclick: () => del({ run: runSel.value }) }, "Delete this run")) : null,
          el("div", { class: "inline-form" }, formRow("Everything older than", before), el("button", { type: "button", class: "small danger", onclick: () => { if (before.value) del({ before: before.value }); } }, "Delete older records"))) : null));
    });
  }

  // ---- Administration › Dashboard settings (W20) ----

  async function dashSettingsPage() {
    let p;
    try { p = await api("/api/dashboard-settings"); } catch (err) { if (err.message !== "login required") failed(err); return; }
    const notice = el("div", { "aria-live": "polite" });
    const idle = el("input", { type: "number", name: "idle", min: 1, max: 1440, value: p.session_idle_minutes });
    const marks = el("input", { type: "number", name: "marks", min: 0, max: 3650, value: p.marks_max_age_days || "", placeholder: "forever" });
    const configs = el("textarea", { name: "configs", rows: 4, spellcheck: "false" }, p.test_configs.join("\n"));
    const folder = el("input", { name: "folder", value: p.test_requests_dir, spellcheck: "false", placeholder: "none" });
    const names = el("textarea", { name: "names", rows: 3, spellcheck: "false", placeholder: "none" }, p.cert_names.join("\n"));
    const reason = el("input", { name: "reason", placeholder: "Why? The change log keeps it", maxlength: 1000, autocomplete: "off" });
    const password = el("input", { type: "password", name: "password", placeholder: "Your password", autocomplete: "current-password" });
    const save = el("button", { type: "button", class: "primary", onclick: async () => {
      try {
        const a = await send("/api/dashboard-settings", { session_idle_minutes: Number(idle.value), marks_max_age_days: Number(marks.value) || 0,
          test_configs: lines(configs.value), test_requests_dir: folder.value.trim(), cert_names: lines(names.value), reason: reason.value.trim(), password: password.value });
        password.value = "";
        refill(notice, banner("success", "Saved.", `Written to ${a.saved} and taken at once.` + (a.fingerprint ? ` The dashboard made a new certificate with the new names; its fingerprint is ${a.fingerprint}. Browsers ask to trust it again.` : "") +
          (a.certificate_error ? " The certificate could not be made: " + a.certificate_error : "")));
      } catch (err) {
        if (err.message !== "login required") refill(notice, banner("error", "Not saved.", err.message));
      }
    } }, "Save the dashboard settings");
    replace(el("div", { class: "stack" }, notice,
      card("Settings",
        el("div", { class: "form-grid analyse-form" },
          formRow("Idle time, minutes", idle, "A login ends after this long without use."),
          formRow("Marks kept, days", marks, "The marks of alerts older than this are dropped once a day; each keeps its alert's client address (C6). Empty keeps them."),
          formRow("Test tab configurations", configs, "Product configurations, one per line; relative paths start at the folder of the configuration file."),
          formRow("Example folder", folder, "Request files that the Test tab and Analyse files offer."),
          formRow("Extra certificate names", names, p.own_cert ? "Names and addresses the dashboard's own certificate should carry too, one per line, such as an address it is reached at through a VPN. A new certificate is made at once." : "The dashboard serves certificate files given in its configuration, so it makes no certificate of its own.")),
        el("div", { class: "form-grid" }, formRow("Reason", reason), formRow("Your password", password)),
        el("div", { class: "form-actions" }, save)),
      card("In the configuration file, changed by hand", kv([
        ["File", el("code", {}, p.file)],
        ["Address", el("code", {}, p.listen)],
        ["Certificate", p.own_cert ? ["its own, ", el("code", { class: "wrap" }, p.fingerprint)] : "certificate files of the configuration"],
        ["Names it carries", p.cert_names_on.join(", ")],
        ["Records folder", el("code", {}, p.records_dir)],
        ["State folder", el("code", {}, p.state_dir)],
        ["The IDS's configuration", p.ids_config ? el("code", {}, p.ids_config) : "not named (ids_config): changes to the IDS are off"]]),
        el("p", { class: "muted" }, "These stay on the command line on purpose (W21): with a wrong address or certificate, nobody could reach this page to put it right. After changing them, start the dashboard again."))), false);
  }

  // settingsPage is System › Settings: the settings for every application
  // (W4), on one page, each control naming its reach (W5).
  function settingsPage() {
    changesPanel("global", document.getElementById("changes"));
    const notice = el("div", { "aria-live": "polite" });
    every(async () => {
      const p = await api("/api/settings");
      if (same("/api/settings", p)) return;
      if (!p.configured || p.error) {
        replace(card(null, banner("warning", "The settings can't be shown.", p.error)));
        return;
      }
      const can = adminRole;
      const add = (label, make) => can ? el("button", { type: "button", class: "small", onclick: () => { const ch = make(); if (ch) addChange("global", ch, notice); } }, label) : null;
      const num = (name, value, help, min, max) => el("input", { name, type: "number", value: value || "", min, max, placeholder: help, disabled: !can, inputmode: "numeric" });
      // Rule files
      const boxes = p.rule_files.map((f) => el("input", { type: "checkbox", checked: f.on, disabled: !can || (f.needed && f.on), "aria-label": f.name }));
      const filesTable = el("div", { class: "table-wrap" }, el("table", { class: "wide" },
        el("thead", {}, el("tr", {}, el("th", {}, "Loaded"), el("th", {}, "File"), el("th", { class: "num" }, "Rules"), el("th", {}, ""))),
        el("tbody", {}, p.rule_files.map((f, i) => el("tr", {},
          el("td", {}, boxes[i]),
          el("td", { class: "mono" }, f.name),
          el("td", { class: "num" }, f.on ? nf.format(f.rules) : "–"),
          el("td", { class: "muted" }, f.needed ? "needed: without it CRS does not work" : ""))))));
      // Levels
      const level = el("select", { name: "default-level", disabled: !can }, [1, 2, 3, 4].map((n) => el("option", { value: String(n) }, `Level ${n}`)));
      level.value = String(p.default_level);
      const upTo = (n) => Object.entries(p.rules_at_level).filter(([l]) => Number(l) >= 1 && Number(l) <= n).reduce((sum, [, c]) => sum + c, 0);
      const own = Object.entries(p.own_levels);
      // Rules off for everyone
      const exId = el("input", { name: "exclude-rule", inputmode: "numeric", placeholder: "Rule number", size: 10, disabled: !can });
      const exReason = el("input", { name: "exclude-reason", placeholder: "Why? It is shown on the rule's page", maxlength: 1000, disabled: !can });
      // Analysis
      const limit = num("body-limit", p.body_limit ? Math.round(p.body_limit / 1024) : "", `${nf.format(Math.round(p.body_limit_default / 1024))} kB, the default`, 1, Math.floor(p.body_limit_max / 1024));
      const require = el("input", { type: "checkbox", name: "require-profile", checked: p.require_profile, disabled: !can });
      // Records
      const r = p.records, rd = p.records_defaults;
      const maxFile = r ? num("max-file", r.max_file_mb, rd.max_file_mb + " MB, the default", 1, 1024) : null;
      const keep = r ? num("keep-files", r.keep_files, rd.keep_files + ", the default", 1, 1000) : null;
      const full = r ? el("input", { type: "checkbox", name: "full-requests", checked: r.full_requests, disabled: !can }) : null;
      const secrets = r ? el("input", { name: "secret-names", value: (r.secret_names || []).join(", "), placeholder: "none besides the built-in ones", disabled: !can }) : null;
      const maxAge = r ? num("max-age", r.max_age_days, "no age limit", 0, 3650) : null;
      // Live input
      const l = p.live, ld = p.live_defaults;
      const workers = num("workers", l.workers, ld.workers + ", the default", 1, 64);
      const qCopies = num("queue-copies", l.queue_copies, nf.format(ld.queue_copies) + ", the default", 1, 1000000);
      const qMB = num("queue-mb", l.queue_mb, ld.queue_mb + " MB, the default", 1, 4096);
      const frame = num("frame-mb", l.max_frame_mb, ld.max_frame_mb + " MB, the default", 1, 1024);
      const n = (input, fallback) => Number(input.value) || fallback;
      replace(el("div", { class: "stack" }, notice,
        el("p", { class: "lead muted" }, `These settings are for every application, from the configuration ${p.file}. An application's own paranoia level, mode and exceptions are on its page and win over these.`),
        card("Rule files, for every application", filesTable,
          el("div", { class: "form-actions" }, add("Load the checked rule files for every application", () => ({ kind: "files", files: p.rule_files.filter((f, i) => boxes[i].checked).map((f) => f.path) })))),
        card("Paranoia level",
          el("div", { class: "form-grid" },
            formRow("Default level", level, `For requests of no application, and for applications without their own. Level 1 runs ${nf.format(upTo(1))} rules, 2 runs ${nf.format(upTo(2))}, 3 runs ${nf.format(upTo(3))}, 4 runs ${nf.format(upTo(4))}.`),
            add("Set the default level (for requests of no application and applications without their own)", () => ({ kind: "default_level", level: Number(level.value) }))),
          own.length ? el("p", { class: "muted" }, "With a level of their own: " + own.map(([a, v]) => `${a} (${v})`).join(", ") + ".") : el("p", { class: "muted" }, "No application has a level of its own.")),
        card("Rules off for every application",
          p.excluded.length ? el("ul", { class: "plain" }, p.excluded.map((ex) => el("li", {}, el("a", { href: "/rules/" + ex.id }, String(ex.id)), ex.msg ? " " + ex.msg : "", el("div", { class: "sub" }, ex.reason),
            add(`Back on for every application`, () => ({ kind: "include", rule: ex.id }))))) : el("p", { class: "muted" }, "None."),
          can ? el("div", { class: "inline-form" }, formRow("Rule", exId), formRow("Reason", exReason),
            add("Switch off for every application", () => ({ kind: "exclude", rule: Number(exId.value), reason: exReason.value.trim() }))) : null),
        card("Analysis",
          el("div", { class: "form-grid" },
            formRow("Body limit, kB", limit, "How much of each request body is inspected; the rest makes the request partly inspected. Empty for the default."),
            add("Set the body limit for every application", () => ({ kind: "body_limit", number: limit.value ? Number(limit.value) * 1024 : 0 })),
            el("label", { class: "check-row" }, require, " A request of no application gets a no_profile finding (require_profile)"),
            add("Set it for every request of no application", () => ({ kind: "require_profile", on: require.checked })))),
        card("Records",
          r ? [kv([["Folder", el("code", {}, r.dir)]]), el("p", { class: "muted" }, "The folder stays in the configuration file: the IDS and the dashboard both depend on it."),
            el("div", { class: "form-grid" },
              formRow("File size, MB", maxFile, "When the current file reaches it, a new one starts."),
              formRow("Files kept", keep, "Older files are deleted, the current one included in the count."),
              formRow("Days kept", maxAge, "Full files closed longer ago are deleted, once a day; empty for no age limit."),
              el("label", { class: "check-row" }, full, " Full requests: an alert's record keeps every header and the body (more personal data)"),
              formRow("Extra secret names", secrets, "Parameter names whose values are masked, besides password, token, session and the others built in; separated by commas.")),
            el("div", { class: "form-actions" }, add("Set the records settings", () => ({ kind: "records", records: { max_file_mb: n(maxFile, rd.max_file_mb), keep_files: n(keep, rd.keep_files), full_requests: full.checked, secret_names: lines(secrets.value), max_age_days: Number(maxAge.value) || 0 } })))]
            : el("p", { class: "muted" }, "The configuration has no records section, so it names no records folder; ids-live is then given one with -records.")),
        card("Live input",
          kv([["Socket", l.socket ? el("code", {}, l.socket) : "not in the configuration; ids-live is given one with -socket"]]),
          el("p", { class: "muted" }, "The socket stays in the configuration file: Caddy's side names it too. These settings take effect when ids-live starts again (scripts/ids-live-ctl restart); the queue and the workers are made at its start."),
          el("div", { class: "form-grid" },
            formRow("Workers", workers, "Copies analysed at the same time; more take more of the server's CPU."),
            formRow("Queue, copies", qCopies, "Copies that may wait; past it they are dropped and counted as gaps."),
            formRow("Queue, MB", qMB, "The same limit in memory."),
            formRow("Largest copy, MB", frame, "The copier cuts a copy's body to fit.")),
          el("div", { class: "form-actions" }, add("Set the live input settings", () => ({ kind: "live", live: { workers: n(workers, ld.workers), queue_copies: n(qCopies, ld.queue_copies), queue_mb: n(qMB, ld.queue_mb), max_frame_mb: n(frame, ld.max_frame_mb) } }))))));
    });
  }

  function settingsHistoryPage() {
    changesPanel("global", document.getElementById("changes"));
    historyPage("global");
  }

  // proposalsPage lists every object's pending changes for the admins (W9).
  function proposalsPage() {
    every(async () => {
      const p = await api("/api/proposals");
      if (same("/api/proposals", p)) return;
      const objects = Object.entries(p.objects).sort(([a], [b]) => (a === "global" ? -1 : b === "global" ? 1 : a.localeCompare(b)));
      const link = (object) => (object === "global" ? "/settings" : appLink(object.replace(/^app:/, "")));
      replace(el("div", { class: "stack" },
        !p.configured ? banner("warning", "Changes are off.", "The dashboard does not know the IDS's configuration; name it as ids_config in the dashboard's configuration file.") : null,
        objects.length ? objects.map(([object, items]) => card(null,
          el("div", { class: "card-head" }, el("h2", {}, `For ${reachName(object)}`), el("a", { href: link(object) }, "Look at the preview and apply →")),
          el("ul", { class: "changes" }, items.map((ch) => el("li", {},
            el("div", { class: "what" }, ch.what, ch.proposal ? el("span", { class: "badge proposal" }, "Proposed") : null),
            el("div", { class: "sub" }, `${ch.proposal ? "Proposed" : "Added"} by ${ch.user}, ${ago(ch.time)}` + (ch.reason ? ". Reason: " + ch.reason : ""))))))) :
          card(null, el("p", { class: "empty" }, "Nothing is pending."))));
    });
  }

  // ---- Changes: pending, previewed, applied, undone (W7–W11) ----

  const me = body.dataset.user || "";
  const adminRole = body.dataset.role === "admin";

  // reloadChanges loads the page's pending changes again, after one of its
  // controls added one.
  let reloadChanges = () => Promise.resolve();

  // addChange adds a change to an object's pending changes, or proposes it
  // for an analyst (W9), and says so in box.
  async function addChange(object, change, box) {
    try {
      const ch = await send("/api/changes", { action: "add", object, change });
      if (box) refill(box, banner("success", ch.proposal ? "Proposed." : "Added to the pending changes.",
        `${ch.what}. ` + (ch.proposal ? "An admin applies it or turns it down." : "It is applied with the others, after their preview, at the top of the page.")));
      await reloadChanges();
      return ch;
    } catch (err) {
      if (err.message !== "login required" && box) refill(box, banner("error", "Not added.", err.message));
      return null;
    }
  }

  // reachName says whom an object's changes concern (W5).
  const reachName = (object) => (object === "global" ? "every application" : object.replace(/^app:/, ""));

  // changesPanel shows an object's pending changes in box, with their
  // preview and, for an admin, the form that applies them. It returns a
  // function that loads them again, for a page that adds one.
  function changesPanel(object, box) {
    if (!box) return () => {};
    const who = reachName(object);
    const notice = el("div", { "aria-live": "polite" });
    const state = { reason: "", password: "", key: "" };
    const act = async (data, done) => {
      try {
        const answer = await send("/api/changes", Object.assign({ object }, data));
        if (done) done(answer);
        await load(true);
        if (live.run) live.run();
      } catch (err) {
        if (err.message !== "login required") refill(notice, banner("error", "Not done.", err.message));
      }
    };
    const effects = (pv) => {
      if (pv.error) return banner("error", "These changes can't be applied as they are.", pv.error);
      const of = pv.records ? `the ${nf.format(pv.records)} records of ${who === "every application" ? "every application" : who} kept${pv.since ? " since " + fmtTime(pv.since) : ""}` : "";
      return el("div", { class: "preview stack" },
        el("h3", {}, "What they would do"),
        pv.records ? el("p", { class: "muted" }, `Worked out from ${of}: the records keep what each rule found and what it added to the score.`)
          : el("p", { class: "muted" }, "There are no records to try them on."),
        pv.real_attacks ? banner("warning", `${nf.format(pv.real_attacks)} ${pv.real_attacks === 1 ? "alert" : "alerts"} marked real attack would no longer be ${pv.real_attacks === 1 ? "an alert" : "alerts"}.`, "They are first in the list below; look at them before applying.") : null,
        pv.records ? el("ul", { class: "plain effects" },
          el("li", {}, el("strong", {}, nf.format(pv.alerts_removed)), ` of ${nf.format(pv.alerts)} alerts would no longer be alerts`,
            pv.alerts_removed ? el("span", { class: "muted" }, ` · ${nf.format(pv.false_positives)} marked false positive, ${nf.format(pv.not_reviewed)} not reviewed`) : null),
          pv.records_removed ? el("li", {}, el("strong", {}, nf.format(pv.records_removed)), " records would no longer be recorded: no finding would be left") : null,
          pv.alerts_added ? el("li", {}, el("strong", {}, nf.format(pv.alerts_added)), " records would become alerts") : null) : null,
        pv.by_rule.length ? el("div", {}, el("div", { class: "sub" }, "Alerts no longer alerts, by the rule that would stop finding them"),
          el("ul", { class: "plain" }, pv.by_rule.map((i) => el("li", {}, el("a", { href: "/rules/" + i.key }, i.key), " ", i.msg || "", el("span", { class: "muted" }, " · " + nf.format(i.count)))))) : null,
        pv.examples.length ? el("div", {}, el("div", { class: "sub" }, pv.alerts_removed > pv.examples.length ? `The first ${pv.examples.length} of them` : "They are"),
          listTable(pv.examples, { verdict: true, apps: object === "global" })) : null,
        pv.untested.length ? el("div", {}, el("div", { class: "sub" }, "What the records can't tell"),
          el("ul", { class: "plain" }, pv.untested.map((t) => el("li", { class: "muted" }, t))),
          analyst ? el("p", {}, el("a", { href: "/analyse?" + query({ try: object }) }, "Try these changes on request files in Analyse files →")) : null) : null);
    };
    const draw = (c, pv) => {
      if (!c.configured || !c.items.length) {
        refill(box, notice.childNodes.length ? notice : null);
        return;
      }
      const n = c.items.length;
      const reason = el("input", { name: "reason", value: state.reason, maxlength: 1000, autocomplete: "off", placeholder: "Why? The change log and the version keep it", "aria-label": "Reason",
        oninput: (e) => { state.reason = e.target.value; } });
      const password = c.password ? el("input", { type: "password", name: "password", value: state.password, autocomplete: "current-password", placeholder: "Your password", "aria-label": "Your password",
        oninput: (e) => { state.password = e.target.value; } }) : null;
      const apply = el("button", { type: "button", class: "primary", disabled: !!pv.error, onclick: () => {
        if (!state.reason.trim()) { refill(notice, banner("error", "Not applied.", "give a reason: the change log and the version keep it")); reason.focus(); return; }
        act({ action: "apply", reason: state.reason.trim(), password: state.password }, (a) => {
          state.reason = state.password = "";
          refill(notice, banner("success", a.unchanged ? "Applied; no file changed." : `Applied as version ${a.version.id}.`,
            a.unchanged ? "The files already were as these changes make them." : "ids-live takes it within a few seconds, without stopping; the History tab shows when it runs it."));
        });
      } }, `Apply ${n === 1 ? "this change" : "these " + n + " changes"} for ${who}`);
      refill(box, notice, el("section", { class: "card pending" },
        el("div", { class: "card-head" }, el("h2", {}, `Pending changes for ${who}`), el("span", { class: "muted" }, `${n} ${n === 1 ? "change" : "changes"}, applied together as one version`)),
        el("ul", { class: "changes" }, c.items.map((ch) => el("li", {},
          el("div", { class: "what" }, ch.what, ch.proposal ? el("span", { class: "badge proposal", title: "An analyst proposed it; an admin applies it or turns it down" }, "Proposed") : null),
          el("div", { class: "sub" }, `${ch.proposal ? "Proposed" : "Added"} by ${ch.user}, ${ago(ch.time)}` + (ch.reason ? ". Reason: " + ch.reason : "")),
          c.apply || (ch.proposal && ch.user === me) ? el("div", { class: "item-actions" },
            el("button", { type: "button", class: "small", onclick: () => act({ action: "drop", id: ch.id }) }, ch.proposal && ch.user === me ? "Take back" : "Drop"),
            c.apply && ch.proposal ? el("button", { type: "button", class: "small", onclick: () => {
              const why = window.prompt("Why is this proposal turned down? The change log keeps it, for the analyst to read.");
              if (why && why.trim()) act({ action: "turn_down", id: ch.id, reason: why.trim() });
            } }, "Turn down") : null) : null))),
        effects(pv),
        c.apply ? el("div", { class: "apply-bar" }, reason, password, apply)
          : el("p", { class: "muted" }, c.propose ? "An admin applies these changes, or turns them down." : "An admin applies these changes.")));
    };
    const load = async (force) => {
      const [c, pv] = await Promise.all([api("/api/changes?" + query({ object })), api("/api/changes/preview?" + query({ object }))]);
      const key = JSON.stringify([c, pv]);
      if (!force && key === state.key) return;
      state.key = key;
      draw(c, pv);
    };
    load(true).catch((err) => { if (err.message !== "login required") refill(box, banner("error", "The pending changes could not be loaded.", err.message)); });
    // A poll leaves the panel alone while the user types in it.
    setInterval(() => { if (!live.paused && !box.contains(document.activeElement)) load(false).catch(() => {}); }, poll);
    reloadChanges = () => load(true);
    return reloadChanges;
  }

  // historyPage lists an object's versions, newest first, each with Undo
  // for an admin (W11).
  function historyPage(object) {
    const notice = el("div", { "aria-live": "polite" });
    const admin = body.dataset.role === "admin";
    const run = every(async () => {
      const url = "/api/versions?" + query({ object });
      const d = await api(url);
      if (same(url, d)) return;
      const undo = async (v) => {
        if (v.later && !window.confirm(`${v.later} later ${v.later === 1 ? "change" : "changes"} touched the same files; undoing version ${v.id} takes ${v.later === 1 ? "it" : "them"} back too. Add the undo to the pending changes?`)) return;
        try {
          await send("/api/changes", { action: "undo", version: v.id });
          refill(notice, banner("success", `The undo of version ${v.id} is pending.`, "Its preview is above; apply it there."));
          window.scrollTo(0, 0);
          location.reload();
        } catch (err) {
          if (err.message !== "login required") refill(notice, banner("error", "Not undone.", err.message));
        }
      };
      const stateOf = (v) => v.live ? `ids-live runs it since ${fmtTime(v.live)}` : v.current ? "on disk; ids-live has not run it yet" : "changed by a later change";
      replace(el("div", { class: "stack" }, notice,
        d.versions.length ? card(`Changes applied to ${reachName(object)}`, el("div", { class: "table-wrap" }, el("table", { class: "wide history" },
          el("thead", {}, el("tr", {}, el("th", {}, "Version"), el("th", {}, "Applied"), el("th", {}, "By"), el("th", {}, "What"), el("th", {}, "Reason"), el("th", {}, "State"), admin ? el("th", {}, "") : null)),
          el("tbody", {}, d.versions.map((v) => el("tr", {},
            el("td", { class: "mono nowrap" }, v.id),
            el("td", { class: "nowrap" }, fmtTime(v.time)),
            el("td", {}, v.user),
            el("td", { class: "wrap" }, v.undoes ? el("div", {}, `Undoes version ${v.undoes}`) : v.changes.map((c) => el("div", {}, c.what))),
            el("td", { class: "wrap" }, v.reason),
            el("td", { class: "wrap" }, stateOf(v)),
            admin ? el("td", {}, el("button", { type: "button", class: "small", onclick: () => undo(v) }, "Undo")) : null))))))
          : card(null, el("p", { class: "empty" }, `No change has been applied to ${reachName(object)} from the dashboard yet.`))));
    });
    return run;
  }

  // ---- One rule (W6) ----

  // ruleBadge is a rule's status for one application.
  function ruleBadge(st) {
    switch (st.status) {
      case "excluded": return el("span", { class: "badge excluded" }, "Excluded for every application");
      case "off": return el("span", { class: "badge off" }, "Off");
      case "above": return el("span", { class: "badge above", title: "Its paranoia level is above the level the rules run at, so the CRS gate rule skips it." }, `Above level ${st.level}`);
      default: return el("span", { class: "badge active" }, "Runs");
    }
  }

  const phases = { 1: "1, the request headers", 2: "2, the request body", 3: "3, the response headers", 4: "4, the response body", 5: "5, logging" };

  function rulePage() {
    const id = body.dataset.id;
    changesPanel("global", document.getElementById("changes"));
    const notice = el("div", { "aria-live": "polite" });
    const run = every(async () => {
      const range = period.value;
      const url = "/api/rules/" + encodeURIComponent(id) + "?" + query({ range });
      const [p, set] = await Promise.all([api(url), adminRole ? api("/api/settings") : Promise.resolve(null)]);
      if (same(url, { p, set })) return;
      // Off for every application, or back on: an admin's change, pending
      // under Settings for every application.
      const excluded = set && set.excluded.find((ex) => String(ex.id) === String(id));
      const protectedRule = /^REQUEST-9(01|49)-/.test(p.rule.file);
      let everyApp = null;
      if (set && set.configured && !set.error && !protectedRule) {
        const reason = el("input", { name: "reason", placeholder: "Why? It is shown on this page", maxlength: 1000, autocomplete: "off" });
        everyApp = excluded
          ? el("div", { class: "inline-form" }, el("span", {}, `Off for every application: ${excluded.reason}`),
            el("button", { type: "button", class: "small", onclick: () => addChange("global", { kind: "include", rule: Number(id) }, notice) }, "Back on for every application"))
          : p.rule.active ? el("div", { class: "inline-form" }, formRow("Reason", reason),
            el("button", { type: "button", class: "small", onclick: () => addChange("global", { kind: "exclude", rule: Number(id), reason: reason.value.trim() }, notice) }, "Switch off for every application")) : null;
      }
      const r = p.rule;
      const alerts = (extra) => "/alerts?" + query({ range, kind: "all", rule: id, ...extra });
      const count = (n, href) => (n ? el("a", { href }, nf.format(n)) : "0");
      const pick = (from, to) => {
        const start = toDate(p.range.from);
        if (start && start > toDate(from)) from = start;
        location.assign("/alerts?" + query({ kind: "all", rule: id, from: toDate(from).toISOString(), to: to.toISOString() }));
      };
      replace(el("div", { class: "stack" },
        el("p", { class: "lead" }, r.msg || el("span", { class: "muted" }, "This rule has no description."), el("span", { class: "muted" }, " · " + p.group)),
        el("div", { class: "grid-2" },
          card("About this rule", kv([
            ["Attack group", p.group],
            ["File", el("code", {}, `${r.file}, line ${r.line}`)],
            ["Phase", phases[r.phase] || String(r.phase)],
            ["Paranoia level", r.paranoia_level ? `${r.paranoia_level}: it runs for applications at level ${r.paranoia_level} or higher` : "none: a setup or scoring rule, which runs at every level"],
            ["Rule set", p.crs],
            ["Status", r.active ? "loaded" : "excluded for every application: " + r.reason]])),
          card("What it found", kv([
            ["Records", count(p.fired, alerts({}))],
            ["Alerts among them", count(p.alerts, alerts({ kind: "alerts" }))],
            ["Marked false positive", count(p.false_positives, alerts({ review: "false_positive" }))],
            ["From the run", fmtTime(p.time)]]))),
        notice,
        card("Where it runs",
          el("p", { class: "muted" }, "Its status for each application, at that application's paranoia level and with its exceptions. An application's own exception is changed on that application's Rules tab."),
          everyApp,
          el("div", { class: "table-wrap" }, el("table", { class: "wide" },
            el("thead", {}, el("tr", {}, [["Application", ""], ["Level", ""], ["Status", ""], ["Reason", ""], ["Records", "num"], ["False positives", "num"]].map(([h, c]) => el("th", { class: c }, h)))),
            el("tbody", {}, p.statuses.map((st) => {
              const none = st.application === "none";
              return el("tr", {},
                el("td", {}, none ? "Requests of no application" : el("a", { href: appLink(st.application, "rules") + "?" + query({ q: id }) }, st.application),
                  !st.running ? el("div", { class: "sub" }, "not in the running configuration") : null),
                el("td", {}, String(st.level)),
                el("td", { class: "wrap" }, ruleBadge(st), st.skips ? el("div", { class: "sub" }, "Skips " + st.skips.join(", ")) : null),
                el("td", { class: "wrap" }, st.reason || "–", st.no_effect ? el("div", { class: "sub" }, "No effect now: " + st.no_effect) : null),
                el("td", { class: "num" }, count(st.fired, alerts({ app: st.application }))),
                el("td", { class: "num" }, count(st.false_positives, alerts({ app: st.application, review: "false_positive" }))));
            }))))),
        card("Records over time",
          el("div", { class: "legend" },
            el("span", { class: "key" }, el("span", { class: "swatch alerts" }), "Alerts"),
            el("span", { class: "key" }, el("span", { class: "swatch others" }), "Records below the threshold")),
          p.fired ? columns(p, pick, false) : el("p", { class: "empty" }, "This rule found nothing in this period.")),
        p.fired ? el("div", { class: "grid-2x2" },
          card("Where in the request", toplist(p.top_locations, (i) => i.key, (i) => alerts({ location: i.key }))),
          card("Paths", toplist(p.top_paths, (i) => el("span", { class: "mono" }, i.key))),
          card("Client IP addresses", toplist(p.top_ips, (i) => i.key, (i) => alerts({ ip: i.key })))) : null,
        card("The rule as written",
          p.text ? el("pre", { class: "block rule-text" }, p.text) : el("p", { class: "muted" }, "Its text can't be shown: " + p.text_error + "."),
          analyst && p.test_file ? el("p", {}, "CRS has tests for this rule. ", el("a", { href: "/test?" + query({ file: p.test_file }) }, "Try them in the Test tab →")) : null)));
    });
    period.onChange(() => {
      history.replaceState(null, "", location.pathname + "?" + query({ range: period.value }));
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
      const exportQuery = (format) => "/api/export?" + query({ ...current(), format });
      replace(el("div", { class: "stack" }, markNotice, card(null,
        analyst && l.rows.length ? bar : null,
        l.rows.length ? el("div", { class: "export-bar" }, el("span", { class: "muted" }, `Export these ${nf.format(l.total)}:`),
          el("a", { href: exportQuery("csv") }, "CSV"), el("a", { href: exportQuery("jsonl") }, "JSON Lines")) : null,
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
    // On an application's Rules tab the application is fixed (W3).
    const fixed = body.dataset.app || "";
    const appValue = () => fixed || (form.elements.app ? form.elements.app.value : "");
    let data = null;
    let own = true; // the user changed the filters: sections open as the filters say
    const status = (r, level) => (!r.active ? "excluded" : r.off ? "off" : (r.paranoia_level || 0) > level ? "above" : "runs");

    // An application's exception of the rule, below its status (F9).
    const exceptionNote = (r) => [
      r.skips ? el("div", { class: "sub" }, "Skips " + r.skips.join(", ") + ": " + r.exception_reason) : null,
      r.no_effect ? el("div", { class: "sub" }, r.no_effect) : null];

    // On an application's Rules tab, an analyst or admin changes a rule
    // for that application only (W6): off, skipping places, or back on.
    const notice = fixed ? el("div", { "aria-live": "polite" }) : null;
    const editRule = (r, tr) => {
      const next = tr.nextElementSibling;
      if (next && next.classList.contains("editor")) { next.remove(); return; }
      const box = el("div", { "aria-live": "polite" });
      const excepted = r.off || (r.skips && r.skips.length);
      const choice = el("select", { name: "what" },
        !r.off ? el("option", { value: "off" }, `Off for ${fixed}`) : null,
        el("option", { value: "skip" }, `Skip places for ${fixed}`),
        excepted ? el("option", { value: "on" }, `Back on for ${fixed}, without exception`) : null);
      const places = el("input", { name: "places", placeholder: "ARGS:search, REQUEST_COOKIES:session", autocomplete: "off", spellcheck: "false" });
      const reason = el("input", { name: "reason", placeholder: "Why? It is shown with the exception", maxlength: 1000, autocomplete: "off" });
      const placesRow = formRow("Places to skip", places), reasonRow = formRow("Reason", reason);
      const show = () => { placesRow.hidden = choice.value !== "skip"; reasonRow.hidden = choice.value === "on"; };
      choice.addEventListener("change", show);
      const row = el("tr", { class: "editor" }, el("td", { colspan: 8 },
        el("div", { class: "inline-form" }, formRow(`Rule ${r.id}`, choice), placesRow, reasonRow,
          el("button", { type: "button", class: "small primary", onclick: async () => {
            const change = { kind: { off: "rule_off", skip: "rule_skip", on: "rule_on" }[choice.value], rule: r.id };
            if (choice.value === "skip") change.targets = lines(places.value);
            if (choice.value !== "on") change.reason = reason.value.trim();
            if (await addChange("app:" + fixed, change, box)) { row.remove(); refill(notice, box.firstChild); window.scrollTo({ top: 0, behavior: "smooth" }); }
          } }, adminRole ? "Add to the pending changes" : "Propose"),
          el("button", { type: "button", class: "small", onclick: () => row.remove() }, "Cancel")), box));
      tr.after(row);
      show();
      choice.focus();
    };
    const changeButton = (r) => fixed && analyst && r.active ? el("button", { type: "button", class: "link", onclick: (e) => editRule(r, e.currentTarget.closest("tr")) }, "Change…") : null;

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
      if (fixed || !appField) return;
      const names = (d.applications || []).map((a) => `${a.name}\t${a.paranoia_level}`).concat(d.applications && d.applications.length ? [`none\t${d.engine.paranoia_level}`] : []);
      if (names.join("\n") === appChoices) return;
      appChoices = names.join("\n");
      const chosen = form.elements.app.value;
      refill(form.elements.app, el("option", { value: "" }, `All applications (default level ${d.engine.paranoia_level})`),
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
            el("td", {}, el("a", { href: "/rules/" + r.id + "?" + query({ range: f.range }), title: "This rule's page: where it runs, and what it found" }, String(r.id))),
            el("td", { class: "wrap" }, r.msg || el("span", { class: "muted" }, "–")),
            el("td", {}, String(r.line)),
            el("td", {}, String(r.phase)),
            el("td", {}, r.paranoia_level ? String(r.paranoia_level) : "–"),
            el("td", { class: "wrap" }, statusCell(r, level, appLabel), changeButton(r)),
            el("td", { class: "num" }, r.fired ? el("a", { href: "/alerts?" + query({ kind: "all", rule: r.id, range: f.range, app: data.app }) }, nf.format(r.fired)) : "0"),
            el("td", { class: "num" }, r.false_positives ? el("a", { href: "/alerts?" + query({ kind: "all", rule: r.id, range: f.range, app: data.app, review: "false_positive" }) }, nf.format(r.false_positives)) : "–")))))));

      replace(el("div", { class: "stack" },
        notice,
        el("p", { class: "muted" }, `${nf.format(data.rules.length)} rules of ${data.engine.crs} at paranoia level ${level}` +
          (data.app ? ` for ${data.app === "none" ? "requests of no application" : "the application " + data.app}` : "") + ": " +
          `${nf.format(counts.runs)} run, ${are(counts.above)} above the level and skipped, ${are(counts.excluded)} excluded` +
          (counts.off ? `, ${are(counts.off)} off for the application` : "") + ". " +
          `Showing ${nf.format(shownCount)}; fired counts ${data.app ? "this application's records only" : "every record"}. From the run that started ${fmtTime(data.time)}.`),
        chosen && !fixed ? el("p", {}, el("a", { href: appLink(chosen.name, "rules") }, `${chosen.name}'s own page →`)) : null,
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
    const fields = (fixed ? [] : ["app"]).concat(["status", "level", "q", "sort"]);
    if (!fixed && params.get("app")) form.elements.app.append(el("option", { value: params.get("app") }, appName(params.get("app"))));
    for (const f of fields) if (params.has(f)) form.elements[f].value = params.get(f);
    const sync = () => {
      const p = { range: period.value };
      for (const f of fields) p[f] = form.elements[f].value.trim();
      if (p.sort === "id") p.sort = "";
      history.replaceState(null, "", (fixed ? location.pathname : "/rules") + "?" + query(p));
    };
    const run = every(async () => {
      const url = "/api/rules?" + query({ range: period.value, app: appValue() });
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
      const [p, ctl] = await Promise.all([api("/api/engine"), api("/api/control")]);
      if (same("/api/engine", { p, ctl })) return;
      const l = p.latest;
      // A replay started when it was replayed; its records carry the
      // requests' own times.
      const startedAt = (r) => (r.input && r.input.kind === "replay" && r.input.replayed ? r.input.replayed : r.time);
      const runs = p.runs.map((r, i) => {
        const older = p.runs[i + 1];
        const changed = older && older.engine.config !== r.engine.config;
        return el("tr", {},
          el("td", { class: "nowrap" }, fmtTime(startedAt(r))),
          el("td", { class: "nowrap" }, el("code", { title: r.run }, r.run.slice(0, 8)), copyButton(r.run, "the run ID")),
          el("td", { title: r.input && r.input.kind === "replay" ? "Request files replayed on " + fmtTime(r.input.replayed) + "; the records carry the requests' own times" : null },
            r.input && r.input.kind === "live" ? "live" : r.input && r.input.kind === "replay" ? "replay" : "files"),
          el("td", { class: "nowrap", title: r.engine.crs }, r.engine.crs.replace(/^OWASP_CRS\//, "CRS ")),
          el("td", {}, String(r.engine.paranoia_level)),
          el("td", { class: "num" }, nf.format(r.analysed)),
          el("td", { class: "num" }, nf.format(r.records)),
          el("td", { class: "num" }, nf.format(r.alerts)),
          el("td", { class: "nowrap" }, el("code", { title: r.engine.config }, short(r.engine.config, 15)), copyButton(r.engine.config, "the fingerprint"),
            changed ? el("div", {}, el("span", { class: "chip changed", title: "The configuration is not the one of the run before" }, "changed")) : null));
      });
      const level = l ? l.engine.paranoia_level : 0;
      replace(el("div", { class: "stack" },
        liveInputCard(p, ctl),
        l ? card("Running configuration", kv([
          ["Started", fmtTime(startedAt(l))],
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

  // liveInputCard is the state of ids-live (W17): whether it runs, what it
  // runs, whether a copier is connected, and what it could not analyse.
  function liveInputCard(p, ctl) {
    const l = p.latest, live = p.live;
    const start = el("p", { class: "muted" }, "On the server, ids-live is started and stopped with ", el("code", {}, "scripts/ids-live-ctl start"), " and ", el("code", {}, "stop"), " (or a systemd unit). Changes made here need no restart: ids-live reads its configuration again every few seconds.");
    const disk = ctl && ctl.configured ? kv([
      ["Configuration", el("code", {}, ctl.file)],
      ["On disk", ctl.error ? el("span", { class: "error" }, "does not load: " + ctl.error) : el("code", { title: ctl.on_disk }, short(ctl.on_disk, 23))],
      ["ids-live runs it", ctl.taken ? `yes, since ${fmtTime(ctl.since)}` : ctl.running ? "not yet: it runs an older configuration and takes this one within a few seconds while it runs" : "no live run has been seen"]]) : null;
    if (!live) {
      return card("Live input", el("p", { class: "muted" }, l
        ? `The newest run read ${l.input && l.input.kind === "replay" ? "replayed request files" : "request files"} (ids-offline), so the dashboard can't tell whether ids-live runs. When it runs, its state shows here.`
        : "No run has been read yet. When ids-live runs, its state shows here."), disk, start);
    }
    const since = live.last_counts || live.start;
    return card("Live input",
      live.stale ? banner("error", "ids-live is not running.", `It has written nothing since ${fmtTime(since)} (${ago(since)}); it writes counts every minute while it runs. Start it again on the server: scripts/ids-live-ctl start.`)
        : live.copiers === 0 ? banner("warning", "Running, but no copier is connected.", "No proxy sent copies in the last minute. Check that Caddy runs with ids_copy.") : null,
      kv([
        ["State", live.stale ? "not running" : `running since ${fmtTime(live.start)}`],
        ["Last counts", live.last_counts ? `${fmtTime(live.last_counts)} (${ago(live.last_counts)})` : "none yet: the first come a minute after the start"],
        ["Copiers connected", live.copiers === undefined || live.copiers === null ? "not known yet" : nf.format(live.copiers)],
        ["Socket", live.socket ? el("code", {}, live.socket) : ""],
        ["Run", el("code", {}, l.run)],
        ["Not analysed in the last hour", p.not_analysed_last_hour ? p.not_analysed_by.map((m) => el("div", {}, `${nf.format(m.missed)}: ${gapReason(m)}`)) : "none"]]),
      disk, start);
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
    // A rule's page links here with its CRS test file (W6).
    const asked = new URLSearchParams(location.search).get("file");
    if (asked && [...fileSel.options].some((o) => o.value === asked)) {
      fileSel.value = asked;
      fileSel.dispatchEvent(new Event("change"));
    }
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
    const role = body.dataset.role || "";
    replace(el("div", { class: "stack" },
      notice,
      card("You", kv([["User", me], ["Role", `${roleNames[role] || role}: ${roleText[role] || ""}`]])),
      card("Change your password", form,
        el("p", { class: "muted" }, "At least 15 characters. Any characters count, and there are no rules about mixing kinds: a few unrelated words make a long password that is easy to remember."))), false);
  }

  async function logPage() {
    const params = new URLSearchParams(location.search);
    const kinds = [
      ["", "Everything"], ["change", "Changes"], ["login", "Logins"], ["mark", "Marks"],
      ["user_added", "User added"], ["user_removed", "User removed"], ["role_changed", "Role changed"],
      ["password_reset", "Password reset"], ["password_changed", "Own password changed"],
      ["changes_applied", "IDS changes applied"], ["change_added", "IDS change added"], ["change_proposed", "IDS change proposed"],
      ["change_dropped", "IDS change dropped"], ["change_turned_down", "IDS proposal turned down"],
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
        case "changes_applied": case "change_added": case "change_proposed": case "change_dropped": case "change_turned_down": {
          const verbs = { changes_applied: "applied changes for", change_added: "added a pending change for", change_proposed: "proposed a change for", change_dropped: "dropped a pending change for", change_turned_down: `turned down a proposal of ${c.target} for` };
          return [`${verbs[c.action]} ${reachName(c.object)}`, c.version ? el("span", { class: "muted" }, ", version " + c.version) : null,
            (c.what || []).map((w) => el("div", { class: "sub" }, w)),
            c.reason ? el("div", { class: "sub" }, "Reason: " + c.reason) : null];
        }
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

  // ---- The UI shell (Y8 of docs/development-plan-dashboard-carbon.md) ----

  // The side navigation is open on wide screens, 1312 pixels and more as
  // in app.css; narrower, the menu button opens it over the page, and
  // Escape or a click beside it closes it. Open, Carbon's side navigation
  // takes the header's name and actions out of the tab order, for the
  // overlay of a narrow screen; beside the page they stay in it.
  const side = document.getElementById("side");
  const menuButton = document.getElementById("menu");
  if (side && menuButton) {
    const wide = window.matchMedia("(min-width: 1312px)");
    const setOpen = async (open) => {
      side.expanded = open;
      menuButton.active = open;
      await side.updateComplete;
      if (wide.matches) for (const n of document.querySelectorAll("cds-header-name, cds-header-global-action")) n.removeAttribute("tabindex");
    };
    customElements.whenDefined("cds-side-nav").then(async () => {
      await setOpen(wide.matches);
      side.classList.add("ready");
    });
    wide.addEventListener("change", () => setOpen(wide.matches));
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !wide.matches && side.expanded) {
        setOpen(false);
        menuButton.focus();
      }
    });
    document.addEventListener("click", (e) => {
      if (!wide.matches && side.expanded && !e.composedPath().some((n) => n === side || n === menuButton)) setOpen(false);
    });
  }

  // The colour theme (U7): the system's, or one chosen in the header's
  // panel. theme.js applies a stored choice before the page is drawn.
  const theme = document.getElementById("theme");
  if (theme) {
    const showTheme = () => {
      const v = document.documentElement.dataset.theme || "";
      for (const b of theme.querySelectorAll("button[data-value]")) b.setAttribute("aria-pressed", String(b.dataset.value === v));
    };
    showTheme();
    theme.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-value]");
      if (!b) return;
      if (b.dataset.value) document.documentElement.dataset.theme = b.dataset.value;
      else delete document.documentElement.dataset.theme;
      store("localStorage", "ids.theme", b.dataset.value);
      showTheme();
    });
  }

  const pages = { overview: overviewPage, alerts: alertsPage, alert: alertPage, rules: rulesPage, rule: rulePage, applications: applicationsPage, application: applicationPage, settings: settingsPage, settingshistory: settingsHistoryPage, proposals: proposalsPage, analyse: analysePage, clients: clientsPage, client: clientPage, endpoints: endpointsPage, records: recordsPage, dashsettings: dashSettingsPage, engine: enginePage, test: testPage, users: usersPage, account: accountPage, log: logPage, login: loginPage };
  if (pages[page] && (view || page === "login")) pages[page]();
})();
