# Development plan: the dashboard on IBM Carbon's own components

Written: 21 November 2026, at the user's request: the dashboard "is a little raw", for example in the Latest alerts card the times look like links and so does "All 732 alerts →"; "we need to make the dashboard more professional". Of three ways (fix what is seen, a design audit first, or IBM's Carbon component library), the user chose the library. Every question has a code (Y1, Y2, …) and numbered options; the user decides them one by one, and each answer gets its date here.

## 1. What was checked first (21 November 2026)

1. The packages: `@carbon/web-components` 2.68.0 and `@carbon/react` 1.121.0, both Apache-2.0.
2. IBM publishes the web components as ready ES module files per component, which load their shared parts from the same folder: no build step is needed. The 31 components the dashboard would use come to 103 files, 3.2 MB.
3. No telemetry in the browser: `@ibm/telemetry-js` is named only in the files' licence comment; it collects at `npm install` time, which this project does not use. The files hold no network call (`fetch`, `sendBeacon`, `XMLHttpRequest`, `WebSocket`) and no address but npm links in comments.
4. The themes: Carbon's g10 (light) and g100 (dark) colours, as the dashboard has them now, are 26 KB taken out of `@carbon/styles` 1.120.0's 1.2 MB stylesheet.
5. The Content-Security-Policy: a test page of 12 components, under the dashboard's exact policy, in headless Chromium. The components style themselves with constructable stylesheets, which the policy allows; all 12 drew as they should. Three components write a `style="…"` attribute, which `style-src 'self'` blocks (`style-src-attr`): the select (a divider in its warning or error state), skeleton text (the width of each line), the expandable tile (its height while opening).
6. What other dashboards allow: GitHub sends `style-src 'unsafe-inline' github.githubassets.com`, Cloudflare's dashboard `style-src 'unsafe-inline'`.

## 2. Questions

Y1. Which form of Carbon.

1. Carbon Web Components: `<cds-…>` tags used from the dashboard's plain JavaScript; no build step.
2. Carbon for React: the pages rewritten in React, with Node.js and a bundler at every build.

Decided by the user on 21 November 2026: 1.

Y2. The three components that write a style attribute.

1. Allow inline style attributes only: `style-src-attr 'unsafe-inline'` added to the policy; scripts, `<style>` elements and stylesheets stay as strict as before.
2. Keep the policy as it is and draw those three with our own CSS.

Recommendation was 2. Decided by the user on 21 November 2026: 1, after asking what the policy holds and how critical the change is: an injected style attribute needs another bug first (attacker text inserted as HTML), can only change how something looks, and can run no script, load nothing from elsewhere and send nothing out.

Y3. Where the component files come from, and how they are kept.

1. IBM's ready files of one version (2.68.0), copied into `internal/dashboard/web/static/carbon/` with Carbon's LICENSE, and built into the binary as now. A script, `tools/carbon-fetch.sh VERSION`, downloads the components the dashboard uses with every file they load, and makes the theme file; updating Carbon is running it with a new version, then a browser round.
2. Built here from the npm package with a bundler, into one file.

Recommendation was 1: no Node.js, nothing to build, and the files are IBM's own, as IBM tests them. Decided by the user on 21 November 2026: 1.

Y4. Tables and the links in them (the user's example).

1. A row of a list is one link: the whole row is clickable, lights up under the pointer and ends with a ›; its text keeps the text colour. A blue link stays only where the text itself goes somewhere else, such as a rule number in a row about an alert. "All 732 alerts →" becomes a small Carbon button, "View all alerts", in the same place on every card.
2. As now: the first cell of a row is a blue link.

Recommendation was 1, as Carbon's data table and most products do it. Decided by the user on 21 November 2026: 1, with the recommendations for all the questions on the look (Y4 to Y8).

Y5. The explanations on the pages.

1. Each page keeps a one-line subtitle under its title; longer explanations move behind an ⓘ beside the title of their card or page (Carbon's toggletip), opened on a click.
2. As now: grey paragraphs at the top of pages and cards.

Recommendation was 1: the page shows its data first; the help is one click away. Decided by the user on 21 November 2026: 1, with the recommendations for all the questions on the look (Y4 to Y8).

Y6. Icons.

1. Carbon's icons (`@carbon/icons`, Apache-2.0, the same set the components use): beside each page in the navigation, on buttons (export, copy, undo, delete, apply), and for states (running, warning, error, alert).
2. No icons, as now.

Recommendation was 1. Decided by the user on 21 November 2026: 1, with the recommendations for all the questions on the look (Y4 to Y8).

Y7. The charts.

1. Keep the dashboard's own chart, which follows Carbon's chart look already, drawn with Carbon's colours and tooltip.
2. Carbon Charts (`@carbon/charts`), IBM's chart library, which needs D3 and adds about 1 MB.

Recommendation was 1: the chart already does what the pages need (bars that open their records, a table twin, keyboard steps), and the library would add weight for the same look. Decided by the user on 21 November 2026: 1, with the recommendations for all the questions on the look (Y4 to Y8).

Y8. The frame: header and navigation.

1. Carbon's UI shell: a dark header (as IBM's products have it, in both themes) with the product name, the account and the theme switch; the navigation as Carbon's side nav with icons, open on wide screens and folded into a menu on narrow ones, as now.
2. Carbon's UI shell with a light header in the light theme.

Recommendation was 1. Decided by the user on 21 November 2026: 1, with the recommendations for all the questions on the look (Y4 to Y8).

Y9. Stages, and how they run.

1. In this order, each with its tests, a browser round of every page it touches as each role, light and dark, and a commit:
   1. the files, the script, the theme and the policy (Y2, Y3); the frame (Y8) and the icons (Y6);
   2. lists and tables (Y4): the alerts list, the overview's cards, Clients, Endpoints, Applications, Rules, Runs, the change log, Users;
   3. forms and settings: every field, select, button and notification of the Settings tabs, System › Settings, Records, Dashboard settings, Analyse files, the pending changes;
   4. the detail pages: an alert, a rule, a client, an application's tabs, the Test tab, the Profile editor;
   5. explanations (Y5), loading and empty states, and the close: documents and full checks.
2. Another order, which the user names.

Recommendation was 1: the frame and the parts every page uses come first. Decided by the user on 21 November 2026: 1.

Y10. Running the stages.

1. All stages without stopping, as the last plan, committed one by one and pushed when the user says so.
2. Stage 1 first, for the user to see the new frame, then the rest.

Recommendation was 2: the frame decides the whole look; it is cheap to change before the other stages are built on it. Decided by the user on 21 November 2026: 1.

## 3. Progress

| Stage | Status |
| --- | --- |
| Decisions Y1–Y10 | All decided on 21 November 2026 |
| 1. Files, script, theme, policy, frame, icons | Done 21 November 2026 |
| 2. Lists and tables | Done 21 November 2026 |
| 3. Forms and settings | Next |
| 4. Detail pages | Waiting |
| 5. Explanations, loading and empty states, close | Waiting |

## 4. Notes from the work

1. Stage 1. `tools/carbon-fetch.sh 2.68.0` takes 84 of IBM's files (2.5 MB) for 24 components, Carbon's LICENSE, the themes of `@carbon/styles` 1.120.0 and 50 icons of `@carbon/icons` 11.92.0. `tools/carbonprep`, a small Go program, makes `themes.css` and `icons.svg` from the packages, so the script needs curl, tar and Go only. It stops when a file could make a network request, and copies an icon only when it is plain shapes. `SHA256SUMS` lists every file.
2. The browser keeps the files: with Carbon a page loads about 2.5 MB of script, and every answer of the dashboard was `Cache-Control: no-store`. A page now names its files under `/static/<version>/`, the version being a hash of every file, and the browser keeps that address for a year; a new build has a new version. The pages and the answers stay `no-store`.
3. The policy is the one of Y2: `style-src-attr 'unsafe-inline'` added, nothing else. A test checks every directive.
4. The header is Carbon's, dark in both themes: the menu button, the name, and two actions with Carbon's header panels, the colour theme and the account (name, role, the account page, log out). The side navigation is Carbon's, with an icon per page and the groups' names as before. Carbon's side navigation folds below 1056 pixels; the dashboard's folds below 1312, as the user chose on 21 November 2026, so app.js opens and closes it (Carbon's "fixed" mode) and keeps the header's actions in the tab order while it is open beside the page.
5. The parts every page uses: the period is Carbon's content switcher, as is "Show" on the alerts list; messages are Carbon's inline notification (low contrast), with the title in its slot so that the browser shows no tooltip of it; Pause is a ghost button; the way up from an application, a rule or a client is Carbon's breadcrumb.
6. Stage 2. The tables stay HTML tables in Carbon's data table look: Carbon's `cds-table` sets no column widths, and the record lists need fixed ones (a long request is cut short in its cell, not pushing the last column out of the card). A row that opens a page (a record, a client, an application, a rule) is one link: in the text colour, lit up under the pointer, with a › at its end; its first cell's link is the one the keyboard reaches, and a click anywhere else in the row follows it. Ctrl-click opens it in a new tab. Counts and chips that open another list stay blue. Lists whose rows open nothing (Endpoints, Runs, the change log, Users, an application's History) have no ›. The bar lists of the overview, a client and a rule end with a › too.
7. "All 34 alerts →" is a small Carbon button, "View all alerts", at the right of the card's title; a client and a rule have "View all records" on their "Records over time" card. The pages of the alerts list and the change log turn with Carbon's two page buttons, ‹ and ›, named in their tooltips.
8. The record lists have 12 pixels between columns instead of 16, and narrower fixed columns, because Carbon's side navigation (256 pixels) is wider than the old one. At 1440 pixels the request keeps about 7rem beside the navigation; it grows with the window, and the whole request is in its tooltip and on the record's page.
