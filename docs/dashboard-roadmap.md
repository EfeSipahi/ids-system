# Dashboard roadmap

Written: 21 November 2026, at the user's request, from the conversations of 19–21 November 2026. This is a list to choose from, not a plan: each part gets its own decisions and plan before work starts, as every step of this project has.

## 1. Where the dashboard stands

| Part | Since | Plan |
| --- | --- | --- |
| Records, alerts, a read-only dashboard behind a login over HTTPS | 23 October | [development-plan-records-dashboard.md](development-plan-records-dashboard.md) |
| UI rework, then the IBM Carbon look | 24 October, 18 November | [development-plan-dashboard-ui.md](development-plan-dashboard-ui.md) |
| Applications and profiles shown (application filter, exceptions per application) | 25 October | [development-plan-profiles.md](development-plan-profiles.md) |
| The live input: gaps, copier status, proxy and response fields | 18 November | [development-plan-proxy.md](development-plan-proxy.md) |
| Test tab: a request written by hand, analysed by the IDS's own engine | 19 November | [development-plan-test-tab.md](development-plan-test-tab.md) |
| Marks on alerts, roles (viewer, analyst, admin), Users, Account and Log pages, change log | 20 November | [development-plan-marks-users.md](development-plan-marks-users.md) |
| Replay of request files on their own clock (`ids-offline -replay`) | 20 November | main plan, section 11.33 |
| The pages in a navigation panel on the left, in named groups | 21 November | [development-plan-dashboard-ui.md](development-plan-dashboard-ui.md), "The side navigation" |

What the dashboard still can't do: change anything of the IDS. Its exceptions, levels, modes, profiles and rules are edited by hand in files, and `ids-live` reads them only when it starts.

## 2. Foundations: needed by several parts below

| # | Item | What it gives | Decisions it needs |
| --- | --- | --- | --- |
| 2.1 | Application selector | A selector at the top of the navigation panel: "All applications", each application, and "No application". The overview, the alerts list, the Rules page and the Test tab follow it; Users, Log and Engine stay global. The choice is kept in the page address, so a shared link keeps its application. Fastly's Next-Gen WAF works this way (a corp overview across sites and a dashboard per site). The user's idea, 21 November | Which pages follow the selection; whether a selected application is remembered between visits; what "All applications" shows on pages made for one |
| 2.2 | A safe change path | Every change to the IDS goes through the same steps: check it (the engine's own loader, the profile reader), preview it against recorded traffic ("removes 37 alerts, 2 of them marked real attack"), apply it with a reason, keep a version so it can be undone, write it to the change log. Exceptions (3), settings (4) and own rules (5) use it; the MCP server (I1) can later too | Who may change what (analyst or admin); whether changes need the password again, as user changes do; where versions are kept |
| 2.3 | `ids-live` reloads without stopping | Today `ids-live` reads its configuration, rules and profiles only at its start. A reload (for example on SIGHUP, or a request over a control socket) prepares the new rule set beside the old one and switches when it is ready, so no request goes unanalysed | How the dashboard asks for a reload; what happens when the new configuration fails to load (the old one stays) |
| 2.4 | The dashboard writes IDS settings | Until now the dashboard writes only its own state folder (C1 of the marks plan). Changing profiles and configurations means writing those files too, with their permissions, a lock against a second editor, and a copy of each version | This changes an earlier decision (V2, C1), so it needs the user's approval |

## 3. Exceptions: from a false positive to a fix (group 3)

| # | Item | What it gives |
| --- | --- | --- |
| 3.1 | An exception from an alert | On an alert marked false positive: the dashboard proposes the smallest exception, for example "rule 942100 skips the parameter `search` for the application `shop`" (a skip), or the rule off for that application, or a CRS setting. A reason is required |
| 3.2 | An exception from a rule | On a rule's page (6.1), for the selected application: off, skip a place, or back on |
| 3.3 | The preview | Before saving, the exception is tried on the recorded traffic of the application: how many alerts it would remove, how many of those are marked real attack (a warning) |
| 3.4 | History and undo | Every exception with who, when and why; one click to take it back |
| 3.5 | A single stricter rule on for one application | Today only the whole paranoia level can be raised; switching on one level-3 rule while the application stays at level 2 needs an engine change ("on" exceptions) |

## 4. Applications and their settings (group 4)

| # | Item | What it gives |
| --- | --- | --- |
| 4.1 | Application settings | Monitor or alert mode, paranoia level, hosts and paths, for the selected application |
| 4.2 | A new application | Add an application with its hosts; it starts with an empty profile in monitor mode |
| 4.3 | Profile editor | Endpoints, parameters, types, lengths, secret fields; suggestions from recorded traffic, as `ids-offline -endpoints` lists them today |
| 4.4 | Global settings | The default paranoia level, the rules excluded for everyone, records (file size, how many files to keep, full requests on or off), `ids-live`'s workers and queues |
| 4.5 | Retention | How long records and marks are kept; marks keep a client address after their record rotates away (C6 of the marks plan, open with A09) |

## 5. Own rules (group 7, first part)

| # | Item | What it gives | Decisions it needs |
| --- | --- | --- | --- |
| 5.1 | Rules of one's own | Rules for an application's own attacks, such as "alert when `/admin` is reached from outside the office network". Kept in a rule file of their own, never inside CRS's files | Written as SecLang text, or built with a form (target, operator, value, score); which rule numbers they get; global or per application |
| 5.2 | Checked before they go live | The engine's loader refuses what it doesn't support; the rule is tried in the Test tab and previewed on recorded traffic (2.2) | |
| 5.3 | Rules for one application only | An engine change: today an application can switch rules off or narrow them, not have rules of its own | How the engine keeps one shared rule set (decision F's option B) while some rules run only for one application |

## 6. The Rules page (group 7, second part)

| # | Item | What it gives |
| --- | --- | --- |
| 6.1 | A page per rule | Its pattern as written in CRS, its description, file, level and phase; its status per application (with the exceptions); how often it fired over time; how many of its records are marked false positive; CRS's own tests for it, each one click into the Test tab |
| 6.2 | Search | By rule number or by words of its description |
| 6.3 | The paranoia levels explained | What each level adds, with the number of rules, for the selected application |

## 7. More views, read only (group 5)

| # | Item | What it gives |
| --- | --- | --- |
| 7.1 | A page per client address | Everything an address sent, over time, its alerts and marks; the place to start blocking later (K4) |
| 7.2 | A page per endpoint | Which paths are attacked most, per application |
| 7.3 | Live health | Whether the copier is connected, how full the queues are, dropped copies per minute, whether `ids-live` writes. Parts exist today on the overview (the not-analysed tile, gaps, two warnings) |
| 7.4 | Export | The filtered records as CSV or JSON; left over from the first group |

## 8. Smaller fixes and leftovers

| # | Item | Note |
| --- | --- | --- |
| 8.1 | Extra names for the dashboard's certificate | A setting for names and addresses its own certificate should carry (for example an address the dashboard is reached at through a VPN), so browsers stop warning about the name. Open since 19 November |
| 8.2 | Common passwords refused | NIST SP 800-63B-4 also asks to check a chosen password against a list of known or leaked passwords; today only the length is checked |
| 8.3 | The Log page in words | A bulk mark shows its filter as an address query (`kind=alerts&rule=942100`); it could say "alerts of rule 942100" |
| 8.4 | Long chips | A long attack-group name alone in its column is cut short, with the full name in its tooltip |
| 8.5 | Marks of records that are gone | Marks whose records rotated or were replaced still count on the Engine page ("Marked records"); the page could tell them apart |

## 9. Controlling the system (group 6, idea I3)

Starting and stopping `ids-live`, editing Caddy's configuration from the dashboard, an installer. The riskiest part: whoever controls this controls all the traffic. It needs 2.2 to 2.4 first, and its own decisions on who may do it.

## 10. After the dashboard

The order the user set on 12 October continues: the response rules (K8) and alerts sent by webhook and syslog; their destinations would be set in the dashboard (2.2). Then the ML model and the decision mechanism, prevention (K4: blocking addresses from 7.1), learned profiles, the Nginx input. The MCP server (I1) uses the change path of 2.2.

## 11. A suggested order

| Step | Parts | Why in this order |
| --- | --- | --- |
| 1 | 2.1 application selector, 7.4 export | Small; the selector shapes every page that follows |
| 2 | 2.2 change path, 2.3 reload, 2.4 writing settings, 3.1–3.4 exceptions | The step with the most value: marks already show the false positives; the foundations are built once, with the first thing that uses them |
| 3 | 4.1–4.3 application settings and profile editor, 6.1–6.3 Rules page | On the same foundations; the rule page is where exceptions and statuses meet |
| 4 | 7.1–7.3 views | Read only, so low risk; can also be fitted in between |
| 5 | 5.1–5.3 own rules, 3.5 "on" exceptions | Needs engine decisions |
| 6 | 4.4–4.5 global settings and retention, section 8 | Smaller pieces |
| 7 | 9 controlling the system | Last: the most power, the most risk |

Each step starts with the user's decisions, then a plan for approval.
