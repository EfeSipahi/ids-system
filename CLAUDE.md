# Notes for Claude Code

Read these first, in this order:

1. [context.md](context.md): what exists, what doesn't, the order of work, and the rules for working here (section 4).
2. [docs/development-plan-proxy.md](docs/development-plan-proxy.md): the current step, live traffic through Caddy. Its progress table says which stage is next.
3. [ids-system-plan-phaze1.md](ids-system-plan-phaze1.md): the main plan, for the architecture and the history of decisions (section 11).

Check the status against the code and `git log` before relying on it.

## How the user wants to work

1. Answer in English with numbered points; plans and documents in this repository are in English. In a Turkish text the user asks for (a report, a form), keep technical terms in English (proxy, dashboard, endpoint), with Turkish suffixes after an apostrophe (proxy'nin).
2. Bold is invisible in the user's terminal. Never use it to carry meaning; write a recommendation as a plain line starting with "Recommendation:". In tables, keep one fact per cell and say what each number is ("5 of 99 normal flagged").
3. The user approves decisions one at a time. Re-ask a question exactly as it was first posed, keep side topics for after the current list, and never approve anything on the user's behalf.
4. Batch tool calls that need approval. Browser checks are one batched call per round: visit every page, save screenshots, then look at them.
5. Don't commit unless the user asks. Never commit `proje_oneri_formu.docx` or the course forms; they hold personal data.
