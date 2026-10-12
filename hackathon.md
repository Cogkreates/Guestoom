# neatHack build log: Stock Agent

## Project
**Stock Agent** is an AI agent for small traders who resell non-perishable goods. The trader gives it a want-list with price ceilings and a budget. The agent watches a supplier for new stock, orders it automatically within those limits (asking a human above a spend threshold), verifies the order confirmation, tracks the shipment, and notifies when it arrives.

**Problem:** traders lose time and miss new stock by checking suppliers by hand and chasing orders and shipments.

## Team
COG (GitHub: Cogkreates)

## Stack
- Python (standard library only for the agent), run in GitHub Codespaces from an Android phone
- Mock supplier with scripted failures (sold out, price change, payment decline) so runs are repeatable
- neatlogs Python SDK for tracing; `uv` to run on Python 3.12
- Entire with Copilot CLI for session capture and checkpoints
- cfo.ai (Ari) for the business plan

## How each required tool is used
- **neatlogs:** every run is one WORKFLOW trace. Agent steps are CHAIN/AGENT spans, supplier calls are TOOL spans, order verification is a GUARDRAIL span, and recoveries and alerts are structured logs. Two workflows exist so runs can be compared: `stock-agent` (recovery on) and `stock-agent-baseline` (recovery off).
- **Entire:** a Copilot CLI session wrote `test_agent.py`, and Entire captured it as a checkpoint linked to the commit "Add agent tests with Entire".
  - Link: https://entire.io/gh/Cogkreates/Stock-agent-2/commit/4ec849c6dfa2196e9aad0c2f20015eb2ebf40aed
  - Checkpoint ID: 01M4NTW4E2J80NFTXZAFS708TF (confirm against `entire checkpoint list` before submitting)
- **cfo.ai:** a 12-month model with main, downside (half the customers) and upside scenarios. Key assumptions: $29/month plus 0.5% of order value per trader, 5 traders growing to 200 by month 12, $5,000 starting cash, $0 founder salary. Main scenario: revenue $65.5K, gross margin about 76%, first profitable month Nov 2026, cash never runs out. All customer numbers are unvalidated assumptions. The exported model is included in the submission.

## Build log
### 2026-10-10
- Chose the idea after comparing several options. Planned the architecture: watcher, planner, orderer, verifier, tracker, notifier.
- Built the repo: models, mock supplier, agent loop with budget cap, price ceiling, approval gate, verification, substitution and payment retry, and shipment tracking.

### 2026-10-11
- Wired in neatlogs tracing. First attempts failed: `init()` rejected the `endpoint` option, then `workflow_name`, because pip installed an old neatlogs on the Codespace's newer Python. Fix: run with `uv run --python 3.12 --with neatlogs`, and make `tracing.py` tolerate older SDKs.
- The neatlogs doctor probe timed out waiting for readback (ingestion was still processing). The real run's trace did appear in the dashboard: `stock-agent`, 67 spans, including the sold-out substitution and the payment retry.
- Set up Entire with Copilot CLI and captured a checkpoint.

### 2026-10-12
- Built the cfo.ai model and exported it (date to confirm).
- Added a recovery switch (`STOCK_RECOVERY=off`) for before/after evidence, and made the workflow output return a run summary.
- Ran both modes against the deterministic mock supplier:
  - Baseline (recovery off): sold-out mug and declined payment are left unfilled. Spent 64.00 of 300.00. Remaining: ceramic mug 12, LED bulb 40, tote bag 30.
  - Recovery on: the mug is substituted with the approved stoneware mug and the payment is retried. Spent 213.60 of 300.00. Remaining: only the tote bag (30), which is over its price ceiling.
- Ran `python3 test_agent.py`: 3 tests (sold-out substitution, price ceiling alert, payment retry) ran and passed.
- Trace IDs for both runs: TODO, add from the neatlogs dashboard.

## Demo
Run `uv run --python 3.12 --with neatlogs python run_demo.py` (recovery on) or prefix with `STOCK_RECOVERY=off` for the baseline. Set `NEATLOGS_API_KEY` in your own shell first and never commit it. Demo video: TODO.

## Known limitations and next steps
- The supplier and shipment tracker are mocks. No real supplier integration yet.
- Decisions are rule-based. A Claude planner is planned, not built.
- Approval is auto-approved in the demo, and notifications print to the console instead of sending email.
- Demand is unvalidated, and order fees are about 58% of modelled revenue.
- Resale of ordered stock is a planned expansion, not built.

## Submission
- Confirmed from the hackathon page: public repo with commits made during the event; demo video of 3 minutes or less covering neatlogs, Entire and cfo.ai; Entire checkpoint link and ID; business plan; quote-post on X during the Oct 12 window, 7:00-11:55 PM IST.
- Pending: deadline conflict (Entire's page says Oct 10-11), to confirm on Discord.
- Outstanding: demo video, X post, trace IDs.
