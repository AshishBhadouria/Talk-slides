# Proactive Cyber defense with AI Agents — worked example

## Reproduce

```bash
# 1. data (240 MB, public): Scott Piper's flaws.cloud CloudTrail logs, 2017-02-12 → 2020-10-07, 1,939,207 events
curl -sSL -o flaws_cloudtrail_logs.tar https://summitroute.com/downloads/flaws_cloudtrail_logs.tar && tar xf flaws_cloudtrail_logs.tar
python3 -m pip install duckdb

# 2. load into DuckDB (edit DATA path in load.py) → flaws.duckdb, table ev
python3 load.py

# 3. stage 1: deterministic pre-filter (no model). Incident tick, incident day, quiet control day
python3 stage1.py 2019-08-21T07:00:00 2019-08-21T08:00:00 --top 5 --out candidates/cand_hour.json
python3 stage1.py 2019-08-21T00:00:00 2019-08-22T00:00:00 --top 5 --out candidates/cand_aug21.json
python3 stage1.py 2019-08-14T00:00:00 2019-08-15T00:00:00 --top 5 --out candidates/cand_aug14.json

# 4. stage 2: read-only investigator agent (Claude Code CLI, allow-listed to one command)
claude auth login   # the stored CLI session had expired when the talk was built; the two runs in runs/ were made
                    # with the same prompt and tool as Claude Code subagents on claude-opus-5-5 instead
python3 run_agent.py candidates/cand_hour.json --name incident --model opus --top 1
python3 run_agent.py candidates/cand_aug14.json --name control --model opus --top 1
```

## Files

- `load.py` — flattens the 20 json.gz files to NDJSON and builds the DuckDB table `ev`.
- `stage1.py` — per-actor hourly aggregates, 90-day own-baseline, first-seen anti-joins (event, IP, region, user agent), tripwires, scoring, ranking. ~2–3 s per window.
- `ctquery.py` — the ONLY tool the agent gets: read-only DuckDB, 7 subcommands, rows capped at 200, payloads truncated.
- `run_agent.py` — drives `claude -p` with `--tools Bash --allowedTools "Bash(python3 ./ctquery.py:*)"`, stream-json transcripts, cost/usage summary.
- `candidates/` — stage-1 output for the 5-min tick, 1-hour tick, incident day and control day.
- `runs/incident_aug21.json` — 8 tool calls, verdict malicious / page=true (claude-opus-5-5, 64 s, ~$0.95 at list).
- `runs/control_aug14.json` — 7 tool calls, verdict benign / page=false (63 s, ~$1.07 at list), plus two correct pre-filter tuning suggestions.
- `research/` — primary-source notes for the agent slides (Agent 1 identity; Agents 2–3 CI/CD and exposure). Agents 4–5 were written from the Stratus list, Entra/Google docs and MSRC/GTIG posts cited on the slides.

## Known follow-ups
- Count `Client.UnauthorizedOperation` as a denial in stage1.py (the control agent caught this).
- Weight `first_seen_ip` by actor type; cluster candidates sharing an IP/user agent before investigating.
- Add the memory stage (write verdicts back to a table the next run reads).


Check the detection rules I collected from Elastic 
https://github.com/AshishBhadouria/detection-rules/tree/main