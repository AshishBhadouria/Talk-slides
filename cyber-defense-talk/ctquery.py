#!/usr/bin/env python3
"""Read-only CloudTrail query tool handed to the stage-2 investigator agent.
Every subcommand opens DuckDB read-only, caps rows, truncates payloads. There is no write path.
  ctquery.py summary  --actor ARN --from T --to T
  ctquery.py events   --actor ARN --from T --to T [--event NAME] [--ip IP] [--errors-only] [--limit 50]
  ctquery.py timeline --actor ARN --from T --to T [--bucket hour|day]
  ctquery.py baseline --actor ARN --to T [--days 90]
  ctquery.py ip       --ip IP [--from T --to T]
  ctquery.py search   --event NAME --from T --to T [--limit 50]
  ctquery.py actors   --from T --to T
"""
import duckdb, argparse, json, sys, os
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flaws.duckdb")
ap = argparse.ArgumentParser(); ap.add_argument("cmd")
for f in ("actor","event","ip"): ap.add_argument("--"+f)
ap.add_argument("--from", dest="t0"); ap.add_argument("--to", dest="t1")
ap.add_argument("--limit", type=int, default=50); ap.add_argument("--days", type=int, default=90)
ap.add_argument("--bucket", default="hour"); ap.add_argument("--errors-only", action="store_true")
a = ap.parse_args()
LIM = min(a.limit, 200)
con = duckdb.connect(DB, read_only=True); con.execute("SET threads=4")
ACTOR = "coalesce(arn, principal, id_type)"
def where():
    w = []
    if a.actor: w.append(f"{ACTOR} = $actor")
    if a.t0: w.append("ts >= CAST($t0 AS TIMESTAMP)")
    if a.t1: w.append("ts < CAST($t1 AS TIMESTAMP)")
    if a.event: w.append("event = $event")
    if a.ip: w.append("ip = $ip")
    if a.errors_only: w.append("err IS NOT NULL")
    return (" WHERE " + " AND ".join(w)) if w else ""
P = {k: v for k, v in dict(actor=a.actor, t0=a.t0, t1=a.t1, event=a.event, ip=a.ip).items() if v}
def run(sql): return con.execute(sql, P).fetchall(), [d[0] for d in con.description]
def emit(rows, cols, note=None):
    out = {"rows": [dict(zip(cols, [str(v) if v is not None else None for v in r])) for r in rows], "n": len(rows)}
    if note: out["note"] = note
    print(json.dumps(out, indent=None))
W = where()
if a.cmd == "summary":
    rows, cols = run(f"""SELECT count(*) n, min(ts) first, max(ts) last, count(DISTINCT ip) ips, count(DISTINCT region) regions,
        count(DISTINCT event) distinct_events, count(*) FILTER (WHERE err IS NULL) ok, count(*) FILTER (WHERE err IS NOT NULL) failed,
        any_value(id_type) id_type FROM ev {W}"""); emit(rows, cols)
    rows, cols = run(f"SELECT event, err, count(*) n FROM ev {W} GROUP BY 1,2 ORDER BY 3 DESC LIMIT {LIM}"); emit(rows, cols, "event x error breakdown")
    rows, cols = run(f"SELECT ip, substr(ua,1,80) ua, count(*) n, min(ts) first, max(ts) last FROM ev {W} GROUP BY 1,2 ORDER BY 3 DESC LIMIT 20"); emit(rows, cols, "sources")
elif a.cmd == "events":
    rows, cols = run(f"SELECT ts, event, region, ip, err, substr(req,1,300) request, substr(resp,1,200) response, substr(ua,1,60) ua FROM ev {W} ORDER BY ts LIMIT {LIM}"); emit(rows, cols)
elif a.cmd == "timeline":
    b = "hour" if a.bucket not in ("hour","day","minute") else a.bucket
    rows, cols = run(f"SELECT date_trunc('{b}',ts) t, count(*) n, count(*) FILTER (WHERE err IS NOT NULL) failed, count(DISTINCT event) events, count(DISTINCT ip) ips FROM ev {W} GROUP BY 1 ORDER BY 1 LIMIT {LIM}"); emit(rows, cols)
elif a.cmd == "baseline":
    if not (a.actor and a.t1): sys.exit("baseline needs --actor and --to")
    P.clear(); P.update({"actor": a.actor, "t1": a.t1})
    rows, cols = run(f"""SELECT count(*) n, count(DISTINCT date_trunc('hour',ts)) active_hours, count(DISTINCT ip) ips, count(DISTINCT region) regions,
        count(DISTINCT event) distinct_events, min(ts) first, max(ts) last FROM ev WHERE {ACTOR}=$actor AND ts >= CAST($t1 AS TIMESTAMP) - INTERVAL {a.days} DAY AND ts < CAST($t1 AS TIMESTAMP)"""); emit(rows, cols, f"{a.days}-day baseline before --to")
    rows, cols = run(f"SELECT event, count(*) n FROM ev WHERE {ACTOR}=$actor AND ts >= CAST($t1 AS TIMESTAMP) - INTERVAL {a.days} DAY AND ts < CAST($t1 AS TIMESTAMP) GROUP BY 1 ORDER BY 2 DESC LIMIT 25"); emit(rows, cols, "usual events")
    rows, cols = run(f"SELECT ip, count(*) n FROM ev WHERE {ACTOR}=$actor AND ts >= CAST($t1 AS TIMESTAMP) - INTERVAL {a.days} DAY AND ts < CAST($t1 AS TIMESTAMP) GROUP BY 1 ORDER BY 2 DESC LIMIT 15"); emit(rows, cols, "usual source IPs")
elif a.cmd == "ip":
    if not a.ip: sys.exit("ip needs --ip")
    rows, cols = run(f"SELECT min(ts) first, max(ts) last, count(*) n, count(DISTINCT {ACTOR}) actors, list(DISTINCT {ACTOR})[:10] actor_list, count(DISTINCT event) events FROM ev {W}"); emit(rows, cols, "all-time history of this IP in the account")
    rows, cols = run(f"SELECT event, err, count(*) n FROM ev {W} GROUP BY 1,2 ORDER BY 3 DESC LIMIT 25"); emit(rows, cols)
elif a.cmd == "search":
    rows, cols = run(f"SELECT ts, {ACTOR} actor, region, ip, err, substr(req,1,200) request FROM ev {W} ORDER BY ts LIMIT {LIM}"); emit(rows, cols)
elif a.cmd == "actors":
    rows, cols = run(f"SELECT {ACTOR} actor, count(*) n, count(DISTINCT ip) ips, count(*) FILTER (WHERE err IS NOT NULL) failed, min(ts) first, max(ts) last FROM ev {W} GROUP BY 1 ORDER BY 2 DESC LIMIT {LIM}"); emit(rows, cols)
else:
    sys.exit(__doc__)
