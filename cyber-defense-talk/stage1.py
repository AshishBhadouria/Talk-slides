#!/usr/bin/env python3
"""Stage 1: deterministic pre-filter over CloudTrail (DuckDB).
Per-actor aggregation -> compare to that actor's own baseline -> first-seen -> score -> rank.
No model involved. Usage: stage1.py WINDOW_START WINDOW_END [--baseline-days 90] [--top 5] [--out candidates.json]
"""
import duckdb, json, sys, argparse, math, datetime as dt

ap = argparse.ArgumentParser()
ap.add_argument("start"); ap.add_argument("end")
ap.add_argument("--baseline-days", type=int, default=90)
ap.add_argument("--top", type=int, default=5)
ap.add_argument("--db", default="flaws.duckdb")
ap.add_argument("--out", default="candidates.json")
a = ap.parse_args()

con = duckdb.connect(a.db, read_only=True); con.execute("SET threads=4")
t0 = dt.datetime.fromisoformat(a.start); t1 = dt.datetime.fromisoformat(a.end)
b0 = t0 - dt.timedelta(days=a.baseline_days)
W = f"ts >= '{t0}' AND ts < '{t1}'"; B = f"ts >= '{b0}' AND ts < '{t0}'"
ACTOR = "coalesce(arn, principal, id_type)"

# sensitivity classes for first-seen events (what a brand-new action is worth, by what it can do)
HIGH = ("CreateUser","CreateAccessKey","AttachUserPolicy","PutUserPolicy","CreateRole","AttachRolePolicy","PutRolePolicy",
        "UpdateAssumeRolePolicy","CreateLoginProfile","UpdateLoginProfile","DeactivateMFADevice","StopLogging","DeleteTrail",
        "UpdateTrail","PutEventSelectors","ModifySnapshotAttribute","ModifyImageAttribute","PutBucketPolicy","PutBucketAcl",
        "AuthorizeSecurityGroupIngress","CreateFunction20150331","UpdateFunctionCode20150331v2","ModifyDBSnapshotAttribute",
        "GetSecretValue","PassRole","DeleteUser","DeleteAccessKey","UpdateAccessKey","DeleteBucket","DeleteLogGroup","PutBucketVersioning")
MED  = ("RunInstances","CreateKeyPair","CreateVolume","CopySnapshot","CreateSnapshot","CreateImage","GetSessionToken","GetFederationToken",
        "ConsoleLogin","StartInstances","TerminateInstances","GetObject","PutObject","GetParameter","GetParameters","Invoke","AssumeRole")
def cls(ev):
    if ev in HIGH: return "high", 90
    if ev in MED:  return "med", 60
    if ev.startswith(("Describe","List","Get","Head")): return "discovery", 30
    return "other", 40
def sql_list(xs): return "(" + ",".join("'"+x+"'" for x in xs) + ")"

funnel = {}
funnel["window_events"] = con.sql(f"SELECT count(*) FROM ev WHERE {W}").fetchall()[0][0]
funnel["baseline_events"] = con.sql(f"SELECT count(*) FROM ev WHERE {B}").fetchall()[0][0]

# 1. aggregate per actor in window
win = con.sql(f"""
SELECT {ACTOR} actor, any_value(id_type) id_type, count(*) n, count(DISTINCT date_trunc('hour',ts)) hrs,
       max(cnt_h) max_hour, count(DISTINCT ip) ips, count(DISTINCT region) regions, count(DISTINCT event) events,
       count(*) FILTER (WHERE err IN ('AccessDenied','Client.UnauthorizedOperation')) denied,
       count(*) FILTER (WHERE err IS NULL) ok, min(ts) first, max(ts) last
FROM (SELECT *, count(*) OVER (PARTITION BY {ACTOR}, date_trunc('hour',ts)) cnt_h FROM ev WHERE {W}) GROUP BY 1
""").fetchall()
cols = ["actor","id_type","n","hrs","max_hour","ips","regions","events","denied","ok","first","last"]
actors = {r[0]: dict(zip(cols, r)) for r in win}
funnel["window_actors"] = len(actors)

# 2. baseline per actor (its own history)
base = con.sql(f"""
SELECT {ACTOR} actor, count(*) n, count(DISTINCT date_trunc('hour',ts)) hrs,
       quantile_cont(cnt_h, 0.95) p95_hour, max(cnt_h) max_hour, count(DISTINCT ip) ips,
       count(*) FILTER (WHERE err IN ('AccessDenied','Client.UnauthorizedOperation')) denied
FROM (SELECT *, count(*) OVER (PARTITION BY {ACTOR}, date_trunc('hour',ts)) cnt_h FROM ev WHERE {B}) GROUP BY 1
""").fetchall()
baseline = {r[0]: dict(zip(["n","hrs","p95_hour","max_hour","ips","denied"], r[1:])) for r in base}

# 3. first-seen: (actor, dim) pairs present in window but absent from the actor's baseline
def first_seen(dim, expr):
    rows = con.sql(f"""
    WITH w AS (SELECT {ACTOR} actor, {expr} v, count(*) n, min(ts) first FROM ev WHERE {W} AND {expr} IS NOT NULL GROUP BY 1,2),
         b AS (SELECT DISTINCT {ACTOR} actor, {expr} v FROM ev WHERE {B} AND {expr} IS NOT NULL)
    SELECT w.actor, w.v, w.n, w.first FROM w ANTI JOIN b USING (actor, v) ORDER BY w.n DESC
    """).fetchall()
    for actor, v, n, first in rows:
        actors[actor].setdefault("first_seen", {}).setdefault(dim, []).append({"value": v, "count": n, "first": str(first)})
first_seen("event", "event"); first_seen("ip", "ip"); first_seen("region", "region"); first_seen("user_agent", "ua")

# 4. tripwires: successful sensitive writes in window regardless of history
trip = con.sql(f"SELECT {ACTOR} actor, event, count(*) n, min(ts) FROM ev WHERE {W} AND err IS NULL AND event IN {sql_list(HIGH)} GROUP BY 1,2").fetchall()
for actor, ev, n, first in trip:
    actors[actor].setdefault("tripwires", []).append({"event": ev, "count": n, "first": str(first)})

# 5. score: each signal scored, actor takes its strongest signal (tie-break on sum)
for act, A in actors.items():
    Bl = baseline.get(act); sig = []
    if Bl is None:
        sig.append(("new_actor", 70, f"no activity in prior {a.baseline_days} days"))
    else:
        ratio = A["max_hour"] / max(Bl["p95_hour"], 1)
        if ratio >= 3: sig.append(("rate_deviation", min(85, int(30 + 15*math.log10(ratio))), f"peak {A['max_hour']}/h vs own p95 {Bl['p95_hour']:.0f}/h ({ratio:.0f}x)"))
        base_denied_rate = Bl["denied"] / max(Bl["n"], 1)
        if A["denied"] >= 20 and A["denied"]/max(A["n"],1) > max(0.2, 3*base_denied_rate):
            sig.append(("denied_burst", min(80, 40 + int(10*math.log10(A["denied"]))), f"{A['denied']} AccessDenied/Unauthorized in window vs {base_denied_rate:.1%} baseline rate"))
    for fs in A.get("first_seen", {}).get("event", []):
        c, s = cls(fs["value"]); sig.append((f"first_seen_event:{c}", s, f"{fs['value']} x{fs['count']} (never seen for this actor)"))
    for fs in A.get("first_seen", {}).get("ip", []):
        sig.append(("first_seen_ip", 45, f"{fs['value']} x{fs['count']}"))
    for fs in A.get("first_seen", {}).get("region", []):
        sig.append(("first_seen_region", 35, f"{fs['value']} x{fs['count']}"))
    for fs in A.get("first_seen", {}).get("user_agent", []):
        sig.append(("first_seen_user_agent", 25, f"{fs['value'][:60]} x{fs['count']}"))
    for tw in A.get("tripwires", []):
        sig.append(("tripwire_success", 95, f"{tw['event']} x{tw['count']} succeeded"))
    sig.sort(key=lambda s: -s[1])
    A["signals"] = [{"type": t, "score": s, "detail": d} for t, s, d in sig[:12]]
    A["score"] = sig[0][1] if sig else 0
    A["score_sum"] = sum(s for _, s, _ in sig)
    A["baseline"] = Bl
    for k in ("first", "last"): A[k] = str(A[k])

ranked = sorted(actors.values(), key=lambda A: (-A["score"], -A["score_sum"]))
funnel["actors_with_signal"] = sum(1 for A in ranked if A["score"] > 0)
funnel["candidates_sent"] = min(a.top, funnel["actors_with_signal"])
cands = [A for A in ranked if A["score"] > 0][:a.top]
out = {"window": [str(t0), str(t1)], "baseline": [str(b0), str(t0)], "funnel": funnel, "candidates": cands}
json.dump(out, open(a.out, "w"), indent=1, default=str)

print(f"window {t0} -> {t1}   baseline {a.baseline_days}d")
print("funnel:", json.dumps(funnel))
print(f"{'rank':<4} {'score':<5} {'actor':<62} {'events':>8} {'peak/h':>7} {'top signal'}")
for i, A in enumerate(ranked[:15], 1):
    top = A["signals"][0] if A["signals"] else {"type":"-","detail":""}
    print(f"{i:<4} {A['score']:<5} {A['actor'][:62]:<62} {A['n']:>8} {A['max_hour']:>7} {top['type']}: {top['detail'][:70]}")
