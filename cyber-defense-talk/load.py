import duckdb, glob, time, gzip, json, os
DATA = "/private/tmp/claude-502/-Users-ashish-bhadouria-Claude-Code/1572719d-4d59-4f99-a6fd-2db4a010e237/scratchpad/flaws_data/flaws_cloudtrail_logs/*.json.gz"
OUT = "flat.ndjson"
t0=time.time(); n=0
with open(OUT,"w") as out:
    for f in sorted(glob.glob(DATA)):
        with gzip.open(f,"rt") as fh:
            recs = json.load(fh)["Records"]
        for r in recs:
            ui = r.get("userIdentity") or {}
            sc = ui.get("sessionContext") or {}
            row = {
             "ts": r.get("eventTime"), "event": r.get("eventName"), "source": r.get("eventSource"), "region": r.get("awsRegion"),
             "ip": r.get("sourceIPAddress"), "ua": r.get("userAgent"), "err": r.get("errorCode"), "errmsg": r.get("errorMessage"),
             "id_type": ui.get("type"), "arn": ui.get("arn"), "username": ui.get("userName"), "akid": ui.get("accessKeyId"),
             "principal": ui.get("principalId"), "issuer_arn": (sc.get("sessionIssuer") or {}).get("arn"),
             "mfa": (sc.get("attributes") or {}).get("mfaAuthenticated"), "readonly": r.get("readOnly"), "etype": r.get("eventType"),
             "req": json.dumps(r.get("requestParameters")) if r.get("requestParameters") is not None else None,
             "resp": json.dumps(r.get("responseElements")) if r.get("responseElements") is not None else None,
             "eid": r.get("eventID"), "ro_console": (ui.get("invokedBy")), "rcpt": r.get("recipientAccountId")}
            out.write(json.dumps(row)+"\n"); n+=1
        print(os.path.basename(f), n, round(time.time()-t0,1), flush=True)
con = duckdb.connect("flaws.duckdb")
con.execute("SET memory_limit='6GB'; SET threads=4;")
con.execute(f"""CREATE TABLE ev AS SELECT CAST(ts AS TIMESTAMP) ts, event, source, region, ip, ua, err, errmsg, id_type, arn, username, akid, principal, issuer_arn, mfa, TRY_CAST(readonly AS BOOLEAN) readonly, etype, req, resp, eid, ro_console AS invoked_by, rcpt
 FROM read_ndjson('{OUT}', columns={{'ts':'VARCHAR','event':'VARCHAR','source':'VARCHAR','region':'VARCHAR','ip':'VARCHAR','ua':'VARCHAR','err':'VARCHAR','errmsg':'VARCHAR','id_type':'VARCHAR','arn':'VARCHAR','username':'VARCHAR','akid':'VARCHAR','principal':'VARCHAR','issuer_arn':'VARCHAR','mfa':'VARCHAR','readonly':'VARCHAR','etype':'VARCHAR','req':'VARCHAR','resp':'VARCHAR','eid':'VARCHAR','ro_console':'VARCHAR','rcpt':'VARCHAR'}})""")
print("done", round(time.time()-t0,1))
print(con.sql("SELECT count(*) n, min(ts), max(ts), count(DISTINCT arn) actors, count(DISTINCT ip) ips, count(DISTINCT event) events FROM ev"))
print(con.sql("SELECT id_type, count(*) n FROM ev GROUP BY 1 ORDER BY 2 DESC"))
print(con.sql("SELECT coalesce(arn, principal) actor, count(*) n, min(ts) first, max(ts) last FROM ev GROUP BY 1 ORDER BY 2 DESC LIMIT 25"))
print(con.sql("SELECT event, count(*) n FROM ev GROUP BY 1 ORDER BY 2 DESC LIMIT 30"))
print(con.sql("SELECT err, count(*) n FROM ev WHERE err IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 10"))
print(con.sql("SELECT date_trunc('month', ts) m, count(*) n FROM ev GROUP BY 1 ORDER BY 1"))
