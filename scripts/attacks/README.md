# ACT attack simulations

Scripts that exercise ACT end to end. They produce the log activity a real
intrusion would, so you can watch ACT ingest it, correlate it, score it, map it
to MITRE ATT&CK, decide, and (when armed) respond.

> ⚠️ **Authorised use only.** The `--live` / SSH paths generate real
> authentication traffic. Only point them at machines you own or have written
> permission to test. The default (replay) paths generate log text and touch
> nothing on the network.

| Script | What it does | Needs |
| --- | --- | --- |
| `lateral_movement.py` | Emits a reproducible syslog stream for a 3-host lateral-movement intrusion. Pure text, no side effects. | Python 3 |
| `lateral_movement.sh` | `--replay` appends that stream to a log ACT tails; `--live` actually SSH-hops WEB→DB→APP and escalates/persists on each. | bash; `sshpass` for `--live` |
| `ssh_hop.sh` | Minimal real pivot: this host → A → B, escalate + persist on B, over real SSH sessions. | bash; SSH keys to A and B |

## The scenario

`lateral_movement.py` models this chain (three machines, three source addresses):

1. **Initial access** – external `203.0.113.66` brute-forces `deploy` on **web-01** and gets in.
2. **Discovery + privilege escalation** – `deploy` reads `/etc/passwd`, fails `sudo`.
3. **Lateral movement, hop 1** – from web-01's internal address `10.0.5.11` the attacker SSH-hops to **db-01** and brute-forces `dbadmin`.
4. **Credential theft + persistence** – on db-01: failed `sudo`, `sudo cat /etc/shadow`, then `useradd svc-monitor` + `usermod -aG sudo`.
5. **Lateral movement, hop 2** – from db-01's internal address `10.0.5.20` the attacker hops again to **app-02** and brute-forces `svc`.

## Quick start (replay – safe anywhere)

```bash
# 1. start ACT
cd backend
python -m uvicorn app.api.main:app --reload

# 2. in another shell, tail a lab log into ACT
#    dashboard: put nothing in the Kali box, use the "Replay" flow, OR:
curl -X POST "http://127.0.0.1:8000/api/live/start?file=act_lab.log&since=-1h"

# 3. generate the attack
python scripts/attacks/lateral_movement.py --out backend/tests/logs/act_lab.log
#    (or append with a live clock:)
scripts/attacks/lateral_movement.sh --replay backend/tests/logs/act_lab.log
```

You can also just replay the committed fixture directly:

```bash
curl -X POST "http://127.0.0.1:8000/api/ingest/file?path=lateral_movement.log"
```

### What you should see in ACT

- **~3 attack paths**, one per pivoted host, most ending in a confirmed compromise.
- Behaviours: `brute-force`, `successful-brute-force`, `privilege-escalation`,
  `sensitive-file-access`, `persistence`.
- The db-01 path reaches **kill-chain stage 6 (Persistence)**.
- A **BLOCK** decision for `203.0.113.66`, `10.0.5.11` and `10.0.5.20`.
- If notifications are enabled, a critical alert per source address.
- "Export Report" on any path produces the full incident report (HTML + PDF).

## Live mode (your lab only)

```bash
scripts/attacks/lateral_movement.sh --live \
  --web deploy@10.0.5.11  --web-pass 'webpw' \
  --db  dbadmin@10.0.5.20 --db-pass  'dbpw' \
  --app svc@10.0.5.30     --app-pass 'apppw'
```

Point ACT at each host first (`POST /api/live/start?host=...` or the dashboard
"Go live" field), so it reads the real journald events as the hops happen.

The regression test `backend/tests/test_lateral_movement.py` asserts ACT still
detects this chain from the committed `tests/logs/lateral_movement.log` fixture,
which is exactly `lateral_movement.py`'s default output.
