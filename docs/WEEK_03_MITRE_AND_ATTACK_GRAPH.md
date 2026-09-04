# ACT — Week 3: MITRE ATT&CK and the Attack Graph

**Goal:** stop producing a list of findings. Produce an attack.

**Status:** done. 146 tests passing.

---

## 1. What changed

Week 2 gave seven scored behaviors. But a list cannot answer the two questions
a security team actually asks:

- **"What is this, in normal security language?"** → MITRE ATT&CK mapping
- **"Is this one attacker, and how far did he get?"** → the attack graph

```
python -m app.main --file tests/logs/auth_bruteforce.log --graph
```

```
1 attack path(s)

Attack path 1, source 192.168.1.50
    kill chain 6 of 6 stages, 100% complete, the attacker succeeded
    from 2026-08-06 21:10:58 to 21:12:58
    highest risk 100/100

    1. Discovery   SSH User Enumeration   T1087.001   risk 68
    |   same source address 192.168.1.50
    2. Credential Access   Possible Brute Force Attack   T1110.001   risk 73
    |   same source address 192.168.1.50
    2. Credential Access   Possible Brute Force Attack   T1110.001   risk 58
    |   same source address 192.168.1.50, same user account kali
    3. Initial Access   Account Compromise After Brute Force   T1110.001, T1078.003   risk 100
    |   same source address 192.168.1.50, same user account kali
    4. Privilege Escalation   Privilege Escalation Attempt   T1548.003   risk 45
    |   same user account kali
    5. Credential Theft   Sensitive File Access   T1003.008   risk 80
    |   same source address 192.168.1.50
    6. Persistence   Suspicious Account Creation   T1136.001   risk 85
```

That is the whole story of the break-in on one screen.

---

## 2. MITRE ATT&CK mapping

`app/analyzer/mitre_mapper.py` + `data/mitre_attack.json`

ATT&CK is the standard vocabulary the whole security industry uses for attacker
behaviour. Saying **T1110.001** instead of "5 failed logins" means any analyst,
any tool, and any examiner immediately knows what ACT found.

| ACT rule | Technique | Tactic | Stage |
|---|---|---|---|
| `user-enumeration` | T1087.001 Account Discovery: Local Account | Discovery | 1 |
| `brute-force` | T1110.001 Brute Force: Password Guessing | Credential Access | 2 |
| `distributed-brute-force` | T1110.001 Brute Force: Password Guessing | Credential Access | 2 |
| `successful-brute-force` | T1110.001 + T1078.003 Valid Accounts: Local Accounts | Initial Access | 3 |
| `privilege-escalation` | T1548.003 Sudo and Sudo Caching | Privilege Escalation | 4 |
| `sensitive-file-access` | T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow | Credential Access | 5 |
| `persistence` | T1136.001 Create Account: Local Account | Persistence | 6 |

Three design decisions worth defending:

**The mapping lives in JSON, not in Python.** ATT&CK is updated a few times a
year, and a new correlation rule should be mappable by editing a data file.

**The knowledge base is offline.** A live demo must never depend on the internet
being available in the exam room. A missing or broken file leaves behaviors
unmapped instead of crashing detection.

**One behavior can map to several techniques.** `successful-brute-force` is both
the guessing (T1110.001) and the use of the working credentials (T1078.003).
Forcing one technique per behavior would lose information.

---

## 3. Kill chain stages

ACT uses **six ordered stages**, not MITRE's tactic order. This is deliberate.

MITRE lists Credential Access *before* Discovery, because its list is a
catalogue, not a timeline. For measuring **how far an attacker got**, ACT needs
depth of access, so it defines its own ladder:

```
1 Discovery            looking for accounts
2 Credential Access    guessing passwords
3 Initial Access       got in
4 Privilege Escalation trying to become root
5 Credential Theft     stealing the password file
6 Persistence          building a way back in
```

**Kill chain completeness** = deepest stage reached / 6. It is the single number
that says how bad an incident was:

- 33% — someone knocked on the door and failed
- 100% — someone is living in your machine

---

## 4. The attack graph

`app/models/attack_graph.py` + `app/analyzer/attack_graph_builder.py`

**Nodes** are behaviors. **Edges** mean "these two share an actor and one came
after the other".

How edges are decided, in three steps:

1. Every behavior gets **actor keys** from its attributes —
   `("ip", "192.168.1.50")`, `("user", "kali")`, `("host", "kali")`.
2. Behaviors sharing a key are put in order and each is linked to the one
   **immediately** before it.
3. Edges between the same two nodes are merged, keeping every reason.

Linking only to the immediate predecessor is what keeps the graph readable.
Linking every matching pair would give a mesh nobody can look at.

**Ordering is by stage first, time second.** This matters and is a good question
to be ready for: the compromise behavior *starts* at the timestamp of the first
failed login it uses as evidence, so sorting by time alone would put the
compromise before the brute force that produced it. The stage number carries the
logical order; time only breaks ties.

**Separate attackers become separate paths.** A plain connected-components
search over the edges. Two people attacking the same machine must never be drawn
as one attack.

---

## 5. Two attackers, proved

`tests/logs/two_attackers.log` is a new sample log: a failed attack from the
internet at 02:14, and a successful one from inside the network at 09:41.

```
python -m app.main --file tests/logs/two_attackers.log --graph
```

```
2 attack path(s)

Attack path 1, source 10.10.10.22
    kill chain 5 of 6 stages, 83% complete, the attacker succeeded
    2. Credential Access   Possible Brute Force Attack   T1110.001   risk 58
    |   same source address 10.10.10.22, same user account devops
    3. Initial Access   Account Compromise After Brute Force   T1110.001, T1078.003   risk 100
    |   same user account devops
    5. Credential Theft   Sensitive File Access   T1003.008   risk 80

Attack path 2, source 185.220.101.34
    kill chain 2 of 6 stages, 33% complete, no confirmed compromise
    1. Discovery   SSH User Enumeration   T1087.001   risk 85
    |   same source address 185.220.101.34
    2. Credential Access   Possible Brute Force Attack   T1110.001   risk 95
```

Three things this demonstrates at once:

- the two attackers are separated correctly, no shared nodes
- the one who **got in** is ranked first even though the other scored higher
  per behavior — completeness beats loudness
- the insider skipped stage 4 (no failed sudo), and the path handles the gap
  instead of breaking

The outsider's brute force scores 95 because the risk engine sees three extra
things the insider's does not: an external address (+10), 02:14 in the morning
(+5), and `root` as the target (+15).

---

## 6. JSON for the dashboard

```
python -m app.main --file tests/logs/auth_bruteforce.log --graph --json
```

```json
{
  "path_count": 1,
  "paths": [{
    "actor": "192.168.1.50",
    "succeeded": true,
    "deepest_stage": 6,
    "total_stages": 6,
    "completeness": 1.0,
    "highest_risk": 100,
    "techniques": ["T1087.001", "T1110.001", "T1078.003",
                   "T1548.003", "T1003.008", "T1136.001"],
    "nodes": [...],
    "edges": [...]
  }]
}
```

This is exactly the shape the Week 4 dashboard will draw. Every node carries its
technique and a link to the ATT&CK page.

---

## 7. Files

**Added**

| File | Purpose |
|---|---|
| `data/mitre_attack.json` | offline ATT&CK knowledge base, rule to technique and stage |
| `app/models/mitre.py` | `MitreTechnique`, builds its own attack.mitre.org URL |
| `app/analyzer/mitre_mapper.py` | fills techniques and stage on each behavior |
| `app/models/attack_graph.py` | `AttackNode`, `AttackEdge`, `AttackPath`, `AttackGraph` |
| `app/analyzer/attack_graph_builder.py` | actor keys, edges, connected components |
| `tests/logs/two_attackers.log` | two separate attackers on one machine |
| `tests/test_mitre_mapper.py` | mapping, stage order, broken knowledge base |
| `tests/test_attack_graph.py` | edges, ordering, completeness, JSON export |
| `tests/test_attack_chain_mitre.py` | full log, end to end |
| `tests/test_two_attackers.py` | path separation |

**Modified**

| File | Change |
|---|---|
| `app/models/behavior.py` | added `techniques`, `stage`, `stage_name`, `technique_ids`, `tactics` |
| `app/analyzer/behavior_correlator.py` | applies the mapper, added `build_attack_graph()` |
| `app/utils/report_printer.py` | prints techniques per behavior, added `print_attack_graph()` |
| `app/main.py` | added `--graph` |

---

## 8. Running it

```bash
cd backend

python -m app.main --file tests/logs/auth_bruteforce.log            # behaviors + techniques
python -m app.main --file tests/logs/auth_bruteforce.log --graph    # the attack path
python -m app.main --file tests/logs/two_attackers.log --graph      # two attackers
python -m app.main --file tests/logs/auth_bruteforce.log --graph --json

python -m pytest
```

---

## 9. Next week

REST API (`/events`, `/behaviors`, `/attack-graph`, `/stats`, websocket stream),
the dashboard that draws this graph, and the defense deck.
