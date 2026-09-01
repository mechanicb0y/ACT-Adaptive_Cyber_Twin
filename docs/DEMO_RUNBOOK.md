# ACT — Demo Runbook

What to type on the day. About five minutes. Practise it twice.

---

## Before you walk in

```bash
cd backend
python -m pip install pytest fastapi uvicorn
python -m pytest                    # must say 176 passed
python -m app.main --file tests/logs/auth_bruteforce.log --graph
```

Open two terminals in `backend/`, and a browser tab on `http://127.0.0.1:8000`.

**Record a backup video of the whole demo the day before.** If the Kali VM
misbehaves in the room, you play the recording and keep talking.

---

## Part 1 — the command line, 2 minutes

**1. Behaviors, scored and explained**

```bash
python -m app.main --file tests/logs/auth_bruteforce.log
```

Say: *"Thirty-five lines of a real auth log go in. Seven behaviors come out,
each with a risk score and the reasons behind it."*

Point at the compromise: **100, Critical**, and read two of the `+` lines out
loud. The point is that the score explains itself.

Then scroll to the two brute force findings. **root scored 73, kali scored 58** —
same address, same minute, same speed. The only difference is that root is a
privileged account, worth +15. That comparison lands better than any slide.

**2. The attack path**

```bash
python -m app.main --file tests/logs/auth_bruteforce.log --graph
```

Say: *"Those same seven behaviors, connected. One attacker, six of six kill
chain stages, one hundred percent complete. Every step carries its MITRE
technique."*

**3. Two attackers**

```bash
python -m app.main --file tests/logs/two_attackers.log --graph
```

Say: *"One machine, one log file, two different incidents. The one from the
internet at two in the morning failed at stage two. The one from inside the
network got in and reached stage five. The one who actually got in is ranked
first, even though the other looked louder."*

---

## Part 2 — the dashboard, 2 minutes

```bash
python -m uvicorn app.api.main:app --reload
```

In the browser:

1. Pick `auth_bruteforce.log` and press **Replay log** — the header fills in.
2. Open one behavior card, expand **"Why this score is 100"**.
3. Click a **T1110.001** chip — it opens the real MITRE page.
4. Switch to the **Attack paths** tab and walk down the chain.

---

## Part 3 — live from the Kali VM, 1 minute (optional, highest impact)

Set this up once before the day using `docs/KALI_SETUP.md`. On the day, with the
dashboard already open:

1. In the **Kali VM** row, the address is remembered — press **Test connection**
   to confirm the VM is reachable.
2. Press **Start live monitor**.
3. From another terminal, attack the VM:

```powershell
for ($i=1; $i -le 10; $i++) { ssh baduser@<KALI-IP> }
```

Events appear in the live feed within a second or two, and a brute force
behavior appears once five failures land in the window. This is real traffic
against a real machine, read live over SSH — say that out loud.

**Skip this if the network is unreliable.** Parts 1 and 2 are enough, and the
recorded backup covers it.

---

## Answers to keep ready

**"Is this just a SIEM?"**
A SIEM collects and searches logs. ACT understands behavior. A SIEM can show
you twenty failed logins; it will not tell you that the login that followed
them was a breach, or that the attacker reached stage six of six.

**"Why no AI?"**
AI needs correct data first. In week one I found that every event was stamped
with the time ACT read it, not the time it happened. A model trained on that
would have learned the wrong thing very confidently. The four weeks built the
clean, labelled, timestamped history a model would need.

**"How hard is Windows support?"**
One reader and one parser. Nothing else changes — that is the whole reason for
the layered design.

**"Why your own kill chain instead of MITRE's tactic order?"**
MITRE lists Credential Access before Discovery because their list is a
catalogue, not a timeline. To measure how far an attacker got you need depth of
access, so ACT defines its own six stage ladder and keeps the ATT&CK technique
IDs unchanged.

**"The same failed logins appear in three findings. Is that double counting?"**
No. Enumeration answers *which accounts did he look for*, brute force answers
*which password did he guess*, compromise answers *did he get in*. Three
different questions about the same evidence.

**"What is the 77% coverage?"**
The share of a real log file ACT understands. The rest is cron, systemd and
session noise that is correctly ignored. It is an honest number, and it is
printed on every run.

**"What would you do next?"**
Risk scoring over time, so a source that attacks every night builds a
reputation. Then prediction: given the first three stages, what is stage four
likely to be. Then automatic response.
