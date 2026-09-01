# Connecting ACT to the Kali VM in VMware

Goal: ACT running on Windows reads the **real, live** systemd journal of the
Kali virtual machine. When you brute force Kali over SSH, the events show up in
the dashboard within a second or two.

There are two ways to do this. Read section 1, then pick.

---

## 1. Which setup to use

**Option A — run ACT on Windows, pull logs from Kali over SSH (recommended).**
Your code stays where you develop it. ACT connects to Kali with `ssh` and
streams `journalctl`. This is what the `--ssh` flag and the dashboard's *Kali VM*
row are for. It also demonstrates the whole point of the architecture: reading a
new machine was **one new reader file**, nothing else changed.

**Option B — run ACT inside Kali.** Copy the `backend` folder into Kali and run
it there. `journalctl` works natively with zero extra setup. You open the
dashboard from Windows at `http://<kali-ip>:8000`. Simplest, but your code lives
in two places.

The rest of this guide is Option A, with Option B at the end.

---

## 2. VMware network — get an address you can reach

In VMware, with Kali powered off: **VM → Settings → Network Adapter**.

- **NAT** (the default) — works. Kali gets an address like `192.168.x.x` that
  Windows can reach. Fine for this.
- **Bridged** — also works, and Kali looks like a normal machine on your LAN.

Either is fine. Start Kali, open a terminal in it, and find its address:

```bash
ip -4 addr show | grep inet
```

You want the one that is not `127.0.0.1` — for example `192.168.86.130`. Write
it down; this guide calls it `<KALI-IP>`.

From **Windows PowerShell**, check you can reach it:

```powershell
ping <KALI-IP>
```

If ping fails, the network adapter mode is the problem, not ACT.

---

## 3. On Kali — turn on SSH and the log source

```bash
# SSH server, so Windows can connect and so there are login events to detect
sudo systemctl enable --now ssh
sudo systemctl status ssh          # should say active (running)

# let your user read the journal without sudo (this is the clean way)
sudo usermod -aG systemd-journal $USER

# log out and back in for the group to take effect, then confirm:
groups | grep systemd-journal      # the word systemd-journal should appear
journalctl -t sshd -n 5            # should print, without sudo
```

That group membership is the important step. Without it, `journalctl` over SSH
returns *"No journal files were opened due to insufficient permissions"* — the
dashboard's **Test connection** button will tell you exactly this if it happens.

---

## 4. On Windows — SSH keys, so ACT never needs a password

ACT connects with `BatchMode=yes`, meaning it will **never** sit waiting at a
password prompt. So set up key login once:

```powershell
# only if you do not already have a key
ssh-keygen -t ed25519

# copy it to Kali (enter the Kali password this one time)
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh kali@<KALI-IP> "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

Test it — this must succeed **without** asking for a password:

```powershell
ssh kali@<KALI-IP> "journalctl -t sshd -n 3"
```

If that prints log lines, ACT will work. If it asks for a password, key login is
not set up yet; redo the copy step.

> Windows has no `ssh`? Install it once: **Settings → Apps → Optional features →
> Add a feature → OpenSSH Client**.

---

## 5. Point ACT at the VM

### From the command line

```powershell
cd C:\Users\awabn\ACT\backend

# read the last 24 hours once
python -m app.main --ssh kali@<KALI-IP> --since=-24h

# read the last 24 hours and show it as an attack path
python -m app.main --ssh kali@<KALI-IP> --since=-24h --graph

# follow the machine live, events print as they happen
python -m app.main --ssh kali@<KALI-IP> --follow
```

> Note the `=` in `--since=-24h`. PowerShell hands the value `-24h` to Python,
> and because it starts with a dash the parser can mistake it for another flag.
> The `=` avoids that. (ACT also accepts the spaced form, but `=` always works.)

### From the dashboard

```powershell
python -m pip install fastapi uvicorn      # first time only
python -m uvicorn app.api.main:app --reload
```

Open `http://127.0.0.1:8000`, then in the **Kali VM** row:

1. type `<KALI-IP>` in the address box (user stays `kali`)
2. **Test connection** — confirms SSH and journal access, shows a sample line
3. **Pull last hour** — loads recent events, the dashboard fills in
4. **Start live monitor** — follows the VM; leave it running

The address is remembered between sessions, so next time it is one click.

---

## 6. Generate a real attack to watch

Leave the live monitor running. From **Windows** (or any other machine), throw
failed logins at Kali:

```powershell
# 10 attempts against an account that does not exist -> user enumeration + brute force
for ($i=1; $i -le 10; $i++) { ssh baduser@<KALI-IP> }
```

Press Enter through the password prompts (or wait for them to fail). Within a
couple of seconds:

- the **live feed** fills with `FAILED_LOGIN` events
- once five land inside the window, a **brute force** behavior appears
- if you then log in **correctly**, ACT raises a **compromise** behavior

For the full six stage chain, after logging in successfully run on Kali:

```bash
sudo cat /etc/shadow                          # credential theft
sudo useradd -m backdoor                       # persistence
```

and press **Pull last hour** to bring them in.

---

## 7. When something does not work

The dashboard's **Test connection** button turns each of these into a plain
message. Here they are with fixes:

| Symptom | Cause | Fix |
|---|---|---|
| "Could not connect… code 255" | VM off, wrong IP, or SSH not running | check the VM is on, re-check `<KALI-IP>`, `sudo systemctl start ssh` |
| "Permission denied" | key login not set up | redo section 4, test with plain `ssh` first |
| "insufficient permissions" / "No journal files" | user not in the journal group | section 3: `sudo usermod -aG systemd-journal $USER`, then re-login. Or as a stopgap, tick sudo: add `--ssh-sudo` on the CLI |
| Page stays empty, no error | nothing ingested yet | press **Pull last hour**, or replay a sample log first |
| "ssh was not found" | no SSH client on Windows | install OpenSSH Client (end of section 4) |

Prove the pipeline itself is fine, independent of the VM, any time:

```powershell
python -m app.main --file tests/logs/auth_bruteforce.log --graph
```

---

## 8. Option B — run ACT inside Kali instead

If SSH is more trouble than it is worth on the day:

```bash
# copy the project into Kali (shared folder, scp, or git), then:
cd ACT/backend
sudo apt install python3-pip -y
pip install fastapi uvicorn --break-system-packages

# read the local journal directly, no SSH involved
python3 -m app.main --journal --since "-1h" --graph

# or the dashboard, reachable from Windows
python3 -m uvicorn app.api.main:app --host 0.0.0.0 --port 8000
```

From Windows open `http://<KALI-IP>:8000` and press **Read this machine**.

Everything else — behaviors, risk scores, ATT&CK, the attack graph — is
identical. Only the reader changed, which is exactly the design working.

---

## 9. One line for the defense

> ACT runs on my Windows host and reads the live journal of the Kali VM over
> SSH. Supporting a remote machine was a single new reader class of about
> seventy lines; the parser, correlator, risk engine and attack graph did not
> change at all, because none of them knows or cares where the logs come from.
