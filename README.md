```
░██████╗███████╗ ██████╗ ███████╗ █████╗ ██╗   ██╗██╗  ████████╗
██╔════╝██╔════╝██╔════╝ ██╔════╝██╔══██╗██║   ██║██║     ██╔══╝
╚█████╗ █████╗  ██║  ███╗█████╗  ███████║██║   ██║██║     ██║
 ╚═══██╗██╔══╝  ██║   ██║██╔══╝  ██╔══██║██║   ██║██║     ██║
██████╔╝███████╗╚██████╔╝██║     ██║  ██║╚██████╔╝███████╗██║
╚═════╝ ╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝
                                          // ACTIVE DIRECTORY
  certipy  //  bloodyAD  //  impacket  //  netexec  //  rubeus
```

> **v3.0.1** — Single-file Python Active Directory pentest REPL. 100+ modules, live color-coded attack map, custom BloodHound viewer (no Neo4j), Hivemind C2 integration, AI autopwn, Dijkstra pathfinding.

```bash
python3 segfault-ad.py --dc 10.10.10.10
```

---

## What is it

`segfault-ad` is a purpose-built Active Directory pentest toolkit built as a persistent REPL. Set your target once — every module inherits it. No re-typing credentials, no flag-hunting per tool.

Wraps **certipy**, **bloodyAD**, **impacket**, **netexec**, **bloodhound-python**, **smbclientng**, **powerview.py**, **abuseACL**, **kerbrute**, **autobloody** and 30+ other tools into a unified interface with consistent auth handling, automatic loot collection, and a live attack map.

Works with `spawn.py` — spawn a machine and segfault-ad auto-loads the IP and domain. Ctrl+C cleanly stops any module and returns to the REPL.

---

## What's new in v3.0.1

- **ESC8 full auto-relay** — starts ntlmrelayx in background, auto-coerces, captures cert, authenticates — zero manual steps
- **ESC14** — inject forged cert mapping into `altSecurityIdentities` → PKINIT impersonation
- **Bronze Bit (CVE-2020-17049)** — modify service ticket forwardable flag via `getST -force-forwardable`
- **SID History injection** — enum, inject (mimikatz/DSInternals), cross-domain forest privilege escalation
- **GenericWrite → Kerberoast** — set SPN on target, roast, auto-remove SPN for stealth
- **UnPAC `shadow-then-unpac` mode** — full chain: shadow creds → PKINIT auth → NT hash. Auto-sets target hash.
- **ShadowCoerce + MSEven6** added to `coercion` module alongside PetitPotam, PrinterBug, DFSCoerce
- **bh-view node→module** — click any node in the BloodHound viewer, get exploit suggestions, copy commands to clipboard
- **Color-coded attack map** — cyan=recon, orange=creds, green=shell (◉), red=exploitation (◆), gold=DA (★)
- **Clean Ctrl+C** — kills active subprocess, returns to REPL cleanly
- **auto-discovery** — entering a DC IP runs 7 probes: LDAP rootDSE, SMB banner, reverse DNS, clock skew, ports, DNS SRV, WinRM
- **module cache** — "already ran kerberoast this session, run again? [n]"
- **plugin system** — drop `.py` in `~/.segfault-ad/plugins/`
- **workspace tab completion** — `ws load <TAB>` shows actual workspace names

---

## Install

```bash
git clone https://github.com/YOUR_USERNAME/segfault-ad.git ~/segfault-ad
cd ~/segfault-ad
python3 segfault-ad.py
```

Inside the REPL:

```
→ install
```

Shows `[✓]/[✗]` for every tool, skips already-installed ones, asks before installing.

| Type | Tools |
|------|-------|
| **pip** | impacket, certipy-ad, bloodyad, bloodhound, ldeep, netexec, lsassy, autobloody, abuseACL, smbclientng, powerview, pywerview, coercer |
| **apt** | enum4linux, smbclient, ldap-utils, responder, faketime, nmap, kerbrute |
| **git** | mitm6, PetitPotam, Coercer, krbrelayx, PKINITtools, PassTheCert, gMSADumper, pre2k, Timeroast, noPac, sccmhunter, ADCSKiller, ACLight, Grouper2, abuseACL, pywsus |
| **win** | Rubeus, mimikatz, winPEAS, SharpHound, Snaffler, GodPotato, PowerView.ps1, chisel, ligolo-agent, RunasCs |

All data lives under `~/.segfault-ad/` — repo stays clean.

---

## Usage

```bash
# basic
python3 segfault-ad.py --dc 10.10.10.10

# with creds
python3 segfault-ad.py -d corp.local -u jsmith -p Password123 --dc 10.10.10.10

# flags
--quiet      skip banner animation
--yes        auto-confirm all prompts (scripting/CI)
--workspace  load workspace on startup
--run nmap   run a module immediately on startup
--timeout N  subprocess timeout in seconds (default: 300)
```

**Basic flow:**

```
→ set          # enter DC IP — auto-discovers domain, FQDN, OS, clock skew, open ports
→ nmap         # port scan with live progress (elapsed, %, open ports shown inline)
→ enum         # parallel enum + auto-suggest next steps based on results
→ asreproast   # AS-REP roast without creds
→ hashcrack    # Weakpass API pre-check → hashcat, auto pattern generation
→ shares       # spider all shares, guest fallback, auto-download interesting files
→ spray        # smart wordlist generation + password spray
→ adrecon      # BloodHound collection via rusthound-ce (Kerberos + LDAPS)
→ pathpwn      # weighted Dijkstra path to DA, auto-chains bloody/dcsync
→ bh-view      # BloodHound graph in browser — no Neo4j needed
→ aclscan      # instant ACL scan via abuseACL — no collection needed
→ exec         # evil-winrm shell — auto-logs shell info on open
→ certipy      # ADCS ESC1-16 — ESC8 fully auto-relays
→ unpac        # shadow-then-unpac: shadow creds → PKINIT → NT hash (fully chained)
→ dcsync       # secretsdump all domain hashes
→ flag         # grab flags — skull art on full pwn
→ report       # HTML report: MITRE ATT&CK, severity, executive summary, cleanup log
```

---

## Modules

### recon
`enum` `ldapenum` `bloodyenum` `kerbrute` `enum4linux` `rpcenum` `gpp` `adrecon` `dnsdump` `adidns` `pathfind` `shares` `mssql` `unauth` `bh-query` `autoenum` `ftp` `nmap` `ffuf` `pywerview` `nxcmodules` `healthcheck` `sccm` `trusts` `aclscan` `grouper2` `aclight` `snaffler` `powerview` `smbclientng`

### credentials
`asreproast` `kerberoast` `hashcrack` `spray` `gmsa` `laps` `lapstoolkit` `pkinit` `unpac` `pre2k` `azureadsync` `timeroast` `dpapi` `dploot` `lsassy` `keepass`

### lateral
`exec` `secretsdump` `dcsync` `pth` `ptt` `bloody` `passthecert` `smbclient` `smbclientng` `pkinit` `ldapshell` `jea` `godpotato` `runasc` `ligolo`

### exploitation
`certipy` `relay` `mitm6` `coerce` `coercion` `zerologon` `nopac` `rbcd` `shadowcred` `pywhisker` `spnjack` `badsuccessor` `syncjacking` `dnsadmins` `addcomputer` `groupscope` `aclpersist` `dcshadow` `trusts` `crossdomain` `backupabuse` `sliver` `pathpwn` `adcskiller` `pywsus` `bronzebit` `sidhistory`

---

## Attack Chains

| Chain | Steps |
|-------|-------|
| **AS-REP Roast** | `asreproast` → `hashcrack` → `exec` → `dcsync` → `flag` |
| **Kerberoast** | `kerberoast` → `hashcrack` → `pth` → `dcsync` |
| **BloodHound auto** | `adrecon` → `pathpwn` (auto-chains everything) → `flag` |
| **ADCS ESC1** | `certipy find` → `certipy esc1` → `certipy auth` → `dcsync` |
| **ADCS ESC8 relay** | `certipy esc8` (auto: relay+coerce+auth) → `dcsync` |
| **ADCS ESC14** | `certipy esc14` → inject `altSecurityIdentities` → `certipy auth` |
| **Shadow → UnPAC** | `unpac shadow-then-unpac` → NT hash auto-set → `exec` / `dcsync` |
| **GenericWrite abuse** | `bloody genericwrite-kerberoast` → `hashcrack` → `exec` |
| **Bronze Bit** | `bronzebit` → forwardable ticket → `exec` as admin |
| **SID History** | `sidhistory inject` → DA SID in token → domain access |
| **WriteDACL** | `bloody dcsync-rights` → `dcsync` → `flag` |
| **RBCD** | `addcomputer` → `rbcd` write → `exec` |
| **MSSQL UNC** | `mssql hash` → `hashcrack` → `exec` → `backupabuse` |
| **GPP creds** | `gpp` → `hashcrack` → `exec` → `dcsync` |
| **SCCM NAA** | `sccm enum` → `sccm naa` → lateral |

---

## Attack Map

```
  nmap       asreproast   hashcrack      exec        dcsync        flag
   ◉────────────◉────────────◉────────────◉────────────◈─────────────★
16 ports     3 hashes     cracked      shell       33 hashes    user+root

                                                            ★ DOMAIN ADMIN
```

| Color | Symbol | Meaning |
|-------|--------|---------|
| cyan  | `◉` | recon |
| orange | `◉` | credentials |
| green | `◉` | shell / owned |
| red  | `◆` | exploitation |
| red  | `◈` | dcsync |
| gold | `★` | flags / DA reached |

---

## BloodHound Viewer

```
→ adrecon    # collect BloodHound data via rusthound-ce
→ bh-view    # opens interactive graph in browser
```

- **No Neo4j required** — reads JSON directly from `loot/bloodhound/`
- **Force-directed layout** — nodes spread by type (domain center, groups middle, users outer)
- **Click any node** → see dangerous edges + "exploit this node" buttons
- **Copy to clipboard** — `↗ bloody → dcsync-rights` copies the command
- **Mark as owned** — updates DA path BFS live
- **Filter** by node type, edge type, path to DA
- Dangerous edges highlighted in red (`WriteDacl`, `GenericAll`, `GetChangesAll`, etc.)

---

## Hivemind Integration

```
→ hivemind             # show rack status (C2, redirector, tool server, logger)
→ hivemind upload x    # push payload to HTTPS tool server
→ sliver               # generate Sliver implant + auto-upload
→ relay                # lhost auto-defaults to Hivemind redirector IP
→ coercion             # listener auto-defaults to Hivemind redirector IP
```

Integrates with [Hivemind](https://github.com/YOUR_USERNAME/hivemind) — 4× Raspberry Pi distributed attack rack: Sliver C2, nginx redirector, tool server, Grafana/Loki logging.

---

## Plugin System

Drop a `.py` file in `~/.segfault-ad/plugins/`:

```python
class MyModule(Module):
    name='mymod'; description='custom module'; category='recon'
    def run(self, target):
        log(f'Hello from {target.domain}','info')

PLUGIN_MODULES = [MyModule]
```

```
→ plugins    # show loaded plugins
→ mymod      # run it
```

---

## Key Commands

| Command | Description |
|---------|-------------|
| `set` | configure target — shows current state, highlights changes |
| `ws` | workspace — `ws load <TAB>` tab-completes workspace names from disk |
| `tgt` | get Kerberos TGT — password, hash, AES key, or PFX |
| `exec` | shell — evil-winrm, wmiexec — auto-logs session info |
| `bloody` | bloodyAD wrapper — resetpwd, addtogroup, dcsync-rights, genericwrite-kerberoast |
| `certipy` | ADCS ESC1-16 — ESC8 fully auto-relays (ntlmrelayx + coerce + auth) |
| `unpac` | shadow-then-unpac: shadow creds → PKINIT → NT hash, fully chained |
| `pathpwn` | auto-execute BloodHound path — weighted Dijkstra, prefers WriteDACL/GenericAll paths |
| `bh-view` | BloodHound graph in browser — click nodes for exploit suggestions |
| `aclscan` | instant ACL vulnerability scan — no BloodHound collection needed |
| `lsassy` | remote LSASS dump — 6 methods (comsvcs, procdump, dumpert...) |
| `snaffler` | sensitive file discovery across shares |
| `bronzebit` | CVE-2020-17049 — forwardable service ticket via getST -force-forwardable |
| `sidhistory` | SID history enum / inject / cross-domain privilege |
| `coercion` | PetitPotam / PrinterBug / DFSCoerce / ShadowCoerce / MSEven6 / Coercer |
| `export` | export session (creds, chain, hashes) for teammate handoff |
| `import` | import a session from JSON |
| `targets` | run any module against a list of IPs in parallel |
| `report` | HTML report — MITRE ATT&CK coverage, severity, executive summary |
| `cleanup` | undo tracked changes — auto/manual/select modes, export log |
| `db` | `db creds` / `db search <q>` / `db stats` — SQLite credential store |
| `hint` | paste error or situation — AI suggests next steps |
| `autopwn` | AI-driven full attack chain |
| `install` | install all tools — pip, apt, git, Windows binaries |
| `plugins` | show loaded plugins from `~/.segfault-ad/plugins/` |
| `bh-view` | BloodHound graph viewer — served at localhost:8889 |
| `doctor` | tool status table — fast ✓/✗ check without installing |

---

## Directory Layout

```
~/.segfault-ad/
├── workspaces/
│   └── corp/
│       ├── loot/               # hashes, certs, BloodHound JSON, reports, bh-view.html
│       └── session_state.json  # attack map persistence
├── tools/                      # git-cloned tools
│   └── win/                    # Windows binaries (Rubeus, mimikatz, SharpHound...)
├── plugins/                    # custom modules (.py)
├── logs/                       # daily session logs (YYYYMMDD.log)
├── .key                        # Fernet encryption key for DB (chmod 600)
├── hivemind_state              # Hivemind rack node IPs
├── spawn_state                 # written by spawn.py on machine start
└── segfault.db                 # SQLite credential DB (WAL mode, encrypted values)
```

---

## Technical Notes

- **Single file** — intentional. No install step, just `python3 segfault-ad.py`
- **Credential encryption** — Fernet key at `~/.segfault-ad/.key`, transparent to all modules
- **BloodHound cache** — JSON parsed once per session, invalidated after `adrecon`
- **Module cache** — tracks which modules ran this session, prompts before re-running
- **Subprocess timeout** — 300s default, configurable via `--timeout`
- **Password masking** — `-p` and `-H` values masked in logs and terminal output
- **SQLite WAL mode** — faster concurrent writes, indexed on workspace+username+hash
- **Retry decorator** — `@retry(max_attempts=3)` available for network ops

---

## Legal

For authorized penetration testing only. Do not use against systems you do not own or have explicit written permission to test.

---

**segfault.solutions**

---

## Changelog

| Version | Changes |
|---------|---------|
| **v3.0.1** | Fix Dijkstra double import (pathpwn crash) · pathfind searches groups+computers · CanCompromiseMember graph edges · certipy/exec prefer hash over Kerberos · BH cache cleared on workspace switch · pywhisker pip/git syntax detection · auto-recon loop fix · ESC9 correct actor · shadowcred-bloody chains gettgtpkinit |
| **v3.0.0** | ESC8 auto-relay · ESC14 · Bronze Bit · SID History · GenericWrite→Kerberoast · UnPAC shadow chain · coercion++ · exec auto-recon · adrecon progress · color attack map |
| **v2.9.0** | Plugin system · file logging · BH cache · credential encryption · retry decorator · module cache · auto-discovery · clean Ctrl+C · VERSION constant |
| **v2.8.0** | bh-view node→module · workspace tab completion · nmap progress · auto-suggest after enum · better set UX · color-coded attack map |
| **v2.0.0** | pywhisker · pkinit · unpac · ldap-shell · crossdomain · hint/explain/autopwn AI · NoPAC |
