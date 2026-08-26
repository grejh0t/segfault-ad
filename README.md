```
░██████╗███████╗ ██████╗ ███████╗ █████╗ ██╗   ██╗██╗  ███████╗
██╔════╝██╔════╝██╔════╝ ██╔════╝██╔══██╗██║   ██║██║     ██╔══╝
╚█████╗ █████╗  ██║  ███╗█████╗  ███████║██║   ██║██║     ██║
 ╚═══██╗██╔══╝  ██║   ██║██╔══╝  ██╔══██║██║   ██║██║     ██║
██████╔╝███████╗╚██████╔╝██║     ██║  ██║╚██████╔╝███████╗██║
╚═════╝ ╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝
                                          // ACTIVE DIRECTORY
  certipy  //  bloodyAD  //  impacket  //  netexec  //  rubeus
```

> Python 3 Active Directory pentest REPL — 100+ modules, live attack map, BloodHound viewer, Hivemind C2 integration, AI autopwn

```bash
python3 segfault-ad.py -d domain.local --dc 10.10.10.10
```

---

## What is it

`segfault-ad` is a purpose-built Active Directory attack toolkit. Runs as a persistent REPL — set your target once, run any module against it. Wraps impacket, certipy, bloodyAD, bloodhound-python, netexec, kerbrute, smbclientng, powerview, abuseACL and a dozen other tools into a unified interface with consistent auth handling, automatic loot collection, and color-coded output.

**Core philosophy: one target context, all attacks.** Set domain, DC, user, and password once. Every module inherits it — no re-typing credentials, no flag-hunting per tool. Tab complete everywhere. Ctrl+C cleanly stops any module and returns to the REPL.

Works with **spawn.py** — spawn a box, segfault-ad auto-loads the target IP and domain. No `set` needed.

---

## What's new in v2.9

- **pathpwn** — Dijkstra-weighted BloodHound path execution, auto-chains modules to DA
- **bh-view** — custom BloodHound graph viewer, no Neo4j needed, click nodes to get exploit suggestions
- **auto-discovery** — entering a DC IP runs 7 probes: LDAP rootDSE, SMB banner, reverse DNS, clock skew, port check, DNS SRV, WinRM detection
- **Hivemind integration** — 4× Raspberry Pi C2 rack: Sliver, redirector, tool server, Grafana logging
- **plugin system** — drop a `.py` in `~/.segfault-ad/plugins/` to add custom modules
- **credential encryption** — Fernet encryption for DB at rest
- **module cache** — "already ran kerberoast this session, run again? [n]" — no duplicate work
- **recursive cred reuse** — after hashcrack/spray hit, auto-retries SMB, WinRM, shares, aclscan
- **improved report** — MITRE ATT&CK coverage, executive summary, severity rating, cleanup log
- **color-coded attack map** — cyan=recon, orange=creds, green=shell, red=exploitation, gold=DA/flags
- **clean interrupt** — Ctrl+C kills active subprocess and returns to REPL, no crash

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

`install` handles everything — shows a `[✓]/[✗]` status grid, skips already-installed tools.

| Type | Tools |
|------|-------|
| **pip** | impacket, certipy-ad, bloodyad, bloodhound, ldeep, netexec, lsassy, autobloody, abuseACL, smbclientng, powerview, pywsus |
| **apt** | enum4linux, smbclient, ldap-utils, responder, faketime, nmap, kerbrute |
| **git** | mitm6, PetitPotam, Coercer, krbrelayx, PKINITtools, PassTheCert, gMSADumper, pre2k, Timeroast, noPac, sccmhunter, ADCSKiller, ACLight, Grouper2 |
| **win bins** | Rubeus, mimikatz, winPEAS, SharpHound, Snaffler, GodPotato, PowerView, chisel, ligolo-agent, RunasCs |

All data lives under `~/.segfault-ad/` — repo stays clean.

---

## Usage

```bash
# spawn a box (auto-loads target)
spawn Forest
python3 segfault-ad.py   # IP + domain pre-loaded

# or configure manually
python3 segfault-ad.py -d corp.local -u jsmith -p Password123 --dc 192.168.1.10

# flags
python3 segfault-ad.py --quiet     # skip banner
python3 segfault-ad.py --yes       # auto-confirm all prompts
python3 segfault-ad.py --run nmap  # run a module on startup
python3 segfault-ad.py --workspace forest  # load workspace on startup
```

**Basic flow:**

```
→ set          # enter DC IP — auto-discovers domain, FQDN, OS, clock skew
→ nmap         # port scan with live progress bar (elapsed, %, open ports)
→ enum         # parallel enum — auto-flags passwords in descriptions
→ asreproast   # AS-REP roast, no creds needed
→ hashcrack    # Weakpass API pre-check + hashcat, auto pattern generation
→ shares       # smbclient spider, guest fallback, auto-download
→ spray        # password spray with generated wordlist
→ adrecon      # BloodHound collection via rusthound-ce
→ pathpwn      # auto-execute BloodHound path to DA
→ bh-view      # open BloodHound graph in browser (no Neo4j needed)
→ exec         # evil-winrm / wmiexec shell
→ certipy      # ADCS ESC1-8 + auth — full ADCS chain
→ dcsync       # secretsdump all domain hashes
→ flag         # grab flags — skull on full pwn
→ report       # HTML report with MITRE ATT&CK, severity, cleanup log
```

---

## Modules

### recon
`enum` `ldapenum` `bloodyenum` `kerbrute` `enum4linux` `rpcenum` `gpp` `adrecon` `dnsdump` `adidns` `pathfind` `shares` `mssql` `unauth` `bh-query` `autoenum` `ftp` `nmap` `ffuf` `pywerview` `nxcmodules` `healthcheck` `sccm` `trusts` `aclscan` `grouper2` `aclight` `snaffler` `powerview` `smbclientng`

### credentials
`asreproast` `kerberoast` `hashcrack` `spray` `gmsa` `laps` `lapstoolkit` `pkinit` `unpac` `pre2k` `azureadsync` `timeroast` `dpapi` `dploot` `lsassy` `keepass`

### lateral
`exec` `secretsdump` `dcsync` `pth` `ptt` `bloody` `passthecert` `smbclient` `smbclientng` `pkinit` `ldapshell` `jea` `godpotato` `zipslip` `runasc` `ligolo`

### exploitation
`certipy` `relay` `mitm6` `coerce` `coercion` `zerologon` `nopac` `rbcd` `shadowcred` `pywhisker` `spnjack` `badsuccessor` `syncjacking` `dnsadmins` `addcomputer` `groupscope` `aclpersist` `dcshadow` `trusts` `crossdomain` `backupabuse` `sliver` `pathpwn` `adcskiller` `pywsus`

---

## Attack Chains

| Pattern | Steps |
|---------|-------|
| **AS-REP Roast** | asreproast → hashcrack → exec → dcsync → flag |
| **Kerberoast** | kerberoast → hashcrack → pth → dcsync |
| **BloodHound auto-chain** | adrecon → pathpwn → (bloody/dcsync automated) → flag |
| **ADCS ESC1** | certipy find → certipy esc1 → certipy auth → dcsync |
| **ADCS ESC9** | certipy find → shadowcred → certipy auth → dcsync |
| **WriteDACL** | bloody dcsync-rights → dcsync → flag |
| **RBCD** | addcomputer → rbcd write → exec |
| **MSSQL UNC** | mssql hash → hashcrack → exec → backupabuse |
| **SeBackupPrivilege** | backupabuse → reg save → secretsdump → admin |
| **SCCM NAA** | sccm enum → sccm naa → lateral |
| **GPP creds** | gpp → hashcrack → exec → dcsync |

---

## Attack Map

```
  nmap       asreproast   hashcrack     exec        dcsync       flag
   ◉────────────◉────────────◉────────────◉────────────◈────────────★
16 ports    3 hashes     cracked     svc@DC      33 hashes   user+root
                                                           ★ DOMAIN ADMIN
```

Color legend:
- `◉` cyan — recon
- `◉` orange — credentials
- `◉` green — shell / owned
- `◆` red — exploitation
- `◈` red — dcsync
- `★` gold — flags / DA

Persists across restarts. `ws load` restores full chain.

---

## BloodHound Viewer

```
→ adrecon    # collect BloodHound data
→ bh-view    # opens browser with interactive graph
```

- No Neo4j required — reads JSON directly
- Click any node → see dangerous edges + exploit suggestions
- "Mark as owned" updates DA path BFS live
- "↗ bloody → dcsync-rights" buttons copy commands to clipboard
- Filter by node type, edge type, path to DA
- Force-directed layout with automatic node clustering

---

## Hivemind Integration

`segfault-ad` integrates with [Hivemind](https://github.com/YOUR_USERNAME/hivemind) — a 4× Raspberry Pi distributed attack rack:

```
→ hivemind             # show rack status (C2, redirector, tool server, logger)
→ hivemind upload x    # push payload to HTTPS tool server
→ sliver               # generate implant via Sliver C2 + auto-upload
→ relay                # lhost defaults to redirector IP automatically
```

Deploy with `deploy.py --all` — fully automated Sliver C2, nginx redirector, Grafana/Loki logging.

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
| `set` | configure target — auto-discovers domain/FQDN/OS/skew from DC IP |
| `ws` | workspace — `ws load <TAB>` tab-completes workspace names |
| `tgt` | get Kerberos TGT — password, hash, AES key, or PFX |
| `exec` | shell — evil-winrm, wmiexec; auto-logs shell info on open |
| `flag` | grab flags — paste manually or auto-grab via wmiexec |
| `pathpwn` | auto-execute BloodHound attack path, weighted Dijkstra |
| `bh-view` | BloodHound graph in browser, no Neo4j |
| `aclscan` | instant ACL vulnerability scan via abuseACL, no collection needed |
| `lsassy` | remote LSASS dump via comsvcs/procdump/dumpert |
| `snaffler` | find sensitive files across shares |
| `export` | export session (creds, chain, hashes) for teammate handoff |
| `import` | import a session from JSON |
| `targets` | run any module against a list of IPs in parallel |
| `report` | HTML report — MITRE ATT&CK, severity, executive summary |
| `cleanup` | undo tracked changes — auto/manual modes, export log |
| `db` | `db creds` / `db search <q>` / `db stats` |
| `hivemind` | Hivemind rack status and payload upload |
| `plugins` | show loaded plugins from `~/.segfault-ad/plugins/` |
| `install` | install all tools — pip, apt, git, Windows binaries |
| `hint` | paste error or situation — Claude AI suggests next steps |
| `autopwn` | AI-driven full attack chain |

---

## Directory Layout

```
~/.segfault-ad/
├── workspaces/
│   └── forest/
│       ├── loot/               # hashes, certs, files, reports, bh-view.html
│       └── session_state.json  # attack map persistence
├── tools/                      # git-cloned tools
│   └── win/                    # Windows binaries
├── plugins/                    # custom modules (.py files)
├── logs/                       # session logs (YYYYMMDD.log)
├── .key                        # Fernet encryption key (chmod 600)
├── hivemind_state              # Hivemind rack config
├── spawn_state                 # written by spawn.py
└── segfault.db                 # SQLite credential database (WAL mode)
```

---

## Tested Against

Validated against a wide range of AD lab environments covering ADCS ESC1-13, RBCD, shadow credentials, Azure AD Connect, Pre-Windows 2000 accounts, DPAPI, gMSA, delegation abuse, SCCM NAA, Kerberos relay, MSSQL UNC injection, and full BloodHound ACL chains.

Covers ADCS ESC1-13, RBCD, shadow credentials, Azure AD Connect, Pre-Windows 2000 accounts, DPAPI, gMSA, delegation abuse, SCCM NAA, Kerberos relay, MSSQL UNC injection, and full BloodHound ACL chains.

---

## Legal

For authorized penetration testing only. Do not use against systems you do not own or have explicit written permission to test.

---

## Author

**segfault.solutions**
