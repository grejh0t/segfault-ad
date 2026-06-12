# segfault-ad

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

> Python 3 Active Directory pentest REPL — 83 modules, live attack map, session persistence, HTML reports

```bash
python3 segfault-ad.py -d domain.local --dc 10.10.10.10
```

---

## What is it

`segfault-ad` is a purpose-built Active Directory attack toolkit. Runs as a persistent REPL — set your target once, run any module against it. Wraps impacket, certipy, bloodyAD, bloodhound-python, netexec, kerbrute, and a dozen other tools into a unified interface with consistent auth handling, automatic loot collection, and color-coded output.

**Core philosophy: one target context, all attacks.** Set domain, DC, user, and password once. Every module inherits it — no re-typing credentials, no flag-hunting per tool. Tab complete everywhere.

Works with **spawn.py** — spawn a box, segfault-ad auto-loads the target IP and domain. No `set` needed.

---

## Features

| | |
|--|--|
| **83 modules** | recon, credentials, lateral, exploitation, persistence, tooling |
| **auth** | password / NT hash / AES key / PFX cert / ccache — all modules support PTH + Kerberos |
| **attack map** | live ◉───◉ ASCII kill chain, persists across restarts, skull on pwn |
| **session persistence** | attack map auto-saved to workspace on every step, restored on load |
| **spawn.py integration** | auto-loads IP + domain from `~/.segfault-ad/spawn_state` on startup |
| **LDAP auto-discovery** | detects real domain via `ldapsearch namingContexts` on startup |
| **desc scanner** | auto-flags passwords hidden in AD user description fields |
| **shares spider** | smbclient recursive listing — actually finds files, auto-downloads interesting ones |
| **guest fallback** | shares module auto-retries with guest when null session is denied |
| **nmap auto-trigger** | after port scan, offers to auto-run suggested modules |
| **password patterns** | after hashcrack, auto-generates variants for next spray → `loot/patterns.txt` |
| **workspaces** | per-target loot dirs at `~/.segfault-ad/workspaces/`, save/load/list |
| **AI integration** | `hint` / `explain` / `autopwn` — Claude AI via Anthropic API |
| **SQLite DB** | credentials and findings persist at `~/.segfault-ad/segfault.db` |
| **HTML report** | `report` exports full session: chain, creds, flags, loot files |
| **background shells** | listeners and relay spawn in qterminal/xterm/tmux, UI stays alive |
| **skull calling card** | prints on `flag` when both user + root flags are captured |

---

## Install

```bash
git clone https://github.com/grejh0t/segfault-ad.git ~/segfault-ad
cd ~/segfault-ad
python3 segfault-ad.py
```

Then inside the REPL:

```
→ install
```

`install` handles everything — shows a `[✓]/[✗]` status grid, skips already-installed:

| Type | Tools |
|------|-------|
| **pip** | impacket, certipy-ad, bloodyad, evil-winrm, bloodhound, ldeep, adidnsdump, pywhisker, pywerview, coercer, netexec, ldap3 |
| **apt** | enum4linux, smbclient, ldap-utils, responder, faketime, golang-go |
| **git → `~/.segfault-ad/tools/`** | mitm6, PetitPotam, Coercer, DFSCoerce, krbrelayx, PKINITtools, PassTheCert, gMSADumper, pre2k, targetedKerberoast, AADInternals, Timeroast, noPac, pywhisker |
| **Windows bins → `~/.segfault-ad/tools/win/`** | Rubeus, mimikatz, winPEAS, SharpHound, GodPotato, PowerView, nc64, chisel, ligolo-agent, RunasCs |

All data lives under `~/.segfault-ad/` — repo stays clean with just `segfault-ad.py` and `README.md`.

---

## Usage

```bash
# spawn a box (auto-loads target)
spawn Forest
python3 segfault-ad.py   # IP + domain pre-loaded from spawn_state

# or configure manually
python3 segfault-ad.py -d domain.local -u username -p password --dc 10.10.10.10
```

**Basic flow:**
```
→ nmap        # port scan, progress spinner, auto-trigger suggestions
→ enum        # user/group enum, auto-flags passwords in descriptions
→ asreproast  # AS-REP roast — no creds needed
→ hashcrack   # auto-detect hash type, crack, generate password patterns
→ shares      # auto mode: smbclient spider, guest fallback, auto-download
→ spray       # password spray with pattern wordlist
→ exec        # evil-winrm / wmiexec shell
→ backupabuse # SeBackupPrivilege → reg save SAM/SYSTEM → admin hash
→ dcsync      # secretsdump all domain hashes
→ flag        # grab user.txt + root.txt → skull calling card
→ report      # export HTML report, auto-open in browser
```

---

## Modules

### recon — 22
`enum` `ldapenum` `bloodyenum` `kerbrute` `enum4linux` `rpcenum` `gpp` `adrecon` `dnsdump` `adidns` `pathfind` `shares` `mssql` `unauth` `bh-query` `autoenum` `ftp` `nmap` `ffuf` `pywerview` `nxcmodules` `healthcheck`

### credentials — 14
`asreproast` `kerberoast` `hashcrack` `spray` `gmsa` `laps` `lapstoolkit` `pkinit` `unpac` `pre2k` `azureadsync` `timeroast` `dpapi` `dploot`

### lateral movement — 13
`exec` `secretsdump` `dcsync` `pth` `ptt` `bloody` `passthecert` `smbclient` `pkinit` `ldapshell` `jea` `godpotato` `zipslip`

### exploitation — 24
`certipy` `relay` `mitm6` `coerce` `coercion` `zerologon` `nopac` `rbcd` `shadowcred` `pywhisker` `spnjack` `badsuccessor` `syncjacking` `dnsadmins` `addcomputer` `groupscope` `printnightmare` `aclpersist` `dcshadow` `trusts` `crossdomain` `runasc` `owneredit` `backupabuse`

### persistence — 2
`aclpersist` `dcshadow`

### tooling
`set` `pivot` `ws` `tgt` `exec` `flag` `loot` `report` `db` `hint` `explain` `autopwn` `b64get` `clockskew` `cleanup` `install` `healthcheck` `modules` `pathfind` `rubeus`

---

## Attack Chains

Common AD attack patterns the tool automates:

| Pattern | Steps |
|---------|-------|
| **AS-REP Roast** | asreproast → hashcrack → exec → dcsync → flag |
| **Kerberoast** | kerberoast → hashcrack → pth → dcsync |
| **GPP creds** | gpp → hashcrack → exec → dcsync |
| **ADCS ESC1** | certipy find → addcomputer → certipy req → pkinit → unpac → dcsync |
| **ADCS ESC9** | certipy find → shadowcred → certipy auth → dcsync (autopwn ~4 min) |
| **WriteDACL** | bloody dcsync-rights → dcsync → flag |
| **RBCD** | addcomputer → rbcd write → rbcd gst → exec |
| **Shadow creds** | shadowcred → pkinit → unpac → dcsync |
| **Azure AD Connect** | shares auto → azureadsync msol → dcsync |
| **SeBackupPrivilege** | backupabuse → reg save → secretsdump → admin hash |
| **ZipSlip + DLL hijack** | zipslip → shell → privilege escalation |
| **Pre2k + gMSA** | pre2k → gmsa → lateral → dcsync |

---

## Key Commands

| Command | Description |
|---------|-------------|
| `set` | configure target — domain, DC, user, creds; auto-discovers domain from IP via LDAP |
| `ws` | workspace management — save/load/list; attack map persists across restarts |
| `tgt` | get Kerberos TGT — password, hash, AES key, or PFX (PKINIT) |
| `exec` | shell — evil-winrm, wmiexec, smbexec; pre-checks hostname/whoami for attack map |
| `flag` | grab user.txt + root.txt via wmiexec — skull prints when both found |
| `loot` | view downloaded files with sizes, timestamps, new-file highlight |
| `report` | export HTML session report — chain, creds, hashes, flags, loot files |
| `db` | `db search <q>` / `db creds` / `db reuse <pw>` / `db stats` |
| `b64get` | exfil files via base64 — bypasses evil-winrm hidden file download bug |
| `clockskew` | detect and sync Kerberos clock offset, write `/etc/krb5.conf` |
| `cleanup` | undo tracked changes — writeowner, dacledit, addself, addtogroup, resetpwd |
| `autopwn` | AI-driven full attack chain via Claude Sonnet |
| `hint` | paste error or situation — Claude suggests next steps |
| `install` | install all dependencies — pip, apt, git tools, Windows binaries |

---

## Attack Map

```
  nmap        enum        shares       spray      hashcrack    dcsync      flag
    ◉────────────◉────────────◉────────────◉────────────◉────────────◉────────◉
16 ports    15 users    3 shares    1 hit      cracked     32 hashes  user+root
```

- Persists across restarts — `ws load` restores full chain
- Flag nodes show actual values (`user:ba2f0872…  root:85676f…`)
- Exec nodes show `user@hostname` via pre-shell wmiexec check
- Skull prints when both flags captured

---

## spawn.py Integration

```bash
spawn Cicada          # writes ~/.segfault-ad/spawn_state
python3 segfault-ad.py  # auto-loads IP + domain, no set needed
```

On startup segfault-ad reads `spawn_state` and runs `ldapsearch namingContexts` to auto-discover the real AD domain. `spawn --stop` clears the state.

---

## Directory Layout

```
~/.segfault-ad/
├── workspaces/
│   ├── forest/
│   │   ├── loot/          # hashes, certs, files, reports
│   │   ├── session_state.json   # attack map persistence
│   │   └── target.ini     # saved target config
│   └── cicada/
├── tools/                 # git-cloned tools
│   ├── krbrelayx/
│   ├── PKINITtools/
│   └── tools/win/         # Windows binaries
└── segfault.db            # SQLite credential database
```

---

## Tested Against

Built and validated against HTB and VulnLab machines covering a wide range of AD attack techniques including ADCS ESC1-13, RBCD, shadow credentials, Azure AD Connect, pre-Windows 2000 accounts, DPAPI, gMSA, delegation abuse, and more.

---

## Legal

For authorized penetration testing only. Do not use against systems you don't own or have explicit written permission to test.

---

## Author

**grejh0t** — [segfault.solutions](https://segfault.solutions) · [github.com/grejh0t](https://github.com/grejh0t)
