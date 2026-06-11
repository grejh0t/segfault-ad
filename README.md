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

> Python 3 Active Directory pentest REPL — 82 modules, live attack map, workspaces, HTML reports

```bash
python3 segfault-ad.py -d domain.local --dc 10.10.10.10
```

---

## What is it

`segfault-ad` is a purpose-built Active Directory attack toolkit. Runs as a persistent REPL — set your target once, run any module against it. Wraps impacket, certipy, bloodyAD, bloodhound-python, netexec, kerbrute, and a dozen other tools into a unified interface with consistent auth handling, automatic loot collection, and color-coded output.

**Core philosophy: one target context, all attacks.** Set domain, DC, user, and password once. Every module inherits it — no re-typing credentials, no flag-hunting per tool. Tab complete everywhere.

---

## Features

| | |
|--|--|
| **82 modules** | recon, credentials, lateral, exploitation, persistence, tooling |
| **auth** | password / NT hash / AES key / PFX cert / ccache — all modules support PTH + Kerberos, auto-formats per tool |
| **attack map** | live ◉───◉ ASCII kill chain timeline, grows as modules run, next-step hint ◎ |
| **workspaces** | per-target loot dirs at `~/.segfault_workspaces/`, save/load/list |
| **AI integration** | `hint` / `explain` / `autopwn` — Claude AI via Anthropic API; autopwn fully automates the chain |
| **SQLite DB** | credentials and findings persist across all sessions at `~/.segfault_workspaces/segfault.db` |
| **parallel exec** | ThreadPoolExecutor on enum (4 workers), pre2k spray (5 workers), enrich (4 workers) |
| **auto TGT refresh** | detects KRB_AP_ERR_TKT_EXPIRED, re-runs getTGT, retries automatically |
| **clock skew** | `clockskew` detects offset, auto-wraps Kerberos modules with `faketime`, writes `/etc/krb5.conf` |
| **cleanup** | session undo stack — reverses all DACL/group/user changes in one command |
| **HTML report** | `report` exports full session: chain, creds, flags, loot files, auto-opens in browser |
| **background shells** | listeners and relay spawn in qterminal/xterm/tmux, UI stays alive |
| **tool availability** | `[+]/[-]` per module at startup — shows which tools are in PATH before you run |

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

`install` handles everything — shows a `[✓]/[✗]` status grid, asks for confirmation, skips already-installed:

| Type | Tools |
|------|-------|
| **pip** | impacket, certipy-ad, bloodyad, evil-winrm, bloodhound, ldeep, adidnsdump, pywhisker, pywerview, coercer, netexec, ldap3 |
| **apt** | enum4linux, smbclient, ldap-utils, responder, faketime, golang-go |
| **git → `./tools/`** | mitm6, PetitPotam, Coercer, DFSCoerce, krbrelayx, PKINITtools, PassTheCert, gMSADumper, pre2k, targetedKerberoast, AADInternals, Timeroast, noPac, pywhisker |
| **Windows bins → `./tools/win/`** | Rubeus, mimikatz, winPEAS, SharpHound, GodPotato, PowerView, nc64, chisel, ligolo-agent, RunasCs |

---

## Usage

```bash
# start with target
python3 segfault-ad.py -d domain.local -u username -p password --dc 10.10.10.10

# or configure inside REPL
→ set
  domain > domain.local
  dc IP  > 10.10.10.10
  user   > username
  pass   > password
```

**Basic flow:**
```
→ nmap        # port scan, highlights interesting ports, suggests next modules
→ enum        # user/group/computer enum (null session or authed)
→ asreproast  # AS-REP roast — no creds needed
→ hashcrack   # auto-detect hash type, run hashcat + john fallback
→ exec        # evil-winrm / wmiexec / smbexec shell
→ dcsync      # secretsdump all domain hashes
→ flag        # grab user.txt + root.txt via wmiexec
→ report      # export HTML report, auto-open in browser
```

Tab completion works on all commands, module names, and prompted inputs.

---

## Modules

### recon — 22
`enum` `ldapenum` `bloodyenum` `kerbrute` `enum4linux` `rpcenum` `gpp` `adrecon` `dnsdump` `adidns` `pathfind` `shares` `mssql` `unauth` `bh-query` `autoenum` `ftp` `nmap` `ffuf` `pywerview` `nxcmodules` `healthcheck`

### credentials — 14
`asreproast` `kerberoast` `hashcrack` `spray` `gmsa` `laps` `lapstoolkit` `pkinit` `unpac` `pre2k` `azureadsync` `timeroast` `dpapi` `dploot`

### lateral movement — 13
`exec` `secretsdump` `dcsync` `pth` `ptt` `bloody` `passthecert` `smbclient` `pkinit` `ldapshell` `jea` `godpotato` `zipslip`

### exploitation — 23
`certipy` `relay` `mitm6` `coerce` `coercion` `zerologon` `nopac` `rbcd` `shadowcred` `pywhisker` `spnjack` `badsuccessor` `syncjacking` `dnsadmins` `addcomputer` `groupscope` `printnightmare` `aclpersist` `dcshadow` `trusts` `crossdomain` `runasc` `owneredit`

### persistence — 2
`aclpersist` `dcshadow`

### tooling
`set` `pivot` `ws` `tgt` `exec` `flag` `loot` `report` `db` `hint` `explain` `autopwn` `b64get` `clockskew` `cleanup` `install` `healthcheck` `modules` `pathfind` `rubeus`

---

## Attack Chains

| Chain | Steps |
|-------|-------|
| **Forest** | asreproast → hashcrack → bloody dcsync-rights → dcsync → flag |
| **Sauna** | webscrape → asreproast → hashcrack → exec → winlogon → pivot → dcsync |
| **Active** | gpp → hashcrack → kerberoast → hashcrack → exec → dcsync |
| **Certified** | certipy find → ESC9 → shadowcred → certipy auth → dcsync → flag (autopwn: ~4 min) |
| **Manager** | kerbrute → spray → mssql → ESC7 → certipy auth → dcsync |
| **Authority** | guest SMB → Ansible vault → crack → ESC1 → addcomputer → passthecert → dcsync |
| **Rebound** | AS-REP Kerberoast → RID brute → OU ACL → shadow creds → dcsync |
| **Vintage** | pre2k → gmsa → servicemanagers → asreproast → dpapi → rbcd → flag |
| **Querier** | mssql hash capture → NTLMv2 crack → xp_cmdshell → gpp → flag |
| **Monteverde** | shares auto → azure.xml → mhope → azureadsync msol → dcsync → flag |
| **Bruno** | asreproast → hashcrack → zipslip DLL hijack → shell → rbcd → flag |
| **PingPong** | ESC13 → Ligolo pivot → cross-domain gMSA → JEA → RBCD → GodPotato → DCSync → ESC4 → ESC1 (Insane) |

---

## Key Commands

| Command | Description |
|---------|-------------|
| `set` | configure target — domain, DC, user, creds; auto-discovers domain/DC from IP |
| `ws` | workspace management — save/load/list/delete, own loot dir per target |
| `tgt` | get Kerberos TGT — password, hash, AES key, or PFX (PKINIT) |
| `exec` | shell — evil-winrm, wmiexec, smbexec; pre-checks hostname/whoami for attack map |
| `flag` | grab user.txt + root.txt via wmiexec — shows actual values in attack map |
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
         asreproast          hashcrack              bloody               dcsync               exec
              ◉─────────────────◉─────────────────◉─────────────────◉─────────────────◉
     1 AS-REP hash(es)    password cracked   DCSync rights →       32 hashes        user@HOSTNAME
```

- Flag nodes show actual flag values (`user:3f8a1b2c…  root:d4e7f901…`)
- Exec nodes show `user@hostname` via pre-shell wmiexec check
- Next-step hint `◎` reads edge type and ESC number, suggests exact module

---

## Boxes Tested

**HTB:** Forest · Sauna · Active · Certified · Redelegate · Manager · Authority · Rebound · PingPong · Vintage · Querier · Monteverde

**VulnLab:** Bruno

---

## Legal

For authorized penetration testing only. Do not use against systems you don't own or have explicit written permission to test.

---

## Author

**grejh0t** — [segfault.solutions](https://segfault.solutions) · [github.com/grejh0t](https://github.com/grejh0t)
