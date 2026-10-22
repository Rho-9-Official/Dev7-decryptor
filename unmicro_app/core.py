#!/usr/bin/env python3
"""unmicro GUI core: everything except the widgets.

Rho-9 Systems. Styled after Aviary (Hyper dark).

The GUI never decrypts anything itself. It builds an unmicro command line from
the choices on its tabs, runs the already built binary (or unmicro.py), and
reads its output. Pure standard library, shared by the Tk UI (tk_ui.py)
and the PySide6 UI (qt_ui.py), on Windows, macOS and Linux.

The binary is driven the way a person at a terminal would drive it: its
standard input is a terminal (a pty on Linux/macOS, a hidden console on
Windows). That matters because unmicro 3.9.1 only handles Ctrl+C cleanly when
it is interactive: it opens its pause menu, and the GUI answers "2" (stop and
recover the files already matched). Run non-interactively it hangs inside the
worker pool instead. The same channel answers the "keep going into
N-character keys?" question with a dialog.
"""
import codecs
import json
import math
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

APP_NAME = 'unmicro'
from . import __version__ as APP_VERSION  # noqa: E402
WINDOWS = os.name == 'nt'
MACOS = sys.platform == 'darwin'
EXT = '.cryptedmicro'
LICENSE_ENV = 'UNMICRO_LICENSE'
CONTACT = 'recon@rho-9.com'

# Aviary's palette (webgui/index.html :root)
C = {
    'body': '#323a46', 'card': '#37424c', 'card2': '#3b4651', 'topbar': '#3c4752',
    'hover': '#424e5a', 'border': '#464f5b', 'input': '#2b323c',
    'text': '#aab8c5', 'muted': '#8391a2', 'faint': '#6c757d', 'bright': '#e3eaef',
    'navtext': '#919eab', 'navhover': '#bccee4',
    'primary': '#727cf5', 'primary_hover': '#6169e0', 'success': '#0acf97',
    'info': '#39afd1', 'warning': '#ffc35a', 'danger': '#fa5c7c', 'thumb': '#5a6570',
}

# What the recovered-key data of 3.9.1 gives; replaced by the real numbers
# once the licence is checked (--list-keys).
DEFAULT_ALPHABETS = {'observed': 61, 'turkish': 67, 'full': 77}
DEFAULT_MAX_LEN = 30
ENGLISH_LOWER = 'abcdefghijklmnopqrstuvwxyz'
TURKISH_LOWER = '\u00e7\u011f\u0131\u00f6\u015f\u00fc'
TURKISH_UPPER = '\u00c7\u011e\u0130\u00d6\u015e\u00dc'
DIGITS = '0123456789'
# Speed per CPU worker when nothing has been measured yet (pycryptodome back
# end, AES-ECB one block per guess; measured at 37-65k/s per core).
DEFAULT_RATE_PER_WORKER = 37500.0
DEFAULT_GPU_RATE = 3.0e8


# --------------------------------------------------------------------------
# Windows console helpers. These run in a separate copy of this program
# (started with --console-host / --console-send) so the GUI's own process
# never has to attach to, or free, a console.
# --------------------------------------------------------------------------

def _console_host(argv):
    """Run argv on this (hidden) console with stdin = the console, so the
    binary sees a terminal. stdout/stderr are the pipes the GUI gave us."""
    import signal
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    k32.GetConsoleWindow.restype = wintypes.HWND
    k32.GetStdHandle.restype = wintypes.HANDLE
    if not k32.GetConsoleWindow():
        # A GUI-subsystem copy (pythonw.exe, the windowed .exe) gets no
        # console from CREATE_NEW_CONSOLE: make a hidden one, and keep the
        # stdout/stderr pipes AllocConsole would otherwise replace.
        hout, herr = k32.GetStdHandle(-11), k32.GetStdHandle(-12)
        k32.AllocConsole()
        hwnd = k32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
        k32.SetStdHandle(-11, wintypes.HANDLE(hout))
        k32.SetStdHandle(-12, wintypes.HANDLE(herr))
    conin = open('CONIN$', 'rb')
    child = subprocess.Popen(argv, stdin=conin)
    # Ctrl+C sent to the console reaches us too; only the child may act on it.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    while True:
        try:
            return child.wait()
        except KeyboardInterrupt:
            continue


def _console_send(pid, action, text=''):
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    k32.FreeConsole()
    if not k32.AttachConsole(int(pid)):
        return 2
    try:
        if action == 'ctrlc':
            k32.SetConsoleCtrlHandler(None, True)
            k32.GenerateConsoleCtrlEvent(0, 0)  # CTRL_C_EVENT, whole console
            time.sleep(0.5)
            return 0
        if action == 'type':
            class KEY_EVENT_RECORD(ctypes.Structure):
                _fields_ = [('bKeyDown', wintypes.BOOL), ('wRepeatCount', wintypes.WORD),
                            ('wVirtualKeyCode', wintypes.WORD), ('wVirtualScanCode', wintypes.WORD),
                            ('UnicodeChar', wintypes.WCHAR), ('dwControlKeyState', wintypes.DWORD)]

            class INPUT_RECORD(ctypes.Structure):
                _fields_ = [('EventType', wintypes.WORD), ('_pad', wintypes.WORD), ('KeyEvent', KEY_EVENT_RECORD)]
            k32.CreateFileW.restype = wintypes.HANDLE
            h = k32.CreateFileW('CONIN$', 0xC0000000, 3, None, 3, 0, None)
            recs = []
            for ch in text:
                vk = 0x0D if ch in '\r\n' else 0
                c = '\r' if ch in '\r\n' else ch
                for down in (True, False):
                    recs.append(INPUT_RECORD(1, 0, KEY_EVENT_RECORD(down, 1, vk, 0, c, 0)))
            arr = (INPUT_RECORD * len(recs))(*recs)
            n = wintypes.DWORD()
            ok = k32.WriteConsoleInputW(h, arr, len(recs), ctypes.byref(n))
            k32.CloseHandle(h)
            return 0 if ok else 3
        return 4
    finally:
        k32.FreeConsole()


def _helper_cmd():
    """How to start a copy of this program in a helper mode. Every entry
    point (the built exe, python -m unmicro_app, either UI's main) hands the
    helper modes to helper_main() before anything else."""
    if getattr(sys, 'frozen', False):
        return [sys.executable]
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return [sys.executable, '-c', 'import sys; sys.path.insert(0, sys.argv.pop(1)); '
            'from unmicro_app.core import helper_main; sys.exit(helper_main())', pkg_parent]


# --------------------------------------------------------------------------
# Pure helpers (tested in tests/test_core.py)
# --------------------------------------------------------------------------

def fmt_count(n):
    return '{:,}'.format(int(n))


def fmt_duration(secs):
    if secs is None:
        return 'unknown'
    if secs != secs or secs == float('inf'):
        return 'forever'
    secs = float(secs)
    if secs < 1:
        return 'under a second'
    if secs < 90:
        return '%d seconds' % round(secs)
    if secs < 5400:
        return '%.0f minutes' % (secs / 60)
    if secs < 172800:
        return '%.1f hours' % (secs / 3600)
    days = secs / 86400
    if days < 730:
        return '%.0f days' % days
    years = days / 365.25
    if years < 1e6:
        return '{:,.0f} years'.format(years)
    return '10^%d years' % int(math.floor(math.log10(years)))


def fmt_bytes(n):
    n = float(n)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return ('%d %s' % (n, unit)) if unit == 'B' else ('%.1f %s' % (n, unit))
        n /= 1024.0


def alphabet_sizes(keys):
    """Mirror unmicro's dumb_alphabet() for each charset, from the recovered
    keys printed by --list-keys."""
    observed = []
    for k in keys:
        for ch in k:
            if ch not in observed:
                observed.append(ch)

    def ext(base, extra):
        out = list(base)
        for ch in extra:
            if ch not in out:
                out.append(ch)
        return out
    turk = ext(observed, ENGLISH_LOWER + TURKISH_LOWER + DIGITS)
    full = ext(observed, ENGLISH_LOWER + TURKISH_LOWER + DIGITS + ENGLISH_LOWER.upper() + TURKISH_UPPER)
    return {'observed': len(observed) or 36, 'turkish': len(turk), 'full': len(full)}


def brute_schedule(alpha, max_len, rate, min_len=1):
    """[(length, candidates, seconds, cumulative seconds)] for the
    structural brute force."""
    rows, cum = [], 0.0
    rate = max(rate, 1.0)
    for L in range(min_len, max_len + 1):
        size = alpha ** L
        secs = size / rate
        cum += secs
        rows.append((L, size, secs, cum))
    return rows


def reachable_length(schedule, budget_secs):
    """Longest length whose whole sweep (all shorter lengths included)
    finishes within budget_secs; 0 if none."""
    best = 0
    for L, _, _, cum in schedule:
        if cum <= budget_secs:
            best = L
    return best


def estimate_rate(cfg, workers, gpu):
    m = cfg.get('measured') or {}
    if gpu:
        return m.get('gpu_rate') or DEFAULT_GPU_RATE
    per = m.get('per_worker') or DEFAULT_RATE_PER_WORKER
    return per * max(1, workers)


def time_to_failure(search_secs, res, limits, rate_window=None):
    """Combine the projections into one estimate.
    res: latest resource sample; limits: safety limits. Returns
    (seconds, reason, details[list of (label, seconds or None, note)])."""
    details = [('Search space runs out', search_secs, 'every length up to the longest recovered key')]
    if res:
        if res.get('on_battery') and res.get('battery') is not None:
            left = res.get('battery_secs')
            pct = res['battery']
            floor = limits.get('min_battery', 10)
            if left:
                # The OS figure is for the current load; a full sweep pins
                # every core, so assume about half of it.
                usable = left * 0.5 * max(0.0, (pct - floor)) / max(pct, 1)
                details.append(('Battery reaches %d%%' % floor, usable, 'OS estimate halved for full load'))
            else:
                details.append(('Battery reaches %d%%' % floor, None, 'on battery; drain rate measured once running'))
        slopes = (rate_window or {})
        for key, label, lim, sign, unit in (
                ('temp', 'CPU reaches %d\u00b0C', limits.get('max_temp', 95), 1, ''),
                ('ram', 'Memory reaches %d%%', limits.get('max_ram', 92), 1, ''),
                ('disk_free_gb', 'Free disk falls to %d GB', limits.get('min_disk_gb', 2), -1, '')):
            cur = res.get(key)
            slope = slopes.get(key)
            if cur is None or not slope:
                continue
            gap = (lim - cur) if sign > 0 else (cur - lim)
            moving = slope * sign
            if gap <= 0:
                details.append((label % lim, 0, 'limit already reached'))
            elif moving > 1e-9:
                details.append((label % lim, gap / moving, 'at the current trend'))
    finite = [(s, lbl) for lbl, s, _ in details if s is not None]
    if not finite:
        return (None, 'unknown', details)
    secs, why = min(finite)
    return (secs, why, details)


def limits_tripped(s, lims):
    """{metric: description} for every safety limit the sample breaks."""
    out = {}
    if s.get('temp') is not None and s['temp'] >= lims['max_temp']:
        out['temp'] = 'CPU at %.0f\u00b0C' % s['temp']
    if s.get('ram') is not None and s['ram'] >= lims['max_ram']:
        out['ram'] = 'memory at %.0f%%' % s['ram']
    if s.get('disk_free_gb') is not None and s['disk_free_gb'] <= lims['min_disk_gb']:
        out['disk'] = '%.1f GB free disk' % s['disk_free_gb']
    if s.get('on_battery') and s.get('battery') is not None and s['battery'] <= lims['min_battery']:
        out['battery'] = 'battery at %.0f%%' % s['battery']
    return out


def build_args(cfg, file_list_path=None):
    """The unmicro argument list for the settings in cfg (no licence: that
    travels in the environment, never on the command line)."""
    a = []
    src = cfg.get('source', 'folders')
    if src == 'auto':
        a.append('--auto')
        for r in cfg.get('scan_roots', []):
            a += ['--scan-root', r]
        if cfg.get('no_prune'):
            a.append('--no-prune')
        if cfg.get('max_files'):
            a += ['--max-files', str(int(cfg['max_files']))]
    elif src == 'list':
        a += ['--file-list', cfg.get('file_list', '')]
    else:
        paths = cfg.get('paths', [])
        if file_list_path:
            a += ['--file-list', file_list_path]
        elif paths:
            a += ['--in', paths[0]]
            if os.path.isdir(paths[0]) and cfg.get('recursive', True):
                a.append('--recursive')
    for k in cfg.get('keys', []):
        a += ['--key', k]
    if cfg.get('wordlist'):
        a += ['--wordlist', cfg['wordlist']]
    for s in cfg.get('scavenge', []):
        a += ['--scavenge', s]
    level = cfg.get('level', 'quick')
    if level in ('standard', 'deep'):
        a.append('--brute')
    if level == 'deep':
        a.append('--deep')
    endless = False
    if cfg.get('dumb'):
        a.append('--dumb-brute')
        if cfg.get('charset', 'turkish') != 'turkish':
            a += ['--charset', cfg['charset']]
        endless = cfg.get('dumb_mode') == 'endless'
    if cfg.get('dumb') and cfg.get('dumb_mode') in ('keepgoing', 'endless'):
        a.append('--yes')
    workers = int(cfg.get('workers') or 0)
    if workers > 0:
        a += ['--workers', str(workers)]
    if cfg.get('gpu'):
        a.append('--gpu')
    if int(cfg.get('max_passes', 8)) != 8:
        a += ['--max-passes', str(int(cfg['max_passes']))]
    if cfg.get('max_candidates') and not endless:
        a += ['--max-candidates', str(int(cfg['max_candidates']))]
    if cfg.get('checkpoint_on', True) and cfg.get('checkpoint'):
        a += ['--checkpoint', cfg['checkpoint']]
    if int(cfg.get('seen_cap', 1000000)) != 1000000:
        a += ['--seen-cap', str(int(cfg['seen_cap']))]
    if cfg.get('identify'):
        a.append('--identify')
    elif cfg.get('out'):
        a += ['--out', cfg['out']]
    if cfg.get('flat'):
        a.append('--flat')
    if cfg.get('overwrite'):
        a.append('--overwrite')
    verify = cfg.get('verify', 'normal')
    if verify == 'strict':
        a.append('--strict')
    elif verify == 'keep':
        a.append('--keep-unverified')
    if not cfg.get('fix_ext', True):
        a.append('--no-fix-ext')
    if cfg.get('force') and len(cfg.get('keys', [])) == 1:
        a.append('--force')
    if cfg.get('pure_python'):
        a.append('--pure-python')
    a.append('--verbose')
    return a


def problems(cfg):
    """Things that stop a run from starting, in plain words."""
    out = []
    src = cfg.get('source', 'folders')
    if src == 'folders' and not cfg.get('paths'):
        out.append('Choose the encrypted files or folders on the Files tab.')
    if src == 'list' and not cfg.get('file_list'):
        out.append('Choose the file list on the Files tab.')
    if not cfg.get('identify') and not cfg.get('out'):
        out.append('Choose where recovered files are saved on the Output tab.')
    if not cfg.get('license'):
        out.append('Enter the licence key on the Keys tab.')
    return out


def quote_arg(s):
    if WINDOWS:
        return subprocess.list2cmdline([s])
    import shlex
    return shlex.quote(s)


def find_encrypted(paths, recursive=True, cancel=None, limit=200000):
    """Yield (path, size) for .cryptedmicro files under paths."""
    seen = 0
    for p in paths:
        if os.path.isfile(p):
            try:
                yield (p, os.path.getsize(p))
            except OSError:
                pass
            continue
        for root, dirs, files in os.walk(p):
            if cancel is not None and cancel.is_set():
                return
            if not recursive:
                dirs[:] = []
            for f in files:
                if f.lower().endswith(EXT):
                    fp = os.path.join(root, f)
                    try:
                        yield (fp, os.path.getsize(fp))
                    except OSError:
                        continue
                    seen += 1
                    if seen >= limit:
                        return


def guess_format(size):
    if size == 0:
        return 'empty (damaged)'
    if size % 16 == 0:
        return 'older (AES-ECB)' if size >= 16 else 'too short (damaged)'
    if size >= 44:
        return 'newer (AES-GCM)'
    return 'too short (damaged)'


# Output parsing ------------------------------------------------------------

RE_STEP = re.compile(r'^STEP (\d+) OF (\d+): (.+)$')
RE_PROGRESS = re.compile(r'^\s*(GCM )?(.+?)\s+(\d+) tried\s+([\d.]+)/s\s*$')
RE_PLAIN_PROGRESS = re.compile(r'^Still searching.*?: ([\d,]+) keys? tried, ([\d:]+) elapsed \| (.+?)(\s{2}slow.*)?$')
RE_TIER = re.compile(r'^\s*(GCM )?tier (.+?)\s+(\d+) candidates\s+(HIT|no hit)')
RE_FOUND = re.compile(r"^FOUND A KEY: '(.*)'\. It opens (\d+) of (\d+) files")
RE_RESULT = re.compile(r'^RESULT: (.+)$')
RE_COUNT = re.compile(r'^\s+(Recovered and checked|Damaged \(not a key issue\)|Still locked \(need a key\)|Had a problem)[ .]*\s(\d[\d,]*)')
RE_CORES = re.compile(r'^Using (\d+) core')
RE_GATE = re.compile(r'Keep going into (\d+)-character keys\? \[y/N\]\s*$')
RE_GATE_TEXT = re.compile(r"^machine's speed that is roughly (.+?), and each step")
RE_BRUTE_LEN = re.compile(r'structural brute len=(\d+)')
PROMPT_PAUSE = 'Choose [1]: '
PROMPT_CLOSE = 'Press Enter to close this window.'
PROMPT_LICENSE = 'License key: '


def parse_line(line):
    """Classify one complete output line. Returns (kind, data)."""
    s = line.rstrip('\n')
    m = RE_PROGRESS.match(s)
    if m:
        return ('progress', {'gcm': bool(m.group(1)), 'name': m.group(2).strip(), 'tried': int(m.group(3)), 'rate': float(m.group(4))})
    m = RE_PLAIN_PROGRESS.match(s)
    if m:
        return ('plainprogress', {'tried': int(m.group(1).replace(',', '')), 'elapsed': m.group(2), 'name': m.group(3)})
    m = RE_STEP.match(s)
    if m:
        return ('step', {'n': int(m.group(1)), 'of': int(m.group(2)), 'title': m.group(3).title()})
    m = RE_TIER.match(s)
    if m:
        return ('tier', {'gcm': bool(m.group(1)), 'name': m.group(2).strip(), 'count': int(m.group(3)), 'hit': m.group(4) == 'HIT'})
    m = RE_FOUND.match(s)
    if m:
        return ('found', {'key': m.group(1), 'opens': int(m.group(2)), 'of': int(m.group(3))})
    m = RE_RESULT.match(s)
    if m:
        return ('result', {'verdict': m.group(1)})
    m = RE_COUNT.match(s)
    if m:
        return ('count', {'what': m.group(1), 'n': int(m.group(2).replace(',', ''))})
    m = RE_CORES.match(s)
    if m:
        return ('cores', {'n': int(m.group(1))})
    m = RE_GATE_TEXT.match(s)
    if m:
        return ('gatetime', {'when': m.group(1)})
    return ('text', {'text': s})


def classify_tag(text):
    t = text.strip()
    if not t:
        return None
    if t.startswith('FOUND') or t.startswith('OK ') or 'HIT' in t.split()[-1:] or t.startswith('Recovered:') or t.startswith('RESULT: ALL'):
        return 'ok'
    if t.startswith('RESULT:'):
        return 'warn'
    if t.startswith('STEP ') or set(t) == {'='}:
        return 'stage'
    if t.startswith('FAIL') or 'error' in t.lower() or t.startswith('Traceback'):
        return 'err'
    if t.startswith('PROVEN') or t.startswith('PAUSED') or t.startswith('Stopped') or 'still locked' in t.lower():
        return 'warn'
    if t.startswith('tier ') or t.startswith('GCM tier'):
        return 'info'
    return None


def split_lines(buf):
    """Split buffered output into complete lines. Returns
    ([(line, separator)], unfinished tail)."""
    parts = re.split(r'(\r\n|\n|\r)', buf)
    return [(parts[i], parts[i + 1]) for i in range(0, len(parts) - 1, 2)], parts[-1]


def classify_prompt(tail):
    """What the unfinished last output line is asking, if anything:
    ('pause', None), ('gate', length), ('close', None), ('license', None)
    or None."""
    if not tail:
        return None
    if tail.endswith(PROMPT_PAUSE):
        return ('pause', None)
    m = RE_GATE.search(tail)
    if m:
        return ('gate', int(m.group(1)))
    if tail.rstrip().endswith(PROMPT_CLOSE):
        return ('close', None)
    if tail.endswith(PROMPT_LICENSE):
        return ('license', None)
    return None


# Shared by both UIs: everything they show that is computed, not drawn -----

# Aviary's bird (24x24 SVG path; the eye is at 16,8)
BIRD = 'M3 14c2-1 4-3 6-6 1 3 3 4 6 4 2 0 4-1 5-3 0 4-2 7-5 8l3 4-4-1-2 3-1-3-4 1 2-3c-4 0-7-2-9-5z'
BIRD_EYE = (16, 8, 1.2)


def bird_polygon(scale=1.0, ox=0.0, oy=0.0):
    """The bird as a polygon (curves flattened), scaled and offset."""
    toks = re.findall(r'[MmCcLlZz]|-?\d*\.?\d+', BIRD)
    pts, i, cmd = [], 0, None
    x = y = 0.0
    while i < len(toks):
        t = toks[i]
        if t in 'MmCcLlZz':
            cmd = t
            i += 1
            continue
        if cmd == 'M':
            x, y = float(toks[i]), float(toks[i + 1])
            i += 2
            pts.append((x, y))
            cmd = 'l'
        elif cmd in 'lL':
            dx, dy = float(toks[i]), float(toks[i + 1])
            i += 2
            x, y = (x + dx, y + dy) if cmd == 'l' else (dx, dy)
            pts.append((x, y))
        elif cmd in 'cC':
            v = [float(toks[i + k]) for k in range(6)]
            i += 6
            if cmd == 'c':
                v = [x + v[0], y + v[1], x + v[2], y + v[3], x + v[4], y + v[5]]
            for s in range(1, 9):
                tt = s / 8.0
                mt = 1 - tt
                px = mt ** 3 * x + 3 * mt * mt * tt * v[0] + 3 * mt * tt * tt * v[2] + tt ** 3 * v[4]
                py = mt ** 3 * y + 3 * mt * mt * tt * v[1] + 3 * mt * tt * tt * v[3] + tt ** 3 * v[5]
                pts.append((px, py))
            x, y = v[4], v[5]
        else:
            i += 1
    return [(ox + px * scale, oy + py * scale) for px, py in pts]


def alpha_and_max(cfg, charset):
    """(alphabet size, longest key length) for the structural brute force."""
    kd = cfg.get('keydata') or {}
    sizes = kd.get('alphabets') or DEFAULT_ALPHABETS
    return sizes.get(charset, DEFAULT_ALPHABETS['turkish']), kd.get('max_len') or DEFAULT_MAX_LEN


def finish_snapshot(s, cpu_n):
    """Fill in what the tabs leave implicit: the default checkpoint file, and
    0 workers (= unmicro's default, every core) when all cores are chosen."""
    if s.get('checkpoint_on') and not s.get('checkpoint') and s.get('out'):
        s['checkpoint'] = os.path.join(s['out'], 'unmicro-progress.checkpoint')
    if (s.get('workers') or 0) >= cpu_n:
        s['workers'] = 0
    return s


def keydata_from_list(out, version=None):
    """keydata from --list-keys output (one recovered key per line)."""
    keys = [ln for ln in out.splitlines() if ln.strip()]
    if not keys:
        return None
    return {'keys': keys, 'alphabets': alphabet_sizes(keys), 'max_len': max(len(k) for k in keys), 'version': version}


def summary(s, cpu_n):
    """The Run tab's review: [(heading, text)]."""
    out = []
    if s['source'] == 'auto':
        out.append(('Files', 'Search the whole computer' + (' plus %d extra place(s)' % len(s['scan_roots']) if s['scan_roots'] else '') + (', system folders included' if s['no_prune'] else '')))
    elif s['source'] == 'list':
        out.append(('Files', 'The files listed in %s' % (s['file_list'] or '(not chosen)')))
    else:
        n = len(s['paths'])
        out.append(('Files', ('%d place(s): %s' % (n, '; '.join(s['paths'][:3]) + (' \u2026' if n > 3 else ''))) if n else '(nothing chosen)'))
    k = []
    if s['keys']:
        k.append('%d key(s) you typed' % len(s['keys']))
    if s['wordlist']:
        k.append('a wordlist')
    if s['scavenge']:
        k.append('%d dump(s)' % len(s['scavenge']))
    k.append('the recovered operator keys')
    out.append(('Keys', ', '.join(k)))
    lv = {'quick': 'Quick', 'standard': 'Standard (likely variations)', 'deep': 'Deep (widened variations)'}[s['level']]
    if s['dumb']:
        mode = {'ask': 'asking before long lengths', 'keepgoing': 'every length without asking', 'endless': 'UNTIL THE MACHINE CANNOT TAKE IT'}[s['dumb_mode']]
        lv += '; then every possible key, %s alphabet, %s' % (s['charset'], mode)
    out.append(('Search', lv))
    out.append(('Machine', '%s%s%s' % ('all %d cores' % cpu_n if not s['workers'] else '%d of %d cores' % (s['workers'], cpu_n),
                                       ', GPU' if s['gpu'] else '', (', stop after %s guesses' % s['max_candidates']) if s['max_candidates'] and not (s['dumb'] and s['dumb_mode'] == 'endless') else '')))
    if s['identify']:
        out.append(('Output', 'Key check only: nothing is written'))
    else:
        out.append(('Output', '%s%s%s' % (s['out'] or '(not chosen)', ', one folder' if s['flat'] else '', {'normal': '', 'strict': ', strict checking', 'keep': ', keep unverified files'}[s['verify']])))
    return out


def command_preview(engine, s):
    """The copyable command for the Run tab. The licence is shown as an
    environment variable with its value elided, never on the command line."""
    args = build_args(s, '<file list>' if s['source'] == 'folders' and len(s['paths']) > 1 else None)
    env_hint = ('set %s=\u2026 && ' % LICENSE_ENV) if WINDOWS else ('%s=\u2026 ' % LICENSE_ENV)
    return env_hint + ' '.join(quote_arg(x) for x in engine.argv(args))


def schedule_tone(cum_secs):
    """'ok' under an hour, 'warn' under a month, else 'bad'."""
    return 'ok' if cum_secs < 3600 else ('warn' if cum_secs < 86400 * 30 else 'bad')


def estimate_table(cfg, s, cpu_n):
    """The Search tab's brute-force estimate: (heading, rows, footer).
    rows: [(length, keys, this length, total so far, tone)]."""
    alpha, maxlen = alpha_and_max(cfg, s['charset'])
    workers = s['workers'] or cpu_n
    rate = estimate_rate(cfg, workers, s['gpu'])
    measured = bool((cfg.get('measured') or {}).get('per_worker'))
    head = '%d characters, lengths 1 to %d, about %s keys/s on %s %s' % (
        alpha, maxlen, fmt_count(rate), ('the GPU' if s['gpu'] else '%d core(s)' % workers),
        '(measured)' if measured else '(rough guess until a run measures it)')
    sched = brute_schedule(alpha, maxlen, rate)
    shown = [r for r in sched if r[0] <= 4] + [r for r in sched if r[0] > 4][:6]
    rows = [(str(L), '{:.3g}'.format(size) if size > 1e12 else fmt_count(size), fmt_duration(secs), fmt_duration(cum), schedule_tone(cum))
            for L, size, secs, cum in shown]
    foot = 'In a day this machine finishes keys up to %d characters; in a year, up to %d. The longest recovered key has %d.' % (
        reachable_length(sched, 86400), reachable_length(sched, 365.25 * 86400), maxlen)
    return head, rows, foot


def length_progress(name, tried, tier_start, rate, alpha, maxlen):
    """Progress through the current structural brute-force length, or None
    when the method running is not the structural brute force.
    Returns {'method', 'frac', 'detail'}."""
    m = RE_BRUTE_LEN.search(name or '')
    if not m:
        return None
    L = int(m.group(1))
    size = alpha ** L
    done = max(0, tried - tier_start)
    frac = min(1.0, done / float(size))
    left = (size - done) / rate if rate > 0 else None
    return {'method': 'Every possible key of %d characters (of up to %d)' % (L, maxlen), 'frac': frac,
            'detail': '%s of %s keys of this length (%.2f%%), about %s left for this length' % (
                fmt_count(done), '{:.3g}'.format(size) if size > 1e12 else fmt_count(size), frac * 100, fmt_duration(left))}


def live_rate(rates, cfg, workers, gpu):
    """The brute-force speed now: the last 10 readings, else the estimate."""
    recent = rates[-10:]
    return (sum(recent) / len(recent)) if recent else estimate_rate(cfg, workers, gpu)


def search_left_secs(alpha, maxlen, rate, tier, tried, tier_start):
    """Seconds until the structural brute force has tried every length."""
    sched = brute_schedule(alpha, maxlen, rate)
    m = RE_BRUTE_LEN.search(tier or '')
    if not m:
        return sched[-1][3]
    L = int(m.group(1))
    done = max(0, tried - tier_start)
    left = sum(r[1] for r in sched if r[0] > L) + max(0, alpha ** L - done)
    return left / max(rate, 1)


def phrase(label):
    """A label as part of a sentence: 'Search space runs out' -> 'search
    space runs out', but 'CPU reaches 95\u00b0C' keeps its capitals."""
    return label[:1].lower() + label[1:] if label[1:2].islower() else label


def ttf_text(secs, why, details):
    """(headline, detail line) for a live time to failure."""
    when = 'now' if secs is not None and secs < 1 else 'about %s' % fmt_duration(secs)
    return ('Time to failure: %s (%s)' % (when, phrase(why)),
            '  \u00b7  '.join('%s: %s' % (lbl, fmt_duration(v) if v is not None else 'measuring') for lbl, v, _ in details))


def endless_estimate(cfg, s, cpu_n, res, lims):
    """Everything the endless-mode warning shows."""
    alpha, maxlen = alpha_and_max(cfg, s['charset'])
    workers = s['workers'] or cpu_n
    rate = estimate_rate(cfg, workers, s['gpu'])
    sched = brute_schedule(alpha, maxlen, rate)
    secs, why, details = time_to_failure(sched[-1][3], res, lims, {})
    return {'alpha': alpha, 'maxlen': maxlen, 'workers': workers, 'rate': rate, 'secs': secs, 'why': why, 'details': details,
            'measured': bool((cfg.get('measured') or {}).get('per_worker')),
            'day': reachable_length(sched, 86400), 'week': reachable_length(sched, 7 * 86400),
            'year': reachable_length(sched, 365.25 * 86400), 'temp': (res or {}).get('temp')}


METERS = (('cpu', 'CPU'), ('ram', 'Memory'), ('temp', 'CPU temperature'), ('disk', 'Free disk (output)'), ('battery', 'Battery'))


def meter_readings(s, lims):
    """{meter: (text, percent of the bar, tone 'bad'|'warn'|None)} for the
    readings this sample has."""
    out = {}
    if s.get('cpu') is not None:
        out['cpu'] = ('%.0f%%' % s['cpu'], s['cpu'], None)
    if s.get('ram') is not None:
        r = s['ram']
        out['ram'] = ('%.0f%%' % r, r, 'bad' if r >= lims['max_ram'] else ('warn' if r >= lims['max_ram'] - 8 else None))
    if s.get('temp') is not None:
        t = s['temp']
        out['temp'] = ('%.0f°C' % t, t / lims['max_temp'] * 100,
                       'bad' if t >= lims['max_temp'] else ('warn' if t >= lims['max_temp'] - 10 else None))
    if s.get('disk_free_gb') is not None:
        d, lo = s['disk_free_gb'], lims['min_disk_gb']
        out['disk'] = ('%.1f GB' % d, min(100, d / max(lo * 10, 1) * 100), 'bad' if d <= lo else ('warn' if d <= lo * 2 else None))
    if s.get('battery') is not None:
        b, lo, on = s['battery'], lims['min_battery'], s.get('on_battery')
        out['battery'] = ('%.0f%%%s' % (b, ' on battery' if on else ' plugged in'), b,
                          'bad' if on and b <= lo else ('warn' if on and b <= lo + 10 else None))
    for k, (text, frac, tone) in list(out.items()):
        out[k] = (text, max(0, min(100, frac)), tone)
    return out


LIMIT_READINGS = 6  # readings in a row (5 s apart) before a safety limit trips


def count_limit_hits(hits, tripped, need=LIMIT_READINGS):
    """Update the consecutive-reading counts in hits (in place) from this
    reading's tripped limits; True once any limit has held for need readings.
    A reading back under a limit resets its count."""
    for k in tripped:
        hits[k] = hits.get(k, 0) + 1
    for k in list(hits):
        if k not in tripped:
            hits.pop(k)
    return any(v >= need for v in hits.values())


def record_speed(cfg, rates, workers, gpu):
    """Remember the median brute-force speed for future estimates."""
    if not rates:
        return
    med = sorted(rates)[len(rates) // 2]
    if gpu:
        cfg.setdefault('measured', {})['gpu_rate'] = med
    else:
        cfg.setdefault('measured', {})['per_worker'] = med / max(1, workers)


def scan_places(source, paths, file_list, scan_roots):
    """Where "Find files" looks: (places, error text or None)."""
    if source == 'folders':
        places = list(paths)
    elif source == 'list':
        try:
            with open(file_list, encoding='utf-8', errors='replace') as fh:
                places = [ln.strip() for ln in fh if ln.strip()]
        except OSError as ex:
            return [], 'Could not read the list: %s' % ex
    else:
        if WINDOWS:
            places = ['%s:\\' % d for d in 'CDEFGHIJKLMNOPQRSTUVWXYZ' if os.path.exists('%s:\\' % d)]
        else:
            places = [os.path.expanduser('~'), '/media', '/mnt', '/Volumes'] + list(scan_roots)
        places = [p for p in places if os.path.exists(p)]
    return places, None


def scan_status(n, nbytes, kinds, done):
    """The preview's status line and its tone ('ok', 'warn' or 'muted')."""
    ks = ', '.join('%s %s' % (fmt_count(v), k) for k, v in sorted(kinds.items()))
    text = '%s %s file(s), %s%s' % ('Found' if done else 'Searching\u2026', fmt_count(n), fmt_bytes(nbytes), (': ' + ks) if ks else '')
    return text, ('ok' if done and n else ('warn' if done else 'muted'))


def write_file_list(paths, recursive):
    """Collect the encrypted files under several places into a temporary
    file list; returns its path, or None when there are none."""
    items = [p for p, _ in find_encrypted(paths, recursive)]
    if not items:
        return None
    fd, path = tempfile.mkstemp(prefix='unmicro-files-', suffix='.txt')
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(items) + '\n')
    return path


def open_path(p):
    """Open a folder in the system file manager. Returns an error text or
    None."""
    if not p:
        return None
    if not os.path.exists(p):
        return 'The folder does not exist yet:\n%s' % p
    try:
        if WINDOWS:
            os.startfile(p)
        elif MACOS:
            subprocess.Popen(['open', p])
        else:
            subprocess.Popen(['xdg-open', p], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as ex:
        return str(ex)
    return None


def engine_verdict(rc, out):
    """(ok, chip text, detail text, version or None) for --version output."""
    first = out.strip().splitlines()[-1] if out.strip() else ''
    if rc == 0 and 'unmicro' in out:
        ver = first.split()[-1]
        return True, 'unmicro %s' % ver, 'Ready: %s' % first, ver
    hint = ''
    if 'GLIBC' in out:
        hint = '\nThis Linux build needs glibc 2.35 or newer (Ubuntu 22.04+, Debian 12+). On an older system choose unmicro.py instead (needs Python 3; pip install pycryptodome makes it fast).'
    return False, 'not working', 'The engine did not start: %s%s' % (out.strip()[-400:], hint), None


# --------------------------------------------------------------------------
# Resource monitor (stdlib; uses psutil when it is installed)
# --------------------------------------------------------------------------

class Resources(object):
    def __init__(self):
        try:
            import psutil  # noqa
            self.ps = psutil
        except Exception:
            self.ps = None
        self._cpu_prev = None
        self._win_temp_ok = None
        self._win_temp_last = (0, None)
        self.history = []  # (t, sample)

    def sample(self, disk_path):
        s = {'t': time.time(), 'cpu': self.cpu(), 'ram': None, 'disk_free_gb': None,
             'temp': self.temp(), 'battery': None, 'on_battery': False, 'battery_secs': None}
        r = self.ram()
        if r:
            s['ram'] = r
        try:
            p = disk_path if disk_path and os.path.exists(disk_path) else os.path.expanduser('~')
            s['disk_free_gb'] = shutil.disk_usage(p).free / 1e9
        except Exception:
            pass
        b = self.battery()
        if b:
            s['battery'], s['on_battery'], s['battery_secs'] = b
        self.history.append(s)
        cutoff = s['t'] - 900
        while self.history and self.history[0]['t'] < cutoff:
            self.history.pop(0)
        return s

    def slopes(self, window=600):
        """Per-second trend of each metric over the last window seconds
        (least squares)."""
        out = {}
        now = time.time()
        pts = [h for h in self.history if h['t'] >= now - window]
        if len(pts) < 6:
            return out
        for key in ('temp', 'ram', 'disk_free_gb', 'battery'):
            xs = [p['t'] for p in pts if p.get(key) is not None]
            ys = [p[key] for p in pts if p.get(key) is not None]
            if len(xs) < 6 or xs[-1] - xs[0] < 30:
                continue
            mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
            den = sum((x - mx) ** 2 for x in xs)
            if den:
                out[key] = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den
        return out

    def cpu(self):
        if self.ps:
            try:
                return self.ps.cpu_percent(interval=None)
            except Exception:
                pass
        try:
            if WINDOWS:
                import ctypes
                from ctypes import wintypes
                idle, kern, user = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
                ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user))
                f = lambda ft: (ft.dwHighDateTime << 32) | ft.dwLowDateTime
                cur = (f(idle), f(kern) + f(user))
            elif os.path.exists('/proc/stat'):
                with open('/proc/stat') as fh:
                    parts = [int(x) for x in fh.readline().split()[1:]]
                cur = (parts[3] + (parts[4] if len(parts) > 4 else 0), sum(parts))
            else:
                la = os.getloadavg()[0]
                return min(100.0, 100.0 * la / (os.cpu_count() or 1))
        except Exception:
            return None
        prev, self._cpu_prev = self._cpu_prev, cur
        if not prev:
            return None
        didle, dtotal = cur[0] - prev[0], cur[1] - prev[1]
        if dtotal <= 0:
            return None
        return max(0.0, min(100.0, 100.0 * (1 - didle / float(dtotal))))

    def ram(self):
        if self.ps:
            try:
                return self.ps.virtual_memory().percent
            except Exception:
                pass
        try:
            if WINDOWS:
                import ctypes

                class MS(ctypes.Structure):
                    _fields_ = [('dwLength', ctypes.c_ulong), ('dwMemoryLoad', ctypes.c_ulong),
                                ('t1', ctypes.c_ulonglong), ('a1', ctypes.c_ulonglong), ('t2', ctypes.c_ulonglong),
                                ('a2', ctypes.c_ulonglong), ('t3', ctypes.c_ulonglong), ('a3', ctypes.c_ulonglong),
                                ('e', ctypes.c_ulonglong)]
                ms = MS()
                ms.dwLength = ctypes.sizeof(MS)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
                return float(ms.dwMemoryLoad)
            if os.path.exists('/proc/meminfo'):
                info = {}
                with open('/proc/meminfo') as fh:
                    for ln in fh:
                        k, v = ln.split(':', 1)
                        info[k] = int(v.split()[0])
                avail = info.get('MemAvailable', info.get('MemFree', 0))
                return 100.0 * (1 - avail / float(info['MemTotal']))
            if MACOS:
                total = int(subprocess.check_output(['sysctl', '-n', 'hw.memsize']).strip())
                vm = subprocess.check_output(['vm_stat']).decode()
                page = int(re.search(r'page size of (\d+)', vm).group(1))
                free = sum(int(re.search(r'%s:\s+(\d+)' % k, vm).group(1)) for k in ('Pages free', 'Pages inactive', 'Pages speculative'))
                return 100.0 * (1 - free * page / float(total))
        except Exception:
            return None
        return None

    def temp(self):
        if self.ps and hasattr(self.ps, 'sensors_temperatures'):
            try:
                temps = self.ps.sensors_temperatures()
                best = None
                for name in ('k10temp', 'coretemp', 'zenpower', 'cpu_thermal', 'acpitz'):
                    for t in temps.get(name, []):
                        best = max(best or 0, t.current)
                    if best:
                        return best
            except Exception:
                pass
        if sys.platform.startswith('linux'):
            best = None
            try:
                base = '/sys/class/hwmon'
                for d in os.listdir(base):
                    try:
                        with open(os.path.join(base, d, 'name')) as fh:
                            name = fh.read().strip()
                    except OSError:
                        continue
                    if name not in ('k10temp', 'coretemp', 'zenpower', 'cpu_thermal'):
                        continue
                    for f in os.listdir(os.path.join(base, d)):
                        if f.startswith('temp') and f.endswith('_input'):
                            with open(os.path.join(base, d, f)) as fh:
                                best = max(best or 0, int(fh.read()) / 1000.0)
            except OSError:
                pass
            if best is None:
                try:
                    for z in os.listdir('/sys/class/thermal'):
                        if z.startswith('thermal_zone'):
                            with open('/sys/class/thermal/%s/temp' % z) as fh:
                                best = max(best or 0, int(fh.read()) / 1000.0)
                except OSError:
                    pass
            return best
        if WINDOWS:
            # Only some machines expose this, and often only to an admin.
            # Probe once; afterwards read at most every 30 seconds.
            if self._win_temp_ok is False:
                return None
            t, val = self._win_temp_last
            if time.time() - t < 30:
                return val
            try:
                out = subprocess.check_output(
                    ['powershell', '-NoProfile', '-Command',
                     '(Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop | Measure-Object CurrentTemperature -Maximum).Maximum'],
                    stderr=subprocess.DEVNULL, timeout=15, creationflags=0x08000000).decode().strip()
                val = float(out) / 10.0 - 273.15
                self._win_temp_ok = True
            except Exception:
                val = None
                self._win_temp_ok = False if self._win_temp_ok is None else self._win_temp_ok
            self._win_temp_last = (time.time(), val)
            return val
        return None

    def battery(self):
        """(percent, on_battery, seconds_left or None) or None."""
        if self.ps:
            try:
                b = self.ps.sensors_battery()
                if b is None:
                    return None
                secs = b.secsleft if isinstance(b.secsleft, (int, float)) and b.secsleft > 0 else None
                return (b.percent, not b.power_plugged, secs)
            except Exception:
                pass
        try:
            if WINDOWS:
                import ctypes

                class SPS(ctypes.Structure):
                    _fields_ = [('ACLineStatus', ctypes.c_byte), ('BatteryFlag', ctypes.c_byte),
                                ('BatteryLifePercent', ctypes.c_ubyte), ('SystemStatusFlag', ctypes.c_byte),
                                ('BatteryLifeTime', ctypes.c_ulong), ('BatteryFullLifeTime', ctypes.c_ulong)]
                s = SPS()
                ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(s))
                if s.BatteryFlag & 128 or s.BatteryLifePercent == 255:
                    return None
                secs = s.BatteryLifeTime if s.BatteryLifeTime not in (0xFFFFFFFF, -1) else None
                return (float(s.BatteryLifePercent), s.ACLineStatus == 0, secs)
            if sys.platform.startswith('linux'):
                base = '/sys/class/power_supply'
                for d in sorted(os.listdir(base)):
                    if not d.startswith('BAT'):
                        continue
                    rd = lambda f: open(os.path.join(base, d, f)).read().strip()
                    pct = float(rd('capacity'))
                    on_batt = rd('status') == 'Discharging'
                    secs = None
                    try:
                        now = float(rd('energy_now'))
                        pw = float(rd('power_now'))
                        if on_batt and pw > 0:
                            secs = now / pw * 3600
                    except Exception:
                        pass
                    return (pct, on_batt, secs)
                return None
            if MACOS:
                out = subprocess.check_output(['pmset', '-g', 'batt']).decode()
                m = re.search(r'(\d+)%', out)
                if not m:
                    return None
                secs = None
                t = re.search(r'(\d+):(\d+) remaining', out)
                if t:
                    secs = int(t.group(1)) * 3600 + int(t.group(2)) * 60
                return (float(m.group(1)), "'Battery Power'" in out, secs)
        except Exception:
            return None
        return None


# --------------------------------------------------------------------------
# Running the engine
# --------------------------------------------------------------------------

class Engine(object):
    """Where the unmicro binary (or unmicro.py) is, and how to start it."""

    def __init__(self, path='', python=''):
        self.path = path
        self.python = python

    def argv(self, args):
        if self.path.lower().endswith('.py'):
            py = self.python or (sys.executable if not getattr(sys, 'frozen', False) else ('py' if WINDOWS else 'python3'))
            if WINDOWS and os.path.basename(py).lower() == 'pythonw.exe':
                py = os.path.join(os.path.dirname(py), 'python.exe')
            return [py, self.path] + list(args)
        return [self.path] + list(args)

    @staticmethod
    def candidates():
        here = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))
        # a copy bundled inside the one-file exe comes first
        bundled = [os.path.join(sys._MEIPASS, 'engine')] if hasattr(sys, '_MEIPASS') else []
        dirs = bundled + [here, os.path.join(here, 'engine'), os.getcwd(), os.path.expanduser('~/tools'),
                os.path.expanduser('~/Downloads'), os.path.expanduser('~/Desktop')]
        pats = (re.compile(r'^unmicro-[\d.]+-windows-x86_64\.exe$', re.I) if WINDOWS else re.compile(r'^unmicro-[\d.]+-linux-x86_64$'),
                re.compile(r'^unmicro(\.exe)?$', re.I), re.compile(r'^unmicro\.py$'))
        found = []
        for pat in pats:
            for d in dirs:
                try:
                    names = sorted(os.listdir(d), reverse=True)
                except OSError:
                    continue
                for n in names:
                    p = os.path.join(d, n)
                    if pat.match(n) and os.path.isfile(p) and p not in found:
                        found.append(p)
        w = shutil.which('unmicro')
        if w and w not in found:
            found.append(w)
        return found

    def quick(self, args, env=None, timeout=120):
        """Run a short command (version, self-test, list keys) and return
        (returncode, output)."""
        kw = {}
        if WINDOWS:
            kw['creationflags'] = 0x08000000  # CREATE_NO_WINDOW
        e = dict(os.environ)
        e.update(env or {})
        e['PYTHONIOENCODING'] = 'utf-8'
        try:
            p = subprocess.run(self.argv(args), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=timeout, env=e, **kw)
            return (p.returncode, p.stdout.decode('utf-8', 'replace'))
        except subprocess.TimeoutExpired:
            return (-1, 'timed out after %d s' % timeout)
        except OSError as ex:
            return (-1, str(ex))


class Job(object):
    """A running unmicro with a terminal on stdin. Output arrives on
    self.q as ('out'|'err'|'exit', text|code)."""

    def __init__(self, argv, env, cwd=None):
        self.argv = argv
        self.q = queue.Queue()
        self.proc = None
        self.master = None
        env = dict(env)
        env['PYTHONUNBUFFERED'] = '1'
        env['PYTHONIOENCODING'] = 'utf-8'
        env.pop('UNMICRO_NO_UI', None)
        self.env = env
        self.cwd = cwd

    def start(self):
        if WINDOWS:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0  # SW_HIDE
            self.proc = subprocess.Popen(_helper_cmd() + ['--console-host'] + self.argv,
                                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         env=self.env, cwd=self.cwd, startupinfo=si,
                                         creationflags=0x00000010)  # CREATE_NEW_CONSOLE
        else:
            import pty
            import termios
            master, slave = pty.openpty()
            try:
                attrs = termios.tcgetattr(slave)
                attrs[3] &= ~termios.ECHO
                termios.tcsetattr(slave, termios.TCSANOW, attrs)
            except Exception:
                pass
            self.proc = subprocess.Popen(self.argv, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         env=self.env, cwd=self.cwd, start_new_session=True, close_fds=True)
            os.close(slave)
            self.master = master
            threading.Thread(target=self._drain_pty, daemon=True).start()
        self._readers = [threading.Thread(target=self._read, args=(self.proc.stdout, 'out'), daemon=True),
                         threading.Thread(target=self._read, args=(self.proc.stderr, 'err'), daemon=True)]
        for t in self._readers:
            t.start()
        threading.Thread(target=self._wait, daemon=True).start()

    def _read(self, fh, tag):
        dec = codecs.getincrementaldecoder('utf-8')('replace')
        fd = fh.fileno()
        while True:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            self.q.put((tag, dec.decode(data)))
        rest = dec.decode(b'', final=True)
        if rest:
            self.q.put((tag, rest))

    def _drain_pty(self):
        while self.master is not None:
            try:
                if not os.read(self.master, 1024):
                    break
            except OSError:
                break

    def _wait(self):
        rc = self.proc.wait()
        for t in self._readers:
            t.join(5)
        if self.master is not None:
            try:
                os.close(self.master)
            except OSError:
                pass
            self.master = None
        self.q.put(('exit', rc))

    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def send(self, text):
        if not self.running():
            return False
        if WINDOWS:
            return self._win_send('type', text)
        try:
            os.write(self.master, text.encode('utf-8'))
            return True
        except OSError:
            return False

    def interrupt(self):
        """What Ctrl+C at the keyboard does: unmicro pauses and asks."""
        if not self.running():
            return False
        if WINDOWS:
            return self._win_send('ctrlc')
        import signal
        try:
            os.kill(self.proc.pid, signal.SIGINT)
            return True
        except OSError:
            return False

    def kill(self):
        if not self.running():
            return
        if WINDOWS:
            subprocess.call(['taskkill', '/PID', str(self.proc.pid), '/T', '/F'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000)
        else:
            import signal
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except OSError:
                self.proc.kill()

    def _win_send(self, action, text=''):
        try:
            rc = subprocess.call(_helper_cmd() + ['--console-send', str(self.proc.pid), action, text],
                                 creationflags=0x08000000, timeout=20)
            return rc == 0
        except Exception:
            return False


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

def config_dir():
    if WINDOWS:
        base = os.environ.get('APPDATA') or os.path.expanduser('~')
        return os.path.join(base, 'unmicro-gui')
    if MACOS:
        return os.path.expanduser('~/Library/Application Support/unmicro-gui')
    return os.path.join(os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config'), 'unmicro-gui')


def default_out():
    home = os.path.expanduser('~')
    desk = os.path.join(home, 'Desktop')
    return os.path.join(desk if os.path.isdir(desk) else home, 'unmicro-recovered')


DEFAULTS = {
    'source': 'folders', 'paths': [], 'recursive': True, 'scan_roots': [], 'no_prune': False, 'max_files': '',
    'file_list': '', 'license': '', 'remember_license': False, 'keys': [], 'wordlist': '', 'scavenge': [],
    'level': 'standard', 'dumb': False, 'charset': 'turkish', 'dumb_mode': 'ask',
    'workers': 0, 'gpu': False, 'max_passes': 8, 'max_candidates': '', 'checkpoint_on': True, 'checkpoint': '',
    'seen_cap': 1000000, 'pure_python': False,
    'out': '', 'identify': False, 'flat': False, 'overwrite': False, 'verify': 'normal', 'fix_ext': True, 'force': False,
    'engine': '', 'python': '', 'ui': '',
    'limits': {'max_temp': 95, 'max_ram': 92, 'min_disk_gb': 2, 'min_battery': 15},
    'measured': {}, 'keydata': {},
}


def load_config(path):
    cfg = json.loads(json.dumps(DEFAULTS))
    try:
        with open(path, encoding='utf-8') as fh:
            saved = json.load(fh)
        for k, v in saved.items():
            if k in cfg:
                if isinstance(cfg[k], dict) and isinstance(v, dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
    except (OSError, ValueError):
        pass
    if not cfg['out']:
        cfg['out'] = default_out()
    return cfg


def save_config(path, cfg):
    data = dict(cfg)
    if not data.get('remember_license'):
        data['license'] = ''
    # an engine bundled in the one-file exe lives in a temporary folder that
    # changes every start: found again each time, never saved
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass and os.path.abspath(data.get('engine') or '').startswith(os.path.abspath(meipass) + os.sep):
        data['engine'] = ''
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=1, ensure_ascii=False)
        os.replace(tmp, path)
        if not WINDOWS:
            os.chmod(path, 0o600)
    except OSError:
        pass


def helper_main(argv=None):
    """Handle the Windows console helper modes; None if argv is not one."""
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['--console-host']:
        return _console_host(argv[1:])
    if argv[:1] == ['--console-send']:
        return _console_send(*argv[1:4])
    return None


