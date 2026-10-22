#!/usr/bin/env python3
"""unmicro GUI: a desktop front end for the unmicro decryptor binary.

Rho-9 Systems. Styled after Aviary (Hyper dark).

The GUI never decrypts anything itself. It builds an unmicro command line from
the choices on its tabs, runs the already built binary (or unmicro.py), and
reads its output. Pure standard library (tkinter), so the same file runs on
Windows, macOS and Linux. Everything that is not a widget lives in
core.py, shared with the PySide6 UI (qt_ui.py).

The binary is driven the way a person at a terminal would drive it: its
standard input is a terminal (a pty on Linux/macOS, a hidden console on
Windows). That matters because unmicro 3.9.1 only handles Ctrl+C cleanly when
it is interactive: it opens its pause menu, and the GUI answers "2" (stop and
recover the files already matched). Run non-interactively it hangs inside the
worker pool instead. The same channel answers the "keep going into
N-character keys?" question with a dialog.
"""
import os
import queue
import sys
import threading
import time

from .core import *  # noqa: F401,F403  (shared with the Qt UI)
from .core import helper_main


# ==========================================================================
# GUI
# ==========================================================================

def run_gui():
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import filedialog, ttk

    if WINDOWS:
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    root = tk.Tk()
    root.withdraw()
    families = set(tkfont.families(root))

    def pick(names, fallback):
        for n in names:
            if n in families:
                return n
        return fallback
    UI = pick(['Cerebri Sans', 'Segoe UI', 'Helvetica Neue', 'Inter', 'Noto Sans', 'Ubuntu', 'Cantarell', 'DejaVu Sans'], 'TkDefaultFont')
    MONO = pick(['Cascadia Mono', 'Consolas', 'Menlo', 'Roboto Mono', 'DejaVu Sans Mono', 'Liberation Mono', 'Noto Mono'], 'TkFixedFont')
    F = {
        'ui': (UI, 10), 'small': (UI, 9), 'tiny': (UI, 8), 'bold': (UI, 10, 'bold'),
        'title': (UI, 14, 'bold'), 'h': (UI, 10, 'bold'), 'nav': (UI, 10), 'wm': (UI, 17, 'bold'),
        'num': (UI, 20, 'bold'), 'mono': (MONO, 9), 'monos': (MONO, 8), 'big': (UI, 11, 'bold'),
    }

    cfg_path = os.path.join(config_dir(), 'settings.json')
    cfg = load_config(cfg_path)

    # ---------------- ttk styles -----------------
    st = ttk.Style(root)
    st.theme_use('clam')
    st.configure('.', background=C['card'], foreground=C['text'], fieldbackground=C['input'],
                 bordercolor=C['border'], lightcolor=C['card'], darkcolor=C['card'], troughcolor=C['input'],
                 font=F['ui'], focuscolor=C['primary'], selectbackground=C['primary'], selectforeground='#fff')
    for orient in ('Vertical', 'Horizontal'):
        st.configure('%s.TScrollbar' % orient, background=C['thumb'], troughcolor=C['card'], bordercolor=C['card'],
                     arrowcolor=C['muted'], lightcolor=C['thumb'], darkcolor=C['thumb'], gripcount=0, arrowsize=11)
        st.map('%s.TScrollbar' % orient, background=[('active', C['muted'])])
    st.configure('Treeview', background=C['input'], fieldbackground=C['input'], foreground=C['text'],
                 bordercolor=C['border'], rowheight=24, font=F['mono'])
    st.map('Treeview', background=[('selected', C['hover'])], foreground=[('selected', C['bright'])])
    st.configure('Treeview.Heading', background=C['card2'], foreground=C['muted'], bordercolor=C['border'],
                 relief='flat', font=F['h'], lightcolor=C['card2'], darkcolor=C['card2'])
    st.map('Treeview.Heading', background=[('active', C['hover'])])
    st.configure('Horizontal.TProgressbar', background=C['primary'], troughcolor=C['input'], bordercolor=C['input'],
                 lightcolor=C['primary'], darkcolor=C['primary'], thickness=8)
    st.configure('Ok.Horizontal.TProgressbar', background=C['success'], lightcolor=C['success'], darkcolor=C['success'])
    st.configure('Warn.Horizontal.TProgressbar', background=C['warning'], lightcolor=C['warning'], darkcolor=C['warning'])
    st.configure('Bad.Horizontal.TProgressbar', background=C['danger'], lightcolor=C['danger'], darkcolor=C['danger'])

    root.configure(bg=C['body'])
    root.title('unmicro - Dev7 / Micro decryptor')
    root.minsize(980, 640)
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    w, h = min(1280, int(sw * 0.9)), min(860, int(sh * 0.88))
    root.geometry('%dx%d+%d+%d' % (w, h, (sw - w) // 2, max(0, (sh - h) // 3)))

    # ---------------- logo (Aviary's bird, rasterised) -----------------
    def draw_mark(cv, size):
        r = max(4, size // 5)
        p = C['primary']
        cv.create_rectangle(r, 0, size - r, size, fill=p, outline=p)
        cv.create_rectangle(0, r, size, size - r, fill=p, outline=p)
        for cx, cy in ((r, r), (size - r, r), (r, size - r), (size - r, size - r)):
            cv.create_oval(cx - r, cy - r, cx + r, cy + r, fill=p, outline=p)
        sc = size * 0.6 / 24.0
        off = size * 0.2
        poly = bird_polygon(sc, off, off)
        cv.create_polygon([c for pt in poly for c in pt], fill='#ffffff', outline='', smooth=False)
        ex, ey, er = off + BIRD_EYE[0] * sc, off + BIRD_EYE[1] * sc, BIRD_EYE[2] * sc
        cv.create_oval(ex - er, ey - er, ex + er, ey + er, fill=C['topbar'], outline='')

    def icon_image(size=32):
        img = tk.PhotoImage(width=size, height=size)
        poly = bird_polygon(size * 0.62 / 24.0, size * 0.19, size * 0.19)
        rows = []
        for yy in range(size):
            row = []
            for xx in range(size):
                inside = False
                j = len(poly) - 1
                for k in range(len(poly)):
                    xi, yi = poly[k]
                    xj, yj = poly[j]
                    if (yi > yy + .5) != (yj > yy + .5) and xx + .5 < (xj - xi) * (yy + .5 - yi) / ((yj - yi) or 1e-9) + xi:
                        inside = not inside
                    j = k
                row.append('#ffffff' if inside else C['primary'])
            rows.append('{' + ' '.join(row) + '}')
        img.put(' '.join(rows))
        return img
    try:
        root._icon = icon_image()
        root.iconphoto(True, root._icon)
    except Exception:
        pass

    # ---------------- small widget kit -----------------
    def lbl(parent, text='', fg=None, font=None, bg=None, **kw):
        w = tk.Label(parent, text=text, fg=fg or C['text'], bg=bg or parent['bg'], font=font or F['ui'],
                     justify='left', anchor='w', **kw)
        if kw.get('wraplength'):
            autowrap(w, parent, kw['wraplength'])
        return w

    def autowrap(w, parent, most, margin=8):
        """Wrap at the parent's real width (never wider than most)."""
        def fit(e=None):
            try:
                width = parent.winfo_width()
                if width > 50:
                    w.configure(wraplength=max(160, min(most, width - margin)))
            except tk.TclError:
                pass
        parent.bind('<Configure>', lambda e: fit(), add='+')

    class Btn(tk.Label):
        KINDS = {
            'primary': (C['primary'], '#ffffff', C['primary_hover'], C['primary']),
            'ghost': (None, C['text'], C['hover'], C['border']),
            'danger': (None, C['danger'], '#4a3a48', C['danger']),
            'success': (None, C['success'], '#2f4d4b', C['success']),
        }

        def __init__(self, parent, text, cmd, kind='primary', small=False, width=None):
            self.kind = kind
            bg, fg, hov, bd = self.KINDS[kind]
            self._bg = bg or parent['bg']
            self._fg, self._hov, self._bd = fg, hov, bd
            tk.Label.__init__(self, parent, text=text, bg=self._bg, fg=fg, font=F['small'] if small else F['ui'],
                              padx=10 if small else 16, pady=4 if small else 7, cursor='hand2',
                              highlightthickness=1, highlightbackground=bd, highlightcolor=C['bright'],
                              takefocus=1, width=width or 0)
            self.cmd = cmd
            self.enabled = True
            self.bind('<Enter>', lambda e: self.enabled and self.configure(bg=self._hov))
            self.bind('<Leave>', lambda e: self.configure(bg=self._bg if self.enabled else self._bg))
            self.bind('<Button-1>', self._click)
            self.bind('<Return>', self._click)
            self.bind('<space>', self._click)

        def _click(self, e=None):
            if self.enabled and self.cmd:
                self.cmd()

        def set_enabled(self, on):
            self.enabled = on
            if on:
                self.configure(fg=self._fg, bg=self._bg, highlightbackground=self._bd, cursor='hand2')
            else:
                self.configure(fg=C['faint'], bg=C['border'] if self.kind == 'primary' else self._bg,
                               highlightbackground=C['border'], cursor='arrow')

    class Toggle(tk.Frame):
        """Aviary's switch (.sw2): label + note on the left, switch right."""

        def __init__(self, parent, var, text, note=None, command=None):
            tk.Frame.__init__(self, parent, bg=parent['bg'])
            self.var, self.command = var, command
            left = tk.Frame(self, bg=parent['bg'])
            left.pack(side='left', fill='x', expand=True)
            self.t = lbl(left, text)
            self.t.pack(anchor='w')
            if note:
                self.n = lbl(left, note, fg=C['faint'], font=F['tiny'], wraplength=760)
                self.n.pack(anchor='w')
            self.cv = tk.Canvas(self, width=44, height=22, bg=parent['bg'], highlightthickness=0, cursor='hand2', takefocus=1)
            self.cv.pack(side='right', padx=(12, 0))
            for wdg in (self.cv, self.t):
                wdg.bind('<Button-1>', self.flip)
            self.cv.bind('<space>', self.flip)
            self.cv.bind('<Return>', self.flip)
            var.trace_add('write', lambda *a: self.draw())
            self.enabled = True
            self.draw()

        def flip(self, e=None):
            if self.enabled:
                self.var.set(not self.var.get())
                if self.command:
                    self.command()

        def set_enabled(self, on):
            self.enabled = on
            self.t.configure(fg=C['text'] if on else C['faint'])
            self.draw()

        def draw(self):
            cv = self.cv
            cv.delete('all')
            on = bool(self.var.get())
            col = (C['primary'] if on else C['border']) if self.enabled else C['hover']
            cv.create_oval(1, 1, 21, 21, fill=col, outline=col)
            cv.create_oval(23, 1, 43, 21, fill=col, outline=col)
            cv.create_rectangle(11, 1, 33, 21, fill=col, outline=col)
            x = 25 if on else 4
            cv.create_oval(x, 4, x + 15, 19, fill='#ffffff' if self.enabled else C['faint'], outline='')

    class Choice(tk.Frame):
        """A column of radio cards: title + description, selected one is
        outlined in primary."""

        def __init__(self, parent, var, options, command=None, columns=1):
            tk.Frame.__init__(self, parent, bg=parent['bg'])
            self.var, self.command, self.items = var, command, {}
            for i, (value, title, desc) in enumerate(options):
                f = tk.Frame(self, bg=C['card2'], highlightthickness=1, highlightbackground=C['border'], cursor='hand2', takefocus=1)
                r, c = divmod(i, columns)
                f.grid(row=r, column=c, sticky='nsew', padx=(0 if c == 0 else 10, 0), pady=(0, 8))
                cv = tk.Canvas(f, width=18, height=18, bg=C['card2'], highlightthickness=0)
                cv.grid(row=0, column=0, rowspan=2, sticky='n', padx=(12, 8), pady=12)
                t = lbl(f, title, fg=C['bright'], font=F['bold'], bg=C['card2'])
                t.grid(row=0, column=1, sticky='w', pady=(10, 0), padx=(0, 12))
                d = tk.Label(f, text=desc, fg=C['muted'], font=F['small'], bg=C['card2'], justify='left', anchor='w', wraplength=300)
                d.grid(row=1, column=1, sticky='w', pady=(0, 10), padx=(0, 12))
                f.bind('<Configure>', lambda e, d=d: d.configure(wraplength=max(120, e.width - 56)), add='+')
                f.columnconfigure(1, weight=1)
                for wdg in (f, cv, t, d):
                    wdg.bind('<Button-1>', lambda e, v=value: self.choose(v))
                f.bind('<space>', lambda e, v=value: self.choose(v))
                self.items[value] = (f, cv, t, d)
            for c in range(columns):
                self.columnconfigure(c, weight=1, uniform='ch')
            var.trace_add('write', lambda *a: self.draw())
            self.draw()

        def choose(self, v):
            self.var.set(v)
            if self.command:
                self.command()

        def draw(self):
            cur = self.var.get()
            for v, (f, cv, t, d) in self.items.items():
                on = v == cur
                f.configure(highlightbackground=C['primary'] if on else C['border'])
                cv.delete('all')
                cv.create_oval(2, 2, 16, 16, outline=C['primary'] if on else C['muted'], width=2)
                if on:
                    cv.create_oval(6, 6, 12, 12, fill=C['primary'], outline='')

    def entry(parent, var, width=40, show=None, mono=False):
        e = tk.Entry(parent, textvariable=var, width=width, bg=C['input'], fg=C['bright'], insertbackground=C['bright'],
                     relief='flat', highlightthickness=1, highlightbackground=C['border'], highlightcolor=C['primary'],
                     font=F['mono'] if mono else F['ui'], disabledbackground=C['card2'], disabledforeground=C['faint'],
                     selectbackground=C['primary'], selectforeground='#fff')
        if show:
            e.configure(show=show)
        return e

    def spin(parent, var, lo, hi, width=8, inc=1):
        return tk.Spinbox(parent, textvariable=var, from_=lo, to=hi, increment=inc, width=width, bg=C['input'], fg=C['bright'],
                          insertbackground=C['bright'], relief='flat', highlightthickness=1, highlightbackground=C['border'],
                          highlightcolor=C['primary'], buttonbackground=C['card2'], font=F['ui'],
                          disabledbackground=C['card2'], disabledforeground=C['faint'])

    def textbox(parent, height=6, mono=True):
        t = tk.Text(parent, height=height, bg=C['input'], fg=C['bright'], insertbackground=C['bright'], relief='flat',
                    highlightthickness=1, highlightbackground=C['border'], highlightcolor=C['primary'],
                    font=F['mono'] if mono else F['ui'], wrap='none', padx=8, pady=6, undo=True,
                    selectbackground=C['primary'], selectforeground='#fff')
        return t

    def card(parent, title=None, sub=None, pady=(0, 18)):
        outer = tk.Frame(parent, bg=C['card'])
        outer.pack(fill='x', pady=pady)
        body = tk.Frame(outer, bg=C['card'])
        body.pack(fill='both', expand=True, padx=22, pady=18)
        if title:
            hd = tk.Frame(body, bg=C['card'])
            hd.pack(fill='x', pady=(0, 12))
            lbl(hd, title, fg=C['bright'], font=F['h']).pack(side='left')
            if sub:
                lbl(hd, '  ' + sub, fg=C['faint'], font=F['tiny']).pack(side='left', pady=(2, 0))
            body.head = hd
        return body

    def row(parent, pady=(0, 10)):
        f = tk.Frame(parent, bg=parent['bg'])
        f.pack(fill='x', pady=pady)
        return f

    def path_row(parent, var, mode, label=None, filetypes=None, note=None):
        f = row(parent)
        if label:
            lbl(f, label, fg=C['muted'], font=F['small']).pack(anchor='w', pady=(0, 4))
        line = tk.Frame(f, bg=f['bg'])
        line.pack(fill='x')
        e = entry(line, var, width=60, mono=True)
        e.pack(side='left', fill='x', expand=True, ipady=5)

        def browse():
            cur = var.get()
            init = cur if os.path.isdir(cur) else (os.path.dirname(cur) if cur else os.path.expanduser('~'))
            if mode == 'dir':
                p = filedialog.askdirectory(parent=root, initialdir=init if os.path.isdir(init) else None, mustexist=False)
            elif mode == 'save':
                p = filedialog.asksaveasfilename(parent=root, initialdir=init if os.path.isdir(init) else None)
            else:
                p = filedialog.askopenfilename(parent=root, initialdir=init if os.path.isdir(init) else None, filetypes=filetypes or [('All files', '*')])
            if p:
                var.set(os.path.normpath(p))
        Btn(line, 'Browse\u2026', browse, 'ghost', small=True).pack(side='left', padx=(8, 0))
        if note:
            lbl(f, note, fg=C['faint'], font=F['tiny'], wraplength=760).pack(anchor='w', pady=(4, 0))
        return e

    class Scroller(tk.Frame):
        """A page that scrolls when the window is short."""

        def __init__(self, parent):
            tk.Frame.__init__(self, parent, bg=C['body'])
            self.cv = tk.Canvas(self, bg=C['body'], highlightthickness=0, bd=0)
            self.sb = ttk.Scrollbar(self, orient='vertical', command=self.cv.yview)
            self.inner = tk.Frame(self.cv, bg=C['body'])
            self.win = self.cv.create_window(0, 0, window=self.inner, anchor='nw')
            self.cv.configure(yscrollcommand=self.sb.set)
            self.cv.pack(side='left', fill='both', expand=True)
            self.sb.pack(side='right', fill='y')
            self.inner.bind('<Configure>', lambda e: self.cv.configure(scrollregion=self.cv.bbox('all')))
            self.cv.bind('<Configure>', self._width)
            self.bind_all_wheel()

        def _width(self, e):
            pad = 24
            maxw = 1240
            wdt = min(e.width - 2 * pad, maxw)
            x = max(pad, (e.width - wdt) // 2)
            self.cv.itemconfigure(self.win, width=wdt)
            self.cv.coords(self.win, x, 20)

        def bind_all_wheel(self):
            def wheel(e):
                if not self.winfo_ismapped():
                    return
                wdg = e.widget
                try:
                    if wdg.winfo_toplevel() is not root or isinstance(wdg, (tk.Text, ttk.Treeview)):
                        return
                except Exception:
                    return
                if self.inner.winfo_height() <= self.cv.winfo_height():
                    return
                if e.num == 4:
                    d = -1
                elif e.num == 5:
                    d = 1
                else:
                    d = -1 if e.delta > 0 else 1
                    if MACOS:
                        d = -e.delta
                self.cv.yview_scroll(d * (1 if MACOS else 3), 'units')
            root.bind_all('<MouseWheel>', wheel, add='+')
            root.bind_all('<Button-4>', wheel, add='+')
            root.bind_all('<Button-5>', wheel, add='+')

    # ---------------- dialogs -----------------
    def dialog(title, body_fn, buttons, danger=False, width=640):
        """Modal themed dialog. buttons: [(text, value, kind)]. body_fn(frame,
        set_button_state) builds the body. Returns the chosen value."""
        d = tk.Toplevel(root)
        d.withdraw()
        d.title(title)
        d.configure(bg=C['card'])
        d.transient(root)
        d.resizable(False, False)
        bar = tk.Frame(d, bg=C['danger'] if danger else C['primary'], height=3)
        bar.pack(fill='x')
        wrap = tk.Frame(d, bg=C['card'])
        wrap.pack(fill='both', expand=True, padx=26, pady=20)
        lbl(wrap, title, fg=C['danger'] if danger else C['bright'], font=F['big']).pack(anchor='w', pady=(0, 12))
        body = tk.Frame(wrap, bg=C['card'])
        body.pack(fill='both', expand=True)
        result = {'v': None}
        btns = {}

        def set_state(value, on):
            if value in btns:
                btns[value].set_enabled(on)
        body_fn(body, set_state)
        bf = tk.Frame(wrap, bg=C['card'])
        bf.pack(fill='x', pady=(18, 0))
        for text, value, kind in reversed(buttons):
            def done(v=value):
                result['v'] = v
                d.destroy()
            b = Btn(bf, text, done, kind)
            b.pack(side='right', padx=(8, 0))
            btns[value] = b
        d.protocol('WM_DELETE_WINDOW', d.destroy)
        d.bind('<Escape>', lambda e: d.destroy())
        d.update_idletasks()
        ww = max(width, d.winfo_reqwidth())
        hh = d.winfo_reqheight()
        x = root.winfo_rootx() + (root.winfo_width() - ww) // 2
        y = root.winfo_rooty() + max(40, (root.winfo_height() - hh) // 3)
        d.geometry('%dx%d+%d+%d' % (ww, hh, max(0, x), max(0, y)))
        d.deiconify()
        d.grab_set()
        d.focus_set()
        root.wait_window(d)
        return result['v']

    def message(title, text, kind='info'):
        def body(f, _):
            lbl(f, text, wraplength=580).pack(anchor='w')
        dialog(title, body, [('OK', True, 'primary')], danger=(kind == 'danger'))

    # ---------------- variables -----------------
    V = {}

    def var(name, kind=tk.StringVar):
        v = kind(value=cfg.get(name))
        V[name] = v
        return v
    for n in ('source', 'file_list', 'license', 'wordlist', 'level', 'charset', 'dumb_mode', 'out', 'checkpoint', 'verify', 'engine', 'python', 'max_files', 'max_candidates'):
        var(n)
    for n in ('recursive', 'no_prune', 'remember_license', 'dumb', 'gpu', 'checkpoint_on', 'pure_python', 'identify', 'flat', 'overwrite', 'fix_ext', 'force'):
        var(n, tk.BooleanVar)
    for n in ('workers', 'max_passes', 'seen_cap'):
        var(n, tk.IntVar)
    cpu_n = os.cpu_count() or 1
    if not V['workers'].get():
        V['workers'].set(cpu_n)
    LIM = {k: tk.IntVar(value=v) for k, v in cfg['limits'].items()}
    lists = {'paths': list(cfg['paths']), 'scan_roots': list(cfg['scan_roots']), 'scavenge': list(cfg['scavenge'])}

    def snapshot():
        """cfg dict from the widgets."""
        out = dict(cfg)
        for k, v in V.items():
            try:
                out[k] = v.get()
            except (tk.TclError, ValueError):
                out[k] = DEFAULTS.get(k)
        out.update({k: list(v) for k, v in lists.items()})
        out['keys'] = [k for k in keys_text.get('1.0', 'end').splitlines() if k.strip()] if keys_text else []
        out['limits'] = {}
        for k, v in LIM.items():
            try:
                out['limits'][k] = v.get()
            except (tk.TclError, ValueError):
                out['limits'][k] = DEFAULTS['limits'][k]
        return finish_snapshot(out, cpu_n)
    keys_text = None
    ready = {'v': False}

    # ---------------- top bar -----------------
    top = tk.Frame(root, bg=C['topbar'], height=64)
    top.pack(fill='x')
    top.pack_propagate(False)
    logo = tk.Frame(top, bg=C['topbar'])
    logo.pack(side='left', padx=(24, 0))
    mk = tk.Canvas(logo, width=32, height=32, bg=C['topbar'], highlightthickness=0)
    mk.pack(side='left')
    draw_mark(mk, 32)
    wm = tk.Frame(logo, bg=C['topbar'])
    wm.pack(side='left', padx=(10, 0))
    wmf = tkfont.Font(root, font=F['wm'])
    wmc = tk.Canvas(wm, width=wmf.measure('unmicro') + 4, height=wmf.metrics('linespace'), bg=C['topbar'], highlightthickness=0)
    wmc.pack(side='left')
    wmc.create_text(0, 0, text='u', fill=C['primary'], font=wmf, anchor='nw')
    wmc.create_text(wmf.measure('u'), 0, text='nmicro', fill='#ffffff', font=wmf, anchor='nw')
    lbl(logo, '   Dev7 / Micro decryptor', fg=C['faint'], font=F['small'], bg=C['topbar']).pack(side='left', pady=(6, 0))

    right = tk.Frame(top, bg=C['topbar'])
    right.pack(side='right', padx=(0, 18), fill='y')

    def chip(parent, k):
        f = tk.Frame(parent, bg=C['topbar'], highlightthickness=0)
        f.pack(side='left', fill='y', padx=(0, 0))
        tk.Frame(f, bg='#4a5560', width=1).pack(side='left', fill='y', pady=0)
        inner = tk.Frame(f, bg=C['topbar'])
        inner.pack(side='left', padx=14)
        lbl(inner, k, fg=C['faint'], font=F['tiny'], bg=C['topbar']).pack(anchor='w', pady=(13, 0))
        line = tk.Frame(inner, bg=C['topbar'])
        line.pack(anchor='w')
        dot = tk.Canvas(line, width=10, height=10, bg=C['topbar'], highlightthickness=0)
        dot.pack(side='left', padx=(0, 6))
        val = lbl(line, '...', fg=C['bright'], font=F['small'], bg=C['topbar'])
        val.pack(side='left')

        def set_(text, color):
            dot.delete('all')
            dot.create_oval(1, 1, 9, 9, fill=color, outline='')
            val.configure(text=text)
        return set_
    set_engine_chip = chip(right, 'Engine')
    set_license_chip = chip(right, 'Licence')
    set_run_chip = chip(right, 'Status')
    set_run_chip('Idle', C['faint'])

    # ---------------- nav -----------------
    nav = tk.Frame(root, bg=C['topbar'], height=46)
    nav.pack(fill='x')
    nav.pack_propagate(False)
    tk.Frame(root, bg=C['border'], height=1).pack(fill='x')
    navin = tk.Frame(nav, bg=C['topbar'])
    navin.pack(side='left', padx=(16, 0), fill='y')
    content = tk.Frame(root, bg=C['body'])
    content.pack(fill='both', expand=True)

    pages, tabs, order = {}, {}, []
    current = {'name': None}

    def add_page(name, label):
        sc = Scroller(content)
        pages[name] = sc
        f = tk.Frame(navin, bg=C['topbar'], cursor='hand2')
        f.pack(side='left', fill='y')
        t = tk.Label(f, text=label, fg=C['navtext'], bg=C['topbar'], font=F['nav'], padx=16)
        t.pack(fill='both', expand=True)
        u = tk.Frame(f, bg=C['topbar'], height=2)
        u.pack(fill='x', side='bottom')
        for wdg in (f, t):
            wdg.bind('<Button-1>', lambda e, n=name: show(n))
            wdg.bind('<Enter>', lambda e, n=name, t=t: current['name'] != n and t.configure(fg=C['navhover']))
            wdg.bind('<Leave>', lambda e, n=name, t=t: current['name'] != n and t.configure(fg=C['navtext']))
        tabs[name] = (t, u)
        order.append(name)
        return sc.inner

    def show(name):
        if current['name'] == name:
            return
        if current['name']:
            pages[current['name']].pack_forget()
            t, u = tabs[current['name']]
            t.configure(fg=C['navtext'])
            u.configure(bg=C['topbar'])
        current['name'] = name
        pages[name].pack(fill='both', expand=True)
        t, u = tabs[name]
        t.configure(fg=C['primary'])
        u.configure(bg=C['primary'])
        pages[name].cv.yview_moveto(0)
        hooks = on_show.get(name)
        if hooks:
            hooks()
    on_show = {}

    def page_title(parent, title, crumb):
        f = tk.Frame(parent, bg=C['body'])
        f.pack(fill='x', pady=(0, 16))
        lbl(f, title, fg=C['bright'], font=F['title']).pack(side='left')
        lbl(f, crumb, fg=C['faint'], font=F['small']).pack(side='right')
        return f

    def nav_buttons(parent, back=None, nxt=None, nxt_text=None):
        f = tk.Frame(parent, bg=C['body'])
        f.pack(fill='x', pady=(4, 30))
        if nxt:
            names = {'keys': 'Keys', 'search': 'Search', 'output': 'Output', 'run': 'Run'}
            Btn(f, nxt_text or ('Next: %s  \u2192' % names.get(nxt, nxt.title())), lambda: show(nxt), 'primary').pack(side='right')
        if back:
            Btn(f, '\u2190  Back', lambda: show(back), 'ghost').pack(side='right', padx=(0, 8))

    # ======================= Files =======================
    P = add_page('files', '1  Files')
    page_title(P, 'Encrypted files', 'Step 1 of 5 \u00b7 what to decrypt')
    c = card(P, 'Where are the encrypted files?', 'files renamed to .cryptedmicro')
    files_box = {}

    def src_changed():
        s = V['source'].get()
        for k, f in files_box.items():
            if k == s:
                f.pack(fill='x', pady=(6, 0))
            else:
                f.pack_forget()
        refresh_review()
    Choice(c, V['source'], [
        ('folders', 'Folders or files I choose', 'Pick one or more folders (subfolders included) or single files. The quickest way when you know where they are.'),
        ('auto', 'The whole computer', 'Search every drive and user folder for .cryptedmicro files. Slower; use it when you are not sure where they all are.'),
        ('list', 'A list of files', 'A text file with one encrypted file path per line, for example from an earlier run.'),
    ], command=src_changed, columns=3).pack(fill='x')

    # folders
    fb = tk.Frame(c, bg=C['card'])
    files_box['folders'] = fb
    pl_frame = tk.Frame(fb, bg=C['card'])
    pl_frame.pack(fill='x')
    paths_lb = tk.Listbox(pl_frame, height=5, bg=C['input'], fg=C['bright'], selectbackground=C['hover'], selectforeground=C['bright'],
                          relief='flat', highlightthickness=1, highlightbackground=C['border'], highlightcolor=C['primary'],
                          font=F['mono'], activestyle='none', selectmode='extended')
    paths_lb.pack(side='left', fill='x', expand=True)
    pbtns = tk.Frame(pl_frame, bg=C['card'])
    pbtns.pack(side='left', padx=(10, 0), anchor='n')

    def sync_paths():
        paths_lb.delete(0, 'end')
        for p in lists['paths']:
            paths_lb.insert('end', p)
        if not lists['paths']:
            paths_lb.insert('end', '  (nothing chosen yet: add a folder or files)')
            paths_lb.itemconfigure(0, fg=C['faint'])
        refresh_review()

    def add_folder():
        p = filedialog.askdirectory(parent=root, mustexist=True)
        if p and os.path.normpath(p) not in lists['paths']:
            lists['paths'].append(os.path.normpath(p))
            sync_paths()

    def add_files():
        ps = filedialog.askopenfilenames(parent=root, filetypes=[('Encrypted files', '*.cryptedmicro *.CRYPTEDMICRO'), ('All files', '*')])
        for p in ps or ():
            p = os.path.normpath(p)
            if p not in lists['paths']:
                lists['paths'].append(p)
        sync_paths()

    def remove_paths():
        sel = [paths_lb.get(i) for i in paths_lb.curselection()]
        lists['paths'] = [p for p in lists['paths'] if p not in sel]
        sync_paths()
    Btn(pbtns, 'Add folder\u2026', add_folder, 'ghost', small=True, width=14).pack(fill='x', pady=(0, 6))
    Btn(pbtns, 'Add files\u2026', add_files, 'ghost', small=True, width=14).pack(fill='x', pady=(0, 6))
    Btn(pbtns, 'Remove', remove_paths, 'danger', small=True, width=14).pack(fill='x')
    tg = tk.Frame(fb, bg=C['card'])
    tg.pack(fill='x', pady=(12, 0))
    Toggle(tg, V['recursive'], 'Include subfolders', 'Look inside every folder below the ones you chose.', command=lambda: refresh_review()).pack(fill='x')

    # auto
    ab = tk.Frame(c, bg=C['card'])
    files_box['auto'] = ab
    lbl(ab, 'Every drive and the usual user locations are searched. Add extra places below if files live somewhere unusual (a USB drive, a network share).',
        fg=C['muted'], font=F['small'], wraplength=900).pack(anchor='w', pady=(0, 8))
    rl_frame = tk.Frame(ab, bg=C['card'])
    rl_frame.pack(fill='x')
    roots_lb = tk.Listbox(rl_frame, height=3, bg=C['input'], fg=C['bright'], selectbackground=C['hover'], relief='flat',
                          highlightthickness=1, highlightbackground=C['border'], font=F['mono'], activestyle='none')
    roots_lb.pack(side='left', fill='x', expand=True)
    rb = tk.Frame(rl_frame, bg=C['card'])
    rb.pack(side='left', padx=(10, 0), anchor='n')

    def sync_roots():
        roots_lb.delete(0, 'end')
        for p in lists['scan_roots']:
            roots_lb.insert('end', p)
        refresh_review()

    def add_root():
        p = filedialog.askdirectory(parent=root, mustexist=True)
        if p and p not in lists['scan_roots']:
            lists['scan_roots'].append(os.path.normpath(p))
            sync_roots()

    def rm_root():
        for i in reversed(roots_lb.curselection()):
            del lists['scan_roots'][i]
        sync_roots()
    Btn(rb, 'Add place\u2026', add_root, 'ghost', small=True, width=14).pack(fill='x', pady=(0, 6))
    Btn(rb, 'Remove', rm_root, 'danger', small=True, width=14).pack(fill='x')
    ag = tk.Frame(ab, bg=C['card'])
    ag.pack(fill='x', pady=(12, 0))
    Toggle(ag, V['no_prune'], 'Also search system folders', 'Windows, Program Files and similar are skipped by default. Much slower when on.', command=lambda: refresh_review()).pack(fill='x', pady=(0, 10))
    mf = tk.Frame(ag, bg=C['card'])
    mf.pack(fill='x')
    lbl(mf, 'Stop after this many files (blank = no limit)').pack(side='left')
    entry(mf, V['max_files'], width=10).pack(side='right', ipady=3)

    # list
    lb_ = tk.Frame(c, bg=C['card'])
    files_box['list'] = lb_
    path_row(lb_, V['file_list'], 'file', 'File list (one path per line)', [('Text files', '*.txt'), ('All files', '*')])

    # preview
    c2 = card(P, 'Preview', 'optional: see what will be worked on')
    pv_top = row(c2)
    pv_status = lbl(pv_top, 'Press "Find files" to list the encrypted files in the places above. Nothing is changed.', fg=C['muted'], font=F['small'])
    pv_status.pack(side='left')
    pv_btn_holder = tk.Frame(pv_top, bg=C['card'])
    pv_btn_holder.pack(side='right')
    tree_f = tk.Frame(c2, bg=C['card'])
    tree_f.pack(fill='x')
    tree = ttk.Treeview(tree_f, columns=('size', 'fmt', 'path'), show='headings', height=8)
    tree.heading('size', text='Size')
    tree.heading('fmt', text='Format (from its length)')
    tree.heading('path', text='File')
    tree.column('size', width=90, anchor='e', stretch=False)
    tree.column('fmt', width=190, stretch=False)
    tree.column('path', width=600)
    tsb = ttk.Scrollbar(tree_f, orient='vertical', command=tree.yview)
    tree.configure(yscrollcommand=tsb.set)
    tree.pack(side='left', fill='x', expand=True)
    tsb.pack(side='right', fill='y')
    scan_state = {'cancel': None}

    def find_files():
        if scan_state['cancel']:
            scan_state['cancel'].set()
            return
        s = V['source'].get()
        places, err = scan_places(s, lists['paths'], V['file_list'].get(), lists['scan_roots'])
        if err:
            pv_status.configure(text=err, fg=C['danger'])
            return
        if not places:
            pv_status.configure(text='Nothing chosen yet.', fg=C['warning'])
            return
        tree.delete(*tree.get_children())
        cancel = threading.Event()
        scan_state['cancel'] = cancel
        find_btn.configure(text='Stop')
        res = queue.Queue()
        rec = V['recursive'].get() if s == 'folders' else True

        def work():
            n = 0
            for item in find_encrypted(places, rec, cancel):
                res.put(item)
                n += 1
            res.put(None)
        threading.Thread(target=work, daemon=True).start()
        tot = {'n': 0, 'b': 0, 'kinds': {}}

        def poll():
            done = False
            try:
                for _ in range(500):
                    it = res.get_nowait()
                    if it is None:
                        done = True
                        break
                    p, size = it
                    fmt = guess_format(size)
                    tot['n'] += 1
                    tot['b'] += size
                    tot['kinds'][fmt] = tot['kinds'].get(fmt, 0) + 1
                    if tot['n'] <= 5000:
                        tree.insert('', 'end', values=(fmt_bytes(size), fmt, p))
            except queue.Empty:
                pass
            text, tone = scan_status(tot['n'], tot['b'], tot['kinds'], done)
            pv_status.configure(text=text, fg={'ok': C['success'], 'warn': C['warning']}.get(tone, C['muted']))
            if done:
                scan_state['cancel'] = None
                find_btn.configure(text='Find files')
            else:
                root.after(150, poll)
        poll()
    find_btn = Btn(pv_btn_holder, 'Find files', find_files, 'ghost', small=True)
    find_btn.pack()
    nav_buttons(P, None, 'keys')

    # ======================= Keys =======================
    P = add_page('keys', '2  Keys')
    page_title(P, 'Licence and keys', 'Step 2 of 5 \u00b7 what to try')
    c = card(P, 'Licence key', 'needed for every run that looks at your files')
    lbl(c, 'Each unmicro build is sealed with its own licence key. If you do not have one, email %s and mention "Chattering Magpies". There is no charge.' % CONTACT,
        fg=C['muted'], font=F['small'], wraplength=900).pack(anchor='w', pady=(0, 10))
    lr = row(c)
    lic_entry = entry(lr, V['license'], width=50, show='\u2022', mono=True)
    lic_entry.pack(side='left', fill='x', expand=True, ipady=5)
    show_lic = tk.BooleanVar(value=False)

    def toggle_show():
        show_lic.set(not show_lic.get())
        lic_entry.configure(show='' if show_lic.get() else '\u2022')
        show_btn.configure(text='Hide' if show_lic.get() else 'Show')
    show_btn = Btn(lr, 'Show', toggle_show, 'ghost', small=True, width=6)
    show_btn.pack(side='left', padx=(8, 0))
    check_btn = Btn(lr, 'Check licence', lambda: check_license(), 'primary', small=True)
    check_btn.pack(side='left', padx=(8, 0))
    lic_status = lbl(c, '', fg=C['muted'], font=F['small'])
    lic_status.pack(anchor='w', pady=(0, 8))
    Toggle(c, V['remember_license'], 'Remember the licence on this computer',
           'Saved in your user settings file (readable only by you on Linux/macOS). Leave off on a shared machine.').pack(fill='x')
    rk_holder = tk.Frame(c, bg=C['card'])
    rk_holder.pack(fill='x', pady=(10, 0))
    rk_open = {'v': False}
    rk_btn = Btn(rk_holder, 'Show the recovered keys this build knows', lambda: toggle_rk(), 'ghost', small=True)
    rk_btn.pack(anchor='w')
    rk_box = textbox(rk_holder, height=8)

    def toggle_rk():
        rk_open['v'] = not rk_open['v']
        if rk_open['v']:
            keys = cfg['keydata'].get('keys') or []
            rk_box.configure(state='normal')
            rk_box.delete('1.0', 'end')
            rk_box.insert('1.0', '\n'.join(keys) if keys else 'Check the licence first.')
            rk_box.configure(state='disabled')
            rk_box.pack(fill='x', pady=(8, 0))
            rk_btn.configure(text='Hide the recovered keys')
        else:
            rk_box.pack_forget()
            rk_btn.configure(text='Show the recovered keys this build knows')

    c = card(P, 'Keys you already know', 'optional')
    lbl(c, 'If you have the key, or think you might (from a ransom note, the attackers, or someone else hit by the same crew), type it here, one per line. These are tried first.',
        fg=C['muted'], font=F['small'], wraplength=900).pack(anchor='w', pady=(0, 8))
    keys_text = textbox(c, height=4)
    keys_text.pack(fill='x')
    keys_text.insert('1.0', '\n'.join(cfg.get('keys', [])))
    keys_text.bind('<<Modified>>', lambda e: (keys_text.edit_modified(False), refresh_review()))
    ftg = tk.Frame(c, bg=C['card'])
    ftg.pack(fill='x', pady=(10, 0))
    force_tg = Toggle(ftg, V['force'], 'Apply my one key to every file without checking first',
                      'Only when exactly one key is given and nothing else is searched. Faster, but a wrong key writes garbage.', command=lambda: refresh_review())
    force_tg.pack(fill='x')

    c = card(P, 'Wordlist and memory dumps', 'optional')
    path_row(c, V['wordlist'], 'file', 'Wordlist: a text file of candidate keys, one per line', [('Text files', '*.txt *.lst *.dic'), ('All files', '*')])
    lbl(c, 'Memory dumps, pagefile, hibernation file, strings listings or implant logs. The key is a typed string and often survives in the clear. Never add an encrypted file here.',
        fg=C['muted'], font=F['small'], wraplength=900).pack(anchor='w', pady=(6, 6))
    sv_frame = tk.Frame(c, bg=C['card'])
    sv_frame.pack(fill='x')
    sc_lb = tk.Listbox(sv_frame, height=3, bg=C['input'], fg=C['bright'], selectbackground=C['hover'], relief='flat',
                       highlightthickness=1, highlightbackground=C['border'], font=F['mono'], activestyle='none')
    sc_lb.pack(side='left', fill='x', expand=True)
    scb = tk.Frame(sv_frame, bg=C['card'])
    scb.pack(side='left', padx=(10, 0), anchor='n')

    def sync_sc():
        sc_lb.delete(0, 'end')
        for p in lists['scavenge']:
            sc_lb.insert('end', p)
        refresh_review()

    def add_sc():
        for p in filedialog.askopenfilenames(parent=root) or ():
            p = os.path.normpath(p)
            if p.lower().endswith(EXT):
                message('Not an encrypted file', 'That file is encrypted. Memory dumps must be unencrypted; skipping it.', 'danger')
                continue
            if p not in lists['scavenge']:
                lists['scavenge'].append(p)
        sync_sc()

    def rm_sc():
        for i in reversed(sc_lb.curselection()):
            del lists['scavenge'][i]
        sync_sc()
    Btn(scb, 'Add dump\u2026', add_sc, 'ghost', small=True, width=14).pack(fill='x', pady=(0, 6))
    Btn(scb, 'Remove', rm_sc, 'danger', small=True, width=14).pack(fill='x')
    nav_buttons(P, 'files', 'search')

    # ======================= Search =======================
    P = add_page('search', '3  Search')
    page_title(P, 'How hard to look for the key', 'Step 3 of 5 \u00b7 effort and machine use')
    c = card(P, 'Search level')
    Choice(c, V['level'], [
        ('quick', 'Quick', 'Your keys, wordlist and dumps, plus every key already recovered from these attackers. Seconds.'),
        ('standard', 'Standard', 'Quick, then likely variations modelled on this crew\'s key history (--brute). Minutes.'),
        ('deep', 'Deep', 'Standard with every generator widened (--brute --deep). Hours, not seconds.'),
    ], command=lambda: refresh_review(), columns=3).pack(fill='x')

    c = card(P, 'Structural brute force', '--dumb-brute: every possible key, shortest first')
    Toggle(c, V['dumb'], 'Also try every possible key, one length at a time',
           'Runs after the level above. Exhaustive, so short keys finish and long ones may never. Each extra character multiplies the work by the alphabet size.',
           command=lambda: dumb_changed()).pack(fill='x', pady=(0, 14))
    dumb_box = tk.Frame(c, bg=C['card'])
    dumb_box.pack(fill='x')
    lbl(dumb_box, 'Alphabet', fg=C['muted'], font=F['small']).pack(anchor='w', pady=(0, 6))
    cs_choice = Choice(dumb_box, V['charset'], [
        ('observed', 'Observed', 'Only characters seen in recovered keys.'),
        ('turkish', 'Turkish + English (default)', 'Adds Turkish and English lowercase and digits.'),
        ('full', 'Full', 'Adds uppercase. Widest and slowest.'),
    ], command=lambda: dumb_changed(), columns=3)
    cs_choice.pack(fill='x', pady=(0, 6))
    lbl(dumb_box, 'When the keys get long', fg=C['muted'], font=F['small']).pack(anchor='w', pady=(6, 6))
    Choice(dumb_box, V['dumb_mode'], [
        ('ask', 'Ask me before each long length', 'Before a length that would take long, unmicro stops and the GUI asks you, with its time estimate.'),
        ('keepgoing', 'Keep going without asking', 'Answers yes to every length (--yes). Still respects "Stop after N guesses" below.'),
        ('endless', 'Run until this machine cannot take it any more', 'Every core, no guess limit, no questions, through every length up to the longest recovered key. Runs until a safety limit trips, you stop it, or the hardware gives out. You will be warned first.'),
    ], command=lambda: dumb_changed(), columns=3).pack(fill='x')
    est_card = tk.Frame(dumb_box, bg=C['card2'], highlightthickness=1, highlightbackground=C['border'])
    est_card.pack(fill='x', pady=(8, 0))
    est_head = lbl(est_card, '', fg=C['bright'], font=F['bold'], bg=C['card2'])
    est_head.pack(anchor='w', padx=14, pady=(10, 4))
    est_tbl = tk.Frame(est_card, bg=C['card2'])
    est_tbl.pack(fill='x', padx=14, pady=(0, 10))

    def draw_estimates():
        for wdg in est_tbl.winfo_children():
            wdg.destroy()
        head, rows, foot = estimate_table(cfg, snapshot(), cpu_n)
        est_head.configure(text=head)
        hdrs = ('Length', 'Keys to try', 'This length', 'Total so far')
        for j, h in enumerate(hdrs):
            lbl(est_tbl, h, fg=C['muted'], font=F['tiny'], bg=C['card2']).grid(row=0, column=j, sticky='w', padx=(0, 28))
        tones = {'ok': C['success'], 'warn': C['warning'], 'bad': C['danger']}
        for i, r in enumerate(rows, 1):
            for j, v in enumerate(r[:4]):
                lbl(est_tbl, v, fg=tones[r[4]] if j == 3 else C['text'], font=F['monos'], bg=C['card2']).grid(row=i, column=j, sticky='w', padx=(0, 28))
        lbl(est_tbl, foot, fg=C['muted'], font=F['small'], bg=C['card2']).grid(row=len(rows) + 1, column=0, columnspan=4, sticky='w', pady=(8, 0))

    def dumb_changed():
        on = V['dumb'].get()
        if on:
            dumb_box.pack(fill='x')
            draw_estimates()
        else:
            dumb_box.pack_forget()
        endless = on and V['dumb_mode'].get() == 'endless'
        try:
            mc_entry.configure(state='disabled' if endless else 'normal')
            if endless:
                V['workers'].set(cpu_n)
        except NameError:
            pass
        refresh_review()

    c = card(P, 'Machine use')
    wr = row(c)
    lbl(wr, 'CPU workers').pack(side='left')
    wl = lbl(wr, '', fg=C['bright'], font=F['bold'])
    wl.pack(side='right')
    wsc = tk.Scale(c, from_=1, to=cpu_n, orient='horizontal', variable=V['workers'], showvalue=False, bg=C['card'], fg=C['text'],
                   troughcolor=C['input'], activebackground=C['primary'], highlightthickness=0, bd=0, sliderrelief='flat',
                   sliderlength=22, width=12, command=lambda v: workers_changed())
    wsc.pack(fill='x', pady=(0, 2))
    lbl(c, 'All %d cores searches fastest; fewer keeps the computer usable while it runs.' % cpu_n, fg=C['faint'], font=F['tiny']).pack(anchor='w', pady=(0, 12))

    def workers_changed():
        n = V['workers'].get()
        wl.configure(text=('%d of %d (all)' % (n, cpu_n)) if n >= cpu_n else ('%d of %d' % (n, cpu_n)))
        if V['dumb'].get():
            draw_estimates()
        refresh_review()
    gr = tk.Frame(c, bg=C['card'])
    gr.pack(fill='x', pady=(0, 10))
    Toggle(gr, V['gpu'], 'Use the graphics card (OpenCL)',
           'NVIDIA or AMD with OpenCL drivers. unmicro checks the GPU against the CPU first and falls back if it disagrees. Not used for the newer (GCM) files.',
           command=lambda: (dumb_changed(), refresh_review())).pack(side='left', fill='x', expand=True)
    Btn(gr, 'Check GPU', lambda: quick_run(['--gpu-info'], 'GPU check', need_license=False), 'ghost', small=True).pack(side='right', padx=(16, 0))
    g2 = tk.Frame(c, bg=C['card'])
    g2.pack(fill='x', pady=(4, 0))
    lbl(g2, 'Stop after this many guesses (blank = never)').grid(row=0, column=0, sticky='w')
    mc_entry = entry(g2, V['max_candidates'], width=14)
    mc_entry.grid(row=0, column=1, sticky='e', ipady=3)
    lbl(g2, 'Search passes (each pass looks for another key for files still locked)').grid(row=1, column=0, sticky='w', pady=(10, 0))
    spin(g2, V['max_passes'], 1, 64).grid(row=1, column=1, sticky='e', pady=(10, 0))
    g2.columnconfigure(0, weight=1)
    ck = tk.Frame(c, bg=C['card'])
    ck.pack(fill='x', pady=(14, 0))
    Toggle(ck, V['checkpoint_on'], 'Save progress so a stopped search can resume',
           'Recommended for long runs. Leave the file name blank to keep it in the output folder.', command=lambda: refresh_review()).pack(fill='x')
    path_row(ck, V['checkpoint'], 'save', None)

    adv = card(P, 'Advanced')
    a1 = tk.Frame(adv, bg=C['card'])
    a1.pack(fill='x')
    lbl(a1, 'Duplicate-suppression memory per generator (lower on a small-memory machine)').pack(side='left')
    spin(a1, V['seen_cap'], 10000, 100000000, width=12, inc=100000).pack(side='right')
    Toggle(adv, V['pure_python'], 'Use the built-in AES (much slower)', 'Ignore the bundled fast AES library. Only for troubleshooting.', command=lambda: refresh_review()).pack(fill='x', pady=(12, 0))
    nav_buttons(P, 'keys', 'output')

    # ======================= Output =======================
    P = add_page('output', '4  Output')
    page_title(P, 'Recovered files', 'Step 4 of 5 \u00b7 where and how')
    c = card(P, 'Save recovered files to')
    path_row(c, V['out'], 'dir', None, note='A new folder is best. Your encrypted files are never changed, renamed or deleted; recovered copies go here.')
    Toggle(c, V['identify'], 'Only find the key, write nothing', 'A key check: reports which key opens which files and saves nothing (--identify).', command=lambda: refresh_review()).pack(fill='x', pady=(4, 0))
    c = card(P, 'Layout')
    Toggle(c, V['flat'], 'Put everything in one folder', 'Off: recovered files mirror their original folders, so same-named files never collide.', command=lambda: refresh_review()).pack(fill='x', pady=(0, 12))
    Toggle(c, V['overwrite'], 'Overwrite files that already exist', 'Off: a name collision gets a numeric suffix instead.', command=lambda: refresh_review()).pack(fill='x', pady=(0, 12))
    Toggle(c, V['fix_ext'], 'Fix swapped extensions', 'This crew randomises extensions. On: a recovered video named .jpg is saved as .mp4, and the swap is reported. Bytes are never changed.', command=lambda: refresh_review()).pack(fill='x')
    c = card(P, 'Checking recovered files')
    Choice(c, V['verify'], [
        ('normal', 'Normal (recommended)', 'Write files whose structure checks out, and files the proven key opens cleanly but whose type cannot be checked (marked .UNVERIFIED).'),
        ('strict', 'Strict', 'Write only files that pass a structural check (--strict).'),
        ('keep', 'Keep everything', 'Also write files that failed the check, suffixed .UNVERIFIED (--keep-unverified).'),
    ], command=lambda: refresh_review(), columns=3).pack(fill='x')
    nav_buttons(P, 'search', 'run', 'Next: Review and run  \u2192')

    # ======================= Run =======================
    P = add_page('run', '5  Run')
    page_title(P, 'Review and run', 'Step 5 of 5')
    rv = card(P, 'Review')
    review_lines = tk.Frame(rv, bg=C['card'])
    review_lines.pack(fill='x')
    cmd_box = tk.Text(rv, height=3, bg=C['input'], fg=C['info'], relief='flat', highlightthickness=1, highlightbackground=C['border'],
                      font=F['monos'], wrap='word', padx=10, pady=8)
    cmd_box.pack(fill='x', pady=(10, 0))
    ctl = tk.Frame(rv, bg=C['card'])
    ctl.pack(fill='x', pady=(14, 0))
    start_btn = Btn(ctl, 'Start', lambda: start_run(), 'primary')
    start_btn.pack(side='left')
    stop_btn = Btn(ctl, 'Stop and recover what is matched', lambda: stop_run(), 'ghost')
    stop_btn.pack(side='left', padx=(8, 0))
    kill_btn = Btn(ctl, 'Force stop', lambda: kill_run(), 'danger')
    kill_btn.pack(side='left', padx=(8, 0))
    Btn(ctl, 'Copy command', lambda: (root.clipboard_clear(), root.clipboard_append(cmd_box.get('1.0', 'end').strip())), 'ghost', small=True).pack(side='right')
    Btn(ctl, 'Open output folder', lambda: open_path_(snapshot().get('out')), 'ghost', small=True).pack(side='right', padx=(0, 8))
    stop_btn.set_enabled(False)
    kill_btn.set_enabled(False)

    # stat tiles
    tiles = tk.Frame(P, bg=C['body'])
    tiles.pack(fill='x', pady=(0, 18))
    tile_vals = {}
    for i, (key, title) in enumerate((('step', 'Step'), ('tried', 'Keys tried'), ('rate', 'Speed'), ('elapsed', 'Elapsed'), ('found', 'Keys found'))):
        t = tk.Frame(tiles, bg=C['card'])
        t.grid(row=0, column=i, sticky='nsew', padx=(0 if i == 0 else 14, 0))
        tiles.columnconfigure(i, weight=1, uniform='t')
        lbl(t, title, fg=C['bright'], font=F['h']).pack(anchor='w', padx=16, pady=(12, 0))
        v = lbl(t, '\u2013', fg=C['primary'], font=F['num'])
        v.pack(anchor='w', padx=16, pady=(4, 0))
        sub = lbl(t, '', fg=C['faint'], font=F['tiny'])
        sub.pack(anchor='w', padx=16, pady=(0, 12))
        tile_vals[key] = (v, sub)

    def tile(key, value, sub=None, color=None):
        v, s = tile_vals[key]
        v.configure(text=value, fg=color or C['primary'])
        if sub is not None:
            s.configure(text=sub)

    mid = tk.Frame(P, bg=C['body'])
    mid.pack(fill='x', pady=(0, 18))
    mid.columnconfigure(0, weight=3, uniform='m')
    mid.columnconfigure(1, weight=2, uniform='m')
    lc = tk.Frame(mid, bg=C['card'])
    lc.grid(row=0, column=0, sticky='nsew', padx=(0, 14))
    lcb = tk.Frame(lc, bg=C['card'])
    lcb.pack(fill='both', expand=True, padx=20, pady=16)
    lbl(lcb, 'Current method', fg=C['bright'], font=F['h']).pack(anchor='w')
    method_l = lbl(lcb, 'Not started', fg=C['text'])
    method_l.pack(anchor='w', pady=(6, 6))
    len_bar = ttk.Progressbar(lcb, mode='determinate', maximum=1000)
    len_bar.pack(fill='x')
    len_l = lbl(lcb, '', fg=C['faint'], font=F['tiny'])
    len_l.pack(anchor='w', pady=(4, 0))
    result_l = lbl(lcb, '', fg=C['bright'], font=F['big'], wraplength=620)
    result_l.pack(anchor='w', pady=(12, 0))
    counts_l = lbl(lcb, '', fg=C['muted'], font=F['small'], wraplength=620)
    counts_l.pack(anchor='w')

    rc_ = tk.Frame(mid, bg=C['card'])
    rc_.grid(row=0, column=1, sticky='nsew')
    rcb = tk.Frame(rc_, bg=C['card'])
    rcb.pack(fill='both', expand=True, padx=20, pady=16)
    lbl(rcb, 'This machine', fg=C['bright'], font=F['h']).pack(anchor='w', pady=(0, 6))
    meters = {}
    for key, title in METERS:
        f = tk.Frame(rcb, bg=C['card'])
        f.pack(fill='x', pady=(3, 0))
        lbl(f, title, fg=C['muted'], font=F['small']).pack(side='left')
        vl = lbl(f, 'n/a', fg=C['text'], font=F['small'])
        vl.pack(side='right')
        pb = ttk.Progressbar(rcb, mode='determinate', maximum=100)
        pb.pack(fill='x', pady=(2, 0))
        meters[key] = (vl, pb)
    ttf_l = lbl(rcb, '', fg=C['warning'], font=F['bold'], wraplength=420)
    ttf_l.pack(anchor='w', pady=(10, 0))
    ttf_sub = lbl(rcb, '', fg=C['faint'], font=F['tiny'], wraplength=420)
    ttf_sub.pack(anchor='w')

    logc = card(P, 'Output', 'what unmicro prints')
    log_f = tk.Frame(logc, bg=C['card'])
    log_f.pack(fill='both', expand=True)
    log = tk.Text(log_f, height=18, bg=C['input'], fg=C['text'], relief='flat', highlightthickness=1, highlightbackground=C['border'],
                  font=F['mono'], wrap='word', padx=12, pady=10, state='disabled')
    lsb = ttk.Scrollbar(log_f, orient='vertical', command=log.yview)
    log.configure(yscrollcommand=lsb.set)
    log.pack(side='left', fill='both', expand=True)
    lsb.pack(side='right', fill='y')
    for tag, col in (('ok', C['success']), ('warn', C['warning']), ('err', C['danger']), ('info', C['muted']), ('stage', C['primary']), ('gui', C['info']), ('t', C['faint'])):
        log.tag_configure(tag, foreground=col)
    log.tag_configure('stage', font=(MONO, 9, 'bold'))

    def log_write(text, tag=None):
        log.configure(state='normal')
        at_end = log.yview()[1] > 0.98
        log.insert('end', text + '\n', (tag,) if tag else ())
        n = int(log.index('end-1c').split('.')[0])
        if n > 6000:
            log.delete('1.0', '%d.0' % (n - 5000))
        if at_end:
            log.see('end')
        log.configure(state='disabled')

    def gui_note(text):
        log_write('[gui] ' + text, 'gui')

    # ======================= Settings =======================
    P = add_page('settings', 'Settings')
    page_title(P, 'Settings', 'engine, safety limits, profiles')
    c = card(P, 'Engine', 'the unmicro program this window runs')
    eng_row = row(c)
    eng_combo_var = V['engine']
    eng_e = entry(eng_row, eng_combo_var, width=70, mono=True)
    eng_e.pack(side='left', fill='x', expand=True, ipady=5)

    def browse_engine():
        p = filedialog.askopenfilename(parent=root, filetypes=[('unmicro', 'unmicro*'), ('All files', '*')])
        if p:
            V['engine'].set(os.path.normpath(p))
            check_engine()
    Btn(eng_row, 'Browse\u2026', browse_engine, 'ghost', small=True).pack(side='left', padx=(8, 0))
    Btn(eng_row, 'Use the built-in engine', lambda: (V['engine'].set(''), check_engine()), 'ghost', small=True).pack(side='left', padx=(8, 0))
    lbl(c, '"built-in" is the engine inside this program, and the right choice almost always. To test another version, choose an unmicro release binary or unmicro.py instead. Only use a copy downloaded from the Rho-9-Official GitHub repository, with its checksum verified.',
        fg=C['faint'], font=F['tiny'], wraplength=900).pack(anchor='w', pady=(0, 10))
    py_row = row(c)
    lbl(py_row, 'Python for unmicro.py (blank = this one)', fg=C['muted'], font=F['small']).pack(side='left')
    entry(py_row, V['python'], width=40, mono=True).pack(side='right', ipady=3)
    eng_out = lbl(c, '', fg=C['muted'], font=F['small'], wraplength=900)
    eng_out.pack(anchor='w', pady=(4, 8))
    eb = row(c, pady=(0, 0))
    Btn(eb, 'Version', lambda: quick_run(['--version'], 'Version', need_license=False), 'ghost', small=True).pack(side='left')
    Btn(eb, 'Self-test', lambda: quick_run(['--self-test'], 'Self-test', need_license=False), 'ghost', small=True).pack(side='left', padx=(8, 0))
    Btn(eb, 'GPU info', lambda: quick_run(['--gpu-info'], 'GPU check', need_license=False), 'ghost', small=True).pack(side='left', padx=(8, 0))

    c = card(P, 'Safety limits', 'used by "Run until this machine cannot take it any more"')
    lbl(c, 'The endless run is watched every 5 seconds. If a limit holds for 30 seconds, the GUI stops the search cleanly and recovers every file already matched to a key. Progress is kept, so it can resume.',
        fg=C['muted'], font=F['small'], wraplength=900).pack(anchor='w', pady=(0, 10))
    lg = tk.Frame(c, bg=C['card'])
    lg.pack(fill='x')
    for i, (k, text, lo, hi) in enumerate((('max_temp', 'Stop when the CPU is hotter than (\u00b0C)', 50, 110),
                                            ('max_ram', 'Stop when memory use is above (%)', 50, 99),
                                            ('min_disk_gb', 'Stop when free disk on the output drive is below (GB)', 1, 500),
                                            ('min_battery', 'Stop when on battery and below (%)', 1, 90))):
        lbl(lg, text).grid(row=i, column=0, sticky='w', pady=4)
        spin(lg, LIM[k], lo, hi, width=6).grid(row=i, column=1, sticky='e', pady=4)
    lg.columnconfigure(0, weight=1)

    c = card(P, 'Profiles')
    lbl(c, 'Settings are saved automatically when the window closes (to %s). Save or load a named profile here, for example one per case.' % cfg_path,
        fg=C['muted'], font=F['small'], wraplength=900).pack(anchor='w', pady=(0, 10))
    pr = row(c, pady=(0, 0))

    def save_profile():
        p = filedialog.asksaveasfilename(parent=root, defaultextension='.json', filetypes=[('Profile', '*.json')])
        if p:
            s = snapshot()
            s['remember_license'] = False
            save_config(p, s)
            gui_note('profile saved: %s (licence not included)' % p)

    def load_profile():
        p = filedialog.askopenfilename(parent=root, filetypes=[('Profile', '*.json')])
        if p:
            apply_cfg(load_config(p))
            gui_note('profile loaded: %s' % p)

    def reset_defaults():
        if dialog('Reset every setting?', lambda f, s: lbl(f, 'All tabs go back to their defaults. The licence and engine stay.', wraplength=560).pack(anchor='w'),
                  [('Cancel', False, 'ghost'), ('Reset', True, 'danger')]):
            d = load_config('')
            d['license'] = V['license'].get()
            d['engine'] = V['engine'].get()
            apply_cfg(d)
    Btn(pr, 'Save profile\u2026', save_profile, 'ghost', small=True).pack(side='left')
    Btn(pr, 'Load profile\u2026', load_profile, 'ghost', small=True).pack(side='left', padx=(8, 0))
    Btn(pr, 'Reset to defaults', reset_defaults, 'danger', small=True).pack(side='left', padx=(8, 0))

    def apply_cfg(d):
        for k, v in V.items():
            if k in d:
                try:
                    v.set(d[k])
                except tk.TclError:
                    pass
        if not V['workers'].get():
            V['workers'].set(cpu_n)
        for k in lists:
            lists[k] = list(d.get(k, []))
        for k, v in LIM.items():
            v.set(d.get('limits', {}).get(k, DEFAULTS['limits'][k]))
        keys_text.delete('1.0', 'end')
        keys_text.insert('1.0', '\n'.join(d.get('keys', [])))
        sync_paths()
        sync_roots()
        sync_sc()
        src_changed()
        dumb_changed()
        workers_changed()

    # ======================= Help =======================
    P = add_page('help', 'Help')
    page_title(P, 'Help', 'Rho-9 Systems \u00b7 your first line of unusual defense')
    c = card(P, 'If you have just been hit, read this first')
    for t in ('1.  Do not pay. There is no guarantee of recovery and it funds the next round of victims.',
              '2.  Their "decryption" is a command run by their bot on your still-infected machine. Do not keep the infection alive for it.',
              '3.  Do not wipe the machine or delete the encrypted files. Copy them to an external drive before anything else.',
              '4.  If the machine is still on and infected, leave it powered on and take it off the network. The key may still be in memory.',
              '5.  This crew disables Windows Recovery, Task Manager and Regedit, and adds a Defender exclusion. Check what is left.',
              '6.  When you post about this anywhere, use the phrase "Chattering Magpies".'):
        lbl(c, t, wraplength=1000).pack(anchor='w', pady=2)
    c = card(P, 'How to use this window')
    for t in ('Files: choose where the .cryptedmicro files are, or search the whole computer. "Find files" previews them; nothing is changed.',
              'Keys: enter the licence key and any keys you know. Check licence confirms it and loads the recovered keys this build knows.',
              'Search: Quick takes seconds and is often enough. Standard and Deep guess harder. The structural brute force tries every key by length.',
              'Output: where recovered copies go. Your encrypted files are opened read-only and never changed.',
              'Run: review the plan and the exact command, then Start. "Stop and recover" ends the search and still saves every file already matched to a key.'):
        lbl(c, '\u2022  ' + t, wraplength=1000).pack(anchor='w', pady=2)
    c = card(P, 'Reading the result')
    for t in ('OK: decrypted and structurally verified.',
              'PROVEN: the key was proved on another file; this one decrypted cleanly but its type cannot be checked. Saved with a .UNVERIFIED suffix.',
              'Damaged: left half-written when the attack was interrupted. No key can fix these; restore them from backups if you have any.',
              'Still locked: intact, but no key found yet. Most often the attack was run again with a different key: search harder.'):
        lbl(c, '\u2022  ' + t, wraplength=1000).pack(anchor='w', pady=2)
    lbl(c, 'Keep your encrypted copies until you have opened the recovered files and are satisfied.', fg=C['warning'], wraplength=1000).pack(anchor='w', pady=(8, 0))
    c = card(P, 'Contact')
    lbl(c, 'Licence keys and cases: %s (mention "Chattering Magpies"). unmicro GUI %s, a front end for the unmicro command-line tool.' % (CONTACT, APP_VERSION), wraplength=1000).pack(anchor='w')

    # ======================= logic =======================
    state = {'job': None, 'buf': {'out': '', 'err': ''}, 'tier': None, 'tier_start': 0, 'found': [], 'step': None,
             't0': None, 'tried': 0, 'rate': 0.0, 'endless': False, 'stop_reason': None, 'limit_hits': {},
             'pending_stop': False, 'stop_sent': None, 'file_list_tmp': None, 'workers_used': None, 'gpu_used': False,
             'rates': [], 'verdict': None, 'counts': {}, 'gate_when': None}
    res_mon = Resources()

    def open_path_(p):
        err = open_path(p)
        if err:
            message('Could not open', err)

    def engine():
        return Engine(V['engine'].get().strip(), V['python'].get().strip())

    def check_engine():
        e = engine()
        if not e.available():
            cands = Engine.candidates()
            if cands:
                V['engine'].set(cands[0])
                e = engine()
        if not e.available():
            set_engine_chip('not found', C['danger'])
            eng_out.configure(text='No engine found. Press "Use the built-in engine", or choose an unmicro binary with Browse.', fg=C['danger'])
            return

        def work():
            rc, out = e.quick(['--version'], timeout=60)
            root.after(0, lambda: engine_result(rc, out))
        set_engine_chip('checking\u2026', C['warning'])
        threading.Thread(target=work, daemon=True).start()

    def engine_result(rc, out):
        ok, chip_text, detail, ver = engine_verdict(rc, out)
        set_engine_chip(chip_text, C['success'] if ok else C['danger'])
        eng_out.configure(text=detail, fg=C['success'] if ok else C['danger'])
        if ver:
            cfg['engine_version'] = ver

    def lic_env():
        return {LICENSE_ENV: V['license'].get().strip()}

    def check_license():
        if not V['license'].get().strip():
            lic_status.configure(text='Enter a licence key first.', fg=C['warning'])
            return
        e = engine()
        lic_status.configure(text='Checking\u2026', fg=C['muted'])
        check_btn.set_enabled(False)

        def work():
            rc, out = e.quick(['--list-keys'], env=lic_env(), timeout=120)
            root.after(0, lambda: license_result(rc, out))
        threading.Thread(target=work, daemon=True).start()

    def license_result(rc, out):
        check_btn.set_enabled(True)
        kd = keydata_from_list(out, cfg.get('engine_version')) if rc == 0 else None
        if kd:
            cfg['keydata'] = kd
            keys = kd['keys']
            lic_status.configure(text='Licence OK. This build knows %d recovered keys (longest %d characters).' % (len(keys), cfg['keydata']['max_len']), fg=C['success'])
            set_license_chip('OK \u00b7 %d keys' % len(keys), C['success'])
            if V['dumb'].get():
                draw_estimates()
        else:
            lic_status.configure(text='Licence not accepted: %s' % (out.strip().splitlines()[-1] if out.strip() else 'no output'), fg=C['danger'])
            set_license_chip('not accepted', C['danger'])

    def quick_run(args, title, need_license=True):
        e = engine()
        env = lic_env() if need_license else {}

        def work():
            rc, out = e.quick(args, env=env, timeout=180)
            root.after(0, lambda: show_output(title, rc, out))
        threading.Thread(target=work, daemon=True).start()
        gui_note('%s: running %s' % (title, ' '.join(args)))

    def show_output(title, rc, out):
        def body(f, _):
            t = textbox(f, height=min(24, max(6, out.count('\n') + 2)))
            t.insert('1.0', out.strip() or '(no output)')
            t.configure(state='disabled', wrap='word', width=90)
            t.pack(fill='both', expand=True)
        dialog('%s (exit code %s)' % (title, rc), body, [('Close', True, 'primary')], danger=rc != 0, width=760)

    def refresh_review(*_):
        if not ready['v']:
            return
        try:
            s = snapshot()
        except Exception:
            return
        for wdg in review_lines.winfo_children():
            wdg.destroy()
        for i, (k, v) in enumerate(summary(s, cpu_n)):
            lbl(review_lines, k, fg=C['muted'], font=F['small']).grid(row=i, column=0, sticky='nw', padx=(0, 18), pady=2)
            lbl(review_lines, v, fg=C['danger'] if 'CANNOT' in v else C['bright'], wraplength=900).grid(row=i, column=1, sticky='w', pady=2)
        probs = problems(s)
        for j, p in enumerate(probs):
            lbl(review_lines, '!  ' + p, fg=C['warning'], font=F['small']).grid(row=20 + j, column=0, columnspan=2, sticky='w', pady=(4 if j == 0 else 0, 0))
        e = engine()
        cmd_box.configure(state='normal')
        cmd_box.delete('1.0', 'end')
        cmd_box.insert('1.0', command_preview(e, s))
        cmd_box.configure(state='disabled')
        if not (state['job'] and state['job'].running()):
            start_btn.set_enabled(not probs and e.available())

    # ---------- running -----------
    def start_run():
        s = snapshot()
        probs = problems(s)
        if probs:
            message('Not ready yet', '\n'.join(probs))
            return
        e = engine()
        if not e.available():
            message('No engine', 'Choose the unmicro program on the Settings tab.', 'danger')
            show('settings')
            return
        endless = s['dumb'] and s['dumb_mode'] == 'endless'
        if endless and not endless_warning(s):
            return
        if not s['identify']:
            try:
                os.makedirs(s['out'], exist_ok=True)
            except OSError as ex:
                message('Cannot use the output folder', str(ex), 'danger')
                return
        if s.get('checkpoint_on') and s.get('checkpoint'):
            try:
                os.makedirs(os.path.dirname(s['checkpoint']) or '.', exist_ok=True)
            except OSError:
                pass
        flp = None
        if s['source'] == 'folders' and len(s['paths']) > 1:
            gui_note('collecting the files from %d places into a file list\u2026' % len(s['paths']))
            flp = write_file_list(s['paths'], s['recursive'])
            if not flp:
                message('No encrypted files', 'No .cryptedmicro files were found in the places you chose.')
                return
            state['file_list_tmp'] = flp
        args = build_args(s, flp)
        argv = e.argv(args)
        env = dict(os.environ)
        env.update(lic_env())
        save_config(cfg_path, s)
        # reset state
        state.update({'buf': {'out': '', 'err': ''}, 'tier': None, 'tier_start': 0, 'found': [], 'step': None, 't0': time.time(),
                      'tried': 0, 'rate': 0.0, 'endless': endless, 'stop_reason': None, 'limit_hits': {}, 'pending_stop': False,
                      'stop_sent': None, 'workers_used': s['workers'] or cpu_n, 'gpu_used': s['gpu'], 'rates': [], 'verdict': None,
                      'counts': {}, 'gate_when': None, 'hits': 0, 'out': s['out'], 'charset': s['charset'], 'ckpt': s.get('checkpoint')})
        log.configure(state='normal')
        log.delete('1.0', 'end')
        log.configure(state='disabled')
        gui_note('started %s' % time.strftime('%Y-%m-%d %H:%M:%S'))
        gui_note(' '.join(quote_arg(x) for x in argv))
        for k in tile_vals:
            tile(k, '\u2013', '')
        result_l.configure(text='')
        counts_l.configure(text='')
        method_l.configure(text='Starting\u2026')
        len_bar.configure(value=0)
        len_l.configure(text='')
        try:
            job = Job(argv, env, cwd=s['out'] if s['out'] and os.path.isdir(s['out']) else None, builtin=e.path == BUILTIN)
            job.start()
        except Exception as ex:
            message('Could not start unmicro', str(ex), 'danger')
            return
        state['job'] = job
        start_btn.set_enabled(False)
        stop_btn.set_enabled(True)
        kill_btn.set_enabled(True)
        set_run_chip('Endless run' if endless else 'Running', C['danger'] if endless else C['warning'])
        root.after(100, pump)
        root.after(1000, tick)

    def pump():
        job = state['job']
        if job is None:
            return
        try:
            for _ in range(2000):
                tag, data = job.q.get_nowait()
                if tag == 'exit':
                    finished(data)
                    return
                feed(tag, data)
        except queue.Empty:
            pass
        check_prompt()
        root.after(100, pump)

    def feed(tag, text):
        lines, state['buf'][tag] = split_lines(state['buf'][tag] + text)
        for line, sep in lines:
            handle_line(tag, line, sep)

    def handle_line(tag, line, sep):
        kind, d = parse_line(line)
        if kind == 'progress':
            name = d['name']
            if name != state['tier']:
                state['tier'] = name
                state['tier_start'] = state['tried']
            state['tried'] = d['tried']
            state['rate'] = d['rate']
            if 'structural brute' in name and d['rate'] > 0:
                state['rates'].append(d['rate'])
                state['rates'] = state['rates'][-50:]
            update_progress(d)
            return
        if kind == 'plainprogress':
            state['tried'] = d['tried']
            method_l.configure(text=d['name'])
            return
        if not line.strip() and tag == 'err':
            return
        log_write(line, classify_tag(line))
        if kind == 'step':
            state['step'] = d
            tile('step', '%d / %d' % (d['n'], d['of']), d['title'])
        elif kind == 'tier':
            if d['hit']:
                state['hits'] = state.get('hits', 0) + 1
                gui_note('a key opened files (%s)' % d['name'])
                if not state['found']:
                    tile('found', str(state['hits']), 'named when the search ends', C['success'])
        elif kind == 'found':
            state['found'].append(d['key'])
            tile('found', str(len(state['found'])), ', '.join(repr(k) for k in state['found'])[:60], C['success'])
        elif kind == 'result':
            state['verdict'] = d['verdict']
            ok = d['verdict'].startswith('ALL')
            result_l.configure(text=d['verdict'], fg=C['success'] if ok else C['warning'])
        elif kind == 'count':
            state['counts'][d['what']] = d['n']
            counts_l.configure(text='   '.join('%s: %s' % (k.split(' (')[0], fmt_count(v)) for k, v in state['counts'].items()))
        elif kind == 'gatetime':
            state['gate_when'] = d['when']

    def update_progress(d):
        name = d['name']
        tile('tried', fmt_count(d['tried']), name[:30])
        tile('rate', '%s/s' % fmt_count(d['rate']), '%d worker(s)%s' % (state['workers_used'], ' + GPU' if state['gpu_used'] else ''))
        lp = length_progress(name, d['tried'], state['tier_start'], d['rate'], *alpha_and_max(cfg, state.get('charset', 'turkish')))
        if lp:
            len_bar.configure(value=lp['frac'] * 1000)
            method_l.configure(text=lp['method'])
            len_l.configure(text=lp['detail'])
        else:
            method_l.configure(text=('GCM: ' if d['gcm'] else '') + name)
            len_bar.configure(value=0)
            len_l.configure(text='')

    def check_prompt():
        job = state['job']
        tail = state['buf']['out']
        if not tail or job is None:
            return
        pr = classify_prompt(tail)
        kind = pr[0] if pr else None
        if kind == 'pause':
            log_write(tail)
            state['buf']['out'] = ''
            choice = '2'
            if not state['pending_stop']:
                # Not asked for by us (should not happen): ask the person.
                choice = '1' if dialog('Search paused', lambda f, s: lbl(f, 'unmicro paused the search. Keep searching, or stop and recover the files already matched?', wraplength=560).pack(anchor='w'),
                                       [('Stop and recover', False, 'ghost'), ('Keep searching', True, 'primary')]) else '2'
            gui_note('answering the pause menu: %s' % ('stop and recover the matched files' if choice == '2' else 'keep searching'))
            job.send(choice + '\n')
            if choice == '1':
                state['pending_stop'] = False
        elif kind == 'gate':
            log_write(tail)
            state['buf']['out'] = ''
            L = pr[1]
            when = state.get('gate_when') or 'a long time'
            yes = dialog('Keep going into %d-character keys?' % L,
                         lambda f, s: lbl(f, 'Every shorter key has been tried with no match. Keys of exactly %d characters would take roughly %s on this machine, and each length after it is far longer.\n\nYou can stop here and recover nothing new, or keep going (progress is saved if "Save progress" is on).' % (L, when),
                                          wraplength=580).pack(anchor='w'),
                         [('Stop here', False, 'ghost'), ('Keep going', True, 'primary')])
            gui_note('length %d: %s' % (L, 'keep going' if yes else 'stop here'))
            job.send('y\n' if yes else 'n\n')
        elif kind == 'close':
            state['buf']['out'] = ''
            job.send('\n')
        elif kind == 'license':
            state['buf']['out'] = ''
            gui_note('unmicro asked for a licence key: it did not get one. Stopping.')
            job.kill()

    def tick():
        job = state['job']
        if job is None:
            return
        el = time.time() - (state['t0'] or time.time())
        tile('elapsed', '%d:%02d:%02d' % (el // 3600, el % 3600 // 60, el % 60), time.strftime('since %H:%M', time.localtime(state['t0'])))
        if time.time() - state.get('last_mon', 0) >= 5:
            state['last_mon'] = time.time()
            monitor()
        if state['stop_sent'] and time.time() - state['stop_sent'] > 120 and job.running():
            gui_note('unmicro has not stopped 2 minutes after the request; you can use Force stop.')
            state['stop_sent'] = time.time() + 1e9
        root.after(1000, tick)

    def monitor():
        s = res_mon.sample(state.get('out'))
        lims = {k: v.get() for k, v in LIM.items()}
        styles = {'bad': 'Bad.Horizontal.TProgressbar', 'warn': 'Warn.Horizontal.TProgressbar'}
        for key, (text, frac, tone) in meter_readings(s, lims).items():
            vl, pb = meters[key]
            vl.configure(text=text, fg={'bad': C['danger'], 'warn': C['warning']}.get(tone, C['text']))
            pb.configure(value=frac, style=styles.get(tone, 'Horizontal.TProgressbar'))
        if not state['endless']:
            ttf_l.configure(text='')
            ttf_sub.configure(text='')
            return
        # time to failure
        alpha, maxlen = alpha_and_max(cfg, state.get('charset', 'turkish'))
        rate = live_rate(state['rates'], cfg, state['workers_used'], state['gpu_used'])
        search_secs = search_left_secs(alpha, maxlen, rate, state['tier'], state['tried'], state['tier_start'])
        head, sub = ttf_text(*time_to_failure(search_secs, s, lims, res_mon.slopes()))
        ttf_l.configure(text=head)
        ttf_sub.configure(text=sub)
        # safety limits
        tripped = limits_tripped(s, lims)
        if count_limit_hits(state['limit_hits'], tripped) and not state['pending_stop']:
            why = ', '.join(tripped.values())
            state['stop_reason'] = 'safety limit: ' + why
            gui_note('SAFETY LIMIT HIT (%s) for 30 seconds: stopping and recovering the matched files.' % why)
            stop_run(confirm=False)

    def stop_run(confirm=True):
        job = state['job']
        if not job or not job.running():
            return
        if confirm and not dialog('Stop the search?', lambda f, s: lbl(f, 'unmicro stops searching, then recovers every file already matched to a key. Files still locked stay locked; run again later to continue.', wraplength=560).pack(anchor='w'),
                                  [('Keep searching', False, 'ghost'), ('Stop and recover', True, 'primary')]):
            return
        state['pending_stop'] = True
        state['stop_sent'] = time.time()
        set_run_chip('Stopping\u2026', C['warning'])
        gui_note('asking unmicro to stop at the end of the current batch (a few seconds), then recover the files already matched')
        if not job.interrupt():
            gui_note('could not ask unmicro to stop; use Force stop')

    def kill_run():
        job = state['job']
        if not job or not job.running():
            return
        if dialog('Force stop?', lambda f, s: lbl(f, 'This ends unmicro at once. Files already matched are NOT recovered by this run (use "Stop and recover" for that). Your encrypted files are not affected.', wraplength=560).pack(anchor='w'),
                  [('Cancel', False, 'ghost'), ('Force stop', True, 'danger')], danger=True):
            gui_note('force stop')
            state['stop_reason'] = 'force stopped'
            job.kill()

    def finished(rc):
        job = state['job']
        for tag in ('out', 'err'):
            if state['buf'][tag].strip():
                handle_line(tag, state['buf'][tag], '')
            state['buf'][tag] = ''
        state['job'] = None
        el = time.time() - state['t0']
        gui_note('unmicro exited with code %s after %s' % (rc, fmt_duration(el)))
        # remember the measured speed for future estimates
        record_speed(cfg, state['rates'], state['workers_used'], state['gpu_used'])
        if state['file_list_tmp']:
            try:
                os.unlink(state['file_list_tmp'])
            except OSError:
                pass
            state['file_list_tmp'] = None
        start_btn.set_enabled(True)
        stop_btn.set_enabled(False)
        kill_btn.set_enabled(False)
        v = state['verdict']
        if v:
            set_run_chip(v.split(':')[0].title()[:28], C['success'] if v.startswith('ALL') else C['warning'])
        else:
            set_run_chip('Exited (%s)' % rc, C['danger'] if rc else C['faint'])
            if not v and rc not in (0, None):
                result_l.configure(text='unmicro stopped without a result (exit code %s). See the output below.' % rc, fg=C['danger'])
        if state.get('stop_reason'):
            counts_l.configure(text=counts_l.cget('text') + '\nStopped: %s' % state['stop_reason'])
        method_l.configure(text='Finished')
        len_l.configure(text='')
        len_bar.configure(value=0)
        refresh_review()

    def endless_warning(s):
        lims = {k: v.get() for k, v in LIM.items()}
        E = endless_estimate(cfg, s, cpu_n, res_mon.sample(s.get('out')), lims)
        maxlen, workers, rate, secs, why, details, measured = E['maxlen'], E['workers'], E['rate'], E['secs'], E['why'], E['details'], E['measured']

        def body(f, set_state):
            lbl(f, 'This search does not end by itself.', fg=C['bright'], font=F['bold']).pack(anchor='w')
            lbl(f, 'Every %s, with no guess limit and no questions, through every key length up to %d characters, '
                   'it pins all %d cores%s at 100%% for as long as it runs. The computer will be hot, loud and slow; a laptop will drain its battery.' % (
                       ('core and the GPU' if s['gpu'] else 'core'), maxlen, workers, ' and the GPU' if s['gpu'] else ''),
                wraplength=640).pack(anchor='w', pady=(4, 12))
            box = tk.Frame(f, bg=C['card2'], highlightthickness=1, highlightbackground=C['danger'])
            box.pack(fill='x')
            lbl(box, 'Estimated time to failure:  %s' % fmt_duration(secs), fg=C['danger'], font=F['big'], bg=C['card2']).pack(anchor='w', padx=14, pady=(10, 0))
            lbl(box, 'Limited by: %s' % phrase(why), fg=C['text'], bg=C['card2']).pack(anchor='w', padx=14)
            for name, v, note in details:
                lbl(box, '\u2022 %s: %s  (%s)' % (name, fmt_duration(v) if v is not None else 'measured once running', note), fg=C['muted'], font=F['small'], bg=C['card2']).pack(anchor='w', padx=14)
            lbl(box, 'In practice: every key up to %d characters is tried within a day, up to %d within a week, up to %d within a year.' % (
                E['day'], E['week'], E['year']),
                fg=C['text'], font=F['small'], bg=C['card2'], wraplength=620).pack(anchor='w', padx=14, pady=(6, 0))
            lbl(box, 'Speed assumed: %s keys/s %s.' % (
                fmt_count(rate), '(measured on this machine)' if measured else '(rough guess; the live figure replaces it once running)'),
                fg=C['faint'], font=F['tiny'], bg=C['card2'], wraplength=620).pack(anchor='w', padx=14, pady=(2, 10))
            lbl(f, 'Safety limits (Settings tab) stop it cleanly and recover every matched file: CPU over %d\u00b0C, memory over %d%%, under %d GB free disk, battery under %d%%. %s' % (
                       lims['max_temp'], lims['max_ram'], lims['min_disk_gb'], lims['min_battery'],
                       ('CPU temperature now: %.0f\u00b0C; the time to failure is refined from its trend once running.' % E['temp']) if E['temp'] is not None
                       else 'This machine gives no temperature reading, so overheating is left to the hardware\'s own protection.'),
                fg=C['muted'], font=F['small'], wraplength=640).pack(anchor='w', pady=(12, 8))
            ack = tk.BooleanVar(value=False)
            Toggle(f, ack, 'I understand: run until this machine cannot take it any more', command=lambda: set_state('go', ack.get())).pack(fill='x', pady=(4, 0))
            set_state('go', False)
        return dialog('Run until this machine cannot take it any more?', body,
                      [('Cancel', False, 'ghost'), ('Start the endless run', 'go', 'danger')], danger=True, width=720) == 'go'

    # ---------- wire-up -----------
    for name in ('level', 'charset', 'dumb_mode', 'out', 'source', 'file_list', 'wordlist', 'checkpoint', 'max_candidates', 'max_files', 'engine', 'python', 'max_passes', 'seen_cap'):
        V[name].trace_add('write', lambda *a: refresh_review())
    V['license'].trace_add('write', lambda *a: (set_license_chip('entered' if V['license'].get().strip() else 'not set', C['info'] if V['license'].get().strip() else C['danger']), refresh_review()))
    on_show['run'] = refresh_review
    on_show['search'] = lambda: V['dumb'].get() and draw_estimates()

    def on_close():
        job = state['job']
        if job and job.running():
            if not dialog('A search is running', lambda f, s: lbl(f, 'Closing the window stops unmicro. Stop and recover the matched files first, or force stop now?', wraplength=560).pack(anchor='w'),
                          [('Keep running', False, 'ghost'), ('Force stop and close', True, 'danger')], danger=True):
                return
            job.kill()
        s = snapshot()
        s['keydata'] = cfg.get('keydata', {})
        s['measured'] = cfg.get('measured', {})
        save_config(cfg_path, s)
        root.destroy()
    root.protocol('WM_DELETE_WINDOW', on_close)

    sync_paths()
    sync_roots()
    sync_sc()
    src_changed()
    dumb_changed()
    workers_changed()
    if cfg['keydata'].get('keys'):
        kd = cfg['keydata']
        set_license_chip(('OK \u00b7 %d keys' % len(kd['keys'])) if V['license'].get() else 'not set', C['success'] if V['license'].get() else C['danger'])
    else:
        set_license_chip('entered' if V['license'].get() else 'not set', C['info'] if V['license'].get() else C['danger'])
    ready['v'] = True
    refresh_review()
    show(os.environ.get('UNMICRO_GUI_TAB', 'files'))
    root.deiconify()
    root.after(200, check_engine)
    if os.environ.get('UNMICRO_GUI_TEST_HOOK'):
        # used by the screenshot harness: python code run after start-up
        ns = {'root': root, 'show': show, 'V': V, 'lists': lists, 'start_run': start_run, 'stop_run': stop_run, 'state': state,
              'endless_warning': endless_warning, 'snapshot': snapshot, 'sync_paths': sync_paths, 'check_license': check_license,
              'dumb_changed': dumb_changed, 'pages': pages, 'LIMV': LIM, 'find_files': find_files, 'dialog': dialog}
        exec(open(os.environ['UNMICRO_GUI_TEST_HOOK']).read(), ns)
    root.mainloop()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    rc = helper_main(argv)
    if rc is not None:
        return rc
    if argv[:1] in (['--version'], ['-V']):
        print('unmicro GUI %s' % APP_VERSION)
        return 0
    run_gui()
    return 0


if __name__ == '__main__':
    sys.exit(main())
