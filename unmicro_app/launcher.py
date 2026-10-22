#!/usr/bin/env python3
"""unmicro GUI launcher: pick the PySide6 UI (qt_ui) or the Tk UI
(tk_ui), and remember the choice in the settings file.

Falls back to the Tk UI when PySide6 is not installed. Run it with --choose
to see the menu again, or --qt / --tk to pick for this start only. This is
the program's entry point (python -m unmicro_app, and the built exe), and it
also runs the built-in engine: --cli for the command line, --engine for the
GUI's own runs.
"""
import os
import sys

from .core import (C, APP_VERSION, WINDOWS, builtin_available, config_dir, helper_main, load_config, run_engine,
                   save_config, win_std_streams)


def engine_version():
    import unmicro
    return unmicro.VERSION


def qt_available():
    try:
        import importlib.util
        return importlib.util.find_spec('PySide6') is not None
    except Exception:
        return False


def choose(current):
    """A small Tk menu. Returns 'qt', 'tk' or None (closed)."""
    import tkinter as tk
    root = tk.Tk()
    root.title('unmicro')
    root.configure(bg=C['card'])
    root.resizable(False, False)
    pick = tk.StringVar(value=current or 'qt')
    out = {'v': None}
    tk.Frame(root, bg=C['primary'], height=3).pack(fill='x')
    wrap = tk.Frame(root, bg=C['card'])
    wrap.pack(padx=26, pady=20)
    tk.Label(wrap, text='Which window should unmicro use?', bg=C['card'], fg=C['bright'], font=('TkDefaultFont', 12, 'bold')).pack(anchor='w')
    tk.Label(wrap, text='Both do the same job with the same settings. The choice is remembered; start with --choose to see this again.',
             bg=C['card'], fg=C['muted'], wraplength=440, justify='left').pack(anchor='w', pady=(4, 12))
    cards = {}
    for value, title, desc in (('qt', 'Modern (Qt)', 'Sharper on high-resolution screens. Needs PySide6.'),
                               ('tk', 'Classic (Tk)', 'Works everywhere Python does.')):
        f = tk.Frame(wrap, bg=C['card2'], highlightthickness=1, highlightbackground=C['border'], cursor='hand2')
        f.pack(fill='x', pady=(0, 8))
        rb = tk.Radiobutton(f, variable=pick, value=value, text=title, bg=C['card2'], fg=C['bright'], selectcolor=C['input'],
                            activebackground=C['card2'], activeforeground=C['bright'], font=('TkDefaultFont', 10, 'bold'), anchor='w',
                            highlightthickness=0, bd=0)
        rb.pack(fill='x', padx=10, pady=(8, 0))
        tk.Label(f, text=desc, bg=C['card2'], fg=C['muted'], anchor='w').pack(fill='x', padx=34, pady=(0, 8))
        for w in (f,) + tuple(f.winfo_children()):
            w.bind('<Button-1>', lambda e, v=value: pick.set(v), add='+')
        cards[value] = f

    def outline(*_):
        for v, f in cards.items():
            f.configure(highlightbackground=C['primary'] if pick.get() == v else C['border'])
    pick.trace_add('write', outline)
    outline()
    btns = tk.Frame(wrap, bg=C['card'])
    btns.pack(fill='x', pady=(8, 0))

    def go():
        out['v'] = pick.get()
        root.destroy()
    tk.Button(btns, text='Open', command=go, bg=C['primary'], fg='#ffffff', activebackground=C['primary_hover'],
              activeforeground='#ffffff', relief='flat', bd=0, highlightthickness=0, padx=18, pady=5).pack(side='right')
    tk.Button(btns, text='Cancel', command=root.destroy, bg=C['card'], fg=C['text'], activebackground=C['hover'],
              relief='flat', bd=0, highlightthickness=1, highlightbackground=C['border'], padx=14, pady=5).pack(side='right', padx=(0, 8))
    root.bind('<Return>', lambda e: go())
    root.bind('<Escape>', lambda e: root.destroy())
    if os.environ.get('UNMICRO_LAUNCHER_TEST_HOOK'):
        exec(open(os.environ['UNMICRO_LAUNCHER_TEST_HOOK']).read(), {'root': root, 'pick': pick, 'go': go})
    root.mainloop()
    return out['v']


def main(argv=None):
    # The engine's worker processes start as copies of the built exe; this
    # turns such a copy into a worker (and does nothing otherwise).
    import multiprocessing
    multiprocessing.freeze_support()
    argv = sys.argv[1:] if argv is None else argv
    rc = helper_main(argv)  # Windows console helper modes
    if rc is not None:
        return rc
    if argv[:1] in (['--engine'], ['--cli']):
        # --engine: the GUI running the built-in engine. --cli: a person who
        # wants the command line (its own console window on Windows when
        # nothing is redirected).
        if WINDOWS:
            win_std_streams(own_console=argv[0] == '--cli')
        return run_engine(argv[1:])
    if argv[:1] in (['--version'], ['-V']):
        ev = engine_version() if builtin_available() else None
        print('unmicro %s' % APP_VERSION if ev in (None, APP_VERSION) else 'unmicro %s (engine %s)' % (APP_VERSION, ev))
        return 0
    cfg_path = os.path.join(config_dir(), 'settings.json')
    cfg = load_config(cfg_path)
    has_qt = qt_available()
    if '--tk' in argv:
        ui = 'tk'
    elif '--qt' in argv:
        ui = 'qt'
    elif '--choose' in argv or cfg.get('ui') not in ('qt', 'tk'):
        if not has_qt:
            ui = 'tk'
        else:
            ui = choose(cfg.get('ui'))
            if ui is None:
                return 0
            cfg['ui'] = ui
            save_config(cfg_path, cfg)
    else:
        ui = cfg['ui']
    if ui == 'qt' and not has_qt:
        if sys.stderr:  # None in the windowed exe
            sys.stderr.write('PySide6 is not installed: using the Tk window.\n')
        ui = 'tk'
    if ui == 'qt':
        from . import qt_ui
        return qt_ui.run_gui() or 0
    from . import tk_ui
    tk_ui.run_gui()
    return 0


if __name__ == '__main__':
    sys.exit(main())
