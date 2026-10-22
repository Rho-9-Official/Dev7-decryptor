#!/usr/bin/env python3
"""unmicro GUI (PySide6): a desktop front end for the unmicro decryptor binary.

Rho-9 Systems. Styled after Aviary (Hyper dark).

Same tabs, wording and behaviour as the Tk UI (tk_ui.py), which is the
reference. Everything that is not a widget (the command line, the output
parser, process control, the estimates, the safety limits) comes from
core.py; this file only draws it. The GUI never decrypts anything
itself: it runs the already built unmicro binary (or unmicro.py) with a
terminal on its stdin, so unmicro's own pause menu and prompts work.
"""
import html
import os
import queue
import sys
import threading
import time

from .core import *  # noqa: F401,F403  (shared with the Tk UI)
from .core import helper_main


class Var(object):
    """A value shared by widgets (tk.Variable's role): get, set, and
    callbacks on change."""

    def __init__(self, value=None):
        self._v = value
        self._cbs = []

    def get(self):
        return self._v

    def set(self, v):
        if v != self._v:
            self._v = v
            for cb in list(self._cbs):
                cb()

    def trace(self, cb):
        self._cbs.append(cb)


def qss(F):
    """Aviary's Hyper dark theme as a Qt style sheet, from palette C."""
    return '''
* { font-family: "%(ui)s"; font-size: 13px; }
QWidget { color: %(text)s; }
QMainWindow, QWidget#body, QScrollArea, QScrollArea > QWidget > QWidget#page { background: %(body)s; }
QFrame#topbar, QFrame#nav { background: %(topbar)s; }
QFrame#navline { background: %(border)s; }
QFrame#chipsep { background: #4a5560; }
QPushButton#tab { background: transparent; color: %(navtext)s; border: none; border-bottom: 2px solid transparent;
    border-top: 2px solid transparent; padding: 0 16px; }
QPushButton#tab:hover { color: %(navhover)s; }
QPushButton#tab[active="true"] { color: %(primary)s; border-bottom-color: %(primary)s; }
QFrame#card { background: %(card)s; border-radius: 4px; }
QFrame#inset { background: %(card2)s; border: 1px solid %(border)s; border-radius: 3px; }
QFrame#dangerbox { background: %(card2)s; border: 1px solid %(danger)s; border-radius: 3px; }
QFrame#choice { background: %(card2)s; border: 1px solid %(border)s; border-radius: 3px; }
QFrame#choice[selected="true"] { border-color: %(primary)s; }
QFrame#choice:hover { border-color: %(muted)s; }
QFrame#choice[selected="true"]:hover { border-color: %(primary)s; }
QFrame#choice QLabel, QFrame#inset QLabel, QFrame#dangerbox QLabel { background: transparent; }
QDialog { background: %(card)s; }

QLabel[role="title"] { color: %(bright)s; font-size: 19px; font-weight: 600; }
QLabel[role="crumb"] { color: %(faint)s; font-size: 12px; }
QLabel[role="h"] { color: %(bright)s; font-weight: 600; }
QLabel[role="big"] { color: %(bright)s; font-size: 15px; font-weight: 600; }
QLabel[role="bold"] { color: %(bright)s; font-weight: 600; }
QLabel[role="muted"] { color: %(muted)s; font-size: 12px; }
QLabel[role="faint"] { color: %(faint)s; font-size: 11px; }
QLabel[role="num"] { color: %(primary)s; font-size: 26px; font-weight: 600; }
QLabel[role="mono"] { font-family: "%(mono)s"; font-size: 12px; }
QLabel[role="chipkey"] { color: %(faint)s; font-size: 11px; }
QLabel[role="chipval"] { color: %(bright)s; font-size: 12px; }
QLabel[role="wm"] { font-size: 22px; font-weight: 700; }

QPushButton { border-radius: 3px; padding: 7px 16px; border: 1px solid %(border)s; background: transparent; color: %(text)s; }
QPushButton[small="true"] { padding: 4px 10px; font-size: 12px; }
QPushButton[kind="primary"] { background: %(primary)s; color: #ffffff; border-color: %(primary)s; }
QPushButton[kind="primary"]:hover { background: %(primary_hover)s; border-color: %(primary_hover)s; }
QPushButton[kind="ghost"]:hover { background: %(hover)s; }
QPushButton[kind="danger"] { color: %(danger)s; border-color: %(danger)s; }
QPushButton[kind="danger"]:hover { background: #4a3a48; }
QPushButton:focus { border-color: %(bright)s; }
QPushButton:disabled, QPushButton[kind="danger"]:disabled { color: %(faint)s; border-color: %(border)s; background: transparent; }
QPushButton[kind="primary"]:disabled { background: %(border)s; }

QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QListWidget, QTreeWidget {
    background: %(input)s; color: %(bright)s; border: 1px solid %(border)s; border-radius: 3px;
    selection-background-color: %(primary)s; selection-color: #ffffff; }
QLineEdit { padding: 5px 8px; }
QLineEdit[mono="true"], QPlainTextEdit, QListWidget, QTreeWidget { font-family: "%(mono)s"; font-size: 12px; }
QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QListWidget:focus, QTreeWidget:focus { border-color: %(primary)s; }
QLineEdit:disabled, QSpinBox:disabled { background: %(card2)s; color: %(faint)s; }
QPlainTextEdit#cmd { color: %(info)s; font-size: 11px; }
QSpinBox { padding: 4px 6px; min-width: 70px; }
QSpinBox::up-button, QSpinBox::down-button { background: %(card2)s; border: none; width: 16px; }
QSpinBox::up-arrow { border-left: 4px solid transparent; border-right: 4px solid transparent; border-bottom: 5px solid %(muted)s; width: 0; height: 0; }
QSpinBox::down-arrow { border-left: 4px solid transparent; border-right: 4px solid transparent; border-top: 5px solid %(muted)s; width: 0; height: 0; }
QListWidget::item { padding: 3px 6px; }
QListWidget::item:selected, QTreeWidget::item:selected { background: %(hover)s; color: %(bright)s; }
QTreeWidget::item { height: 24px; }
QHeaderView::section { background: %(card2)s; color: %(muted)s; border: none; border-bottom: 1px solid %(border)s;
    padding: 5px 8px; font-weight: 600; font-family: "%(ui)s"; font-size: 13px; }

QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 0; }
QScrollBar::handle { background: %(thumb)s; border-radius: 4px; min-height: 24px; min-width: 24px; margin: 1px; }
QScrollBar::handle:hover { background: %(muted)s; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

QProgressBar { background: %(input)s; border: none; border-radius: 4px; max-height: 8px; min-height: 8px; }
QProgressBar::chunk { background: %(primary)s; border-radius: 4px; }
QProgressBar[tone="ok"]::chunk { background: %(success)s; }
QProgressBar[tone="warn"]::chunk { background: %(warning)s; }
QProgressBar[tone="bad"]::chunk { background: %(danger)s; }

QSlider::groove:horizontal { background: %(input)s; height: 6px; border-radius: 3px; }
QSlider::sub-page:horizontal { background: %(primary)s; border-radius: 3px; }
QSlider::handle:horizontal { background: #ffffff; border: 3px solid %(primary)s; width: 12px; height: 12px; margin: -6px 0; border-radius: 9px; }

QToolTip { background: %(card2)s; color: %(bright)s; border: 1px solid %(border)s; padding: 4px; }
QMenu { background: %(card2)s; border: 1px solid %(border)s; }
QMenu::item:selected { background: %(hover)s; }
''' % dict(C, ui=F['ui'], mono=F['mono'])


# ==========================================================================
# GUI
# ==========================================================================

def run_gui():
    from PySide6 import QtCore, QtGui, QtWidgets
    from PySide6.QtCore import Qt

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
    app.setApplicationName('unmicro')
    app.setStyle('Fusion')
    fams = set(QtGui.QFontDatabase.families())

    def pick(names, fallback):
        for n in names:
            if n in fams:
                return n
        return fallback
    F = {'ui': pick(['Cerebri Sans', 'Segoe UI', 'Helvetica Neue', 'Inter', 'Noto Sans', 'Ubuntu', 'Cantarell', 'DejaVu Sans'], 'Sans Serif'),
         'mono': pick(['Cascadia Mono', 'Consolas', 'Menlo', 'Roboto Mono', 'DejaVu Sans Mono', 'Liberation Mono', 'Noto Mono'], 'Monospace')}
    pal = app.palette()
    for role, col in ((QtGui.QPalette.Window, C['body']), (QtGui.QPalette.Base, C['input']), (QtGui.QPalette.Text, C['bright']),
                      (QtGui.QPalette.WindowText, C['text']), (QtGui.QPalette.Button, C['card2']), (QtGui.QPalette.ButtonText, C['text']),
                      (QtGui.QPalette.Highlight, C['primary']), (QtGui.QPalette.HighlightedText, '#ffffff'),
                      (QtGui.QPalette.ToolTipBase, C['card2']), (QtGui.QPalette.ToolTipText, C['bright'])):
        pal.setColor(role, QtGui.QColor(col))
    app.setPalette(pal)
    app.setStyleSheet(qss(F))

    cfg_path = os.path.join(config_dir(), 'settings.json')
    cfg = load_config(cfg_path)
    cpu_n = os.cpu_count() or 1

    class Bridge(QtCore.QObject):
        """Runs callables on the GUI thread (worker threads emit)."""
        call = QtCore.Signal(object)
    bridge = Bridge()
    bridge.call.connect(lambda fn: fn())

    def later(ms, fn):
        QtCore.QTimer.singleShot(ms, fn)

    # ---------------- logo (Aviary's bird) -----------------
    def paint_mark(p, size, eye=C['topbar']):
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        p.setBrush(QtGui.QColor(C['primary']))
        r = max(4, size // 5)
        p.drawRoundedRect(QtCore.QRectF(0, 0, size, size), r, r)
        sc, off = size * 0.6 / 24.0, size * 0.2
        p.setBrush(QtGui.QColor('#ffffff'))
        p.drawPolygon(QtGui.QPolygonF([QtCore.QPointF(x, y) for x, y in bird_polygon(sc, off, off)]))
        ex, ey, er = BIRD_EYE
        p.setBrush(QtGui.QColor(eye))
        p.drawEllipse(QtCore.QPointF(off + ex * sc, off + ey * sc), er * sc, er * sc)

    class Mark(QtWidgets.QWidget):
        def __init__(self, size=32):
            QtWidgets.QWidget.__init__(self)
            self.setFixedSize(size, size)

        def paintEvent(self, e):
            p = QtGui.QPainter(self)
            paint_mark(p, self.width())
            p.end()

    def icon():
        ic = QtGui.QIcon()
        for size in (16, 32, 64, 128):
            pm = QtGui.QPixmap(size, size)
            pm.fill(Qt.transparent)
            p = QtGui.QPainter(pm)
            paint_mark(p, size, eye=C['primary'])
            p.end()
            ic.addPixmap(pm)
        return ic

    # ---------------- small widget kit -----------------
    def restyle(w, prop, value):
        w.setProperty(prop, value)
        w.style().unpolish(w)
        w.style().polish(w)
        w.update()

    def lbl(text='', role=None, wrap=False, color=None, sel=False):
        w = QtWidgets.QLabel(text)
        if role:
            w.setProperty('role', role)
        if wrap:
            w.setWordWrap(True)
        if color:
            w.setStyleSheet('color: %s;' % color)
        if sel:
            w.setTextInteractionFlags(Qt.TextSelectableByMouse)
        return w

    def set_color(w, color):
        w.setStyleSheet('color: %s;' % color)

    class ClickLabel(QtWidgets.QLabel):
        clicked = QtCore.Signal()

        def mousePressEvent(self, e):
            if e.button() == Qt.LeftButton:
                self.clicked.emit()

    class Btn(QtWidgets.QPushButton):
        def __init__(self, text, cmd, kind='primary', small=False, width=None):
            QtWidgets.QPushButton.__init__(self, text)
            self.kind = kind
            self.setProperty('kind', kind)
            if small:
                self.setProperty('small', True)
            self.setCursor(Qt.PointingHandCursor)
            if width:
                self.setMinimumWidth(width)
            self.cmd = cmd
            self.clicked.connect(self._click)

        def _click(self, *_):
            if self.isEnabled() and self.cmd:
                self.cmd()

        def set_enabled(self, on):
            self.setEnabled(on)
            self.setCursor(Qt.PointingHandCursor if on else Qt.ArrowCursor)

        @property
        def enabled(self):
            return self.isEnabled()

    class Switch(QtWidgets.QAbstractButton):
        """Aviary's switch (.sw2)."""

        def __init__(self, var):
            QtWidgets.QAbstractButton.__init__(self)
            self.var = var
            self.setCursor(Qt.PointingHandCursor)
            self.setFixedSize(44, 22)
            self.setFocusPolicy(Qt.StrongFocus)

        def paintEvent(self, e):
            p = QtGui.QPainter(self)
            p.setRenderHint(QtGui.QPainter.Antialiasing)
            on, en = bool(self.var.get()), self.isEnabled()
            p.setPen(QtGui.QPen(QtGui.QColor(C['bright']), 1) if self.hasFocus() else Qt.NoPen)
            p.setBrush(QtGui.QColor((C['primary'] if on else C['border']) if en else C['hover']))
            p.drawRoundedRect(QtCore.QRectF(0.5, 0.5, 43, 21), 10.5, 10.5)
            p.setPen(Qt.NoPen)
            p.setBrush(QtGui.QColor('#ffffff' if en else C['faint']))
            x = 25 if on else 4
            p.drawEllipse(QtCore.QRectF(x, 3.5, 15, 15))
            p.end()

    class Toggle(QtWidgets.QWidget):
        """Label + note on the left, switch on the right."""

        def __init__(self, var, text, note=None, command=None):
            QtWidgets.QWidget.__init__(self)
            self.var, self.command = var, command
            h = QtWidgets.QHBoxLayout(self)
            h.setContentsMargins(0, 0, 0, 0)
            h.setSpacing(12)
            left = QtWidgets.QVBoxLayout()
            left.setSpacing(1)
            self.t = ClickLabel(text)
            self.t.setWordWrap(True)
            self.t.setCursor(Qt.PointingHandCursor)
            self.t.clicked.connect(self.flip)
            left.addWidget(self.t)
            if note:
                self.n = lbl(note, 'faint', wrap=True)
                left.addWidget(self.n)
            h.addLayout(left, 1)
            self.sw = Switch(var)
            self.sw.clicked.connect(self.flip)
            h.addWidget(self.sw, 0, Qt.AlignVCenter)
            self.enabled = True
            var.trace(self.sw.update)

        def flip(self, *_):
            if self.enabled:
                self.var.set(not self.var.get())
                if self.command:
                    self.command()

        def set_enabled(self, on):
            self.enabled = on
            self.sw.setEnabled(on)
            set_color(self.t, C['text'] if on else C['faint'])

    class Radio(QtWidgets.QWidget):
        def __init__(self):
            QtWidgets.QWidget.__init__(self)
            self.on = False
            self.setFixedSize(18, 18)

        def paintEvent(self, e):
            p = QtGui.QPainter(self)
            p.setRenderHint(QtGui.QPainter.Antialiasing)
            p.setPen(QtGui.QPen(QtGui.QColor(C['primary'] if self.on else C['muted']), 2))
            p.setBrush(Qt.NoBrush)
            p.drawEllipse(QtCore.QRectF(2, 2, 14, 14))
            if self.on:
                p.setPen(Qt.NoPen)
                p.setBrush(QtGui.QColor(C['primary']))
                p.drawEllipse(QtCore.QRectF(6, 6, 6, 6))
            p.end()

    class ChoiceCard(QtWidgets.QFrame):
        def __init__(self, owner, value, title, desc):
            QtWidgets.QFrame.__init__(self)
            self.setObjectName('choice')
            self.setCursor(Qt.PointingHandCursor)
            self.setFocusPolicy(Qt.StrongFocus)
            self.owner, self.value = owner, value
            g = QtWidgets.QGridLayout(self)
            g.setContentsMargins(12, 10, 12, 10)
            g.setHorizontalSpacing(8)
            g.setVerticalSpacing(2)
            self.radio = Radio()
            g.addWidget(self.radio, 0, 0, 2, 1, Qt.AlignTop)
            self.t = lbl(title, 'bold', wrap=True)
            g.addWidget(self.t, 0, 1)
            self.d = lbl(desc, 'muted', wrap=True)
            g.addWidget(self.d, 1, 1)
            g.setColumnStretch(1, 1)
            g.setRowStretch(2, 1)

        def mousePressEvent(self, e):
            if e.button() == Qt.LeftButton:
                self.owner.choose(self.value)

        def keyPressEvent(self, e):
            if e.key() in (Qt.Key_Space, Qt.Key_Return, Qt.Key_Enter):
                self.owner.choose(self.value)
            else:
                QtWidgets.QFrame.keyPressEvent(self, e)

    class Choice(QtWidgets.QWidget):
        """A row (or grid) of radio cards: title + description, the
        selected one outlined in primary."""

        def __init__(self, var, options, command=None, columns=1):
            QtWidgets.QWidget.__init__(self)
            self.var, self.command, self.items = var, command, {}
            g = QtWidgets.QGridLayout(self)
            g.setContentsMargins(0, 0, 0, 0)
            g.setHorizontalSpacing(10)
            g.setVerticalSpacing(8)
            for i, (value, title, desc) in enumerate(options):
                r, c = divmod(i, columns)
                card_ = ChoiceCard(self, value, title, desc)
                g.addWidget(card_, r, c)
                self.items[value] = card_
            for c in range(columns):
                g.setColumnStretch(c, 1)
            var.trace(self.draw)
            self.draw()

        def choose(self, v):
            self.var.set(v)
            if self.command:
                self.command()

        def draw(self):
            cur = self.var.get()
            for v, card_ in self.items.items():
                on = v == cur
                card_.radio.on = on
                card_.radio.update()
                restyle(card_, 'selected', on)

    def bind_line(e, var):
        e.setText('' if var.get() is None else str(var.get()))
        e.textChanged.connect(lambda t: var.set(t))
        var.trace(lambda: e.text() != str(var.get()) and e.setText(str(var.get())))
        return e

    def entry(var, width=None, mono=False, password=False, digits=False):
        e = QtWidgets.QLineEdit()
        if digits:
            e.setValidator(QtGui.QRegularExpressionValidator(QtCore.QRegularExpression('[0-9]{0,15}'), e))
        if mono:
            e.setProperty('mono', True)
        if width:
            e.setFixedWidth(width)
        if password:
            e.setEchoMode(QtWidgets.QLineEdit.Password)
        return bind_line(e, var)

    def spin(var, lo, hi, step=1, width=None):
        s = QtWidgets.QSpinBox()
        s.setRange(lo, hi)
        s.setSingleStep(step)
        s.setAlignment(Qt.AlignRight)
        if width:
            s.setFixedWidth(width)
        try:
            s.setValue(int(var.get()))
        except (TypeError, ValueError):
            pass
        s.valueChanged.connect(lambda v: var.set(int(v)))

        def back():
            try:
                if s.value() != int(var.get()):
                    s.setValue(int(var.get()))
            except (TypeError, ValueError):
                pass
        var.trace(back)
        return s

    def textbox(height=6, ro=False):
        t = QtWidgets.QPlainTextEdit()
        t.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        t.setReadOnly(ro)
        fm = QtGui.QFontMetrics(QtGui.QFont(F['mono'], 9))
        t.setFixedHeight(height * (fm.lineSpacing() + 2) + 16)
        return t

    def listbox(height=5):
        lb = QtWidgets.QListWidget()
        lb.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        lb.setFixedHeight(height * 26 + 8)
        return lb

    def hbox(*items, spacing=8, margins=(0, 0, 0, 0)):
        h = QtWidgets.QHBoxLayout()
        h.setContentsMargins(*margins)
        h.setSpacing(spacing)
        for it in items:
            if it is None:
                h.addStretch(1)
            elif isinstance(it, QtWidgets.QLayout):
                h.addLayout(it)
            elif isinstance(it, tuple):
                h.addWidget(*it)
            else:
                h.addWidget(it)
        return h

    def vbox(spacing=0, margins=(0, 0, 0, 0)):
        v = QtWidgets.QVBoxLayout()
        v.setContentsMargins(*margins)
        v.setSpacing(spacing)
        return v

    def clear_layout(lay):
        while lay.count():
            it = lay.takeAt(0)
            w = it.widget()
            if w is not None:
                w.hide()
                w.deleteLater()
            elif it.layout() is not None:
                clear_layout(it.layout())

    def card(parent, title=None, sub=None, gap=18):
        """A card on a page; returns its body layout."""
        f = QtWidgets.QFrame()
        f.setObjectName('card')
        body = vbox(10, (22, 18, 22, 18))
        f.setLayout(body)
        if title:
            hd = hbox(spacing=0)
            hd.addWidget(lbl(title, 'h'))
            if sub:
                hd.addWidget(lbl('  ' + sub, 'faint'), 0, Qt.AlignBottom)
            hd.addStretch(1)
            body.addLayout(hd)
            body.addSpacing(2)
        parent.addWidget(f)
        parent.addSpacing(gap)
        body.frame = f
        return body

    def browse_for(var, mode, filetypes=None):
        def go():
            cur = var.get() or ''
            init = cur if os.path.isdir(cur) else (os.path.dirname(cur) if cur else os.path.expanduser('~'))
            if not os.path.isdir(init):
                init = os.path.expanduser('~')
            if mode == 'dir':
                p = QtWidgets.QFileDialog.getExistingDirectory(win, 'Choose a folder', init)
            elif mode == 'save':
                p = QtWidgets.QFileDialog.getSaveFileName(win, 'Save as', init)[0]
            else:
                p = QtWidgets.QFileDialog.getOpenFileName(win, 'Choose a file', init, filetypes or 'All files (*)')[0]
            if p:
                var.set(os.path.normpath(p))
        return go

    def path_row(parent, var, mode, label=None, filetypes=None, note=None):
        if label:
            parent.addWidget(lbl(label, 'muted'))
        e = entry(var, mono=True)
        parent.addLayout(hbox(e, Btn('Browse…', browse_for(var, mode, filetypes), 'ghost', small=True)))
        if note:
            parent.addWidget(lbl(note, 'faint', wrap=True))
        return e

    class Page(QtWidgets.QScrollArea):
        """A page that scrolls when the window is short; content centred, at
        most 1240 px wide."""

        def __init__(self):
            QtWidgets.QScrollArea.__init__(self)
            self.setWidgetResizable(True)
            self.setFrameShape(QtWidgets.QFrame.NoFrame)
            self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            self.inner = QtWidgets.QWidget()
            self.inner.setObjectName('page')
            self.lay = vbox(0, (24, 20, 24, 10))
            self.inner.setLayout(self.lay)
            self.setWidget(self.inner)

        def resizeEvent(self, e):
            w = self.viewport().width()
            side = max(24, (w - 1240) // 2)
            self.lay.setContentsMargins(side, 20, side, 10)
            QtWidgets.QScrollArea.resizeEvent(self, e)

    # ---------------- dialogs -----------------
    def dialog(title, body_fn, buttons, danger=False, width=640):
        """Modal themed dialog. buttons: [(text, value, kind)], left to
        right. body_fn(layout, set_button_state) builds the body. Returns
        the chosen value (None if closed)."""
        d = QtWidgets.QDialog(win)
        d.setWindowTitle(title)
        d.setModal(True)
        outer = vbox(0)
        d.setLayout(outer)
        bar = QtWidgets.QFrame()
        bar.setFixedHeight(3)
        bar.setStyleSheet('background: %s;' % (C['danger'] if danger else C['primary']))
        outer.addWidget(bar)
        wrap = vbox(12, (26, 20, 26, 20))
        outer.addLayout(wrap)
        t = lbl(title, 'big', wrap=True)
        if danger:
            set_color(t, C['danger'])
        wrap.addWidget(t)
        body = vbox(6)
        wrap.addLayout(body)
        result = {'v': None}
        btns = {}

        def set_state(value, on):
            if value in btns:
                btns[value].set_enabled(on)
        bf = hbox(None)
        for text, value, kind in buttons:
            def done(v=value):
                result['v'] = v
                d.accept()
            b = Btn(text, done, kind)
            bf.addWidget(b)
            btns[value] = b
        body_fn(body, set_state)
        wrap.addSpacing(6)
        wrap.addLayout(bf)
        d.setFixedWidth(width)
        outer.activate()
        hh = outer.totalHeightForWidth(width) if outer.hasHeightForWidth() else d.sizeHint().height()
        d.setFixedHeight(max(hh, 120))
        g = win.frameGeometry()
        d.move(g.x() + max(0, (g.width() - width) // 2), g.y() + max(40, (g.height() - hh) // 3))
        if buttons:
            # Enter picks the last button, unless that one is destructive
            safe = buttons[-1] if buttons[-1][2] != 'danger' else buttons[0]
            btns[safe[1]].setDefault(True)
        d.exec()
        return result['v']

    def message(title, text, kind='info'):
        dialog(title, lambda f, _: f.addWidget(lbl(text, wrap=True)), [('OK', True, 'primary')], danger=(kind == 'danger'))

    def say(text):
        """A dialog body that is one wrapped paragraph."""
        return lambda f, _: f.addWidget(lbl(text, wrap=True))

    # ---------------- variables -----------------
    V = {}
    for n in ('source', 'file_list', 'license', 'wordlist', 'level', 'charset', 'dumb_mode', 'out', 'checkpoint', 'verify', 'engine', 'python', 'max_files', 'max_candidates'):
        v = cfg.get(n)
        V[n] = Var('' if v is None else str(v))
    for n in ('recursive', 'no_prune', 'remember_license', 'dumb', 'gpu', 'checkpoint_on', 'pure_python', 'identify', 'flat', 'overwrite', 'fix_ext', 'force'):
        V[n] = Var(bool(cfg.get(n)))
    for n in ('workers', 'max_passes', 'seen_cap'):
        try:
            V[n] = Var(int(cfg.get(n) or 0))
        except (TypeError, ValueError):
            V[n] = Var(int(DEFAULTS[n]))
    if not V['workers'].get():
        V['workers'].set(cpu_n)
    LIM = {k: Var(int(v)) for k, v in cfg['limits'].items()}
    lists = {'paths': list(cfg['paths']), 'scan_roots': list(cfg['scan_roots']), 'scavenge': list(cfg['scavenge'])}
    W = {}  # widgets the logic needs, filled in as the tabs are built

    def snapshot():
        """cfg dict from the widgets."""
        out = dict(cfg)
        for k, v in V.items():
            out[k] = v.get()
        out.update({k: list(v) for k, v in lists.items()})
        out['keys'] = [k for k in W['keys'].toPlainText().splitlines() if k.strip()] if 'keys' in W else []
        out['limits'] = {k: v.get() for k, v in LIM.items()}
        return finish_snapshot(out, cpu_n)
    ready = {'v': False}

    # ---------------- window -----------------
    class Win(QtWidgets.QMainWindow):
        def closeEvent(self, e):
            if not on_close():
                e.ignore()
                return
            e.accept()

    win = Win()
    win.setWindowTitle('unmicro - Dev7 / Micro decryptor')
    win.setWindowIcon(icon())
    app.setWindowIcon(win.windowIcon())
    win.setMinimumSize(1000, 660)
    scr = app.primaryScreen().availableGeometry()
    ww, wh = min(1280, int(scr.width() * 0.9)), min(860, int(scr.height() * 0.88))
    win.resize(ww, wh)
    win.move(scr.x() + (scr.width() - ww) // 2, scr.y() + max(0, (scr.height() - wh) // 3))
    central = QtWidgets.QWidget()
    central.setObjectName('body')
    win.setCentralWidget(central)
    root_l = vbox(0)
    central.setLayout(root_l)

    # ---------------- top bar -----------------
    top = QtWidgets.QFrame()
    top.setObjectName('topbar')
    top.setFixedHeight(64)
    tl = hbox(spacing=0, margins=(24, 0, 18, 0))
    top.setLayout(tl)
    tl.addWidget(Mark(32))
    tl.addSpacing(10)
    wm = lbl('<span style="color:%s">u</span><span style="color:#ffffff">nmicro</span>' % C['primary'], 'wm')
    wm.setTextFormat(Qt.RichText)
    tl.addWidget(wm)
    tl.addSpacing(14)
    tl.addWidget(lbl('Dev7 / Micro decryptor', 'muted', color=C['faint']), 0, Qt.AlignVCenter)
    tl.addStretch(1)

    def chip(k):
        f = QtWidgets.QWidget()
        h = hbox(spacing=0)
        f.setLayout(h)
        sep = QtWidgets.QFrame()
        sep.setObjectName('chipsep')
        sep.setFixedWidth(1)
        h.addWidget(sep)
        inner = vbox(2, (14, 0, 14, 0))
        inner.addStretch(1)
        inner.addWidget(lbl(k, 'chipkey'))
        dot = QtWidgets.QLabel()
        dot.setFixedSize(8, 8)
        val = lbl('...', 'chipval')
        inner.addLayout(hbox(dot, val, None, spacing=6))
        inner.addStretch(1)
        h.addLayout(inner)
        tl.addWidget(f)

        def set_(text, color):
            dot.setStyleSheet('background: %s; border-radius: 4px;' % color)
            val.setText(text)
        return set_
    set_engine_chip = chip('Engine')
    set_license_chip = chip('Licence')
    set_run_chip = chip('Status')
    set_run_chip('Idle', C['faint'])
    root_l.addWidget(top)

    # ---------------- nav -----------------
    nav = QtWidgets.QFrame()
    nav.setObjectName('nav')
    nav.setFixedHeight(46)
    navl = hbox(spacing=0, margins=(16, 0, 16, 0))
    nav.setLayout(navl)
    root_l.addWidget(nav)
    line = QtWidgets.QFrame()
    line.setObjectName('navline')
    line.setFixedHeight(1)
    root_l.addWidget(line)
    stack = QtWidgets.QStackedWidget()
    root_l.addWidget(stack, 1)
    navl.addStretch(1)

    pages, tabs, order = {}, {}, []
    current = {'name': None}
    on_show = {}

    def add_page(name, label):
        pg = Page()
        pages[name] = pg
        stack.addWidget(pg)
        b = QtWidgets.QPushButton(label)
        b.setObjectName('tab')
        b.setCursor(Qt.PointingHandCursor)
        b.setFixedHeight(46)
        b.clicked.connect(lambda *_: show(name))
        navl.insertWidget(navl.count() - 1, b)
        tabs[name] = b
        order.append(name)
        return pg.lay

    def show(name):
        if current['name'] == name:
            return
        if current['name']:
            restyle(tabs[current['name']], 'active', False)
        current['name'] = name
        stack.setCurrentWidget(pages[name])
        restyle(tabs[name], 'active', True)
        pages[name].verticalScrollBar().setValue(0)
        hook = on_show.get(name)
        if hook:
            hook()

    def page_title(P, title, crumb):
        P.addLayout(hbox(lbl(title, 'title'), None, lbl(crumb, 'crumb')))
        P.addSpacing(16)

    def nav_buttons(P, back=None, nxt=None, nxt_text=None):
        P.addSpacing(4)
        h = hbox(None)
        if back:
            h.addWidget(Btn('←  Back', lambda: show(back), 'ghost'))
        if nxt:
            names = {'keys': 'Keys', 'search': 'Search', 'output': 'Output', 'run': 'Run'}
            h.addWidget(Btn(nxt_text or ('Next: %s  →' % names.get(nxt, nxt.title())), lambda: show(nxt), 'primary'))
        P.addLayout(h)
        P.addSpacing(30)
        P.addStretch(1)

    # ======================= Files =======================
    P = add_page('files', '1  Files')
    page_title(P, 'Encrypted files', 'Step 1 of 5 · what to decrypt')
    c = card(P, 'Where are the encrypted files?', 'files renamed to .cryptedmicro')
    files_box = {}

    def src_changed():
        s = V['source'].get()
        for k, f in files_box.items():
            f.setVisible(k == s)
        refresh_review()
    c.addWidget(Choice(V['source'], [
        ('folders', 'Folders or files I choose', 'Pick one or more folders (subfolders included) or single files. The quickest way when you know where they are.'),
        ('auto', 'The whole computer', 'Search every drive and user folder for .cryptedmicro files. Slower; use it when you are not sure where they all are.'),
        ('list', 'A list of files', 'A text file with one encrypted file path per line, for example from an earlier run.'),
    ], command=src_changed, columns=3))

    def sub_box(key):
        w = QtWidgets.QWidget()
        lay = vbox(10, (0, 6, 0, 0))
        w.setLayout(lay)
        files_box[key] = w
        c.addWidget(w)
        return lay

    # folders
    fb = sub_box('folders')
    paths_lb = listbox(5)
    pbtns = vbox(6)

    def sync_paths():
        paths_lb.clear()
        for p in lists['paths']:
            paths_lb.addItem(p)
        if not lists['paths']:
            it = QtWidgets.QListWidgetItem('  (nothing chosen yet: add a folder or files)')
            it.setForeground(QtGui.QColor(C['faint']))
            it.setFlags(Qt.NoItemFlags)
            paths_lb.addItem(it)
        refresh_review()

    def add_folder():
        p = QtWidgets.QFileDialog.getExistingDirectory(win, 'Add a folder', os.path.expanduser('~'))
        if p and os.path.normpath(p) not in lists['paths']:
            lists['paths'].append(os.path.normpath(p))
            sync_paths()

    def add_files():
        ps, _ = QtWidgets.QFileDialog.getOpenFileNames(win, 'Add encrypted files', os.path.expanduser('~'),
                                                       'Encrypted files (*.cryptedmicro *.CRYPTEDMICRO);;All files (*)')
        for p in ps or ():
            p = os.path.normpath(p)
            if p not in lists['paths']:
                lists['paths'].append(p)
        sync_paths()

    def remove_paths():
        sel = set(i.text() for i in paths_lb.selectedItems())
        lists['paths'] = [p for p in lists['paths'] if p not in sel]
        sync_paths()
    for b in (Btn('Add folder…', add_folder, 'ghost', small=True, width=130),
              Btn('Add files…', add_files, 'ghost', small=True, width=130),
              Btn('Remove', remove_paths, 'danger', small=True, width=130)):
        pbtns.addWidget(b)
    pbtns.addStretch(1)
    fb.addLayout(hbox(paths_lb, pbtns, spacing=10))
    fb.addSpacing(2)
    fb.addWidget(Toggle(V['recursive'], 'Include subfolders', 'Look inside every folder below the ones you chose.', command=lambda: refresh_review()))

    # auto
    ab = sub_box('auto')
    ab.addWidget(lbl('Every drive and the usual user locations are searched. Add extra places below if files live somewhere unusual (a USB drive, a network share).', 'muted', wrap=True))
    roots_lb = listbox(3)

    def sync_roots():
        roots_lb.clear()
        for p in lists['scan_roots']:
            roots_lb.addItem(p)
        refresh_review()

    def add_root():
        p = QtWidgets.QFileDialog.getExistingDirectory(win, 'Add a place to search', os.path.expanduser('~'))
        if p and os.path.normpath(p) not in lists['scan_roots']:
            lists['scan_roots'].append(os.path.normpath(p))
            sync_roots()

    def rm_root():
        for i in sorted((roots_lb.row(it) for it in roots_lb.selectedItems()), reverse=True):
            del lists['scan_roots'][i]
        sync_roots()
    rb = vbox(6)
    rb.addWidget(Btn('Add place…', add_root, 'ghost', small=True, width=130))
    rb.addWidget(Btn('Remove', rm_root, 'danger', small=True, width=130))
    rb.addStretch(1)
    ab.addLayout(hbox(roots_lb, rb, spacing=10))
    ab.addWidget(Toggle(V['no_prune'], 'Also search system folders', 'Windows, Program Files and similar are skipped by default. Much slower when on.', command=lambda: refresh_review()))
    ab.addLayout(hbox(lbl('Stop after this many files (blank = no limit)'), None, entry(V['max_files'], width=110, digits=True)))

    # list
    lb_ = sub_box('list')
    path_row(lb_, V['file_list'], 'file', 'File list (one path per line)', 'Text files (*.txt);;All files (*)')

    # preview
    c2 = card(P, 'Preview', 'optional: see what will be worked on')
    pv_status = lbl('Press "Find files" to list the encrypted files in the places above. Nothing is changed.', 'muted', wrap=True)
    find_btn = Btn('Find files', lambda: find_files(), 'ghost', small=True)
    c2.addLayout(hbox((pv_status, 1), find_btn, spacing=12))
    tree = QtWidgets.QTreeWidget()
    tree.setColumnCount(3)
    tree.setHeaderLabels(['Size', 'Format (from its length)', 'File'])
    tree.setRootIsDecorated(False)
    tree.setUniformRowHeights(True)
    tree.setFixedHeight(8 * 24 + 34)
    tree.setColumnWidth(0, 90)
    tree.setColumnWidth(1, 190)
    tree.header().setStretchLastSection(True)
    tree.headerItem().setTextAlignment(0, Qt.AlignRight | Qt.AlignVCenter)
    c2.addWidget(tree)
    scan_state = {'cancel': None}

    def find_files():
        if scan_state['cancel']:
            scan_state['cancel'].set()
            return
        s = V['source'].get()
        places, err = scan_places(s, lists['paths'], V['file_list'].get(), lists['scan_roots'])
        if err:
            pv_status.setText(err)
            set_color(pv_status, C['danger'])
            return
        if not places:
            pv_status.setText('Nothing chosen yet.')
            set_color(pv_status, C['warning'])
            return
        tree.clear()
        cancel = threading.Event()
        scan_state['cancel'] = cancel
        find_btn.setText('Stop')
        res = queue.Queue()
        rec = V['recursive'].get() if s == 'folders' else True

        def work():
            for item in find_encrypted(places, rec, cancel):
                res.put(item)
            res.put(None)
        threading.Thread(target=work, daemon=True).start()
        tot = {'n': 0, 'b': 0, 'kinds': {}}

        def poll():
            done = False
            rows = []
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
                        row = QtWidgets.QTreeWidgetItem([fmt_bytes(size), fmt, p])
                        row.setTextAlignment(0, Qt.AlignRight | Qt.AlignVCenter)
                        rows.append(row)
            except queue.Empty:
                pass
            if rows:
                tree.addTopLevelItems(rows)
            text, tone = scan_status(tot['n'], tot['b'], tot['kinds'], done)
            pv_status.setText(text)
            set_color(pv_status, {'ok': C['success'], 'warn': C['warning']}.get(tone, C['muted']))
            if done:
                scan_state['cancel'] = None
                find_btn.setText('Find files')
            else:
                later(150, poll)
        poll()
    nav_buttons(P, None, 'keys')

    # ======================= Keys =======================
    P = add_page('keys', '2  Keys')
    page_title(P, 'Licence and keys', 'Step 2 of 5 · what to try')
    c = card(P, 'Licence key', 'needed for every run that looks at your files')
    c.addWidget(lbl('Each unmicro build is sealed with its own licence key. If you do not have one, email %s and mention "Chattering Magpies". There is no charge.' % CONTACT, 'muted', wrap=True))
    lic_entry = entry(V['license'], mono=True, password=True)

    def toggle_show():
        hidden = lic_entry.echoMode() == QtWidgets.QLineEdit.Password
        lic_entry.setEchoMode(QtWidgets.QLineEdit.Normal if hidden else QtWidgets.QLineEdit.Password)
        show_btn.setText('Hide' if hidden else 'Show')
    show_btn = Btn('Show', toggle_show, 'ghost', small=True, width=64)
    check_btn = Btn('Check licence', lambda: check_license(), 'primary', small=True)
    c.addLayout(hbox((lic_entry, 1), show_btn, check_btn))
    lic_status = lbl('', 'muted', wrap=True)
    c.addWidget(lic_status)
    c.addWidget(Toggle(V['remember_license'], 'Remember the licence on this computer',
                       'Saved in your user settings file (readable only by you on Linux/macOS). Leave off on a shared machine.'))
    rk_btn = Btn('Show the recovered keys this build knows', lambda: toggle_rk(), 'ghost', small=True)
    c.addLayout(hbox(rk_btn, None))
    rk_box = textbox(8, ro=True)
    rk_box.hide()
    c.addWidget(rk_box)

    def toggle_rk():
        if rk_box.isHidden():
            keys = cfg['keydata'].get('keys') or []
            rk_box.setPlainText('\n'.join(keys) if keys else 'Check the licence first.')
            rk_box.show()
            rk_btn.setText('Hide the recovered keys')
        else:
            rk_box.hide()
            rk_btn.setText('Show the recovered keys this build knows')

    c = card(P, 'Keys you already know', 'optional')
    c.addWidget(lbl('If you have the key, or think you might (from a ransom note, the attackers, or someone else hit by the same crew), type it here, one per line. These are tried first.', 'muted', wrap=True))
    keys_text = textbox(4)
    keys_text.setPlainText('\n'.join(cfg.get('keys', [])))
    keys_text.textChanged.connect(lambda: refresh_review())
    W['keys'] = keys_text
    c.addWidget(keys_text)
    c.addWidget(Toggle(V['force'], 'Apply my one key to every file without checking first',
                       'Only when exactly one key is given and nothing else is searched. Faster, but a wrong key writes garbage.', command=lambda: refresh_review()))

    c = card(P, 'Wordlist and memory dumps', 'optional')
    path_row(c, V['wordlist'], 'file', 'Wordlist: a text file of candidate keys, one per line', 'Text files (*.txt *.lst *.dic);;All files (*)')
    c.addWidget(lbl('Memory dumps, pagefile, hibernation file, strings listings or implant logs. The key is a typed string and often survives in the clear. Never add an encrypted file here.', 'muted', wrap=True))
    sc_lb = listbox(3)

    def sync_sc():
        sc_lb.clear()
        for p in lists['scavenge']:
            sc_lb.addItem(p)
        refresh_review()

    def add_sc():
        ps, _ = QtWidgets.QFileDialog.getOpenFileNames(win, 'Add memory dumps', os.path.expanduser('~'))
        for p in ps or ():
            p = os.path.normpath(p)
            if p.lower().endswith(EXT):
                message('Not an encrypted file', 'That file is encrypted. Memory dumps must be unencrypted; skipping it.', 'danger')
                continue
            if p not in lists['scavenge']:
                lists['scavenge'].append(p)
        sync_sc()

    def rm_sc():
        for i in sorted((sc_lb.row(it) for it in sc_lb.selectedItems()), reverse=True):
            del lists['scavenge'][i]
        sync_sc()
    scb = vbox(6)
    scb.addWidget(Btn('Add dump…', add_sc, 'ghost', small=True, width=130))
    scb.addWidget(Btn('Remove', rm_sc, 'danger', small=True, width=130))
    scb.addStretch(1)
    c.addLayout(hbox(sc_lb, scb, spacing=10))
    nav_buttons(P, 'files', 'search')

    # ======================= Search =======================
    P = add_page('search', '3  Search')
    page_title(P, 'How hard to look for the key', 'Step 3 of 5 · effort and machine use')
    c = card(P, 'Search level')
    c.addWidget(Choice(V['level'], [
        ('quick', 'Quick', 'Your keys, wordlist and dumps, plus every key already recovered from these attackers. Seconds.'),
        ('standard', 'Standard', 'Quick, then likely variations modelled on this crew\'s key history (--brute). Minutes.'),
        ('deep', 'Deep', 'Standard with every generator widened (--brute --deep). Hours, not seconds.'),
    ], command=lambda: refresh_review(), columns=3))

    c = card(P, 'Structural brute force', '--dumb-brute: every possible key, shortest first')
    c.addWidget(Toggle(V['dumb'], 'Also try every possible key, one length at a time',
                       'Runs after the level above. Exhaustive, so short keys finish and long ones may never. Each extra character multiplies the work by the alphabet size.',
                       command=lambda: dumb_changed()))
    dumb_w = QtWidgets.QWidget()
    db = vbox(6, (0, 4, 0, 0))
    dumb_w.setLayout(db)
    c.addWidget(dumb_w)
    db.addWidget(lbl('Alphabet', 'muted'))
    db.addWidget(Choice(V['charset'], [
        ('observed', 'Observed', 'Only characters seen in recovered keys.'),
        ('turkish', 'Turkish + English (default)', 'Adds Turkish and English lowercase and digits.'),
        ('full', 'Full', 'Adds uppercase. Widest and slowest.'),
    ], command=lambda: dumb_changed(), columns=3))
    db.addSpacing(4)
    db.addWidget(lbl('When the keys get long', 'muted'))
    db.addWidget(Choice(V['dumb_mode'], [
        ('ask', 'Ask me before each long length', 'Before a length that would take long, unmicro stops and the GUI asks you, with its time estimate.'),
        ('keepgoing', 'Keep going without asking', 'Answers yes to every length (--yes). Still respects "Stop after N guesses" below.'),
        ('endless', 'Run until this machine cannot take it any more', 'Every core, no guess limit, no questions, through every length up to the longest recovered key. Runs until a safety limit trips, you stop it, or the hardware gives out. You will be warned first.'),
    ], command=lambda: dumb_changed(), columns=3))
    est = QtWidgets.QFrame()
    est.setObjectName('inset')
    el = vbox(4, (14, 10, 14, 10))
    est.setLayout(el)
    est_head = lbl('', 'bold', wrap=True)
    el.addWidget(est_head)
    est_tbl = QtWidgets.QGridLayout()
    est_tbl.setHorizontalSpacing(28)
    est_tbl.setVerticalSpacing(2)
    el.addLayout(est_tbl)
    est_foot = lbl('', 'muted', wrap=True)
    el.addSpacing(4)
    el.addWidget(est_foot)
    db.addSpacing(2)
    db.addWidget(est)

    def draw_estimates():
        clear_layout(est_tbl)
        head, rows, foot = estimate_table(cfg, snapshot(), cpu_n)
        est_head.setText(head)
        for j, h in enumerate(('Length', 'Keys to try', 'This length', 'Total so far')):
            est_tbl.addWidget(lbl(h, 'faint'), 0, j)
        tones = {'ok': C['success'], 'warn': C['warning'], 'bad': C['danger']}
        for i, r in enumerate(rows, 1):
            for j, v in enumerate(r[:4]):
                w = lbl(v, 'mono', color=tones[r[4]] if j == 3 else None)
                est_tbl.addWidget(w, i, j)
        est_tbl.setColumnStretch(4, 1)
        est_foot.setText(foot)

    def dumb_changed():
        on = V['dumb'].get()
        dumb_w.setVisible(bool(on))
        if on:
            draw_estimates()
        endless = on and V['dumb_mode'].get() == 'endless'
        if 'mc' in W:
            W['mc'].setEnabled(not endless)
            if endless:
                V['workers'].set(cpu_n)
        refresh_review()

    c = card(P, 'Machine use')
    wl = lbl('', 'bold')
    c.addLayout(hbox(lbl('CPU workers'), None, wl))
    wsc = QtWidgets.QSlider(Qt.Horizontal)
    wsc.setRange(1, cpu_n)
    wsc.setValue(max(1, min(cpu_n, V['workers'].get())))
    wsc.setCursor(Qt.PointingHandCursor)
    wsc.valueChanged.connect(lambda v: (V['workers'].set(int(v)), workers_changed()))
    V['workers'].trace(lambda: wsc.value() != V['workers'].get() and wsc.setValue(V['workers'].get()))
    c.addWidget(wsc)
    c.addWidget(lbl('All %d cores searches fastest; fewer keeps the computer usable while it runs.' % cpu_n, 'faint'))

    def workers_changed():
        n = V['workers'].get()
        wl.setText(('%d of %d (all)' % (n, cpu_n)) if n >= cpu_n else ('%d of %d' % (n, cpu_n)))
        if V['dumb'].get():
            draw_estimates()
        refresh_review()
    c.addSpacing(4)
    c.addLayout(hbox((Toggle(V['gpu'], 'Use the graphics card (OpenCL)',
                             'NVIDIA or AMD with OpenCL drivers. unmicro checks the GPU against the CPU first and falls back if it disagrees. Not used for the newer (GCM) files.',
                             command=lambda: (dumb_changed(), refresh_review())), 1),
                     (Btn('Check GPU', lambda: quick_run(['--gpu-info'], 'GPU check', need_license=False), 'ghost', small=True), 0, Qt.AlignVCenter),
                     spacing=16))
    g2 = QtWidgets.QGridLayout()
    g2.setVerticalSpacing(10)
    g2.addWidget(lbl('Stop after this many guesses (blank = never)'), 0, 0)
    W['mc'] = entry(V['max_candidates'], width=140, digits=True)
    g2.addWidget(W['mc'], 0, 1, Qt.AlignRight)
    g2.addWidget(lbl('Search passes (each pass looks for another key for files still locked)', wrap=True), 1, 0)
    g2.addWidget(spin(V['max_passes'], 1, 64), 1, 1, Qt.AlignRight)
    g2.setColumnStretch(0, 1)
    c.addSpacing(4)
    c.addLayout(g2)
    c.addSpacing(4)
    c.addWidget(Toggle(V['checkpoint_on'], 'Save progress so a stopped search can resume',
                       'Recommended for long runs. Leave the file name blank to keep it in the output folder.', command=lambda: refresh_review()))
    path_row(c, V['checkpoint'], 'save')

    c = card(P, 'Advanced')
    c.addLayout(hbox((lbl('Duplicate-suppression memory per generator (lower on a small-memory machine)', wrap=True), 1), spin(V['seen_cap'], 10000, 100000000, 100000, width=130)))
    c.addSpacing(4)
    c.addWidget(Toggle(V['pure_python'], 'Use the built-in AES (much slower)', 'Ignore the bundled fast AES library. Only for troubleshooting.', command=lambda: refresh_review()))
    nav_buttons(P, 'keys', 'output')

    # ======================= Output =======================
    P = add_page('output', '4  Output')
    page_title(P, 'Recovered files', 'Step 4 of 5 · where and how')
    c = card(P, 'Save recovered files to')
    path_row(c, V['out'], 'dir', None, note='A new folder is best. Your encrypted files are never changed, renamed or deleted; recovered copies go here.')
    c.addWidget(Toggle(V['identify'], 'Only find the key, write nothing', 'A key check: reports which key opens which files and saves nothing (--identify).', command=lambda: refresh_review()))
    c = card(P, 'Layout')
    c.addWidget(Toggle(V['flat'], 'Put everything in one folder', 'Off: recovered files mirror their original folders, so same-named files never collide.', command=lambda: refresh_review()))
    c.addSpacing(4)
    c.addWidget(Toggle(V['overwrite'], 'Overwrite files that already exist', 'Off: a name collision gets a numeric suffix instead.', command=lambda: refresh_review()))
    c.addSpacing(4)
    c.addWidget(Toggle(V['fix_ext'], 'Fix swapped extensions', 'This crew randomises extensions. On: a recovered video named .jpg is saved as .mp4, and the swap is reported. Bytes are never changed.', command=lambda: refresh_review()))
    c = card(P, 'Checking recovered files')
    c.addWidget(Choice(V['verify'], [
        ('normal', 'Normal (recommended)', 'Write files whose structure checks out, and files the proven key opens cleanly but whose type cannot be checked (marked .UNVERIFIED).'),
        ('strict', 'Strict', 'Write only files that pass a structural check (--strict).'),
        ('keep', 'Keep everything', 'Also write files that failed the check, suffixed .UNVERIFIED (--keep-unverified).'),
    ], command=lambda: refresh_review(), columns=3))
    nav_buttons(P, 'search', 'run', 'Next: Review and run  →')

    # ======================= Run =======================
    P = add_page('run', '5  Run')
    page_title(P, 'Review and run', 'Step 5 of 5')
    rv = card(P, 'Review')
    review_lines = QtWidgets.QGridLayout()
    review_lines.setHorizontalSpacing(18)
    review_lines.setVerticalSpacing(4)
    review_lines.setColumnStretch(1, 1)
    rv.addLayout(review_lines)
    cmd_box = QtWidgets.QPlainTextEdit()
    cmd_box.setObjectName('cmd')
    cmd_box.setReadOnly(True)
    cmd_box.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
    cmd_box.setFixedHeight(64)
    rv.addSpacing(4)
    rv.addWidget(cmd_box)
    start_btn = Btn('Start', lambda: start_run(), 'primary')
    stop_btn = Btn('Stop and recover what is matched', lambda: stop_run(), 'ghost')
    kill_btn = Btn('Force stop', lambda: kill_run(), 'danger')
    open_btn = Btn('Open output folder', lambda: open_path_(snapshot().get('out')), 'ghost', small=True)
    copy_btn = Btn('Copy command', lambda: app.clipboard().setText(cmd_box.toPlainText().strip()), 'ghost', small=True)
    rv.addSpacing(6)
    rv.addLayout(hbox(start_btn, stop_btn, kill_btn, None, (open_btn, 0, Qt.AlignVCenter), (copy_btn, 0, Qt.AlignVCenter)))
    stop_btn.set_enabled(False)
    kill_btn.set_enabled(False)

    # stat tiles
    tiles = QtWidgets.QGridLayout()
    tiles.setHorizontalSpacing(14)
    tile_vals = {}
    for i, (key, title) in enumerate((('step', 'Step'), ('tried', 'Keys tried'), ('rate', 'Speed'), ('elapsed', 'Elapsed'), ('found', 'Keys found'))):
        t = QtWidgets.QFrame()
        t.setObjectName('card')
        tv = vbox(2, (16, 12, 16, 12))
        t.setLayout(tv)
        tv.addWidget(lbl(title, 'h'))
        v = lbl('–', 'num')
        tv.addWidget(v)
        sub = lbl('', 'faint')
        sub.setMinimumWidth(10)
        tv.addWidget(sub)
        tiles.addWidget(t, 0, i)
        tiles.setColumnStretch(i, 1)
        tile_vals[key] = (v, sub)
    P.addLayout(tiles)
    P.addSpacing(18)

    def tile(key, value, sub=None, color=None):
        v, s = tile_vals[key]
        v.setText(value)
        set_color(v, color or C['primary'])
        if sub is not None:
            s.setText(sub)
            s.setToolTip(sub)

    mid = QtWidgets.QHBoxLayout()
    mid.setSpacing(14)
    lc = QtWidgets.QFrame()
    lc.setObjectName('card')
    lcb = vbox(6, (20, 16, 20, 16))
    lc.setLayout(lcb)
    lcb.addWidget(lbl('Current method', 'h'))
    method_l = lbl('Not started', wrap=True)
    lcb.addWidget(method_l)
    len_bar = QtWidgets.QProgressBar()
    len_bar.setRange(0, 1000)
    len_bar.setTextVisible(False)
    lcb.addWidget(len_bar)
    len_l = lbl('', 'faint', wrap=True)
    lcb.addWidget(len_l)
    lcb.addSpacing(6)
    result_l = lbl('', 'big', wrap=True, sel=True)
    lcb.addWidget(result_l)
    counts_l = lbl('', 'muted', wrap=True, sel=True)
    lcb.addWidget(counts_l)
    lcb.addStretch(1)
    mid.addWidget(lc, 3)

    rc_ = QtWidgets.QFrame()
    rc_.setObjectName('card')
    rcb = vbox(2, (20, 16, 20, 16))
    rc_.setLayout(rcb)
    rcb.addWidget(lbl('This machine', 'h'))
    rcb.addSpacing(4)
    meters = {}
    for key, title in METERS:
        vl = lbl('n/a', 'muted', color=C['text'])
        rcb.addLayout(hbox(lbl(title, 'muted'), None, vl))
        pb = QtWidgets.QProgressBar()
        pb.setRange(0, 100)
        pb.setTextVisible(False)
        rcb.addWidget(pb)
        rcb.addSpacing(3)
        meters[key] = (vl, pb)
    ttf_l = lbl('', 'bold', wrap=True, color=C['warning'])
    rcb.addSpacing(6)
    rcb.addWidget(ttf_l)
    ttf_sub = lbl('', 'faint', wrap=True)
    rcb.addWidget(ttf_sub)
    rcb.addStretch(1)
    mid.addWidget(rc_, 2)
    P.addLayout(mid)
    P.addSpacing(18)

    logc = card(P, 'Output', 'what unmicro prints')
    log = QtWidgets.QPlainTextEdit()
    log.setReadOnly(True)
    log.setMaximumBlockCount(6000)
    log.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
    log.setFixedHeight(340)
    log.setStyleSheet('QPlainTextEdit { color: %s; padding: 6px 4px; }' % C['text'])
    logc.addWidget(log)
    TAGS = {'ok': C['success'], 'warn': C['warning'], 'err': C['danger'], 'info': C['muted'], 'stage': C['primary'], 'gui': C['info'], 't': C['faint']}

    def log_write(text, tag=None):
        sb = log.verticalScrollBar()
        at_end = sb.value() >= sb.maximum() - 4
        col = TAGS.get(tag, C['text'])
        weight = 'font-weight:600;' if tag == 'stage' else ''
        log.appendHtml('<span style="white-space:pre-wrap;color:%s;%s">%s</span>' % (col, weight, html.escape(text) or '&nbsp;'))
        if at_end:
            sb.setValue(sb.maximum())

    def gui_note(text):
        log_write('[gui] ' + text, 'gui')
    nav_buttons(P)

    # ======================= Settings =======================
    P = add_page('settings', 'Settings')
    page_title(P, 'Settings', 'engine, safety limits, profiles')
    c = card(P, 'Engine', 'the unmicro program this window runs')

    def browse_engine():
        p = QtWidgets.QFileDialog.getOpenFileName(win, 'Choose the unmicro program', os.path.expanduser('~'), 'unmicro (unmicro*);;All files (*)')[0]
        if p:
            V['engine'].set(os.path.normpath(p))
            check_engine()
    c.addLayout(hbox((entry(V['engine'], mono=True), 1), Btn('Browse…', browse_engine, 'ghost', small=True),
                     Btn('Find automatically', lambda: (V['engine'].set(''), check_engine()), 'ghost', small=True)))
    c.addWidget(lbl('The release binary for this system (unmicro-<version>-windows-x86_64.exe or -linux-x86_64), or unmicro.py. Only use a copy downloaded from the Rho-9-Official GitHub repository, with its checksum verified.', 'faint', wrap=True))
    c.addLayout(hbox(lbl('Python for unmicro.py (blank = this one)', 'muted'), None, entry(V['python'], width=340, mono=True)))
    eng_out = lbl('', 'muted', wrap=True, sel=True)
    c.addWidget(eng_out)
    c.addLayout(hbox(Btn('Version', lambda: quick_run(['--version'], 'Version', need_license=False), 'ghost', small=True),
                     Btn('Self-test', lambda: quick_run(['--self-test'], 'Self-test', need_license=False), 'ghost', small=True),
                     Btn('GPU info', lambda: quick_run(['--gpu-info'], 'GPU check', need_license=False), 'ghost', small=True), None))

    c = card(P, 'Safety limits', 'used by "Run until this machine cannot take it any more"')
    c.addWidget(lbl('The endless run is watched every 5 seconds. If a limit holds for 30 seconds, the GUI stops the search cleanly and recovers every file already matched to a key. Progress is kept, so it can resume.', 'muted', wrap=True))
    lg = QtWidgets.QGridLayout()
    lg.setVerticalSpacing(8)
    for i, (k, text, lo, hi) in enumerate((('max_temp', 'Stop when the CPU is hotter than (°C)', 50, 110),
                                           ('max_ram', 'Stop when memory use is above (%)', 50, 99),
                                           ('min_disk_gb', 'Stop when free disk on the output drive is below (GB)', 1, 500),
                                           ('min_battery', 'Stop when on battery and below (%)', 1, 90))):
        lg.addWidget(lbl(text), i, 0)
        lg.addWidget(spin(LIM[k], lo, hi, width=90), i, 1, Qt.AlignRight)
    lg.setColumnStretch(0, 1)
    c.addLayout(lg)

    c = card(P, 'Profiles')
    c.addWidget(lbl('Settings are saved automatically when the window closes (to %s). Save or load a named profile here, for example one per case.' % cfg_path, 'muted', wrap=True))

    def save_profile():
        p = QtWidgets.QFileDialog.getSaveFileName(win, 'Save profile', os.path.expanduser('~'), 'Profile (*.json)')[0]
        if p:
            if not p.lower().endswith('.json'):
                p += '.json'
            s = snapshot()
            s['remember_license'] = False
            save_config(p, s)
            gui_note('profile saved: %s (licence not included)' % p)

    def load_profile():
        p = QtWidgets.QFileDialog.getOpenFileName(win, 'Load profile', os.path.expanduser('~'), 'Profile (*.json)')[0]
        if p:
            apply_cfg(load_config(p))
            gui_note('profile loaded: %s' % p)

    def reset_defaults():
        if dialog('Reset every setting?', say('All tabs go back to their defaults. The licence and engine stay.'),
                  [('Cancel', False, 'ghost'), ('Reset', True, 'danger')]):
            d = load_config('')
            d['license'] = V['license'].get()
            d['engine'] = V['engine'].get()
            apply_cfg(d)
    c.addLayout(hbox(Btn('Save profile…', save_profile, 'ghost', small=True), Btn('Load profile…', load_profile, 'ghost', small=True),
                     Btn('Reset to defaults', reset_defaults, 'danger', small=True), None))
    nav_buttons(P)

    def apply_cfg(d):
        for k, v in V.items():
            if k in d:
                val = d[k]
                if isinstance(v.get(), bool):
                    val = bool(val)
                elif isinstance(v.get(), int):
                    try:
                        val = int(val or 0)
                    except (TypeError, ValueError):
                        continue
                else:
                    val = '' if val is None else str(val)
                v.set(val)
        if not V['workers'].get():
            V['workers'].set(cpu_n)
        for k in lists:
            lists[k] = list(d.get(k, []))
        for k, v in LIM.items():
            v.set(int(d.get('limits', {}).get(k, DEFAULTS['limits'][k])))
        keys_text.setPlainText('\n'.join(d.get('keys', [])))
        sync_paths()
        sync_roots()
        sync_sc()
        src_changed()
        dumb_changed()
        workers_changed()

    # ======================= Help =======================
    P = add_page('help', 'Help')
    page_title(P, 'Help', 'Rho-9 Systems · your first line of unusual defense')
    c = card(P, 'If you have just been hit, read this first')
    for t in ('1.  Do not pay. There is no guarantee of recovery and it funds the next round of victims.',
              '2.  Their "decryption" is a command run by their bot on your still-infected machine. Do not keep the infection alive for it.',
              '3.  Do not wipe the machine or delete the encrypted files. Copy them to an external drive before anything else.',
              '4.  If the machine is still on and infected, leave it powered on and take it off the network. The key may still be in memory.',
              '5.  This crew disables Windows Recovery, Task Manager and Regedit, and adds a Defender exclusion. Check what is left.',
              '6.  When you post about this anywhere, use the phrase "Chattering Magpies".'):
        c.addWidget(lbl(t, wrap=True))
    c = card(P, 'How to use this window')
    for t in ('Files: choose where the .cryptedmicro files are, or search the whole computer. "Find files" previews them; nothing is changed.',
              'Keys: enter the licence key and any keys you know. Check licence confirms it and loads the recovered keys this build knows.',
              'Search: Quick takes seconds and is often enough. Standard and Deep guess harder. The structural brute force tries every key by length.',
              'Output: where recovered copies go. Your encrypted files are opened read-only and never changed.',
              'Run: review the plan and the exact command, then Start. "Stop and recover" ends the search and still saves every file already matched to a key.'):
        c.addWidget(lbl('•  ' + t, wrap=True))
    c = card(P, 'Reading the result')
    for t in ('OK: decrypted and structurally verified.',
              'PROVEN: the key was proved on another file; this one decrypted cleanly but its type cannot be checked. Saved with a .UNVERIFIED suffix.',
              'Damaged: left half-written when the attack was interrupted. No key can fix these; restore them from backups if you have any.',
              'Still locked: intact, but no key found yet. Most often the attack was run again with a different key: search harder.'):
        c.addWidget(lbl('•  ' + t, wrap=True))
    c.addSpacing(4)
    c.addWidget(lbl('Keep your encrypted copies until you have opened the recovered files and are satisfied.', wrap=True, color=C['warning']))
    c = card(P, 'Contact')
    c.addWidget(lbl('Licence keys and cases: %s (mention "Chattering Magpies"). unmicro GUI %s, a front end for the unmicro command-line tool.' % (CONTACT, APP_VERSION), wrap=True, sel=True))
    nav_buttons(P)

    # ======================= logic =======================
    state = {'job': None, 'buf': {'out': '', 'err': ''}, 'tier': None, 'tier_start': 0, 'found': [], 'step': None,
             't0': None, 'tried': 0, 'rate': 0.0, 'endless': False, 'stop_reason': None, 'limit_hits': {},
             'pending_stop': False, 'stop_sent': None, 'file_list_tmp': None, 'workers_used': None, 'gpu_used': False,
             'rates': [], 'verdict': None, 'counts': {}, 'gate_when': None, 'asking': False}
    res_mon = Resources()
    pump_timer = QtCore.QTimer()
    pump_timer.setInterval(100)
    tick_timer = QtCore.QTimer()
    tick_timer.setInterval(1000)

    def open_path_(p):
        err = open_path(p)
        if err:
            message('Could not open', err)

    def engine():
        return Engine(V['engine'].get().strip(), V['python'].get().strip())

    def check_engine():
        e = engine()
        if not e.path or not os.path.exists(e.path):
            cands = Engine.candidates()
            if cands:
                V['engine'].set(cands[0])
                e = engine()
        if not e.path or not os.path.exists(e.path):
            set_engine_chip('not found', C['danger'])
            eng_out.setText('No unmicro found. Put the binary next to this program, or choose it with Browse.')
            set_color(eng_out, C['danger'])
            return

        def work():
            rc, out = e.quick(['--version'], timeout=60)
            bridge.call.emit(lambda: engine_result(rc, out))
        set_engine_chip('checking…', C['warning'])
        threading.Thread(target=work, daemon=True).start()

    def engine_result(rc, out):
        ok, chip_text, detail, ver = engine_verdict(rc, out)
        set_engine_chip(chip_text, C['success'] if ok else C['danger'])
        eng_out.setText(detail)
        set_color(eng_out, C['success'] if ok else C['danger'])
        if ver:
            cfg['engine_version'] = ver

    def lic_env():
        return {LICENSE_ENV: V['license'].get().strip()}

    def check_license():
        if not V['license'].get().strip():
            lic_status.setText('Enter a licence key first.')
            set_color(lic_status, C['warning'])
            return
        e = engine()
        lic_status.setText('Checking…')
        set_color(lic_status, C['muted'])
        check_btn.set_enabled(False)

        def work():
            rc, out = e.quick(['--list-keys'], env=lic_env(), timeout=120)
            bridge.call.emit(lambda: license_result(rc, out))
        threading.Thread(target=work, daemon=True).start()

    def license_result(rc, out):
        check_btn.set_enabled(True)
        kd = keydata_from_list(out, cfg.get('engine_version')) if rc == 0 else None
        if kd:
            cfg['keydata'] = kd
            lic_status.setText('Licence OK. This build knows %d recovered keys (longest %d characters).' % (len(kd['keys']), kd['max_len']))
            set_color(lic_status, C['success'])
            set_license_chip('OK · %d keys' % len(kd['keys']), C['success'])
            if V['dumb'].get():
                draw_estimates()
        else:
            lic_status.setText('Licence not accepted: %s' % (out.strip().splitlines()[-1] if out.strip() else 'no output'))
            set_color(lic_status, C['danger'])
            set_license_chip('not accepted', C['danger'])

    def quick_run(args, title, need_license=True):
        e = engine()
        env = lic_env() if need_license else {}

        def work():
            rc, out = e.quick(args, env=env, timeout=180)
            bridge.call.emit(lambda: show_output(title, rc, out))
        threading.Thread(target=work, daemon=True).start()
        gui_note('%s: running %s' % (title, ' '.join(args)))

    def show_output(title, rc, out):
        def body(f, _):
            t = textbox(min(24, max(6, out.count('\n') + 2)), ro=True)
            t.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
            t.setPlainText(out.strip() or '(no output)')
            f.addWidget(t)
        dialog('%s (exit code %s)' % (title, rc), body, [('Close', True, 'primary')], danger=rc != 0, width=760)

    def refresh_review(*_):
        if not ready['v']:
            return
        try:
            s = snapshot()
        except Exception:
            return
        clear_layout(review_lines)
        for i, (k, v) in enumerate(summary(s, cpu_n)):
            review_lines.addWidget(lbl(k, 'muted'), i, 0, Qt.AlignTop)
            review_lines.addWidget(lbl(v, wrap=True, color=C['danger'] if 'CANNOT' in v else C['bright']), i, 1)
        probs = problems(s)
        for j, p in enumerate(probs):
            review_lines.addWidget(lbl('!  ' + p, 'muted', wrap=True, color=C['warning']), 20 + j, 0, 1, 2)
        e = engine()
        cmd_box.setPlainText(command_preview(e, s))
        if not (state['job'] and state['job'].running()):
            start_btn.set_enabled(not probs and bool(e.path))

    # ---------- running -----------
    def start_run():
        s = snapshot()
        probs = problems(s)
        if probs:
            message('Not ready yet', '\n'.join(probs))
            return
        e = engine()
        if not e.path or not os.path.exists(e.path):
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
            gui_note('collecting the files from %d places into a file list…' % len(s['paths']))
            flp = write_file_list(s['paths'], s['recursive'])
            if not flp:
                message('No encrypted files', 'No .cryptedmicro files were found in the places you chose.')
                return
            state['file_list_tmp'] = flp
        argv = e.argv(build_args(s, flp))
        env = dict(os.environ)
        env.update(lic_env())
        save_config(cfg_path, s)
        state.update({'buf': {'out': '', 'err': ''}, 'tier': None, 'tier_start': 0, 'found': [], 'step': None, 't0': time.time(),
                      'tried': 0, 'rate': 0.0, 'endless': endless, 'stop_reason': None, 'limit_hits': {}, 'pending_stop': False,
                      'stop_sent': None, 'workers_used': s['workers'] or cpu_n, 'gpu_used': s['gpu'], 'rates': [], 'verdict': None,
                      'counts': {}, 'gate_when': None, 'hits': 0, 'out': s['out'], 'charset': s['charset'], 'ckpt': s.get('checkpoint'),
                      'asking': False, 'last_mon': 0})
        log.clear()
        gui_note('started %s' % time.strftime('%Y-%m-%d %H:%M:%S'))
        gui_note(' '.join(quote_arg(x) for x in argv))
        for k in tile_vals:
            tile(k, '–', '')
        result_l.setText('')
        counts_l.setText('')
        method_l.setText('Starting…')
        len_bar.setValue(0)
        len_l.setText('')
        try:
            job = Job(argv, env, cwd=s['out'] if s['out'] and os.path.isdir(s['out']) else None)
            job.start()
        except Exception as ex:
            message('Could not start unmicro', str(ex), 'danger')
            return
        state['job'] = job
        start_btn.set_enabled(False)
        stop_btn.set_enabled(True)
        kill_btn.set_enabled(True)
        set_run_chip('Endless run' if endless else 'Running', C['danger'] if endless else C['warning'])
        pump_timer.start()
        tick_timer.start()

    def pump():
        job = state['job']
        if job is None:
            pump_timer.stop()
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
    pump_timer.timeout.connect(pump)

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
                state['rates'] = (state['rates'] + [d['rate']])[-50:]
            update_progress(d)
            return
        if kind == 'plainprogress':
            state['tried'] = d['tried']
            method_l.setText(d['name'])
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
            result_l.setText(d['verdict'])
            set_color(result_l, C['success'] if d['verdict'].startswith('ALL') else C['warning'])
        elif kind == 'count':
            state['counts'][d['what']] = d['n']
            counts_l.setText('   '.join('%s: %s' % (k.split(' (')[0], fmt_count(v)) for k, v in state['counts'].items()))
        elif kind == 'gatetime':
            state['gate_when'] = d['when']

    def update_progress(d):
        name = d['name']
        tile('tried', fmt_count(d['tried']), name[:30])
        tile('rate', '%s/s' % fmt_count(d['rate']), '%d worker(s)%s' % (state['workers_used'], ' + GPU' if state['gpu_used'] else ''))
        lp = length_progress(name, d['tried'], state['tier_start'], d['rate'], *alpha_and_max(cfg, state.get('charset', 'turkish')))
        if lp:
            len_bar.setValue(int(lp['frac'] * 1000))
            method_l.setText(lp['method'])
            len_l.setText(lp['detail'])
        else:
            method_l.setText(('GCM: ' if d['gcm'] else '') + name)
            len_bar.setValue(0)
            len_l.setText('')

    def check_prompt():
        job = state['job']
        tail = state['buf']['out']
        if not tail or job is None or state['asking']:
            return
        pr = classify_prompt(tail)
        if not pr:
            return
        kind = pr[0]
        state['buf']['out'] = ''
        if kind == 'pause':
            log_write(tail)
            choice = '2'
            if not state['pending_stop']:
                # Not asked for by us (should not happen): ask the person.
                state['asking'] = True
                keep = dialog('Search paused', say('unmicro paused the search. Keep searching, or stop and recover the files already matched?'),
                              [('Stop and recover', False, 'ghost'), ('Keep searching', True, 'primary')])
                state['asking'] = False
                choice = '1' if keep else '2'
            gui_note('answering the pause menu: %s' % ('stop and recover the matched files' if choice == '2' else 'keep searching'))
            job.send(choice + '\n')
            if choice == '1':
                state['pending_stop'] = False
        elif kind == 'gate':
            log_write(tail)
            L = pr[1]
            when = state.get('gate_when') or 'a long time'
            state['asking'] = True
            yes = dialog('Keep going into %d-character keys?' % L,
                         say('Every shorter key has been tried with no match. Keys of exactly %d characters would take roughly %s on this machine, and each length after it is far longer.\n\nYou can stop here and recover nothing new, or keep going (progress is saved if "Save progress" is on).' % (L, when)),
                         [('Stop here', False, 'ghost'), ('Keep going', True, 'primary')])
            state['asking'] = False
            gui_note('length %d: %s' % (L, 'keep going' if yes else 'stop here'))
            job.send('y\n' if yes else 'n\n')
        elif kind == 'close':
            job.send('\n')
        elif kind == 'license':
            gui_note('unmicro asked for a licence key: it did not get one. Stopping.')
            job.kill()

    def tick():
        job = state['job']
        if job is None:
            tick_timer.stop()
            return
        el = time.time() - (state['t0'] or time.time())
        tile('elapsed', '%d:%02d:%02d' % (el // 3600, el % 3600 // 60, el % 60), time.strftime('since %H:%M', time.localtime(state['t0'])))
        if time.time() - state.get('last_mon', 0) >= 5:
            state['last_mon'] = time.time()
            monitor()
        if state['stop_sent'] and time.time() - state['stop_sent'] > 120 and job.running():
            gui_note('unmicro has not stopped 2 minutes after the request; you can use Force stop.')
            state['stop_sent'] = time.time() + 1e9
    tick_timer.timeout.connect(tick)

    def monitor():
        s = res_mon.sample(state.get('out'))
        lims = {k: v.get() for k, v in LIM.items()}
        for key, (text, frac, tone) in meter_readings(s, lims).items():
            vl, pb = meters[key]
            vl.setText(text)
            set_color(vl, {'bad': C['danger'], 'warn': C['warning']}.get(tone, C['text']))
            pb.setValue(int(frac))
            if pb.property('tone') != tone:
                restyle(pb, 'tone', tone)
        if not state['endless']:
            ttf_l.setText('')
            ttf_sub.setText('')
            return
        # time to failure
        alpha, maxlen = alpha_and_max(cfg, state.get('charset', 'turkish'))
        rate = live_rate(state['rates'], cfg, state['workers_used'], state['gpu_used'])
        search_secs = search_left_secs(alpha, maxlen, rate, state['tier'], state['tried'], state['tier_start'])
        head, sub = ttf_text(*time_to_failure(search_secs, s, lims, res_mon.slopes()))
        ttf_l.setText(head)
        ttf_sub.setText(sub)
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
        if confirm and not dialog('Stop the search?', say('unmicro stops searching, then recovers every file already matched to a key. Files still locked stay locked; run again later to continue.'),
                                  [('Keep searching', False, 'ghost'), ('Stop and recover', True, 'primary')]):
            return
        state['pending_stop'] = True
        state['stop_sent'] = time.time()
        set_run_chip('Stopping…', C['warning'])
        gui_note('sending Ctrl+C: unmicro pauses at the end of the current batch (a few seconds)')
        if not job.interrupt():
            gui_note('could not deliver Ctrl+C; use Force stop')

    def kill_run(confirm=True):
        job = state['job']
        if not job or not job.running():
            return
        if not confirm or dialog('Force stop?', say('This ends unmicro at once. Files already matched are NOT recovered by this run (use "Stop and recover" for that). Your encrypted files are not affected.'),
                                 [('Cancel', False, 'ghost'), ('Force stop', True, 'danger')], danger=True):
            gui_note('force stop')
            state['stop_reason'] = 'force stopped'
            job.kill()

    def finished(rc):
        pump_timer.stop()
        tick_timer.stop()
        for tag in ('out', 'err'):
            if state['buf'][tag].strip():
                handle_line(tag, state['buf'][tag], '')
            state['buf'][tag] = ''
        state['job'] = None
        el = time.time() - state['t0']
        gui_note('unmicro exited with code %s after %s' % (rc, fmt_duration(el)))
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
            if rc not in (0, None):
                result_l.setText('unmicro stopped without a result (exit code %s). See the output below.' % rc)
                set_color(result_l, C['danger'])
        if state.get('stop_reason'):
            counts_l.setText((counts_l.text() + '\n' if counts_l.text() else '') + 'Stopped: %s' % state['stop_reason'])
        method_l.setText('Finished')
        len_l.setText('')
        len_bar.setValue(0)
        refresh_review()

    def endless_warning(s):
        lims = {k: v.get() for k, v in LIM.items()}
        E = endless_estimate(cfg, s, cpu_n, res_mon.sample(s.get('out')), lims)

        def body(f, set_state):
            f.addWidget(lbl('This search does not end by itself.', 'bold'))
            f.addWidget(lbl('Every %s, with no guess limit and no questions, through every key length up to %d characters, '
                            'it pins all %d cores%s at 100%% for as long as it runs. The computer will be hot, loud and slow; a laptop will drain its battery.' % (
                                ('core and the GPU' if s['gpu'] else 'core'), E['maxlen'], E['workers'], ' and the GPU' if s['gpu'] else ''), wrap=True))
            f.addSpacing(6)
            box = QtWidgets.QFrame()
            box.setObjectName('dangerbox')
            bl = vbox(2, (14, 10, 14, 10))
            box.setLayout(bl)
            bl.addWidget(lbl('Estimated time to failure:  %s' % fmt_duration(E['secs']), 'big', color=C['danger']))
            bl.addWidget(lbl('Limited by: %s' % phrase(E['why']), wrap=True))
            for name, v, note in E['details']:
                bl.addWidget(lbl('• %s: %s  (%s)' % (name, fmt_duration(v) if v is not None else 'measured once running', note), 'muted', wrap=True))
            bl.addSpacing(4)
            bl.addWidget(lbl('In practice: every key up to %d characters is tried within a day, up to %d within a week, up to %d within a year.' % (
                E['day'], E['week'], E['year']), 'muted', wrap=True, color=C['text']))
            bl.addWidget(lbl('Speed assumed: %s keys/s %s.' % (
                fmt_count(E['rate']), '(measured on this machine)' if E['measured'] else '(rough guess; the live figure replaces it once running)'), 'faint', wrap=True))
            f.addWidget(box)
            f.addSpacing(6)
            f.addWidget(lbl('Safety limits (Settings tab) stop it cleanly and recover every matched file: CPU over %d°C, memory over %d%%, under %d GB free disk, battery under %d%%. %s' % (
                lims['max_temp'], lims['max_ram'], lims['min_disk_gb'], lims['min_battery'],
                ('CPU temperature now: %.0f°C; the time to failure is refined from its trend once running.' % E['temp']) if E['temp'] is not None
                else 'This machine gives no temperature reading, so overheating is left to the hardware\'s own protection.'), 'muted', wrap=True))
            f.addSpacing(4)
            ack = Var(False)
            f.addWidget(Toggle(ack, 'I understand: run until this machine cannot take it any more', command=lambda: set_state('go', ack.get())))
            set_state('go', False)
        return dialog('Run until this machine cannot take it any more?', body,
                      [('Cancel', False, 'ghost'), ('Start the endless run', 'go', 'danger')], danger=True, width=720) == 'go'

    # ---------- wire-up -----------
    for name in ('level', 'charset', 'dumb_mode', 'out', 'source', 'file_list', 'wordlist', 'checkpoint', 'max_candidates', 'max_files', 'engine', 'python', 'max_passes', 'seen_cap'):
        V[name].trace(refresh_review)

    def license_changed():
        on = bool(V['license'].get().strip())
        set_license_chip('entered' if on else 'not set', C['info'] if on else C['danger'])
        refresh_review()
    V['license'].trace(license_changed)
    on_show['run'] = refresh_review
    on_show['search'] = lambda: V['dumb'].get() and draw_estimates()

    def on_close():
        job = state['job']
        if job and job.running():
            if not dialog('A search is running', say('Closing the window stops unmicro. Stop and recover the matched files first, or force stop now?'),
                          [('Keep running', False, 'ghost'), ('Force stop and close', True, 'danger')], danger=True):
                return False
            job.kill()
        s = snapshot()
        s['keydata'] = cfg.get('keydata', {})
        s['measured'] = cfg.get('measured', {})
        save_config(cfg_path, s)
        return True

    sync_paths()
    sync_roots()
    sync_sc()
    src_changed()
    dumb_changed()
    workers_changed()
    if cfg['keydata'].get('keys'):
        kd = cfg['keydata']
        set_license_chip(('OK · %d keys' % len(kd['keys'])) if V['license'].get() else 'not set', C['success'] if V['license'].get() else C['danger'])
    else:
        set_license_chip('entered' if V['license'].get() else 'not set', C['info'] if V['license'].get() else C['danger'])
    ready['v'] = True
    refresh_review()
    show(os.environ.get('UNMICRO_GUI_TAB', 'files'))
    win.show()
    later(200, check_engine)
    if os.environ.get('UNMICRO_GUI_TEST_HOOK'):
        # used by the screenshot harness: python code run after start-up
        ns = {'app': app, 'win': win, 'show': show, 'V': V, 'lists': lists, 'start_run': start_run, 'stop_run': stop_run,
              'kill_run': kill_run, 'state': state, 'endless_warning': endless_warning, 'snapshot': snapshot, 'sync_paths': sync_paths,
              'check_license': check_license, 'dumb_changed': dumb_changed, 'pages': pages, 'LIMV': LIM, 'find_files': find_files,
              'dialog': dialog, 'QtCore': QtCore, 'QtGui': QtGui, 'QtWidgets': QtWidgets, 'order': order, 'later': later}
        exec(open(os.environ['UNMICRO_GUI_TEST_HOOK']).read(), ns)
    return app.exec()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    rc = helper_main(argv)  # Windows console helper modes: before any Qt import
    if rc is not None:
        return rc
    if argv[:1] in (['--version'], ['-V']):
        print('unmicro GUI %s (Qt)' % APP_VERSION)
        return 0
    return run_gui()


if __name__ == '__main__':
    sys.exit(main())
