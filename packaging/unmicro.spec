# PyInstaller spec: unmicro, the GUI with the engine built in, as one
# windowed single-file executable.
#   python packaging/make_assets.py
#   pyinstaller --noconfirm --clean packaging/unmicro.spec
# The engine (unmicro.py) is a module inside it: the GUI runs it with
# --engine, people who want the command line with --cli.
import os
import sys

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, '..'))  # noqa: F821 (PyInstaller global)
ASSETS = os.path.join(ROOT, 'build', 'assets')
WIN = sys.platform == 'win32'

icon = os.path.join(ASSETS, 'unmicro.ico')
version = os.path.join(ASSETS, 'version_info.txt')

a = Analysis(  # noqa: F821
    [os.path.join(ROOT, 'unmicro_app', '__main__.py')],
    pathex=[ROOT],
    hiddenimports=['unmicro', 'unmicro_app.qt_ui', 'unmicro_app.tk_ui',
                   'Crypto.Cipher.AES'] + collect_submodules('filetype'),
    excludes=['PySide6.QtNetwork', 'PySide6.QtQml', 'PySide6.QtQuick', 'PySide6.QtSql', 'PySide6.QtTest',
              'PySide6.QtOpenGL', 'PySide6.QtOpenGLWidgets', 'PySide6.QtPdf', 'PySide6.QtSvg', 'PySide6.QtXml',
              'PySide6.QtDBus', 'PySide6.QtConcurrent', 'PySide6.QtPrintSupport', 'PySide6.QtDesigner',
              'PySide6.QtUiTools', 'PySide6.QtHelp', 'PySide6.QtMultimedia', 'PySide6.QtWebEngineCore',
              'PIL'],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821
# upx=False on purpose: UPX is one of the biggest drivers of antivirus false
# positives, and a decryptor quarantined on a victim's machine is a failure.
exe = EXE(  # noqa: F821
    pyz, a.scripts, a.binaries, a.datas, [],
    name='unmicro',
    console=False,
    icon=icon if os.path.exists(icon) else None,
    version=version if WIN and os.path.exists(version) else None,
    upx=False,
    debug=False,
    strip=False,
)
