# PyInstaller spec: unmicro-gui as one windowed, single-file executable.
#   python packaging/make_assets.py
#   pyinstaller --noconfirm --clean packaging/unmicro.spec
# Set UNMICRO_ENGINE_DIR to a folder holding the unmicro engine binary to
# bundle it inside the exe (the GUI finds it there first).
import os
import sys

ROOT = os.path.abspath(os.path.join(SPECPATH, '..'))  # noqa: F821 (PyInstaller global)
BUILD = os.path.join(ROOT, 'build', 'assets')
WIN = sys.platform == 'win32'

datas = []
engine_dir = os.environ.get('UNMICRO_ENGINE_DIR')
if engine_dir:
    for name in sorted(os.listdir(engine_dir)):
        p = os.path.join(engine_dir, name)
        if os.path.isfile(p):
            datas.append((p, 'engine'))
    if not datas:
        raise SystemExit('UNMICRO_ENGINE_DIR=%s holds no files' % engine_dir)

icon = os.path.join(BUILD, 'unmicro.ico')
version = os.path.join(BUILD, 'version_info.txt')

a = Analysis(  # noqa: F821
    [os.path.join(ROOT, 'unmicro_app', '__main__.py')],
    pathex=[ROOT],
    datas=datas,
    hiddenimports=['unmicro_app.qt_ui', 'unmicro_app.tk_ui'],
    excludes=['PySide6.QtNetwork', 'PySide6.QtQml', 'PySide6.QtQuick', 'PySide6.QtSql', 'PySide6.QtTest',
              'PySide6.QtOpenGL', 'PySide6.QtOpenGLWidgets', 'PySide6.QtPdf', 'PySide6.QtSvg', 'PySide6.QtXml',
              'PySide6.QtDBus', 'PySide6.QtConcurrent', 'PySide6.QtPrintSupport', 'PySide6.QtDesigner',
              'PySide6.QtUiTools', 'PySide6.QtHelp', 'PySide6.QtMultimedia', 'PySide6.QtWebEngineCore'],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz, a.scripts, a.binaries, a.datas, [],
    name='unmicro-gui',
    console=False,
    icon=icon if os.path.exists(icon) else None,
    version=version if WIN and os.path.exists(version) else None,
    upx=False,
    debug=False,
    strip=False,
)
