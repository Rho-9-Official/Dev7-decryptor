# unmicro GUI

A desktop window for **unmicro**, Rho-9's free decryptor for files encrypted by
the Dev7 / Micro ransomware (renamed to `.cryptedmicro`).

The GUI never decrypts anything itself. It builds the unmicro command line from
the choices on its tabs, runs the unmicro engine, and shows what it does: the
search, the keys found, the files recovered. Your encrypted files are only ever
read.

Two interchangeable windows share one core:

- **Modern** (PySide6 / Qt), the default when PySide6 is available;
- **Classic** (Tk), which needs nothing beyond Python.

The first start asks which one to use and remembers the choice.

## Using it

1. **Files**: choose the folders with the `.cryptedmicro` files, or search the whole computer.
2. **Keys**: enter your licence key (free from recon@rho-9.com; mention "Chattering Magpies") and any keys you know.
3. **Search**: Quick is often enough. Standard and Deep guess harder; the structural brute force tries every key by length.
4. **Output**: where recovered copies go.
5. **Run**: review the plan and the exact command, then Start.

The engine (`unmicro-<version>-windows-x86_64.exe`, or `-linux-x86_64`) is
found inside the exe when bundled, next to the program, or chosen on the
Settings tab. Only use an engine downloaded from Rho-9-Official, with its
checksum verified.

## Running from source

```
python -m unmicro_app            # remembered window, or the menu on first start
python -m unmicro_app --qt       # or --tk; --choose shows the menu again
pip install PySide6-Essentials psutil   # optional: the Qt window, better machine readings
```

## Building the single-file exe

GitHub Actions (`.github/workflows/build.yml`) builds `unmicro-gui.exe` on
Windows for every push, pull request and `v*` tag. It runs the unit tests,
builds with PyInstaller, starts both windows and the console helper as a smoke
test, writes `unmicro-gui.exe.sha256`, and uploads both as the build artifact.
A `v*` tag also attaches them to that release.

To bundle the engine inside the exe, either:

- commit it to an `engine/` folder, or
- run the workflow by hand (Actions -> build -> Run workflow) with the engine's
  download URL and its SHA-256. The build stops if the checksum does not match.

Locally (on Windows for a Windows exe):

```
pip install -r requirements-build.txt
python packaging/make_assets.py
pyinstaller --noconfirm --clean packaging/unmicro.spec
```

Set `UNMICRO_ENGINE_DIR` to a folder holding the engine to bundle it. The
result is `dist/unmicro-gui.exe`.

## Layout

| Path | What |
| --- | --- |
| `unmicro_app/core.py` | Everything that is not a widget: command line, output parser, process control, estimates, safety limits, settings |
| `unmicro_app/qt_ui.py` | The PySide6 window |
| `unmicro_app/tk_ui.py` | The Tk window |
| `unmicro_app/launcher.py` | Entry point: picks the window, handles the Windows console helper modes |
| `packaging/` | PyInstaller spec, icon and version-info generator, CI smoke test |
| `tests/` | Unit tests for the core (`python -m unittest discover -s tests`) |

Rho-9 Systems. Your first line of unusual defense.
