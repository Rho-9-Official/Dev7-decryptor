#!/usr/bin/env python3
"""Build-time assets for the one-file exe, written to build/assets/:
unmicro.ico (Aviary's bird mark, every Windows icon size) and
version_info.txt (the exe's Windows file properties)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from unmicro_app import __version__  # noqa: E402
from unmicro_app.core import BIRD_EYE, C, bird_polygon  # noqa: E402

OUT = os.path.join(ROOT, 'build', 'assets')


def icon(path):
    from PIL import Image, ImageDraw
    S = 1024  # drawn large, scaled down for each size
    img = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, S - 1, S - 1), radius=S // 5, fill=C['primary'])
    sc, off = S * 0.62 / 24.0, S * 0.19
    d.polygon(bird_polygon(sc, off, off), fill='#ffffff')
    ex, ey, er = BIRD_EYE
    cx, cy, r = off + ex * sc, off + ey * sc, er * sc
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=C['primary'])
    sizes = [(n, n) for n in (16, 20, 24, 32, 40, 48, 64, 128, 256)]
    img.resize((256, 256), Image.LANCZOS).save(path, sizes=sizes)


def version_info(path):
    nums = [int(x) for x in (__version__.split('.') + ['0', '0', '0'])[:4]]
    t = tuple(nums)
    text = '''VSVersionInfo(
  ffi=FixedFileInfo(filevers=%(t)r, prodvers=%(t)r, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'Rho-9 Systems'),
      StringStruct('FileDescription', 'unmicro - Dev7 / Micro decryptor'),
      StringStruct('FileVersion', '%(v)s'),
      StringStruct('InternalName', 'unmicro-gui'),
      StringStruct('OriginalFilename', 'unmicro-gui.exe'),
      StringStruct('ProductName', 'unmicro'),
      StringStruct('ProductVersion', '%(v)s')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
''' % {'t': t, 'v': __version__}
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(text)


if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    icon(os.path.join(OUT, 'unmicro.ico'))
    version_info(os.path.join(OUT, 'version_info.txt'))
    print('assets for unmicro GUI %s in %s' % (__version__, OUT))
