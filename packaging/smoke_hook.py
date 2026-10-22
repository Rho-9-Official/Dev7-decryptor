# CI smoke test: run inside the built program through UNMICRO_GUI_TEST_HOOK.
# It writes what started, and which engine it picked, to $SMOKE_OUT, then
# closes the window.
import os
kind = 'qt' if 'QtWidgets' in globals() else 'tk'


def done():
    with open(os.environ['SMOKE_OUT'], 'w', encoding='utf-8') as fh:
        fh.write('%s ui ok: %d tabs, engine=%r\n' % (kind, len(pages), V['engine'].get()))
    if kind == 'qt':
        app.quit()
    else:
        root.destroy()


(later if kind == 'qt' else root.after)(3000, done)
