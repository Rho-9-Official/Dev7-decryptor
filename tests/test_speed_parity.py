"""Tests for 5.2: the faster key tests and the GCM search's new methods.

Run from the repository root:

    python -m unittest discover -s tests -v

Every speed-up here has to give the same answer as the code it replaced, so
most tests run the new path and a plain reference side by side. The GCM
tests turn the 600,000-round key stretch down to a few thousand rounds
(fixtures and search both read GCM_KDF_ITERS), which changes nothing but the
time they take. The end-to-end test needs UNMICRO_LICENSE, like the others.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import unmicro  # noqa: E402
from test_edge_cases import Base, KEY, LICENSE, _ecb_seal, jpeg, make_ecb, make_gcm, supplied  # noqa: E402

FAST_ITERS = 2000


def tiers(*pairs):
    """A plan from (name, [guesses]) pairs."""
    return [(name, (lambda g=list(guesses): iter(g))) for name, guesses in pairs]


class FastGcm(Base):
    """Base for the GCM tests: a short key stretch for fixtures and search."""

    def setUp(self):
        Base.setUp(self)
        patcher = mock.patch.object(unmicro, 'GCM_KDF_ITERS', FAST_ITERS)
        patcher.start()
        self.addCleanup(patcher.stop)


# ----------------------------------------------------------------------
# Tag-only GCM key test
# ----------------------------------------------------------------------

class TagOnly(FastGcm):

    def factories(self):
        out = [('active', unmicro._gcm_tag_new), ('pure-python', unmicro._PureGcmTag)]
        return [(n, f) for n, f in out if f is not None]

    def test_self_check_passes_on_every_back_end(self):
        self.assertIsNotNone(unmicro._gcm_tag_new)
        for name, factory in self.factories():
            self.assertTrue(unmicro._gcm_tag_selfcheck(factory), name)

    def test_pycryptodome_path_when_installed(self):
        import importlib.util
        if importlib.util.find_spec('Crypto') is None:
            self.skipTest('pycryptodome not installed')
        saved = unmicro.BACKEND
        try:
            unmicro.BACKEND = 'pycryptodome'
            factory = unmicro._tag_factory()
            self.assertTrue(unmicro._gcm_tag_selfcheck(factory))
        finally:
            unmicro.BACKEND = saved

    def test_agrees_with_full_decryption(self):
        # In memory and streamed from disk (over GCM_READ_CHUNK), right key
        # and wrong key, including a body that is not a whole block.
        for n in (1, 15, 16, 4001, unmicro.GCM_READ_CHUNK + 777):
            path = self.p('f%d.jpg.cryptedmicro' % n)
            make_gcm(path, KEY, jpeg(n) if n > 13 else os.urandom(n))
            size, salt, iv, tag = unmicro.gcm_header(path)
            with open(path, 'rb') as fh:
                body = fh.read()[unmicro.GCM_SALT_LEN + unmicro.GCM_IV_LEN:-unmicro.GCM_TAG_LEN]
            for k in (KEY, 'wrong'):
                dk = unmicro.gcm_kdf(k, salt)
                full = unmicro.gcm_stream(path, size, iv, tag, dk, keep=False)[1] is None
                self.assertEqual(unmicro.gcm_key_opens(path, size, iv, tag, dk), full, (n, k))
                self.assertEqual(unmicro.gcm_key_opens(path, size, iv, tag, dk, body=body), full, (n, k))
                self.assertEqual(full, k == KEY)

    def test_lying_tagger_fails_self_check(self):
        class Liar(object):
            def __init__(self, key, iv):
                pass

            def update(self, data):
                pass

            def tag(self):
                return b'\x00' * 16
        self.assertFalse(unmicro._gcm_tag_selfcheck(Liar))

    def test_failed_self_check_falls_back_to_full_decryption(self):
        with mock.patch.object(unmicro, '_gcm_tag_selfcheck', return_value=False):
            unmicro._init_backend(False)
            self.assertIsNone(unmicro._gcm_tag_new)
            good = self.good_gcm()
            mapping, _, _ = unmicro.find_all_gcm_keys(sorted(good), supplied('nope', KEY), quiet=True)
            self.assertEqual(sorted(mapping[KEY]), sorted(good))
        unmicro._init_backend(False)
        self.assertIsNotNone(unmicro._gcm_tag_new)


# ----------------------------------------------------------------------
# Older format, CPU sweep
# ----------------------------------------------------------------------

class IdentifyFast(unittest.TestCase):

    def test_same_as_identify_ex(self):
        heads = [os.urandom(16) for _ in range(50000)]
        for off, magic, _, _ in unmicro.SIGNATURES:
            for _ in range(20):
                h = bytearray(os.urandom(16))
                h[off:off + len(magic)] = magic
                heads.append(bytes(h))
                # Two signatures at once: the earlier one in the table wins.
                h[4:8] = b'ftyp'
                heads.append(bytes(h))
        for h in heads:
            self.assertEqual(unmicro.identify_fast(h), unmicro.identify_ex(h))


def _reference_worker_chunk(chunk, probes):
    """_worker_chunk as it was before 5.2: one decrypt per probe."""
    hits = []
    for cand in chunk:
        kb = unmicro.key_bytes(cand)
        for blk, path in probes:
            label, _, strong = unmicro.identify_ex(unmicro._dec_blocks(kb, blk))
            if not label:
                continue
            if strong or unmicro.confirm_key(cand, path):
                hits.append(cand)
                break
    return hits


@unittest.skipIf(_ecb_seal is None, 'needs cryptography or pycryptodome to build fixtures')
class WorkerChunk(Base):

    def test_same_hits_as_one_probe_at_a_time(self):
        keys = ['k%d' % i for i in range(3)]
        probes = []
        for i, k in enumerate(keys):
            path = self.p('p%d.jpg.cryptedmicro' % i)
            make_ecb(path, k, jpeg(3000 + 16 * i))
            with open(path, 'rb') as fh:
                probes.append((fh.read(16), path))
        probes.append((os.urandom(16), self.p('x.bin')))
        cands = ['c%d' % i for i in range(20000)] + keys + ['k1', 'ç-ğ-ş', 'x' * 40]
        unmicro._worker_init(probes)
        self.assertEqual(unmicro._worker_chunk(cands), _reference_worker_chunk(cands, probes))
        self.assertTrue(set(keys) <= set(unmicro._worker_chunk(cands)))

    def test_sweep_finds_key_in_a_later_chunk_with_workers(self):
        files = []
        for i in range(2):
            path = self.p('d%d' % i, 'e%d.jpg.cryptedmicro' % i)
            make_ecb(path, KEY, jpeg(4000 + 16 * i))
            files.append(path)
        guesses = ['g%d' % i for i in range(1000)] + [KEY]
        found, tried = unmicro.sweep(files, tiers(('wordlist', guesses)), workers=2, quiet=True, chunk_size=97)
        self.assertEqual(found, [KEY])
        self.assertEqual(tried, len(guesses))


# ----------------------------------------------------------------------
# GCM search: every method, checkpoint, gate, GPU pipeline
# ----------------------------------------------------------------------

class GcmMethods(FastGcm):

    def test_open_ended_methods_run_on_gcm(self):
        good = self.good_gcm()
        plan = tiers(('fitted model', ['a', 'b']), ('structural brute len=2', ['aa', 'ab', KEY]))
        found, tried = unmicro.sweep_gcm(sorted(good), plan, quiet=True)
        self.assertEqual(found, [KEY])
        self.assertEqual(tried, 5)

    def test_checkpoint_resumes_without_repeating(self):
        good = self.good_gcm()
        ck = unmicro.gcm_checkpoint_path(self.p('progress.ckpt'))
        guesses = ['w%d' % i for i in range(40)] + [KEY]
        plan = tiers(('wordlist', guesses))
        found, tried = unmicro.sweep_gcm(sorted(good), plan, workers=1, limit=20, quiet=True, checkpoint=ck)
        self.assertEqual(found, [])
        self.assertTrue(os.path.exists(ck))
        seen = []
        real = unmicro.gcm_kdf

        def counting(k, salt):
            seen.append(k)
            return real(k, salt)
        with mock.patch.object(unmicro, 'gcm_kdf', counting):
            found, tried = unmicro.sweep_gcm(sorted(good), plan, workers=1, quiet=True, checkpoint=ck)
        self.assertEqual(found, [KEY])
        self.assertEqual(tried, len(guesses))
        # Nothing before the saved place was tried again.
        self.assertFalse(set(seen) & set(guesses[:20]))
        # A found key clears the entry.
        self.assertFalse(os.path.exists(ck))

    def test_checkpoint_keeps_one_entry_per_file_set(self):
        a = self.good_gcm(2)
        other = []
        for i in range(2):
            path = self.p('o%d.png.cryptedmicro' % i)
            make_gcm(path, 'other-key', jpeg(6007 + i))
            other.append(path)
        ck = unmicro.gcm_checkpoint_path(self.p('progress.ckpt'))
        plan = tiers(('wordlist', ['w%d' % i for i in range(30)]))
        unmicro.sweep_gcm(sorted(a), plan, workers=1, limit=10, quiet=True, checkpoint=ck)
        unmicro.sweep_gcm(sorted(other), plan, workers=1, limit=6, quiet=True, checkpoint=ck)
        entries = unmicro._gcm_ckpt_read(ck)
        self.assertEqual(len(entries), 2)
        sig_a = unmicro._gcm_ckpt_sig(unmicro.gcm_probe_order(sorted(a)))
        self.assertEqual(unmicro._gcm_ckpt_load(ck, sig_a)[3], 10)

    def test_gate_stops_and_saves_place(self):
        good = self.good_gcm()
        ck = unmicro.gcm_checkpoint_path(self.p('progress.ckpt'))
        plan = tiers(('fitted model', ['a', 'b']), ('structural brute len=3', ['abc', KEY]))
        asked = []

        def gate(name, idx):
            asked.append(name)
            return not name.startswith('structural')
        unmicro.STATUS.gate_declined = False
        try:
            found, tried = unmicro.sweep_gcm(sorted(good), plan, quiet=True, checkpoint=ck, on_tier_start=gate)
            self.assertEqual(found, [])
            self.assertTrue(unmicro.STATUS.gate_declined)
        finally:
            unmicro.STATUS.gate_declined = False
        self.assertEqual(asked, ['fitted model', 'structural brute len=3'])
        sig = unmicro._gcm_ckpt_sig(unmicro.gcm_probe_order(sorted(good)))
        self.assertEqual(unmicro._gcm_ckpt_load(ck, sig)[:2], ('structural brute len=3', 0))
        # Resuming starts at the declined method.
        found, tried = unmicro.sweep_gcm(sorted(good), plan, quiet=True, checkpoint=ck)
        self.assertEqual(found, [KEY])
        self.assertEqual(tried, 4)

    def test_rate_is_measured(self):
        unmicro._GCM_RATE[:] = [0, 0.0]
        self.assertEqual(unmicro.gcm_rate(None, 3), 24.0)
        unmicro._GCM_RATE[:] = [100, 4.0]
        self.assertEqual(unmicro.gcm_rate(None, 3), 25.0)
        unmicro._GCM_RATE[:] = [0, 0.0]


class _CpuGpu(object):
    """Right answers from hashlib, in small batches, to drive the GPU
    pipeline without a GPU."""
    name = 'stand-in'
    batch = 8

    def __init__(self, fail_at=None, pause_at=None):
        self.calls = 0
        self.fail_at = fail_at
        self.pause_at = pause_at

    def derive_keys(self, key_strings, salts):
        self.calls += 1
        if self.fail_at is not None and self.calls >= self.fail_at:
            raise RuntimeError('device lost')
        if self.pause_at is not None and self.calls == self.pause_at:
            unmicro.STATUS.pause_requested = True
        if isinstance(salts, (bytes, bytearray)):
            salts = [salts] * len(key_strings)
        return [unmicro.gcm_kdf(k, s) for k, s in zip(key_strings, salts)]


class GpuPipeline(FastGcm):

    def guesses(self):
        return ['wrong%d' % i for i in range(45)] + [KEY]

    def test_finds_key_across_many_chunks(self):
        good = self.good_gcm()
        gpu = _CpuGpu()
        found, tried = unmicro.sweep_gcm(sorted(good), tiers(('wordlist', self.guesses())), workers=1, quiet=True, gpu=gpu)
        self.assertEqual(found, [KEY])
        self.assertEqual(tried, len(self.guesses()))
        self.assertGreater(gpu.calls, 5)

    def test_pause_in_the_middle_loses_no_guess(self):
        good = self.good_gcm()
        gpu = _CpuGpu(pause_at=5)
        status = unmicro.STATUS
        old_menu = status.pause_menu
        status.pause_menu = lambda: 1
        try:
            found, tried = unmicro.sweep_gcm(sorted(good), tiers(('wordlist', self.guesses())), workers=1, quiet=True, gpu=gpu)
        finally:
            status.pause_menu = old_menu
            status.pause_requested = False
        self.assertEqual(found, [KEY])
        self.assertEqual(tried, len(self.guesses()))

    def test_device_lost_mid_run_hands_over_to_cpu(self):
        good = self.good_gcm()
        gpu = _CpuGpu(fail_at=4)
        found, tried = unmicro.sweep_gcm(sorted(good), tiers(('wordlist', self.guesses())), workers=1, quiet=True, gpu=gpu)
        self.assertEqual(found, [KEY])
        self.assertEqual(tried, len(self.guesses()))

    def test_limit_counts_the_chunk_in_flight(self):
        good = self.good_gcm()
        found, tried = unmicro.sweep_gcm(sorted(good), tiers(('wordlist', self.guesses())), workers=1, limit=20, quiet=True, gpu=_CpuGpu())
        self.assertEqual(found, [])
        self.assertEqual(tried, 20)

    def test_map_with_pipeline_and_many_slices(self):
        good = self.good_gcm(5, sizes=(5001, 7003, 9005, 4001, 3003))
        stray = self.p('x.doc.cryptedmicro')
        make_gcm(stray, 'other', jpeg(4099))
        gpu = _CpuGpu()
        gpu.batch = 2
        part = unmicro.map_gcm_keys_to_files(sorted(good + [stray]), ['nope', KEY], workers=1, quiet=True, gpu=gpu)
        self.assertEqual(sorted(part), [KEY])
        self.assertEqual(sorted(part[KEY]), sorted(good))


# ----------------------------------------------------------------------
# End to end (needs the licence, like the other end-to-end tests)
# ----------------------------------------------------------------------

@unittest.skipIf(not LICENSE, 'set UNMICRO_LICENSE to run the end-to-end tests')
class EndToEnd(FastGcm):

    def run_main(self, *argv):
        import contextlib
        import io
        out_dir = tempfile.mkdtemp(prefix='unmicro-out-')
        self.addCleanup(__import__('shutil').rmtree, out_dir, True)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = unmicro.main(['--license', LICENSE, '--workers', '1', '--out', out_dir] + list(argv))
        return code, out.getvalue()

    def test_structural_brute_opens_gcm_files(self):
        # A two-character key over letters every recovered key list holds.
        key = 'za'
        for i in range(2):
            make_gcm(self.p('n%d' % i, 'f%d.jpg.cryptedmicro' % i), key, jpeg(5001 + 2 * i))
        code, out = self.run_main('--in', self.dir, '--recursive', '--dumb-brute', '--charset', 'observed', '--yes', '--max-passes', '1')
        self.assertEqual(code, 0, out)
        self.assertIn('ALL USABLE FILES RECOVERED', out)


if __name__ == '__main__':
    unittest.main()
