"""Regression tests for the 3.8.2 edge-case fixes.

Run from the repository root:

    python -m unittest discover -s tests -v

Most tests need no license. The end-to-end tests drive main() and need the
build's license key in UNMICRO_LICENSE; they are skipped without it, so the
key never has to live in CI or in this repository.

The fixtures are encrypted here with throwaway keys. The encrypt side lives
only in this test file, never in unmicro.py.
"""
import contextlib
import hashlib
import io
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import unmicro  # noqa: E402

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms as _alg, modes as _modes

    def _gcm_seal(dk, iv, pt):
        return _AESGCM(dk).encrypt(iv, pt, None)

    def _ecb_seal(kb, pt):
        enc = _Cipher(_alg.AES(kb), _modes.ECB()).encryptor()
        return enc.update(pt) + enc.finalize()
except ImportError:
    try:
        from Crypto.Cipher import AES as _AES

        def _gcm_seal(dk, iv, pt):
            ct, tag = _AES.new(dk, _AES.MODE_GCM, nonce=iv).encrypt_and_digest(pt)
            return ct + tag

        def _ecb_seal(kb, pt):
            return _AES.new(kb, _AES.MODE_ECB).encrypt(pt)
    except ImportError:
        _gcm_seal = _ecb_seal = None

LICENSE = os.environ.get(unmicro.LICENSE_ENV)
KEY = 'fixture-key-31'


def jpeg(n):
    """A structurally valid JPEG-shaped plaintext of exactly n bytes."""
    body = b'\xff\xd8\xff\xe0' + b'\x00\x10JFIF\x00' + os.urandom(max(0, n - 13))
    return (body[:n - 2] + b'\xff\xd9')


def make_gcm(path, key, pt):
    salt, iv = os.urandom(16), os.urandom(12)
    dk = hashlib.pbkdf2_hmac('sha256', key.encode('utf-8'), salt, unmicro.GCM_KDF_ITERS, 32)
    with open(path, 'wb') as fh:
        fh.write(salt + iv + _gcm_seal(dk, iv, pt))


def make_ecb(path, key, pt):
    n = 16 - len(pt) % 16
    with open(path, 'wb') as fh:
        fh.write(_ecb_seal(unmicro.key_bytes(key), pt + bytes([n]) * n))


def junk(path, n):
    with open(path, 'wb') as fh:
        fh.write(os.urandom(n))


def supplied(*keys):
    return [('supplied keys', lambda: iter(list(keys)))]


@unittest.skipIf(_gcm_seal is None, 'needs cryptography or pycryptodome to build fixtures')
class Base(unittest.TestCase):
    def setUp(self):
        unmicro._init_backend(False)
        unmicro._KDF_CACHE.clear()
        unmicro._GCM_PROBE_CACHE.clear()
        self.dir = tempfile.mkdtemp(prefix='unmicro-test-')

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def p(self, *parts):
        path = os.path.join(self.dir, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    def good_gcm(self, count=3, key=KEY, sizes=(5001, 7003, 9005)):
        out = []
        for i in range(count):
            path = self.p('good%d.jpg.cryptedmicro' % i)
            make_gcm(path, key, jpeg(sizes[i % len(sizes)]))
            out.append(path)
        return out

    def poison(self):
        # Smaller than every good file, so the old code picked exactly these
        # two as its only probes. Sizes avoid multiples of 16.
        a, b = self.p('partial1.jpg.cryptedmicro'), self.p('partial2.doc.cryptedmicro')
        junk(a, 401)
        junk(b, 803)
        return [a, b]


class ProbeRotation(Base):
    """Issue 1: two unopenable small files hid a key that opens the rest."""

    def test_key_found_past_two_bad_smallest_files(self):
        good = self.good_gcm()
        files = sorted(good + self.poison())
        mapping, _, remaining = unmicro.find_all_gcm_keys(files, supplied('nope', KEY), quiet=True)
        self.assertEqual(sorted(mapping.get(KEY, [])), sorted(good))
        self.assertEqual(len(remaining), 2)

    def test_probed_reports_files_actually_tested(self):
        files = sorted(self.good_gcm(1) + self.poison())
        probed = set()
        unmicro.find_all_gcm_keys(files, supplied(KEY), quiet=True, probed=probed)
        self.assertEqual(len(probed), 3)


class LaterPasses(Base):
    """Issue 2: matched files waited behind an hour of variants for stragglers."""

    def test_later_plan_replaces_slow_tier_after_a_hit(self):
        calls = []

        def variants():
            calls.append(1)
            return iter(['v1', 'v2'])
        plan = supplied(KEY) + [('recovered key variants', variants)]
        files = sorted(self.good_gcm() + self.poison())
        later = [t for t in plan if t[0] != 'recovered key variants']
        mapping, _, _ = unmicro.find_all_gcm_keys(files, plan, quiet=True, later_plan=later)
        self.assertEqual(len(mapping[KEY]), 3)
        self.assertEqual(calls, [])
        # Without later_plan the stragglers do get the slow tier.
        unmicro.find_all_gcm_keys(files, plan, quiet=True)
        self.assertEqual(calls, [1])

    def test_on_part_sees_each_mapping_as_it_is_made(self):
        parts = []
        unmicro.find_all_gcm_keys(sorted(self.good_gcm()), supplied(KEY), quiet=True, on_part=parts.append)
        self.assertEqual(len(parts), 1)
        self.assertEqual(len(parts[0][KEY]), 3)


class Scan(Base):
    """Issue 3: Dev, Run, Recovery... skipped at any depth; extension case."""

    def test_system_names_pruned_only_at_root(self):
        keep = [self.p('Users', 'v', d, 'x.jpg.cryptedmicro') for d in ('Dev', 'Run', 'Recovery', 'Windows', 'Snap', 'Sys')]
        keep.append(self.p('Users', 'v', 'Documents', 'UPPER.JPG.CRYPTEDMICRO'))
        drop = [self.p('Windows', 'x.jpg.cryptedmicro'), self.p('Users', 'v', 'node_modules', 'x.jpg.cryptedmicro')]
        for f in keep + drop:
            junk(f, 100)
        found = unmicro.walk_for_encrypted([self.dir], progress=False)
        self.assertEqual(sorted(found), sorted(keep))

    def test_collect_matches_any_case(self):
        f = self.p('a.PNG.CryptedMicro')
        junk(f, 100)
        self.assertEqual(unmicro.collect(self.dir, False), [os.path.abspath(f)])
        self.assertEqual(unmicro.collect(f, False), [os.path.abspath(f)])


class Console(unittest.TestCase):
    """Issue 5: the double-click window closed before anyone could read it."""

    def test_alone_on_console(self):
        self.assertTrue(unmicro.alone_on_console(1, frozen=False))
        self.assertFalse(unmicro.alone_on_console(2, frozen=False))
        self.assertTrue(unmicro.alone_on_console(2, frozen=True))
        self.assertFalse(unmicro.alone_on_console(3, frozen=True))
        self.assertFalse(unmicro.alone_on_console(0, frozen=True))

    def test_not_windows_never_holds(self):
        if not unmicro.WINDOWS:
            self.assertFalse(unmicro.launched_by_double_click())


class Streaming(Base):
    """Issue 7: GCM output is streamed, not built in memory."""

    def test_streamed_matches_in_memory(self):
        path = self.good_gcm(1, sizes=(3 * unmicro.GCM_READ_CHUNK + 777,))[0]
        sink = io.BytesIO()
        self.assertIsNone(unmicro.gcm_decrypt_to(path, KEY, sink))
        pt, verified, _ = unmicro.decrypt_file(path, KEY, scheme='gcm')
        self.assertTrue(verified)
        self.assertEqual(sink.getvalue(), pt)

    def test_wrong_key_reports_reason(self):
        path = self.good_gcm(1)[0]
        self.assertIn('tag mismatch', unmicro.gcm_decrypt_to(path, 'wrong', io.BytesIO()))


@unittest.skipUnless(LICENSE, 'set %s to run the end-to-end tests' % unmicro.LICENSE_ENV)
class EndToEnd(Base):
    def setUp(self):
        Base.setUp(self)
        self.out = tempfile.mkdtemp(prefix='unmicro-out-')
        self.addCleanup(shutil.rmtree, self.out, True)

    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = unmicro.main(['--license', LICENSE, '--workers', str(os.cpu_count() or 1), '--out', self.out] + list(argv))
        return code, out.getvalue()

    def test_poisoned_folder_recovers_good_files(self):
        self.good_gcm()
        self.poison()
        code, out = self.run_main('--in', self.dir, '--key', KEY)
        self.assertEqual(code, 0, out)
        self.assertIn('Recovered and verified : 3', out)

    def test_aligned_gcm_not_stuck_behind_ecb_brute(self):
        # Plaintext length 4 mod 16 makes the GCM file block-aligned.
        make_gcm(self.p('aligned.jpg.cryptedmicro'), KEY, jpeg(16 * 300 + 4))
        self.assertEqual(os.path.getsize(self.p('aligned.jpg.cryptedmicro')) % 16, 0)
        code, out = self.run_main('--in', self.dir, '--key', KEY, '--brute', '--max-candidates', '5000')
        self.assertEqual(code, 0, out)
        self.assertIn('before any brute force', out)
        self.assertIn('Recovered and verified : 1', out)

    def test_ecb_still_recovers(self):
        make_ecb(self.p('old.jpg.cryptedmicro'), KEY, jpeg(4000))
        code, out = self.run_main('--in', self.dir, '--key', KEY)
        self.assertEqual(code, 0, out)
        self.assertIn('Recovered and verified : 1', out)

    def test_mixed_ecb_and_gcm_with_brute(self):
        make_ecb(self.p('old.jpg.cryptedmicro'), KEY, jpeg(4000))
        self.good_gcm(2)
        code, out = self.run_main('--in', self.dir, '--key', KEY, '--brute', '--max-candidates', '5000')
        self.assertEqual(code, 0, out)
        self.assertIn('Recovered and verified : 3', out)

    def test_no_key_message_names_files_tested(self):
        # More files than GCM_ROTATE_FILES, none openable: the message has
        # to say that only the smallest were tested.
        n = unmicro.GCM_ROTATE_FILES + 2
        for i in range(n):
            junk(self.p('j%02d.jpg.cryptedmicro' % i), 401 + i * 2)
        code, out = self.run_main('--in', self.dir, '--key', KEY)
        self.assertEqual(code, 2, out)
        self.assertIn('checked against %d of the %d' % (unmicro.GCM_ROTATE_FILES, n), out)


class DamagedCopies(Base):
    """Interrupted runs leave stubs and cut-short copies. They are screened
    out before probes are chosen and listed in a report."""

    def write(self, name, data):
        path = self.p(name)
        with open(path, 'wb') as fh:
            fh.write(data)
        return path

    def read(self, path):
        with open(path, 'rb') as fh:
            return fh.read()

    def sizes(self, files):
        return {f: unmicro.file_size(f) for f in files}

    def screen(self, files):
        return unmicro.split_damaged(files, self.sizes(files))

    def test_empty_and_stub_lengths_flagged(self):
        files = [self.write('empty.jpg.cryptedmicro', b''), self.write('three.jpg.cryptedmicro', os.urandom(3)),
                 self.write('odd30.jpg.cryptedmicro', os.urandom(30)), self.write('odd43.jpg.cryptedmicro', os.urandom(43))]
        good, bad = self.screen(files)
        self.assertEqual(good, [])
        self.assertEqual([b[2] for b in bad], ['empty', 'stub', 'stub', 'stub'])

    def test_zero_filled_flagged(self):
        files = [self.write('zeros.jpg.cryptedmicro', b'\x00' * 4096),
                 self.write('zerotail.jpg.cryptedmicro', os.urandom(2000) + b'\x00' * 64)]
        good, bad = self.screen(files)
        self.assertEqual(good, [])
        self.assertEqual([b[2] for b in bad], ['zero-head', 'zero-tail'])

    def test_whole_looking_files_pass(self):
        files = self.good_gcm(3)
        make_ecb(self.p('old.jpg.cryptedmicro'), KEY, jpeg(4000))
        files.append(self.p('old.jpg.cryptedmicro'))
        # Smallest legal ECB (one block) and smallest legal GCM (44 bytes).
        files.append(self.write('oneblock.jpg.cryptedmicro', os.urandom(16)))
        files.append(self.write('mingcm.jpg.cryptedmicro', os.urandom(44)))
        good, bad = self.screen(files)
        self.assertEqual(sorted(good), sorted(files))
        self.assertEqual(bad, [])

    def test_stubs_never_become_probes(self):
        good = self.good_gcm()
        stubs = [self.write('s%d.jpg.cryptedmicro' % i, b'\x00' * (100 + i)) for i in range(5)]
        files = sorted(good + stubs)
        kept, bad = self.screen(files)
        self.assertEqual(len(bad), 5)
        self.assertEqual(sorted(unmicro.gcm_probe_order(kept)), sorted(good))
        mapping, _, remaining = unmicro.find_all_gcm_keys(kept, supplied('nope', KEY), quiet=True)
        self.assertEqual(sorted(mapping.get(KEY, [])), sorted(good))
        self.assertEqual(remaining, [])

    def test_many_stubs_do_not_break_ecb_probe_choice(self):
        good = []
        for i in range(3):
            path = self.p('good%d.jpg.cryptedmicro' % i)
            make_ecb(path, KEY, jpeg(3000 + i * 160))
            good.append(path)
        stubs = [self.write('z%02d.jpg.cryptedmicro' % i, b'\x00' * 16) for i in range(40)]
        kept, bad = self.screen(sorted(good + stubs))
        self.assertEqual(len(bad), 40)
        probes = unmicro.probe_set(kept)
        self.assertEqual(sorted(p[1] for p in probes), sorted(good))
        # Before the screen, the zero-block stubs were the biggest group and
        # so the first probe.
        raw = unmicro.probe_set(sorted(good + stubs))
        self.assertIn(stubs[0], [p[1] for p in raw] + stubs)
        self.assertTrue(any(p[1] in stubs for p in raw))

    def test_diagnose_finds_cut_short_real_encryption(self):
        make_ecb(self.p('whole.jpg.cryptedmicro'), KEY, jpeg(4000))
        with open(self.p('whole.jpg.cryptedmicro'), 'rb') as fh:
            data = fh.read()
        cut = self.write('cut.jpg.cryptedmicro', data[:1003])
        foreign = self.write('foreign.jpg.cryptedmicro', os.urandom(1003))
        found = unmicro.diagnose_damaged([cut, foreign], [KEY])
        self.assertEqual([f[0] for f in found], [cut])
        self.assertEqual(found[0][2], 'truncated')

    def test_report_written_and_originals_untouched(self):
        a = self.write('empty.jpg.cryptedmicro', b'')
        b = self.write('zeros.jpg.cryptedmicro', b'\x00' * 64)
        before = [self.read(a), self.read(b)]
        _, bad = self.screen([a, b])
        out = os.path.join(self.dir, 'out')
        path = unmicro.write_damage_report(out, bad, quiet=True)
        self.assertEqual(os.path.basename(path), unmicro.DAMAGE_REPORT)
        with open(path, encoding='utf-8') as fh:
            text = fh.read()
        self.assertIn(a, text)
        self.assertIn(b, text)
        self.assertEqual(before, [self.read(a), self.read(b)])
        self.assertIsNone(unmicro.write_damage_report(out, [], quiet=True))
        self.assertIsNone(unmicro.write_damage_report(None, bad, quiet=True))


if __name__ == '__main__':
    unittest.main()
