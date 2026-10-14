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
        self.assertIn('PARTLY RECOVERED', out)
        self.assertRegex(out, r'Recovered and checked \.*\s+3\b')

    def test_aligned_gcm_not_stuck_behind_ecb_brute(self):
        # Plaintext length 4 mod 16 makes the GCM file block-aligned.
        make_gcm(self.p('aligned.jpg.cryptedmicro'), KEY, jpeg(16 * 300 + 4))
        self.assertEqual(os.path.getsize(self.p('aligned.jpg.cryptedmicro')) % 16, 0)
        code, out = self.run_main('--in', self.dir, '--key', KEY, '--brute', '--max-candidates', '5000', '--verbose')
        self.assertEqual(code, 0, out)
        self.assertIn('before any brute force', out)
        self.assertIn('ALL USABLE FILES RECOVERED', out)
        self.assertRegex(out, r'Recovered and checked \.*\s+1\b')

    def test_ecb_still_recovers(self):
        make_ecb(self.p('old.jpg.cryptedmicro'), KEY, jpeg(4000))
        code, out = self.run_main('--in', self.dir, '--key', KEY)
        self.assertEqual(code, 0, out)
        self.assertIn('ALL USABLE FILES RECOVERED', out)
        self.assertRegex(out, r'Recovered and checked \.*\s+1\b')

    def test_mixed_ecb_and_gcm_with_brute(self):
        make_ecb(self.p('old.jpg.cryptedmicro'), KEY, jpeg(4000))
        self.good_gcm(2)
        code, out = self.run_main('--in', self.dir, '--key', KEY, '--brute', '--max-candidates', '5000')
        self.assertEqual(code, 0, out)
        self.assertIn('ALL USABLE FILES RECOVERED', out)
        self.assertRegex(out, r'Recovered and checked \.*\s+3\b')

    def test_no_key_message_names_files_tested(self):
        # More files than GCM_ROTATE_FILES, none openable: the message has
        # to say that only the smallest were tested.
        n = unmicro.GCM_ROTATE_FILES + 2
        for i in range(n):
            junk(self.p('j%02d.jpg.cryptedmicro' % i), 401 + i * 2)
        code, out = self.run_main('--in', self.dir, '--key', KEY, '--verbose')
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


MB = 1024 * 1024


class ProbeSelection(Base):
    """Probes come from files of 10 MB or more, spread across sizes, and
    never two from one folder unless 60% of the files share a folder."""

    def entries(self, spec):
        # spec: {directory: [size, ...]} -> [(size, path)] with fake paths
        out = []
        for d, sizes in spec.items():
            for i, size in enumerate(sizes):
                out.append((size, '/%s/f%d_%d.cryptedmicro' % (d, size, i)))
        return out

    def pick(self, spec, want, **kw):
        ents = self.entries(spec)
        same = unmicro.dominant_directory_share([p for _, p in ents]) >= unmicro.PROBE_DOMINANT_DIR
        return unmicro.select_probes(ents, want, same, unmicro.PROBE_MIN_BYTES, unmicro.PROBE_MAX_BYTES, **kw)

    def dirs(self, paths):
        return [os.path.dirname(p) for p in paths]

    def test_floor_preferred_over_small_files(self):
        spec = {'a': [4000, 11 * MB], 'b': [5000, 30 * MB], 'c': [9000, 60 * MB]}
        got = self.pick(spec, 3)
        self.assertEqual(sorted(os.path.basename(p).split('_')[0] for p in got), ['f11534336', 'f31457280', 'f62914560'])

    def test_one_per_folder_when_no_folder_dominates(self):
        spec = {'a': [20 * MB, 21 * MB, 22 * MB], 'b': [23 * MB, 24 * MB], 'c': [25 * MB, 26 * MB]}
        got = self.pick(spec, 3)
        self.assertEqual(len(set(self.dirs(got))), 3)

    def test_same_folder_allowed_when_60_percent_share_it(self):
        spec = {'a': [20 * MB, 21 * MB, 22 * MB, 23 * MB, 24 * MB, 25 * MB], 'b': [26 * MB], 'c': [27 * MB]}
        # 6 of 8 files (75%) in /a, so more than one probe may come from it.
        self.assertGreaterEqual(unmicro.dominant_directory_share(p for _, p in self.entries(spec)), 0.6)
        got = self.pick(spec, 5)
        self.assertEqual(len(got), 5)
        self.assertGreater(self.dirs(got).count('/a'), 1)

    def test_not_dominant_stays_strict_beyond_minimum(self):
        spec = {'a': [20 * MB, 21 * MB], 'b': [22 * MB, 23 * MB], 'c': [24 * MB, 25 * MB]}
        self.assertLess(unmicro.dominant_directory_share(p for _, p in self.entries(spec)), 0.6)
        got = self.pick(spec, 6, min_probes=2)
        self.assertEqual(len(got), 3)
        self.assertEqual(len(set(self.dirs(got))), 3)

    def test_minimum_guard_relaxes_folder_rule_for_two_folders(self):
        spec = {'a': [20 * MB, 21 * MB], 'b': [22 * MB, 23 * MB]}
        got = self.pick(spec, 4, min_probes=4)
        self.assertEqual(len(got), 4)

    def test_falls_back_to_small_files_and_spreads_sizes(self):
        spec = {'a': [1000], 'b': [2000], 'c': [3000], 'd': [4000], 'e': [5000]}
        got = self.pick(spec, 3)
        sizes = sorted(int(os.path.basename(p).split('_')[0][1:]) for p in got)
        self.assertEqual(len(got), 3)
        self.assertNotEqual(sizes, [1000, 2000, 3000])
        self.assertIn(3000, sizes)

    def test_oversize_file_is_last_resort(self):
        spec = {'a': [10 * MB], 'b': [unmicro.PROBE_MAX_BYTES + MB], 'c': [5000]}
        got = self.pick(spec, 3)
        names = [os.path.basename(p).split('_')[0] for p in got]
        self.assertEqual(names[0], 'f%d' % (10 * MB))
        self.assertEqual(names[-1], 'f%d' % (unmicro.PROBE_MAX_BYTES + MB))

    def test_picks_are_spread_across_size_range_not_largest(self):
        spec = {'d%d' % i: [(10 + i * 10) * MB] for i in range(9)}
        got = self.pick(spec, 3)
        sizes = sorted(int(os.path.basename(p).split('_')[0][1:]) // MB for p in got)
        self.assertEqual(sizes[1], 50)
        self.assertLess(sizes[0], 50)
        self.assertGreater(sizes[2], 50)

    def test_pure_python_keeps_probes_tiny(self):
        saved = unmicro.BACKEND
        try:
            unmicro.BACKEND = 'pure-python'
            self.assertEqual(unmicro.probe_size_bounds(), (0, unmicro.PURE_PROBE_MAX_BYTES))
        finally:
            unmicro.BACKEND = saved
        self.assertEqual(unmicro.probe_size_bounds(), (unmicro.PROBE_MIN_BYTES, unmicro.PROBE_MAX_BYTES))

    def sparse(self, rel, size):
        path = self.p(*rel.split('/'))
        with open(path, 'wb') as fh:
            fh.write(os.urandom(16))
            fh.truncate(size)
        return path

    def test_gcm_probe_order_uses_large_files_from_different_folders(self):
        big = [self.sparse('d%d/big.cryptedmicro' % i, (12 + i) * MB) for i in range(4)]
        small = [self.sparse('d%d/small%d.cryptedmicro' % (i, j), 3000 + j) for i in range(4) for j in range(3)]
        order = unmicro.gcm_probe_order(sorted(big + small))
        first_four = order[:4]
        self.assertEqual(sorted(first_four), sorted(big))
        self.assertEqual(len(set(os.path.dirname(p) for p in first_four)), 4)

    def test_ecb_probe_set_prefers_large_and_avoids_repeat_folder(self):
        a1 = self.sparse('x/a_big.cryptedmicro', 12 * MB)
        a2 = self.sparse('x/a_small.cryptedmicro', 2000)
        b1 = self.sparse('y/b_big.cryptedmicro', 13 * MB)
        c1 = self.sparse('z/c_big.cryptedmicro', 14 * MB)
        for path, blk in ((a1, b'A' * 16), (a2, b'A' * 16), (b1, b'B' * 16), (c1, b'C' * 16)):
            with open(path, 'r+b') as fh:
                fh.write(blk)
        probes = unmicro.probe_set([a1, a2, b1, c1])
        paths = [p for _, p in probes]
        self.assertEqual(sorted(paths), sorted([a1, b1, c1]))

    def test_big_gcm_probe_is_streamed_and_still_finds_the_key(self):
        big = self.p('only', 'big.jpg.cryptedmicro')
        make_gcm(big, KEY, jpeg(unmicro.GCM_STREAM_ABOVE + MB))
        mapping, _, remaining = unmicro.find_all_gcm_keys([big], supplied('nope', KEY), quiet=True)
        self.assertEqual(mapping.get(KEY), [big])
        self.assertEqual(remaining, [])
        self.assertIsNone(unmicro._GCM_PROBE_CACHE[big][2])


class InteractiveUi(unittest.TestCase):
    """The setup menu that opens when the tool runs with no arguments."""

    def setUp(self):
        self._orig_input = unmicro._ui_input
        self.dir = tempfile.mkdtemp(prefix='unmicro-ui-')
        self.prompts = []

    def tearDown(self):
        unmicro._ui_input = self._orig_input
        shutil.rmtree(self.dir, ignore_errors=True)

    def feed(self, answers):
        it = iter(answers)

        def fake(prompt):
            self.prompts.append(prompt)
            try:
                return next(it)
            except StopIteration:
                raise EOFError
        unmicro._ui_input = fake

    def run_ui(self, answers):
        self.feed(answers)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            argv = unmicro.run_ui()
        self.out = buf.getvalue()
        return argv

    # selection parsing
    def test_plus_style_selection(self):
        self.assertEqual(unmicro.parse_selection('1+2+4', 5), [1, 2, 4])

    def test_other_separators_ranges_all_none(self):
        self.assertEqual(unmicro.parse_selection('1,3', 5), [1, 3])
        self.assertEqual(unmicro.parse_selection('1 3', 5), [1, 3])
        self.assertEqual(unmicro.parse_selection('2-4', 5), [2, 3, 4])
        self.assertEqual(unmicro.parse_selection('a', 3), [1, 2, 3])
        self.assertEqual(unmicro.parse_selection('n', 3), [])
        self.assertEqual(unmicro.parse_selection('2+2+1', 3), [2, 1])

    def test_bad_selection_rejected(self):
        for bad in ('0', '9', 'x', '3-1', '1+x'):
            with self.assertRaises(ValueError):
                unmicro.parse_selection(bad, 5)

    # argument building
    def test_build_argv_levels(self):
        st = unmicro.ui_new_state()
        st['level'] = 'quick'
        self.assertEqual(unmicro.ui_build_argv(st), ['--auto'])
        st['level'] = 'standard'
        self.assertEqual(unmicro.ui_build_argv(st), ['--auto', '--brute'])
        st['level'] = 'thorough'
        self.assertEqual(unmicro.ui_build_argv(st), ['--auto', '--brute', '--dumb-brute', '--checkpoint', unmicro.UI_PROGRESS_FILE])

    def test_build_argv_places(self):
        st = unmicro.ui_new_state()
        st.update(where='file', paths=['/x/a.cryptedmicro'], level='quick')
        self.assertEqual(unmicro.ui_build_argv(st), ['--in', '/x/a.cryptedmicro'])
        st.update(where='folders', paths=['/x/one'])
        self.assertEqual(unmicro.ui_build_argv(st), ['--in', '/x/one', '--recursive'])
        st.update(where='folders', paths=['/x/one', '/y/two'])
        self.assertEqual(unmicro.ui_build_argv(st), ['--auto', '--scan-root', '/x/one', '--scan-root', '/y/two'])

    def test_build_argv_custom_combination(self):
        st = unmicro.ui_new_state()
        st.update(level='custom', keys=['aa', 'bb'], wordlist='/w.txt', scavenge=['/m.dmp'], model=True, structural=True,
                  deep=True, gpu=True, checkpoint='p.json', workers=2, flat=True, strict=True, out='/o')
        self.assertEqual(unmicro.ui_build_argv(st), ['--auto', '--key', 'aa', '--key', 'bb', '--wordlist', '/w.txt', '--scavenge', '/m.dmp',
                                                     '--brute', '--dumb-brute', '--deep', '--gpu', '--checkpoint', 'p.json', '--workers', '2',
                                                     '--flat', '--strict', '--out', '/o'])

    def test_identify_drops_output_folder(self):
        st = unmicro.ui_new_state()
        st.update(identify=True, out='/o')
        self.assertEqual(unmicro.ui_build_argv(st), ['--auto', '--brute', '--identify'])

    def test_built_argv_parses_in_main(self):
        # Every combination the menu can produce must be accepted by main.
        st = unmicro.ui_new_state()
        st.update(level='custom', keys=['aa'], wordlist='/w', scavenge=['/m'], model=True, structural=True, deep=True, gpu=True,
                  checkpoint='p', workers=2, flat=True, overwrite=True, keep_unverified=True, no_fix_ext=True, out='/o')
        argv = unmicro.ui_build_argv(st) + ['--self-test']
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(unmicro.main(argv), 0)

    # scripted walk-throughs
    def test_whole_machine_standard(self):
        argv = self.run_ui(['1', '2', '1', '', '', '1'])
        self.assertEqual(argv, ['--auto', '--brute'])
        self.assertIn('unmicro.py --auto --brute', self.out)

    def test_folder_custom_multi_select(self):
        argv = self.run_ui(['2', self.dir, '', '4', '1+4+8', 'abc', '', '', '1', '', '', '1'])
        self.assertEqual(argv, ['--in', self.dir, '--recursive', '--key', 'abc', '--brute', '--checkpoint', unmicro.UI_PROGRESS_FILE])

    def test_several_folders(self):
        other = tempfile.mkdtemp(prefix='unmicro-ui2-')
        try:
            argv = self.run_ui(['2', self.dir, other, '', '1', '1', '', '', '1'])
        finally:
            shutil.rmtree(other, ignore_errors=True)
        self.assertEqual(argv, ['--auto', '--scan-root', self.dir, '--scan-root', other])

    def test_back_goes_to_previous_screen(self):
        argv = self.run_ui(['1', 'b', '1', '1', '1', '', '', '1'])
        self.assertEqual(argv, ['--auto'])

    def test_back_skips_screens_that_do_not_apply(self):
        # From the effort screen with "whole machine", back must land on the
        # location screen, not on the folder screen.
        self.run_ui(['1', 'b', 'q'])
        self.assertEqual(sum(1 for p in self.prompts if 'Folder' in p), 0)

    def test_bad_input_asks_again(self):
        argv = self.run_ui(['1', 'x', '9', '2', '1', '', '', '1'])
        self.assertEqual(argv, ['--auto', '--brute'])
        self.assertIn('Please type a number', self.out)

    def test_contradictory_output_options_rejected(self):
        argv = self.run_ui(['1', '1', '1', '4+5', '4', '', '1'])
        self.assertIn('contradict', self.out)
        self.assertEqual(argv, ['--auto', '--keep-unverified'])

    def test_quit_and_end_of_input_cancel(self):
        self.assertIsNone(self.run_ui(['q']))
        self.assertIsNone(self.run_ui(['1', '2', 'quit']))
        self.assertIsNone(self.run_ui(['1']))

    def test_review_cancel_and_edit(self):
        self.assertIsNone(self.run_ui(['1', '2', '1', '', '', '3']))
        argv = self.run_ui(['1', '2', '1', '', '', '2', '1', '1', '1', '', '', '1'])
        self.assertEqual(argv, ['--auto'])

    def test_identify_skips_output_folder_prompt(self):
        argv = self.run_ui(['1', '2', '1', '1', '1'])
        self.assertEqual(argv, ['--auto', '--brute', '--identify'])
        self.assertFalse(any('save recovered files' in p for p in self.prompts))

    def test_ui_text_is_plain_ascii(self):
        self.run_ui(['2', self.dir, '', '4', 'a', 'k', '', '/dev/null', '', '', '', '', '', 'x'])
        self.run_ui(['1', '2', '1', '', '', '1'])
        self.assertTrue(all(ord(c) < 128 for c in self.out))
        self.assertTrue(all(ord(c) < 128 for c in ''.join(self.prompts)))

    # entry point
    def test_main_without_arguments_opens_menu_only_on_a_terminal(self):
        saved = (unmicro.ui_is_interactive, unmicro.run_ui, sys.argv)
        try:
            sys.argv = ['unmicro.py']
            unmicro.ui_is_interactive = lambda: True
            unmicro.run_ui = lambda: None
            self.assertEqual(unmicro.main(), 0)
            called = []
            unmicro.run_ui = lambda: called.append(1)
            unmicro.ui_is_interactive = lambda: False
            with contextlib.redirect_stdout(io.StringIO()):
                unmicro.main(['--self-test'])
            self.assertEqual(called, [])
        finally:
            unmicro.ui_is_interactive, unmicro.run_ui, sys.argv = saved

    def test_no_ui_env_var_disables_menu(self):
        os.environ[unmicro.UI_NO_UI_ENV] = '1'
        try:
            self.assertFalse(unmicro.ui_is_interactive())
        finally:
            del os.environ[unmicro.UI_NO_UI_ENV]



class PlainReport(unittest.TestCase):
    """The plain-language wording and the final result report."""

    def verdict(self, **res):
        v, lines = unmicro.build_result_report(res)
        return v, '\n'.join(lines)

    def test_all_recovered(self):
        v, text = self.verdict(recovered=4, out='/x', usable=4)
        self.assertEqual(v, 'ALL USABLE FILES RECOVERED')

    def test_nothing_recovered_no_key(self):
        v, text = self.verdict(recovered=0, locked=['a', 'b'], usable=2)
        self.assertIn('NO KEY FOUND', v)
        self.assertIn('STILL LOCKED: 2', text)

    def test_partly_recovered(self):
        v, text = self.verdict(recovered=2, locked=['a'], usable=3, out='/x')
        self.assertEqual(v, 'PARTLY RECOVERED')

    def test_damaged_is_not_called_a_key_problem(self):
        v, text = self.verdict(recovered=1, damaged=['d1', 'd2'], usable=1, out='/x')
        self.assertIn('DAMAGED', text)
        self.assertNotIn('STILL LOCKED', text)

    def test_problems_listed(self):
        v, text = self.verdict(recovered=1, failed=[('f', 'cannot write: disk full')], usable=2, out='/x')
        self.assertTrue(text)

    def test_key_check_only(self):
        v, text = self.verdict(identify=True, keys=['k'], covered=2, usable=3, locked=['a'])
        self.assertIn('KEY CHECK FINISHED', v)
        self.assertIn('Nothing was written', text)

    def test_plain_reason_wording(self):
        self.assertIn('does not open', unmicro.plain_reason('padding invalid'))
        self.assertIn('damaged', unmicro.plain_reason('length is not a multiple of 16'))
        self.assertEqual(unmicro.plain_reason('weird'), 'weird')

    def test_methods_fold_brute_lengths(self):
        names = ['structural brute len=%d' % n for n in range(4, 9)]
        out = unmicro.summarize_methods(names)
        self.assertEqual(len(out), 1)
        self.assertIn('4 to 8', out[0])

    def test_next_step_hints_escalate(self):
        a = unmicro.next_step_hint(False, False, True)
        b = unmicro.next_step_hint(True, False, True)
        c = unmicro.next_step_hint(True, True, True)
        self.assertEqual(len({a, b, c}), 3)

    def test_retry_argv_escalates_and_writes_list(self):
        argv = ['--in', '/a', '--key', 'k']
        r = unmicro.ui_retry_argv(argv, ['/f1', '/f2'], True)
        self.assertIn('--brute', r)
        self.assertNotIn('/a', r)
        path = r[r.index('--file-list') + 1]
        with open(path) as fh:
            self.assertEqual(fh.read().split(), ['/f1', '/f2'])
        r2 = unmicro.ui_retry_argv(r, ['/f1'], True)
        self.assertIn('--dumb-brute', r2)
        unmicro._ui_cleanup_temp()
        self.assertFalse(os.path.exists(path))

    def test_retry_argv_none_at_top(self):
        self.assertIsNone(unmicro.ui_retry_argv(['--dumb-brute', '--deep'], ['/f'], True))


@unittest.skipUnless(LICENSE, 'set %s to run the end-to-end tests' % unmicro.LICENSE_ENV)
class StatusOutput(Base):
    def setUp(self):
        Base.setUp(self)
        self.out = tempfile.mkdtemp(prefix='unmicro-out-')
        self.addCleanup(shutil.rmtree, self.out, True)

    def run_main(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            code = unmicro.main(['--license', LICENSE, '--workers', '1', '--out', self.out] + list(argv))
        return code, buf.getvalue()

    def test_output_is_ascii_and_staged(self):
        make_ecb(self.p('old.jpg.cryptedmicro'), KEY, jpeg(4000))
        code, out = self.run_main('--in', self.dir, '--key', KEY)
        self.assertEqual(code, 0, out)
        out.encode('ascii')
        for n in range(1, 6):
            self.assertIn('STEP %d OF 5' % n, out)

    def test_file_list_limits_scope(self):
        make_ecb(self.p('a.jpg.cryptedmicro'), KEY, jpeg(4000))
        make_ecb(self.p('b.jpg.cryptedmicro'), KEY, jpeg(4100))
        lst = self.p('list.txt')
        with open(lst, 'w') as fh:
            fh.write(self.p('a.jpg.cryptedmicro') + '\n')
        code, out = self.run_main('--file-list', lst, '--key', KEY, '--flat')
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(os.listdir(self.out)), ['a.jpg'])

    def test_damaged_shown_separately_from_locked(self):
        make_ecb(self.p('a.jpg.cryptedmicro'), KEY, jpeg(4000))
        open(self.p('stub.jpg.cryptedmicro'), 'wb').close()
        code, out = self.run_main('--in', self.dir, '--key', KEY)
        self.assertIn('Damaged (not a key issue)        1', out)
        self.assertIn('Still locked (need a key)        0', out)

    def test_file_list_run_keeps_chosen_level(self):
        # A retry from the menu names only a file list. It must not turn into
        # the whole-machine, every-method run.
        make_ecb(self.p('a.jpg.cryptedmicro'), KEY, jpeg(4000))
        lst = self.p('list.txt')
        with open(lst, 'w') as fh:
            fh.write(self.p('a.jpg.cryptedmicro') + '\n')
        code, out = self.run_main('--file-list', lst, '--key', KEY)
        self.assertNotIn('Full automatic', out)
        self.assertIn('Mode:        Quick', out)

    def test_quiet_prints_less_than_verbose(self):
        make_ecb(self.p('a.jpg.cryptedmicro'), KEY, jpeg(4000))
        _, q = self.run_main('--in', self.dir, '--key', KEY, '--quiet')
        _, v = self.run_main('--in', self.dir, '--key', KEY, '--verbose', '--overwrite')
        self.assertLess(len(q), len(v))


if __name__ == '__main__':
    unittest.main()
