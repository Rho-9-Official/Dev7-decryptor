"""Tests for the GPU key derivation of the GCM files (--gpu, 5.1).

Run from the repository root:

    python -m unittest discover -s tests -v

The tests that drive an OpenCL device need pyopencl and a device, and are
skipped without them. --gpu only takes GPUs, so on a machine with only an
OpenCL CPU runtime (pocl) set UNMICRO_OPENCL_DEVICE to part of its name,
for example UNMICRO_OPENCL_DEVICE=portable. The stand-in tests need neither
and always run.
"""
import hashlib
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import unmicro  # noqa: E402
from test_edge_cases import Base, KEY, jpeg, junk, make_gcm, supplied  # noqa: E402

_DEVICE = None
_WHY = 'no OpenCL device'
try:
    import pyopencl  # noqa: F401
    _DEVICE = unmicro.GpuPBKDF2()
except Exception as e:  # no pyopencl, no runtime, or no device
    _WHY = 'needs pyopencl and an OpenCL device (%s)' % e


class _WrongGpu(object):
    """Returns a wrong key for every guess, like a broken kernel would."""
    name = 'stand-in'
    batch = 8

    def derive_keys(self, key_strings, salts):
        return [os.urandom(32) for _ in key_strings]


class _DyingGpu(_WrongGpu):
    """Fails the way a lost device does."""

    def derive_keys(self, key_strings, salts):
        raise RuntimeError('device lost')


class _CpuGpu(_WrongGpu):
    """Right answers from hashlib, to check the GPU plumbing without a GPU."""

    def __init__(self):
        self.calls = 0

    def derive_keys(self, key_strings, salts):
        self.calls += 1
        if isinstance(salts, (bytes, bytearray)):
            salts = [salts] * len(key_strings)
        return [unmicro.gcm_kdf(k, s) for k, s in zip(key_strings, salts)]


class StandIn(Base):
    """The CPU checks every GPU result, so a bad GPU cannot give a wrong
    answer, and a GPU that fails mid-run hands over to the CPU."""

    def test_plumbing_finds_the_key(self):
        good = self.good_gcm()
        files = sorted(good + self.poison())
        gpu = _CpuGpu()
        mapping, _, remaining = unmicro.find_all_gcm_keys(files, supplied('nope', KEY), quiet=True, gpu=gpu)
        self.assertEqual(sorted(mapping.get(KEY, [])), sorted(good))
        self.assertEqual(len(remaining), 2)
        self.assertGreater(gpu.calls, 0)

    def test_wrong_keys_open_nothing(self):
        files = sorted(self.good_gcm())
        mapping, _, remaining = unmicro.find_all_gcm_keys(files, supplied('nope', KEY), quiet=True, gpu=_WrongGpu())
        self.assertEqual(mapping, {})
        self.assertEqual(sorted(remaining), files)

    def test_failing_gpu_falls_back_to_cpu(self):
        good = self.good_gcm()
        mapping, _, _ = unmicro.find_all_gcm_keys(sorted(good), supplied('nope', KEY), quiet=True, gpu=_DyingGpu())
        self.assertEqual(sorted(mapping.get(KEY, [])), sorted(good))
        unmicro._KDF_CACHE.clear()
        part = unmicro.map_gcm_keys_to_files(sorted(good), [KEY], quiet=True, gpu=_DyingGpu())
        self.assertEqual(sorted(part[KEY]), sorted(good))

    def test_pause_mid_chunk_loses_no_guess(self):
        # A pause during the tag checks ends the chunk early; "keep
        # searching" must still try every guess, the key last of all.
        good = self.good_gcm()
        guesses = ['wrong%d' % i for i in range(29)] + [KEY]
        status = unmicro.STATUS

        class PausingGpu(_CpuGpu):
            batch = 64

            def derive_keys(self, key_strings, salts):
                if self.calls == 0:
                    status.pause_requested = True
                return _CpuGpu.derive_keys(self, key_strings, salts)
        old_menu = status.pause_menu
        status.pause_menu = lambda: 1
        try:
            gpu = PausingGpu()
            found, tried = unmicro.sweep_gcm(sorted(good), [('wordlist', lambda: iter(guesses))], workers=1, quiet=True, gpu=gpu)
        finally:
            status.pause_menu = old_menu
            status.pause_requested = False
        self.assertEqual(found, [KEY])
        self.assertEqual(tried, len(guesses))
        self.assertGreater(gpu.calls, 1)


@unittest.skipIf(_DEVICE is None, _WHY)
class Kernel(unittest.TestCase):

    def test_selftest_passes(self):
        self.assertTrue(_DEVICE.selftest())

    def test_matches_hashlib(self):
        pws = [b'', b'k', b'x' * 64, b'y' * 65, os.urandom(300), 'Dev7-çğış'.encode('utf-8')]
        salts = [os.urandom(16) for _ in pws]
        for iters in (1, 4097):
            got = _DEVICE.derive(pws, salts, iters)
            self.assertEqual(got, [hashlib.pbkdf2_hmac('sha256', p, s, iters, 32) for p, s in zip(pws, salts)])

    def test_batches_split(self):
        # More items than one launch takes, all against one salt.
        n = _DEVICE.batch + 3
        salt = os.urandom(16)
        got = _DEVICE.derive([b'p%d' % i for i in range(n)], salt, 3)
        self.assertEqual(len(got), n)
        for i in (0, _DEVICE.batch - 1, _DEVICE.batch, n - 1):
            self.assertEqual(got[i], hashlib.pbkdf2_hmac('sha256', b'p%d' % i, salt, 3, 32))

    def test_full_rounds_match_gcm_kdf(self):
        salt = os.urandom(16)
        self.assertEqual(_DEVICE.derive_keys([KEY], salt), [unmicro.gcm_kdf(KEY, salt)])

    def test_corrupt_kernel_fails_selftest(self):
        class Corrupt(unmicro.GpuPBKDF2):
            def derive(self, passwords, salts, iters=unmicro.GCM_KDF_ITERS):
                out = unmicro.GpuPBKDF2.derive(self, passwords, salts, iters)
                # Wrong only past the 64-byte HMAC block, as a broken pre-hash would be.
                return [bytes([d[0] ^ 1]) + d[1:] if len(p) > 64 else d for p, d in zip(passwords, out)]
        bad = Corrupt.__new__(Corrupt)
        bad.__dict__.update(_DEVICE.__dict__)
        self.assertFalse(bad.selftest())


@unittest.skipIf(_DEVICE is None, _WHY)
class OnDevice(Base):

    def test_same_result_as_cpu(self):
        other = 'second-key-7'
        good = self.good_gcm()
        more = []
        for i, n in enumerate((6007, 8009)):
            path = self.p('b%d.png.cryptedmicro' % i)
            make_gcm(path, other, jpeg(n))
            more.append(path)
        files = sorted(good + more + self.poison())
        plan = supplied('nope', 'also-nope', other, KEY)
        cpu, cpu_tried, cpu_left = unmicro.find_all_gcm_keys(files, plan, quiet=True)
        unmicro._KDF_CACHE.clear()
        unmicro._GCM_PROBE_CACHE.clear()
        gpu, gpu_tried, gpu_left = unmicro.find_all_gcm_keys(files, plan, quiet=True, gpu=_DEVICE)
        self.assertEqual(gpu, cpu)
        self.assertEqual(sorted(gpu_left), sorted(cpu_left))
        self.assertEqual(sorted(gpu[KEY]), sorted(good))
        self.assertEqual(sorted(gpu[other]), sorted(more))

    def test_map_with_workers(self):
        good = self.good_gcm(5, sizes=(5001, 7003, 9005, 4001, 3003))
        stray = self.p('x.doc.cryptedmicro')
        make_gcm(stray, 'other', jpeg(4099))
        part = unmicro.map_gcm_keys_to_files(sorted(good + [stray]), ['nope', KEY], workers=2, quiet=True, gpu=_DEVICE)
        self.assertEqual(sorted(part), [KEY])
        self.assertEqual(sorted(part[KEY]), sorted(good))
        # The derived keys are kept for the write pass, and are right.
        for path in good:
            salt = unmicro.gcm_header(path)[1]
            self.assertEqual(unmicro._KDF_CACHE[(KEY, salt)], unmicro.gcm_kdf(KEY, salt))

    def test_init_reports_ready(self):
        if not (_DEVICE.device.type & pyopencl.device_type.GPU) and not os.environ.get('UNMICRO_OPENCL_DEVICE'):
            self.skipTest('init_gpu_gcm only takes GPUs unless UNMICRO_OPENCL_DEVICE is set')
        self.assertIsNotNone(unmicro.init_gpu_gcm(quiet=True))


if __name__ == '__main__':
    unittest.main()
