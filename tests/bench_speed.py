"""Speed check for the key-search hot paths, to compare builds on one machine.

    python tests/bench_speed.py            # CPU paths only
    python tests/bench_speed.py --gpu      # and the OpenCL kernels

Run it from a checkout of each version you want to compare (it imports the
unmicro.py next to it). Nothing here needs a license, and nothing is
written to disk. Not part of the test suite.
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import unmicro  # noqa: E402


def timed(fn, *args):
    t = time.time()
    out = fn(*args)
    return out, time.time() - t


def cpu():
    unmicro._init_backend(False)
    print('unmicro %s, AES back end %s' % (unmicro.VERSION, unmicro.BACKEND))
    # Probe paths that do not exist: a chance signature match then fails its
    # full check at once, as it would on a real wrong guess.
    probes = [(os.urandom(16), os.path.join(HERE, 'no-such-probe-%d' % i)) for i in range(4)]
    unmicro._worker_init(probes)
    cands = ['key%07d' % i for i in range(100000)]
    _, dt = timed(unmicro._worker_chunk, cands)
    print('  older files, CPU sweep:      %9.0f guesses/s on one core (4 probes)' % (len(cands) / dt))
    key, iv = os.urandom(32), os.urandom(12)
    body = os.urandom(16 << 20)
    tag = os.urandom(16)
    reps = 10

    def full():
        for _ in range(reps):
            g = unmicro._gcm_new(key, iv, tag)
            g.update(body)
            g.verify()
    _, dt = timed(full)
    print('  newer files, full decrypt:   %9.1f ms per 16 MB probe' % (dt / reps * 1000))
    tagger = getattr(unmicro, '_gcm_tag_new', None)
    if tagger is not None:
        def tag_only():
            for _ in range(reps):
                t = tagger(key, iv)
                t.update(body)
                t.tag()
        _, dt = timed(tag_only)
        print('  newer files, tag-only check: %9.1f ms per 16 MB probe' % (dt / reps * 1000))
    _, dt = timed(unmicro.gcm_kdf, 'Dev7', os.urandom(16))
    print('  newer files, CPU key stretch: %8.2f guesses/s on one core' % (1 / dt))


def gpu():
    kdf = unmicro.GpuPBKDF2()
    print('OpenCL device: %s' % kdf.name)
    print('  PBKDF2 self-test: %s' % ('passed' if kdf.selftest() else 'FAILED'))
    pws = [os.urandom(12) for _ in range(kdf.batch)]
    salt = os.urandom(16)
    kdf.derive(pws, salt, 20000)
    _, dt = timed(kdf.derive, pws, salt, 60000)
    print('  newer files, GPU key stretch: %8.1f guesses/s at the full 600,000 rounds' % (len(pws) * 60000.0 / dt / unmicro.GCM_KDF_ITERS))
    aes = unmicro.GpuAES()
    print('  AES self-test: %s' % ('passed' if aes.selftest() else 'FAILED'))
    aes.set_alphabet(list('abcdefghijklmnopqrstuvwxyz0123456789'))
    ct = os.urandom(16)
    n = 1 << 24
    aes.brute_length(6, [(ct, None)], 0, 1 << 16)
    _, dt = timed(aes.brute_length, 6, [(ct, None)], 0, n)
    print('  older files, GPU structural:  %8.0f guesses/s' % (n / dt))
    cands = ['key%07d' % i for i in range(1 << 18)]
    probes = [(os.urandom(16), None) for _ in range(4)]
    aes.filter_chunk(cands[:1000], probes)
    _, dt = timed(aes.filter_chunk, cands, probes)
    print('  older files, GPU word list:   %8.0f guesses/s (4 probes)' % (len(cands) / dt))


if __name__ == '__main__':
    cpu()
    if '--gpu' in sys.argv:
        gpu()
