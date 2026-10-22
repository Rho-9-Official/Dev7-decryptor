import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unmicro_core as g  # noqa: E402


def cfg(**kw):
    c = dict(g.DEFAULTS)
    c.update({'paths': ['/cases/enc'], 'out': '/cases/out', 'license': 'K'})
    c.update(kw)
    return c


class BuildArgs(unittest.TestCase):
    def test_folder_defaults(self):
        a = g.build_args(cfg(level='quick'))
        self.assertEqual(a[:2], ['--in', '/cases/enc'])
        self.assertIn('--out', a)
        self.assertEqual(a[-1], '--verbose')
        self.assertNotIn('--brute', a)
        self.assertNotIn('--yes', a)

    def test_levels(self):
        self.assertIn('--brute', g.build_args(cfg(level='standard')))
        a = g.build_args(cfg(level='deep'))
        self.assertIn('--brute', a)
        self.assertIn('--deep', a)

    def test_auto(self):
        a = g.build_args(cfg(source='auto', scan_roots=['/mnt/usb'], no_prune=True, max_files='50'))
        self.assertEqual(a[:3], ['--auto', '--scan-root', '/mnt/usb'])
        self.assertIn('--no-prune', a)
        self.assertEqual(a[a.index('--max-files') + 1], '50')
        self.assertNotIn('--in', a)

    def test_many_paths_use_file_list(self):
        a = g.build_args(cfg(paths=['/a', '/b']), file_list_path='/tmp/list.txt')
        self.assertEqual(a[:2], ['--file-list', '/tmp/list.txt'])

    def test_keys_wordlist_scavenge(self):
        a = g.build_args(cfg(keys=['zarox', 'q7z'], wordlist='/w.txt', scavenge=['/m1', '/m2']))
        self.assertEqual(a.count('--key'), 2)
        self.assertEqual(a[a.index('--wordlist') + 1], '/w.txt')
        self.assertEqual(a.count('--scavenge'), 2)

    def test_dumb_ask(self):
        a = g.build_args(cfg(dumb=True, dumb_mode='ask'))
        self.assertIn('--dumb-brute', a)
        self.assertNotIn('--yes', a)
        self.assertNotIn('--charset', a)

    def test_dumb_endless_drops_guess_limit(self):
        a = g.build_args(cfg(dumb=True, dumb_mode='endless', charset='full', max_candidates='1000'))
        self.assertIn('--yes', a)
        self.assertEqual(a[a.index('--charset') + 1], 'full')
        self.assertNotIn('--max-candidates', a)

    def test_keepgoing_keeps_guess_limit(self):
        a = g.build_args(cfg(dumb=True, dumb_mode='keepgoing', max_candidates='1000'))
        self.assertIn('--yes', a)
        self.assertEqual(a[a.index('--max-candidates') + 1], '1000')

    def test_output_options(self):
        a = g.build_args(cfg(flat=True, overwrite=True, verify='strict', fix_ext=False))
        for f in ('--flat', '--overwrite', '--strict', '--no-fix-ext'):
            self.assertIn(f, a)
        self.assertIn('--keep-unverified', g.build_args(cfg(verify='keep')))

    def test_identify_writes_nothing(self):
        a = g.build_args(cfg(identify=True))
        self.assertIn('--identify', a)
        self.assertNotIn('--out', a)

    def test_force_only_with_one_key(self):
        self.assertIn('--force', g.build_args(cfg(force=True, keys=['k'])))
        self.assertNotIn('--force', g.build_args(cfg(force=True, keys=['k', 'j'])))

    def test_workers_and_checkpoint(self):
        a = g.build_args(cfg(workers=3, checkpoint='/c/p.ckpt', gpu=True, max_passes=2))
        self.assertEqual(a[a.index('--workers') + 1], '3')
        self.assertEqual(a[a.index('--checkpoint') + 1], '/c/p.ckpt')
        self.assertIn('--gpu', a)
        self.assertEqual(a[a.index('--max-passes') + 1], '2')
        self.assertNotIn('--workers', g.build_args(cfg(workers=0)))

    def test_license_never_on_command_line(self):
        a = g.build_args(cfg(license='SECRET-KEY'))
        self.assertNotIn('SECRET-KEY', ' '.join(a))

    def test_problems(self):
        self.assertEqual(g.problems(cfg()), [])
        self.assertTrue(g.problems(cfg(paths=[])))
        self.assertTrue(g.problems(cfg(license='')))
        self.assertEqual(g.problems(cfg(out='', identify=True)), [])


class Parse(unittest.TestCase):
    # lines copied from unmicro 3.9.1 runs
    def test_progress(self):
        k, d = g.parse_line('  structural brute len=4         1812750 tried     261441/s')
        self.assertEqual(k, 'progress')
        self.assertEqual(d['name'], 'structural brute len=4')
        self.assertEqual(d['tried'], 1812750)
        self.assertEqual(d['rate'], 261441.0)
        k, d = g.parse_line('  GCM recovered operator key          48 tried       42.4/s')
        self.assertEqual(k, 'progress')
        self.assertTrue(d['gcm'])

    def test_step_tier_found_result(self):
        self.assertEqual(g.parse_line('STEP 3 OF 5: LOOKING FOR THE KEY'), ('step', {'n': 3, 'of': 5, 'title': 'Looking For The Key'}))
        k, d = g.parse_line('  tier recovered operator keys                  103 candidates  HIT')
        self.assertEqual((k, d['hit'], d['count']), ('tier', True, 103))
        k, d = g.parse_line('  GCM tier recovered operator keys              103 candidates  no hit')
        self.assertEqual((k, d['hit'], d['gcm']), ('tier', False, True))
        k, d = g.parse_line("FOUND A KEY: 'q7z'. It opens 3 of 5 files.")
        self.assertEqual((k, d['key'], d['opens'], d['of']), ('found', 'q7z', 3, 5))
        k, d = g.parse_line("FOUND A KEY: 'it's'. It opens 1 of 1 files.")
        self.assertEqual(d['key'], "it's")
        self.assertEqual(g.parse_line('RESULT: PARTLY RECOVERED'), ('result', {'verdict': 'PARTLY RECOVERED'}))

    def test_counts(self):
        k, d = g.parse_line('  Recovered and checked ...        5   saved in /tmp/rec')
        self.assertEqual((k, d['n']), ('count', 5))
        k, d = g.parse_line('  Still locked (need a key)        1')
        self.assertEqual((k, d['what'], d['n']), ('count', 'Still locked (need a key)', 1))
        k, d = g.parse_line('  Damaged (not a key issue)    1,204   list in /x')
        self.assertEqual(d['n'], 1204)

    def test_plain_progress(self):
        k, d = g.parse_line('Still searching (method 1 of 1): 103 keys tried, 0:00 elapsed | keys already recovered from the attackers')
        self.assertEqual((k, d['tried']), ('plainprogress', 103))

    def test_gate(self):
        self.assertTrue(g.RE_GATE.search('Keep going into 6-character keys? [y/N] '))
        k, d = g.parse_line("machine's speed that is roughly 3.4 hours, and each step after it is far longer.")
        self.assertEqual((k, d['when']), ('gatetime', '3.4 hours'))

    def test_text(self):
        self.assertEqual(g.parse_line('No damaged files found.')[0], 'text')


class Estimates(unittest.TestCase):
    def test_alphabet_sizes_mirror_unmicro(self):
        sizes = g.alphabet_sizes(['abc', 'a1Ş'])
        self.assertEqual(sizes['observed'], 5)
        # observed + 26 lower + 6 Turkish lower + 10 digits, minus overlaps a b c 1
        self.assertEqual(sizes['turkish'], 5 + 26 + 6 + 10 - 4)
        # + 26 upper + 6 Turkish upper, minus the Ş already observed
        self.assertEqual(sizes['full'], sizes['turkish'] + 26 + 6 - 1)

    def test_schedule(self):
        s = g.brute_schedule(10, 3, 10.0)
        self.assertEqual([r[1] for r in s], [10, 100, 1000])
        self.assertAlmostEqual(s[-1][3], 111.0)
        self.assertEqual(g.reachable_length(s, 12), 2)
        self.assertEqual(g.reachable_length(s, 5), 1)
        self.assertEqual(g.reachable_length(s, 0.5), 0)

    def test_time_to_failure_search_only(self):
        secs, why, det = g.time_to_failure(1e9, {'on_battery': False}, g.DEFAULTS['limits'], {})
        self.assertEqual((secs, why), (1e9, 'Search space runs out'))

    def test_time_to_failure_battery(self):
        res = {'on_battery': True, 'battery': 60.0, 'battery_secs': 7200}
        secs, why, _ = g.time_to_failure(1e12, res, {'min_battery': 10}, {})
        self.assertTrue(why.startswith('Battery'))
        self.assertAlmostEqual(secs, 7200 * 0.5 * 50 / 60)

    def test_time_to_failure_temperature_trend(self):
        res = {'temp': 80.0}
        secs, why, _ = g.time_to_failure(1e12, res, {'max_temp': 95}, {'temp': 0.01})
        self.assertTrue(why.startswith('CPU'))
        self.assertAlmostEqual(secs, 1500)

    def test_limits_tripped(self):
        lims = {'max_temp': 90, 'max_ram': 90, 'min_disk_gb': 2, 'min_battery': 15}
        self.assertEqual(g.limits_tripped({'temp': 91, 'ram': 50, 'disk_free_gb': 100}, lims).keys(), {'temp'})
        self.assertEqual(g.limits_tripped({'battery': 10, 'on_battery': False}, lims), {})
        self.assertIn('battery', g.limits_tripped({'battery': 10, 'on_battery': True}, lims))

    def test_formats(self):
        self.assertEqual(g.guess_format(0), 'empty (damaged)')
        self.assertEqual(g.guess_format(480), 'older (AES-ECB)')
        self.assertEqual(g.guess_format(1044), 'newer (AES-GCM)')
        self.assertEqual(g.guess_format(20), 'too short (damaged)')
        self.assertEqual(g.fmt_duration(30), '30 seconds')
        self.assertEqual(g.fmt_duration(7200), '2.0 hours')
        self.assertTrue(g.fmt_duration(1e30).startswith('10^'))


if __name__ == '__main__':
    unittest.main()
