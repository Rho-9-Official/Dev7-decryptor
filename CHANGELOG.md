# Changelog

All notable changes to unmicro, the Dev7 / Micro (`.cryptedmicro`) decryptor.

## Unreleased

One program per platform: a window with the engine built in.

### Added
- **The window** (`unmicro_app`): Files, Keys, Search, Output and Run tabs,
  plus Settings and Help. It builds the command line from those choices,
  runs the engine, and shows the method in use, keys tried, speed, keys
  found, the machine's load and a colourised log. The length question, the
  pause menu and the final "press Enter" are answered from dialogs and
  buttons. A modern (Qt) and a classic (Tk) window share one core; the
  first start asks which to use.
- **Endless mode** ("run until this machine cannot take it any more"): every
  core, no guess limit, after a warning with the estimated time to failure.
  Safety limits on CPU temperature, memory, free disk and battery stop it
  cleanly once one has held for 30 seconds, and every matched file is still
  recovered.
- **`--cli`**: the engine's full command line inside the same executable
  (its own console window on Windows unless the output is redirected).

### Changed
- **Releases** are now one file per platform,
  `unmicro-<version>-windows-x86_64.exe` and `unmicro-<version>-linux-x86_64`,
  both the window with the engine inside. The separate command-line
  downloads are gone; `unmicro.py` still runs on its own from source.
- Build dependencies pinned by hash now include the window's (PySide6,
  psutil) and the icon generator's (Pillow, build time only).

## 3.9.1

Candidate search update. Same license as 3.9.

### Changed
- **Wider candidate model.** Two more families for keys that mix letters
  and digits. Each starts from the characters the recovered data uses most
  and widens one character at a time, so the likeliest guesses come first.
- **Sealed data refreshed** for this build. The sealed-blob integrity digest
  changed accordingly; `--self-test` checks the new one.
- Release notes now name the exact download files, version number
  included.
- If an earlier version did not open your files, run this one.

## 3.9

Damaged copies from interrupted encryption runs no longer break the file
picker. The malware writes a new `.cryptedmicro` copy and then deletes the
original, so a run that was cut short leaves stubs and half-written files.
On a machine with many of them, the smallest files were chosen as probes,
and a probe that can never open hides the key from the whole sweep.

### Changed: plain-language progress and results
- Output is now five numbered steps (finding files, checking files, looking
  for the key, recovering files, results), so it is always clear which part
  of the job is running.
- A live status line shows the method in use ("method 2 of 3"), how many keys
  have been tried and the time elapsed, and says so when slow is normal.
- The final report puts every file in exactly one row: recovered, damaged
  (not a key issue), still locked (needs a key), or had a problem. It opens
  with a one-line verdict such as `PARTLY RECOVERED` and a plain "Next:" hint.
  This is how to tell a new key from corrupted files at a glance.
- `--verbose` brings back the technical detail; `--quiet` prints the minimum.
  Output is plain ASCII.

### Added: pause, retry and file lists
- Ctrl+C opens a pause menu (keep searching, stop and recover what is matched,
  or quit) instead of killing the run.
- After a run started from the menu, a next-steps menu offers to retry only
  the files still locked, at the same or a harder level.
- `--file-list FILE` works on the paths listed in FILE instead of searching.

### Added
- **Damaged-copy screen.** Before any probe is chosen, files that cannot be a
  whole ciphertext are set aside: zero-byte files, lengths that are neither a
  whole number of AES blocks nor long enough for AES-GCM (under 44 bytes),
  files whose first block is all zeros, and files ending in a run of 32 or
  more zero bytes. These checks are exact or near impossible to trip by
  chance on real ciphertext.
- **Cut-short detection once a key is known.** A file no key opened, whose
  first block decrypts to a recognised file signature (three bytes or more)
  under a key found on the same machine, is a real encryption that was cut
  short. It is excluded and reported rather than counted as "no key found".
- **`corrupted-files.txt`** is written to the output folder, listing every
  excluded file with its size and the reason. Nothing is deleted or changed.
  With `--identify`, nothing is written and the list is only printed.
- **Better probe choice.** Key guesses used to be tested against the smallest
  files, which are the likeliest to be stubs or fragments. Probes now come from
  files of 10 MB or more where there are any (up to 256 MB), spread across the
  size range rather than clustered at one end, and never two from the same
  folder unless 60% or more of all files share one folder. If fewer than two
  probes can be found that way, the folder rule is relaxed so a run is never
  left without a probe. With no file over 10 MB the same spreading applies to
  smaller files. The pure-python back end keeps to tiny probes, since it
  cannot run AES over megabytes per guess.
- **Large GCM probes are streamed.** A probe over 16 MB is read from disk for
  each guess instead of being held in memory.
- **Interactive menu.** Run with no options on a terminal and the tool asks
  where the files are, how hard to try, how many cores to use, output options
  and where to save, then shows a review screen with the equivalent command
  line before it starts. Choices that combine take `+`-joined answers (`1+2+4`);
  commas, spaces and ranges also work. Plain text only. `--no-ui` or
  `UNMICRO_NO_UI=1` skips it and keeps the old no-options full-auto run, and
  scripts and CI are unaffected because the menu only opens on a terminal.

## 3.8.2

Edge-case fixes. A double-click (full-auto) run could report 0 hits on files
the recovered keys open; this release fixes that and the other cases found
alongside it. Same license as 3.8.1.

### Fixed
- **Two bad files no longer hide a working key.** The GCM search checked
  every guess against only the two smallest GCM files. If both were partial
  copies from an interrupted run, or under another key, nothing matched and
  the run reported no key at all. The supplied and recovered keys now move on
  to the next two files, through up to 16, before giving up.
- **`--auto` searched past user folders.** `Dev`, `Run`, `Recovery`,
  `Windows`, `Snap`, `Sys` and `Proc` were skipped at any depth, so a
  victim's `Documents\Dev` was never searched. They are now skipped only at
  the top of a scan root (`C:\Windows`, `/proc`). The extension check is also
  no longer case-sensitive, so `.CRYPTEDMICRO` is found.
- **Block-aligned GCM files waited behind the ECB brute.** One GCM file in
  sixteen is a whole number of AES blocks. With no other GCM file to find the
  key on, these went through the full ECB brute force before a recovered key
  was tried on them as GCM. The quick key sources now run in both formats
  before any open-ended search.
- **Double-click window closed on exit.** Launched from Explorer, the window
  now stays open until Enter is pressed, including after an unexpected error.
- **Full-auto held opened files back for an hour.** Once a key had opened
  files, the files left over got the full 15,000-candidate variant tier
  before anything was written. In full-auto that second sweep now skips the
  variants (`--brute` given explicitly still runs them), and a time estimate
  is printed before the variant tier starts.
- **Ctrl+C lost everything.** Interrupting the key search now writes every
  file already matched to a key, then stops.
- **Misleading no-key advice.** When nothing opens, the output now says how
  many of the GCM files were actually tested, and suggests running `--in` on
  a folder of known-intact files.
- **GCM output held in memory.** GCM files are now decrypted straight to a
  temporary `.part` file that only becomes the recovered file once the tag
  verifies, so very large files no longer have to fit in RAM. ECB output is
  unchanged (its structural check needs the whole plaintext).
- **README:** `--dumb-brute` starts at 1 character, not 3.

### Added
- `tests/test_edge_cases.py`: regression tests for each of the above, run in
  CI. The end-to-end tests run only when `UNMICRO_LICENSE` is set.

## 3.8.1

First published build of the 3.8 changes. The `v3.8` tag was created from an
earlier, partial merge (before the cross-format key fix and the updated
recovered-key table), so the full 3.8 set ships under this version instead.
No code changes from 3.8 as merged; same license.

## 3.8

Recovers the newer AES-GCM `.cryptedmicro` format alongside the original
AES-ECB one.

### Added
- **AES-256-GCM decryption.** Newer `!micro` builds write
  `salt(16) | iv(12) | ciphertext | tag(16)`, keyed by
  PBKDF2-HMAC-SHA256 over the typed key (UTF-8), 600,000 rounds, 256 bits.
  Works on every back end: `cryptography`, `pycryptodome`, and the built in
  pure-Python AES (with its own GHASH), so a bare interpreter still runs it.
  Large files are streamed in 1 MiB chunks, and no plaintext leaves the GCM
  path until the tag has verified.
- **Per-file format detection.** Both formats share the extension. Files whose
  length cannot be ECB go to the GCM search; block-aligned files go through
  the ECB search, and those it cannot open, or that a GCM key from the same
  machine opens, are treated as GCM. One machine with both formats, or
  several keys of each, is handled in one run. A key found on either format
  is also tried on the other, since the same typed key can be reused across
  builds.
- **GCM key search.** Supplied keys, wordlist, recovered operator keys,
  scavenged strings and (with `--brute`) recovered key variants, across all
  worker processes. A hit is a tag match, so there are no false positives.
  Each found key is then mapped across the remaining files in parallel, and
  the derived keys are cached so the write pass does not run PBKDF2 again.
- **Self-test** now checks PBKDF2-HMAC-SHA256 against the RFC 7914 vector and
  AES-256-GCM against NIST test case 15 on both the active back end and the
  pure-Python one, and confirms a corrupted tag is rejected. Still no license
  needed.

- **Sealed recovered-key table updated** with newly recovered operator keys.
  Same license as 3.7; the table is still only readable with it.

### Unchanged
- The original AES-ECB path: decryption, key search, GPU brute, checkpoints
  and verification behave exactly as in 3.7. ECB-only machines see no
  difference except that files which cannot be ECB are no longer swept as ECB.

### Notes
- The fitted model, structural brute and GPU are not run against GCM files.
  At 600,000 PBKDF2 rounds a guess costs roughly 0.2 seconds per core, so an
  open-ended search there is not practical. `--checkpoint` covers the ECB
  search only; the GCM tiers are bounded.
- The built in AES gained a forward block function, used only as GCM's
  counter-mode keystream. The tool still has no code that computes a tag or
  writes ciphertext, so it still cannot produce a `.cryptedmicro` file.

## 3.7

Per-build license key, so the recovered-key list stops riding in the public
binary.

### Added
- **Per-build license key.** The recovered-key list, operator handles, Turkish
  vocabulary, keyboard layouts and actor notes are sealed with AES-256-CBC +
  HMAC-SHA256 under a license key that is distinct for each release. The tool
  reads the key from `--license KEY`, from the `UNMICRO_LICENSE` environment
  variable, or from an interactive prompt. If you do not have a key for your
  build, contact **recon@rho-9.com** and mention "Chattering Magpies"; Rho-9
  sends one back once your case is confirmed.
- **`--self-test`.** Confirms the sealed blobs survived PyInstaller
  (SHA-256 over the ciphertext bytes), confirms the AES back end can decrypt a
  known vector, and cross-checks the back end against the built in pure-Python
  AES on a random block. Does not require a license. This is the CI smoke
  test.
- **`--list-keys`.** Prints the recovered operator keys this build knows
  about. Requires the license, so a copy of the binary alone cannot be grepped
  for them.

### Changed
- Pure-Python AES-256 is now reused for the sealed-blob unseal as well
  (CBC built on the existing ECB primitive), so the tool runs on a bare
  interpreter end to end, with no new dependencies and no encrypt path. The
  "unmicro cannot produce a .cryptedmicro file" invariant is unchanged.
- CI smoke test switched from `--list-keys` (which never shipped) to
  `--self-test`, so building this repo does not need the license secret.

### Why
The Chattering Magpies rotate their key choices once Rho-9 publishes new
recovered ones, which stops this tool from opening the next round of victims'
files. Taking the key list out of the public binary keeps the gang reading
only what Rho-9 chooses to publish on its own channels, not what is sitting
ready to grep inside this tool. The license key is rotated at every release;
victims who already have a key for a previous build get the new one with
their case, same channel.

### Notes
- Key is per build. Rebuilding the tool against a new license is an offline
  step at Rho-9; the shipped tool itself still has no encrypt path.
- A wrong license fails the HMAC verify in constant time and refuses to
  unseal; nothing is partially decrypted and no cleartext is cached.
- The licensing is a social-engineering friction layer, not a cryptographic
  secret-sharing scheme: anyone who gets a key can read the tables that build
  exposes. Rotation is how we handle that.

## 3.6

GPU throughput for the structural brute.

### Added
- **On-device structural brute for `--gpu`.** The bottleneck for GPU
  acceleration was feeding it: one Python thread produces only a few hundred
  thousand candidates a second. Now, for `--dumb-brute`, the GPU generates the
  candidates itself, each work item turns its index into a candidate over the
  alphabet, builds the key, decrypts, and checks the magic table in-kernel,
  writing back only hits. The structural brute runs at device speed instead of
  Python speed. Correct multi-byte (Turkish) handling; a second self-test
  (`mask_selftest`) requires the GPU's hit set to equal the CPU's over the same
  candidates before the device is trusted, on top of the raw-AES self-test.
  The fitted-model tier stays on the CPU.

### Changed
- CPU sweep chunk size raised (65,536) to cut per-dispatch overhead on
  many-core machines.
- The `--dumb-brute` length gate now sizes the "too long" wall against GPU
  throughput when `--gpu` is active.

### Notes
- GPU runs from the Python source (`pip install pyopencl numpy` + your GPU's
  OpenCL runtime). The released binary is CPU-only by design: victims rarely
  have a GPU or an OpenCL runtime, and bundling it would bloat the binary and
  raise antivirus false positives. GPU is the operator's cracking path.
- Developed without a GPU in CI. The kernel AES and the index-to-candidate
  brute are verified against a reference implementation; the OpenCL execution
  is validated by the on-device self-tests at run time.

## 3.5

Recovery, guessing throughput, and file naming.

### Added
- **Extension repair** after decryption. The crew randomises file extensions
  before encrypting (a video named `.jpg`, an archive named `.png`), so unmicro
  now reads each recovered file's true type from its decrypted bytes and, on a
  genuine cross-category mismatch, writes the output under the corrected
  extension and reports the swap. Conservative: container families (docx/zip,
  mov/m4a, wav/webp) and same-category names are left alone. Uses the `filetype`
  library when present, an internal table otherwise. On by default; `--no-fix-ext`
  disables it.
- **`--scavenge FILE`** (repeatable). Pull candidate keys out of an unencrypted
  dump: a memory image, the pagefile or hibernation file, a `strings` listing,
  an implant log. The key is a typed string and often survives there in the
  clear. ASCII and UTF-16LE.
- **`--dumb-brute`**. Classic incremental brute, 3 characters up to the longest
  recovered key, over the alphabet these operators type. `--charset`
  {observed, turkish, full}, default `turkish` (Turkish + English lowercase and
  digits). Pauses and explains before a length that would take too long.
- **`--checkpoint FILE`**. Save sweep progress and resume, skipping finished
  tiers and fast-forwarding the current one. Keyed to the files; matches the
  tier by name so it resumes across flag changes.
- **`--gpu` and `--gpu-info`** (experimental). OpenCL sweep for NVIDIA and AMD.
  Key derivation stays on the CPU; the device runs a startup AES self-test
  against the CPU back end and disables itself on any mismatch; every GPU hit is
  re-validated on the CPU. It can make the search faster or not engage; it
  cannot make it wrong or miss a key. Developed without a GPU in CI, so the
  OpenCL execution is validated by the on-device self-test.
- **Full-auto**: a bare `python3 unmicro.py` searches every drive, tries every
  route, and writes to `./unmicro-recovered`.

### Changed
- **`--workers` defaults to every CPU core** (was 1). Set `--workers 1` for a
  single process.
- **Bounded-memory sweep.** The candidate de-duplication is capped
  (`--seen-cap`, default 1,000,000) and cleared at the cap rather than growing
  without bound, which fixes an out-of-memory kill deep into a `--brute` run.
  De-duplication stays exact, so no candidate is skipped.

### Notes
- No change to the cryptography: AES-256 is not attacked. Recovery still rests on
  the tiny keyspace (no KDF) and known-plaintext verification.
- This tool only decrypts. It cannot produce a `.cryptedmicro` file. Your
  encrypted files are never modified, renamed or deleted.

## 3.2

- Baseline released build: autodiscovery, recovered operator keys, the fitted
  key model (`--brute`/`--deep`), structural verification of every recovery, and
  multi-key handling for interrupted encryption runs.
