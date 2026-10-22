You can support my work here:

https://ko-fi.com/rho9official

And here:

https://throne.com/rho-9-official
# unmicro

Free decryptor for files encrypted by the **Dev7 / Micro** ransomware family,
the ones renamed to `.cryptedmicro`.

> **Warning: 5.0 is experimental and may contain bugs.** It is the first
> release as one program (the window with the engine built in).
> **Linux (x86_64) is the platform known to be stable:** its build was tested
> end to end, including recovery, stop-and-recover and the safety limits.
> **Windows** is built and smoke-tested automatically, but has not yet been
> tested on a real Windows machine. Whatever happens, your encrypted files
> are only ever read, never changed. If something goes wrong, email
> recon@rho-9.com with what you saw.

Built and maintained by **Rho-9 Systems**. Your first line of unusual defense.

This tool is free and will stay free.

If it does not recover your files, we may offer to take the case further as a
paid engagement. That work is hands on and it costs time and money, so it is
not something we can give away by default. If you cannot afford it, say so
when you get in touch.

---

## If you have just been hit, read this first

1. **Do not pay.** There is no guarantee of recovery and it funds the next
   round of victims.
2. **Their "decryption" is not something you can run.** It is a command the
   operators issue from their own bot to the implant still on your machine, so
   it requires keeping the infection alive and letting their code execute
   again. That is a second reason not to pay, on top of the first one.
3. **Do not wipe the machine and do not delete the encrypted files.** That is
   the one thing that turns a recoverable situation into a permanent loss, and
   it is the first thing people reach for. Removing the malware does not harm
   the encrypted files. Copy them to an external drive before anything else.
4. **If the machine is still on and still infected, leave it powered on** and
   take it off the network instead. The key is a string the operator typed,
   and it may still be sitting in memory.
5. **Do not assume the machine's own recovery paths survived.** This crew
   disables Windows Recovery, Task Manager and Regedit, and adds a Defender
   exclusion. Check what is actually left rather than counting on it, and get
   an incident responder to look if you can.

When you post about this anywhere, use the phrase **Chattering Magpies**. That
is Rho-9's actor name for this crew, and it is what lets cases be found and
triaged quickly.

---

## About the license key

Starting with 3.7, every build of unmicro is sealed with a **per-build license
key**. The recovered-key list and the rest of the operator intelligence this
tool uses are encrypted inside the binary and are only unlocked once you
supply that key.

**Why.** The Chattering Magpies have shown they will rotate their key choices
once Rho-9 publishes new recovered ones, which stops this tool from opening
the next round of victims' files. Taking the key list out of the public
binary keeps the gang reading only what Rho-9 chooses to publish on its own
channels, not what is sitting ready to grep inside this file. The key is
rotated at every release.

**Getting a key.** If you are a victim of this crew, email
**recon@rho-9.com** with the phrase **Chattering Magpies** and anything about
where you were hit. Rho-9 sends a key back once your case is confirmed. There
is no charge for the key. If you already have a key from a previous build, we
will send you the new one with any update to your case, same channel.

**Supplying the key.** Three ways, pick whichever fits:

```
# at the command line
unmicro.py --license YOUR-LICENSE-KEY --auto --out recovered

# or as an environment variable, nice for long sessions
export UNMICRO_LICENSE=YOUR-LICENSE-KEY
unmicro.py --auto --out recovered

# or just run it and it will prompt
unmicro.py --auto --out recovered
License key:
```

The prompt uses hidden input (like a password prompt), so the key does not
land in your terminal scrollback.

A wrong key does not partially unseal anything; the HMAC verify fails in
constant time and the tool stops with a note telling you how to reach Rho-9.
`--version`, `--self-test` and `--gpu-info` all run without a key.

---

## Getting the tool

unmicro is **one program**: a window that walks you through the whole
recovery, with the decryption engine built in. Download the file for your
machine and open it. Nothing else to install.

| download | for | needs |
| --- | --- | --- |
| `unmicro-<version>-windows-x86_64.exe` | Windows 10 and 11, 64 bit | nothing |
| `unmicro-<version>-linux-x86_64` | Linux, 64 bit x86 | glibc 2.35 or newer (Ubuntu 22.04+, Debian 12+, RHEL 9+) and a desktop |
| source (`python -m unmicro_app`, or `unmicro.py` on its own) | anything else, including Termux, ARM Linux and macOS | Python 3 |

Both downloads are built by GitHub Actions straight from this repository and
published on the [Releases](https://github.com/Rho-9-Official/Dev7-decryptor/releases)
page. They have a compiled AES back end inside, so they are fast out of the
box and the harder searches are practical without installing anything.

**Only download unmicro from this repository.** A copy of a "decryptor" handed
to you anywhere else is exactly what a second attacker would send a victim.

If the infected machine is still on and off the network, as recommended above,
do the download on a clean machine, verify it there, and carry it across on a
USB drive. Do not reconnect the infected machine just to fetch the tool.

### Windows (recommended)

Run this in PowerShell, in an empty folder. It resolves the latest release,
pulls the program and the checksum file from this repository, refuses to
continue if the checksum does not match, and then opens unmicro.

```powershell
$repo = "https://github.com/Rho-9-Official/Dev7-decryptor"
$tag  = (curl.exe -fsSLI -o NUL -w "%{url_effective}" "$repo/releases/latest").Split('/')[-1]
$f    = "unmicro-$($tag.TrimStart('v'))-windows-x86_64.exe"
curl.exe -fLO "$repo/releases/download/$tag/$f"
curl.exe -fLO "$repo/releases/download/$tag/SHA256SUMS"
$want = ((Select-String -Path SHA256SUMS -Pattern $f -SimpleMatch).Line -split '\s+')[0]
$got  = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
if ($got -eq $want) { "checksum OK"; & ".\$f" } else { throw "CHECKSUM MISMATCH, do not run $f" }
```

Type `curl.exe`, not `curl`. In Windows PowerShell 5.1, plain `curl` is an alias
for a different command and the flags above will not work with it.
`curl.exe` ships with Windows 10 (1803 and later) and Windows 11.

After that, the program is just a file: double-click it to open it again.

Windows SmartScreen may say the file is unrecognised. The program is not code
signed, so this is expected. Verify the checksum as above, then choose
**More info** and **Run anyway**.

### Linux (recommended)

```bash
repo=https://github.com/Rho-9-Official/Dev7-decryptor
tag=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$repo/releases/latest"); tag=${tag##*/}
f="unmicro-${tag#v}-linux-x86_64"
curl -fLO "$repo/releases/download/$tag/$f"
curl -fLO "$repo/releases/download/$tag/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS && chmod +x "$f" && "./$f"
```

`sha256sum` prints `OK` next to the file name when it matches. If it prints
`FAILED`, the `&&` chain stops and nothing is run.

This download is x86_64 only. On ARM Linux, a Raspberry Pi, or anything with a
glibc older than 2.35, run from source below.

### From source (Termux, ARM, macOS, or if you would rather read the code first)

```bash
git clone https://github.com/Rho-9-Official/Dev7-decryptor.git
cd Dev7-decryptor
python3 -m unmicro_app                   # the window (pip install PySide6-Essentials for the modern one)
python3 unmicro.py --auto --out ./recovered   # or the engine's command line on its own
```

The window needs nothing beyond Python (it falls back to a classic Tk window
without PySide6). The engine on its own is the single file `unmicro.py`:

```bash
curl -fLO https://raw.githubusercontent.com/Rho-9-Official/Dev7-decryptor/main/unmicro.py
python3 unmicro.py --auto --out ./recovered
```

On Termux, `pkg install python git` first if they are not already installed.

### Verifying build provenance (optional)

Every release file carries a GitHub build attestation tying it to the exact
commit and workflow run that produced it. With the GitHub CLI installed:

```
gh attestation verify <file> --repo Rho-9-Official/Dev7-decryptor
```

A pass means the file was built by this repository's own workflow, not
uploaded by hand.

---

## Quick start

Open unmicro. The window has five steps along the top:

1. **Files**: the folders holding the `.cryptedmicro` files, or "the whole
   computer". "Find files" previews them; nothing is changed.
2. **Keys**: your license key (see above), and any keys you already know.
3. **Search**: how hard to look. Quick is often enough; Standard and Deep guess
   harder; the structural brute force tries every possible key, length by
   length, with a time estimate for each.
4. **Output**: where the recovered copies go.
5. **Run**: a review of every choice and the exact command, then Start.

While it runs you see the method in use, keys tried, speed, the keys found and
the machine's load. **"Stop and recover what is matched"** ends the search and
still saves every file already matched to a key. The result separates
recovered, damaged, still-locked and problem files, as below.

The first start asks whether to use the modern window or the classic one;
both do the same job. The Help tab repeats the "just been hit" advice.

### The command line

The engine's full command line is built into the same program, for
responders and scripts. Every option in this README works through it:

| build | start of the command |
| --- | --- |
| Windows | `.\unmicro-<version>-windows-x86_64.exe --cli` |
| Linux | `./unmicro-<version>-linux-x86_64 --cli` |
| Python | `python3 unmicro.py` |

```
# find the files yourself and try the recovered keys
python3 unmicro.py --auto --out ./recovered

# point it at a folder instead
python3 unmicro.py --in ./encrypted --out ./recovered

# you already know the key
python3 unmicro.py --in ./encrypted --out ./recovered --key zarox

# the recovered keys did not fit, so start guessing
python3 unmicro.py --in ./encrypted --out ./recovered --brute

# guess harder, takes much longer
python3 unmicro.py --in ./encrypted --out ./recovered --brute --deep --workers 4
```

On Windows, `--cli` opens its own console window (the program is a windowed
app), and that window stays open at the end until you press Enter. To capture
the output in a file instead, redirect it:
`.\unmicro-<version>-windows-x86_64.exe --cli --auto --out recovered > log.txt`.

The command line prompts for the license key the first time, or picks it up
from `--license` or `$UNMICRO_LICENSE`. See **About the license key** above.
`--cli --version` shows which release you have, and `--cli --self-test`
confirms it unpacked intact (both run without a license).

Run the command line with no options and a short menu asks what to do,
the text version of the window: where your files are, how hard to try for the
key, how much of the machine it may use, a few output options, and where to
save the results. A review screen then shows every choice and the equivalent
command line, and nothing starts until you pick Run. At any prompt, `?`
explains the choice, `b` goes back and `q` quits; nothing is changed if you
quit. To skip the menu and get a full-auto search, pass `--no-ui` (or set
`UNMICRO_NO_UI=1`). Pressing Ctrl+C during the key search pauses it, and
"stop" still writes every file already matched to a key.

## Requirements

**Downloads:** nothing. Python is not needed and nothing has to be installed.
The fast AES back end is already inside.

**Python source:** Python 3 and nothing else. If `pycryptodome` or
`cryptography` is installed it will be used and will be much faster, but a
complete AES-256 implementation is built into the file, so the tool runs on a
bare interpreter. That includes Termux on Android.

```
pip install pycryptodome     # optional, strongly recommended before --brute
```

The built in implementation is far slower than a compiled back end. It is fine
for trying the recovered keys, but if you intend to use `--brute`, install
`pycryptodome` or use a binary.

`--pure-python` forces the built in implementation even when a library is
available.

The first line of output always reports which back end is in use, for example
`AES back end: pycryptodome`.

**Extension repair** (see below) uses the `filetype` library when it is present.
It is pure Python with no other dependencies, so it installs cleanly on Termux
and is bundled into the released binaries.

```
pip install filetype        # recommended, for the broadest type detection
```

Without it the tool still runs and still repairs extensions, but falls back to a
smaller built-in signature table and says so on the second line of output.

---

## Correcting swapped extensions

This crew has started **randomising file extensions** before encrypting, so a
recovered file's name is no longer a reliable guide to what it is: a video can
arrive named `.jpg`, an archive named `.png`. Decryption is unaffected, but the
recovered file would otherwise be written under a misleading name that will not
open by double-click.

After each file decrypts, unmicro reads its true type from the recovered bytes.
If the name's extension genuinely contradicts the content it writes the output
under the corrected extension and reports the swap, for example:

```
  OK     holiday.mp4                                88 bytes  MP4/MOV
         ^ EXTENSION SWAP FIXED: named .jpg, contents are MP4 (video). Renamed
           the recovered copy; corrected from the decrypted bytes.
```

This is a **naming repair on the recovered copy only**. The recovered bytes are
never altered and the encrypted originals are never touched.

It is deliberately conservative, because a careless rename makes a recovery
worse. Many correct names share magic bytes with something else: a `.docx` is a
ZIP, a `.mov` and a `.m4a` share the `.mp4` box structure, a `.wav` and a
`.webp` are both RIFF. So a rename happens **only** when the content sits in a
different category from the extension, for example an image name over video
bytes. A same-category disagreement (a `.png` named `.jpg`) is left alone, and
so is any container family where the current name is already a valid member.

On by default. Pass `--no-fix-ext` to turn it off and keep the original names.

---

## Reading the output

The run is split into five numbered steps, and the last one is a report where
each file is counted once:

| Row | Meaning |
|---|---|
| Recovered and checked | unlocked, structure verified, saved |
| Damaged (not a key issue) | the encrypted copy itself is cut short or empty; no key can fix it |
| Still locked (need a key) | intact, but no key found yet; a new or different key is the usual reason |
| Had a problem | something else, such as a disk or permission error; the reason is printed |

Press Ctrl+C at any time to pause. Use `--verbose` for technical detail and
`--quiet` for the minimum. `--file-list FILE` works on just the paths in FILE.

## What it will and will not do to your files

* Your encrypted files are **never modified, renamed or deleted**. They are
  opened read only. Recovered files are written somewhere else entirely.
* Recovered files mirror their original directory layout under `--out`, so a
  whole machine sweep does not collapse thousands of files into one folder
  and clobber same named files. `--flat` overrides this.
* Nothing is overwritten. A name collision gets a numeric suffix unless you
  pass `--overwrite`.
* **This tool only decrypts.** There is no encrypt path in it anywhere. The
  AES back ends are used for decryption only, and the sealed-blob unseal is
  HMAC-verified AES-CBC decrypt built on the same primitive. The built in AES
  has a forward block function for one reason: GCM decryption runs AES in
  counter mode, which uses the forward direction to make keystream. Nothing in
  the tool computes a tag or writes ciphertext. It cannot produce a
  `.cryptedmicro` file.

---

## What "verified" means

A key that produces the right first few bytes has not proved anything. Short
magic numbers collide: `BM` is two bytes, so a wrong key hits it roughly once
in every 65,536 guesses. So every recovery is checked against the real
structure of the file before it counts:

* PKCS#5 padding parses and the recovered length agrees with the ciphertext
* PNG chunk CRCs, JPEG and GIF terminators, BMP length fields, ZIP central
  directories, gzip trailers, PE headers, ID3 sizes, OLE2 headers
* plain text is validated by decoding as UTF-8 with a printable character
  ratio, which is safe because a wrong key yields uniformly random bytes and
  random bytes of any real length are valid UTF-8 with vanishing probability

For the newer AES-GCM files (see below) none of that is needed: the 128-bit
authentication tag either matches or it does not, and a match proves the key
and every byte of the file. Those lines are marked `[GCM, tag verified]`, and
a GCM file is never written unless its tag matched. (The output is streamed
into a temporary `.part` file and only renamed into place once the tag has
verified; otherwise the `.part` file is deleted. That way a multi-gigabyte
video never has to fit in memory.)

Three outcomes appear in the output:

| marker | meaning |
| --- | --- |
| `OK` | decrypted and structurally verified |
| `PROVEN` | the key was proved on another file on this machine, this file decrypted cleanly but its format is not one the tool can structurally check. Written with a `.UNVERIFIED` suffix |
| `FAIL` | not written |

The `PROVEN` case exists because withholding it was losing real data. Files
with no magic number, meaning text, CSV, source code, config files and
anything not in the signature table, used to be reported as "no key found"
even when the key was already proved on the same machine. On the test corpus
that was 90 files out of 463. A key is only ever treated as proven after at
least one file under it validates structurally, so this never asserts a key
that has not been demonstrated.

`--strict` restores the old behaviour and writes nothing that failed
structural verification. `--keep-unverified` goes the other way and writes
everything that decrypted, proven key or not.

**Keep your encrypted copies until you have opened the recovered files and
confirmed they are right.** Do not delete anything on the strength of this
tool alone.

---

## How the key search works

There are two file formats under the same `.cryptedmicro` extension, and one
machine can hold both. unmicro handles both in the same run and works out the
format per file.

### The original format (AES-ECB)

The malware derives its AES key with no KDF, no IV, no salt and no per file
state:

```
key        = Arrays.copyOf(keyString.getBytes(UTF_8), 32)
cipher     = AES/ECB/PKCS5Padding
ciphertext = encrypt(entire file)
```

One operator typed string covers every file the walker touched on that
machine. That single design choice is what makes recovery by guessing
practical at all: one AES key schedule and one block per candidate, instead of
the hundred thousand PBKDF2 rounds a competent implementation would have used.

AES-256 itself is **not** broken here and is not being attacked. The key is a
string a person typed. It is not derived from anything in the file and cannot
be read out of the ciphertext.

The candidate generator is fitted from the recovered keys handed over to this
build. Nothing in it is hand ranked. The character alphabets, the length
prior, the affix widths, the tiling motifs and the share of the sweep each
family receives are all measured from those keys. The families are:

| family | share | what it covers |
| --- | --- | --- |
| digit | ~32% | tilings and rotations of a short motif over the observed digit alphabet, plus fumbled tilings |
| word | ~27% | Turkish and English words with folding and short affixes |
| motor | ~24% | keyboard runs, reversals and zigzags on the Turkish Q layout |
| stem | ~18% | operator handle or word plus a digit tail |

Two things the fit ruled out, recorded here so nobody rebuilds them:

* A **positional mask model** does not work on this data. The fitted masks are
  dominated by `l9`, `d15`, `d16`, `l11` and `l13`, whose enumeration spaces
  are 5.1e11 to 8.2e16. Observed key length runs 5 to 23 with a mean of 11, so
  the tractable short masks are exactly the ones these operators do not use.
* A **character bigram** suffers the degenerate repeat pathology. Its highest
  scoring strings are `1111111111111111` and `KKKKKKKK`, and fitted on all
  recovered keys it surfaced only a few of them in the first million
  candidates.

### The newer format (AES-GCM)

Newer builds of the `!micro` command do it properly:

```
salt       = 16 random bytes per file
iv         = 12 random bytes per file
key        = PBKDF2-HMAC-SHA256(keyString as UTF-8, salt, 600000 rounds, 32 bytes)
cipher     = AES/GCM/NoPadding, 128-bit tag
file       = salt | iv | ciphertext | tag
```

The typed key is still the only secret, so the recovered keys still work.
What changes is the cost of a guess: 600,000 PBKDF2 rounds per file, roughly
0.2 seconds per CPU core, instead of one AES block. So on GCM files unmicro
tries the supplied keys, wordlist, recovered operator keys, scavenged strings
and (under `--brute`) the recovered key variants, and leaves the fitted model
and the structural brute to the older files, where they finish in a sensible
time. The GPU path is not used for GCM.

Because a GCM guess is so expensive, each one is checked against two files at
a time, and a key that opens one of them is then tried on every other file.
Those probe files are chosen to be unlikely to be damaged: files of 10 MB or
more where there are any (up to 256 MB), spread across the size range, and
never two from the same folder unless 60% or more of the files live in one
folder. Large probes are streamed from disk rather than held in memory. Files
left by an interrupted encryption run are also screened out first. If the
supplied and recovered keys open neither of the first two, they are tried on
the next two, and so on through up to 16 files. When nothing opens at all, the output says
how many of the GCM files were actually tested. If you know some files are
intact, running `--in` on a folder of just those is the quickest check.

Once a key has opened files, the files it did not open are swept again on
their own. In full-auto (no options, or a double-click) that second sweep
skips the slow recovered key variants, so the files already opened are
written in minutes rather than after an hour. Run with `--brute` explicitly
to include the variants for the stragglers.

Telling the formats apart: a GCM file is the original length plus 44 bytes, so
it is a whole number of AES blocks only one time in sixteen, while an ECB file
always is. Files that cannot be ECB go straight to the GCM search. Block
aligned files are first tried with the quick key sources (supplied keys,
wordlist, recovered keys, scavenged strings) as ECB and then as GCM, before
any open-ended search starts. Whatever is still closed then goes through the
ECB search, and anything that does not open as ECB, or that a GCM key from
the same machine opens, is treated as GCM.

---

## How well it works

Measured by leave one out: refit the model without each recovered key in turn,
then find where that key lands in the stream it would actually be swept in. A
model scored against keys it was fitted on is scoring its own memory.

Result on the 3.6 corpus: **14 of 34** within a 2,000,000 candidate budget, at
roughly 1.3M candidates per second generated. The 3.7 build adds further
recovered keys; the measurement harness is deliberately not shipped in the
tool. Nothing in `unmicro.py` exists except to recover files.

### Known gaps

These are real and are not regressions:

* **Uppercase mashes.** Keys like `KŞL132KŞL2KŞL432`, `qwkewqkeqwk` and
  `WQEŞİQW2ELŞ12` are motor noise over a twelve character alphabet at lengths
  8 to 17. Nothing reaches them at any budget tested. A Turkish Q adjacency
  walker was built and measured for this family, reached none of the confirmed
  mash keys inside 3M candidates, and was removed rather than left in taking
  budget from the families that work.
* **Vocabulary.** A key built on a name the vocabulary does not contain is
  unreachable no matter how candidates are ordered. Coverage of the stem and
  word families is vocabulary, not structure. Adding names to the sealed
  Turkish vocabulary is the cheapest way to improve this tool.
* `keyu3131` is missed. The honest route to it is stem mutation, not a
  hardcoded prefix copied out of the key itself.

---

## What's new

- **One program with a window (5.0).** unmicro is now a single
  download per platform: a window that walks through files, keys, search,
  output and the run, with the engine built in. The command line is inside the
  same file (`--cli`). In endless mode, safety limits on CPU temperature,
  memory, free disk and battery stop the search cleanly and recover what is
  matched. The separate command-line downloads are gone; `unmicro.py` still
  runs on its own from source.
- **Damaged copies, plain output, interactive menu (3.9).** Files left damaged
  by an interrupted attack are screened out before keys are tested and listed
  in `corrupted-files.txt`. Key probes are chosen from larger files spread
  across sizes and folders. Running with no arguments opens a plain-text menu.
  Output is five numbered steps with a final report that separates recovered,
  damaged, still-locked and problem files. Ctrl+C pauses, and a retry menu
  covers only the files still locked. See the changelog for details.
- **Edge-case fixes (3.8.2).** A machine-wide or double-click run could report
  0 hits on files the recovered keys open, if the two smallest GCM files were
  partial or under another key; the recovered keys now move on through up to
  16 files. `--auto` no longer skips user folders named `Dev`, `Run`,
  `Recovery`, `Windows`, `Snap`, `Sys` or `Proc` below the top of a drive, and
  finds `.CRYPTEDMICRO` in any letter case. Block-aligned GCM files are no
  longer held behind the ECB brute force. The double-click window stays open
  at the end, Ctrl+C writes what is already matched, and GCM output is
  streamed to disk. See CHANGELOG.md.
- **AES-GCM files (3.8).** Newer builds of the malware encrypt with
  AES-256-GCM under a PBKDF2-SHA256 key, still to `.cryptedmicro`. unmicro now
  recovers both formats in one run, works out which one each file is, and
  verifies GCM files by their authentication tag. Nothing changes for the
  original ECB files. See "How the key search works".
- **Per-build license key (3.7).** The recovered-key list, operator handles,
  Turkish vocabulary, keyboard layouts and actor notes are sealed with
  AES-256-CBC + HMAC-SHA256 under a key that is rotated at every release, so
  the gang cannot grep the public binary for them and rotate around what Rho-9
  has recovered. Supplied via `--license`, `UNMICRO_LICENSE`, or an
  interactive prompt. Victims get a key from **recon@rho-9.com**, free of
  charge.
- **`--self-test` (3.7).** Confirms the sealed blobs survived the freeze and
  the AES back end is intact. No license needed. This is what CI runs.
- **`--list-keys` (3.7).** Prints the recovered operator keys this build
  knows about. Requires the license.
- **Extension repair.** Recovered files are written under their true extension.
  This crew randomises extensions before encrypting (a video named `.jpg`), so
  unmicro reads the decrypted bytes and corrects a genuinely mismatched
  extension, reporting each one. On by default; `--no-fix-ext` turns it off.
- **`--scavenge FILE`.** Pulls candidate keys out of an unencrypted dump (memory
  image, pagefile, hibernation file, strings listing) and tries them first,
  where a typed key most often survives in the clear.
- **`--dumb-brute`.** A plain structural brute, 3 characters up to the longest
  recovered key, over the Turkish+English alphabet these operators type
  (`--charset`). Pauses and asks before a length that would take too long.
- **Bounded-memory sweep.** A long `--brute`/`--dumb-brute` run now holds flat
  memory instead of growing without bound (`--seen-cap`), which fixes an
  out-of-memory kill on deep runs.
- **`--checkpoint FILE`.** Save sweep progress and resume, skipping finished
  tiers and fast-forwarding the current one.
- **Full-auto.** A bare `python3 unmicro.py` searches every drive, tries every
  route, and writes to `./unmicro-recovered`.
- **All cores by default.** `--workers` now defaults to every CPU core; set 1 to
  stay single-process.
- **`--gpu` with an on-device structural brute (experimental, 3.6).** OpenCL for
  NVIDIA and AMD. The GPU generates the candidates itself, so `--dumb-brute`
  runs at device speed instead of being fed from one Python thread. See below.

## GPU acceleration (optional, experimental)

The sweep is one AES-256 decrypt per candidate, which is exactly what a GPU is
good at. The catch is feeding it: a single Python thread can only produce a few
hundred thousand candidates a second, which would starve any GPU. So for the
structural brute (`--dumb-brute`), **the GPU generates the candidates itself**,
each work item turns its own index into a candidate, builds the key, decrypts,
and checks the result. Nothing but the rare hit crosses the bus, so it runs at
the card's speed. One OpenCL kernel covers both NVIDIA and AMD.

**Run it from the Python source, not the released `.exe`.** The GPU needs
`pyopencl` and your GPU's OpenCL runtime, which the standalone binary does not
bundle (and most victim machines do not have). GPU is the operator's cracking
path:

```
pip install pyopencl numpy      # plus your NVIDIA or AMD OpenCL runtime
python3 unmicro.py --gpu-info                        # what OpenCL sees
python3 unmicro.py --in ./encrypted --out ./rec --dumb-brute --gpu
```

The fitted-model tier stays on the CPU (its candidates come from Python logic
that does not map to a GPU); the big win is the structural brute.

It is opt-in, and safe by construction for a recovery tool. Key derivation stays
on the CPU, so nothing is mis-encoded on the device. Two self-tests run before
the GPU is trusted for a single real candidate: it decrypts random blocks under
random keys and requires every byte to match the CPU AES back end, and it runs
the on-device brute over a sample and requires its hit set to equal the CPU's
over the same candidates. Any mismatch disables the GPU and the whole run
continues on the CPU, and every GPU hit is re-validated on the CPU before it
counts. So the GPU can make the search faster, or on hardware where the kernel
does not hold up simply not engage. It cannot make the search wrong or miss a
key.

This path is **new and experimental in 3.6**, and it was developed without a GPU
in the build environment. The kernel's AES-256 logic and the index-to-candidate
brute were verified against a reference implementation on random vectors, but
the OpenCL execution itself should be confirmed on your own card: run `--gpu`
and look for `GPU ready: …` followed by `GPU brute self-test passed`. If you see
a self-test failure instead, it has already fallen back to the CPU; please
report the device.

## Options worth knowing

| flag | effect |
| --- | --- |
| (no options) | open the interactive menu on a terminal. With `--no-ui`: search every drive, try every route, write to `./unmicro-recovered` |
| `--no-ui` | skip the menu. Also set by `UNMICRO_NO_UI=1` |
| `--license KEY` | this build's license key. Also read from `UNMICRO_LICENSE`, else prompted |
| `--self-test` | sealed-blob integrity + AES back end check. Does not need a license |
| `--list-keys` | print the recovered operator keys this build knows about. Needs a license |
| `--auto` | search every drive and user location for encrypted files |
| `--brute` | sweep generated candidates when the recovered keys do not fit |
| `--deep` | widen every family, including the layout walker. Hours, not seconds |
| `--dumb-brute` | plain structural brute force, 1 character up to the longest key, over the Turkish+English alphabet. Asks before a length that would take too long |
| `--charset observed\|turkish\|full` | alphabet for `--dumb-brute` (default `turkish`: Turkish and English lowercase and digits) |
| `--scavenge FILE` | pull candidate keys out of an unencrypted dump (memory image, pagefile, strings listing) and try them first. Repeatable |
| `--checkpoint FILE` | save sweep progress and resume from it, so an interrupted or capped run continues |
| `--seen-cap N` | cap each generator's dedup set at N entries (default 1,000,000). Lower on a low-memory machine |
| `--workers N` | parallel worker processes for the sweep. Defaults to every CPU core; set 1 to stay single-process |
| `--gpu` | use an OpenCL GPU (NVIDIA or AMD) for the sweep. Self-tests against the CPU first and falls back if it fails |
| `--gpu-info` | list the OpenCL platforms and devices found, and exit |
| `--max-candidates N` | give up after N guesses |
| `--yes` | answer yes to prompts, for unattended runs |
| `--identify` | work out which key applies and write nothing |
| `--wordlist FILE` | try your own candidates first, one per line |
| `--no-fix-ext` | stop correcting swapped extensions (this crew randomises them, so the correction is on by default) |
| `--strict` | never write anything that failed structural verification |
| `--force` | apply a single supplied key without header checking |

---

## Who this crew is

| name | what it refers to |
| --- | --- |
| **Chattering Magpies** | Rho-9's actor name for the operators. Use this in posts |
| **Micro** | what the malware calls itself |
| **Dev7** | the family designation |
| **Remote Sense** | the current disposable bot identity, not a durable name |

MAGPIES is Rho-9's category noun for financially motivated extortion crews.
Delivery has been observed through trojanized Minecraft mods in CurseForge
packs, and through files posing as games.

## Getting help

Reply or DM wherever you saw the Rho-9 post about this, or email
**recon@rho-9.com**. Include the phrase Chattering Magpies so the case is
routed quickly.

If this tool recovered your files, that is the end of it and you owe nobody
anything. If it did not, keep the encrypted copies and get in touch. There may
be more we can do, some of it as paid work, and we would rather hear from you
than have you delete the only copies that can still be recovered.
