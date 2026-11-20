# Python Keylogger — Educational Project (Malware Analysis & Detection)

> ⚠️ **Ethical Disclaimer**: this repository contains educational software developed exclusively for cybersecurity learning purposes, as part of my preparation for the CompTIA Security+ certification and the building of a technical portfolio. The keylogger it contains **does not exfiltrate any data to the outside**, does not hide itself, does not persist automatically, and must be run EXCLUSIVELY on machines owned by the author in an isolated lab environment (Kali Linux VM on a private network). Do not use this code on systems you do not have explicit authorization to test: doing so is a crime in almost every jurisdiction.

## 📌 Objective
Understand from the inside how a keylogger works — one of the most common categories of malware (see Module 2 of the CompTIA Security+ SY0-701 path) — by writing a minimal, transparent one, and building in parallel the tools to detect it: a YARA rule based on its code signatures and a runtime behavioral detection script. The learning goal is twofold: offensive skills (how the attack works) and defensive skills (how to detect it).

## 🧩 Context / Scenario
Personal lab (see [home-lab-cybersecurity](https://github.com/luigiderosa2299-gif/home-lab-cybersecurity)): Kali Linux VM on UTM, isolated private network. The keylogger was written, run and analyzed exclusively inside this controlled environment, with an active X11 graphical session on display `:0`.

## 🛠 Technologies and Tools
- **Python 3** with the [`pynput`](https://pypi.org/project/pynput/) library for intercepting keyboard events (X11 backend on Linux, Win32 on Windows)
- **YARA** for writing detection rules based on static signatures (source code and compiled PyInstaller binary)
- **psutil** for inspecting running processes (runtime behavioral detection, cross-platform)
- **PyInstaller** to compile the keylogger into a standalone executable
- Test environment: Kali Linux VM (main development) + Windows 11 VM (cross-platform verification), both on UTM

## ⚙️ What I Did

1. **Design rules**: local logging to a file only (`keylog.txt`), no network exfiltration, no persistence or process-hiding mechanism, explicit on-screen warning while running.
2. **Wrote the keylogger** (`keylogger.py`) in Python with `pynput`: it captures key presses through a listener attached to the graphical session, handles both normal characters (`key.char`) and special keys (SPACE, ENTER, BACKSPACE, ESC) through exception handling, and stops cleanly when ESC is pressed. Verified with `python3 -m py_compile` before running.
3. **Practical discovery of a limitation of raw logging**: the keylogger records keys in the exact order they are pressed, BACKSPACE included as a literal string (`Key.backspace`) — it does not reconstruct the "final" text taking deletions into account. A real forensic analysis would need a further step to reconstruct the text from the raw log.
4. **Wrote the YARA rule** (`detection/keylogger.yar`) based on the real strings present in the keylogger's source code (the `pynput` import, the log file name, the ESC key check, the exception handling).
5. **Verified the YARA rule** against the real source file with the command `yara detection/keylogger.yar keylogger.py` — match confirmed.
6. **Wrote the behavioral detection script** (`detection/detect_keylogger.py`) that scans running processes looking for keylogging-related text indicators in their command line.
7. **Tested the behavioral detection** while the keylogger was actually running — detection succeeded, but with **false positives**: the initial heuristic (based only on the string "keylogger" in the command line) also flagged the launching shell and the detection script itself.
8. **Rewrote `detect_keylogger.py` (v2)** to eliminate the false positives: exclusion of its own PID, exclusion of launcher shells (zsh/bash/...), exclusion of other instances of the script itself by file name. I also added a more robust behavioral check: an X11 listener must have at least one open Unix socket connection to the X server, verifiable with `psutil` without needing root permissions (pure Python modules like `pynput` are never memory-mapped with `mmap()`, so a check on `/proc/<pid>/maps` would not detect them).
9. **Final verification**: with the real keylogger running, only its process is flagged (zero false positives); with the keylogger stopped, no process is flagged.
10. **Compiled with PyInstaller** (`pyinstaller --onefile keylogger.py`) to get a standalone executable version, and analyzed what remains visible in the binary (`strings dist/keylogger`): the source code phrases used by the first YARA rule are no longer present (the bytecode is compressed into an internal archive), but the `pynput` submodule names remain in clear text in the bootloader's import table.
11. **Wrote a second YARA rule** (`Python_Keylogger_PyInstaller_Frozen`) based on these module strings, to also recognize the compiled version — verified with `yara detection/keylogger.yar dist/keylogger`: only the new rule matches, correctly not the one based on the source code.
12. **Cross-platform verification on a Windows 11 VM**: the same keylogger (`py keylogger.py`) ran successfully there too, confirming that `pynput` captures the keyboard correctly on the Win32 backend as well, not just on X11.
13. **Adapted `detect_keylogger.py` for Windows**: the behavioral Unix socket check (valid only on Linux/X11) has no equivalent on Windows, where `pynput` uses the native `SetWindowsHookEx` hooks with no IPC socket involved — the script now detects the platform and honestly reports the check as "not applicable" there, instead of failing.
14. **Discovered a Windows-specific false positive**: the Windows `py.exe` launcher does not replace itself with the real interpreter the way a Linux shell does, but keeps it as a separate child process — as a result, both appeared in the list with the same command line. Solved by treating `py.exe` as a launcher, on par with `zsh`/`bash`.

## 📊 Results

**Keylogger run** — real excerpt from `keylog.txt` after a typing test:
```
[2026-10-10 11:51:17] a
[2026-10-10 11:51:18] c
...
[2026-10-10 11:51:19] Key.backspace
...
[2026-10-10 11:51:20] Key.enter
[2026-10-10 11:51:28] c
[2026-10-10 11:51:28] i
[2026-10-10 11:51:28] a
[2026-10-10 11:51:28] o
[2026-10-10 11:51:28] Key.space
...
[2026-10-10 11:51:48] Key.esc
```

**YARA rule match** against the real source code:
```
$ yara detection/keylogger.yar keylogger.py
Python_Keylogger_Educational_PyNPut keylogger.py
```

**Runtime behavioral detection** (keylogger running in the background):
```
$ python3 detect_keylogger.py
🔍 Scansione processi in esecuzione per indicatori di keylogging...

⚠️  Trovati 4 processo/i sospetto/i:

  PID 21233 (python3) — indicatore: 'keylogger'
    cmdline: python3 keylogger.py
  PID 21565 (zsh) — indicatore: 'keylogger'
    cmdline: zsh -c cd ~/keylogger-lab && (...) python3 keylogger.py (...)
  PID 21567 (python3) — indicatore: 'keylogger'
    cmdline: python3 keylogger.py
  PID 21587 (python3) — indicatore: 'keylogger'
    cmdline: python3 detect_keylogger.py
```

The real keylogger process (`keylogger.py`) was correctly identified, but together with 3 false positives — including the shell that had launched it and the detection script itself, because the heuristic naively looks for the string "keylogger" anywhere in the command line.

**Detection v2, after the fix** (same scenario, real keylogger running):
```
$ python3 detect_keylogger.py
🔍 Scansione processi in esecuzione per indicatori di keylogging...

⚠️  Trovati 1 processo/i sospetto/i:

  PID 9556 (python3) — 🔴 RAFFORZATO (ha anche un socket IPC aperto, coerente con un listener GUI/X11)
    indicatori testuali: keylogger.py
    cmdline: python3 keylogger.py
```
Zero false positives, also confirmed with the keylogger stopped (no process flagged).

**YARA rule on the PyInstaller-compiled version**:
```
$ yara -s detection/keylogger.yar dist/keylogger
Python_Keylogger_PyInstaller_Frozen dist/keylogger
0xaa8f41:$mod_keyboard: pynput.keyboard
0xaa9067:$mod_mouse: pynput.mouse
0xaa8eed:$mod_util_xorg: pynput._util.xorg
0xaa8e9b:$mod_util_win32: pynput._util.win32
0xaa8e1f:$mod_util_darwin: pynput._util.darwin
0xaa980b:$script_name: keylogger
```
Only the new rule matches the compiled binary; the one based on the source code does not — confirming that the two forms of the same tool require different signatures.

**Run on Windows 11** — `python.exe keylogger.py` started successfully, keylogger working identically to Linux.

**Behavioral detection on Windows, before the fix** — crash:
```
ValueError: invalid kind argument 'unix'; valid ones are ('all', 'tcp', 'tcp4', 'udp', 'inet', 'inet4', 'inet6', 'tcp6', 'udp6')
```

**After the cross-platform adaptation**, with `py.exe` still to be excluded:
```
⚠️  Trovati 2 processo/i sospetto/i:
  PID 2656 (python.exe) — ⚪ non verificabile
    cmdline: python.exe keylogger.py
  PID 11860 (py.exe) — ⚪ non verificabile
    cmdline: py.exe keylogger.py
```

**After the final fix** (excluding `py.exe` as a launcher): only the real `python.exe` process is flagged, zero false positives on Windows as well.

## 💡 What I Learned
- **A "raw" keylogger does not produce readable text**: it records events, not meaning. Understanding this difference is essential when analyzing real logs in an incident response context — raw data always has to be interpreted, never taken literally.
- **YARA is effective on source code/static binaries**, but says nothing about an already running process: that requires a different approach (process inspection, system hooks, EDR telemetry) — hence the choice to pair the YARA rule with a separate behavioral detection script.
- **Naive behavioral detection produces false positives**: searching for a single keyword in a process's command line does not distinguish between "the malicious process" and "anything that mentions that word", including the detection tool itself. A real detector (an EDR, a SIEM rule) has to be much more specific — for example by checking the process's actual IPC behavior, not just the text of its command line. This is the same principle of "understand the cause before trusting the result" I already met in the Nmap scan of the home-lab project.
- **Compiling does not mean hiding the code**: a PyInstaller executable does not expose the original source code, but the libraries it bundles still leave a footprint (the names of the imported modules) — a well-designed static signature has to adapt to the form in which the malware shows up, not just to its original source code.
- **A cross-platform tool has to be tested on every platform, not assumed**: the same detection script behaved radically differently between Linux and Windows — a total crash on one, a new false positive on the other (`py.exe` as a "ghost" process of the launcher). Without actually testing it on Windows, both problems would have stayed invisible until the first real use.

## 🔬 How Realistic Is This Lab? Comparison with Real Implementations

**Vs. public educational keyloggers** (e.g. common GitHub repos, tutorials): the structure of `keylogger.py` is practically identical to the standard pattern used by anyone writing an educational keylogger with `pynput` — `keyboard.Listener` + an `on_press` function + `try/except AttributeError` to tell normal keys from special keys + writing to a file. It is not an improvised implementation: it is the canonical skeleton for this purpose.

**Vs. real malware** (public analyses of Snake Keylogger, VIP Keylogger, Kimsuky): the difference is huge, and intentional. A real keylogger typically adds:
- **Persistence**: copies itself into a hidden folder and registers to start at boot (Windows registry, scheduled task, logon script) — ours does not, it has to be launched manually every time.
- **Concealment**: a file name that imitates a legitimate system process, no on-screen warning, sometimes process hollowing to hide inside a trusted process — ours prints an explicit warning and is a Python file with its own name.
- **Exfiltration**: sending the stolen data to a remote C2 server via email (SMTP), Telegram, FTP or HTTP — ours only writes to a local file, no network.
- **Additional collection**: theft of credentials saved in the browser, periodic screenshots, clipboard monitoring — ours only records keystrokes.
- **Anti-analysis**: code obfuscation, date-based kill switches, checks on whether the environment is a sandbox — ours is code readable by anyone, deliberately.

This comparison is the central teaching point of the project: the "hard" part of a real keylogger is not capturing keystrokes (that is the easy part, 10 lines of code), but everything else — staying invisible, surviving a reboot, and getting the data out without being caught. This is also why the two defensive halves of the lab (YARA + behavioral detection) remain conceptually valid even against more sophisticated variants: a static signature and a behavioral check are exactly the two categories of detection a real EDR would use, just more elaborate.

## 🔗 Links
- [Home Lab — Cybersecurity Practice Environment](https://github.com/luigiderosa2299-gif/home-lab-cybersecurity)
- [pynput documentation](https://pynput.readthedocs.io/)
- [YARA documentation](https://yara.readthedocs.io/)
