# Python Keylogger — Progetto Didattico (Malware Analysis & Detection)

> ⚠️ **Disclaimer etico**: questo repository contiene software didattico sviluppato esclusivamente per scopi di apprendimento in cybersecurity, nell'ambito della preparazione alla certificazione CompTIA Security+ e della costruzione di un portfolio tecnico. Il keylogger qui contenuto **non effettua alcuna esfiltrazione di dati verso l'esterno**, non si nasconde, non persiste automaticamente, e va eseguito ESCLUSIVAMENTE su macchine di proprietà dell'autore in un ambiente di laboratorio isolato (VM Kali Linux su rete privata). Non utilizzare questo codice su sistemi di cui non si ha l'autorizzazione esplicita: farlo costituisce un reato in quasi tutte le giurisdizioni.

## 📌 Obiettivo
Comprendere dall'interno il funzionamento di un keylogger — una delle categorie di malware più comuni (vedi Modulo 2 del percorso CompTIA Security+ SY0-701) — scrivendone uno minimale e trasparente, e costruire in parallelo gli strumenti per riconoscerlo: una regola YARA basata sulle sue firme di codice e uno script di detection comportamentale a runtime. L'obiettivo didattico è duplice: capacità offensiva (come funziona l'attacco) e capacità difensiva (come lo si rileva).

## 🧩 Contesto / Scenario
Laboratorio personale (vedi [home-lab-cybersecurity](https://github.com/luigiderosa2299-gif/home-lab-cybersecurity)): VM Kali Linux su UTM, rete privata isolata. Il keylogger è stato scritto, eseguito e analizzato esclusivamente all'interno di questo ambiente controllato, con sessione grafica X11 attiva sul display `:0`.

## 🛠 Tecnologie e Strumenti
- **Python 3** con libreria [`pynput`](https://pypi.org/project/pynput/) per l'intercettazione degli eventi di tastiera (backend X11 su Linux)
- **YARA** per la scrittura di una regola di detection basata su firma statica
- **psutil** per l'ispezione dei processi in esecuzione (detection comportamentale a runtime)
- Ambiente di test: VM Kali Linux (lab isolato)

## ⚙️ Cosa ho fatto

1. **Progettazione delle regole di design**: solo logging locale su file (`keylog.txt`), nessuna esfiltrazione di rete, nessun meccanismo di persistenza o occultamento del processo, avviso esplicito a schermo quando è in esecuzione.
2. **Scrittura del keylogger** (`keylogger.py`) in Python con `pynput`: intercetta la pressione dei tasti tramite un listener collegato alla sessione grafica, gestisce sia caratteri normali (`key.char`) sia tasti speciali (SPAZIO, INVIO, BACKSPACE, ESC) tramite gestione delle eccezioni, e si ferma in modo pulito alla pressione di ESC. Verificato con `python3 -m py_compile` prima dell'esecuzione.
3. **Scoperta pratica di una limitazione del logging grezzo**: il keylogger registra i tasti nell'ordine esatto in cui vengono premuti, BACKSPACE incluso come stringa letterale (`Key.backspace`) — non ricostruisce il testo "finale" tenendo conto delle cancellazioni. Per un'analisi forense vera servirebbe un passo successivo di ricostruzione del testo a partire dal log grezzo.
4. **Scrittura della regola YARA** (`detection/keylogger.yar`) basata sulle stringhe reali presenti nel codice sorgente del keylogger (import di `pynput`, nome del file di log, controllo del tasto ESC, gestione dell'eccezione).
5. **Verifica della regola YARA** contro il file sorgente reale con il comando `yara detection/keylogger.yar keylogger.py` — match confermato.
6. **Scrittura dello script di detection comportamentale** (`detection/detect_keylogger.py`) che scansiona i processi in esecuzione cercando indicatori testuali legati al keylogging nella loro command line.
7. **Test della detection comportamentale** mentre il keylogger era realmente in esecuzione — rilevamento riuscito, ma con **falsi positivi**: l'euristica iniziale (basata solo sulla stringa "keylogger" nella command line) segnalava anche la shell di lancio e lo script di detection stesso.
8. **Riscrittura di `detect_keylogger.py` (v2)** per eliminare i falsi positivi: esclusione del proprio PID, esclusione delle shell di lancio (zsh/bash/...), esclusione delle altre istanze dello script stesso per nome file. Aggiunto anche un controllo comportamentale più solido: un listener X11 deve avere almeno una connessione socket Unix aperta verso il server X, verificabile con `psutil` senza bisogno di permessi root (i moduli Python puri come `pynput` non vengono mai mappati in memoria con `mmap()`, quindi un controllo su `/proc/<pid>/maps` non li rileverebbe).
9. **Verifica finale**: con il keylogger reale in esecuzione, solo il suo processo viene segnalato (zero falsi positivi); a keylogger fermato, nessun processo viene segnalato.
10. **Compilazione con PyInstaller** (`pyinstaller --onefile keylogger.py`) per ottenere una versione eseguibile standalone, e analisi di cosa resta visibile nel binario (`strings dist/keylogger`): le frasi di codice sorgente usate dalla prima regola YARA non sono più presenti (il bytecode viene compresso in un archivio interno), ma i nomi dei sottomoduli di `pynput` restano in chiaro nella tabella di import del bootloader.
11. **Scrittura di una seconda regola YARA** (`Python_Keylogger_PyInstaller_Frozen`) basata su queste stringhe di modulo, per riconoscere anche la versione compilata — verificata con `yara detection/keylogger.yar dist/keylogger`: matcha solo la nuova regola, correttamente non quella basata sul codice sorgente.

## 📊 Risultati

**Esecuzione del keylogger** — estratto reale da `keylog.txt` dopo un test di digitazione:
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

**Match della regola YARA** contro il codice sorgente reale:
```
$ yara detection/keylogger.yar keylogger.py
Python_Keylogger_Educational_PyNPut keylogger.py
```

**Detection comportamentale a runtime** (keylogger in esecuzione in background):
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

Il processo reale del keylogger (`keylogger.py`) è stato individuato correttamente, ma insieme a 3 falsi positivi — inclusa la shell che lo aveva lanciato e lo script di detection stesso, perché l'euristica cerca ingenuamente la stringa "keylogger" ovunque nella command line.

**Detection v2, dopo il fix** (stesso scenario, keylogger reale in esecuzione):
```
$ python3 detect_keylogger.py
🔍 Scansione processi in esecuzione per indicatori di keylogging...

⚠️  Trovati 1 processo/i sospetto/i:

  PID 9556 (python3) — 🔴 RAFFORZATO (ha anche un socket IPC aperto, coerente con un listener GUI/X11)
    indicatori testuali: keylogger.py
    cmdline: python3 keylogger.py
```
Zero falsi positivi, confermato anche a keylogger fermato (nessun processo segnalato).

**Regola YARA sulla versione compilata PyInstaller**:
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
Solo la nuova regola matcha il binario compilato; quella basata sul codice sorgente no — conferma che le due forme dello stesso strumento richiedono firme diverse.

## 💡 Cosa ho imparato
- **Un keylogger "grezzo" non produce testo leggibile**: registra eventi, non significato. Capire questa differenza è fondamentale quando si analizzano log reali in un contesto di incident response — il dato grezzo va sempre interpretato, mai preso alla lettera.
- **YARA è efficace sul codice sorgente/binario statico**, ma non dice nulla su un processo già in esecuzione: per quello serve un approccio diverso (ispezione dei processi, hook di sistema, telemetria EDR) — da qui la scelta di affiancare alla regola YARA uno script di detection comportamentale separato.
- **La detection comportamentale ingenua produce falsi positivi**: cercare una singola parola chiave nella command line di un processo non distingue tra "il processo malevolo" e "qualunque cosa menzioni quella parola", incluso lo strumento di detection stesso. Un detector reale (un EDR, una regola SIEM) deve essere molto più specifico — per esempio verificando il comportamento IPC effettivo del processo, non solo il testo della sua riga di comando. Questo è lo stesso principio di "capire la causa prima di fidarsi del risultato" già incontrato nello scan Nmap del progetto home-lab.
- **Compilare non significa nascondere il codice**: un eseguibile PyInstaller non espone il codice sorgente originale, ma le librerie che bundla lasciano comunque un'impronta (i nomi dei moduli importati) — una firma statica ben progettata deve adattarsi alla forma in cui il malware si presenta, non solo al suo codice sorgente originale.

## 🔬 Quanto è realistico questo lab? Confronto con implementazioni reali

**Vs. keylogger didattici pubblici** (es. repo GitHub comuni, tutorial): la struttura di `keylogger.py` è praticamente identica al pattern standard usato da chiunque scriva un keylogger educational con `pynput` — `keyboard.Listener` + funzione `on_press` + `try/except AttributeError` per distinguere tasti normali da tasti speciali + scrittura su file. Non è un'implementazione improvvisata: è lo scheletro canonico per questo scopo.

**Vs. malware reali** (analisi pubbliche di Snake Keylogger, VIP Keylogger, Kimsuky): la differenza è enorme, e voluta. Un keylogger reale aggiunge tipicamente:
- **Persistenza**: si copia in una cartella nascosta e si registra per partire al boot (registro di Windows, task pianificato, script di logon) — il nostro non lo fa, va lanciato manualmente ogni volta.
- **Occultamento**: nome file che imita un processo di sistema legittimo, nessun avviso a schermo, a volte process hollowing per nascondersi dentro un processo fidato — il nostro stampa un avviso esplicito ed è un file Python a nome proprio.
- **Esfiltrazione**: invio dei dati rubati a un server C2 remoto via email (SMTP), Telegram, FTP o HTTP — il nostro scrive solo su un file locale, nessuna rete.
- **Raccolta aggiuntiva**: furto di credenziali salvate nel browser, screenshot periodici, monitoraggio della clipboard — il nostro registra solo i tasti.
- **Anti-analisi**: offuscamento del codice, kill switch basati su data, controllo se l'ambiente è una sandbox — il nostro è codice leggibile a chiunque, volutamente.

Questo confronto è il punto didattico centrale del progetto: la parte "difficile" di un vero keylogger non è intercettare i tasti (quella è la parte facile, 10 righe di codice), ma tutto il resto — restare invisibile, resistere al riavvio, e far uscire i dati senza farsi beccare. È anche per questo che le due metà difensive del lab (YARA + detection comportamentale) restano concettualmente valide anche contro varianti più sofisticate: una firma statica e un controllo comportamentale sono esattamente le due categorie di detection che un EDR reale userebbe, solo più elaborate.

## 🔗 Collegamenti
- [Home Lab — Cybersecurity Practice Environment](https://github.com/luigiderosa2299-gif/home-lab-cybersecurity)
- [pynput documentation](https://pynput.readthedocs.io/)
- [YARA documentation](https://yara.readthedocs.io/)
