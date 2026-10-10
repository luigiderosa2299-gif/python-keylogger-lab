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
2. **Scrittura del keylogger** (`keylogger.py`) in Python con `pynput`: intercetta la pressione dei tasti tramite un listener collegato alla sessione grafica, gestisce sia caratteri normali (`key.char`) sia tasti speciali (SPAZIO, INVIO, BACKSPACE, ESC) tramite gestione delle eccezioni, e si ferma in modo pulito alla pressione di ESC.
3. **Debug di un primo tentativo**: la prima stesura conteneva cinque errori tipici da principiante — indentazione errata dentro un blocco `except`, un refuso nel nome del modulo (`datetie` invece di `datetime`), una stringa di formato data priva di separatori, una confusione tra l'operatore di assegnazione `=` e quello di confronto `==` in due punti distinti del codice (incluso il blocco `if __name__ == "__main__":` scritto con underscore singoli invece di doppi). Tutti risolti e verificati con `python3 -m py_compile` prima dell'esecuzione.
4. **Scoperta pratica di una limitazione del logging grezzo**: il keylogger registra i tasti nell'ordine esatto in cui vengono premuti, BACKSPACE incluso come stringa letterale (`Key.backspace`) — non ricostruisce il testo "finale" tenendo conto delle cancellazioni. Per un'analisi forense vera servirebbe un passo successivo di ricostruzione del testo a partire dal log grezzo.
5. **Scrittura della regola YARA** (`detection/keylogger.yar`) basata sulle stringhe reali presenti nel codice sorgente del keylogger (import di `pynput`, nome del file di log, controllo del tasto ESC, gestione dell'eccezione).
6. **Verifica della regola YARA** contro il file sorgente reale con il comando `yara detection/keylogger.yar keylogger.py` — match confermato.
7. **Scrittura dello script di detection comportamentale** (`detection/detect_keylogger.py`) che scansiona i processi in esecuzione cercando indicatori testuali legati al keylogging nella loro command line.
8. **Test della detection comportamentale** mentre il keylogger era realmente in esecuzione — rilevamento riuscito, ma con **falsi positivi** (lo script ha segnalato anche se stesso e il comando shell di lancio, perché entrambi contenevano la stringa "keylogger").

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

## 💡 Cosa ho imparato
- **Indentazione, `=` vs `==`, doppio underscore**: errori banali da scrivere ma impossibili da ignorare in Python — il linguaggio non compila proprio finché non sono corretti, il che costringe a un livello di precisione diverso rispetto ad altri linguaggi più permissivi.
- **Un keylogger "grezzo" non produce testo leggibile**: registra eventi, non significato. Capire questa differenza è fondamentale quando si analizzano log reali in un contesto di incident response — il dato grezzo va sempre interpretato, mai preso alla lettera.
- **YARA è efficace sul codice sorgente/binario statico**, ma non dice nulla su un processo già in esecuzione: per quello serve un approccio diverso (ispezione dei processi, hook di sistema, telemetria EDR) — da qui la scelta di affiancare alla regola YARA uno script di detection comportamentale separato.
- **La detection comportamentale ingenua produce falsi positivi**: cercare una singola parola chiave nella command line di un processo non distingue tra "il processo malevolo" e "qualunque cosa menzioni quella parola", incluso lo strumento di detection stesso. Un detector reale (un EDR, una regola SIEM) deve essere molto più specifico — per esempio verificando quali librerie sono effettivamente caricate in memoria dal processo, non solo il testo della sua riga di comando. Questo è lo stesso principio di "capire la causa prima di fidarsi del risultato" già incontrato nello scan Nmap del progetto home-lab.

## 🔜 Prossimi passi
- [ ] Migliorare `detect_keylogger.py` per ridurre i falsi positivi (es. escludere il proprio PID, verificare le librerie effettivamente caricate invece della sola command line)
- [ ] Estendere la regola YARA per coprire anche un'eventuale versione compilata (PyInstaller) del keylogger
- [ ] Script di ricostruzione del testo a partire dal log grezzo (gestione dei BACKSPACE)

## 🔗 Collegamenti
- [Home Lab — Cybersecurity Practice Environment](https://github.com/luigiderosa2299-gif/home-lab-cybersecurity)
- [pynput documentation](https://pynput.readthedocs.io/)
- [YARA documentation](https://yara.readthedocs.io/)
