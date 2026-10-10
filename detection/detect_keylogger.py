"""
Script di detection comportamentale per il progetto python-keylogger-lab.

Obiettivo didattico: individuare, a runtime, processi Python in esecuzione che
importano la libreria pynput per l'intercettazione della tastiera — una euristica
semplice ma realistica di come un EDR identificherebbe un comportamento sospetto
leggendo la command line e le librerie caricate da un processo, invece di
affidarsi solo a una firma statica del file (quello lo fa già la regola YARA
in keylogger.yar).

Uso: python3 detect_keylogger.py
Richiede: psutil (pip install psutil --break-system-packages)
"""

import psutil

INDICATORI_SOSPETTI = ["pynput", "keylogger", "keyboard.listener"]


def scansiona_processi():
    trovati = []

    for processo in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmdline = " ".join(processo.info["cmdline"] or []).lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        for indicatore in INDICATORI_SOSPETTI:
            if indicatore in cmdline:
                trovati.append(
                    {
                        "pid": processo.info["pid"],
                        "nome": processo.info["name"],
                        "cmdline": cmdline,
                        "indicatore": indicatore,
                    }
                )
                break

    return trovati


if __name__ == "__main__":
    print("🔍 Scansione processi in esecuzione per indicatori di keylogging...\n")
    risultati = scansiona_processi()

    if not risultati:
        print("Nessun indicatore sospetto trovato.")
    else:
        print(f"⚠️  Trovati {len(risultati)} processo/i sospetto/i:\n")
        for r in risultati:
            print(f"  PID {r['pid']} ({r['nome']}) — indicatore: '{r['indicatore']}'")
            print(f"    cmdline: {r['cmdline']}\n")
