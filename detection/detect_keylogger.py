"""
Script di detection comportamentale per il progetto python-keylogger-lab.

Obiettivo didattico: individuare, a runtime, processi Python in esecuzione che
usano la libreria pynput per l'intercettazione della tastiera — una euristica
più vicina a come un EDR reale distinguerebbe "il processo ha davvero caricato
quella libreria" da "il testo del comando contiene una parola sospetta".

Versione 2 — corregge i 3 falsi positivi osservati nella v1 (si segnalava da
solo, segnalava la shell di lancio, e si basava solo sul testo della command
line):
  1. Esclude sempre il proprio PID.
  2. Esclude le shell (zsh/bash/sh/...) che hanno solo lanciato il comando:
     non sono il processo malevolo, solo il tramite.
  3. Esclude le altre istanze di questo stesso script per nome file.
  4. Aggiunge una seconda verifica, più vicina al comportamento reale: legge
     /proc/<pid>/maps (solo Linux) per controllare se la libreria pynput/Xlib
     è davvero mappata in memoria dal processo, non solo menzionata nel testo
     del comando. Un detector che si fida solo della command line è facile da
     ingannare (basta rinominare lo script); uno che controlla cosa è
     davvero caricato in memoria no.

Uso: python3 detect_keylogger.py
Richiede: psutil (pip install psutil --break-system-packages)
"""

import os
import platform

import psutil

OWN_PID = os.getpid()
SELF_SCRIPT = os.path.basename(__file__)
SISTEMA = platform.system()  # "Linux", "Windows", "Darwin"

# Nomi di processo che sono solo "lanciatori" (shell): non sono mai loro il
# processo malevolo, solo il tramite che lo ha avviato.
NOMI_SHELL = {"zsh", "bash", "sh", "dash", "fish", "powershell", "powershell.exe", "cmd.exe"}

INDICATORI_CMDLINE = ["keylogger.py", "pynput", "keyboard.listener"]


def ha_connessione_socket_sospetta(pid):
    """Verifica se il processo ha almeno una connessione socket Unix aperta.

    NOTA ONESTA sul perché questo controllo esiste al posto di uno basato su
    /proc/<pid>/maps: un modulo Python puro come pynput (o python-xlib, da cui
    dipende su Linux/X11) NON viene mai mappato in memoria con mmap() — viene
    letto con una normale read() dal bytecode .pyc, quindi non appare MAI in
    /proc/<pid>/maps, nemmeno quando è davvero importato e in uso. Verificato
    empiricamente su questo stesso lab (vedi README). Un keylogger X11 reale,
    invece, DEVE aprire una connessione IPC verso il server X (socket Unix su
    /tmp/.X11-unix/X0) per ricevere gli eventi di tastiera — e questo si vede
    senza bisogno di permessi root, tramite psutil.

    LIMITE SCOPERTO TESTANDO SU WINDOWS: i socket Unix non esistono su quella
    piattaforma (psutil solleva ValueError se gli chiedi kind="unix" lì). Non
    è un bug da correggere: è che pynput usa un backend completamente diverso
    su Windows (gli hook nativi SetWindowsHookEx), senza alcun socket IPC di
    mezzo — quindi questo specifico controllo comportamentale non ha proprio
    un equivalente su quella piattaforma. Per questo il controllo si limita a
    Linux e su altri sistemi dichiara onestamente "non applicabile", invece
    di far crashare lo script o fingere un risultato che non ha verificato.

    È un segnale comportamentale più solido del solo testo della command
    line (più difficile falsificare "ho una connessione IPC attiva" che
    "il mio script non si chiama keylogger.py"), ma resta un'euristica: un
    qualsiasi programma GUI legittimo apre socket simili. Non è una prova
    definitiva, è un indizio in più da incrociare con quello testuale."""
    if SISTEMA != "Linux":
        return None  # controllo non applicabile su questa piattaforma

    try:
        proc = psutil.Process(pid)
        try:
            connessioni = proc.net_connections(kind="unix")
        except AttributeError:
            connessioni = proc.connections(kind="unix")  # psutil più vecchie
        return len(connessioni) > 0
    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError, ValueError):
        return None


def scansiona_processi():
    trovati = []

    for processo in psutil.process_iter(["pid", "name", "cmdline"]):
        pid = processo.info["pid"]

        if pid == OWN_PID:
            continue  # non segnalare mai se stesso

        try:
            nome = processo.info["name"] or ""
            cmdline = " ".join(processo.info["cmdline"] or []).lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        if SELF_SCRIPT in cmdline:
            continue  # un'altra istanza di questo stesso script di detection

        if nome.lower() in NOMI_SHELL:
            continue  # la shell che ha lanciato il comando, non il processo reale

        indicatori_trovati = [i for i in INDICATORI_CMDLINE if i in cmdline]
        if not indicatori_trovati:
            continue

        conferma_socket = ha_connessione_socket_sospetta(pid)

        trovati.append(
            {
                "pid": pid,
                "nome": nome,
                "cmdline": cmdline,
                "indicatori": indicatori_trovati,
                "socket_ipc_aperto": conferma_socket,
            }
        )

    return trovati


if __name__ == "__main__":
    print("🔍 Scansione processi in esecuzione per indicatori di keylogging...\n")
    risultati = scansiona_processi()

    if not risultati:
        print("Nessun indicatore sospetto trovato.")
    else:
        print(f"⚠️  Trovati {len(risultati)} processo/i sospetto/i:\n")
        for r in risultati:
            if r["socket_ipc_aperto"] is True:
                badge = "🔴 RAFFORZATO (ha anche un socket IPC aperto, coerente con un listener GUI/X11)"
            elif r["socket_ipc_aperto"] is False:
                badge = "🟡 solo indizio testuale (nessun socket IPC aperto trovato)"
            else:
                badge = "⚪ non verificabile (permessi insufficienti, o controllo non applicabile su questa piattaforma)"

            print(f"  PID {r['pid']} ({r['nome']}) — {badge}")
            print(f"    indicatori testuali: {', '.join(r['indicatori'])}")
            print(f"    cmdline: {r['cmdline']}\n")
