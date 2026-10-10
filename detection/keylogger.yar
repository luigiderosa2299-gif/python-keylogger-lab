/*
    Regola YARA per il keylogger didattico del progetto python-keylogger-lab.

    Obiettivo: riconoscere il keylogger scritto in questo repository (o varianti
    molto simili basate su pynput con la stessa struttura) a partire da stringhe
    caratteristiche presenti nel codice sorgente o, se compilato con PyInstaller/
    simili, embeddate nel binario risultante.
*/

rule Python_Keylogger_Educational_PyNPut
{
    meta:
        author      = "Luigi De Rosa"
        description = "Rileva il keylogger didattico basato su pynput sviluppato per il portfolio cybersecurity"
        date        = "2026-10-10"
        reference   = "github.com/luigiderosa2299-gif/python-keylogger-lab"

    strings:
        $import_pynput    = "from pynput import keyboard" ascii
        $listener_call    = "keyboard.Listener(on_press=on_press)" ascii
        $log_file_name     = "keylog.txt" ascii
        $esc_check        = "keyboard.Key.esc" ascii
        $attr_error_catch = "except AttributeError" ascii

    condition:
        3 of ($import_pynput, $listener_call, $log_file_name, $esc_check, $attr_error_catch)
}
