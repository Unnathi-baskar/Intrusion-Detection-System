import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import subprocess
import os
import signal

server_process = None
client_process = None

DETECTION_CONFIG = {
    "Test Log": {
        "server_cmd": None,
        "client_cmd": ["./log_test"]
    }
}

def start_process(command, tag, method):
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            text=True,
            preexec_fn=os.setsid
        )

        def reader():
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                output_text.insert(tk.END, f"[{tag}] {line}")
                output_text.see(tk.END)

        threading.Thread(target=reader, daemon=True).start()
        return process

    except Exception as e:
        output_text.insert(tk.END, f"[{tag} ERROR] {str(e)}\n")
        output_text.see(tk.END)
        return None

def start_detection():
    global server_process, client_process
    method = detection_method.get()
    config = DETECTION_CONFIG.get(method)

    if server_process or client_process:
        output_text.insert(tk.END, "Detection is already running.\n")
        return

    output_text.insert(tk.END, f"Starting {method} detection...\n")

    if config["client_cmd"]:
        client_process = start_process(config["client_cmd"], "CLIENT", method)

    output_text.insert(tk.END, "Detection started.\n\n")

def stop_detection():
    global server_process, client_process
    if client_process:
        os.killpg(os.getpgid(client_process.pid), signal.SIGTERM)
        output_text.insert(tk.END, "Client stopped.\n")
        client_process = None

    if not client_process:
        output_text.insert(tk.END, "All detection stopped.\n\n")

root = tk.Tk()
root.title("Minimal Test GUI")
root.geometry("700x450")

detection_method = tk.StringVar(value="Test Log")
ttk.Label(root, text="Select Detection Method:").pack(pady=5)
method_selector = ttk.Combobox(root, textvariable=detection_method, values=list(DETECTION_CONFIG.keys()), state="readonly")
method_selector.pack()

btn_frame = ttk.Frame(root)
btn_frame.pack(pady=10)

start_button = ttk.Button(btn_frame, text="Start Detection", command=start_detection)
start_button.grid(row=0, column=0, padx=10)

stop_button = ttk.Button(btn_frame, text="Stop Detection", command=stop_detection)
stop_button.grid(row=0, column=1, padx=10)

output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=18)
output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

root.mainloop()
