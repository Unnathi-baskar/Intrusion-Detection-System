import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import subprocess
import os
import signal

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

DETECTION_CONFIG = {
    "IP Spoofing": {
        "server_cmd": [
            os.path.join(SCRIPT_DIR, "spoof_udp", "ssl_server"),
            "-cert", os.path.join(SCRIPT_DIR, "spoof_udp", "server.crt"),
            "-key",  os.path.join(SCRIPT_DIR, "spoof_udp", "server.key")
        ],
        "client_cmd": [
            os.path.join(SCRIPT_DIR, "spoof_udp", "ids_sniffer")
        ]
    },
    "UDP Flood": {
        "server_cmd": [
            os.path.join(SCRIPT_DIR, "spoof_udp", "udp_server"),
            "-cert", os.path.join(SCRIPT_DIR, "spoof_udp", "udp.crt"),
            "-key",  os.path.join(SCRIPT_DIR, "spoof_udp", "udp.key")
        ],
        "client_cmd": [
            os.path.join(SCRIPT_DIR, "spoof_udp", "udp_flood_detector")
        ]
    },
    "SYN Scan": {
        "server_cmd": [
            os.path.join(SCRIPT_DIR, "syn_scan", "syn_scan_detect"),
            "ens160",
            "172.20.10.3",
            os.path.join(SCRIPT_DIR, "syn_scan", "syn_detect.crt"),
            os.path.join(SCRIPT_DIR, "syn_scan", "syn_detect.key"),
            "9447"
        ],
        "client_cmd": []
    },
    "SYN Flood": {
        "server_cmd": [
            os.path.join(SCRIPT_DIR, "syn_flood", "syn_flood_detect"),
        ],
        "client_cmd": []
    }
}

server_process = None
client_process = None

def stream_logs(proc, tag):
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        output_text.insert(tk.END, f"[{tag}] {line.decode()}")
        output_text.see(tk.END)

def start_process(command, tag):
    cwd = os.path.dirname(command[0])
    p = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
        cwd=cwd
    )
    threading.Thread(target=stream_logs, args=(p, tag), daemon=True).start()
    return p

def start_detection():
    global server_process, client_process
    method = detection_method.get()
    cfg = DETECTION_CONFIG[method]

    if server_process or client_process:
        output_text.insert(tk.END, "Detection is already running.\n")
        return

    output_text.insert(tk.END, f"Starting {method} detection...\n")

    server_process = start_process(cfg["server_cmd"], "SERVER")

    if cfg.get("client_cmd"):
        client_process = start_process(cfg["client_cmd"], "CLIENT")

    output_text.insert(tk.END, "Detection started.\n\n")

def stop_detection():
    global server_process, client_process
    for proc, name in ((server_process, "Server"), (client_process, "Client")):
        if proc:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            output_text.insert(tk.END, f"{name} stopped.\n")
    server_process = client_process = None
    output_text.insert(tk.END, "All detection stopped.\n\n")

root = tk.Tk()
root.title("Network Intrusion Detection System")
root.geometry("600x400")

detection_method = tk.StringVar(value="IP Spoofing")
ttk.Label(root, text="Select Detection Method:").pack(pady=10)
ttk.Combobox(
    root,
    textvariable=detection_method,
    values=list(DETECTION_CONFIG.keys()),
    state="readonly"
).pack()

btn_frame = ttk.Frame(root); btn_frame.pack(pady=10)
ttk.Button(btn_frame, text="Start Detection", command=start_detection).grid(row=0, column=0, padx=10)
ttk.Button(btn_frame, text="Stop Detection",  command=stop_detection).grid(row=0, column=1, padx=10)

output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=15)
output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

root.mainloop()