# network_scanner_gui_fallback.py
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import ipaddress
import socket
import platform
import subprocess
import re
from queue import Queue
import time

# Try to import scapy (optional). If import fails, we'll just use fallback.
try:
    import scapy.all as scapy
    HAS_SCAPY = True
except Exception:
    HAS_SCAPY = False

SYSTEM = platform.system().lower()

def ping_host(ip, timeout=1000):
    """Ping an IP once. Returns True if host replies (ICMP)."""
    try:
        if SYSTEM == "windows":
            # -n 1 : one ping, -w timeout in ms
            completed = subprocess.run(["ping", "-n", "1", "-w", str(timeout), ip],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return completed.returncode == 0
        else:
            # mac/linux: -c 1 count 1, -W timeout in seconds (Linux) or -W on mac uses ms? approximate
            # Use -c 1 and timeout via subprocess timeout param
            completed = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            return completed.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

def get_mac_from_arp_table(ip):
    """Parse the OS ARP table to try to find the MAC for ip. Returns MAC or None."""
    try:
        if SYSTEM == "windows":
            out = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL, text=True)
            # Windows arp output: Interface: 192.168.1.2 --- 0x6
            #   Internet Address      Physical Address      Type
            #   192.168.1.1           00-11-22-33-44-55     dynamic
            m = re.search(rf"^{re.escape(ip)}\s+([0-9a-fA-F-:]+)", out, flags=re.MULTILINE)
            if m:
                return m.group(1).replace('-', ':').lower()
        else:
            # linux/mac: use 'arp -n' or 'arp -a'. We'll try both
            try:
                out = subprocess.check_output(["arp", "-n", ip], stderr=subprocess.DEVNULL, text=True)
            except Exception:
                out = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL, text=True)
            # Look for MAC patterns
            m = re.search(r"([0-9a-fA-F]{1,2}(?::|-)){5}[0-9a-fA-F]{1,2}", out)
            if m:
                return m.group(0).replace('-', ':').lower()
    except Exception:
        return None
    return None

def scan_with_scapy(ip, result_queue):
    """Send ARP request using scapy. Put list of dicts into result_queue."""
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answer = scapy.srp(packet, timeout=1, verbose=False)[0]
        clients = []
        for client in answer:
            client_info = {'IP': client[1].psrc, 'MAC': client[1].hwsrc}
            try:
                hostname = socket.gethostbyaddr(client_info['IP'])[0]
                client_info['Hostname'] = hostname
            except Exception:
                client_info['Hostname'] = 'Unknown'
            clients.append(client_info)
        result_queue.put(clients)
    except Exception as e:
        # Put an error marker so the GUI can show it
        result_queue.put([{'IP': ip, 'MAC': None, 'Hostname': None, 'Error': str(e)}])

def scan_fallback(ip, result_queue, log_text):
    """Ping + read ARP table fallback. Puts 0 or 1 client dicts into result_queue."""
    try:
        log_text_insert_safe(log_text, f"Pinging {ip} ...")
        alive = ping_host(ip)
        time_str = time.strftime("%H:%M:%S")
        if alive:
            # After ping, OS ARP cache may have the mac
            mac = get_mac_from_arp_table(ip)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = 'Unknown'
            client_info = {'IP': ip, 'MAC': mac if mac else 'Unknown', 'Hostname': hostname}
            result_queue.put([client_info])
            log_text_insert_safe(log_text, f"{time_str} - {ip} is alive, MAC: {client_info['MAC']}")
        else:
            log_text_insert_safe(log_text, f"{time_str} - {ip} no response")
            # you can choose to not put anything for non-responsive hosts
    except Exception as e:
        log_text_insert_safe(log_text, f"Error scanning {ip}: {e}")

def log_text_insert_safe(log_text, txt):
    def inner():
        log_text.insert(tk.END, txt + "\n")
        log_text.see(tk.END)
    try:
        log_text.after(0, inner)
    except Exception:
        # fallback if GUI gone
        pass

def start_scan(cidr, tree, status_label, scan_button, log_text, prefer_scapy=True):
    def threaded_scan():
        try:
            status_label.config(text="Preparing scan...")
            scan_button.config(state="disabled")
            results_queue = Queue()
            threads = []

            # Validate CIDR
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except Exception as e:
                messagebox.showerror("Invalid network", f"Invalid CIDR: {e}")
                status_label.config(text="Ready")
                scan_button.config(state="normal")
                return

            hosts = list(network.hosts())
            total = len(hosts)
            status_label.config(text=f"Scanning {total} hosts... (0/{total})")
            found = 0
            processed = 0

            # create worker threads for each host (bounded)
            max_threads = 100
            sem = threading.BoundedSemaphore(max_threads)

            def worker_for(ip_str):
                nonlocal found, processed
                sem.acquire()
                try:
                    if HAS_SCAPY and prefer_scapy:
                        scan_with_scapy(ip_str, results_queue)
                    else:
                        scan_fallback(ip_str, results_queue, log_text)
                finally:
                    processed += 1
                    status_label.after(0, lambda: status_label.config(text=f"Scanning {total} hosts... ({processed}/{total})"))
                    sem.release()

            for ip in hosts:
                t = threading.Thread(target=worker_for, args=(str(ip),), daemon=True)
                threads.append(t)
                t.start()

            # Wait for threads to finish
            for t in threads:
                t.join()

            # Collect results
            all_clients = []
            while not results_queue.empty():
                all_clients.extend(results_queue.get())

            # Clear table
            def populate_table():
                for row in tree.get_children():
                    tree.delete(row)
                for client in all_clients:
                    ip = client.get('IP', '')
                    mac = client.get('MAC', '') or ''
                    hostname = client.get('Hostname', '') or ''
                    if 'Error' in client:
                        tree.insert("", tk.END, values=(ip, f"ERROR: {client['Error']}", hostname))
                    else:
                        tree.insert("", tk.END, values=(ip, mac, hostname))
            tree.after(0, populate_table)

            # Final status
            if all_clients:
                status_label.config(text=f"Scan complete. {len(all_clients)} host(s) found (listed).")
            else:
                status_label.config(text="Scan complete. No hosts listed. If you expected results, try running as Admin/root or enable Scapy.")
                if not HAS_SCAPY:
                    messagebox.showinfo("Scapy not available", "Scapy is not installed or failed to import. The program used the ping+ARP-table fallback which may show fewer details.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            status_label.config(text="Error during scan.")
        finally:
            scan_button.config(state="normal")

    threading.Thread(target=threaded_scan, daemon=True).start()


def main_gui():
    root = tk.Tk()
    root.title("Network Scanner (scapy if available; fallback ping+arp otherwise)")
    root.geometry("850x520")

    # Input frame
    frame = ttk.Frame(root, padding=10)
    frame.pack(fill=tk.X)

    ttk.Label(frame, text="Enter Network (CIDR):").pack(side=tk.LEFT, padx=5)
    cidr_entry = ttk.Entry(frame, width=30)
    cidr_entry.pack(side=tk.LEFT, padx=5)
    cidr_entry.insert(0, "192.168.1.0/24")

    prefer_scapy_var = tk.BooleanVar(value=HAS_SCAPY)
    prefer_check = ttk.Checkbutton(frame, text="Prefer Scapy (requires admin/root & scapy)", variable=prefer_scapy_var)
    prefer_check.pack(side=tk.LEFT, padx=5)

    scan_button = ttk.Button(frame, text="Start Scan")
    scan_button.pack(side=tk.LEFT, padx=5)

    # Treeview (results)
    columns = ("IP", "MAC / Error", "Hostname")
    tree = ttk.Treeview(root, columns=columns, show="headings", height=13)
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=270, anchor=tk.W)
    tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

    # Log text box
    ttk.Label(root, text="Scan Log:").pack(anchor=tk.W, padx=10)
    log_text = tk.Text(root, height=8)
    log_text.pack(fill=tk.BOTH, expand=False, padx=10, pady=5)

    # Status label
    status_label = ttk.Label(root, text="Ready", anchor=tk.W)
    status_label.pack(fill=tk.X, padx=10, pady=5)

    # Bind button
    scan_button.config(command=lambda: start_scan(cidr_entry.get(), tree, status_label, scan_button, log_text, prefer_scapy_var.get()))

    root.mainloop()

if __name__ == "__main__":
    main_gui()
