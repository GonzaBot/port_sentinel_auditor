import socket
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import ipaddress
import subprocess
import re

# ──────────────────────────────────────────────
# Mapa de servicios conocidos por puerto
# ──────────────────────────────────────────────
SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-TLS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

# Puertos que mandan banner automáticamente (no enviar nada)
PASSIVE_BANNER_PORTS = {21, 22, 23, 25, 110, 143, 465, 587, 993, 995}

class PortSentinelGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Sentinel Auditor v3.0")
        self.root.geometry("920x830")
        self.root.configure(bg="#121212")
        self.cancel_flag = threading.Event()

        # ── Título ──────────────────────────────
        tk.Label(
            root, text="SENTINEL NETWORK AUDITOR",
            font=("Courier", 20, "bold"), fg="#00ff00", bg="#121212"
        ).pack(pady=15)

        # ── Input ───────────────────────────────
        frame_input = tk.Frame(root, bg="#121212")
        frame_input.pack(pady=5)
        tk.Label(
            frame_input, text="OBJETIVO (IP, Dominio o CIDR):",
            fg="#aaaaaa", bg="#121212", font=("Arial", 10, "bold")
        ).grid(row=0, column=0, padx=5)
        self.entry_target = tk.Entry(
            frame_input, font=("Consolas", 14), width=32,
            bg="#222222", fg="#00ff00", insertbackground="white", borderwidth=0
        )
        self.entry_target.grid(row=0, column=1, padx=5, pady=10)

        # ── Botones de modo ──────────────────────
        frame_btns = tk.Frame(root, bg="#121212")
        frame_btns.pack(pady=6)

        self.btn_passive = tk.Button(
            frame_btns, text="PASIVO", font=("Arial", 10, "bold"),
            command=lambda: self.start_scan_thread("passive"),
            bg="#2e7d32", fg="white", width=14, relief="flat", pady=6
        )
        self.btn_passive.grid(row=0, column=0, padx=5)

        self.btn_standard = tk.Button(
            frame_btns, text="ESTÁNDAR", font=("Arial", 10, "bold"),
            command=lambda: self.start_scan_thread("standard"),
            bg="#1565c0", fg="white", width=14, relief="flat", pady=6
        )
        self.btn_standard.grid(row=0, column=1, padx=5)

        self.btn_heavy = tk.Button(
            frame_btns, text="AGRESIVO", font=("Arial", 10, "bold"),
            command=lambda: self.start_scan_thread("heavy"),
            bg="#c62828", fg="white", width=14, relief="flat", pady=6
        )
        self.btn_heavy.grid(row=0, column=2, padx=5)

        self.btn_cancel = tk.Button(
            frame_btns, text="CANCELAR", font=("Arial", 10, "bold"),
            command=self._request_cancel,
            bg="#555555", fg="white", width=14, relief="flat",
            pady=6, state=tk.DISABLED
        )
        self.btn_cancel.grid(row=0, column=3, padx=5)

        # ── Barra de progreso + contador ─────────
        frame_progress = tk.Frame(root, bg="#121212")
        frame_progress.pack(fill="x", padx=25, pady=(6, 0))

        self.progress_var = tk.DoubleVar(value=0)
        self.progressbar = ttk.Progressbar(
            frame_progress, variable=self.progress_var,
            maximum=100, mode="determinate", length=860
        )
        self.progressbar.pack(fill="x", pady=(0, 4))

        # Estilo verde para la barra
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "green.Horizontal.TProgressbar",
            troughcolor="#1a1a1a", background="#00cc44",
            bordercolor="#1a1a1a", lightcolor="#00cc44", darkcolor="#00cc44"
        )
        self.progressbar.configure(style="green.Horizontal.TProgressbar")

        # Fila con porcentaje, contador de puertos y puertos abiertos
        frame_stats = tk.Frame(root, bg="#121212")
        frame_stats.pack(fill="x", padx=25)

        self.lbl_percent = tk.Label(
            frame_stats, text="0%",
            fg="#00cc44", bg="#121212", font=("Consolas", 10, "bold"), width=6, anchor="w"
        )
        self.lbl_percent.pack(side="left")

        self.lbl_port_counter = tk.Label(
            frame_stats, text="Puertos escaneados: 0 / 0",
            fg="#888888", bg="#121212", font=("Consolas", 10)
        )
        self.lbl_port_counter.pack(side="left", padx=15)

        self.lbl_open_counter = tk.Label(
            frame_stats, text="Abiertos: 0",
            fg="#00ff88", bg="#121212", font=("Consolas", 10, "bold")
        )
        self.lbl_open_counter.pack(side="left")

        self.lbl_host_info = tk.Label(
            frame_stats, text="",
            fg="#555555", bg="#121212", font=("Consolas", 9), anchor="e"
        )
        self.lbl_host_info.pack(side="right")

        # ── Output ──────────────────────────────
        self.txt_output = scrolledtext.ScrolledText(
            root, width=104, height=23,
            bg="#0a0a0a", fg="#00ff00", font=("Consolas", 10),
            insertbackground="#00ff00", selectbackground="#003300"
        )
        self.txt_output.pack(pady=10, padx=20)

        # ── Estado inferior ──────────────────────
        self.lbl_status = tk.Label(
            root, text="Sistema listo para auditoría",
            fg="#666666", bg="#121212", font=("Arial", 9, "italic")
        )
        self.lbl_status.pack(pady=4)

        # Contadores internos (thread-safe via after())
        self._open_count = 0
        self._scanned_count = 0
        self._total_ports = 0

    # ────────────────────────────────────────────
    # Utilidades de red
    # ────────────────────────────────────────────
    def get_network_scope(self, ip_str):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback:  return "LOCAL",            "🔒"
            if ip_obj.is_private:   return "PRIVADA (LAN)",    "🏠"
            return "PÚBLICA (INTERNET)", "🌍"
        except (ValueError, TypeError):
            return "DESCONOCIDO", "❓"

    def get_mac_address(self, ip):
        """
        Obtiene el MAC via tabla ARP del sistema.
        SOLO funciona en red local (LAN/loopback).
        Para IPs públicas siempre devolverá N/A — es una limitación
        del protocolo: los routers no reenvían MACs de terceros.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not (ip_obj.is_private or ip_obj.is_loopback):
                return "N/A (host remoto — ARP no aplica)"

            # Ping silencioso para poblar la caché ARP del sistema
            ping_cmd = (
                ["ping", "-n", "1", "-w", "800", ip]   # Windows
                if os.name == "nt" else
                ["ping", "-c", "1", "-W", "1", ip]     # Linux / macOS
            )
            subprocess.run(
                ping_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3
            )

            # Leer tabla ARP
            arp_cmd = (
                ["arp", "-a", ip] if os.name == "nt"
                else ["arp", "-n", ip]
            )
            result = subprocess.run(
                arp_cmd,
                capture_output=True, text=True, timeout=3
            )

            # Buscar patrón XX:XX:XX:XX:XX:XX  o  XX-XX-XX-XX-XX-XX
            mac_pattern = (
                r"([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}"
            )
            match = re.search(mac_pattern, result.stdout)
            if match:
                mac = match.group(0).upper().replace("-", ":")
                return mac

            return "N/A (no encontrado en caché ARP)"

        except subprocess.TimeoutExpired:
            return "N/A (timeout ARP)"
        except Exception:
            return "N/A (error)"

    def analyze_banner(self, banner):
        if not banner or banner == "-":
            return "No detectado", "No detectado"

        os_info  = "No detectado"
        srv_info = "No detectado"

        # Servidor
        if   "Apache"        in banner: srv_info = "Apache"
        elif "nginx"         in banner: srv_info = "Nginx"
        elif "Microsoft-IIS" in banner: srv_info = "IIS (Windows Server)"
        elif "lighttpd"      in banner: srv_info = "Lighttpd"
        elif "OpenSSH"       in banner: srv_info = "OpenSSH"
        elif "vsftpd"        in banner: srv_info = "vsftpd (FTP)"
        elif "Postfix"       in banner: srv_info = "Postfix (SMTP)"

        # Sistema operativo
        if   "Ubuntu" in banner or "Debian"   in banner: os_info = "Linux (Ubuntu/Debian)"
        elif "Win64"  in banner or "Windows"  in banner: os_info = "Windows OS"
        elif "CentOS" in banner or "Red Hat"  in banner: os_info = "Linux (RHEL/CentOS)"
        elif "FreeBSD" in banner:                         os_info = "FreeBSD"
        elif "Darwin"  in banner:                         os_info = "macOS/Darwin"

        return os_info, srv_info

    def fetch_banner(self, sock, port):
        try:
            sock.settimeout(0.9)
            # Puertos web: enviamos HEAD request
            if port in {80, 443, 8080, 8443}:
                sock.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            # Puertos pasivos (FTP, SSH, SMTP, etc.) ya mandan banner solos

            data = sock.recv(1024).decode(errors="ignore").strip()
            return data.replace("\n", " ").replace("\r", "") if data else "Sin banner"
        except Exception:
            return "-"

    # ────────────────────────────────────────────
    # Escaneo de un solo puerto (usado en el pool)
    # ────────────────────────────────────────────
    def scan_port(self, ip, port, timeout):
        if self.cancel_flag.is_set():
            return None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = self.fetch_banner(sock, port)
                sock.close()
                return port, banner
            sock.close()
        except Exception:
            pass
        return None

    # ────────────────────────────────────────────
    # UI helpers
    # ────────────────────────────────────────────
    def set_ui_state(self, scanning: bool):
        btn_state   = tk.DISABLED if scanning else tk.NORMAL
        cancel_state = tk.NORMAL if scanning else tk.DISABLED
        self.btn_passive.config(state=btn_state)
        self.btn_standard.config(state=btn_state)
        self.btn_heavy.config(state=btn_state)
        self.btn_cancel.config(state=cancel_state)

    def safe_log(self, message):
        self.root.after(
            0,
            lambda: (
                self.txt_output.insert(tk.END, message + "\n"),
                self.txt_output.see(tk.END)
            )
        )

    def _request_cancel(self):
        self.cancel_flag.set()
        self.lbl_status.config(text="Cancelando escaneo...")

    def _update_progress(self, scanned, total, open_count, current_ip=""):
        pct = (scanned / total * 100) if total > 0 else 0
        self.progress_var.set(pct)
        self.lbl_percent.config(text=f"{int(pct)}%")
        self.lbl_port_counter.config(text=f"Puertos escaneados: {scanned} / {total}")
        self.lbl_open_counter.config(text=f"Abiertos: {open_count}")
        if current_ip:
            self.lbl_host_info.config(text=f"Host: {current_ip}")

    def _reset_progress(self, total):
        self._scanned_count = 0
        self._open_count    = 0
        self._total_ports   = total
        self.root.after(0, lambda: self._update_progress(0, total, 0))

    # ────────────────────────────────────────────
    # Lanzador del hilo de escaneo
    # ────────────────────────────────────────────
    def start_scan_thread(self, mode):
        target = self.entry_target.get().strip()
        if not target:
            messagebox.showwarning("Atención", "Por favor, ingresa una IP, dominio o subred.")
            return

        self.cancel_flag.clear()
        self.set_ui_state(True)
        self.txt_output.delete(1.0, tk.END)
        threading.Thread(
            target=self.run_scanner,
            args=(target, mode),
            daemon=True
        ).start()

    # ────────────────────────────────────────────
    # Núcleo del escáner
    # ────────────────────────────────────────────
    def run_scanner(self, target, mode):
        full_log_data = []

        profiles = {
            "passive":  {"ports": [22, 80, 443],
                         "timeout": 0.5, "workers": 20},
            "standard": {"ports": [21, 22, 25, 53, 80, 110, 143, 443,
                                    445, 3306, 3389, 5432, 8080, 8443],
                         "timeout": 0.3, "workers": 50},
            "heavy":    {"ports": list(range(1, 1025)),
                         "timeout": 0.15, "workers": 150},
        }

        conf = profiles[mode]

        try:
            # ── Resolución de targets ────────────
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)

                # Advertencia para redes grandes
                if network.num_addresses > 256:
                    proceed = [False]
                    ev = threading.Event()
                    def ask():
                        proceed[0] = messagebox.askyesno(
                            "Red grande",
                            f"Esta subred contiene {network.num_addresses - 2} hosts.\n"
                            "Esto puede tardar mucho tiempo. ¿Continuar?"
                        )
                        ev.set()
                    self.root.after(0, ask)
                    ev.wait()
                    if not proceed[0]:
                        self.set_ui_state(False)
                        return

                targets = [str(ip) for ip in network.hosts()]
            else:
                targets = [socket.gethostbyname(target)]

            total_ports_all = len(targets) * len(conf["ports"])
            self._reset_progress(total_ports_all)

            header = (
                f"=== AUDITORÍA {mode.upper()} — {len(targets)} HOST(S) | "
                f"{len(conf['ports'])} puertos c/u | {datetime.now().strftime('%H:%M:%S')} ==="
            )
            self.safe_log(f"{header}\n{'─' * 84}")
            full_log_data.append(header)

            global_open = 0

            # ── Loop por hosts ───────────────────
            for idx, ip in enumerate(targets, 1):
                if self.cancel_flag.is_set():
                    self.safe_log("\n⚠️  Escaneo cancelado por el usuario.")
                    break

                scope, icon = self.get_network_scope(ip)
                self.root.after(
                    0,
                    lambda i=ip, s=idx, t=len(targets):
                        self.lbl_status.config(
                            text=f"Escaneando host {s}/{t}: {i}"
                        )
                )

                # ── Obtener MAC (LAN solamente) ──
                mac = self.get_mac_address(ip)

                host_line = (
                    f"\n{icon} HOST: {ip} | ÁMBITO: {scope}\n"
                    f"      ┗━ MAC : {mac}"
                )
                # El host_line se muestra SOLO si tiene puertos abiertos (ver abajo)

                host_open = 0
                results = []

                # ── Escaneo paralelo del host ────
                with ThreadPoolExecutor(max_workers=conf["workers"]) as ex:
                    futures = {
                        ex.submit(self.scan_port, ip, p, conf["timeout"]): p
                        for p in conf["ports"]
                    }
                    for future in as_completed(futures):
                        if self.cancel_flag.is_set():
                            ex.shutdown(wait=False, cancel_futures=True)
                            break

                        self._scanned_count += 1
                        result = future.result()

                        if result:
                            results.append(result)
                            host_open    += 1
                            global_open  += 1
                            self._open_count = global_open

                        # Actualizar UI cada 5 puertos o al final
                        sc = self._scanned_count
                        if sc % 5 == 0 or sc == total_ports_all:
                            self.root.after(
                                0,
                                lambda s=sc, t=total_ports_all, o=global_open, i=ip:
                                    self._update_progress(s, t, o, i)
                            )

                # Ordenar resultados por número de puerto
                results.sort(key=lambda x: x[0])

                # Solo mostrar el host si tiene al menos un puerto abierto
                if results:
                    self.safe_log(host_line)
                    full_log_data.append(host_line)

                for port, banner in results:
                    service  = SERVICES.get(port, "Unknown")
                    os_det, srv_det = self.analyze_banner(banner)
                    exposed  = "SÍ ⚠️" if "PÚBLICA" in scope else "NO ✅"
                    trunc    = banner[:65] + ("…" if len(banner) > 65 else "")

                    output = (
                        f"  [+] PUERTO {port:<5} ({service:<12}) | ABIERTO | "
                        f"INTERNET: {exposed}\n"
                        f"      ┗━ Banner : {trunc}\n"
                        f"      ┗━ OS     : {os_det:<28} Servidor: {srv_det}"
                    )
                    self.safe_log(output)
                    full_log_data.append(output)

                if results:
                    summary_line = f"  ── {host_open} puerto(s) abierto(s) en {ip}"
                    self.safe_log(summary_line)
                    full_log_data.append(summary_line)

            # ── Resumen final ────────────────────
            if not self.cancel_flag.is_set():
                footer = (
                    f"\n{'═' * 84}\n"
                    f"  RESUMEN: {global_open} puerto(s) abierto(s) en {len(targets)} host(s)\n"
                    f"  Fin: {datetime.now().strftime('%H:%M:%S')}\n"
                    f"{'═' * 84}"
                )
                self.safe_log(footer)
                full_log_data.append(footer)

                # Progreso al 100%
                self.root.after(
                    0,
                    lambda: self._update_progress(
                        total_ports_all, total_ports_all, global_open
                    )
                )

                path = self.save_to_downloads(target, full_log_data)
                self.root.after(
                    0,
                    lambda p=path: messagebox.showinfo(
                        "Auditoría completada",
                        f"Se encontraron {global_open} puerto(s) abierto(s).\n\nLog guardado en:\n{p}"
                    )
                )

        except socket.gaierror:
            self.safe_log(f"⚠️  No se pudo resolver el host: {target}")
        except Exception as e:
            self.safe_log(f"⚠️  Error crítico: {e}")
        finally:
            self.root.after(0, lambda: self.set_ui_state(False))
            self.root.after(
                0,
                lambda: self.lbl_status.config(
                    text="Escaneo finalizado" if not self.cancel_flag.is_set()
                    else "Escaneo cancelado"
                )
            )

    # ────────────────────────────────────────────
    # Guardar reporte
    # ────────────────────────────────────────────
    def save_to_downloads(self, target, data):
        home    = os.path.expanduser("~")
        d_path  = os.path.join(home, "Downloads")
        os.makedirs(d_path, exist_ok=True)   # Garantiza que existe

        safe_name  = target.replace(".", "_").replace("/", "_")
        timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        final_file = os.path.join(d_path, f"Audit_{safe_name}_{timestamp}.txt")

        with open(final_file, "w", encoding="utf-8") as f:
            f.write(f"PORT SENTINEL AUDITOR — Reporte generado: {datetime.now()}\n")
            f.write("=" * 84 + "\n")
            f.write("\n".join(data))

        return final_file


# ──────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    app  = PortSentinelGUI(root)
    root.mainloop()