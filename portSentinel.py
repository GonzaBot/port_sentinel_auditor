import socket
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from datetime import datetime
import os
import ipaddress

# Comentario: Día 2 - Port Sentinel (Dual Logging Mode + Network Scope)
# Pantalla: Filtrado (Abiertos con Alcance) | Archivo: Verbose (Todo)

class PortSentinelGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Port Sentinel Auditor")
        self.root.geometry("800x700")
        self.root.configure(bg="#121212")

        tk.Label(root, text="NETWORK PORT AUDITOR", font=("Courier", 18, "bold"), fg="#00ff00", bg="#121212").pack(pady=20)
        
        frame_input = tk.Frame(root, bg="#121212")
        frame_input.pack(pady=10)

        tk.Label(frame_input, text="IP o Dominio:", fg="white", bg="#121212").grid(row=0, column=0, padx=5)
        self.entry_target = tk.Entry(frame_input, font=("Consolas", 12), width=25, bg="#333", fg="white", insertbackground="white")
        self.entry_target.grid(row=0, column=1, padx=5)

        self.btn_scan = tk.Button(root, text="INICIAR AUDITORÍA", command=self.start_scan_thread, bg="#007acc", fg="white", font=("Arial", 10, "bold"), width=25, relief="flat")
        self.btn_scan.pack(pady=15)

        # Amplié un poco el ancho del cuadro de texto para acomodar la nueva columna
        self.txt_output = scrolledtext.ScrolledText(root, width=95, height=22, bg="#1e1e1e", fg="#00ff00", font=("Consolas", 10))
        self.txt_output.pack(pady=10, padx=20)

        self.lbl_status = tk.Label(root, text="Estado: Listo", fg="#888", bg="#121212")
        self.lbl_status.pack()

    def safe_log(self, message):
        """Actualiza la GUI desde el hilo principal."""
        self.root.after(0, lambda: (self.txt_output.insert(tk.END, message + "\n"), self.txt_output.see(tk.END)))

    def get_network_scope(self, ip_str):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback: return "LOOPBACK"
            if ip_obj.is_private: return "LAN (Privada)"
            return "WAN (Pública)"
        except: return "N/A"

    def fetch_banner(self, sock):
        try:
            sock.settimeout(1.0)
            sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
            data = sock.recv(512).decode(errors='ignore').strip()
            return data.split('\r\n')[0][:40] if data else "Servicio sin banner"
        except: return "-"

    def start_scan_thread(self):
        target = self.entry_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Ingresa un objetivo.")
            return
        self.btn_scan.config(state=tk.DISABLED)
        self.txt_output.delete(1.0, tk.END)
        self.lbl_status.config(text="Escaneando...", fg="#ffcc00")
        threading.Thread(target=self.run_scanner, args=(target,), daemon=True).start()

    def run_scanner(self, target):
        full_log_data = [] # Para el TXT (Todo el registro)
        try:
            target_ip = socket.gethostbyname(target)
            scope = self.get_network_scope(target_ip)
            
            # Encabezados
            info_header = f"[*] AUDITORÍA: {target} ({target_ip})"
            self.safe_log(info_header)
            full_log_data.append(info_header)
            full_log_data.append(f"[*] Fecha: {datetime.now()}\n")
            
            # Agregamos 'ALCANCE' a la tabla visual
            table_header = f"{'PUERTO':<10} {'ESTADO':<10} {'ALCANCE':<15} {'DETALLES/BANNER'}"
            self.safe_log(f"\n{table_header}")
            self.safe_log("-" * 75)
            full_log_data.append(table_header)
            full_log_data.append("-" * 75)

            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080]

            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    banner = self.fetch_banner(sock)
                    # INCLUIMOS EL SCOPE AQUÍ PARA LA PANTALLA Y EL LOG
                    line = f"{port:<10} {'ABIERTO':<10} {scope:<15} {banner}"
                    self.safe_log(f"[+] {line}")
                    full_log_data.append(f"[+] {line}")
                else:
                    # SOLO SE GUARDA EN EL LOG (TXT), MANTENIENDO EL ALINEAMIENTO
                    full_log_data.append(f"[-] {port:<10} {'CERRADO':<10} {scope:<15} Timeout/Refused")
                
                sock.close()

            path = self.save_to_downloads(target, full_log_data)
            self.root.after(0, lambda: self.lbl_status.config(text="Finalizado", fg="#00ff00"))
            self.root.after(0, lambda: messagebox.showinfo("Listo", f"Auditoría terminada.\nLog completo guardado en:\n{path}"))

        except Exception as e:
            self.safe_log(f"[!] Error: {str(e)}")
        finally:
            self.root.after(0, lambda: self.btn_scan.config(state=tk.NORMAL))

    def save_to_downloads(self, target, data):
        try:
            home = os.path.expanduser("~")
            d_path = os.path.join(home, "Downloads")
            if not os.path.exists(d_path):
                d_path = os.path.join(home, "Descargas")
            
            filename = f"Full_Audit_{target.replace('.', '_')}.txt"
            final_file = os.path.join(d_path, filename)
            
            with open(final_file, "w", encoding="utf-8") as f:
                f.write("=== REPORTE TÉCNICO COMPLETO (SIN FILTROS) ===\n")
                for item in data:
                    f.write(item + "\n")
            return final_file
        except: return "Error al guardar"

if __name__ == "__main__":
    root = tk.Tk()
    app = PortSentinelGUI(root)
    root.mainloop()