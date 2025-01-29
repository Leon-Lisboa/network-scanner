import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import ARP, Ether, srp
import requests
import threading
import socket

# Função para validar o intervalo de IP
import ipaddress

def is_valid_ip_range(ip_range):
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False

# Função para buscar o fabricante via API Mac Vendors
def get_vendor(mac_address):
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
    except Exception:
        pass
    return "Desconhecido"

# Função de escaneamento
def network_scan(ip_range):
    devices = []
    try:
        # Construindo o pacote ARP
        arp_request = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request

        # Enviando o pacote e recebendo respostas
        answered, _ = srp(packet, timeout=2, verbose=False)
        
        for sent, received in answered:
            device = {
                "ip": received.psrc,
                "mac": received.hwsrc,
                "vendor": get_vendor(received.hwsrc),
                "open_ports": scan_ports(received.psrc)
            }
            devices.append(device)
    except Exception as e:
        print(f"Erro no escaneamento: {e}")
    return devices

# Função para escanear portas abertas
def scan_ports(ip):
    open_ports = []
    try:
        for port in range(1, 1025):  # Escaneia as portas de 1 a 1024
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
    except Exception:
        pass
    return open_ports

# Classe principal com a GUI
class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("800x600")

        # Entrada para o intervalo de IPs
        self.label = tk.Label(root, text="Intervalo de IPs (CIDR):", font=("Arial", 12))
        self.label.pack(pady=10)

        self.target_entry = tk.Entry(root, width=30, font=("Arial", 12))
        self.target_entry.pack(pady=10)

        # Botão de iniciar escaneamento
        self.scan_button = tk.Button(root, text="Iniciar Escaneamento", font=("Arial", 12), command=self.start_scan)
        self.scan_button.pack(pady=10)

        # Área de texto para exibir os resultados
        self.text_area = tk.Text(root, wrap=tk.WORD, font=("Courier New", 10), width=80, height=20)
        self.text_area.pack(pady=10)

        # Barra de rolagem
        self.scrollbar = ttk.Scrollbar(root, command=self.text_area.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_area.config(yscrollcommand=self.scrollbar.set)

        # Botão de salvar resultados
        self.save_button = tk.Button(root, text="Salvar Resultados", font=("Arial", 12), state=tk.DISABLED, command=self.save_results)
        self.save_button.pack(pady=10)

        self.results = []

    # Função para iniciar o escaneamento
    def start_scan(self):
        target = self.target_entry.get()
        if not target or not is_valid_ip_range(target):
            messagebox.showerror("Erro", "Por favor, insira um intervalo de IPs válido no formato CIDR (ex.: 192.168.1.0/24).")
            return

        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, "[+] Iniciando escaneamento...\n")
        self.root.update()

        # Usando Threading para evitar congelamento da interface
        threading.Thread(target=self.perform_scan, args=(target,)).start()

    # Função para realizar o escaneamento
    def perform_scan(self, target):
        try:
            self.results = network_scan(target)
            self.text_area.insert(tk.END, f"[+] {len(self.results)} dispositivos encontrados:\n")
            for device in self.results:
                self.text_area.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}, Fabricante: {device['vendor']}, Portas Abertas: {device['open_ports']}\n")
            self.save_button.config(state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror("Erro", f"Erro durante o escaneamento: {e}")

    # Função para salvar os resultados
    def save_results(self):
        try:
            with open("scan_results.txt", "w") as file:
                for device in self.results:
                    file.write(f"IP: {device['ip']}, MAC: {device['mac']}, Fabricante: {device['vendor']}, Portas Abertas: {device['open_ports']}\n")
            messagebox.showinfo("Sucesso", "Resultados salvos em 'scan_results.txt'.")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao salvar os resultados: {e}")

# Inicializando a aplicação
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
