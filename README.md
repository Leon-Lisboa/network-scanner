# Network Scanner

## Descrição (Português 🇧🇷)
O **Network Scanner** é uma ferramenta interativa desenvolvida em Python, que permite realizar escaneamentos em redes locais. Ele utiliza ARP para descobrir dispositivos conectados e exibe informações como endereço IP, endereço MAC, fabricante (via API Mac Vendors) e portas abertas (1 a 1024). A interface gráfica foi criada com `tkinter`.

### Funcionalidades:
- Escaneamento de dispositivos em redes locais.
- Identificação do fabricante dos dispositivos usando a API Mac Vendors.
- Descoberta de portas abertas.
- Salva os resultados em um arquivo `scan_results.txt`.

### Requisitos:
- Python 3.x
- Bibliotecas: `scapy`, `requests`, `tkinter`

### Como usar:
1. Execute o programa como administrador.
2. Insira o intervalo de IPs no formato CIDR (exemplo: `192.168.1.0/24`).
3. Visualize os dispositivos encontrados na interface gráfica.

---

## Description (English 🇺🇸)
The **Network Scanner** is an interactive tool developed in Python that performs scans on local networks. It uses ARP to discover connected devices and displays information such as IP address, MAC address, vendor (via Mac Vendors API), and open ports (1 to 1024). The graphical interface is built with `tkinter`.

### Features:
- Scans devices on local networks.
- Identifies device vendors using the Mac Vendors API.
- Discovers open ports.
- Saves results in a `scan_results.txt` file.

### Requirements:
- Python 3.x
- Libraries: `scapy`, `requests`, `tkinter`

### How to use:
1. Run the program as an administrator.
2. Enter the IP range in CIDR format (e.g., `192.168.1.0/24`).
3. View the found devices in the graphical interface.

---

## Descripción (Español 🇪🇸)
El **Network Scanner** es una herramienta interactiva desarrollada en Python que realiza escaneos en redes locales. Utiliza ARP para descubrir dispositivos conectados y muestra información como dirección IP, dirección MAC, fabricante (a través de la API de Mac Vendors) y puertos abiertos (1 a 1024). La interfaz gráfica está diseñada con `tkinter`.

### Funcionalidades:
- Escanea dispositivos en redes locales.
- Identifica el fabricante del dispositivo utilizando la API de Mac Vendors.
- Descubre puertos abiertos.
- Guarda los resultados en un archivo `scan_results.txt`.

### Requisitos:
- Python 3.x
- Bibliotecas: `scapy`, `requests`, `tkinter`

### Cómo usar:
1. Ejecute el programa como administrador.
2. Ingrese el rango de IPs en formato CIDR (por ejemplo: `192.168.1.0/24`).
3. Visualice los dispositivos encontrados en la interfaz gráfica.
