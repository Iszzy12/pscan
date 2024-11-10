import socket
import threading
from tkinter import *
from tkinter import ttk
import shodan
from cofig import API_KEY
from concurrent.futures import ThreadPoolExecutor

# Shodan API Key (replace this with your actual API key)

api = shodan.Shodan(API_KEY)

# Function to scan a single port
def scan_port(ip, port, protocol):
    try:
        # TCP Scan
        if protocol == "TCP":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:  # Port is open
                    service = socket.getservbyport(port, "tcp")
                    tree.insert("", "end", values=(port, service, "TCP"))
        # UDP Scan
        elif protocol == "UDP":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.5)
                try:
                    s.sendto(b"", (ip, port))
                    service = socket.getservbyport(port, "udp")
                    tree.insert("", "end", values=(port, service, "UDP"))
                except socket.error:
                    pass
    except Exception as e:
        print(f"Error scanning port {port}: {e}")

# Function to scan ports in a given range
def scan_ports(ip, start_port, end_port, protocol):
    for item in tree.get_children():
        tree.delete(item)  # Clear previous results
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, ip, port, protocol)

    port_result_label.config(text="Port scan complete. Fetching Shodan data...", foreground="green")
    threading.Thread(target=fetch_shodan_data, args=(ip,)).start()

# Function to fetch Shodan data for the given IP
def fetch_shodan_data(ip):
    try:
        # Get host data from Shodan
        results = api.host(ip)
        for item in results.get('data', []):
            port = item.get('port', 'Unknown')
            service = item.get('product', 'Unknown')
            vulns = item.get('vulns', {})
            vuln_summary = ", ".join(vulns.keys()) if vulns else "No known vulnerabilities"
            tree.insert("", "end", values=(port, service, "Shodan", vuln_summary))
        port_result_label.config(text="Shodan data fetch complete.", foreground="green")
    except shodan.APIError as e:
        port_result_label.config(text=f"Shodan API error: {e}", foreground="red")

# Validate the user input for the IP and port range
def validate_ip():
    ip = input_field.get()
    try:
        start_port = int(start_port_field.get())
        end_port = int(end_port_field.get())
        protocol = protocol_field.get()

        # Validate IP format
        socket.inet_aton(ip)

        result_label.config(text=f"Valid IP: {ip}", foreground="green")
        threading.Thread(target=scan_ports, args=(ip, start_port, end_port, protocol)).start()
    except socket.error:
        result_label.config(text="Invalid IP address", foreground="red")
    except ValueError:
        result_label.config(text="Invalid port range", foreground="red")

# GUI Setup
root = Tk()
root.title("Port Scanner with Shodan Integration")
root.geometry("800x600")
root.configure(bg="#333")

# Create input fields and buttons
label = ttk.Label(root, text="Enter IP address", font=("Arial", 12))
label.pack(pady=5)

input_field = ttk.Entry(root, font=("Arial", 12))
input_field.pack(pady=5)

start_port_label = ttk.Label(root, text="Start Port", font=("Arial", 12))
start_port_label.pack(pady=5)
start_port_field = ttk.Entry(root, font=("Arial", 12))
start_port_field.pack(pady=5)

end_port_label = ttk.Label(root, text="End Port", font=("Arial", 12))
end_port_label.pack(pady=5)
end_port_field = ttk.Entry(root, font=("Arial", 12))
end_port_field.pack(pady=5)

protocol_label = ttk.Label(root, text="Protocol", font=("Arial", 12))
protocol_label.pack(pady=5)
protocol_field = ttk.Combobox(root, values=["TCP", "UDP"], state="readonly", font=("Arial", 12))
protocol_field.set("TCP")
protocol_field.pack(pady=5)

submit_button = ttk.Button(root, text="Start Scan", command=validate_ip, style="TButton")
submit_button.pack(pady=20)

result_label = ttk.Label(root, text="", font=("Arial", 12))
result_label.pack(pady=5)

# Create treeview for results
tree = ttk.Treeview(root, columns=("Port", "Service", "Protocol", "Vulnerabilities"), show="headings")
tree.heading("Port", text="Port")
tree.heading("Service", text="Service")
tree.heading("Protocol", text="Protocol")
tree.heading("Vulnerabilities", text="Vulnerabilities")
tree.column("Port", width=100)
tree.column("Service", width=200)
tree.column("Protocol", width=100)
tree.column("Vulnerabilities", width=250)
tree.pack(pady=20)

port_result_label = ttk.Label(root, text="", font=("Arial", 12))
port_result_label.pack(pady=10)

# Run the GUI main loop
root.mainloop()
