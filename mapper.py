import tkinter as tk
from tkinter import messagebox
import threading
import socket
import concurrent.futures

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")

        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        self.root.geometry(f"{screen_width}x{screen_height}")
        self.root.configure(bg='black')

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_rowconfigure(3, weight=1)
        self.root.grid_rowconfigure(4, weight=1)
        self.root.grid_rowconfigure(5, weight=1)
        self.root.grid_rowconfigure(6, weight=1)
        self.root.grid_rowconfigure(7, weight=1)
        self.root.grid_rowconfigure(8, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        self.host_label = tk.Label(root, text="Host:", bg='black', fg='green')
        self.host_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.host_entry = tk.Entry(root, width=50, bg='black', fg='green')
        self.host_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        self.scan_type_var = tk.StringVar(value="all")
        self.scan_all_radiobutton = tk.Radiobutton(root, text="Scan All Ports", variable=self.scan_type_var, value="all", command=self.update_scan_type, bg='black', fg='green', selectcolor='black')
        self.scan_all_radiobutton.grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.scan_specific_radiobutton = tk.Radiobutton(root, text="Scan Specific Ports", variable=self.scan_type_var, value="specific", command=self.update_scan_type, bg='black', fg='green', selectcolor='black')
        self.scan_specific_radiobutton.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        self.port_range_frame = tk.Frame(root, bg='black')
        self.port_range_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky=tk.N)

        self.start_port_label = tk.Label(self.port_range_frame, text="Start Port:", bg='black', fg='green')
        self.start_port_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.start_port_entry = tk.Entry(self.port_range_frame, width=10, bg='black', fg='green')
        self.start_port_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        self.end_port_label = tk.Label(self.port_range_frame, text="End Port:", bg='black', fg='green')
        self.end_port_label.grid(row=0, column=2, padx=5, pady=5, sticky=tk.E)
        self.end_port_entry = tk.Entry(self.port_range_frame, width=10, bg='black', fg='green')
        self.end_port_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)

        self.specific_ports_label = tk.Label(root, text="Specific Ports (Comma-separated):", bg='black', fg='green')
        self.specific_ports_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        self.specific_ports_entry = tk.Entry(root, width=50, bg='black', fg='green')

        self.output_label = tk.Label(root, text="Output File:", bg='black', fg='green')
        self.output_label.grid(row=4, column=0, padx=5, pady=5, sticky=tk.E)
        self.output_entry = tk.Entry(root, width=50, bg='black', fg='green')
        self.output_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)

        self.version_check_var = tk.IntVar()
        self.version_check_button = tk.Checkbutton(root, text="Service Version Detection", variable=self.version_check_var, bg='black', fg='green', selectcolor='black')
        self.version_check_button.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky=tk.N)

        self.scan_button = tk.Button(root, text="Scan", command=self.start_scan, bg='black', fg='green')
        self.scan_button.grid(row=6, column=0, columnspan=2, padx=5, pady=5, sticky=tk.N)

        self.result_text = tk.Text(root, height=20, width=100, bg='black', fg='green')
        self.result_text.grid(row=7, column=0, columnspan=2, padx=5, pady=5, sticky=tk.N)

        self.scan_thread = None
        self.update_scan_type()

    def update_scan_type(self):
        scan_type = self.scan_type_var.get()
        if scan_type == "all":
            self.port_range_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky=tk.N)
            self.specific_ports_label.grid_forget()
            self.specific_ports_entry.grid_forget()
        elif scan_type == "specific":
            self.port_range_frame.grid_forget()
            self.specific_ports_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
            self.specific_ports_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)

    def start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan in Progress", "A scan is already in progress.")
            return

        host = self.host_entry.get()
        
        if not host:
            messagebox.showerror("Error", "Enter the host")
            return
        
        try:
            socket.gethostbyname(host)
            socket.gethostbyaddr(host)
        except socket.error:
            messagebox.showerror("Error", "Cannot resolve or connect to the host")
            return

        scan_type = self.scan_type_var.get()
        ports_to_scan = []

        if scan_type == "all":
            try:
                start_port = int(self.start_port_entry.get())
                end_port = int(self.end_port_entry.get())
                if start_port < 0:
                    start_port = 0
                if end_port > 65535:
                    end_port = 65535
                if start_port > end_port:
                    start_port, end_port = end_port, start_port
                ports_to_scan = range(start_port, end_port + 1)
            except ValueError:
                messagebox.showerror("Error", "Please enter valid integers for port range")
                return

        elif scan_type == "specific":
            try:
                specific_ports = self.specific_ports_entry.get().split(",")
                specific_ports = [int(port.strip()) for port in specific_ports if port.strip()]
                if not specific_ports:
                    messagebox.showerror("Error", "Please provide at least one specific port.")
                    return
                ports_to_scan = specific_ports
            except ValueError:
                messagebox.showerror("Error", "Please enter valid integers for specific ports")
                return
        else:
            messagebox.showerror("Error", "Invalid scan type.")
            return

        output_file = self.output_entry.get()
        if output_file and not output_file.endswith(".txt"):
            messagebox.showerror("Error", "Invalid output file extension. Please use a .txt file.")
            return

        self.result_text.delete("1.0", tk.END)  
        self.result_text.insert(tk.END, "Scanning in progress...\n") 

        self.scan_thread = threading.Thread(target=self.scan_ports, args=(host, ports_to_scan, output_file))
        self.scan_thread.start()

    def scan_ports(self, host, ports, output_file):
        segment_size = 100  
        open_ports = []

        with concurrent.futures.ThreadPoolExecutor() as executor:
            segment_count = len(ports) // segment_size
            if len(ports) % segment_size != 0:
                segment_count += 1

            for i in range(segment_count):
                start = i * segment_size
                end = (i + 1) * segment_size
                segment_ports = ports[start:end]

                futures = [executor.submit(self.check_port, host, port) for port in segment_ports]

                for future in concurrent.futures.as_completed(futures):
                    port, result = future.result()
                    if result == 0:
                        self.result_text.insert(tk.END, f"Port {port} is open\n")
                        open_ports.append(port)

        if open_ports:
            pass
        else:
            self.result_text.insert(tk.END, "No open ports found.\n")

        if self.version_check_var.get() == 1:
            self.result_text.insert(tk.END, "\nPerforming Service Version Detection...\n")
            self.perform_service_version_detection(host, open_ports)

        if output_file:
            self.save_output(output_file)
                
        self.result_text.insert(tk.END, "\nScanning finished\n")
        self.result_text.see(tk.END)

    def check_port(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            return port, result
        except socket.error as e:
            return port, None

    def perform_service_version_detection(self, host, open_ports):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_port = {executor.submit(self.detect_service_version, host, port): port for port in open_ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    service_version = future.result()
                    self.result_text.insert(tk.END, f"Port {port}: {service_version}\n")
                except Exception as exc:
                    self.result_text.insert(tk.END, f"Port {port}: Error occurred during service version detection\n {str(exc)}")

    def detect_service_version(self, host, port):
        try:
            service_version = "Unknown"
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                sock.connect((host, port))
                sock.sendall(b"GET / HTTP/1.1\r\n\r\n")
                response = sock.recv(1024)
                if response:
                    service_version = response.decode().splitlines()[0]
            return service_version
        except socket.error:
            return "Unknown"

    def save_output(self, filename):
        try:
            with open(filename, 'w') as file:
                file.write(self.result_text.get("1.0", tk.END))
            messagebox.showinfo("Success", f"Output saved to {filename}.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while saving the output: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    port_scanner = PortScannerGUI(root)
    root.mainloop()
