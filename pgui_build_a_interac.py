import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import random

class SecurityToolSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("Interactive Security Tool Simulator")
        self.root.geometry("800x600")

        # Create notebook for different simulation scenarios
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=1, fill="both")

        # Create frames for each scenario
        self.frame_password_cracking = ttk.Frame(self.notebook)
        self.frame_port_scanning = ttk.Frame(self.notebook)
        self.frame_firewall_configuration = ttk.Frame(self.notebook)

        # Add frames to notebook
        self.notebook.add(self.frame_password_cracking, text="Password Cracking")
        self.notebook.add(self.frame_port_scanning, text="Port Scanning")
        self.notebook.add(self.frame_firewall_configuration, text="Firewall Configuration")

        # Create widgets for password cracking scenario
        self.label_password = ttk.Label(self.frame_password_cracking, text="Enter password:")
        self.label_password.pack()

        self.entry_password = ttk.Entry(self.frame_password_cracking, show="*")
        self.entry_password.pack()

        self.button_crack_password = ttk.Button(self.frame_password_cracking, text="Crack Password", command=self.crack_password)
        self.button_crack_password.pack()

        # Create widgets for port scanning scenario
        self.label_port_range = ttk.Label(self.frame_port_scanning, text="Enter port range (e.g., 1-100):")
        self.label_port_range.pack()

        self.entry_port_range = ttk.Entry(self.frame_port_scanning)
        self.entry_port_range.pack()

        self.button_scan_ports = ttk.Button(self.frame_port_scanning, text="Scan Ports", command=self.scan_ports)
        self.button_scan_ports.pack()

        # Create widgets for firewall configuration scenario
        self.label_firewall_rule = ttk.Label(self.frame_firewall_configuration, text="Enter firewall rule (e.g., allow/deny, protocol, port):")
        self.label_firewall_rule.pack()

        self.entry_firewall_rule = ttk.Entry(self.frame_firewall_configuration)
        self.entry_firewall_rule.pack()

        self.button_configure_firewall = ttk.Button(self.frame_firewall_configuration, text="Configure Firewall", command=self.configure_firewall)
        self.button_configure_firewall.pack()

    def crack_password(self):
        password = self.entry_password.get()
        if len(password) < 8:
            messagebox.showerror("Error", "Password is too weak!")
        else:
            messagebox.showinfo("Success", "Password is strong!")

    def scan_ports(self):
        port_range = self.entry_port_range.get()
        ports = [i for i in range(int(port_range.split("-")[0]), int(port_range.split("-")[1]) + 1)]
        open_ports = random.sample(ports, random.randint(1, len(ports)))
        messagebox.showinfo("Scan Results", "Open ports: " + ", ".join(map(str, open_ports)))

    def configure_firewall(self):
        firewall_rule = self.entry_firewall_rule.get()
        if "allow" in firewall_rule and "tcp" in firewall_rule and "80" in firewall_rule:
            messagebox.showinfo("Success", "Firewall configured successfully!")
        else:
            messagebox.showerror("Error", "Invalid firewall rule!")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityToolSimulator(root)
    root.mainloop()