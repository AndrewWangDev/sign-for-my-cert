import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from threading import Thread
import base64
import hashlib

class CertLiteApp(ttk.Window):
    def __init__(self):
        super().__init__(themename="lumen") # Material-like light theme
        self.title("CertLite - Windows Cert Generator")
        self.geometry("400x550")
        self.resizable(False, False)
        
        # Style configuration
        self.style.configure('TEntry', padding=(10, 5))
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=BOTH, expand=YES)
        
        # Card container (Simulated with Frame + Border/Bg)
        card = ttk.Labelframe(main_frame, text=" Certificate Details ", padding=20, bootstyle="primary")
        card.pack(fill=BOTH, expand=YES, pady=(10, 20))
        
        # 1. Domain Input
        ttk.Label(card, text="Domain / IP", bootstyle="primary").pack(anchor=W, pady=(0, 5))
        self.domain_var = tk.StringVar()
        self.domain_entry = ttk.Entry(card, textvariable=self.domain_var, width=40)
        self.domain_entry.pack(fill=X, pady=(0, 20))
        self.domain_entry.insert(0, "localhost")
        
        # 2. Path Selection
        ttk.Label(card, text="Save to", bootstyle="primary").pack(anchor=W, pady=(0, 5))
        path_frame = ttk.Frame(card)
        path_frame.pack(fill=X, pady=(0, 20))
        
        self.path_var = tk.StringVar(value=os.getcwd())
        self.path_entry = ttk.Entry(path_frame, textvariable=self.path_var, state="readonly")
        self.path_entry.pack(side=LEFT, fill=X, expand=YES, padx=(0, 5))
        
        btn_browse = ttk.Button(path_frame, text="📂", command=self.browse_folder, bootstyle="secondary-outline")
        btn_browse.pack(side=RIGHT)
        
        # 3. Algorithm Selection
        ttk.Label(card, text="Algorithm", bootstyle="primary").pack(anchor=W, pady=(0, 5))
        self.algo_var = tk.StringVar(value="SHA256")
        
        algo_frame = ttk.Frame(card)
        algo_frame.pack(fill=X, pady=(0, 20))
        
        ttk.Radiobutton(algo_frame, text="SHA256 (Default)", variable=self.algo_var, value="SHA256").pack(side=LEFT, padx=(0, 15))
        ttk.Radiobutton(algo_frame, text="SHA384", variable=self.algo_var, value="SHA384").pack(side=LEFT)
        
        # 4. Generate Button
        self.btn_generate = ttk.Button(
            self, 
            text="GENERATE CERTIFICATE", 
            command=self.start_generation, 
            bootstyle="success", 
            width=20
        )
        self.btn_generate.pack(fill=X, padx=40, pady=(0, 20), ipady=5)
        
        # Status Label
        self.status_label = ttk.Label(self, text="Ready", anchor=CENTER, foreground="gray")
        self.status_label.pack(fill=X, pady=(0, 10))

        # Output Text (Hidden initially)
        self.output_text = ttk.Text(self, height=5, state=DISABLED, font=("Consolas", 8))
        # self.output_text.pack(fill=X, padx=20, pady=(0,10)) # Uncomment if we want to show logs

        # Open Folder Link (Hidden initially)
        self.link_label = ttk.Label(
            self, 
            text="Open Destination Folder", 
            cursor="hand2", 
            bootstyle="primary"
        )
        self.link_label.bind("<Button-1>", lambda e: os.startfile(self.path_var.get()))

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.path_var.set(folder)

    def start_generation(self):
        domain = self.domain_var.get().strip()
        path = self.path_var.get()
        algo = self.algo_var.get()
        
        if not domain:
            self.show_toast("Error: Domain cannot be empty", "danger")
            return
            
        if not path:
             self.show_toast("Error: Path cannot be empty", "danger")
             return

        self.btn_generate.configure(state=DISABLED, text="Generating...")
        self.status_label.configure(text="Processing...", foreground="blue")
        
        # Run in thread to allow UI updates
        Thread(target=self.generate_process, args=(domain, path, algo)).start()

    def generate_process(self, domain, path, algo):
        try:
            # 1. Prepare command arguments based on algo
            days = "3650"
            digest = "-sha256" if algo == "SHA256" else "-sha384"
            
            # File names
            root_key = os.path.join(path, "rootCA.key")
            root_crt = os.path.join(path, "root_ca.crt")
            server_key = os.path.join(path, f"{domain}.key")
            server_csr = os.path.join(path, "server.csr")
            server_crt = os.path.join(path, f"{domain}.crt")
            server_ext = os.path.join(path, "server.ext")
            
            # Helper to run openssl
            def run_openssl(args):
                subprocess.run(["openssl"] + args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Step A: Generate CA Key
            run_openssl(["ecparam", "-genkey", "-name", "prime256v1", "-out", root_key])
            
            # Step B: Generate CA Cert (Self-signed)
            run_openssl(["req", "-x509", "-new", "-nodes", "-key", root_key, digest, "-days", "36500", 
                         "-out", root_crt, "-subj", "/C=CN/O=CertLite/CN=CertLite Root CA"])

            # Step C: Generate Server Key
            run_openssl(["ecparam", "-genkey", "-name", "prime256v1", "-out", server_key])
            
            # Step D: Create config file for SAN
            config_content = f"""authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = {domain}
DNS.2 = *.{domain}
"""
            with open(server_ext, "w") as f:
                f.write(config_content)
                
            # Step E: Generate CSR
            run_openssl(["req", "-new", "-key", server_key, "-out", server_csr,
                         "-subj", f"/C=CN/O=CertLite/CN={domain}"])
                         
            # Step F: Sign Server Cert
            run_openssl(["x509", "-req", "-in", server_csr, "-CA", root_crt, "-CAkey", root_key,
                         "-CAcreateserial", "-out", server_crt, "-days", days, digest, "-extfile", server_ext])
            
            # Cleanup
            for f in [root_key, server_csr, server_ext, os.path.join(path, "root_ca.srl")]:
                if os.path.exists(f):
                    try: 
                        os.remove(f)
                    except: pass # Optional cleanup
            
            # Step G: Calculate Hash (Verification) & UI Feedback
            with open(server_crt, "rb") as f:
                cert_bytes = f.read()
            
            # DER format is needed for correct hash if it was PEM (OpenSSL generates PEM by default with x509)
            # Actually OpenSSL default out is PEM. To follow the bash script exactly:
            # openssl x509 -in server.crt -outform DER | openssl dgst -sha256 -binary | openssl base64
            
            # We can do this in python:
            # 1. Load the cert (it's PEM)
            # 2. Convert to DER (using openssl or assume standard libraries, but we rely on openssl cli availability so let's stick to it or use python logic)
            # Let's use subprocess for the exact piped logic to be safe and consistent with previous script requirement
            
            cmd_pipe = f'openssl x509 -in "{server_crt}" -outform DER | openssl dgst -sha256 -binary | openssl base64'
            result = subprocess.run(cmd_pipe, shell=True, capture_output=True, text=True)
            fingerprint = result.stdout.strip()
            
            self.after(0, lambda: self.on_success(fingerprint))
            
        except subprocess.CalledProcessError as e:
            self.after(0, lambda: self.show_toast(f"OpenSSL Error: {e.stderr.decode() if e.stderr else 'Unknown'}", "danger"))
        except Exception as e:
            self.after(0, lambda: self.show_toast(f"Error: {str(e)}", "danger"))
        finally:
            self.after(0, self.reset_ui)

    def on_success(self, fingerprint):
        self.show_toast("Certificate Generated Successfully!", "success")
        self.status_label.configure(text=f"Fingerprint: {fingerprint}", foreground="green")
        self.link_label.pack(pady=10)

    def reset_ui(self):
        self.btn_generate.configure(state=NORMAL, text="GENERATE CERTIFICATE")

    def show_toast(self, message, type):
        # Using a label as a simple in-window toast or update status
        color = "green" if type == "success" else "red"
        self.status_label.configure(text=message, foreground=color)
        if type == "danger":
             self.link_label.pack_forget()

if __name__ == "__main__":
    app = CertLiteApp()
    app.mainloop()
