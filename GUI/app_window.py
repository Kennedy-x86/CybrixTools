import customtkinter as ctk
from modules import hash_generator, pwd_analyzer, totp_generator, port_scanner
import qrcode
from PIL import Image
from customtkinter import CTkImage
import tkinter as tk
import io
import threading
import time
import socket

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class CybrixToolsApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CybrixTools - Cybersecurity Toolkit")
        self.geometry("1000x600")
        self.resizable(True, True)
        self.fullscreen = False

        self.tool_placeholders = {
            'OSINT Lookup': 'Tool coming soon...',
            'Encryption/Decryption': 'Tool coming soon...',
            'HTTP Header Analyzer': 'Tool coming soon...',
            'DNS Lookup': 'Tool coming soon...',
            'Hash Comparison Tool': 'Tool coming soon...',
            'Keylogger (Demo)': 'Tool coming soon...'
        }

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="ns")

        self.main_content = ctk.CTkFrame(self, corner_radius=10)
        self.main_content.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        self.create_sidebar()
        self.create_default_main_content()

        self.bind("<F11>", self.toggle_fullscreen)
        self.bind("<Escape>", self.exit_fullscreen)

    def create_sidebar(self):
        ctk.CTkLabel(self.sidebar, text="CybrixTools", font=("Helvetica", 20, "bold")).pack(pady=(20, 10))

        ctk.CTkButton(self.sidebar, text="Hash Generator", width=180, command=self.run_hash_generator).pack(pady=5)
        ctk.CTkButton(self.sidebar, text="Password Analyzer", width=180, command=self.run_password_analyzer).pack(pady=5)
        ctk.CTkButton(self.sidebar, text="TOTP Generator", width=180, command=self.run_totp_generator).pack(pady=5)
        ctk.CTkButton(self.sidebar, text="Port Scanner", width=180, command=self.run_port_scanner).pack(pady=5)
        ctk.CTkButton(self.sidebar,text="Phishing Detector", width=180, command=self.run_phishing_detector).pack(pady=5)

        for tool_name in self.tool_placeholders:
            ctk.CTkButton(self.sidebar, text=tool_name, width=180,
                         command=lambda name=tool_name: self.load_tool_placeholder(name)).pack(pady=5)

        ctk.CTkLabel(self.sidebar, text="Theme:", anchor="w").pack(pady=(30, 5), padx=10)
        self.mode_option = ctk.CTkOptionMenu(self.sidebar, values=["Light", "Dark", "System"], command=self.change_theme)
        self.mode_option.set("Dark")
        self.mode_option.pack(padx=10)

    def create_default_main_content(self):
        for widget in self.main_content.winfo_children():
            widget.destroy()
        self.content_label = ctk.CTkLabel(self.main_content, text="Select a tool from the sidebar", font=("Helvetica", 18))
        self.content_label.place(relx=0.5, rely=0.5, anchor="center")

    def run_hash_generator(self):
        self.clear_main_content()
        ctk.CTkLabel(self.main_content, text="Hash Generator", font=("Helvetica", 20, "bold")).pack(pady=10)
        entry = ctk.CTkEntry(self.main_content, width=400, placeholder_text="Enter text to hash")
        entry.pack(pady=10)

        result_box = ctk.CTkTextbox(self.main_content, height=120, width=600)
        result_box.pack(pady=10)

        def generate():
            text = entry.get()
            hashes = hash_generator.generate_hash(text)
            result_box.delete("1.0", "end")
            for algo, h in hashes.items():
                result_box.insert("end", f"{algo}: {h}\n")

        ctk.CTkButton(self.main_content, text="Generate Hash", command=generate).pack(pady=5)

    def run_password_analyzer(self):
        self.clear_main_content()
        ctk.CTkLabel(self.main_content, text="Password Strength Analyzer", font=("Helvetica", 20, "bold")).pack(pady=10)
        entry = ctk.CTkEntry(self.main_content, width=400, placeholder_text="Enter your password", show="*")
        entry.pack(pady=10)

        score_label = ctk.CTkLabel(self.main_content, text="", font=("Helvetica", 16))
        score_label.pack(pady=10)

        feedback_box = ctk.CTkTextbox(self.main_content, height=150, width=600)
        feedback_box.pack(pady=10)

        def analyze():
            password = entry.get()
            score, feedback = pwd_analyzer.check_password_strength(password)
            score_label.configure(text=f"Password Strength Score: {score}/10")
            feedback_box.delete("1.0", "end")
            for msg in feedback:
                feedback_box.insert("end", f"- {msg}\n")

        ctk.CTkButton(self.main_content, text="Analyze Password", command=analyze).pack(pady=5)

    def run_totp_generator(self):
        self.clear_main_content()
        secret = totp_generator.load_secret()
        if not secret:
            secret = totp_generator.generate_secret()
            uri = totp_generator.get_provisioning_uri(secret)
            qr_img = qrcode.make(uri)
            with io.BytesIO() as output:
                qr_img.save(output, format="PNG")
                image_data = output.getvalue()
            image = Image.open(io.BytesIO(image_data)).resize((200, 200))
            photo = CTkImage(light_image=image, dark_image=image, size=(200, 200))
            img_label = ctk.CTkLabel(self.main_content, image=photo, text="")
            img_label.pack(pady=10)

        code_label = ctk.CTkLabel(self.main_content, text="", font=("Helvetica", 30, "bold"))
        code_label.pack(pady=20)

        def update_code():
            while True:
                code = totp_generator.get_totp_code(secret)
                code_label.configure(text=f"Current Code: {code}")
                time.sleep(30)

        threading.Thread(target=update_code, daemon=True).start()

        reset_button = ctk.CTkButton(self.main_content, text="Reset TOTP Secret", command=self.reset_totp_secret)
        reset_button.pack(pady=10)

    def reset_totp_secret(self):
        if totp_generator.SECRET_FILE.exists():
            totp_generator.SECRET_FILE.unlink()
            self.show_error("TOTP secret has been reset. Click 'TOTP Generator' to set up a new one.")

    def run_port_scanner(self):
        self.clear_main_content()
        ctk.CTkLabel(self.main_content, text="Port Scanner", font=("Helvetica", 20, "bold")).pack(pady=10)

        ip_mode = tk.StringVar(value="own")
        ctk.CTkRadioButton(self.main_content, text="Scan my own IP", variable=ip_mode, value="own").pack(anchor="w",
                                                                                                         padx=20)
        ctk.CTkRadioButton(self.main_content, text="Enter IP or hostname", variable=ip_mode, value="custom").pack(
            anchor="w", padx=20)

        ip_entry = ctk.CTkEntry(self.main_content, width=300, placeholder_text="Enter IP or hostname")
        ip_entry.pack(pady=5)

        port_mode = tk.StringVar(value="default")
        ctk.CTkRadioButton(self.main_content, text="Default port range (0–1023)", variable=port_mode,
                           value="default").pack(anchor="w", padx=20)
        ctk.CTkRadioButton(self.main_content, text="Specify port range", variable=port_mode, value="custom").pack(
            anchor="w", padx=20)

        start_entry = ctk.CTkEntry(self.main_content, width=150, placeholder_text="Start Port")
        start_entry.pack(pady=5)
        end_entry = ctk.CTkEntry(self.main_content, width=150, placeholder_text="End Port")
        end_entry.pack(pady=5)

        result_box = ctk.CTkTextbox(self.main_content, height=200, width=600)
        result_box.pack(pady=10)

        progress_label = ctk.CTkLabel(self.main_content, text="")
        progress_label.pack(pady=2)
        progress_bar = ctk.CTkProgressBar(self.main_content, width=400)
        progress_bar.pack(pady=5)
        progress_bar.set(0)

        def scan():
            result_box.delete("1.0", "end")
            progress_bar.set(0)
            progress_label.configure(text="")

            if ip_mode.get() == "own":
                ip = socket.gethostbyname(socket.gethostname())
            else:
                ip_input = ip_entry.get().strip()
                if not ip_input:
                    result_box.insert("end", "Error: Enter a valid IP or hostname.\n")
                    return
                try:
                    ip = socket.gethostbyname(ip_input)
                except socket.gaierror:
                    result_box.insert("end", "Error: Invalid hostname.\n")
                    return

            if port_mode.get() == "default":
                start_port, end_port = 0, 1023
            else:
                try:
                    start_port = int(start_entry.get().strip())
                    end_port = int(end_entry.get().strip())
                    if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port):
                        raise ValueError
                except ValueError:
                    result_box.insert("end", "Error: Invalid port range.\n")
                    return

            result_box.insert("end", f"Scanning {ip} from port {start_port} to {end_port}...\n")
            total_ports = end_port - start_port + 1
            completed_ports = [0]  # using a mutable object so threads can update it
            open_ports = []
            lock = threading.Lock()

            def scan_and_update(port):
                if port_scanner.scan_port(ip, port):
                    with lock:
                        open_ports.append(port)
                with lock:
                    completed_ports[0] += 1
                    progress = completed_ports[0] / total_ports
                    progress_bar.set(progress)
                    progress_label.configure(text=f"Scanning... {int(progress * 100)}%")
                    self.update_idletasks()

            def threaded_scan():
                threads = []
                for port in range(start_port, end_port + 1):
                    t = threading.Thread(target=scan_and_update, args=(port,))
                    threads.append(t)
                    t.start()

                for t in threads:
                    t.join()

                if open_ports:
                    result_box.insert("end", "\nOpen ports:\n")
                    for port in sorted(open_ports):
                        result_box.insert("end", f"- Port {port} is open\n")
                else:
                    result_box.insert("end", "\nNo open ports found.\n")

                progress_label.configure(text="Scan complete")

            threading.Thread(target=threaded_scan, daemon=True).start()
            
        ctk.CTkButton(self.main_content, text="Scan", command=scan).pack(pady=10)

#Phishing Detector
def run_phishing_detector(self):
    self.clear_main_content()
    ctk.CTkLabel (self.main_content, text="Phishing Email Detector", font=("Helvetica", 20, "bold")).pack(pady=10)

    entry = ctk.CTkTextbox(self.main_content, height=200, width=600)
    entry.pack(pady=10)
    entry.insert("1.0", "Enter email")

    result_box = ctk.CTkTextbox(self.main_content, height=150, width=600)
    result_box.pack(pady=10)

    def analyze():
        email = entry.get("1.0", "end")
        from modules import phishing_detector
        findings = phishing_detector.check_email(email)
        result_box.delete("1.0", "end")
        for finding in findings:
            result_box.insert("end", f" - {finding}\n")

    ctk.CTkButton(self.main_content, text="Analyze Email", command=analyze).pack(pady=5)

    def load_tool_placeholder(self, tool_name):
        self.clear_main_content()
        message = self.tool_placeholders.get(tool_name, "This tool is under development.")
        ctk.CTkLabel(self.main_content, text=tool_name, font=("Helvetica", 20, "bold")).pack(pady=20)
        ctk.CTkLabel(self.main_content, text=message, font=("Helvetica", 16)).pack(pady=10)

    def clear_main_content(self):
        for widget in self.main_content.winfo_children():
            widget.destroy()

    def show_error(self, message):
        self.clear_main_content()
        error_label = ctk.CTkLabel(self.main_content, text=message, text_color="red", font=("Helvetica", 16))
        error_label.place(relx=0.5, rely=0.5, anchor="center")

    def change_theme(self, mode):
        ctk.set_appearance_mode(mode)

    def toggle_fullscreen(self, event=None):
        self.fullscreen = not self.fullscreen
        self.attributes("-fullscreen", self.fullscreen)

    def exit_fullscreen(self, event=None):
        self.fullscreen = False
        self.attributes("-fullscreen", False)

if __name__ == "__main__":
    app = CybrixToolsApp()
    app.mainloop()
