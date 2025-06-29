import customtkinter as ctk
import subprocess
import os
from pathlib import Path
from modules import hash_generator, pwd_analyzer, totp_generator
import qrcode
from customtkinter import CTkImage
from PIL import Image
import io
import threading
import time

# Set theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class CybrixToolsApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CybrixTools - Cybersecurity Toolkit")
        self.geometry("1000x600")
        self.resizable(True, True)
        self.fullscreen = False

        # Grid layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="ns")

        # Main content
        self.main_content = ctk.CTkFrame(self, corner_radius=10)
        self.main_content.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        self.create_sidebar()
        self.create_default_main_content()

        # Bind F11 to toggle fullscreen
        self.bind("<F11>", self.toggle_fullscreen)
        self.bind("<Escape>", self.exit_fullscreen)

    def create_sidebar(self):
        ctk.CTkLabel(self.sidebar, text="CybrixTools", font=("Helvetica", 20, "bold")).pack(pady=(20, 10))

        ctk.CTkButton(self.sidebar, text="Hash Generator", width=180, command=self.run_hash_generator).pack(pady=5)
        ctk.CTkButton(self.sidebar, text="Password Analyzer", width=180, command=self.run_password_analyzer).pack(pady=5)
        ctk.CTkButton(self.sidebar, text="TOTP Generator", width=180, command=self.run_totp_generator).pack(pady=5)

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
        for widget in self.main_content.winfo_children():
            widget.destroy()

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
        for widget in self.main_content.winfo_children():
            widget.destroy()

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
        for widget in self.main_content.winfo_children():
            widget.destroy()

        secret = totp_generator.load_secret()
        if not secret:
            secret = totp_generator.generate_secret()
            uri = totp_generator.get_provisioning_uri(secret)
            qr_img = qrcode.make(uri)
            with io.BytesIO() as output:
                qr_img.save(output, format="PNG")
                image_data = output.getvalue()
            image = Image.open(io.BytesIO(image_data))
            resized_image = Image.open(io.BytesIO(image_data)).resize((200, 200))
            photo = CTkImage(light_image=resized_image, dark_image=resized_image, size=(200, 200))
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

    def show_error(self, message):
        for widget in self.main_content.winfo_children():
            widget.destroy()
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
