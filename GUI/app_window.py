import customtkinter as ctk
import subprocess
import os
from pathlib import Path
from modules import hash_generator

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
        ctk.CTkButton(self.sidebar, text="TOTP Generator", width=180, command=self.run_totp_tool).pack(pady=5)

        ctk.CTkLabel(self.sidebar, text="Theme:", anchor="w").pack(pady=(30, 5), padx=10)
        self.mode_option = ctk.CTkOptionMenu(self.sidebar, values=["Light", "Dark", "System"], command=self.change_theme)
        self.mode_option.set("Dark")
        self.mode_option.pack(padx=10)

    def create_default_main_content(self):
        for widget in self.main_content.winfo_children():
            widget.destroy()
        self.content_label = ctk.CTkLabel(self.main_content, text="Select a tool from the sidebar", font=("Helvetica", 18))
        self.content_label.place(relx=0.5, rely=0.5, anchor="center")

    #  Hash generator button
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
        from modules import pwd_analyzer
        pwd_analyzer.run_main()

    def run_totp_tool(self):
        totp_path = Path("modules/TOTP/otpapp.py")
        if totp_path.exists():
            subprocess.run(["python", str(totp_path)])
        else:
            self.show_error("TOTP module not found.")

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