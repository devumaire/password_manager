import tkinter as tk
from cryptography.fernet import Fernet
import base64
import os
import string
import random

class PasswordManagerApp:


#file path


    def __init__(self):
        self.key_file = os.path.join(os.path.dirname(__file__), "key.key")
        self.load_or_generate_key()

        self.cipher_suite = Fernet(self.key)
        self.password_file = os.path.join(os.path.dirname(__file__), "password.txt")
        self.windows = []

        self.root = tk.Tk()
        self.root.geometry("400x400")
        self.root.title("Password Manager")
        self.root.config(bg="#264E86")

        self.create_main_buttons()


    def create_invalid_input_window(self, message):
        invalid_input_window = self.create_base_window("Invalid Input", "200x100")
        invalid_label = self.create_label(invalid_input_window, message, 0, 0)

        quit_button = tk.Button(invalid_input_window, text="Quit", command=lambda: self.close_window(invalid_input_window), bg="#Afffff", height=1, width=7)
        quit_button.grid(row=1, column=0, pady=10, padx=20)


    def load_or_generate_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as key_file:
                self.key = key_file.read()
        else:
            self.key = Fernet.generate_key()
            with open(self.key_file, "wb") as key_file:
                key_file.write(self.key)

    def open_window(self, window_type):
        for window in self.windows:
            if window.winfo_exists():
                return

        if window_type == "save":
            self.save_password_window()
        elif window_type == "retrieve":
            self.retrieve_password_window()
        elif window_type == "update":
            self.update_password_window()
        elif window_type == "quit":
            self.root.destroy()
# generate password 

    def generate_password(self, password_entry):
        password_length = 6
        characters = string.ascii_letters + string.digits + string.punctuation
        generated_password = ''.join(random.choice(characters) for _ in range(password_length))
        password_entry.delete(0, 'end')
        password_entry.insert(0, generated_password)
#  main gui for password manager 


    def create_main_buttons(self):
        button_padding = 18
        welcome_label = tk.Label(self.root, text="Welcome to Password Manager", bg="#264E86", fg="white", font=('Times New Roman', 20))
        welcome_label.pack()

        buttons = [
            ("Save Password", "save"),
            ("Retrieve Password", "retrieve"),
            ("Update Password", "update"),
            ("Quit", "quit")
        ]

        for button_text, command in buttons:
            button = tk.Button(self.root, text=button_text, command=lambda cmd=command: self.open_window(cmd), width=20, height=2, bg="#Afffff")
            button.pack(pady=button_padding)

        self.root.mainloop()

    def create_entry(self, window, row, column, pady=10, padx=10, show=None, readonly=False):
        entry = tk.Entry(window, show=show) if show else tk.Entry(window)
        entry.grid(row=row, column=column, pady=pady, padx=padx)
        if readonly:
            entry.config(state='readonly')
        return entry

    def create_label(self, window, text, row, column):
        label = tk.Label(window, text=text, width=20, height=2, fg="#Afffff", font=("Helvetica", "13"), bg="#264E86", padx=7, pady=7)
        label.grid(row=row, column=column)
        return label
    



#save password gui






    def save_password_window(self):
        save_password_window = self.create_base_window("Save Password", "350x250")
        labels = ["App Name:", "Username:", "Password:"]
        entries = [self.create_entry(save_password_window, i, 1, 10, 10, show="*") if i == 2 else self.create_entry(save_password_window, i, 1, 10, 10) for i in range(3)]

        for i, label_text in enumerate(labels):
            self.create_label(save_password_window, label_text, i, 0)

        self.create_show_password_checkbox(save_password_window, entries[2])
        self.create_generate_password_button(save_password_window, entries[2])
        self.create_save_button(save_password_window, entries[0], entries[1], entries[2])

    def create_show_password_checkbox(self, window, password_entry):
        show_password_var = tk.BooleanVar()
        show_password_checkbox = tk.Checkbutton(window, bg="#Afffff", text="Show Password", variable=show_password_var, command=lambda: self.toggle_password_visibility(password_entry, show_password_var))
        show_password_checkbox.grid(row=3, column=0, pady=5)

    def create_generate_password_button(self, window, password_entry):
        generate_password_button = tk.Button(window, text="Generate Password", bg="#Afffff", command=lambda: self.generate_password(password_entry))
        generate_password_button.grid(row=3, column=1)

    def create_save_button(self, window, app_name_entry, username_entry, password_entry):
        save_button = tk.Button(window, text="Save", bg="#Afffff", command=lambda: self.save_password(app_name_entry, username_entry, password_entry, window))
        save_button.grid(row=4, column=1, pady=10, padx=20)

        back_button = tk.Button(window, text="Back", command=lambda: self.close_window(window), bg="#Afffff", height=1, width=7)
        back_button.grid(row=4, column=0)

    def create_base_window(self, title, geometry):
        base_window = tk.Toplevel(self.root)
        self.windows.append(base_window)
        base_window.title(title)
        base_window.geometry(geometry)
        base_window.config(bg="#264E86")
        return base_window
    
    
#checkbox visibility
    def toggle_password_visibility(self, password_entry, show_password_var):
        if show_password_var.get():
            password_entry.config(show="")
        else:
            password_entry.config(show="*")
#retreive pssword 
    def retrieve_password_window(self):
        retrieve_password_window = self.create_base_window("Retrieve Password", "350x200")
        labels = ["App Name:", "Username:", "Your Password:"]
        entries = [self.create_entry(retrieve_password_window, i, 1, 10, 10, readonly=(i == 2)) for i in range(3)]

        for i, label_text in enumerate(labels):
            self.create_label(retrieve_password_window, label_text, i, 0)

        self.create_retrieve_button(retrieve_password_window, entries[0], entries[1], entries[2])

    def create_retrieve_button(self, window, app_name_entry, username_entry, password_entry):
        retrieve_button = tk.Button(window, text="Retrieve", bg="#Afffff", command=lambda: self.retrieve_password(app_name_entry, username_entry, password_entry))
        retrieve_button.grid(row=3, column=1)

        back_button = tk.Button(window, text="Back", command=lambda: self.close_window(window), bg="#Afffff", height=1, width=7)
        back_button.grid(row=3, column=0)
#update password 


    def update_password_window(self):
        update_password_window = self.create_base_window("Update Password", "400x300")
        labels = ["App Name:", "Username:", "Old Password:", "New Password:"]
        entries = [self.create_entry(update_password_window, i, 1, 10, 10, show="*") if i in [3] else self.create_entry(update_password_window, i, 1, 10, 10) for i in range(4)]

        for i, label_text in enumerate(labels):
            self.create_label(update_password_window, label_text, i, 0)

        self.create_show_new_password_checkbox(update_password_window, entries[3])
        self.create_generate_new_password_button(update_password_window, entries[3])
        self.create_update_button(update_password_window, entries[0], entries[1], entries[2], entries[3])

    def create_show_new_password_checkbox(self, window, password_entry):
        show_new_password_var = tk.BooleanVar()
        show_new_password_checkbox = tk.Checkbutton(window, text="Show New Password", bg="#Afffff", variable=show_new_password_var, command=lambda: self.toggle_password_visibility(password_entry, show_new_password_var))
        show_new_password_checkbox.grid(row=4, column=0, pady=5)

    def create_generate_new_password_button(self, window, password_entry):
        generate_new_password_button = tk.Button(window, text="Generate New Password", bg="#Afffff", command=lambda: self.generate_password(password_entry))
        generate_new_password_button.grid(row=4, column=1)

    def create_update_button(self, window, app_name_entry, username_entry, old_password_entry, new_password_entry):
        update_button = tk.Button(window, text="Update", bg="#Afffff", height=1, width=7, command=lambda: self.update_password(app_name_entry, username_entry, old_password_entry, new_password_entry, window))
        update_button.grid(row=8, column=1)

        back_button = tk.Button(window, text="Back", command=lambda: self.close_window(window), bg="#Afffff", height=1, width=7)
        back_button.grid(row=8, column=0)

    def save_password(self, app_name_entry, username_entry, password_entry, window):
        app_name = app_name_entry.get()
        username = username_entry.get()
        password = password_entry.get()

        if app_name and username and password:
            encrypted_password = base64.b64encode(self.cipher_suite.encrypt(password.encode())).decode()

            with open(self.password_file, "a") as file:
                file.write(f"{app_name},{username},{encrypted_password}\n")

            app_name_entry.delete(0, 'end')
            username_entry.delete(0, 'end')
            password_entry.delete(0, 'end')

            self.close_window(window)
        else:
            self.show_fill_label_window("Please fill in all fields")






#retreive passowrd gui


    def retrieve_password(self, app_name_entry, username_entry, password_entry):
        app_name = app_name_entry.get()
        username = username_entry.get()

        if app_name and username:
            with open(self.password_file, "r") as file:
                for line in file:
                    saved_app_name, saved_username, saved_password = line.strip().split(',')
                    if app_name == saved_app_name and username == saved_username:
                        try:
                            decoded_password = base64.b64decode(saved_password.encode())
                            decrypted_password = self.cipher_suite.decrypt(decoded_password).decode()
                            password_entry.config(state='normal')
                            password_entry.delete(0, 'end')
                            password_entry.insert(0, decrypted_password)
                            return
                        except Exception as e:
                            self.show_info_message("Error decrypting the password")
                            return
            self.show_info_message("Password not found")
        else:
            self.show_fill_label_window("Please fill in all fields")




#update password gui



    def update_password(self, app_name_entry, username_entry, old_password_entry, new_password_entry, window):
        app_name = app_name_entry.get()
        username = username_entry.get()
        old_password = old_password_entry.get()
        new_password = new_password_entry.get()

        if app_name and username and old_password and new_password:
            with open(self.password_file, "r") as file:
                lines = file.readlines()

            found = False
            for i, line in enumerate(lines):
                saved_app_name, saved_username, saved_password = line.strip().split(',')
                if app_name == saved_app_name and username == saved_username:
                    try:
                        decoded_password = base64.b64decode(saved_password.encode())
                        decrypted_password = self.cipher_suite.decrypt(decoded_password).decode()

                        if old_password == decrypted_password:
                            found = True
                            encrypted_new_password = base64.b64encode(self.cipher_suite.encrypt(new_password.encode())).decode()
                            lines[i] = f"{app_name},{username},{encrypted_new_password}\n"
                            break
                        else:
                            self.show_fill_label_window("Old Password is incorrect")
                            return
                    except Exception as e:
                        self.show_fill_label_window("Error decrypting the password")
                        return

            if found:
                with open(self.password_file, "w") as file:
                    file.writelines(lines)

                app_name_entry.delete(0, 'end')
                username_entry.delete(0, 'end')
                old_password_entry.delete(0, 'end')
                new_password_entry.delete(0, 'end')

                self.close_window(window)
            else:
                self.show_fill_label_window("App Name or Username not found")
        else:
            self.show_fill_label_window("Please fill in all fields")

    def show_fill_label_window(self, message):
        fill_label_window = self.create_base_window("Info", "250x100")
        fill_label = self.create_label(fill_label_window, message, 0, 0)

        quit_button = tk.Button(fill_label_window, text="Quit", command=fill_label_window.destroy, bg="#Afffff", height=1, width=7)
        quit_button.grid(row=1, column=0, pady=10, padx=20)

    def show_info_message(self, message):
        tk.messagebox.showinfo("Info", message)

    def close_window(self, window):
        self.windows.remove(window)
        window.destroy()

if __name__ == "__main__":
    app = PasswordManagerApp()
    
