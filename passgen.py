import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import pyperclip
import json
import os
from datetime import datetime

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Password Generator")
        self.root.geometry("500x550")
        self.root.resizable(False, False)
        
        # Password history file
        self.history_file = "password_history.json"
        self.password_history = []
        self.load_history()
        
        # Style configuration
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('Header.TLabel', font=('Arial', 14, 'bold'))
        
        self.create_widgets()
    
    def load_history(self):
        if os.path.exists(self.history_file):
            with open(self.history_file, 'r') as f:
                self.password_history = json.load(f)
    
    def save_history(self):
        with open(self.history_file, 'w') as f:
            json.dump(self.password_history, f, indent=2)
    
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header = ttk.Label(main_frame, text="Advanced Password Generator", style='Header.TLabel')
        header.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Password length
        ttk.Label(main_frame, text="Password Length:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.length_var = tk.IntVar(value=12)
        self.length_slider = ttk.Scale(main_frame, from_=4, to=50, variable=self.length_var, 
                                      command=lambda e: self.update_length_label())
        self.length_slider.grid(row=1, column=1, sticky=tk.EW, padx=5)
        self.length_label = ttk.Label(main_frame, textvariable=self.length_var)
        self.length_label.grid(row=1, column=2, padx=5)
        
        # Character types
        ttk.Label(main_frame, text="Character Types:").grid(row=2, column=0, sticky=tk.W, pady=5)
        
        char_types_frame = ttk.Frame(main_frame)
        char_types_frame.grid(row=2, column=1, columnspan=2, sticky=tk.W)
        
        self.lower_var = tk.BooleanVar(value=True)
        self.upper_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(char_types_frame, text="Lowercase (a-z)", variable=self.lower_var).grid(row=0, column=0, sticky=tk.W)
        ttk.Checkbutton(char_types_frame, text="Uppercase (A-Z)", variable=self.upper_var).grid(row=1, column=0, sticky=tk.W)
        ttk.Checkbutton(char_types_frame, text="Digits (0-9)", variable=self.digits_var).grid(row=0, column=1, sticky=tk.W, padx=10)
        ttk.Checkbutton(char_types_frame, text="Symbols (!@#...)", variable=self.symbols_var).grid(row=1, column=1, sticky=tk.W, padx=10)
        
        # Password constraints
        ttk.Label(main_frame, text="Constraints:").grid(row=3, column=0, sticky=tk.W, pady=5)
        
        constraints_frame = ttk.Frame(main_frame)
        constraints_frame.grid(row=3, column=1, columnspan=2, sticky=tk.W)
        
        self.min_lower_var = tk.IntVar(value=1)
        self.min_upper_var = tk.IntVar(value=1)
        self.min_digits_var = tk.IntVar(value=1)
        self.min_symbols_var = tk.IntVar(value=1)
        self.no_duplicates_var = tk.BooleanVar(value=False)
        self.no_similar_var = tk.BooleanVar(value=True)
        self.no_sequential_var = tk.BooleanVar(value=True)
        
        ttk.Label(constraints_frame, text="Min lowercase:").grid(row=0, column=0, sticky=tk.W)
        ttk.Spinbox(constraints_frame, from_=0, to=10, width=3, textvariable=self.min_lower_var).grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(constraints_frame, text="Min uppercase:").grid(row=0, column=2, sticky=tk.W, padx=10)
        ttk.Spinbox(constraints_frame, from_=0, to=10, width=3, textvariable=self.min_upper_var).grid(row=0, column=3, sticky=tk.W, padx=5)
        
        ttk.Label(constraints_frame, text="Min digits:").grid(row=1, column=0, sticky=tk.W)
        ttk.Spinbox(constraints_frame, from_=0, to=10, width=3, textvariable=self.min_digits_var).grid(row=1, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(constraints_frame, text="Min symbols:").grid(row=1, column=2, sticky=tk.W, padx=10)
        ttk.Spinbox(constraints_frame, from_=0, to=10, width=3, textvariable=self.min_symbols_var).grid(row=1, column=3, sticky=tk.W, padx=5)
        
        ttk.Checkbutton(constraints_frame, text="No duplicate characters", variable=self.no_duplicates_var).grid(row=2, column=0, columnspan=4, sticky=tk.W, pady=5)
        ttk.Checkbutton(constraints_frame, text="Exclude similar characters (i, l, 1, L, o, 0, O)", variable=self.no_similar_var).grid(row=3, column=0, columnspan=4, sticky=tk.W)
        ttk.Checkbutton(constraints_frame, text="No sequential characters (abc, 123)", variable=self.no_sequential_var).grid(row=4, column=0, columnspan=4, sticky=tk.W)
        
        # Generate button
        generate_btn = ttk.Button(main_frame, text="Generate Password", command=self.generate_password)
        generate_btn.grid(row=4, column=0, columnspan=3, pady=20)
        
        # Generated password
        ttk.Label(main_frame, text="Generated Password:").grid(row=5, column=0, sticky=tk.W, pady=5)
        
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(main_frame, textvariable=self.password_var, font=('Arial', 12), state='readonly')
        password_entry.grid(row=5, column=1, columnspan=2, sticky=tk.EW, padx=5)
        
        # Buttons for password actions
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=6, column=0, columnspan=3, pady=10)
        
        ttk.Button(btn_frame, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save Password", command=self.save_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Password History", command=self.show_history).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Check Strength", command=self.check_strength).pack(side=tk.LEFT, padx=5)
        
        # Strength meter
        self.strength_var = tk.StringVar(value="Strength: -")
        strength_label = ttk.Label(main_frame, textvariable=self.strength_var, font=('Arial', 10, 'bold'))
        strength_label.grid(row=7, column=0, columnspan=3, pady=10)
        
        self.strength_meter = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.strength_meter.grid(row=8, column=0, columnspan=3, pady=(0, 20))
    
    def update_length_label(self):
        self.length_var.set(int(self.length_slider.get()))
    
    def generate_password(self):
        # Check if at least one character type is selected
        if not (self.lower_var.get() or self.upper_var.get() or 
                self.digits_var.get() or self.symbols_var.get()):
            messagebox.showerror("Error", "Please select at least one character type")
            return
        
        # Calculate minimum required characters
        min_chars = (self.min_lower_var.get() + self.min_upper_var.get() + 
                     self.min_digits_var.get() + self.min_symbols_var.get())
        
        if min_chars > self.length_var.get():
            messagebox.showerror("Error", f"Minimum characters required ({min_chars}) exceeds password length")
            return
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Exclude similar characters if selected
        if self.no_similar_var.get():
            lowercase = lowercase.replace('l', '').replace('o', '')
            uppercase = uppercase.replace('I', '').replace('O', '')
            digits = digits.replace('0', '').replace('1', '')
        
        # Create pool of characters based on selected types
        char_pool = []
        if self.lower_var.get():
            char_pool.extend(list(lowercase))
        if self.upper_var.get():
            char_pool.extend(list(uppercase))
        if self.digits_var.get():
            char_pool.extend(list(digits))
        if self.symbols_var.get():
            char_pool.extend(list(symbols))
        
        # Check if pool is empty (shouldn't happen due to earlier checks)
        if not char_pool:
            messagebox.showerror("Error", "No characters available for generation")
            return
        
        # Generate password with constraints
        password = []
        attempts = 0
        max_attempts = 100
        
        while attempts < max_attempts:
            password = []
            remaining_length = self.length_var.get()
            
            # Add required characters first
            if self.lower_var.get():
                password.extend(random.choices(lowercase, k=self.min_lower_var.get()))
            if self.upper_var.get():
                password.extend(random.choices(uppercase, k=self.min_upper_var.get()))
            if self.digits_var.get():
                password.extend(random.choices(digits, k=self.min_digits_var.get()))
            if self.symbols_var.get():
                password.extend(random.choices(symbols, k=self.min_symbols_var.get()))
            
            # Fill remaining length with random characters from the pool
            remaining_length = self.length_var.get() - len(password)
            if remaining_length > 0:
                password.extend(random.choices(char_pool, k=remaining_length))
            
            # Shuffle the password
            random.shuffle(password)
            
            # Convert to string
            password_str = ''.join(password)
            
            # Check constraints
            valid = True
            
            # Check for duplicates if required
            if self.no_duplicates_var.get() and len(set(password_str)) != len(password_str):
                valid = False
            
            # Check for sequential characters if required
            if self.no_sequential_var.get() and self.has_sequential_chars(password_str):
                valid = False
            
            if valid:
                break
                
            attempts += 1
        
        if attempts >= max_attempts:
            messagebox.showerror("Error", "Could not generate password with the given constraints")
            return
        
        self.password_var.set(password_str)
        self.check_strength()
    
    def has_sequential_chars(self, password):
        """Check for sequential characters (abc, 123, etc.)"""
        for i in range(len(password) - 2):
            # Check for 3 consecutive increasing or decreasing characters
            a, b, c = ord(password[i]), ord(password[i+1]), ord(password[i+2])
            if (a + 1 == b and b + 1 == c) or (a - 1 == b and b - 1 == c):
                return True
        return False
    
    def copy_to_clipboard(self):
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showerror("Error", "No password to copy")
    
    def save_password(self):
        password = self.password_var.get()
        if not password:
            messagebox.showerror("Error", "No password to save")
            return
        
        # Get a description for the password
        description = simpledialog.askstring("Save Password", "Enter a description for this password:")
        if not description:
            return
        
        # Add to history
        entry = {
            "password": password,
            "description": description,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "length": len(password),
            "lower": self.lower_var.get(),
            "upper": self.upper_var.get(),
            "digits": self.digits_var.get(),
            "symbols": self.symbols_var.get()
        }
        
        self.password_history.append(entry)
        self.save_history()
        messagebox.showinfo("Success", "Password saved to history!")
    
    def show_history(self):
        if not self.password_history:
            messagebox.showinfo("History", "No passwords in history")
            return
        
        history_window = tk.Toplevel(self.root)
        history_window.title("Password History")
        history_window.geometry("600x400")
        
        # Create treeview
        columns = ("timestamp", "description", "password", "length")
        tree = ttk.Treeview(history_window, columns=columns, show="headings")
        
        # Define headings
        tree.heading("timestamp", text="Date/Time")
        tree.heading("description", text="Description")
        tree.heading("password", text="Password")
        tree.heading("length", text="Length")
        
        # Set column widths
        tree.column("timestamp", width=150)
        tree.column("description", width=200)
        tree.column("password", width=150)
        tree.column("length", width=50, anchor=tk.CENTER)
        
        # Add data
        for entry in reversed(self.password_history):
            tree.insert("", tk.END, values=(
                entry["timestamp"],
                entry["description"],
                entry["password"],
                entry["length"]
            ))
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(history_window, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(fill=tk.BOTH, expand=True)
        
        # Add buttons
        btn_frame = ttk.Frame(history_window)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="Copy Selected", 
                  command=lambda: self.copy_selected_from_history(tree)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete Selected", 
                  command=lambda: self.delete_selected_from_history(tree)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", 
                  command=history_window.destroy).pack(side=tk.RIGHT, padx=5)
    
    def copy_selected_from_history(self, tree):
        selected = tree.selection()
        if not selected:
            messagebox.showerror("Error", "No item selected")
            return
        
        item = tree.item(selected[0])
        password = item["values"][2]
        pyperclip.copy(password)
        messagebox.showinfo("Success", "Password copied to clipboard!")
    
    def delete_selected_from_history(self, tree):
        selected = tree.selection()
        if not selected:
            messagebox.showerror("Error", "No item selected")
            return
        
        item = tree.item(selected[0])
        timestamp = item["values"][0]
        
        # Find and remove from history
        for i, entry in enumerate(self.password_history):
            if entry["timestamp"] == timestamp:
                del self.password_history[i]
                break
        
        self.save_history()
        tree.delete(selected[0])
        messagebox.showinfo("Success", "Password deleted from history")
    
    def check_strength(self):
        password = self.password_var.get()
        if not password:
            self.strength_var.set("Strength: -")
            self.strength_meter["value"] = 0
            return
        
        length = len(password)
        strength = 0
        feedback = []
        
        # Length score
        if length >= 12:
            strength += 30
            feedback.append("Good length")
        elif length >= 8:
            strength += 15
            feedback.append("Moderate length")
        else:
            feedback.append("Too short")
        
        # Character variety
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        
        variety = sum([has_lower, has_upper, has_digit, has_symbol])
        if variety == 4:
            strength += 30
            feedback.append("Excellent character variety")
        elif variety == 3:
            strength += 20
            feedback.append("Good character variety")
        elif variety == 2:
            strength += 10
            feedback.append("Moderate character variety")
        else:
            feedback.append("Poor character variety")
        
        # Entropy calculation
        pool_size = 0
        if has_lower: pool_size += 26
        if has_upper: pool_size += 26
        if has_digit: pool_size += 10
        if has_symbol: pool_size += 32  # Approximate common symbols
        
        if pool_size > 0:
            entropy = length * (math.log(pool_size) / math.log(2))
            entropy_score = min(30, entropy / 2)  # Scale entropy to 30 points max
            strength += entropy_score
        
        # Deductions for common patterns
        if self.has_sequential_chars(password):
            strength -= 10
            feedback.append("Contains sequential characters")
        
        if len(set(password)) < len(password) * 0.7:  # More than 30% duplicates
            strength -= 10
            feedback.append("Many duplicate characters")
        
        # Ensure strength is within bounds
        strength = max(0, min(100, strength))
        
        # Set strength meter and label
        self.strength_meter["value"] = strength
        
        if strength >= 80:
            rating = "Very Strong"
            color = "green"
        elif strength >= 60:
            rating = "Strong"
            color = "blue"
        elif strength >= 40:
            rating = "Moderate"
            color = "orange"
        elif strength >= 20:
            rating = "Weak"
            color = "red"
        else:
            rating = "Very Weak"
            color = "dark red"
        
        self.strength_var.set(f"Strength: {rating} ({strength:.0f}/100)")
        self.strength_meter["style"] = f"{color}.Horizontal.TProgressbar"
        
        # Show feedback if requested
        if len(feedback) > 0:
            feedback_text = "\n".join(feedback)
            self.strength_var.set(self.strength_var.get() + f"\n{feedback_text}")

if __name__ == "__main__":
    import math
    from tkinter import simpledialog
    
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()