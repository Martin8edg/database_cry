import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from threading import Thread
from crypto import AesGcmCrypto, PasswordAuthError, CryptoError
from database_handler import DatabaseHandler


class DatabaseCryGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DatabaseCry - 本地数据库加密系统")
        self.root.geometry("900x650")
        self.root.resizable(True, True)
        
        self.crypto = None
        self.handler = None
        self.is_unlocked = False
        
        self._create_unlock_frame()
        self._create_main_frame()
        self._show_unlock_frame()
    
    def _create_unlock_frame(self):
        self.unlock_frame = tk.Frame(self.root, bg="#2c3e50")
        
        title_label = tk.Label(
            self.unlock_frame,
            text="DatabaseCry",
            font=("Microsoft YaHei", 32, "bold"),
            fg="#ecf0f1",
            bg="#2c3e50"
        )
        title_label.pack(pady=40)
        
        subtitle_label = tk.Label(
            self.unlock_frame,
            text="本地数据库加密系统",
            font=("Microsoft YaHei", 14),
            fg="#bdc3c7",
            bg="#2c3e50"
        )
        subtitle_label.pack(pady=10)
        
        input_frame = tk.Frame(self.unlock_frame, bg="#2c3e50")
        input_frame.pack(pady=30)
        
        tk.Label(
            input_frame,
            text="主密码:",
            font=("Microsoft YaHei", 12),
            fg="#ecf0f1",
            bg="#2c3e50"
        ).grid(row=0, column=0, padx=10, pady=10, sticky="e")
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(
            input_frame,
            textvariable=self.password_var,
            show="*",
            font=("Consolas", 12),
            width=25
        )
        self.password_entry.grid(row=0, column=1, padx=10, pady=10)
        
        tk.Label(
            input_frame,
            text="确认密码:",
            font=("Microsoft YaHei", 12),
            fg="#ecf0f1",
            bg="#2c3e50"
        ).grid(row=1, column=0, padx=10, pady=10, sticky="e")
        
        self.confirm_password_var = tk.StringVar()
        self.confirm_password_entry = tk.Entry(
            input_frame,
            textvariable=self.confirm_password_var,
            show="*",
            font=("Consolas", 12),
            width=25
        )
        self.confirm_password_entry.grid(row=1, column=1, padx=10, pady=10)
        
        self.unlock_btn = tk.Button(
            self.unlock_frame,
            text="解锁 / 创建金库",
            font=("Microsoft YaHei", 14),
            bg="#27ae60",
            fg="white",
            relief="flat",
            padx=30,
            pady=10,
            command=self._on_unlock
        )
        self.unlock_btn.pack(pady=30)
        
        hint_label = tk.Label(
            self.unlock_frame,
            text="首次使用将创建新金库，请设置主密码",
            font=("Microsoft YaHei", 10),
            fg="#95a5a6",
            bg="#2c3e50"
        )
        hint_label.pack(pady=10)
        
        self.password_entry.bind('<Return>', lambda e: self._on_unlock())
        self.confirm_password_entry.bind('<Return>', lambda e: self._on_unlock())
    
    def _create_main_frame(self):
        self.main_frame = tk.Frame(self.root, bg="#ecf0f1")
        
        toolbar = tk.Frame(self.main_frame, bg="#34495e", height=50)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)
        
        tk.Label(
            toolbar,
            text="DatabaseCry",
            font=("Microsoft YaHei", 16, "bold"),
            fg="#ecf0f1",
            bg="#34495e"
        ).pack(side="left", padx=20)
        
        tk.Button(
            toolbar,
            text="🔒 锁定",
            font=("Microsoft YaHei", 10),
            bg="#e74c3c",
            fg="white",
            relief="flat",
            command=self._lock
        ).pack(side="right", padx=10)
        
        content = tk.Frame(self.main_frame, bg="#ecf0f1")
        content.pack(fill="both", expand=True, padx=10, pady=10)
        
        left_panel = tk.Frame(content, bg="white", relief="solid", bd=1)
        left_panel.pack(side="left", fill="both", expand=False, padx=(0, 5))
        left_panel.configure(width=350)
        
        tk.Label(
            left_panel,
            text="📁 数据库操作",
            font=("Microsoft YaHei", 14, "bold"),
            bg="white",
            fg="#2c3e50"
        ).pack(pady=15)
        
        btn_frame = tk.Frame(left_panel, bg="white")
        btn_frame.pack(pady=10, fill="x", padx=20)
        
        self._create_operation_buttons(btn_frame)
        
        list_frame = tk.Frame(left_panel, bg="white")
        list_frame.pack(pady=20, fill="both", expand=True, padx=20)
        
        tk.Label(
            list_frame,
            text="已加密数据库列表",
            font=("Microsoft YaHei", 12),
            bg="white",
            fg="#34495e"
        ).pack(pady=(10, 5))
        
        list_container = tk.Frame(list_frame, bg="#ecf0f1", relief="sunken", bd=1)
        list_container.pack(fill="both", expand=True)
        
        scrollbar = tk.Scrollbar(list_container)
        scrollbar.pack(side="right", fill="y")
        
        self.db_listbox = tk.Listbox(
            list_container,
            font=("Consolas", 10),
            yscrollcommand=scrollbar.set,
            bg="#ecf0f1",
            selectmode="single"
        )
        self.db_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.db_listbox.yview)
        
        right_panel = tk.Frame(content, bg="white", relief="solid", bd=1)
        right_panel.pack(side="right", fill="both", expand=True, padx=(5, 0))
        
        tk.Label(
            right_panel,
            text="📋 操作日志",
            font=("Microsoft YaHei", 14, "bold"),
            bg="white",
            fg="#2c3e50"
        ).pack(pady=15)
        
        self.log_text = scrolledtext.ScrolledText(
            right_panel,
            font=("Consolas", 10),
            bg="#2c3e50",
            fg="#ecf0f1",
            insertbackground="white",
            relief="flat",
            wrap="word"
        )
        self.log_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))
    
    def _create_operation_buttons(self, parent):
        buttons = [
            ("🔐 加密数据库", "#3498db", self._encrypt_database),
            ("🔓 解密数据库", "#27ae60", self._decrypt_database),
            ("📄 查看信息", "#9b59b6", self._view_info),
            ("🗑️ 删除记录", "#e74c3c", self._delete_database),
            ("🔄 刷新列表", "#f39c12", self._refresh_list),
        ]
        
        for i, (text, color, command) in enumerate(buttons):
            btn = tk.Button(
                parent,
                text=text,
                font=("Microsoft YaHei", 11),
                bg=color,
                fg="white",
                relief="flat",
                padx=15,
                pady=8,
                command=command
            )
            btn.pack(fill="x", pady=3)
    
    def _show_unlock_frame(self):
        self.unlock_frame.pack(fill="both", expand=True)
        self.main_frame.pack_forget()
        self.password_entry.focus()
    
    def _show_main_frame(self):
        self.main_frame.pack(fill="both", expand=True)
        self.unlock_frame.pack_forget()
        self._refresh_list()
        self._log("✅ 金库已解锁")
    
    def _on_unlock(self):
        password = self.password_var.get()
        confirm_password = self.confirm_password_var.get()
        
        if not password:
            messagebox.showwarning("提示", "请输入主密码")
            return
        
        vault_dir = os.path.join(os.path.dirname(__file__), ".vault")
        is_new_vault = not os.path.exists(os.path.join(vault_dir, ".db_verifier"))
        
        if is_new_vault:
            if password != confirm_password:
                messagebox.showerror("错误", "两次输入的密码不一致")
                return
            
            if len(password) < 6:
                messagebox.showwarning("警告", "密码长度建议至少6位")
            
            try:
                self._log("🔧 正在创建新金库...")
                self.crypto = AesGcmCrypto(password)
                self.handler = DatabaseHandler(self.crypto)
                self.is_unlocked = True
                self.password_var.set("")
                self.confirm_password_var.set("")
                messagebox.showinfo("成功", "金库创建成功！")
                self._show_main_frame()
            except Exception as e:
                messagebox.showerror("错误", f"金库创建失败: {str(e)}")
        else:
            try:
                self._log("🔓 正在解锁金库...")
                self.crypto = AesGcmCrypto(password)
                self.handler = DatabaseHandler(self.crypto)
                self.is_unlocked = True
                self.password_var.set("")
                messagebox.showinfo("成功", "金库解锁成功！")
                self._show_main_frame()
            except PasswordAuthError:
                messagebox.showerror("错误", "密码错误，请重试")
            except Exception as e:
                messagebox.showerror("错误", f"解锁失败: {str(e)}")
    
    def _lock(self):
        if self.crypto:
            self.crypto.destroy_memory_traces()
        self.crypto = None
        self.handler = None
        self.is_unlocked = False
        self._log("🔒 金库已锁定")
        self._show_unlock_frame()
    
    def _encrypt_database(self):
        if not self.is_unlocked:
            messagebox.showwarning("提示", "请先解锁金库")
            return
        
        file_path = filedialog.askopenfilename(
            title="选择数据库文件",
            filetypes=[
                ("所有数据库", "*.db *.sqlite *.sqlite3 *.mdb *.accdb"),
                ("SQLite", "*.db *.sqlite *.sqlite3"),
                ("Access", "*.mdb *.accdb"),
                ("所有文件", "*.*")
            ]
        )
        
        if not file_path:
            return
        
        db_name_dialog = tk.Toplevel(self.root)
        db_name_dialog.title("设置数据库名称")
        db_name_dialog.geometry("400x200")
        db_name_dialog.transient(self.root)
        db_name_dialog.grab_set()
        
        tk.Label(
            db_name_dialog,
            text="数据库名称:",
            font=("Microsoft YaHei", 12)
        ).pack(pady=10)
        
        db_name_var = tk.StringVar(value=os.path.splitext(os.path.basename(file_path))[0])
        tk.Entry(
            db_name_dialog,
            textvariable=db_name_var,
            font=("Consolas", 12),
            width=30
        ).pack(pady=10)
        
        tk.Label(
            db_name_dialog,
            text="描述 (可选):",
            font=("Microsoft YaHei", 12)
        ).pack(pady=10)
        
        desc_var = tk.StringVar()
        tk.Entry(
            db_name_dialog,
            textvariable=desc_var,
            font=("Consolas", 12),
            width=30
        ).pack(pady=10)
        
        def do_encrypt():
            db_name = db_name_var.get().strip()
            description = desc_var.get().strip()
            
            if not db_name:
                messagebox.showwarning("提示", "请输入数据库名称")
                return
            
            if self.handler.get_encrypted_path(db_name) and os.path.exists(self.handler.get_encrypted_path(db_name)):
                if not messagebox.askyesno("确认", f"数据库 '{db_name}' 已存在，是否覆盖？"):
                    return
            
            db_name_dialog.destroy()
            
            self._log(f"🔐 正在加密数据库: {db_name}")
            success, msg = self.handler.encrypt_database(
                file_path, db_name, description
            )
            
            if success:
                self._log(f"✅ {msg}")
                messagebox.showinfo("成功", msg)
                self._refresh_list()
            else:
                self._log(f"❌ {msg}")
                messagebox.showerror("错误", msg)
        
        tk.Button(
            db_name_dialog,
            text="开始加密",
            font=("Microsoft YaHei", 11),
            bg="#3498db",
            fg="white",
            command=do_encrypt
        ).pack(pady=20)
    
    def _decrypt_database(self):
        if not self.is_unlocked:
            messagebox.showwarning("提示", "请先解锁金库")
            return
        
        selection = self.db_listbox.curselection()
        if not selection:
            messagebox.showwarning("提示", "请先选择一个数据库")
            return
        
        db_name = self.db_listbox.get(selection[0])
        
        output_path = filedialog.asksaveasfilename(
            title="保存解密后的数据库",
            defaultextension=".db",
            initialfile=db_name,
            filetypes=[
                ("SQLite数据库", "*.db"),
                ("所有文件", "*.*")
            ]
        )
        
        if not output_path:
            return
        
        self._log(f"🔓 正在解密数据库: {db_name}")
        success, msg = self.handler.decrypt_database(db_name, output_path)
        
        if success:
            self._log(f"✅ {msg}")
            messagebox.showinfo("成功", msg)
        else:
            self._log(f"❌ {msg}")
            messagebox.showerror("错误", msg)
    
    def _view_info(self):
        if not self.is_unlocked:
            messagebox.showwarning("提示", "请先解锁金库")
            return
        
        selection = self.db_listbox.curselection()
        if not selection:
            messagebox.showwarning("提示", "请先选择一个数据库")
            return
        
        db_name = self.db_listbox.get(selection[0])
        info = self.handler.get_database_info(db_name)
        
        if info:
            info_text = f"""
数据库名称: {info.get('db_name', 'N/A')}
原始文件名: {info.get('original_filename', 'N/A')}
原始大小: {info.get('original_size', 0):,} 字节
加密时间: {info.get('encrypted_at', 'N/A')}
校验和: {info.get('original_checksum', 'N/A')[:32]}...
描述: {info.get('description', '无')}
版本: {info.get('version', 'N/A')}
"""
            self._log(f"📄 {db_name} 信息:\n{info_text}")
            messagebox.showinfo(f"数据库信息 - {db_name}", info_text)
        else:
            messagebox.showerror("错误", "无法获取数据库信息")
    
    def _delete_database(self):
        if not self.is_unlocked:
            messagebox.showwarning("提示", "请先解锁金库")
            return
        
        selection = self.db_listbox.curselection()
        if not selection:
            messagebox.showwarning("提示", "请先选择一个数据库")
            return
        
        db_name = self.db_listbox.get(selection[0])
        
        if messagebox.askyesno("确认", f"确定要删除 '{db_name}' 吗？\n此操作不可恢复！"):
            success, msg = self.handler.delete_database(db_name)
            
            if success:
                self._log(f"✅ {msg}")
                messagebox.showinfo("成功", msg)
                self._refresh_list()
            else:
                self._log(f"❌ {msg}")
                messagebox.showerror("错误", msg)
    
    def _refresh_list(self):
        self.db_listbox.delete(0, tk.END)
        
        if self.handler:
            databases = self.handler.list_encrypted_databases()
            for db in databases:
                self.db_listbox.insert(tk.END, db)
    
    def _log(self, message: str):
        self.log_text.insert(tk.END, f"\n[{self._get_timestamp()}] {message}")
        self.log_text.see(tk.END)
    
    def _get_timestamp(self) -> str:
        from datetime import datetime
        return datetime.now().strftime("%H:%M:%S")


def main():
    root = tk.Tk()
    
    style = ttk.Style()
    style.theme_use('clam')
    
    app = DatabaseCryGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()