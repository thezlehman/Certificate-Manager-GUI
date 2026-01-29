#!/usr/bin/env python3
"""
Certificate Manager GUI

A companion tool to Code Signing Tool GUI.

Features:
- Browse certificates in common Windows certificate stores
- View subject, thumbprint, and expiration for each certificate
- Import PFX files into a selected store (using certutil)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
import os
from dataclasses import dataclass
from typing import List, Dict, Tuple


@dataclass
class CertificateInfo:
    subject: str
    thumbprint: str
    not_after: str


class CertificateManagerGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Certificate Manager")
        self.root.geometry("900x700")
        self.root.minsize(850, 650)

        self.store_var = tk.StringVar()
        self.pfx_path_var = tk.StringVar()
        self.pfx_password_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")

        self.store_options: Dict[str, Tuple[bool, str]] = {
            "CurrentUser\\My (Personal)": (True, "my"),
            "CurrentUser\\Root (Trusted Root)": (True, "root"),
            "CurrentUser\\TrustedPublisher": (True, "trustedpublisher"),
            "LocalMachine\\My (Personal)": (False, "my"),
            "LocalMachine\\Root (Trusted Root)": (False, "root"),
            "LocalMachine\\TrustedPublisher": (False, "trustedpublisher"),
        }

        self.store_var.set("CurrentUser\\My (Personal)")

        self.create_widgets()
        self.load_store()

    # ---------------------------
    # UI
    # ---------------------------
    def create_widgets(self) -> None:
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=tk.NSEW)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        title_label = ttk.Label(
            main_frame,
            text="Certificate Manager",
            font=("Arial", 16, "bold"),
        )
        title_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 8))

        # Store selection
        store_frame = ttk.LabelFrame(main_frame, text="Certificate Store", padding="8")
        store_frame.grid(row=1, column=0, sticky=tk.EW, pady=5)
        store_frame.columnconfigure(1, weight=1)

        ttk.Label(store_frame, text="Store:", width=14).grid(
            row=0, column=0, sticky=tk.W, pady=3
        )

        store_combo = ttk.Combobox(
            store_frame,
            textvariable=self.store_var,
            values=list(self.store_options.keys()),
            state="readonly",
        )
        store_combo.grid(row=0, column=1, sticky=tk.EW, pady=3, padx=(0, 4))
        store_combo.bind("<<ComboboxSelected>>", lambda _e: self.load_store())

        ttk.Button(
            store_frame,
            text="Refresh",
            command=self.load_store,
            width=10,
        ).grid(row=0, column=2, sticky=tk.W, pady=3)

        # Certificate list
        list_frame = ttk.LabelFrame(
            main_frame, text="Certificates in Store", padding="8"
        )
        list_frame.grid(row=2, column=0, sticky=tk.NSEW, pady=5)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=3)

        columns = ("subject", "thumbprint", "not_after")
        self.tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        self.tree.heading("subject", text="Subject")
        self.tree.heading("thumbprint", text="Thumbprint (SHA1)")
        self.tree.heading("not_after", text="Not After")

        self.tree.column("subject", width=320, anchor=tk.W)
        self.tree.column("thumbprint", width=260, anchor=tk.W)
        self.tree.column("not_after", width=160, anchor=tk.W)

        y_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        x_scroll = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.tree.grid(row=0, column=0, sticky=tk.NSEW)
        y_scroll.grid(row=0, column=1, sticky=tk.NS)
        x_scroll.grid(row=1, column=0, sticky=tk.EW)

        # Details / raw output
        details_frame = ttk.LabelFrame(main_frame, text="Details", padding="8")
        details_frame.grid(row=3, column=0, sticky=tk.NSEW, pady=5)
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=2)

        self.details_text = scrolledtext.ScrolledText(
            details_frame, height=10, wrap=tk.WORD, font=("Consolas", 9)
        )
        self.details_text.grid(row=0, column=0, sticky=tk.NSEW)

        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        # PFX import
        import_frame = ttk.LabelFrame(main_frame, text="Import PFX", padding="8")
        import_frame.grid(row=4, column=0, sticky=tk.EW, pady=5)
        import_frame.columnconfigure(1, weight=1)

        ttk.Label(import_frame, text="PFX File:", width=14).grid(
            row=0, column=0, sticky=tk.W, pady=3
        )
        ttk.Entry(import_frame, textvariable=self.pfx_path_var).grid(
            row=0, column=1, sticky=tk.EW, pady=3, padx=(0, 4)
        )
        ttk.Button(
            import_frame,
            text="Browse...",
            command=self.browse_pfx,
            width=10,
        ).grid(row=0, column=2, sticky=tk.W, pady=3)

        ttk.Label(import_frame, text="Password:", width=14).grid(
            row=1, column=0, sticky=tk.W, pady=3
        )
        ttk.Entry(
            import_frame, textvariable=self.pfx_password_var, show="*"
        ).grid(row=1, column=1, sticky=tk.EW, pady=3, padx=(0, 4))

        ttk.Button(
            import_frame,
            text="Import into Store",
            command=self.import_pfx,
            width=16,
        ).grid(row=1, column=2, sticky=tk.W, pady=3)

        # Status bar
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=5, column=0, sticky=tk.EW, pady=(6, 0))

    # ---------------------------
    # Helpers
    # ---------------------------
    def _get_selected_store(self) -> Tuple[bool, str]:
        return self.store_options[self.store_var.get()]

    def _run_certutil(self, args: List[str]) -> Tuple[int, str, str]:
        try:
            completed = subprocess.run(
                ["certutil"] + args,
                capture_output=True,
                text=True,
                timeout=60,
            )
            return completed.returncode, completed.stdout, completed.stderr
        except FileNotFoundError:
            return 1, "", "certutil.exe not found. This tool requires Windows."
        except Exception as exc:
            return 1, "", str(exc)

    # ---------------------------
    # Store loading & parsing
    # ---------------------------
    def load_store(self) -> None:
        user_store, store_name = self._get_selected_store()

        self.status_var.set(f"Loading store: {self.store_var.get()} ...")
        self.root.update_idletasks()
        self.details_text.delete("1.0", tk.END)

        args = []
        if user_store:
            args.append("-user")
        args.extend(["-store", store_name])

        code, out, err = self._run_certutil(args)

        if code != 0:
            messagebox.showerror(
                "Error loading store", f"certutil returned error:\n\n{err or out}"
            )
            self.status_var.set("Error loading store.")
            return

        certs = self._parse_certutil_store_output(out)
        self._populate_tree(certs)
        self.details_text.insert(tk.END, out)
        self.status_var.set(f"Loaded {len(certs)} certificate(s).")

    def _parse_certutil_store_output(self, output: str) -> List[CertificateInfo]:
        lines = output.splitlines()
        certs: List[CertificateInfo] = []
        current: Dict[str, str] = {}

        def flush_current() -> None:
            if (
                current.get("subject")
                or current.get("thumbprint")
                or current.get("not_after")
            ):
                certs.append(
                    CertificateInfo(
                        subject=current.get("subject", "").strip() or "<no subject>",
                        thumbprint=current.get("thumbprint", "").strip(),
                        not_after=current.get("not_after", "").strip(),
                    )
                )

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("========") or stripped.startswith("Certificate:"):
                # Start of a new certificate block
                if current:
                    flush_current()
                    current = {}
                continue

            if stripped.startswith("Subject:"):
                current["subject"] = stripped[len("Subject:") :].strip()
            elif stripped.startswith("Cert Hash(sha1):"):
                current["thumbprint"] = stripped[len("Cert Hash(sha1):") :].strip()
            elif stripped.startswith("NotAfter:"):
                current["not_after"] = stripped[len("NotAfter:") :].strip()

        if current:
            flush_current()

        return certs

    def _populate_tree(self, certs: List[CertificateInfo]) -> None:
        self.tree.delete(*self.tree.get_children())
        for cert in certs:
            self.tree.insert(
                "",
                tk.END,
                values=(cert.subject, cert.thumbprint, cert.not_after),
            )

    # ---------------------------
    # Events
    # ---------------------------
    def on_tree_select(self, _event: tk.Event) -> None:
        # Scroll to selected certificate details in raw output (best-effort)
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        subject = values[0]
        if not subject:
            return

        text = self.details_text.get("1.0", tk.END)
        idx = text.find(subject)
        if idx != -1:
            index = f"1.0+{idx}c"
            self.details_text.see(index)
            self.details_text.tag_remove("sel", "1.0", tk.END)
            self.details_text.tag_add("sel", index, f"{index} lineend")

    # ---------------------------
    # PFX import
    # ---------------------------
    def browse_pfx(self) -> None:
        filename = filedialog.askopenfilename(
            title="Select PFX file",
            filetypes=[("PFX Files", "*.pfx"), ("All files", "*.*")],
        )
        if filename:
            self.pfx_path_var.set(filename)

    def import_pfx(self) -> None:
        path = self.pfx_path_var.get().strip()
        password = self.pfx_password_var.get()
        if not path:
            messagebox.showerror("Import PFX", "Please select a PFX file.")
            return
        if not os.path.exists(path):
            messagebox.showerror("Import PFX", f"PFX file not found:\n{path}")
            return

        user_store, store_name = self._get_selected_store()

        if not messagebox.askyesno(
            "Confirm Import",
            f"Import PFX into store:\n\n{self.store_var.get()}\n\n"
            "This may require administrator privileges.\n\nContinue?",
        ):
            return

        args: List[str] = []
        if user_store:
            args.append("-user")
        args.extend(
            [
                "-f",
                "-p",
                password,
                "-importpfx",
                store_name,
                path,
            ]
        )

        self.status_var.set("Importing PFX...")
        self.root.update_idletasks()

        code, out, err = self._run_certutil(args)

        if code == 0:
            messagebox.showinfo(
                "Import PFX",
                "PFX imported successfully.\n\n"
                "Note: If this is a LocalMachine store, you may have been prompted for elevation.",
            )
            self.status_var.set("PFX imported successfully.")
            self.load_store()
        else:
            messagebox.showerror(
                "Import PFX failed",
                f"certutil returned an error:\n\n{err or out}",
            )
            self.status_var.set("PFX import failed.")


def main() -> None:
    root = tk.Tk()
    app = CertificateManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

