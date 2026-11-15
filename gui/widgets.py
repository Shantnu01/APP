"""
RepoGuard Custom GUI Widgets
Stat card counters, filter panels, and notification widgets.
"""

import tkinter as tk
from tkinter import ttk


class StatCard(tk.Frame):
    """Modern metric summary card with responsive value and title."""

    def __init__(self, parent, title: str, initial_value: str = "0", accent: str = "#38BDF8", bg: str = "#1E293B"):
        super().__init__(parent, bg=bg, highlightthickness=1, highlightbackground="#334155", padx=12, pady=10)
        self.accent = accent

        self.lbl_title = tk.Label(
            self, text=title.upper(), font=("Segoe UI", 8, "bold"),
            fg="#94A3B8", bg=bg
        )
        self.lbl_title.pack(anchor="w")

        self.lbl_value = tk.Label(
            self, text=initial_value, font=("Segoe UI", 18, "bold"),
            fg=accent, bg=bg
        )
        self.lbl_value.pack(anchor="w", pady=(2, 0))

    def set_value(self, value: str, accent: str = None):
        self.lbl_value.config(text=str(value))
        if accent:
            self.lbl_value.config(fg=accent)
