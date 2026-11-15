"""
RepoGuard GUI Canvas Visualizations
Renders dynamic visual charts and interactive risk gauges directly on Tkinter Canvas.
Designed and implemented for interactive viva demonstrations.
"""

import math
import tkinter as tk
from tkinter import ttk
from typing import Optional
from core.models import RiskMetrics


class RiskGaugeCanvas(tk.Canvas):
    """
    Renders a modern semicircular risk gauge meter (0 to 100) with dynamic needle
    and colored threat segments.
    """

    def __init__(self, parent, width: int = 240, height: int = 140, bg: str = "#1E293B", **kwargs):
        super().__init__(parent, width=width, height=height, bg=bg, highlightthickness=0, **kwargs)
        self.width = width
        self.height = height
        self.score = 0.0
        self.rating = "Safe"
        self.draw()

    def set_score(self, score: float, rating: str):
        self.score = max(0.0, min(100.0, score))
        self.rating = rating
        self.draw()

    def draw(self):
        self.delete("all")
        cx = self.width / 2
        cy = self.height - 25
        radius = min(cx - 20, cy - 15)

        # Draw gauge arc tracks (Safe/Green, Moderate/Yellow, High/Orange, Critical/Red)
        # Angles in tkinter: 0 is 3 o'clock, 90 is 12 o'clock, 180 is 9 o'clock.
        # Semicircle goes from 180 to 0 (span -180).
        bbox = (cx - radius, cy - radius, cx + radius, cy + radius)
        width = 16

        # Background track
        self.create_arc(bbox, start=0, extent=180, outline="#334155", width=width, style="arc")

        # Colored sectors
        # 0-25% (Green): angle 180 to 135 (extent -45)
        self.create_arc(bbox, start=135, extent=45, outline="#10B981", width=width, style="arc")
        # 25-50% (Yellow): angle 135 to 90 (extent -45)
        self.create_arc(bbox, start=90, extent=45, outline="#F59E0B", width=width, style="arc")
        # 50-75% (Orange): angle 90 to 45 (extent -45)
        self.create_arc(bbox, start=45, extent=45, outline="#F97316", width=width, style="arc")
        # 75-100% (Red): angle 45 to 0 (extent -45)
        self.create_arc(bbox, start=0, extent=45, outline="#EF4444", width=width, style="arc")

        # Compute needle angle: 0 score = 180 deg, 100 score = 0 deg
        needle_angle_deg = 180.0 - (self.score / 100.0) * 180.0
        rad = math.radians(needle_angle_deg)
        nx = cx + (radius - 12) * math.cos(rad)
        ny = cy - (radius - 12) * math.sin(rad)

        # Draw needle
        self.create_line(cx, cy, nx, ny, fill="#F8FAFC", width=3, capstyle=tk.ROUND)
        self.create_oval(cx - 6, cy - 6, cx + 6, cy + 6, fill="#38BDF8", outline="#F8FAFC", width=2)

        # Render score and rating text
        color_map = {
            "Safe": "#10B981",
            "Low": "#38BDF8",
            "Moderate": "#F59E0B",
            "High": "#F97316",
            "Critical": "#EF4444",
        }
        text_color = color_map.get(self.rating, "#F8FAFC")

        self.create_text(
            cx, cy + 12,
            text=f"{self.score:.1f} - {self.rating} Risk",
            fill=text_color,
            font=("Segoe UI", 10, "bold")
        )


class SeverityBarCanvas(tk.Canvas):
    """
    Renders an interactive breakdown bar indicating the distribution of findings
    (Critical, High, Moderate, Low, and Clean).
    """

    def __init__(self, parent, width: int = 340, height: int = 70, bg: str = "#1E293B", **kwargs):
        super().__init__(parent, width=width, height=height, bg=bg, highlightthickness=0, **kwargs)
        self.width = width
        self.height = height
        self.metrics: Optional[RiskMetrics] = None
        self.draw()

    def update_metrics(self, metrics: RiskMetrics):
        self.metrics = metrics
        self.draw()

    def draw(self):
        self.delete("all")
        pad_x = 15
        pad_y = 12
        bar_w = self.width - (2 * pad_x)
        bar_h = 16

        # Draw empty baseline if no data
        if not self.metrics or self.metrics.total_dependencies == 0:
            self.create_rectangle(
                pad_x, pad_y, pad_x + bar_w, pad_y + bar_h,
                fill="#334155", outline="#475569", width=1
            )
            self.create_text(
                self.width / 2, pad_y + bar_h + 18,
                text="Awaiting repository scan...",
                fill="#94A3B8", font=("Segoe UI", 9)
            )
            return

        m = self.metrics
        total = m.total_vulnerabilities + m.clean_dependencies
        if total == 0:
            total = 1

        segments = [
            ("Crit", m.critical_count, "#EF4444"),
            ("High", m.high_count, "#F97316"),
            ("Mod", m.moderate_count, "#F59E0B"),
            ("Low", m.low_count, "#3B82F6"),
            ("Clean", m.clean_dependencies, "#10B981"),
        ]

        cur_x = pad_x
        for label, count, color in segments:
            if count <= 0:
                continue
            seg_w = (count / total) * bar_w
            self.create_rectangle(
                cur_x, pad_y, cur_x + seg_w, pad_y + bar_h,
                fill=color, outline=""
            )
            cur_x += seg_w

        # Draw legend underneath
        legend_y = pad_y + bar_h + 18
        leg_items = [
            ("Crit", m.critical_count, "#EF4444"),
            ("High", m.high_count, "#F97316"),
            ("Mod", m.moderate_count, "#F59E0B"),
            ("Clean", m.clean_dependencies, "#10B981"),
        ]

        item_spacing = self.width / len(leg_items)
        for i, (name, cnt, col) in enumerate(leg_items):
            lx = pad_x + (i * item_spacing) + 10
            self.create_oval(lx, legend_y - 4, lx + 8, legend_y + 4, fill=col, outline="")
            self.create_text(
                lx + 14, legend_y,
                text=f"{name}: {cnt}",
                anchor="w",
                fill="#CBD5E1",
                font=("Segoe UI", 8, "bold")
            )
