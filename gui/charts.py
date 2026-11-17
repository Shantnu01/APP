"""
RepoGuard GUI Canvas Visualizations
Renders dynamic visual charts and interactive risk gauges directly on Tkinter Canvas.
Includes smooth needle animations and multi-segment threat telemetry.

Authors: Shantnu, Arya Agrawal, Raiyan Kamal
Course: Advanced Programming Practices (Section: H2) | Dr. Rajesh Kannan
"""

import math
import tkinter as tk
from typing import Optional
from core.models import RiskMetrics


class RiskGaugeCanvas(tk.Canvas):
    """
    Renders an animated, high-fidelity semicircular security speedometer (0 to 100)
    with colored risk zones, tick marks, and a dynamically sweeping needle.
    """

    def __init__(self, parent, width: int = 240, height: int = 135, bg: str = "#1E293B", **kwargs):
        super().__init__(parent, width=width, height=height, bg=bg, highlightthickness=0, **kwargs)
        self.canvas_width = width
        self.canvas_height = height
        self.current_score = 0.0
        self.target_score = 0.0
        self.rating = "Safe"
        self._anim_job = None
        self.draw()

    def set_score(self, target: float, rating: str):
        """Sets the new score and initiates a smooth needle sweep animation."""
        self.target_score = max(0.0, min(100.0, float(target)))
        self.rating = rating

        # Cancel any pending animation loop
        if self._anim_job is not None:
            self.after_cancel(self._anim_job)
            self._anim_job = None

        self._animate_needle()

    def _animate_needle(self):
        """Interpolates needle position smoothly towards the target score."""
        diff = self.target_score - self.current_score
        if abs(diff) < 0.4:
            self.current_score = self.target_score
            self.draw()
            self._anim_job = None
            return

        # Proportional spring animation step
        step = diff * 0.18
        if abs(step) < 0.35:
            step = 0.35 if diff > 0 else -0.35

        self.current_score += step
        self.draw()
        self._anim_job = self.after(16, self._animate_needle)

    def draw(self):
        """Redraws the entire gauge, tracks, tick marks, needle, and readout."""
        self.delete("all")

        cx = self.canvas_width / 2.0
        cy = self.canvas_height - 30.0
        radius = min(cx - 24.0, cy - 14.0)
        track_width = 14

        bbox = (cx - radius, cy - radius, cx + radius, cy + radius)

        # 1. Background dark guide arc (180 deg to 0 deg)
        self.create_arc(
            bbox, start=0, extent=180,
            outline="#334155", width=track_width, style="arc"
        )

        # 2. Colored Threat Sectors (Tkinter arcs measure angles counter-clockwise)
        # 0 - 25% (Safe / Low - Emerald): 180° down to 135° (extent 45 starting at 135°)
        self.create_arc(bbox, start=135, extent=45, outline="#10B981", width=track_width, style="arc")
        # 25 - 50% (Moderate - Amber): 135° down to 90° (extent 45 starting at 90°)
        self.create_arc(bbox, start=90, extent=45, outline="#F59E0B", width=track_width, style="arc")
        # 50 - 75% (High - Orange): 90° down to 45° (extent 45 starting at 45°)
        self.create_arc(bbox, start=45, extent=45, outline="#F97316", width=track_width, style="arc")
        # 75 - 100% (Critical - Red): 45° down to 0° (extent 45 starting at 0°)
        self.create_arc(bbox, start=0, extent=45, outline="#EF4444", width=track_width, style="arc")

        # 3. Scale Ticks and Labels (0, 25, 50, 75, 100)
        ticks = [
            (0, "0"),
            (25, ""),
            (50, "50"),
            (75, ""),
            (100, "100"),
        ]
        tick_r_inner = radius - (track_width / 2.0) - 4
        tick_r_outer = radius + (track_width / 2.0) + 4
        label_r = radius - (track_width / 2.0) - 14

        for val, label in ticks:
            # Angle: 0 score = 180 deg (left), 100 score = 0 deg (right)
            angle_deg = 180.0 - (val / 100.0) * 180.0
            rad = math.radians(angle_deg)
            cos_a = math.cos(rad)
            sin_a = math.sin(rad)

            # Draw tick line
            x1 = cx + tick_r_inner * cos_a
            y1 = cy - tick_r_inner * sin_a
            x2 = cx + tick_r_outer * cos_a
            y2 = cy - tick_r_outer * sin_a
            self.create_line(x1, y1, x2, y2, fill="#64748B", width=1.5)

            # Draw numeric label
            if label:
                lx = cx + label_r * cos_a
                ly = cy - label_r * sin_a
                self.create_text(
                    lx, ly, text=label, fill="#94A3B8",
                    font=("Segoe UI", 7, "bold")
                )

        # 4. Needle Rendering
        # Needle points from cx, cy at current_score angle
        # 0 score = 180°, 100 score = 0°
        needle_deg = 180.0 - (self.current_score / 100.0) * 180.0
        needle_rad = math.radians(needle_deg)
        needle_len = radius - 8.0

        tip_x = cx + needle_len * math.cos(needle_rad)
        tip_y = cy - needle_len * math.sin(needle_rad)

        # Base perpendicular wings for tapered needle
        perp_left = needle_rad + (math.pi / 2.0)
        perp_right = needle_rad - (math.pi / 2.0)
        base_w = 4.5

        left_x = cx + base_w * math.cos(perp_left)
        left_y = cy - base_w * math.sin(perp_left)

        right_x = cx + base_w * math.cos(perp_right)
        right_y = cy - base_w * math.sin(perp_right)

        tail_x = cx - 10.0 * math.cos(needle_rad)
        tail_y = cy + 10.0 * math.sin(needle_rad)

        # Draw needle polygon
        poly_points = [tip_x, tip_y, left_x, left_y, tail_x, tail_y, right_x, right_y]
        needle_color = "#F8FAFC"
        if self.current_score >= 75.0:
            needle_color = "#FCA5A5"  # Soft red highlight
        elif self.current_score >= 50.0:
            needle_color = "#FED7AA"  # Soft orange highlight

        self.create_polygon(
            poly_points, fill=needle_color,
            outline="#38BDF8", width=1.2
        )

        # Needle Center Pivot Hub
        self.create_oval(cx - 7, cy - 7, cx + 7, cy + 7, fill="#0F172A", outline="#38BDF8", width=2)
        self.create_oval(cx - 3, cy - 3, cx + 3, cy + 3, fill="#38BDF8", outline="")

        # 5. Digital Score Readout Badge
        color_map = {
            "Safe": "#10B981",
            "Low": "#38BDF8",
            "Moderate": "#F59E0B",
            "High": "#F97316",
            "Critical": "#EF4444",
        }
        text_color = color_map.get(self.rating, "#F8FAFC")

        # Pill background for readability
        badge_y = cy + 15
        badge_text = f"{self.current_score:.1f}  —  {self.rating} Risk"
        self.create_text(
            cx, badge_y,
            text=badge_text,
            fill=text_color,
            font=("Segoe UI", 9, "bold")
        )


class SeverityBarCanvas(tk.Canvas):
    """
    Renders an interactive horizontal telemetry bar indicating proportional
    breakdown of Critical, High, Moderate, Low, and Clean findings.
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
