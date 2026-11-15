"""
RepoGuard Main Desktop Window
Comprehensive Tkinter GUI incorporating dynamic Canvas charts, multi-threaded
background execution, search/filter controls, and multi-format export capabilities.

Authors: Shantnu, Arya Agrawal, Raiyan Kamal
Course: AA1 - Advanced Programming Practices | Prof. Salomi Samsudeen
"""

from __future__ import annotations
import queue
import threading
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from typing import Optional

from core.db_manager import DatabaseManager
from core.github_engine import GitHubEngine, GitHubError
from core.models import (
    DependencyFinding,
    RiskMetrics,
    ScanReport,
    SeverityLevel,
)
from core.osv_scanner import OSVScanner
from core.reporter import AuditReporter
from gui.charts import RiskGaugeCanvas, SeverityBarCanvas
from gui.widgets import StatCard
from parsers import parse_manifests


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RepoGuard - Repository Security & Vulnerability Auditor")
        self.geometry("1100 excavation" if False else "1140x760")
        self.minsize(980, 680)

        # Apply dark theme styling
        self.configure(bg="#0F172A")
        self._setup_styles()

        # Database and state
        self.db = DatabaseManager()
        self.current_report: Optional[ScanReport] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.msg_queue: queue.Queue = queue.Queue()

        self._build_ui()
        self._load_latest_scan_from_db()
        self._process_queue_messages()

    def _setup_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Configure Notebook
        style.configure("TNotebook", background="#0F172A", borderwidth=0)
        style.configure("TNotebook.Tab", background="#1E293B", foreground="#94A3B8",
                        padding=[16, 8], font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", "#38BDF8")],
                  foreground=[("selected", "#0F172A")])

        # Configure Treeview
        style.configure("Treeview",
                        background="#1E293B",
                        foreground="#F8FAFC",
                        fieldbackground="#1E293B",
                        borderwidth=0,
                        font=("Segoe UI", 9),
                        rowheight=26)
        style.configure("Treeview.Heading",
                        background="#0F172A",
                        foreground="#94A3B8",
                        font=("Segoe UI", 9, "bold"),
                        relief="flat")
        style.map("Treeview", background=[("selected", "#334155")], foreground=[("selected", "#38BDF8")])

        # Progressbar
        style.configure("Horizontal.TProgressbar", background="#38BDF8", troughcolor="#1E293B")

    def _build_ui(self):
        # Header banner
        header = tk.Frame(self, bg="#0F172A", padx=20, pady=12)
        header.pack(fill="x")

        title_box = tk.Frame(header, bg="#0F172A")
        title_box.pack(side="left")
        lbl_app = tk.Label(
            title_box, text="REPOGUARD", font=("Segoe UI", 18, "bold"),
            fg="#38BDF8", bg="#0F172A"
        )
        lbl_app.pack(side="left")

        lbl_sub = tk.Label(
            title_box, text=" | Multi-Ecosystem Vulnerability Auditor",
            font=("Segoe UI", 11), fg="#94A3B8", bg="#0F172A"
        )
        lbl_sub.pack(side="left", padx=(4, 0))

        lbl_team = tk.Label(
            header,
            text="Team: Shantnu &bull; Arya Agrawal &bull; Raiyan Kamal (AA1)",
            font=("Segoe UI", 9, "bold"),
            fg="#64748B", bg="#0F172A"
        )
        lbl_team.pack(side="right")

        # Main Notebook
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        # Tab 1: Live Audit Dashboard
        self.tab_dashboard = tk.Frame(self.notebook, bg="#0F172A")
        self.notebook.add(self.tab_dashboard, text="  Live Security Audit  ")

        # Tab 2: Audit History
        self.tab_history = tk.Frame(self.notebook, bg="#0F172A")
        self.notebook.add(self.tab_history, text="  Audit History  ")

        # Tab 3: Project & Team Architecture
        self.tab_about = tk.Frame(self.notebook, bg="#0F172A")
        self.notebook.add(self.tab_about, text="  About & Team  ")

        self._build_dashboard_tab()
        self._build_history_tab()
        self._build_about_tab()

    def _build_dashboard_tab(self):
        parent = self.tab_dashboard

        # 1. URL Input & Action Control Bar
        bar = tk.Frame(parent, bg="#1E293B", padx=15, pady=12, highlightthickness=1, highlightbackground="#334155")
        bar.pack(fill="x", pady=(10, 10))

        tk.Label(bar, text="GitHub URL:", font=("Segoe UI", 10, "bold"), fg="#F8FAFC", bg="#1E293B").pack(side="left", padx=(0, 8))

        self.entry_url = tk.Entry(
            bar, font=("Segoe UI", 10), bg="#0F172A", fg="#F8FAFC",
            insertbackground="#38BDF8", relief="flat", highlightthickness=1, highlightbackground="#475569"
        )
        self.entry_url.pack(side="left", fill="x", expand=True, padx=(0, 10), ipady=4)
        self.entry_url.insert(0, "https://github.com/Shantnu01/APP")

        self.btn_scan = tk.Button(
            bar, text="Run Security Audit", font=("Segoe UI", 9, "bold"),
            bg="#0284C7", fg="#FFFFFF", activebackground="#0369A1", activeforeground="#FFFFFF",
            relief="flat", padx=16, pady=4, cursor="hand2", command=self._start_scan
        )
        self.btn_scan.pack(side="left", padx=(0, 6))

        # Quick Demo Preset button
        btn_preset = tk.Button(
            bar, text="Default Repo", font=("Segoe UI", 9),
            bg="#334155", fg="#CBD5E1", activebackground="#475569", activeforeground="#FFFFFF",
            relief="flat", padx=10, pady=4, cursor="hand2",
            command=lambda: self._set_demo_url("https://github.com/Shantnu01/APP")
        )
        btn_preset.pack(side="left")

        # Progress bar & Status text
        self.status_frame = tk.Frame(parent, bg="#0F172A")
        self.status_frame.pack(fill="x", pady=(0, 8))

        self.lbl_status = tk.Label(
            self.status_frame, text="Ready to audit repository dependencies.",
            font=("Segoe UI", 9), fg="#94A3B8", bg="#0F172A"
        )
        self.lbl_status.pack(side="left")

        self.progress = ttk.Progressbar(self.status_frame, orient="horizontal", mode="determinate", length=220)
        self.progress.pack(side="right")

        # 2. Metrics & Visualizations Row
        viz_row = tk.Frame(parent, bg="#0F172A")
        viz_row.pack(fill="x", pady=(0, 10))

        # Cards frame
        cards_frame = tk.Frame(viz_row, bg="#0F172A")
        cards_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))

        self.card_total = StatCard(cards_frame, "Total Dependencies", "0", "#38BDF8")
        self.card_total.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)

        self.card_vuln = StatCard(cards_frame, "Vulnerable Packages", "0", "#EF4444")
        self.card_vuln.grid(row=0, column=1, sticky="nsew", padx=4, pady=4)

        self.card_clean = StatCard(cards_frame, "Clean Packages", "0", "#10B981")
        self.card_clean.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)

        self.card_advisories = StatCard(cards_frame, "Total Advisories", "0", "#F59E0B")
        self.card_advisories.grid(row=1, column=1, sticky="nsew", padx=4, pady=4)

        cards_frame.grid_columnconfigure(0, weight=1)
        cards_frame.grid_columnconfigure(1, weight=1)

        # Risk Gauge Canvas
        gauge_box = tk.Frame(viz_row, bg="#1E293B", highlightthickness=1, highlightbackground="#334155", padx=10, pady=8)
        gauge_box.pack(side="left", padx=(0, 10))
        tk.Label(gauge_box, text="SECURITY RISK METER", font=("Segoe UI", 8, "bold"), fg="#94A3B8", bg="#1E293B").pack(anchor="w")
        self.gauge = RiskGaugeCanvas(gauge_box, width=220, height=105, bg="#1E293B")
        self.gauge.pack()

        # Severity Breakdown Bar Canvas
        bar_box = tk.Frame(viz_row, bg="#1E293B", highlightthickness=1, highlightbackground="#334155", padx=12, pady=8)
        bar_box.pack(side="left", fill="both", expand=True)
        tk.Label(bar_box, text="SEVERITY DISTRIBUTION", font=("Segoe UI", 8, "bold"), fg="#94A3B8", bg="#1E293B").pack(anchor="w")
        self.sev_bar = SeverityBarCanvas(bar_box, width=320, height=85, bg="#1E293B")
        self.sev_bar.pack(fill="both", expand=True)

        # 3. Filter and Search Bar
        filter_bar = tk.Frame(parent, bg="#0F172A")
        filter_bar.pack(fill="x", pady=(0, 6))

        tk.Label(filter_bar, text="Filter:", font=("Segoe UI", 9, "bold"), fg="#94A3B8", bg="#0F172A").pack(side="left", padx=(0, 6))

        self.combo_eco = ttk.Combobox(filter_bar, values=["All Ecosystems", "PyPI", "npm", "Maven", "Go"], state="readonly", width=14)
        self.combo_eco.set("All Ecosystems")
        self.combo_eco.pack(side="left", padx=(0, 10))
        self.combo_eco.bind("<<ComboboxSelected>>", lambda e: self._apply_filters())

        self.combo_sev = ttk.Combobox(filter_bar, values=["All Severities", "Only Vulnerable", "Critical", "High", "Moderate", "Clean"], state="readonly", width=14)
        self.combo_sev.set("All Severities")
        self.combo_sev.pack(side="left", padx=(0, 10))
        self.combo_sev.bind("<<ComboboxSelected>>", lambda e: self._apply_filters())

        tk.Label(filter_bar, text="Search:", font=("Segoe UI", 9, "bold"), fg="#94A3B8", bg="#0F172A").pack(side="left", padx=(10, 6))

        self.entry_search = tk.Entry(filter_bar, font=("Segoe UI", 9), bg="#1E293B", fg="#F8FAFC", insertbackground="#38BDF8", relief="flat")
        self.entry_search.pack(side="left", fill="x", expand=True, padx=(0, 10), ipady=2)
        self.entry_search.bind("<KeyRelease>", lambda e: self._apply_filters())

        # 4. Findings Treeview
        tree_frame = tk.Frame(parent, bg="#1E293B", highlightthickness=1, highlightbackground="#334155")
        tree_frame.pack(fill="both", expand=True)

        columns = ("eco", "pkg", "ver", "sev", "adv_id", "summary", "manifest")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("eco", text="Ecosystem", anchor="w")
        self.tree.heading("pkg", text="Package Name", anchor="w")
        self.tree.heading("ver", text="Version", anchor="w")
        self.tree.heading("sev", text="Severity", anchor="center")
        self.tree.heading("adv_id", text="Advisory ID", anchor="w")
        self.tree.heading("summary", text="Vulnerability Summary", anchor="w")
        self.tree.heading("manifest", text="Source Manifest", anchor="w")

        self.tree.column("eco", width=80, stretch=False)
        self.tree.column("pkg", width=150)
        self.tree.column("ver", width=90, stretch=False)
        self.tree.column("sev", width=95, anchor="center", stretch=False)
        self.tree.column("adv_id", width=130, stretch=False)
        self.tree.column("summary", width=360)
        self.tree.column("manifest", width=160)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", self._on_tree_double_click)

        # Tag configurations for colors
        self.tree.tag_configure("CRITICAL", foreground="#EF4444")
        self.tree.tag_configure("HIGH", foreground="#F97316")
        self.tree.tag_configure("MODERATE", foreground="#F59E0B")
        self.tree.tag_configure("LOW", foreground="#60A5FA")
        self.tree.tag_configure("CLEAN", foreground="#10B981")
        self.tree.tag_configure("UNKNOWN", foreground="#94A3B8")

        # 5. Bottom Export Actions Bar
        bottom_bar = tk.Frame(parent, bg="#0F172A", pady=6)
        bottom_bar.pack(fill="x")

        tk.Label(
            bottom_bar, text="Tip: Double-click any row to view advisory online in browser.",
            font=("Segoe UI", 8, "italic"), fg="#64748B", bg="#0F172A"
        ).pack(side="left")

        btn_html = tk.Button(
            bottom_bar, text="Export HTML Report", font=("Segoe UI", 9, "bold"),
            bg="#059669", fg="#FFFFFF", relief="flat", padx=12, pady=3, cursor="hand2",
            command=self._export_html
        )
        btn_html.pack(side="right", padx=(6, 0))

        btn_json = tk.Button(
            bottom_bar, text="Export JSON", font=("Segoe UI", 9),
            bg="#334155", fg="#F8FAFC", relief="flat", padx=10, pady=3, cursor="hand2",
            command=self._export_json
        )
        btn_json.pack(side="right", padx=(6, 0))

        btn_csv = tk.Button(
            bottom_bar, text="Export CSV", font=("Segoe UI", 9),
            bg="#334155", fg="#F8FAFC", relief="flat", padx=10, pady=3, cursor="hand2",
            command=self._export_csv
        )
        btn_csv.pack(side="right")

    def _build_history_tab(self):
        parent = self.tab_history
        box = tk.Frame(parent, bg="#1E293B", padx=15, pady=15, highlightthickness=1, highlightbackground="#334155")
        box.pack(fill="both", expand=True, padx=10, pady=10)

        top_hist = tk.Frame(box, bg="#1E293B")
        top_hist.pack(fill="x", pady=(0, 10))

        tk.Label(top_hist, text="Recorded Repository Scans", font=("Segoe UI", 12, "bold"), fg="#F8FAFC", bg="#1E293B").pack(side="left")

        btn_refresh = tk.Button(
            top_hist, text="Refresh History", font=("Segoe UI", 9),
            bg="#334155", fg="#CBD5E1", relief="flat", padx=10, pady=3, cursor="hand2",
            command=self._refresh_history_list
        )
        btn_refresh.pack(side="right", padx=(6, 0))

        btn_clear = tk.Button(
            top_hist, text="Clear History", font=("Segoe UI", 9),
            bg="#991B1B", fg="#FFFFFF", relief="flat", padx=10, pady=3, cursor="hand2",
            command=self._clear_history
        )
        btn_clear.pack(side="right")

        cols = ("id", "repo", "sha", "time", "deps", "findings", "risk")
        self.hist_tree = ttk.Treeview(box, columns=cols, show="headings", selectmode="browse")
        self.hist_tree.heading("id", text="Scan ID", anchor="w")
        self.hist_tree.heading("repo", text="Repository", anchor="w")
        self.hist_tree.heading("sha", text="Commit SHA", anchor="w")
        self.hist_tree.heading("time", text="Timestamp (UTC)", anchor="w")
        self.hist_tree.heading("deps", text="Dependencies", anchor="center")
        self.hist_tree.heading("findings", text="Vulnerabilities", anchor="center")
        self.hist_tree.heading("risk", text="Risk Rating", anchor="center")

        self.hist_tree.column("id", width=60, stretch=False)
        self.hist_tree.column("repo", width=260)
        self.hist_tree.column("sha", width=110, stretch=False)
        self.hist_tree.column("time", width=180)
        self.hist_tree.column("deps", width=95, anchor="center", stretch=False)
        self.hist_tree.column("findings", width=105, anchor="center", stretch=False)
        self.hist_tree.column("risk", width=100, anchor="center", stretch=False)

        hist_scroll = ttk.Scrollbar(box, orient="vertical", command=self.hist_tree.yview)
        self.hist_tree.configure(yscrollcommand=hist_scroll.set)

        self.hist_tree.pack(side="left", fill="both", expand=True)
        hist_scroll.pack(side="right", fill="y")

        btn_load = tk.Button(
            parent, text="Load Selected Scan into Dashboard", font=("Segoe UI", 10, "bold"),
            bg="#0284C7", fg="#FFFFFF", relief="flat", padx=16, pady=6, cursor="hand2",
            command=self._load_selected_history_scan
        )
        btn_load.pack(pady=(0, 10))

    def _build_about_tab(self):
        parent = self.tab_about
        box = tk.Frame(parent, bg="#1E293B", padx=25, pady=25, highlightthickness=1, highlightbackground="#334155")
        box.pack(fill="both", expand=True, padx=15, pady=15)

        tk.Label(box, text="RepoGuard: Multi-Ecosystem Security & Dependency Auditor", font=("Segoe UI", 16, "bold"), fg="#38BDF8", bg="#1E293B").pack(anchor="w")
        tk.Label(box, text="Course: AA1 - Advanced Programming Practices  |  Faculty: Prof. Salomi Samsudeen", font=("Segoe UI", 11, "bold"), fg="#CBD5E1", bg="#1E293B").pack(anchor="w", pady=(4, 15))

        desc = (
            "RepoGuard is an advanced desktop software quality and security audit suite designed to inspect public "
            "GitHub repositories for open-source software supply chain vulnerabilities. Operating completely in-memory "
            "without risky disk extraction, RepoGuard analyzes Python (requirements.txt), JavaScript/Node.js (package.json), "
            "Java/Maven (pom.xml), and Go (go.mod) dependencies, cross-referencing findings in real time against the "
            "Open Source Vulnerabilities (OSV) distributed database.\n\n"
            "Key Engineering Highlights:\n"
            "• Asynchronous Multi-Threading: Background worker pool ensures zero GUI blocking during network fetches.\n"
            "• In-Memory Archive Inspection: Protects against directory traversal (zip-slip) attacks by validating paths in-RAM.\n"
            "• Java-Python Dual Engine: Native Java XML DOM processor resolves Maven POMs with properties substitution.\n"
            "• Dynamic Canvas Visualizations: Custom Tkinter Canvas spline gauges and distribution charts.\n"
            "• Tri-Format Reporting: Generates CSV, structured JSON, and self-contained executive HTML audit reports."
        )
        lbl_desc = tk.Label(box, text=desc, font=("Segoe UI", 10), fg="#94A3B8", bg="#1E293B", justify="left", wraplength=950)
        lbl_desc.pack(anchor="w", pady=(0, 20))

        # Team Cards
        team_frame = tk.Frame(box, bg="#1E293B")
        team_frame.pack(fill="x")

        members = [
            ("Shantnu", "Team Lead & Core Backend Architect", "GitHub snapshot engine, thread pool scheduler, OSV REST API pipeline, asynchronous execution."),
            ("Arya Agrawal", "Frontend GUI & Data Visualization Engineer", "Modern Tkinter UI layout, custom Canvas dynamic risk gauge & severity distribution bar chart, interactive filtering."),
            ("Raiyan Kamal", "Database & Multi-Ecosystem Engineer", "SQLite schema design, transactions, Java RepoScanner XML DOM engine, and Go/Maven parser extractors."),
        ]

        for name, role, details in members:
            card = tk.Frame(team_frame, bg="#0F172A", padx=15, pady=12, highlightthickness=1, highlightbackground="#334155")
            card.pack(side="left", fill="both", expand=True, padx=6)
            tk.Label(card, text=name, font=("Segoe UI", 12, "bold"), fg="#38BDF8", bg="#0F172A").pack(anchor="w")
            tk.Label(card, text=role, font=("Segoe UI", 9, "bold"), fg="#E2E8F0", bg="#0F172A").pack(anchor="w", pady=(2, 6))
            tk.Label(card, text=details, font=("Segoe UI", 8), fg="#94A3B8", bg="#0F172A", wraplength=260, justify="left").pack(anchor="w")

    def _set_demo_url(self, url: str):
        self.entry_url.delete(0, tk.END)
        self.entry_url.insert(0, url)

    def _start_scan(self):
        url = self.entry_url.get().strip()
        if not url:
            messagebox.showwarning("Input Required", "Please enter a valid GitHub repository URL.")
            return

        self.btn_scan.config(state="disabled", text="Auditing...")
        self.progress.config(mode="indeterminate")
        self.progress.start(10)
        self.lbl_status.config(text=f"Connecting to GitHub: {url}...")

        # Spawn daemon thread to avoid blocking Tkinter main loop
        self.scan_thread = threading.Thread(target=self._run_audit_pipeline, args=(url,), daemon=True)
        self.scan_thread.start()

    def _run_audit_pipeline(self, url: str):
        try:
            owner, repo, canonical = GitHubEngine.parse_repo_url(url)
            self.msg_queue.put(("status", f"Resolving latest commit SHA for {owner}/{repo}..."))

            engine = GitHubEngine()
            commit_sha = engine.get_commit_sha(owner, repo)

            self.msg_queue.put(("status", f"Downloading repository snapshot ({commit_sha[:8]})..."))
            manifests = engine.fetch_manifest_files(owner, repo, commit_sha)

            if not manifests:
                self.msg_queue.put(("error", "No supported manifest files (requirements.txt, package.json, pom.xml, go.mod) found in repository."))
                return

            self.msg_queue.put(("status", f"Parsing {len(manifests)} manifest files..."))
            dependencies = parse_manifests(manifests)

            if not dependencies:
                self.msg_queue.put(("error", "Found manifests, but could not identify any pinned dependencies to audit."))
                return

            self.msg_queue.put(("status", f"Auditing {len(dependencies)} dependencies via OSV vulnerability database..."))

            def on_progress(done, total, current):
                self.msg_queue.put(("progress", (done, total, current)))

            scanner = OSVScanner()
            findings = scanner.scan_dependencies(dependencies, progress_callback=on_progress)

            metrics = RiskMetrics.calculate(findings)

            report = ScanReport(
                repo_url=canonical,
                owner=owner,
                repo_name=repo,
                commit_sha=commit_sha,
                scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                status="COMPLETED",
                findings=findings,
                metrics=metrics,
            )

            # Persist to local database
            scan_id = self.db.save_scan(report)
            report.scan_id = scan_id

            self.msg_queue.put(("scan_complete", report))

        except GitHubError as ge:
            self.msg_queue.put(("error", str(ge)))
        except Exception as ex:
            self.msg_queue.put(("error", f"Unexpected scan failure: {ex}"))

    def _process_queue_messages(self):
        """Processes messages posted from background thread onto the Tkinter main thread."""
        try:
            while not self.msg_queue.empty():
                msg_type, payload = self.msg_queue.get_nowait()

                if msg_type == "status":
                    self.lbl_status.config(text=str(payload))

                elif msg_type == "progress":
                    done, total, current = payload
                    self.progress.stop()
                    self.progress.config(mode="determinate", maximum=total, value=done)
                    self.lbl_status.config(text=f"Audited [{done}/{total}]: {current}")

                elif msg_type == "scan_complete":
                    self.progress.stop()
                    self.progress.config(mode="determinate", value=100)
                    self.btn_scan.config(state="normal", text="Run Security Audit")
                    self.lbl_status.config(text="Audit completed successfully. Findings updated.")
                    self._display_report(payload)
                    self._refresh_history_list()

                elif msg_type == "error":
                    self.progress.stop()
                    self.btn_scan.config(state="normal", text="Run Security Audit")
                    self.lbl_status.config(text="Audit stopped due to an error.")
                    messagebox.showerror("Audit Notice", str(payload))

        finally:
            self.after(100, self._process_queue_messages)

    def _display_report(self, report: ScanReport):
        self.current_report = report
        m = report.metrics

        # Update Stat Cards
        self.card_total.set_value(str(m.total_dependencies))
        self.card_vuln.set_value(str(m.vulnerable_dependencies), "#EF4444" if m.vulnerable_dependencies > 0 else "#10B981")
        self.card_clean.set_value(str(m.clean_dependencies))
        self.card_advisories.set_value(str(m.total_vulnerabilities), "#F59E0B" if m.total_vulnerabilities > 0 else "#10B981")

        # Update Visual Canvas Charts
        self.gauge.set_score(m.risk_score, m.risk_rating)
        self.sev_bar.update_metrics(m)

        # Refresh Treeview
        self._apply_filters()

    def _apply_filters(self):
        if not self.current_report:
            return

        self.tree.delete(*self.tree.get_children())
        sel_eco = self.combo_eco.get()
        sel_sev = self.combo_sev.get()
        search_kw = self.entry_search.get().strip().lower()

        for finding in self.current_report.findings:
            dep = finding.dependency

            # Ecosystem filter
            if sel_eco != "All Ecosystems" and dep.ecosystem.lower() != sel_eco.lower():
                continue

            if not finding.vulnerabilities:
                # Clean dependency
                if sel_sev in ("Critical", "High", "Moderate", "Only Vulnerable"):
                    continue

                # Search keyword matching
                if search_kw and search_kw not in dep.name.lower() and search_kw not in dep.manifest_path.lower():
                    continue

                self.tree.insert(
                    "", tk.END,
                    values=(dep.ecosystem, dep.name, dep.version, "CLEAN", "-", "No known advisories found", dep.manifest_path),
                    tags=("CLEAN",)
                )
            else:
                for v in finding.vulnerabilities:
                    # Severity filter
                    if sel_sev == "Clean":
                        continue
                    if sel_sev == "Critical" and v.severity != SeverityLevel.CRITICAL:
                        continue
                    if sel_sev == "High" and v.severity != SeverityLevel.HIGH:
                        continue
                    if sel_sev == "Moderate" and v.severity != SeverityLevel.MODERATE:
                        continue

                    # Search keyword matching
                    row_text = f"{dep.name} {v.advisory_id} {v.summary} {dep.manifest_path}".lower()
                    if search_kw and search_kw not in row_text:
                        continue

                    self.tree.insert(
                        "", tk.END,
                        values=(dep.ecosystem, dep.name, dep.version, v.severity.value, v.advisory_id, v.summary, dep.manifest_path),
                        tags=(v.severity.value,)
                    )

    def _on_tree_double_click(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id:
            return
        values = self.tree.item(item_id, "values")
        if not values or len(values) < 5:
            return
        adv_id = values[4]
        if adv_id and adv_id != "-":
            # Search current report for URL
            ref_url = f"https://osv.dev/vulnerability/{adv_id}"
            if self.current_report:
                for f in self.current_report.findings:
                    for v in f.vulnerabilities:
                        if v.advisory_id == adv_id and v.reference_url:
                            ref_url = v.reference_url
                            break
            webbrowser.open_new_tab(ref_url)

    def _export_csv(self):
        if not self.current_report:
            messagebox.showinfo("Export", "No active scan findings to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Spreadsheet", "*.csv")],
            initialfile=f"repoguard_{self.current_report.repo_name}_audit.csv"
        )
        if path:
            AuditReporter.export_csv(self.current_report, path)
            messagebox.showinfo("Export Successful", f"Audit data exported to:\n{path}")

    def _export_json(self):
        if not self.current_report:
            messagebox.showinfo("Export", "No active scan findings to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON File", "*.json")],
            initialfile=f"repoguard_{self.current_report.repo_name}_audit.json"
        )
        if path:
            AuditReporter.export_json(self.current_report, path)
            messagebox.showinfo("Export Successful", f"Audit data exported to:\n{path}")

    def _export_html(self):
        if not self.current_report:
            messagebox.showinfo("Export", "No active scan findings to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html")],
            initialfile=f"repoguard_{self.current_report.repo_name}_report.html"
        )
        if path:
            AuditReporter.export_html(self.current_report, path)
            if messagebox.askyesno("Export Successful", "Report generated! Open in web browser now?"):
                webbrowser.open_new_tab(Path(path).as_uri())

    def _load_latest_scan_from_db(self):
        recent = self.db.get_recent_scans(limit=1)
        if recent:
            last_id = recent[0]["scan_id"]
            report = self.db.load_scan(last_id)
            if report:
                self._display_report(report)
        self._refresh_history_list()

    def _refresh_history_list(self):
        self.hist_tree.delete(*self.hist_tree.get_children())
        scans = self.db.get_recent_scans(limit=50)
        for s in scans:
            self.hist_tree.insert(
                "", tk.END,
                values=(
                    s["scan_id"],
                    f"{s['owner']}/{s['repo_name']}",
                    s["commit_sha"][:8],
                    s["scanned_at"],
                    s["dependency_count"],
                    s["finding_count"],
                    f"{s['risk_rating']} ({s['risk_score']})",
                )
            )

    def _load_selected_history_scan(self):
        selected = self.hist_tree.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select a historical scan to load.")
            return
        vals = self.hist_tree.item(selected[0], "values")
        scan_id = int(vals[0])
        report = self.db.load_scan(scan_id)
        if report:
            self._display_report(report)
            self.notebook.select(self.tab_dashboard)
            self.lbl_status.config(text=f"Loaded archived audit #{scan_id} ({report.owner}/{report.repo_name}).")

    def _clear_history(self):
        if messagebox.askyesno("Confirm Clear", "Are you sure you want to delete all historical scans?"):
            self.db.clear_all()
            self._refresh_history_list()
