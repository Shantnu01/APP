# 🎓 RepoGuard &mdash; Quick Viva & Demo Preparation Guide

**Course:** AA1 - Advanced Programming Practices  
**Faculty:** Prof. Salomi Samsudeen  
**Team Members:** Shantnu, Arya Agrawal, Raiyan Kamal  

---

## 💡 1-Minute Elevator Pitch
> *"RepoGuard is an advanced, non-intrusive software supply-chain auditor built with Python, Tkinter, Java, and SQLite. Given any public GitHub repository, it safely streams and inspects dependency manifests (Python, npm, Maven, and Go) 100% in-memory without risky disk extraction. It cross-references packages in parallel against the Open Source Vulnerabilities (OSV) distributed database, computes a composite CVSS-weighted risk score, renders dynamic Tkinter Canvas visual gauges and distribution charts, and exports comprehensive executive reports in CSV, JSON, and standalone HTML."*

---

## 🎤 Individual Viva Talking Points

### 🔹 Shantnu (Team Lead & Core Backend Architect)
**What to emphasize:**
- **Asynchronous Architecture:** How you separated Tkinter's single-threaded event loop from network I/O using daemon worker threads (`threading.Thread(daemon=True)`) and thread-safe queues (`queue.Queue`).
- **Parallel Scanning:** How you utilized `concurrent.futures.ThreadPoolExecutor(max_workers=6)` to query the OSV REST API concurrently, reducing scan latency from 30 seconds to under 4 seconds.
- **In-Memory Security:** Why downloading and unzipping archives directly to disk is dangerous (Zip-Slip and decompression bombs), and how RepoGuard mitigates this by validating paths in-memory using `io.BytesIO` and strict size guards (25 MB max).
- **CLI Pipeline Mode:** How you designed `--cli` mode to allow automated CI/CD pipeline integration without launching the GUI.

### 🔹 Arya Agrawal (Frontend GUI & Data Visualization Engineer)
**What to emphasize:**
- **Dynamic Tkinter Canvas Rendering:** How you implemented custom drawing logic on Tkinter Canvas without external heavy plotting libraries:
  - **Risk Gauge Meter:** Trigonometric arc mapping ($x = cx + r \cdot \cos(\theta)$, $y = cy - r \cdot \sin(\theta)$) to animate a smooth needle pointing to the exact threat rating (0 to 100).
  - **Severity Breakdown Bar:** Dynamic proportional segmentation for Critical (Red), High (Orange), Moderate (Yellow), and Clean (Green) packages.
- **High-DPI Scaling:** How process-level DPI awareness was configured to prevent blurry rendering on Windows displays.
- **Executive HTML Reporting:** How you built the self-contained HTML audit reporter with embedded CSS styling, responsive grid cards, and security tables.

### 🔹 Raiyan Kamal (Database, Java Engine & Multi-Ecosystem Parser)
**What to emphasize:**
- **Java RepoScanner Integration:** Why Java was integrated for Maven parsing (native, strict XML conformance) using `DocumentBuilderFactory` with secure XML processing features enabled (`ACCESS_EXTERNAL_DTD = ""`, `disallow-doctype-decl`).
- **Property Substitution:** How your Java implementation resolved Maven `${property}` version variables by implementing a two-pass DOM traversal.
- **Go Parser & Python Fallback:** How you added Go module (`go.mod`) support and created a resilient pure-Python XML fallback parser for environments without a Java compiler.
- **SQLite Database Architecture:** How you designed normalized tables (`repositories`, `scans`, `dependencies`, `findings`) with cascading foreign keys and connection pooling to prevent database locking on Windows.

---

## ❓ Frequently Asked Viva Questions & Answers

**Q1: Why use OSV instead of NVD (National Vulnerability Database)?**  
*Answer:* OSV (Open Source Vulnerabilities) provides an open, real-time distributed vulnerability database developed by Google and OpenSSF. It has native ecosystem support (PyPI, npm, Maven, Go, etc.) and allows precise package-level and version-level querying with structured Git commit and semver ranges.

**Q2: How does RepoGuard prevent GUI freezing during a scan?**  
*Answer:* Tkinter’s `mainloop()` runs on a single thread. If network calls (`urlopen`) run on that thread, it halts event processing. RepoGuard offloads the entire network pipeline to a background thread. Communication between the background thread and Tkinter occurs exclusively through `queue.Queue` with periodic polling via `self.after(100, self._process_queue_messages)`.

**Q3: How do you protect against Zip-Slip attacks?**  
*Answer:* When reading zip entries in `GitHubEngine`, all file paths are normalized and checked for relative traversal tokens (`..`). Furthermore, the archive is never extracted to physical disk; file bytes are read directly from memory streams.

**Q4: How does the Java and Python inter-process communication work?**  
*Answer:* Python writes the `pom.xml` byte stream to a temporary location and executes the compiled Java class via `subprocess.run(["java", "-cp", "build/classes", "repoguard.scanner.RepoScanner", path])`. Java parses the XML and writes tab-delimited records (`groupId\tartifactId\tversion`) to `stdout`, which Python reads and structures into `Dependency` objects.

---

## 🎬 Recommended 3-Minute Live Demo Flow

1. **Launch:** Double-click `run.bat` (or execute `python main.py`).
2. **Demo Scan:** The input is preloaded with `https://github.com/pralav-25/reposentry-demo`. Click **"Run Security Audit"**.
3. **Observe Live Feedback:** Point out the live progress indicator and status ticker showing packages being scanned in parallel.
4. **Explain Visualizations:**
   - Show the **Risk Gauge needle** pointing to the risk score and color category.
   - Show the **Severity Distribution Bar** highlighting Critical (Red) and High (Orange) dependencies.
   - Show the **Metric Stat Cards** (Total Dependencies, Vulnerable, Clean, Total Advisories).
5. **Interactive Filtering:**
   - Filter by Ecosystem (e.g. switch to "Maven" or "PyPI").
   - Filter by Severity (e.g. "Critical" or "Only Vulnerable").
   - Type in the search box (e.g. `log4j` or `urllib3`).
   - Double-click a row to show the vulnerability advisory opening in the browser.
6. **Exports:** Click **"Export HTML Report"** and open the report to show the printable report.
7. **History Tab:** Switch to the **Audit History** tab to show that the scan was saved into SQLite and can be reloaded instantly.
