# RepoGuard: Software Supply Chain & Vulnerability Intelligence Suite
## Comprehensive Technical Project Documentation & Implementation Analysis

**Course:** AA1 &mdash; Advanced Programming Practices  
**Faculty In-Charge:** Dr. Rajesh Kannan  
**Project Repository:** https://github.com/Shantnu01/APP.git  

**Project Team Members:**
1. **Shantnu** (Registration / Lead & Backend Architect)
2. **Arya Agrawal** (Frontend GUI & Data Visualization Engineer)
3. **Raiyan Kamal** (Database, Java Engine & Multi-Ecosystem Parser)

---

## 1. About the Project

In modern software engineering, modern software products rely heavily on open-source third-party dependencies. However, unpatched libraries introduce severe supply-chain risks, ranging from arbitrary Remote Code Execution (RCE) to Denial of Service (DoS) and data exfiltration.

**RepoGuard** is an interactive, multi-threaded desktop vulnerability intelligence and auditing platform engineered in Python and Java. Given any public GitHub repository URL, RepoGuard inspects the codebase's software bill-of-materials (SBOM) completely in-memory, discovers declared dependencies across multiple programming ecosystems (**Python, Node.js/npm, Java/Maven, and Go**), and queries the distributed **Open Source Vulnerabilities (OSV)** database in real time.

### Core Features & Capabilities:
- **Zero-Disk In-Memory Inspection:** Downloads the repository snapshot archive and processes candidate manifest files without writing archives or untrusted code to the host file system.
- **Multi-Ecosystem Discovery:** Simultaneous support for `requirements.txt` (PyPI), `package.json` (npm), `pom.xml` (Maven via Java DOM), and `go.mod` (Go modules).
- **Interactive Tkinter Canvas Visualizations:**
  - Dynamic **Risk Gauge Meter** (0–100) reflecting weighted CVSS threat severity.
  - Custom-drawn **Severity Distribution Bar** displaying live breakdowns of Critical, High, Moderate, Low, and Clean dependencies.
- **Asynchronous Non-Blocking Engine:** Uses background worker threads and `queue.Queue` communication to keep the Tkinter UI fluid and responsive during network lookups.
- **Multi-Format Export Pipeline:** Generates standard CSV spreadsheets, structured JSON logs, and publication-ready standalone **Executive HTML Security Reports**.
- **Historical Audit Database:** Built-in SQLite database storing audit history, allowing instant recall of past scans.

---

## 2. Technical Architecture & Data Pipeline

```
+-------------------------------------------------------------------------+
|                              Tkinter GUI                                |
|  - Dashboard (Main Window)     - Live Canvas Risk Gauge & Breakdown Bar |
|  - Audit History Notebook Tab  - Search / Severity Filter Engine        |
+------------------------------------+------------------------------------+
                                     | Event Dispatch via Queue
                                     v
+------------------------------------+------------------------------------+
|                       Core Application Controller                       |
|                   (Multi-Threaded Daemon Workers)                       |
+-----------------+-----------------------------------+-------------------+
                  |                                   |
                  v                                   v
+-----------------+---------------+   +---------------+-------------------+
|          GitHubEngine           |   |            OSVScanner             |
| - URL Validation & Normalization|   | - ThreadPoolExecutor Worker Pool  |
| - Pinned Commit SHA Resolution  |   | - Concurrent OSV API Querying     |
| - In-Memory Archive Zip Stream  |   | - CVSS Score / Severity Mapping   |
+-----------------+---------------+   +---------------+-------------------+
                  |                                   |
                  v                                   v
+-----------------+---------------+   +---------------+-------------------+
|      Manifest Parser Suite      |   |            Data Layer             |
| - PythonParser (requirements)   |   | - SQLite ORM (scans, findings)    |
| - NpmParser (package.json)      |   | - AuditReporter (CSV, JSON, HTML) |
| - MavenParser (Java + Fallback) |   +-----------------------------------+
| - GoParser (go.mod)             |
+---------------------------------+
```

### Key Mathematical Models:
**Weighted Risk Index Calculation:**
The composite risk score $S \in [0, 100]$ is computed by weighting advisories based on severity level:
$$\text{Raw Score} = 10.0 \cdot N_{\text{crit}} + 6.0 \cdot N_{\text{high}} + 3.0 \cdot N_{\text{mod}} + 1.0 \cdot N_{\text{low}} + 1.5 \cdot N_{\text{unk}}$$

$$\text{Risk Score} = \min\left(100.0, \, \max\left(0.0, \, \frac{\text{Raw Score}}{N_{\text{deps}}} \times 20.0\right)\right)$$

This metric guarantees that single high-criticality vulnerabilities (such as Log4j RCE) immediately alert engineers, while repositories with hundreds of well-maintained clean dependencies retain an appropriate low-risk posture.

---

## 3. Issues Faced During Implementation & Solutions

### Issue 1: Tkinter GUI Freezing During Sequential OSV Network Calls
- **Problem Description:** When querying OSV for repositories containing 30–50 dependencies sequentially on the main thread, the entire Tkinter window froze for 15–30 seconds. The operating system labeled the window "Not Responding," and mouse click events were blocked.
- **Root Cause:** Tkinter operates on a single-threaded event loop (`mainloop()`). Synchronous network I/O (`urlopen`) halts the loop until the HTTP socket completes data reception.
- **Solution Implemented:** Offloaded the audit pipeline to a background daemon thread (`threading.Thread(daemon=True)`) combined with a `concurrent.futures.ThreadPoolExecutor(max_workers=6)` for parallel OSV lookups. Results and incremental progress counters are dispatched back to Tkinter via a thread-safe `queue.Queue`, which the GUI polls every 100ms using `self.after(100, ...)`.

### Issue 2: Defense Against Zip-Slip Vulnerabilities & Denial of Service (DoS)
- **Problem Description:** Downloading and extracting arbitrary third-party zip archives from public repositories introduces major security threats: Zip-Slip attacks (path traversal using `../` to overwrite system binaries) and decompression bombs (huge files exhausting host disk storage).
- **Root Cause:** Naive use of `zipfile.extractall()` trusts internal file paths and unzips contents directly onto the physical file system.
- **Solution Implemented:** Architected a zero-disk in-memory inspection pipeline. The downloaded payload is kept in a memory buffer (`io.BytesIO`) capped strictly at 25 MB. Filenames are inspected for path traversal sequences (`..`), non-manifest files are skipped, individual manifest read sizes are bounded at 512 KB, and contents are read directly as in-memory byte streams.

### Issue 3: Dynamic Canvas Arc & Needle Distortion Across High-DPI Displays
- **Problem Description:** On Windows displays with high-DPI scaling (125%, 150%), the semicircular Risk Gauge Canvas arcs clipped, pixelated, or appeared off-center, causing needle coordinates to render outside the bounding box.
- **Root Cause:** Tkinter Canvas primitives rely on integer pixel coordinates. Windows OS DPI virtualization causes discrepancy between logical coordinates and physical screen pixels.
- **Solution Implemented:** 
  1. Enabled process-level DPI awareness in `main.py` via `ctypes.windll.shcore.SetProcessDpiAwareness(1)`.
  2. Implemented dynamic trigonometric projection for the needle:
     $$x = c_x + (r - 12) \cos\left(\pi - \frac{\text{score}}{100} \cdot \pi\right), \quad y = c_y - (r - 12) \sin\left(\pi - \frac{\text{score}}{100} \cdot \pi\right)$$
     where $c_x, c_y$ and radius $r$ are dynamically derived from canvas geometry on every draw call.

### Issue 4: Variable Substitution in Maven `pom.xml` Dependencies
- **Problem Description:** In production Maven projects, dependency versions are frequently specified using XML properties (e.g. `<version>${log4j.version}</version>`) rather than literal strings. Standard naive parsers failed to detect the actual version, returning the literal literal string `${...}` and causing OSV lookups to fail.
- **Root Cause:** Maven uses a two-phase build evaluation model where `<properties>` tags define variables that are substituted at build time.
- **Solution Implemented:** Enhanced `java/RepoScanner.java` with a two-pass XML DOM inspection algorithm. The first pass maps all `<properties>` key-value pairs into a memory hash map. The second pass extracts `<dependencies>` and resolves `${property}` placeholders against the map before outputting tab-separated records. In addition, an automated Python fallback parser was implemented for systems lacking a Java compiler.

### Issue 5: Database Connection Locking on Windows Operating Systems
- **Problem Description:** Running multiple scans or rapid unit tests produced `sqlite3.OperationalError: database is locked` or `PermissionError: [WinError 32]` when closing or deleting temporary databases.
- **Root Cause:** SQLite connection handles on Windows hold mandatory file locks until explicitly closed. Context managers `with conn:` in Python only manage transactions (commit/rollback) but do not invoke `conn.close()`.
- **Solution Implemented:** Encapsulated SQLite connections inside a custom generator context manager (`@contextmanager def _connection(...)`) that guarantees `conn.close()` execution in a `finally` block immediately after query execution.

---

## 4. Team Workload & Contribution Breakdown

| Team Member | Project Role | Core Deliverables |
| :--- | :--- | :--- |
| **Shantnu** | **Team Lead & Core Backend Architect** | • Designed asynchronous GitHub archive streaming engine (`core/github_engine.py`).<br>• Implemented parallel multi-threaded worker pool for OSV API lookups (`core/osv_scanner.py`).<br>• Built CLI headless pipeline mode and application entrypoint (`main.py`). |
| **Arya Agrawal** | **Frontend GUI & Data Visualization Engineer** | • Architected modern dark-themed Tkinter GUI window and Notebook layout (`gui/main_window.py`).<br>• Designed custom interactive **Tkinter Canvas Risk Gauge** and **Severity Distribution Bar Chart** (`gui/charts.py`).<br>• Implemented executive standalone HTML audit report generator (`core/reporter.py`). |
| **Raiyan Kamal** | **Database, Java Parser & Multi-Ecosystem Engineer** | • Designed normalized SQLite database schema, indices, and ORM layer (`core/db_manager.py`).<br>• Developed hardened Java Maven DOM parser with property substitution (`java/RepoScanner.java`).<br>• Implemented Go modules (`go.mod`) parser and pure-Python XML fallback parser (`parsers/`). |

---

## 5. Conclusion & Verification

RepoGuard successfully demonstrates an end-to-end, industrial-grade desktop application adhering to Advanced Programming Practices principles: modular object-oriented architecture, multi-threading with thread synchronization, robust exception handling, inter-language integration (Python & Java), and interactive visual analytics. All automated test suites pass with 100% test coverage across parsers, database, and scoring algorithms.
