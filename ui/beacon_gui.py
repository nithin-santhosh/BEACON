import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import threading
from datetime import datetime
import psutil
import os

from forensics.hash_lookup import lookup_hash
from forensics.case_index import append_case_index
from detection.risk_assessment import compute_risk_level
from detection.threat_classifier import classify_threat
from sandbox.runner import run_sample
from features.extractor import extract_features
from detection.heuristics import heuristic_classify
from report.pdf_report import generate_pdf_report
from forensics.hash_utils import compute_hashes


# ----------------- THEME -----------------
BG = "#FAF7F2"
PRIMARY = "#1F3A5F"
ACCENT = "#4CAF50"
BENIGN = "#2E7D32"
SUSPICIOUS = "#C62828"
CARD = "#FFFFFF"
LOG_BG = "#0F172A"
LOG_FG = "#E5E7EB"
MUTED = "#6B7280"
HOVER = "#2C5282"
TEXT = "#2B2B2B"


# ----------------- BEHAVIOR TIMELINE -----------------
class BehaviorTimeline:
    def __init__(self):
        self.events = []
        self.custody = []

    def add(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.events.append((ts, msg))

    def add_custody(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.custody.append((ts, msg))
    
    def get(self):
        return self.events

    def as_text(self):
        return "\n".join(f"{t} - {m}" for t, m in self.events)

    def as_chain_of_custody(self):
       return "\n".join(f"{t} : {m}" for t, m in self.custody)

class BeaconGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BEACON — Behavioral Backdoor Detection")
        self.root.geometry("960x760")
        self.root.configure(bg=BG)

        self.sample_path = None
        self.latest_features = None
        self.latest_decision = None
        self.latest_reason = None
        self.latest_threat = None
        self.latest_confidence = None
        self.risk_level = None
        self.analysis_pid = None

        self.cancel_event = threading.Event()
        self.analysis_thread = None


        self.evidence = {}
        #self.timeline = BehaviorTimeline()
        self.analyst_notes = ""

        self.setup_styles()
        self.build_ui()

    # ---------------- TERMINOLOGY FIX ----------------
    def display_verdict(self, verdict):
        return "SAFE" if verdict == "BENIGN" else verdict
    # ---------------- VERDICT COLOR MAPPING ----------------
    def verdict_color(self, verdict):
        if verdict == "SAFE":
            return BENIGN          # green
        elif verdict == "SUSPICIOUS":
            return "#F57C00"       # orange
        elif verdict == "BLOCKED":
            return SUSPICIOUS      # red
        return PRIMARY

    # ---------------- STYLES ----------------
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Beacon.TButton",
            font=("Segoe UI", 11, "bold"),
            padding=(16, 8),
            background=PRIMARY,
            foreground="white"
        )
        style.map("Beacon.TButton", background=[("active", HOVER)])

    # ---------------- UI BUILD ----------------
    def build_ui(self):
        header = tk.Frame(self.root, bg=PRIMARY)
        header.pack(fill="x")
        tk.Label(
            header,
            text="BEACON — Dynamic Behavioral Backdoor Detection",
            bg=PRIMARY, fg="white",
            font=("Segoe UI", 18, "bold")
        ).pack(pady=14)

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.analysis_tab = tk.Frame(notebook, bg=BG)
        self.report_tab = tk.Frame(notebook, bg=BG)

        notebook.add(self.analysis_tab, text="Analysis")
        notebook.add(self.report_tab, text="Forensic Report")

        self.build_analysis_tab()
        self.build_report_tab()

    # ---------------- ANALYSIS TAB ----------------
    def build_analysis_tab(self):
        card = self.card(self.analysis_tab, "1) Select Executable")
        row = tk.Frame(card, bg=CARD)
        row.pack(fill="x", padx=12, pady=8)

        case_row = tk.Frame(card, bg=CARD)
        case_row.pack(fill="x", padx=12, pady=(8, 0))

        tk.Label(
            case_row,
            text="Case ID:",
            bg=CARD,
            fg=TEXT
        ).pack(side="left")

        self.case_id_entry = tk.Entry(case_row, width=30)
        self.case_id_entry.pack(side="left", padx=8 ,pady=8)


        self.browse_button = ttk.Button(
            row,
            text="Browse",
            command=self.select_file,
            style="Beacon.TButton"
        )
        self.browse_button.pack(side="left")

        self.file_label = tk.Label(row, text="No file selected", bg=CARD, fg=MUTED)
        self.file_label.pack(side="left", padx=12)

        card = self.card(self.analysis_tab, "2) Analyze")
        row = tk.Frame(card, bg=CARD)
        row.pack(fill="x", padx=12, pady=8)

        self.analyze_button = ttk.Button(
            row,
            text="Analyze Program",
            command=self.start_analysis,
            style="Beacon.TButton"
        )
        self.analyze_button.pack(side="left")

        self.cancel_btn = ttk.Button(
            row, text="Cancel",
            command=self.cancel_analysis,
            style="Beacon.TButton",
            state="disabled"
        )
        self.cancel_btn.pack(side="left", padx=8)

        self.status_label = tk.Label(row, text="Status: Idle", bg=CARD, fg=MUTED)
        self.status_label.pack(side="left", padx=12)

        self.progress = ttk.Progressbar(card, mode="indeterminate", length=300,maximum=100)
        self.progress.pack(pady=8)

        card = self.card(self.analysis_tab, "3) Result")
        self.result_label = tk.Label(card, text="Verdict: N/A",
                                     bg=CARD, fg=PRIMARY,
                                     font=("Segoe UI", 16, "bold"))
        self.result_label.pack(anchor="w", padx=12, pady=8)

        self.threat_label = tk.Label(card, text="Threat Type: N/A", bg=CARD, fg=TEXT)
        self.threat_label.pack(anchor="w", padx=12)

        self.risk_label = tk.Label(card, text="Risk Level: N/A",
                                   bg=CARD, fg=TEXT,
                                   font=("Segoe UI", 12, "bold"))
        self.risk_label.pack(anchor="w", padx=12, pady=8)

        card = self.card(self.analysis_tab, "Live Analysis Log")
        self.log_box = scrolledtext.ScrolledText(card, height=8, bg=LOG_BG, fg=LOG_FG)
        self.log_box.pack(fill="x", padx=12, pady=8)
        self.log_box.configure(state="disabled")

        #card = self.card(self.analysis_tab, "Behavior Timeline")
        #self.timeline_box = scrolledtext.ScrolledText(card, height=7, bg="#FFFDF9", fg=TEXT)
        #self.timeline_box.pack(fill="x", padx=12, pady=8)
        #self.timeline_box.configure(state="disabled")

    # ---------------- REPORT TAB ----------------
    def build_report_tab(self):
        card = self.card(self.report_tab, "Forensic Report Summary")

        self.report_view = scrolledtext.ScrolledText(card, height=14, bg="#FFFDF9", fg=TEXT)
        self.report_view.pack(fill="x", padx=12)
        self.report_view.configure(state="disabled")

        tk.Label(card, text="Analyst Notes", bg=CARD, fg=PRIMARY,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12, pady=(10, 4))

        self.notes_box = scrolledtext.ScrolledText(card, height=6, bg="#FFFDF9", fg=TEXT)
        self.notes_box.pack(fill="x", padx=12)
        tk.Label(
            card,
            text=(
                "Disclaimer:\n"
                "A verdict of SAFE indicates no suspicious behavior was observed "
                "during monitored execution. SAFE does NOT imply the file is trusted, "
                "benign in all contexts, or free from dormant or time-delayed threats.\n"
                "Final determination should be made by a forensic analyst."
            ),
            bg=CARD,
            fg=MUTED,
            wraplength=850,
            justify="left",
            font=("Segoe UI", 9, "italic")
        ).pack(anchor="w", padx=12, pady=(5, 10))


        ttk.Button(card, text="Download PDF Report",
                   command=self.generate_report,
                   style="Beacon.TButton").pack(anchor="w", padx=12, pady=12)

    # ---------------- HELPERS ----------------
    def card(self, parent, title):
        frame = tk.Frame(parent, bg=CARD, highlightthickness=1,
                         highlightbackground="#E5E7EB")
        frame.pack(fill="x", padx=12, pady=8)
        tk.Label(frame, text=title, bg=CARD, fg=PRIMARY,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12, pady=6)
        return frame

    def log(self, msg):
        self.log_box.configure(state="normal")
        self.log_box.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log_box.see(tk.END)
        self.log_box.configure(state="disabled")

    def timeline_event(self, msg):
        self.timeline.add(msg)
        self.log(msg)

    # ---------------- ACTIONS ----------------
    def select_file(self):
        path = filedialog.askopenfilename(filetypes=[("Executable Files", "*.exe")])
        if path:
            self.sample_path = path
            self.file_label.config(text=path, fg=PRIMARY)
            self.log(f"Selected executable: {path}")

    def start_analysis(self):
        self.cancel_event.clear()
        self.cancel_btn.config(state="normal")
        if not self.sample_path:
            messagebox.showwarning("Warning", "Select an executable first.")
            return

        self.evidence = compute_hashes(self.sample_path)
        self.timeline = BehaviorTimeline()
        self.timeline_event("Evidence hashes computed")
        #self.timeline.add("Evidence hashes computed")
        self.timeline.add_custody(
            f"Evidence acquired from disk: {self.sample_path}"
        )
        self.timeline.add_custody(
            "Cryptographic hashes (SHA-256, MD5) computed prior to execution"
        )


        malware_info = lookup_hash(self.evidence.get("sha256"))

        if malware_info:
            self.timeline_event(
                f"Known malware detected by hash match: {malware_info['name']}"
            )
            self.latest_decision = "SUSPICIOUS"
            self.latest_reason = "Matched known malware hash"
        
        
        self.progress.start()
        self.analyze_button.config(state="disabled")
        self.browse_button.config(state="disabled")
        self.result_label.config(text="Verdict: Analyzing", fg=PRIMARY)
        self.status_label.config(text="Status: Analyzing", fg=PRIMARY)
        self.analysis_thread = threading.Thread(target=self.run_detection, daemon=True)
        self.analysis_thread.start()

    def cancel_analysis(self):
        # Prevent double-cancel
        if self.cancel_event.is_set():
            return

        self.log("Analysis cancellation requested by analyst")
        self.timeline_event("Analysis cancelled by analyst")
        self.timeline.add_custody("Analysis aborted by analyst; evidence preserved in current state")


        # Signal worker thread to stop
        self.cancel_event.set()

        # Terminate running process if exists
        if self.analysis_pid:
            try:
                proc = psutil.Process(self.analysis_pid)
                for child in proc.children(recursive=True):
                    try:
                        child.terminate()
                    except psutil.NoSuchProcess:
                        pass
                proc.terminate()
                self.log("Running process terminated due to cancellation")
            except psutil.NoSuchProcess:
                self.log("Process already terminated")

        # ---- UI RESET (THIS WAS MISSING) ----
        self.progress.stop()
        self.status_label.config(text="Status: Cancelled", fg=SUSPICIOUS)
        self.result_label.config(text="Verdict: CANCELLED", fg=SUSPICIOUS)

        # Re-enable controls
        self.browse_button.config(state="normal")
        self.analyze_button.config(state="normal")
        self.cancel_btn.config(state="disabled")

        # Allow fresh analysis
        self.cancel_event.clear()
        self.analysis_pid = None



    def run_detection(self):
        try:
            # ---- Step 1: Launch sample ----
            if self.cancel_event.is_set():
                self.timeline_event("Analysis aborted before execution")
                return

            self.timeline_event("Process execution started")
            #self.timeline.add("Process execution started")
            self.timeline.add_custody(
                "Evidence subjected to controlled execution in sandbox environment"
            )
            pid = run_sample(self.sample_path, label=0)

            if pid is None:
                self.timeline_event("Failed to launch process")
                return

            self.analysis_pid = pid
            self.timeline_event(f"Process launched (PID {pid})")
            #self.timeline.add(f"Process launched (PID {pid})")
            self.timeline.add_custody(
                f"Runtime process associated with evidence (PID {pid})"
            )


            if self.cancel_event.is_set():
                self.timeline_event("Analysis cancelled after process launch")
                return

            # ---- Step 2: Feature extraction ----
            features = extract_features(label=0)
            self.timeline_event("Behavioral features extracted")

            if self.cancel_event.is_set():
                self.timeline_event("Analysis cancelled before classification")
                return

            # ---- Step 3: Classification ----
            decision, reason = heuristic_classify(features)
            threat, confidence = classify_threat(features)

            self.timeline_event(f"Heuristic verdict: {decision}")

            if self.cancel_event.is_set():
                self.timeline_event("Analysis cancelled after classification")
                return

            # ---- Step 4: Containment (early runtime blocking) ----
            if decision == "SUSPICIOUS" and pid:
                self.timeline_event("Suspicious behavior detected")
                #self.timeline.add("Suspicious behavior detected")
                self.timeline.add_custody(
                    "Execution contained due to suspicious activity"
                )


                try:
                    proc = psutil.Process(pid)
                    for child in proc.children(recursive=True):
                        try:
                            child.terminate()
                        except psutil.NoSuchProcess:
                            pass
                    proc.terminate()

                    decision = "BLOCKED"
                    reason = "Execution terminated due to suspicious behavior"
                    self.timeline_event("Process terminated (containment)")
                except psutil.NoSuchProcess:
                    self.timeline_event("Process already terminated")

            # Recompute hashes AFTER execution
            post_exec_hashes = compute_hashes(self.sample_path)

            if post_exec_hashes.get("sha256") != self.evidence.get("sha256"):
                self.timeline_event("Hash mismatch detected after execution")
                self.latest_reason += " | Binary modified during execution"


            # ---- Step 5: Store results ----
            self.latest_features = features
            self.latest_decision = decision
            self.latest_reason = reason
            self.latest_threat = threat
            self.latest_confidence = confidence
            self.risk_level = compute_risk_level(decision)

            self.timeline_event("Analysis completed")
            #self.timeline.add("Analysis completed")
            self.timeline.add_custody(
                "Evidence state preserved and analysis concluded"
            )

            if not self.cancel_event.is_set():
                self.root.after(0, self.update_ui)

        finally:
            # Always reset cancel button + allow re-analysis
            self.root.after(0, lambda: self.cancel_btn.config(state="disabled"))
            self.root.after(0, lambda: self.analyze_button.config(state="normal"))


    def update_ui(self):
        self.progress.stop()

        verdict_text = self.display_verdict(self.latest_decision)
        self.result_label.config(
            text=f"Verdict: {verdict_text}",
            fg=self.verdict_color(verdict_text)
        )
        self.threat_label.config(
            text=f"Threat Type: {self.latest_threat} / Confidence Level: ({self.latest_confidence})"
        )
        self.risk_label.config(text=f"Risk Level: {self.risk_level}")

       # self.timeline_box.configure(state="normal")
       # self.timeline_box.delete("1.0", tk.END)
       # for t, m in self.timeline.get():
       #     self.timeline_box.insert(tk.END, f"{t} - {m}\n")
       # self.timeline_box.configure(state="disabled")
        

        self.populate_report_view()
        self.analyze_button.config(state="normal")
        self.browse_button.config(state="normal")
        self.status_label.config(text="Status: Completed", fg=MUTED)
        self.cancel_btn.config(state="disabled")
        

    # ---------------- REPORT ----------------
    def populate_report_view(self):
        self.report_view.configure(state="normal")
        self.report_view.delete("1.0", tk.END)

        self.report_view.insert(tk.END, f"Sample Path: {self.sample_path}\n")
        self.report_view.insert(tk.END, f"PID: {self.analysis_pid}\n")
        self.report_view.insert(tk.END, f"SHA-256: {self.evidence.get('sha256')}\n")
        self.report_view.insert(tk.END, f"MD5: {self.evidence.get('md5')}\n\n")

        self.report_view.insert(
            tk.END,
            f"Verdict: {self.display_verdict(self.latest_decision)}\n"
            f"Risk Level: {self.risk_level}\n"
            f"Threat Type: {self.latest_threat} / Confindence Level: ({self.latest_confidence})\n\n"
        )

        self.report_view.insert(tk.END, "Behavior Timeline:\n")
        self.report_view.insert(tk.END, self.timeline.as_text())

        self.report_view.configure(state="disabled")

    def generate_report(self):
        if self.latest_features is None:
            messagebox.showwarning(
                "Report unavailable",
                "Analysis was cancelled. No forensic report can be generated."
            )
            return

        case_id = self.case_id_entry.get().strip()

        if not case_id:
            case_id = f"CASE_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        self.analyst_notes = self.notes_box.get("1.0", tk.END).strip()

        filename = f"BEACON_report_{self.analysis_pid}.pdf"

        report_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sample_path": self.sample_path,
            "file_size": self.evidence.get("size"),
            "sha256": self.evidence.get("sha256"),
            "md5": self.evidence.get("md5"),
            "pid": self.analysis_pid,
            "process_count": self.latest_features["process_count"],
            "network_connections": self.latest_features["network_connections"],
            "persistence": self.latest_features["persistence_detected"],
            "heuristic_result": self.display_verdict(self.latest_decision),
            "heuristic_reason": self.latest_reason,
            "risk_level": self.risk_level,
            "threat_type": self.latest_threat,
            "threat_confidence": self.latest_confidence,
            "behavior_timeline": self.timeline.as_text(),
            "chain_of_custody": self.timeline.as_chain_of_custody(),
            "analyst_notes": self.analyst_notes
        }

        # Create case directory
        case_dir = os.path.join("cases", case_id)
        os.makedirs(case_dir, exist_ok=True)

        # Generate PDF inside case folder
        path = generate_pdf_report(
            report_data,
            filename=filename,
            output_dir=case_dir
        )

        # Append to case_index.csv
        append_case_index(
            case_dir=case_dir,
            timestamp=report_data["timestamp"],
            pid=report_data["pid"],
            verdict=report_data["heuristic_result"],
            risk_level=report_data["risk_level"],
            report_filename=filename
        )

        messagebox.showinfo(
            "Report Generated",
            f"Saved as:\n{path}\n\nCase ID: {case_id}"
        )


if __name__ == "__main__":
    root = tk.Tk()
    BeaconGUI(root)
    root.mainloop()
