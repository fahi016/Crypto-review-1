import os
import random
import threading
import time
from tkinter import *
from tkinter import messagebox, scrolledtext, ttk

from .attack import AttackSimulator
from .graphs import GraphGenerator
from .prevention import PreventionMechanism
from .shamir import ShamirSecretSharing
from .test_runner import TestRunner


class ShamirGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Shamir's Secret Sharing: Attack & Prevention")
        self.root.geometry("1200x800")
        self.root.configure(bg="#f0f0f0")
        self.sss = None
        self.test_runner = TestRunner()
        self.graph_gen = None
        self.current_results = []
        self.setup_ui()

    def setup_ui(self):
        header = Frame(self.root, bg="#2196F3", height=60)
        header.pack(fill=X)
        header.pack_propagate(False)
        Label(
            header,
            text="Shamir's Secret Sharing Security Analysis",
            font=("Arial", 18, "bold"),
            bg="#2196F3",
            fg="white",
        ).pack(pady=15)
        main = Frame(self.root, bg="#f0f0f0")
        main.pack(fill=BOTH, expand=True, padx=10, pady=10)
        left = Frame(main, bg="white", bd=2, relief=GROOVE)
        left.pack(side=LEFT, fill=Y, padx=5, pady=5)
        btn_frame = Frame(left, bg="white")
        btn_frame.pack(padx=10, pady=10)
        Button(
            btn_frame,
            text="1. Generate Secret/Polynomial",
            command=self.generate_secret,
            bg="#4CAF50",
            fg="white",
            font=("Arial", 10, "bold"),
            width=25,
            height=2,
        ).pack(pady=5)
        Button(
            btn_frame,
            text="2. Run Attack (Low Degree)",
            command=self.run_attack,
            bg="#f44336",
            fg="white",
            font=("Arial", 10, "bold"),
            width=25,
            height=2,
        ).pack(pady=5)
        Button(
            btn_frame,
            text="3. Apply Prevention (High Degree)",
            command=self.apply_prevention,
            bg="#2196F3",
            fg="white",
            font=("Arial", 10, "bold"),
            width=25,
            height=2,
        ).pack(pady=5)
        Button(
            btn_frame,
            text="4. Run Full Test Suite (20-25 cases)",
            command=self.run_test_suite,
            bg="#FF9800",
            fg="white",
            font=("Arial", 10, "bold"),
            width=25,
            height=2,
        ).pack(pady=5)
        Button(
            btn_frame,
            text="5. Show Graphs",
            command=self.show_graphs,
            bg="#9C27B0",
            fg="white",
            font=("Arial", 10, "bold"),
            width=25,
            height=2,
        ).pack(pady=5)
        self.status_frame = Frame(left, bg="white")
        self.status_frame.pack(padx=10, pady=10, fill=X)
        Label(self.status_frame, text="Status Indicators:", font=("Arial", 11, "bold"), bg="white").pack(anchor=W)
        self.vuln_indicator = Label(
            self.status_frame, text="* Vulnerable (Low Degree)", fg="red", bg="white", font=("Arial", 10)
        )
        self.vuln_indicator.pack(anchor=W, pady=2)
        self.secure_indicator = Label(
            self.status_frame, text="* Secure (High Degree + VSS)", fg="green", bg="white", font=("Arial", 10)
        )
        self.secure_indicator.pack(anchor=W, pady=2)
        right = Frame(main, bg="white", bd=2, relief=GROOVE)
        right.pack(side=RIGHT, fill=BOTH, expand=True, padx=5, pady=5)
        Label(right, text="Execution Log", font=("Arial", 12, "bold"), bg="white").pack(anchor=W, padx=5, pady=5)
        self.log = scrolledtext.ScrolledText(right, wrap=WORD, font=("Courier", 10))
        self.log.pack(fill=BOTH, expand=True, padx=5, pady=5)
        self.log.tag_configure("red", foreground="red")
        self.log.tag_configure("green", foreground="green")
        self.log.tag_configure("blue", foreground="blue")
        self.log.tag_configure("bold", font=("Courier", 10, "bold"))

    def log_msg(self, msg, color=None):
        self.log.insert(END, msg + "\n", color)
        self.log.see(END)
        self.root.update()

    def generate_secret(self):
        self.log_msg("=" * 60, "bold")
        self.log_msg("GENERATING SECRET AND POLYNOMIAL", "blue")
        self.log_msg("=" * 60, "bold")
        secret = random.randint(10000, 99999)
        self.sss = ShamirSecretSharing()
        n = 5
        t_low = 2
        self.log_msg("\n[CONFIGURATION]", "bold")
        self.log_msg(f"Secret (s): {secret}")
        self.log_msg(f"Total Shares (n): {n}")
        self.log_msg(f"Threshold (t): {t_low} (DEGREE {t_low-1} - VULNERABLE)", "red")
        self.log_msg(f"Prime (p): {self.sss.prime} (2^127 - 1)")
        coeffs = self.sss.generate_polynomial(secret, t_low)
        shares = self.sss.generate_shares(n)
        commitments = self.sss.create_commitments()
        self.log_msg("\n[POLYNOMIAL GENERATED]", "bold")
        poly_str = f"f(x) = {coeffs[0]}"
        for i, c in enumerate(coeffs[1:], 1):
            poly_str += f" + {c}*x^{i}"
        self.log_msg(f"Polynomial: {poly_str}")
        self.log_msg(f"Degree: {len(coeffs)-1} (Linear - VULNERABLE)", "red")
        self.log_msg("\n[SHARES DISTRIBUTED]", "bold")
        for i, (x, y) in enumerate(shares, 1):
            self.log_msg(f"  Share {i}: (x={x}, y={y})")
        self.log_msg("\n[COMMITMENTS GENERATED]", "bold")
        for i, c in enumerate(commitments):
            self.log_msg(f"  C_{i}: {str(c)[:30]}...")
        self.vuln_indicator.config(text="* Vulnerable: ACTIVE (Low Degree t=2)")
        self.log_msg("\n[STATUS] System is VULNERABLE to low-degree attacks!", "red")

    def run_attack(self):
        if not self.sss:
            messagebox.showwarning("Warning", "Please generate secret first!")
            return
        self.log_msg("\n" + "=" * 60, "bold")
        self.log_msg("RUNNING ATTACK ON LOW-DEGREE POLYNOMIAL", "red")
        self.log_msg("=" * 60, "bold")
        attack = AttackSimulator(self.sss)
        available_shares = self.sss.threshold - 1
        self.log_msg("\n[ATTACK PARAMETERS]", "bold")
        self.log_msg(f"Attacker has: {available_shares} share(s)")
        self.log_msg(f"Required for reconstruction: {self.sss.threshold} shares")
        self.log_msg(f"Polynomial degree: {self.sss.threshold - 1}")
        self.log_msg("\n[ATTACK EXECUTION]", "bold")
        success, leaked, time_taken = attack.brute_force_low_degree(
            self.sss.shares[:available_shares], self.sss.threshold - 1, self.sss.secret
        )
        if success:
            self.log_msg("Attack SUCCESSFUL!", "red")
            self.log_msg(f"  Reconstructed Secret: {leaked}", "red")
            self.log_msg(f"  Time: {time_taken:.6f} seconds")
            self.log_msg("  Confidentiality: BREACHED!", "red")
        else:
            self.log_msg(f"Attack failed with {available_shares} share(s)", "green")
            self.log_msg(f"Trying with {self.sss.threshold} shares (minimum required)...")
            success2, leaked2, time_taken2 = attack.brute_force_low_degree(
                self.sss.shares[: self.sss.threshold], self.sss.threshold - 1, self.sss.secret
            )
            if success2:
                self.log_msg(f"Attack SUCCESSFUL with {self.sss.threshold} shares!", "red")
                self.log_msg(f"  Reconstructed Secret: {leaked2}", "red")
                self.log_msg(f"  Time: {time_taken2:.6f} seconds")
                self.log_msg("\n[VULNERABILITY EXPLANATION]", "bold")
                self.log_msg(
                    f"With degree-{self.sss.threshold-1} polynomial, only {self.sss.threshold} points are needed."
                )
                self.log_msg("Low threshold allows easy reconstruction!", "red")

    def apply_prevention(self):
        if not self.sss:
            messagebox.showwarning("Warning", "Please generate secret first!")
            return
        self.log_msg("\n" + "=" * 60, "bold")
        self.log_msg("APPLYING PREVENTION: HIGH-DEGREE + VERIFIABLE SHARING", "green")
        self.log_msg("=" * 60, "bold")
        secret = self.sss.secret
        n = self.sss.total_shares
        t_high = max(n - 1, 4)
        self.log_msg("\n[PREVENTION CONFIGURATION]", "bold")
        self.log_msg(f"New Threshold (t): {t_high} (DEGREE {t_high-1} - SECURE)", "green")
        self.log_msg(f"Total Shares (n): {n}")
        sss_secure = ShamirSecretSharing()
        prevention = PreventionMechanism(sss_secure)
        start_time = time.time()
        secure_config = prevention.apply_high_degree(secret, n, t_high)
        setup_time = time.time() - start_time
        self.log_msg("\n[SECURE POLYNOMIAL GENERATED]", "bold")
        self.log_msg(f"Degree: {secure_config['degree']} (High - SECURE)", "green")
        self.log_msg("Coefficients: [hidden for security]")
        self.log_msg(f"Setup Time: {setup_time:.6f} seconds")
        self.log_msg("\n[VERIFIABLE COMMITMENTS]", "bold")
        self.log_msg(f"Number of commitments: {len(secure_config['commitments'])}")
        self.log_msg("\n[ATTACK TEST ON HIGH-DEGREE]", "bold")
        attack = AttackSimulator(sss_secure)
        success, _, _ = attack.brute_force_low_degree(sss_secure.shares[:2], 1, secret)
        if not success:
            self.log_msg("Attack FAILED!", "green")
            self.log_msg(f"With only 2 shares, cannot reconstruct. Need {t_high} shares.", "green")
        valid, recovered = prevention.verify_and_reconstruct(sss_secure.shares[:t_high], secure_config["commitments"])
        if valid and recovered == secret:
            self.log_msg(f"Proper reconstruction with {t_high} shares: SUCCESS", "green")
        self.secure_indicator.config(text="* Secure: ACTIVE (High Degree + VSS)")
        self.log_msg("\n[STATUS] System is SECURE!", "green")

    def run_test_suite(self):
        self.log_msg("\n" + "=" * 60, "bold")
        self.log_msg("RUNNING FULL TEST SUITE (20-25 CASES)", "blue")
        self.log_msg("=" * 60, "bold")

        def run_tests():
            results = self.test_runner.run_full_test_suite(20)
            stats = self.test_runner.calculate_statistics()
            graph_gen = GraphGenerator(self.test_runner)
            graph_gen.generate_all_graphs()
            graph_gen.save_all()
            self.root.after(0, lambda: self._on_tests_complete(results, stats, graph_gen))

        threading.Thread(target=run_tests, daemon=True).start()

    def _on_tests_complete(self, results, stats, graph_gen):
        """UI update callback executed on Tk main thread after worker finishes."""
        self.current_results = results
        self.graph_gen = graph_gen
        self.log_msg("\n[TEST RESULTS SUMMARY]", "bold")
        self.log_msg("Total Test Cases: 20")
        self.log_msg(f"Attack Success (Low-Degree): {stats['low_degree_success_rate']:.1f}%", "red")
        self.log_msg(f"Attack Success (High-Degree): {stats['high_degree_attack_success_rate']:.1f}%", "green")
        self.log_msg(f"Confidentiality After: {stats['confidentiality_after']:.1f}%", "green")
        self.log_msg("[GRAPHS GENERATED] All 4 mandatory graphs created.", "green")

    def show_graphs(self):
        if not self.graph_gen:
            messagebox.showwarning("Warning", "Please run test suite first!")
            return
        graph_window = Toplevel(self.root)
        graph_window.title("Security Analysis Graphs")
        graph_window.geometry("1400x900")
        self.graph_gen.save_all()
        from PIL import Image, ImageTk

        notebook = ttk.Notebook(graph_window)
        notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)
        graph_names = [
            ("success_rate", "Attack Success Rate Comparison"),
            ("time_vs_degree", "Time vs Polynomial Degree"),
            ("confidentiality", "Confidentiality Rate"),
            ("latency", "Latency Overhead Analysis"),
        ]
        for key, title in graph_names:
            frame = Frame(notebook)
            notebook.add(frame, text=title)
            img_path = os.path.join(os.getcwd(), "output", f"graph_{key}.png")
            img = Image.open(img_path)
            img = img.resize((1200, 700), Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            label = Label(frame, image=photo)
            label.image = photo
            label.pack(padx=10, pady=10)
        self.log_msg("\n[GRAPHS DISPLAYED] Showing all 4 mandatory graphs.", "green")

