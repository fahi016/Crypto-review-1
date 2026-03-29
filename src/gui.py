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
        self.root.title("Shamir's Secret Sharing: Attack & Prevention Lab")
        self.root.geometry("1200x800")
        self.root.configure(bg="#f0f0f0")
        self.sss = None
        self.test_runner = TestRunner()
        self.graph_gen = None
        self.current_results = []
        self.current_share_commitments = {}
        self.current_profile_label = "Not configured"
        self.attack_budget = None
        self.current_secret = None
        self.current_n = None
        self.current_low_t = None
        self.current_high_t = None
        self.integrity_enabled = False
        self.n_var = StringVar(value="5")
        self.low_t_var = StringVar(value="2")
        self.high_t_var = StringVar(value="4")
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
        param_frame = LabelFrame(left, text="Parameters", bg="white", font=("Arial", 10, "bold"))
        param_frame.pack(fill=X, padx=10, pady=10)
        Label(param_frame, text="Participants (n)", bg="white").grid(row=0, column=0, sticky=W, padx=5, pady=4)
        Entry(param_frame, textvariable=self.n_var, width=8).grid(row=0, column=1, padx=5, pady=4)
        Label(param_frame, text="Vulnerable Threshold", bg="white").grid(row=1, column=0, sticky=W, padx=5, pady=4)
        Entry(param_frame, textvariable=self.low_t_var, width=8).grid(row=1, column=1, padx=5, pady=4)
        Label(param_frame, text="Secure Threshold", bg="white").grid(row=2, column=0, sticky=W, padx=5, pady=4)
        Entry(param_frame, textvariable=self.high_t_var, width=8).grid(row=2, column=1, padx=5, pady=4)
        btn_frame = Frame(left, bg="white")
        btn_frame.pack(padx=10, pady=10)
        Button(
            btn_frame,
            text="1. Generate Vulnerable Setup",
            command=self.generate_secret,
            bg="#4CAF50",
            fg="white",
            font=("Arial", 10, "bold"),
            width=25,
            height=2,
        ).pack(pady=5)
        Button(
            btn_frame,
            text="2. Run Collusion Attack",
            command=self.run_collusion_attack,
            bg="#f44336",
            fg="white",
            font=("Arial", 10, "bold"),
            width=25,
            height=2,
        ).pack(pady=5)
        Button(
            btn_frame,
            text="3. Run Tampering Attack",
            command=self.run_tampering_attack,
            bg="#8E24AA",
            fg="white",
            font=("Arial", 10, "bold"),
            width=25,
            height=2,
        ).pack(pady=5)
        Button(
            btn_frame,
            text="4. Apply Prevention",
            command=self.apply_prevention,
            bg="#2196F3",
            fg="white",
            font=("Arial", 10, "bold"),
            width=25,
            height=2,
        ).pack(pady=5)
        Button(
            btn_frame,
            text="5. Run Full Test Suite",
            command=self.run_test_suite,
            bg="#FF9800",
            fg="white",
            font=("Arial", 10, "bold"),
            width=25,
            height=2,
        ).pack(pady=5)
        Button(
            btn_frame,
            text="6. Show Graphs",
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
            self.status_frame,
            text="* Secure (High Degree + Share Integrity)",
            fg="green",
            bg="white",
            font=("Arial", 10),
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
        self.log.tag_configure("purple", foreground="#8E24AA")
        self.log.tag_configure("bold", font=("Courier", 10, "bold"))

    def log_msg(self, msg, color=None):
        self.log.insert(END, msg + "\n", color)
        self.log.see(END)
        self.root.update()

    def _get_parameters(self):
        try:
            n = int(self.n_var.get())
            low_t = int(self.low_t_var.get())
            high_t = int(self.high_t_var.get())
        except ValueError:
            messagebox.showwarning("Warning", "Parameters must be integers.")
            return None

        if n < 3:
            messagebox.showwarning("Warning", "Participants (n) must be at least 3.")
            return None
        if low_t < 2 or low_t >= n:
            messagebox.showwarning("Warning", "Vulnerable threshold must satisfy 2 <= t < n.")
            return None

        recommended_high = min(n, max(n - 1, low_t + 2))
        adjusted_high = min(max(high_t, low_t + 2), n)
        if adjusted_high != high_t:
            self.high_t_var.set(str(adjusted_high))
            high_t = adjusted_high

        return n, low_t, high_t, recommended_high

    def generate_secret(self):
        params = self._get_parameters()
        if not params:
            return

        n, t_low, t_high, _ = params
        self.log_msg("=" * 60, "bold")
        self.log_msg("GENERATING VULNERABLE BASELINE", "blue")
        self.log_msg("=" * 60, "bold")
        secret = random.randint(10000, 99999)
        self.sss = ShamirSecretSharing()
        self.current_secret = secret
        self.current_n = n
        self.current_low_t = t_low
        self.current_high_t = t_high
        self.attack_budget = t_low
        self.integrity_enabled = False
        self.current_profile_label = "Low Threshold / No Integrity"
        self.high_t_var.set(str(t_high))
        self.log_msg("\n[CONFIGURATION]", "bold")
        self.log_msg(f"Secret (s): {secret}")
        self.log_msg(f"Total Shares (n): {n}")
        self.log_msg(f"Vulnerable Threshold (t): {t_low} (DEGREE {t_low-1} - VULNERABLE)", "red")
        self.log_msg(f"Recommended Secure Threshold: {t_high}")
        self.log_msg(f"Prime (p): {self.sss.prime} (2^127 - 1)")
        coeffs = self.sss.generate_polynomial(secret, t_low)
        shares = self.sss.generate_shares(n)
        self.current_share_commitments = {}
        self.log_msg("\n[POLYNOMIAL GENERATED]", "bold")
        poly_str = f"f(x) = {coeffs[0]}"
        for i, c in enumerate(coeffs[1:], 1):
            poly_str += f" + {c}*x^{i}"
        self.log_msg(f"Polynomial: {poly_str}")
        self.log_msg(f"Degree: {len(coeffs)-1} (Linear - VULNERABLE)", "red")
        self.log_msg("\n[SHARES DISTRIBUTED]", "bold")
        for i, (x, y) in enumerate(shares, 1):
            self.log_msg(f"  Share {i}: (x={x}, y={y})")
        self.log_msg("\n[ATTACK SURFACE]", "bold")
        self.log_msg(f"Collusion attack budget fixed at {self.attack_budget} compromised shares.", "red")
        self.log_msg("Tampering detection is OFF in this baseline profile.", "red")
        self.vuln_indicator.config(text=f"* Vulnerable: ACTIVE (Low Degree t={t_low})")
        self.secure_indicator.config(text="* Secure (High Degree + Share Integrity)")
        self.log_msg("\n[STATUS] System is VULNERABLE to low-degree attacks!", "red")

    def run_collusion_attack(self):
        if not self.sss:
            messagebox.showwarning("Warning", "Please generate secret first!")
            return
        self.log_msg("\n" + "=" * 60, "bold")
        self.log_msg("RUNNING COLLUSION ATTACK", "red")
        self.log_msg("=" * 60, "bold")
        attack = AttackSimulator(self.sss)
        available_shares = min(self.attack_budget or self.sss.threshold, len(self.sss.shares))
        self.log_msg("\n[ATTACK PARAMETERS]", "bold")
        self.log_msg(f"Current Profile: {self.current_profile_label}")
        self.log_msg(f"Attacker has: {available_shares} share(s)")
        self.log_msg(f"Required for reconstruction: {self.sss.threshold} shares")
        self.log_msg(f"Polynomial degree: {self.sss.threshold - 1}")
        self.log_msg("\n[ATTACK EXECUTION]", "bold")
        result = attack.collusion_attack(self.sss.shares[:available_shares], available_shares, self.current_secret)
        if result["success"]:
            self.log_msg("Collusion attack SUCCESSFUL!", "red")
            self.log_msg(f"  Reconstructed Secret: {result['reconstructed_secret']}", "red")
            self.log_msg(f"  Time: {result['time']:.6f} seconds")
            self.log_msg("  Confidentiality: BREACHED!", "red")
        else:
            self.log_msg("Collusion attack BLOCKED!", "green")
            self.log_msg(result["notes"], "green")
            self.log_msg(
                f"With threshold {self.sss.threshold}, {available_shares} compromised shares are not enough to recover the secret.",
                "green",
            )

    def run_tampering_attack(self):
        if not self.sss:
            messagebox.showwarning("Warning", "Please generate secret first!")
            return

        self.log_msg("\n" + "=" * 60, "bold")
        self.log_msg("RUNNING TAMPERING / FORGED-SHARE ATTACK", "purple")
        self.log_msg("=" * 60, "bold")
        attack = AttackSimulator(self.sss)
        self.log_msg("\n[ATTACK PARAMETERS]", "bold")
        self.log_msg(f"Current Profile: {self.current_profile_label}")
        self.log_msg(f"Integrity Verification Enabled: {'YES' if self.integrity_enabled else 'NO'}")
        self.log_msg(f"Reconstruction Threshold: {self.sss.threshold}")
        self.log_msg("\n[ATTACK EXECUTION]", "bold")
        result = attack.tamper_share_attack(
            self.sss.shares,
            self.sss.threshold,
            self.current_secret,
            share_commitments=self.current_share_commitments if self.integrity_enabled else None,
        )
        if result["detected"]:
            self.log_msg("Tampering DETECTED before reconstruction.", "green")
            self.log_msg(f"  Time: {result['time']:.6f} seconds")
            self.log_msg(f"  Forged Share: {result['forged_share']}", "green")
        elif result["success"]:
            self.log_msg("Tampering attack SUCCESSFUL!", "red")
            self.log_msg(f"  Forged Share: {result['forged_share']}", "red")
            self.log_msg(f"  Wrong reconstructed secret: {result['reconstructed_secret']}", "red")
            self.log_msg(f"  Time: {result['time']:.6f} seconds")
            self.log_msg("  Integrity: COMPROMISED!", "red")
        else:
            self.log_msg("Tampering attack BLOCKED or had no effect.", "green")
            self.log_msg(result["notes"], "green")
            self.log_msg(f"  Time: {result['time']:.6f} seconds")

    def apply_prevention(self):
        if not self.sss:
            messagebox.showwarning("Warning", "Please generate secret first!")
            return

        if self.current_n is None or self.current_low_t is None:
            messagebox.showwarning("Warning", "Please generate the vulnerable setup first!")
            return

        n = self.current_n
        low_t = self.current_low_t
        try:
            requested_high = int(self.high_t_var.get())
        except ValueError:
            messagebox.showwarning("Warning", "Secure threshold must be an integer.")
            return

        recommended_high = min(n, max(n - 1, low_t + 2))
        t_high = min(max(requested_high, low_t + 2), n)
        self.high_t_var.set(str(t_high))
        self.log_msg("\n" + "=" * 60, "bold")
        self.log_msg("APPLYING PREVENTION: HIGH THRESHOLD + SHARE INTEGRITY", "green")
        self.log_msg("=" * 60, "bold")
        secret = self.current_secret
        self.log_msg("\n[PREVENTION CONFIGURATION]", "bold")
        self.log_msg(f"New Threshold (t): {t_high} (DEGREE {t_high-1} - SECURE)", "green")
        self.log_msg(f"Total Shares (n): {n}")
        self.log_msg(f"Attack budget remains: {low_t} compromised shares", "green")
        self.log_msg(f"Recommended secure threshold for this n: {recommended_high}", "green")
        sss_secure = ShamirSecretSharing()
        prevention = PreventionMechanism(sss_secure)
        start_time = time.perf_counter()
        secure_config = prevention.apply_high_degree(secret, n, t_high, enable_integrity=True)
        setup_time = time.perf_counter() - start_time
        self.sss = sss_secure
        self.current_share_commitments = secure_config["share_commitments"]
        self.current_profile_label = "High Threshold / Share Integrity"
        self.integrity_enabled = True
        self.current_n = n
        self.current_low_t = low_t
        self.current_high_t = t_high
        self.attack_budget = low_t
        self.log_msg("\n[SECURE POLYNOMIAL GENERATED]", "bold")
        self.log_msg(f"Degree: {secure_config['degree']} (High - SECURE)", "green")
        self.log_msg("Coefficients: [hidden for security]")
        self.log_msg(f"Setup Time: {setup_time:.6f} seconds")
        self.log_msg("\n[PUBLIC SHARE COMMITMENTS]", "bold")
        self.log_msg(f"Published share commitments: {len(secure_config['share_commitments'])}")
        self.log_msg("\n[POST-PREVENTION QUICK CHECK]", "bold")
        attack = AttackSimulator(sss_secure)
        collusion_result = attack.collusion_attack(sss_secure.shares[:low_t], low_t, secret)
        if not collusion_result["success"]:
            self.log_msg("Collusion attack now FAILS with the same attacker budget.", "green")
        tamper_result = attack.tamper_share_attack(
            sss_secure.shares,
            t_high,
            secret,
            share_commitments=secure_config["share_commitments"],
        )
        if tamper_result["detected"]:
            self.log_msg("Forged-share attack is now DETECTED.", "green")
        valid, recovered = prevention.verify_and_reconstruct(sss_secure.shares[:t_high], secure_config["share_commitments"])
        if valid and recovered == secret:
            self.log_msg(f"Proper reconstruction with {t_high} shares: SUCCESS", "green")
        self.vuln_indicator.config(text="* Vulnerable: BLOCKED by prevention")
        self.secure_indicator.config(text="* Secure: ACTIVE (High Degree + Share Integrity)")
        self.log_msg("\n[STATUS] System is SECURE!", "green")

    def run_test_suite(self):
        self.log_msg("\n" + "=" * 60, "bold")
        self.log_msg("RUNNING FULL TEST SUITE (MULTI-ATTACK COMPARISON)", "blue")
        self.log_msg("=" * 60, "bold")

        def run_tests():
            results = self.test_runner.run_full_test_suite(25)
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
        self.log_msg(f"Total Test Cases: {len(results)}")
        self.log_msg(f"Collusion Success Before Prevention: {stats['low_degree_success_rate']:.1f}%", "red")
        self.log_msg(f"Collusion Success After Prevention: {stats['high_degree_attack_success_rate']:.1f}%", "green")
        self.log_msg(f"Tampering Success Before Prevention: {stats['tamper_success_before']:.1f}%", "red")
        self.log_msg(f"Tampering Success After Prevention: {stats['tamper_success_after']:.1f}%", "green")
        self.log_msg(
            f"Security Rates After Prevention - C:{stats['confidentiality_after']:.1f}% "
            f"I:{stats['integrity_after']:.1f}% A:{stats['authentication_after']:.1f}%",
            "green",
        )
        self.log_msg("[GRAPHS GENERATED] 5 comparison graphs created.", "green")

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
            ("success_rate", "Before vs After Attack Success"),
            ("time_vs_degree", "Time vs Degree Across Solutions"),
            ("confidentiality", "Confidentiality / Integrity / Authentication"),
            ("latency", "Attack vs Prevention Latency"),
            ("attack_comparison", "Attack Comparison Across Solutions"),
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
        self.log_msg("\n[GRAPHS DISPLAYED] Showing all comparison graphs.", "green")
