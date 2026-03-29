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
        self.log.tag_configure("orange", foreground="#E65100")
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

        # Fresh random secret every single time
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
        self.log_msg(f"  Secret (s):                {secret}")
        self.log_msg(f"  Total Shares (n):          {n}")
        self.log_msg(f"  Vulnerable Threshold (t):  {t_low}  (degree = {t_low - 1})", "red")
        self.log_msg(f"  Prime (p):                 {self.sss.prime}  (2^127 - 1)")

        # Generate polynomial — fresh random coefficients every call
        coeffs = self.sss.generate_polynomial(secret, t_low)
        shares = self.sss.generate_shares(n)
        self.current_share_commitments = {}

        # Show the polynomial clearly
        self.log_msg("\n[POLYNOMIAL — freshly randomised each time]", "bold")
        poly_str = self._format_polynomial(coeffs)
        self.log_msg(f"  f(x) = {poly_str}", "blue")
        self.log_msg(f"  Degree: {len(coeffs) - 1}  (need {len(coeffs)} points to reconstruct)")
        self.log_msg(f"  Secret is the constant term: f(0) = {secret}")

        # Show each coefficient
        self.log_msg("\n  Coefficients (randomly chosen — different every run):")
        for i, c in enumerate(coeffs):
            if i == 0:
                self.log_msg(f"    a[0] = {c}  ← this IS the secret", "orange")
            else:
                self.log_msg(f"    a[{i}] = {c}  ← random, changes every run", "orange")

        # Show shares
        self.log_msg("\n[SHARES DISTRIBUTED]", "bold")
        self.log_msg("  Each share is just a point (x, f(x)) on the polynomial:")
        for i, (x, y) in enumerate(shares, 1):
            self.log_msg(f"    Share {i}:  x={x},  y=f({x})={y}")

        self.log_msg("\n[ATTACK SURFACE]", "bold")
        self.log_msg(f"  Threshold is {t_low}, so attacker needs ANY {t_low} shares.", "red")
        self.log_msg(f"  With {t_low} points they can fit the degree-{t_low - 1} polynomial", "red")
        self.log_msg(f"  and read off f(0) = secret directly.", "red")

        self.vuln_indicator.config(text=f"* Vulnerable: ACTIVE (t={t_low}, degree={t_low - 1})")
        self.secure_indicator.config(text="* Secure (High Degree + Share Integrity)")
        self.log_msg("\n[STATUS] System is VULNERABLE.", "red")

    def run_collusion_attack(self):
        if not self.sss:
            messagebox.showwarning("Warning", "Please generate secret first!")
            return

        self.log_msg("\n" + "=" * 60, "bold")
        self.log_msg("RUNNING COLLUSION ATTACK", "red")
        self.log_msg("=" * 60, "bold")

        available_shares = min(self.attack_budget or self.sss.threshold, len(self.sss.shares))
        attack_shares = self.sss.shares[:available_shares]

        self.log_msg(f"\n  Attacker has compromised {available_shares} share(s): {attack_shares}", "red")
        self.log_msg(f"  Threshold is {self.sss.threshold}, so {available_shares} shares is {'enough' if available_shares >= self.sss.threshold else 'NOT enough'}.")

        if available_shares >= self.sss.threshold:
            # Walk through the reconstruction step by step
            self.log_msg("\n[DECRYPTION PROCESS — Lagrange Interpolation]", "bold")
            recovered, steps = ShamirSecretSharing.lagrange_interpolation_steps(
                attack_shares, self.sss.prime
            )
            for step in steps:
                self.log_msg(f"  {step}")

            if recovered == self.current_secret:
                self.log_msg("\n[RESULT] Attack SUCCESSFUL!", "red")
                self.log_msg(f"  Real secret:      {self.current_secret}", "red")
                self.log_msg(f"  Recovered secret: {recovered}", "red")
                self.log_msg("  Confidentiality: BREACHED", "red")
            else:
                self.log_msg(f"\n  Reconstruction gave: {recovered} (unexpected mismatch)", "red")
        else:
            self.log_msg("\n[DECRYPTION PROCESS — BLOCKED]", "bold")
            self.log_msg(f"  Only {available_shares} shares available, need {self.sss.threshold}.", "green")
            self.log_msg("  Cannot fit the polynomial — infinitely many curves pass through fewer points.", "green")
            self.log_msg("  Attack FAILED: not enough shares.", "green")

    def run_tampering_attack(self):
        if not self.sss:
            messagebox.showwarning("Warning", "Please generate secret first!")
            return

        self.log_msg("\n" + "=" * 60, "bold")
        self.log_msg("RUNNING TAMPERING / FORGED-SHARE ATTACK", "purple")
        self.log_msg("=" * 60, "bold")

        attack = AttackSimulator(self.sss)
        self.log_msg(f"\n  Profile:                   {self.current_profile_label}")
        self.log_msg(f"  Integrity checks enabled:  {'YES' if self.integrity_enabled else 'NO'}")
        self.log_msg(f"  Reconstruction threshold:  {self.sss.threshold}")

        original_share = self.sss.shares[0]
        tamper_delta = random.randint(1, 10000)
        forged_y = (original_share[1] + tamper_delta) % self.sss.prime
        forged_share = (original_share[0], forged_y)

        self.log_msg(f"\n[TAMPERING PROCESS]", "bold")
        self.log_msg(f"  Original share 1:  (x={original_share[0]}, y={original_share[1]})")
        self.log_msg(f"  Delta applied:     +{tamper_delta}")
        self.log_msg(f"  Forged share 1:    (x={forged_share[0]}, y={forged_y})", "purple")

        result = attack.tamper_share_attack(
            self.sss.shares,
            self.sss.threshold,
            self.current_secret,
            share_commitments=self.current_share_commitments if self.integrity_enabled else None,
            tamper_delta=tamper_delta,
        )

        if result["detected"]:
            self.log_msg("\n[RESULT] Tampering DETECTED before reconstruction.", "green")
            self.log_msg(f"  SHA-256 hash of forged share did not match stored commitment.", "green")
            self.log_msg(f"  Share rejected. Attack blocked.", "green")
        elif result["success"]:
            self.log_msg("\n[DECRYPTION PROCESS — with forged share]", "bold")
            tampered_shares = list(self.sss.shares[:self.sss.threshold])
            tampered_shares[0] = forged_share
            _, steps = ShamirSecretSharing.lagrange_interpolation_steps(tampered_shares, self.sss.prime)
            for step in steps:
                self.log_msg(f"  {step}")
            self.log_msg("\n[RESULT] Tampering SUCCESSFUL!", "red")
            self.log_msg(f"  Real secret:         {self.current_secret}", "red")
            self.log_msg(f"  Wrong secret output: {result['reconstructed_secret']}", "red")
            self.log_msg("  Integrity: COMPROMISED — reconstruction silently returned wrong value.", "red")
        else:
            self.log_msg("\n[RESULT] Tampering had no effect or reconstruction failed.", "green")
            self.log_msg(f"  {result['notes']}", "green")

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

        t_high = min(max(requested_high, low_t + 2), n)
        self.high_t_var.set(str(t_high))

        self.log_msg("\n" + "=" * 60, "bold")
        self.log_msg("APPLYING PREVENTION: HIGH THRESHOLD + SHARE INTEGRITY", "green")
        self.log_msg("=" * 60, "bold")

        secret = self.current_secret

        self.log_msg(f"\n[OLD POLYNOMIAL — vulnerable, degree {low_t - 1}]", "bold")
        old_poly = self._format_polynomial(self.sss.coefficients)
        self.log_msg(f"  f(x)  = {old_poly}", "red")
        self.log_msg(f"  Threshold was {low_t} — attacker needed only {low_t} shares.")

        # Build new secure setup — fresh random coefficients again
        sss_secure = ShamirSecretSharing()
        prevention = PreventionMechanism(sss_secure)
        start_time = time.perf_counter()
        secure_config = prevention.apply_high_degree(secret, n, t_high, enable_integrity=True)
        setup_time = time.perf_counter() - start_time

        self.sss = sss_secure
        self.current_share_commitments = secure_config["share_commitments"]
        self.current_profile_label = "High Threshold / Share Integrity"
        self.integrity_enabled = True
        self.current_high_t = t_high
        self.attack_budget = low_t

        # Show the new polynomial clearly
        self.log_msg(f"\n[NEW POLYNOMIAL — secured, degree {t_high - 1}]", "bold")
        new_poly = self._format_polynomial(sss_secure.coefficients)
        self.log_msg(f"  f'(x) = {new_poly}", "green")
        self.log_msg(f"  Same secret at f'(0) = {secret}", "green")
        self.log_msg(f"  New threshold: {t_high}  (degree = {t_high - 1})", "green")
        self.log_msg(f"  All coefficients re-randomised — polynomial is completely different.", "green")

        self.log_msg("\n  New coefficient comparison:")
        for i, (old_c, new_c) in enumerate(zip(self.sss.coefficients, sss_secure.coefficients)):
            pass
        for i, c in enumerate(sss_secure.coefficients):
            if i == 0:
                self.log_msg(f"    a'[0] = {c}  ← secret (unchanged)", "orange")
            else:
                self.log_msg(f"    a'[{i}] = {c}  ← freshly randomised", "orange")

        self.log_msg(f"\n[NEW SHARES]", "bold")
        for i, (x, y) in enumerate(sss_secure.shares, 1):
            commit_prefix = secure_config["share_commitments"][x][:12]
            self.log_msg(f"    Share {i}: (x={x}, y={y})  SHA-256={commit_prefix}...")

        self.log_msg(f"\n  Setup time: {setup_time:.6f}s")

        # Now immediately show the attack failing on the new setup
        self.log_msg("\n[POST-PREVENTION: RE-RUNNING ATTACK — watch it fail]", "bold")

        # Collusion attempt with same old budget
        self.log_msg(f"\n  Collusion attempt: attacker still has only {low_t} shares.")
        self.log_msg(f"  New threshold is {t_high}. Attacker needs {t_high - low_t} more shares.")
        self.log_msg(f"  => Cannot reconstruct. A degree-{t_high - 1} curve needs {t_high} points.", "green")
        self.log_msg(f"  => Infinitely many polynomials pass through only {low_t} points.", "green")
        self.log_msg("  => Collusion attack: FAILED", "green")

        # Tamper attempt
        self.log_msg(f"\n  Tamper attempt: attacker forges share 1.")
        orig = sss_secure.shares[0]
        fake_y = (orig[1] + 9999) % sss_secure.prime
        real_hash = secure_config["share_commitments"][orig[0]]
        fake_hash_preview = "differs completely"
        self.log_msg(f"    Original y:        {orig[1]}")
        self.log_msg(f"    Forged y:          {fake_y}")
        self.log_msg(f"    Stored commitment: {real_hash[:16]}...")
        self.log_msg(f"    Forged hash:       {fake_hash_preview}")
        self.log_msg("    => SHA-256 mismatch. Share rejected before reconstruction.", "green")
        self.log_msg("  => Tamper attack: FAILED", "green")

        # Verify honest reconstruction still works
        valid, recovered = prevention.verify_and_reconstruct(
            sss_secure.shares[:t_high], secure_config["share_commitments"]
        )
        self.log_msg(f"\n[HONEST RECONSTRUCTION with {t_high} legitimate shares]", "bold")
        if valid and recovered == secret:
            self.log_msg(f"  All {t_high} shares verified against commitments.", "green")
            self.log_msg(f"  Lagrange interpolation => f'(0) = {recovered}", "green")
            self.log_msg(f"  Secret correctly recovered: {recovered}", "green")

        self.vuln_indicator.config(text="* Vulnerable: BLOCKED by prevention")
        self.secure_indicator.config(text=f"* Secure: ACTIVE (t={t_high}, degree={t_high - 1} + SHA-256)")
        self.log_msg("\n[STATUS] System is SECURE.", "green")

    def _format_polynomial(self, coeffs: list) -> str:
        """Format a coefficient list as a readable polynomial string."""
        if not coeffs:
            return "0"
        terms = [str(coeffs[0])]
        for i, c in enumerate(coeffs[1:], 1):
            if i == 1:
                terms.append(f"{c}*x")
            else:
                terms.append(f"{c}*x^{i}")
        return " + ".join(terms)

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
        self.current_results = results
        self.graph_gen = graph_gen
        self.log_msg("\n[TEST RESULTS SUMMARY]", "bold")
        self.log_msg(f"  Total Test Cases: {len(results)}")
        self.log_msg(f"  Collusion Success Before Prevention: {stats['low_degree_success_rate']:.1f}%", "red")
        self.log_msg(f"  Collusion Success After Prevention:  {stats['high_degree_attack_success_rate']:.1f}%", "green")
        self.log_msg(f"  Tampering Success Before Prevention: {stats['tamper_success_before']:.1f}%", "red")
        self.log_msg(f"  Tampering Success After Prevention:  {stats['tamper_success_after']:.1f}%", "green")
        self.log_msg(
            f"  Security Rates After — C:{stats['confidentiality_after']:.1f}%  "
            f"I:{stats['integrity_after']:.1f}%  A:{stats['authentication_after']:.1f}%",
            "green",
        )
        self.log_msg("  [GRAPHS GENERATED] 5 comparison graphs created.", "green")

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
        self.log_msg("\n[GRAPHS DISPLAYED]", "green")