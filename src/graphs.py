import os

import matplotlib

# Use a non-interactive backend so graph generation is thread-safe with Tkinter apps.
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from .test_runner import TestRunner


class GraphGenerator:
    def __init__(self, test_runner: TestRunner):
        self.test_runner = test_runner
        self.figures = {}
        self.output_dir = os.path.join(os.getcwd(), "output")
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_all_graphs(self):
        self.fig1_success_rate()
        self.fig2_time_vs_degree()
        self.fig3_confidentiality()
        self.fig4_latency_overhead()

    def fig1_success_rate(self):
        stats = self.test_runner.calculate_statistics()
        fig, ax = plt.subplots(figsize=(10, 6))
        categories = ["Low Degree\n(Vulnerable)", "High Degree\n(Secure)"]
        success_rates = [stats["low_degree_success_rate"], stats["high_degree_attack_success_rate"]]
        colors = ["#ff4444", "#44ff44"]
        bars = ax.bar(categories, success_rates, color=colors, alpha=0.8, edgecolor="black", linewidth=2)
        for bar, rate in zip(bars, success_rates):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2.0, height, f"{rate:.1f}%", ha="center", va="bottom")
        ax.set_ylabel("Attack Success Rate (%)")
        ax.set_title("Attack Success Rate: Low-Degree vs High-Degree Polynomials")
        ax.set_ylim(0, 110)
        ax.grid(axis="y", alpha=0.3)
        ax.axhline(y=90, color="red", linestyle="--", alpha=0.5, label="90% threshold")
        ax.legend()
        plt.tight_layout()
        self.figures["success_rate"] = fig
        return fig

    def fig2_time_vs_degree(self):
        data = self.test_runner.test_results["time_vs_degree"]
        degree_times = {}
        for d in data:
            low_deg = d["low_degree"]
            high_deg = d["high_degree"]
            degree_times.setdefault(low_deg, []).append(d["low_time"])
            degree_times.setdefault(high_deg, []).append(d["high_time"])
        degrees = sorted(degree_times.keys())
        avg_times = [sum(degree_times[d]) / len(degree_times[d]) for d in degrees]
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.plot(degrees, avg_times, marker="o", linewidth=2, markersize=8, color="#2196F3", label="Computation Time")
        ax.axvspan(0.5, 3.5, alpha=0.2, color="red", label="Vulnerable (Low Degree)")
        ax.axvspan(3.5, max(degrees) + 0.5, alpha=0.2, color="green", label="Secure (High Degree)")
        ax.set_xlabel("Polynomial Degree (t-1)")
        ax.set_ylabel("Average Computation Time (seconds)")
        ax.set_title("Computation Time vs Polynomial Degree")
        ax.grid(True, alpha=0.3)
        ax.legend()
        plt.tight_layout()
        self.figures["time_vs_degree"] = fig
        return fig

    def fig3_confidentiality(self):
        stats = self.test_runner.calculate_statistics()
        fig, ax = plt.subplots(figsize=(10, 6))
        categories = ["Before Prevention\n(Low Degree)", "After Prevention\n(High Degree + VSS)"]
        conf_rates = [stats["confidentiality_before"], stats["confidentiality_after"]]
        colors = ["#ff6666", "#66ff66"]
        bars = ax.bar(categories, conf_rates, color=colors, alpha=0.8, edgecolor="black", linewidth=2)
        for bar, rate in zip(bars, conf_rates):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2.0, height, f"{rate:.1f}%", ha="center", va="bottom")
        ax.set_ylabel("Confidentiality Rate (%)")
        ax.set_title("Confidentiality Rate: Before vs After Prevention Mechanism")
        ax.set_ylim(0, 110)
        ax.grid(axis="y", alpha=0.3)
        ax.axhline(y=100, color="green", linestyle="--", alpha=0.5, label="Target 100%")
        ax.legend()
        plt.tight_layout()
        self.figures["confidentiality"] = fig
        return fig

    def fig4_latency_overhead(self):
        data = self.test_runner.test_results["latency_data"]
        avg_low_setup = sum(d["low_deg_setup"] for d in data) / len(data)
        avg_high_setup = sum(d["high_deg_setup"] for d in data) / len(data)
        avg_overhead = sum(d["overhead"] for d in data) / len(data)
        fig, ax = plt.subplots(figsize=(10, 6))
        categories = ["Low Degree\nSetup", "High Degree\nSetup", "Security\nOverhead"]
        times = [avg_low_setup * 1000, avg_high_setup * 1000, avg_overhead * 1000]
        colors = ["#ff9800", "#4caf50", "#9c27b0"]
        bars = ax.bar(categories, times, color=colors, alpha=0.8, edgecolor="black", linewidth=2)
        for bar, time_val in zip(bars, times):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2.0, height, f"{time_val:.3f} ms", ha="center", va="bottom")
        ax.set_ylabel("Time (milliseconds)")
        ax.set_title("Latency Comparison: Attack vs Prevention Mechanism")
        ax.grid(axis="y", alpha=0.3)
        plt.tight_layout()
        self.figures["latency"] = fig
        return fig

    def save_all(self, prefix="graph"):
        paths = []
        for name, fig in self.figures.items():
            path = os.path.join(self.output_dir, f"{prefix}_{name}.png")
            fig.savefig(path, dpi=150, bbox_inches="tight")
            paths.append(path)
        return paths

