import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from .test_runner import TestRunner


class GraphGenerator:
    PROFILE_ORDER = ["baseline_low", "low_with_integrity", "high_no_integrity", "high_with_integrity"]
    PROFILE_COLORS = {
        "baseline_low": "#d32f2f",
        "low_with_integrity": "#fb8c00",
        "high_no_integrity": "#1976d2",
        "high_with_integrity": "#2e7d32",
    }

    MIN_VISIBLE = 1.5  # minimum bar height so 0% bars are still visible

    def __init__(self, test_runner: TestRunner):
        self.test_runner = test_runner
        self.figures = {}
        self.output_dir = os.path.join(os.getcwd(), "output")
        os.makedirs(self.output_dir, exist_ok=True)

    def _bar_height(self, value):
        """Return at least MIN_VISIBLE so zero bars still show on the chart."""
        return max(value, self.MIN_VISIBLE)

    def _annotate_bar(self, ax, bar, real_value):
        """Put the real percentage label above the bar."""
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            height + 0.5,
            f"{real_value:.1f}%",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    def generate_all_graphs(self):
        self.fig1_success_rate()
        self.fig2_time_vs_degree()
        self.fig3_confidentiality()
        self.fig4_latency_overhead()
        self.fig5_attack_comparison()

    def fig1_success_rate(self):
        stats = self.test_runner.calculate_statistics()
        fig, ax = plt.subplots(figsize=(10, 6))
        categories = ["Before Prevention\n(Low Threshold)", "After Prevention\n(High Threshold + Integrity)"]
        real_rates = [stats["low_degree_success_rate"], stats["high_degree_attack_success_rate"]]
        display_rates = [self._bar_height(r) for r in real_rates]
        colors = ["#ff4444", "#44ff44"]
        bars = ax.bar(categories, display_rates, color=colors, alpha=0.85, edgecolor="black", linewidth=2)
        for bar, real in zip(bars, real_rates):
            self._annotate_bar(ax, bar, real)
        ax.set_ylabel("Collusion Attack Success Rate (%)")
        ax.set_title("Before vs After Prevention: Collusion Attack Success Rate")
        ax.set_ylim(0, 110)
        ax.grid(axis="y", alpha=0.3)
        ax.axhline(y=90, color="red", linestyle="--", alpha=0.5, label="90% threshold")
        ax.legend()
        plt.tight_layout()
        self.figures["success_rate"] = fig
        return fig

    def fig2_time_vs_degree(self):
        data = self.test_runner.test_results["time_vs_degree"]
        profile_degree_times = {profile: {} for profile in self.PROFILE_ORDER}
        for row in data:
            total_time = row["setup_time"] + row["verification_time"] + row["reconstruction_time"]
            degree_times = profile_degree_times[row["profile"]]
            degree_times.setdefault(row["degree"], []).append(total_time)

        fig, ax = plt.subplots(figsize=(10, 6))
        for profile in self.PROFILE_ORDER:
            degree_times = profile_degree_times[profile]
            if not degree_times:
                continue
            degrees = sorted(degree_times.keys())
            avg_times = [sum(degree_times[d]) / len(degree_times[d]) for d in degrees]
            label = self.test_runner.PROFILE_CONFIGS[profile]["label"]
            ax.plot(
                degrees,
                avg_times,
                marker="o",
                linewidth=2,
                markersize=7,
                color=self.PROFILE_COLORS[profile],
                label=label,
            )

        max_degree = max((row["degree"] for row in data), default=4)
        ax.axvspan(0.5, 2.5, alpha=0.12, color="red", label="Low-degree region")
        ax.axvspan(2.5, max_degree + 0.5, alpha=0.08, color="green", label="High-degree region")
        ax.set_xlabel("Polynomial Degree / Threshold-1")
        ax.set_ylabel("Average End-to-End Time (seconds)")
        ax.set_title("Time vs Degree Across Solution Profiles")
        ax.grid(True, alpha=0.3)
        ax.legend()
        plt.tight_layout()
        self.figures["time_vs_degree"] = fig
        return fig

    def fig3_confidentiality(self):
        stats = self.test_runner.calculate_statistics()
        fig, ax = plt.subplots(figsize=(11, 6))
        categories = ["Confidentiality", "Integrity", "Authentication"]

        real_before = [stats["confidentiality_before"], stats["integrity_before"], stats["authentication_before"]]
        real_after  = [stats["confidentiality_after"],  stats["integrity_after"],  stats["authentication_after"]]

        display_before = [self._bar_height(v) for v in real_before]
        display_after  = [self._bar_height(v) for v in real_after]

        positions = range(len(categories))
        width = 0.35

        before_bars = ax.bar(
            [p - width / 2 for p in positions],
            display_before,
            width=width,
            color="#ef5350",
            alpha=0.85,
            edgecolor="black",
            label="Before Prevention",
        )
        after_bars = ax.bar(
            [p + width / 2 for p in positions],
            display_after,
            width=width,
            color="#66bb6a",
            alpha=0.85,
            edgecolor="black",
            label="After Prevention",
        )

        for bar, real in zip(before_bars, real_before):
            self._annotate_bar(ax, bar, real)
        for bar, real in zip(after_bars, real_after):
            self._annotate_bar(ax, bar, real)

        ax.set_xticks(list(positions))
        ax.set_xticklabels(categories)
        ax.set_ylabel("Security Rate (%)")
        ax.set_title("Confidentiality / Integrity / Authentication Rate")
        ax.set_ylim(0, 110)
        ax.grid(axis="y", alpha=0.3)
        ax.axhline(y=100, color="green", linestyle="--", alpha=0.5, label="Target 100%")
        ax.legend()
        plt.tight_layout()
        self.figures["confidentiality"] = fig
        return fig

    def fig4_latency_overhead(self):
        stats = self.test_runner.calculate_statistics()["profiles"]
        fig, ax = plt.subplots(figsize=(11, 6))
        categories = [stats[profile]["label"] for profile in self.PROFILE_ORDER]

        real_attack = [
            (stats[p]["avg_collusion_time"] + stats[p]["avg_tamper_time"]) * 1000
            for p in self.PROFILE_ORDER
        ]
        real_protection = [
            (stats[p]["avg_setup_time"] + stats[p]["avg_verification_time"]) * 1000
            for p in self.PROFILE_ORDER
        ]

        display_attack     = [self._bar_height(v) for v in real_attack]
        display_protection = [self._bar_height(v) for v in real_protection]

        positions = range(len(categories))
        width = 0.35

        attack_bars = ax.bar(
            [p - width / 2 for p in positions],
            display_attack,
            width=width,
            color="#ffb74d",
            alpha=0.85,
            edgecolor="black",
            label="Attack Latency",
        )
        protection_bars = ax.bar(
            [p + width / 2 for p in positions],
            display_protection,
            width=width,
            color="#42a5f5",
            alpha=0.85,
            edgecolor="black",
            label="Protection Overhead",
        )

        for bar, real in zip(attack_bars, real_attack):
            self._annotate_bar(ax, bar, real)
        for bar, real in zip(protection_bars, real_protection):
            self._annotate_bar(ax, bar, real)

        ax.set_xticks(list(positions))
        ax.set_xticklabels(categories, rotation=15, ha="right")
        ax.set_ylabel("Time (milliseconds)")
        ax.set_title("Attack vs Prevention Latency Overhead")
        ax.grid(axis="y", alpha=0.3)
        ax.legend()
        plt.tight_layout()
        self.figures["latency"] = fig
        return fig

    def fig5_attack_comparison(self):
        stats = self.test_runner.calculate_statistics()["profiles"]
        fig, ax = plt.subplots(figsize=(11, 6))
        categories = [stats[profile]["label"] for profile in self.PROFILE_ORDER]

        real_collusion = [stats[p]["collusion_success_rate"] for p in self.PROFILE_ORDER]
        real_tamper    = [stats[p]["tamper_success_rate"]    for p in self.PROFILE_ORDER]

        display_collusion = [self._bar_height(v) for v in real_collusion]
        display_tamper    = [self._bar_height(v) for v in real_tamper]

        positions = range(len(categories))
        width = 0.35

        collusion_bars = ax.bar(
            [p - width / 2 for p in positions],
            display_collusion,
            width=width,
            color="#e53935",
            alpha=0.85,
            edgecolor="black",
            label="Collusion Attack Success",
        )
        tamper_bars = ax.bar(
            [p + width / 2 for p in positions],
            display_tamper,
            width=width,
            color="#8e24aa",
            alpha=0.85,
            edgecolor="black",
            label="Tampering Attack Success",
        )

        for bar, real in zip(collusion_bars, real_collusion):
            self._annotate_bar(ax, bar, real)
        for bar, real in zip(tamper_bars, real_tamper):
            self._annotate_bar(ax, bar, real)

        ax.set_xticks(list(positions))
        ax.set_xticklabels(categories, rotation=15, ha="right")
        ax.set_ylabel("Attack Success Rate (%)")
        ax.set_title("Attack Success Comparison Across Different Solutions")
        ax.set_ylim(0, 110)
        ax.grid(axis="y", alpha=0.3)
        ax.legend()
        plt.tight_layout()
        self.figures["attack_comparison"] = fig
        return fig

    def save_all(self, prefix="graph"):
        paths = []
        for name, fig in self.figures.items():
            path = os.path.join(self.output_dir, f"{prefix}_{name}.png")
            fig.savefig(path, dpi=150, bbox_inches="tight")
            paths.append(path)
        return paths