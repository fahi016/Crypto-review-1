import random
import time
from typing import Dict, List

from .attack import AttackSimulator
from .shamir import ShamirSecretSharing


class TestRunner:
    PROFILE_CONFIGS = {
        "baseline_low": {
            "label": "Low Threshold / No Integrity",
            "threshold_mode": "low",
            "integrity_enabled": False,
        },
        "low_with_integrity": {
            "label": "Low Threshold / Share Integrity",
            "threshold_mode": "low",
            "integrity_enabled": True,
        },
        "high_no_integrity": {
            "label": "High Threshold / No Integrity",
            "threshold_mode": "high",
            "integrity_enabled": False,
        },
        "high_with_integrity": {
            "label": "High Threshold / Share Integrity",
            "threshold_mode": "high",
            "integrity_enabled": True,
        },
    }

    def __init__(self):
        self.reset_results()

    def reset_results(self):
        self.test_results = {
            "profiles": {
                name: {
                    "label": config["label"],
                    "integrity_enabled": config["integrity_enabled"],
                    "collusion_success": [],
                    "tamper_success": [],
                    "tamper_detected": [],
                    "honest_reconstruction": [],
                    "setup_times": [],
                    "verification_times": [],
                    "collusion_times": [],
                    "tamper_times": [],
                    "thresholds": [],
                    "degrees": [],
                    "n_values": [],
                }
                for name, config in self.PROFILE_CONFIGS.items()
            },
            "time_vs_degree": [],
            "comparison_rows": [],
        }

    @staticmethod
    def _average(values: List[float]) -> float:
        return sum(values) / len(values) if values else 0.0

    def _build_profile_configuration(
        self, secret: int, n: int, threshold: int, integrity_enabled: bool
    ) -> Dict[str, object]:
        sss = ShamirSecretSharing()

        start_setup = time.perf_counter()
        sss.generate_polynomial(secret, threshold)
        shares = sss.generate_shares(n)
        coefficient_commitments = sss.create_commitments()
        share_commitments = sss.create_share_commitments(shares) if integrity_enabled else {}
        setup_time = time.perf_counter() - start_setup

        start_verify = time.perf_counter()
        honest_verified = True
        if integrity_enabled:
            honest_verified = sss.verify_shares(shares[:threshold], share_commitments)
        verification_time = time.perf_counter() - start_verify

        start_reconstruct = time.perf_counter()
        honest_reconstruction = sss.reconstruct_secret(shares[:threshold]) == secret
        reconstruction_time = time.perf_counter() - start_reconstruct

        return {
            "sss": sss,
            "shares": shares,
            "threshold": threshold,
            "setup_time": setup_time,
            "verification_time": verification_time,
            "reconstruction_time": reconstruction_time,
            "honest_verified": honest_verified,
            "honest_reconstruction": honest_reconstruction,
            "coefficient_commitments": coefficient_commitments,
            "share_commitments": share_commitments,
        }

    def _run_profile(
        self,
        profile_name: str,
        secret: int,
        n: int,
        threshold: int,
        collusion_budget: int,
        integrity_enabled: bool,
    ) -> Dict[str, object]:
        config = self._build_profile_configuration(secret, n, threshold, integrity_enabled)
        attack = AttackSimulator(config["sss"])

        collusion_result = attack.collusion_attack(config["shares"][:collusion_budget], collusion_budget, secret)
        tamper_result = attack.tamper_share_attack(
            config["shares"],
            threshold,
            secret,
            share_commitments=config["share_commitments"] if integrity_enabled else None,
        )

        profile_metrics = self.test_results["profiles"][profile_name]
        profile_metrics["collusion_success"].append(1 if collusion_result["success"] else 0)
        profile_metrics["tamper_success"].append(1 if tamper_result["success"] else 0)
        profile_metrics["tamper_detected"].append(1 if tamper_result["detected"] else 0)
        profile_metrics["honest_reconstruction"].append(1 if config["honest_reconstruction"] else 0)
        profile_metrics["setup_times"].append(config["setup_time"])
        profile_metrics["verification_times"].append(config["verification_time"])
        profile_metrics["collusion_times"].append(collusion_result["time"])
        profile_metrics["tamper_times"].append(tamper_result["time"])
        profile_metrics["thresholds"].append(threshold)
        profile_metrics["degrees"].append(threshold - 1)
        profile_metrics["n_values"].append(n)

        self.test_results["time_vs_degree"].append(
            {
                "profile": profile_name,
                "degree": threshold - 1,
                "setup_time": config["setup_time"],
                "verification_time": config["verification_time"],
                "reconstruction_time": config["reconstruction_time"],
            }
        )

        return {
            "profile": profile_name,
            "label": self.PROFILE_CONFIGS[profile_name]["label"],
            "threshold": threshold,
            "integrity_enabled": integrity_enabled,
            "collusion": collusion_result,
            "tampering": tamper_result,
            "honest_reconstruction": config["honest_reconstruction"],
            "honest_verified": config["honest_verified"],
            "setup_time": config["setup_time"],
            "verification_time": config["verification_time"],
            "reconstruction_time": config["reconstruction_time"],
        }

    def run_test_case(self, test_id: int, secret: int, n: int, low_t: int, high_t: int) -> Dict[str, object]:
        collusion_budget = low_t
        result = {
            "test_id": test_id,
            "secret": secret,
            "n": n,
            "low_threshold": low_t,
            "high_threshold": high_t,
            "collusion_budget": collusion_budget,
            "profiles": {},
        }

        for profile_name, config in self.PROFILE_CONFIGS.items():
            threshold = low_t if config["threshold_mode"] == "low" else high_t
            profile_result = self._run_profile(
                profile_name,
                secret,
                n,
                threshold,
                collusion_budget,
                config["integrity_enabled"],
            )
            result["profiles"][profile_name] = profile_result

        self.test_results["comparison_rows"].append(
            {
                "test_id": test_id,
                "baseline_collusion": result["profiles"]["baseline_low"]["collusion"]["success"],
                "baseline_tampering": result["profiles"]["baseline_low"]["tampering"]["success"],
                "secure_collusion": result["profiles"]["high_with_integrity"]["collusion"]["success"],
                "secure_tampering": result["profiles"]["high_with_integrity"]["tampering"]["success"],
            }
        )
        return result

    def run_full_test_suite(self, num_tests: int = 25) -> List[Dict[str, object]]:
        self.reset_results()
        all_results = []
        for i in range(num_tests):
            secret = random.randint(1000, 1_000_000)
            n = random.randint(5, 10)
            low_t = random.choice([2, 3])
            high_t = max(n - 1, low_t + 2)
            all_results.append(self.run_test_case(i + 1, secret, n, low_t, high_t))
        return all_results

    def calculate_statistics(self) -> Dict[str, object]:
        profile_stats = {}
        for profile_name, data in self.test_results["profiles"].items():
            collusion_success_rate = self._average(data["collusion_success"]) * 100
            tamper_success_rate = self._average(data["tamper_success"]) * 100
            tamper_detection_rate = self._average(data["tamper_detected"]) * 100
            honest_reconstruction_rate = self._average(data["honest_reconstruction"]) * 100
            avg_setup_time = self._average(data["setup_times"])
            avg_verification_time = self._average(data["verification_times"])
            avg_collusion_time = self._average(data["collusion_times"])
            avg_tamper_time = self._average(data["tamper_times"])

            profile_stats[profile_name] = {
                "label": data["label"],
                "integrity_enabled": data["integrity_enabled"],
                "collusion_success_rate": collusion_success_rate,
                "tamper_success_rate": tamper_success_rate,
                "tamper_detection_rate": tamper_detection_rate,
                "confidentiality_rate": 100.0 - collusion_success_rate,
                "integrity_rate": 100.0 - tamper_success_rate,
                "authentication_rate": tamper_detection_rate if data["integrity_enabled"] else 0.0,
                "honest_reconstruction_rate": honest_reconstruction_rate,
                "avg_setup_time": avg_setup_time,
                "avg_verification_time": avg_verification_time,
                "avg_collusion_time": avg_collusion_time,
                "avg_tamper_time": avg_tamper_time,
                "avg_total_protection_time": avg_setup_time + avg_verification_time,
            }

        baseline = profile_stats.get("baseline_low", {})
        secure = profile_stats.get("high_with_integrity", {})

        return {
            "profiles": profile_stats,
            "low_degree_success_rate": baseline.get("collusion_success_rate", 0.0),
            "high_degree_attack_success_rate": secure.get("collusion_success_rate", 0.0),
            "tamper_success_before": baseline.get("tamper_success_rate", 0.0),
            "tamper_success_after": secure.get("tamper_success_rate", 0.0),
            "confidentiality_before": baseline.get("confidentiality_rate", 0.0),
            "confidentiality_after": secure.get("confidentiality_rate", 0.0),
            "integrity_before": baseline.get("integrity_rate", 0.0),
            "integrity_after": secure.get("integrity_rate", 0.0),
            "authentication_before": baseline.get("authentication_rate", 0.0),
            "authentication_after": secure.get("authentication_rate", 0.0),
            "avg_latency_overhead": secure.get("avg_total_protection_time", 0.0)
            - baseline.get("avg_setup_time", 0.0),
        }
