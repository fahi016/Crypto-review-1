import random
import time
from typing import Dict, List

from .attack import AttackSimulator
from .prevention import PreventionMechanism
from .shamir import ShamirSecretSharing


class TestRunner:
    def __init__(self):
        self.test_results = {
            "low_degree_attack": [],
            "high_degree_prevention": [],
            "confidentiality_rates": [],
            "latency_data": [],
            "time_vs_degree": [],
        }

    def run_test_case(
        self, test_id: int, secret: int, n: int, low_t: int, high_t: int, attack_shares: int
    ) -> Dict:
        result = {
            "test_id": test_id,
            "secret": secret,
            "n": n,
            "low_threshold": low_t,
            "high_threshold": high_t,
            "attack_shares": attack_shares,
        }

        sss_low = ShamirSecretSharing()
        sss_low.generate_polynomial(secret, low_t)
        sss_low.generate_shares(n)
        attack = AttackSimulator(sss_low)
        success, leaked_secret, attack_time = attack.brute_force_low_degree(
            sss_low.shares, low_t - 1, secret
        )
        result["low_degree"] = {
            "success": success,
            "leaked": leaked_secret if success else None,
            "time": attack_time,
            "confidentiality_breach": success,
        }

        sss_high = ShamirSecretSharing()
        prevention = PreventionMechanism(sss_high)
        start_prevention = time.time()
        prevention.apply_high_degree(secret, n, high_t)
        prevention_time = time.time() - start_prevention

        attack_high = AttackSimulator(sss_high)
        success_high, _, attack_time_high = attack_high.brute_force_low_degree(
            sss_high.shares[:attack_shares], low_t - 1, secret
        )
        proper_reconstruct = sss_high.reconstruct_secret(sss_high.shares[:high_t])
        correct_reconstruction = proper_reconstruct == secret

        result["high_degree"] = {
            "attack_success": success_high,
            "proper_reconstruct": correct_reconstruction,
            "setup_time": prevention_time,
            "attack_time": attack_time_high,
            "confidentiality_maintained": not success_high,
        }
        result["latency_overhead"] = prevention_time - (attack_time if attack_time > 0 else 0.001)
        return result

    def run_full_test_suite(self, num_tests: int = 20) -> List[Dict]:
        for key in self.test_results:
            self.test_results[key] = []
        all_results = []
        for i in range(num_tests):
            secret = random.randint(1000, 1000000)
            n = random.randint(5, 10)
            low_t = random.choice([2, 3])
            high_t = max(n - 1, low_t + 2)
            attack_shares = low_t - 1
            test_result = self.run_test_case(i + 1, secret, n, low_t, high_t, attack_shares)
            all_results.append(test_result)
            self.test_results["low_degree_attack"].append(1 if test_result["low_degree"]["success"] else 0)
            self.test_results["high_degree_prevention"].append(
                1 if test_result["high_degree"]["attack_success"] else 0
            )
            self.test_results["confidentiality_rates"].append(
                {
                    "before": 0 if test_result["low_degree"]["confidentiality_breach"] else 1,
                    "after": 1 if test_result["high_degree"]["confidentiality_maintained"] else 0,
                }
            )
            self.test_results["latency_data"].append(
                {
                    "low_deg_setup": test_result["low_degree"]["time"],
                    "high_deg_setup": test_result["high_degree"]["setup_time"],
                    "overhead": test_result["latency_overhead"],
                }
            )
            self.test_results["time_vs_degree"].append(
                {
                    "low_degree": low_t - 1,
                    "high_degree": high_t - 1,
                    "low_time": test_result["low_degree"]["time"],
                    "high_time": test_result["high_degree"]["attack_time"],
                }
            )
        return all_results

    def calculate_statistics(self) -> Dict:
        stats = {
            "low_degree_success_rate": 0,
            "high_degree_attack_success_rate": 0,
            "confidentiality_before": 0,
            "confidentiality_after": 0,
            "avg_latency_overhead": 0,
        }
        if self.test_results["low_degree_attack"]:
            stats["low_degree_success_rate"] = (
                sum(self.test_results["low_degree_attack"]) / len(self.test_results["low_degree_attack"]) * 100
            )
        if self.test_results["high_degree_prevention"]:
            stats["high_degree_attack_success_rate"] = (
                sum(self.test_results["high_degree_prevention"])
                / len(self.test_results["high_degree_prevention"])
                * 100
            )
        if self.test_results["confidentiality_rates"]:
            conf_before = (
                sum(1 for x in self.test_results["confidentiality_rates"] if x["before"] == 1)
                / len(self.test_results["confidentiality_rates"])
                * 100
            )
            conf_after = (
                sum(1 for x in self.test_results["confidentiality_rates"] if x["after"] == 1)
                / len(self.test_results["confidentiality_rates"])
                * 100
            )
            stats["confidentiality_before"] = conf_before
            stats["confidentiality_after"] = conf_after
        if self.test_results["latency_data"]:
            stats["avg_latency_overhead"] = sum(x["overhead"] for x in self.test_results["latency_data"]) / len(
                self.test_results["latency_data"]
            )
        return stats

