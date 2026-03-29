import random
import time
from typing import Dict, List, Optional, Tuple

from .shamir import ShamirSecretSharing


class AttackSimulator:
    def __init__(self, sss: ShamirSecretSharing):
        self.sss = sss

    def brute_force_low_degree(
        self, shares: List[Tuple[int, int]], guessed_degree: int, secret: int
    ) -> Tuple[bool, int, float]:
        result = self.collusion_attack(shares, guessed_degree + 1, secret)
        return (result["success"], result["reconstructed_secret"], result["time"])

    def collusion_attack(self, shares: List[Tuple[int, int]], share_budget: int, secret: int) -> Dict[str, object]:
        start_time = time.perf_counter()
        if len(shares) < share_budget:
            elapsed = time.perf_counter() - start_time
            return {
                "attack_type": "collusion",
                "success": False,
                "reconstructed_secret": None,
                "time": elapsed,
                "share_budget": share_budget,
                "notes": "Insufficient compromised shares for interpolation.",
            }
        try:
            reconstructed = ShamirSecretSharing.lagrange_interpolation(
                shares[:share_budget], self.sss.prime, 0
            )
            elapsed = time.perf_counter() - start_time
            success = reconstructed == secret
            return {
                "attack_type": "collusion",
                "success": success,
                "reconstructed_secret": reconstructed,
                "time": elapsed,
                "share_budget": share_budget,
                "notes": "Secret recovered from compromised shares." if success else "Interpolation guess was incorrect.",
            }
        except Exception:
            elapsed = time.perf_counter() - start_time
            return {
                "attack_type": "collusion",
                "success": False,
                "reconstructed_secret": None,
                "time": elapsed,
                "share_budget": share_budget,
                "notes": "Interpolation failed.",
            }

    def tamper_share_attack(
        self,
        shares: List[Tuple[int, int]],
        threshold: int,
        secret: int,
        share_commitments: Optional[Dict[int, str]] = None,
        tamper_index: int = 0,
        tamper_delta: Optional[int] = None,
    ) -> Dict[str, object]:
        start_time = time.perf_counter()
        if len(shares) < threshold:
            elapsed = time.perf_counter() - start_time
            return {
                "attack_type": "tampering",
                "success": False,
                "detected": False,
                "reconstructed_secret": None,
                "time": elapsed,
                "notes": "Not enough shares supplied for reconstruction.",
            }

        candidate_shares = list(shares[:threshold])
        target_index = max(0, min(tamper_index, threshold - 1))
        forged_share = self._forge_share(candidate_shares[target_index], tamper_delta)
        candidate_shares[target_index] = forged_share

        if share_commitments and not self.sss.verify_shares(candidate_shares, share_commitments):
            elapsed = time.perf_counter() - start_time
            return {
                "attack_type": "tampering",
                "success": False,
                "detected": True,
                "reconstructed_secret": None,
                "time": elapsed,
                "forged_share": forged_share,
                "notes": "Tampered share was detected by integrity verification.",
            }

        try:
            reconstructed = self.sss.reconstruct_secret(candidate_shares)
            elapsed = time.perf_counter() - start_time
            success = reconstructed != secret
            return {
                "attack_type": "tampering",
                "success": success,
                "detected": False,
                "reconstructed_secret": reconstructed,
                "time": elapsed,
                "forged_share": forged_share,
                "notes": "Tampered share changed the reconstructed secret."
                if success
                else "Tampered share did not alter reconstruction.",
            }
        except Exception:
            elapsed = time.perf_counter() - start_time
            return {
                "attack_type": "tampering",
                "success": False,
                "detected": False,
                "reconstructed_secret": None,
                "time": elapsed,
                "forged_share": forged_share,
                "notes": "Tampering caused reconstruction to fail.",
            }

    def _forge_share(self, share: Tuple[int, int], tamper_delta: Optional[int] = None) -> Tuple[int, int]:
        x, y = share
        delta = tamper_delta if tamper_delta is not None else random.randint(1, 10_000)
        return (x, (y + delta) % self.sss.prime)
