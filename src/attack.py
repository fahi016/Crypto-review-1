import time
from typing import List, Tuple

from .shamir import ShamirSecretSharing


class AttackSimulator:
    def __init__(self, sss: ShamirSecretSharing):
        self.sss = sss

    def brute_force_low_degree(
        self, shares: List[Tuple[int, int]], guessed_degree: int, secret: int
    ) -> Tuple[bool, int, float]:
        start_time = time.time()
        if len(shares) < guessed_degree + 1:
            elapsed = time.time() - start_time
            return (False, None, elapsed)
        try:
            reconstructed = ShamirSecretSharing.lagrange_interpolation(
                shares[: guessed_degree + 1], self.sss.prime, 0
            )
            elapsed = time.time() - start_time
            success = reconstructed == secret
            return (success, reconstructed if success else None, elapsed)
        except Exception:
            elapsed = time.time() - start_time
            return (False, None, elapsed)

