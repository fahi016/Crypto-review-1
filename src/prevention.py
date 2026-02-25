import time
from typing import Dict, List, Tuple

from .shamir import ShamirSecretSharing


class PreventionMechanism:
    def __init__(self, sss: ShamirSecretSharing):
        self.sss = sss

    def apply_high_degree(self, secret: int, n: int, t_high: int) -> Dict:
        start_time = time.time()
        coeffs = self.sss.generate_polynomial(secret, t_high)
        shares = self.sss.generate_shares(n)
        commitments = self.sss.create_commitments()
        elapsed = time.time() - start_time
        return {
            "coefficients": coeffs,
            "shares": shares,
            "commitments": commitments,
            "threshold": t_high,
            "time": elapsed,
            "degree": t_high - 1,
        }

    def verify_and_reconstruct(
        self, shares: List[Tuple[int, int]], commitments: List[int]
    ) -> Tuple[bool, int]:
        for share in shares:
            if not self.sss.verify_share(share, commitments):
                return (False, None)
        secret = self.sss.reconstruct_secret(shares)
        return (True, secret)

