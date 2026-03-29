import time
from typing import Dict, List, Optional, Tuple

from .shamir import ShamirSecretSharing


class PreventionMechanism:
    def __init__(self, sss: ShamirSecretSharing):
        self.sss = sss

    def apply_high_degree(self, secret: int, n: int, t_high: int, enable_integrity: bool = True) -> Dict:
        start_time = time.perf_counter()
        coeffs = self.sss.generate_polynomial(secret, t_high)
        shares = self.sss.generate_shares(n)
        coefficient_commitments = self.sss.create_commitments()
        share_commitments = self.sss.create_share_commitments(shares) if enable_integrity else {}
        elapsed = time.perf_counter() - start_time
        return {
            "coefficients": coeffs,
            "shares": shares,
            "coefficient_commitments": coefficient_commitments,
            "share_commitments": share_commitments,
            "threshold": t_high,
            "time": elapsed,
            "degree": t_high - 1,
            "integrity_enabled": enable_integrity,
        }

    def verify_and_reconstruct(
        self, shares: List[Tuple[int, int]], share_commitments: Optional[Dict[int, str]] = None
    ) -> Tuple[bool, int]:
        if share_commitments and not self.sss.verify_shares(shares, share_commitments):
            return (False, None)
        secret = self.sss.reconstruct_secret(shares)
        return (True, secret)
