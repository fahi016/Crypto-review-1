import hashlib
import random
from typing import Dict, List, Optional, Tuple

from .finite_field import FiniteField


class ShamirSecretSharing:
    """
    Shamir's Secret Sharing implementation from scratch.
    Uses polynomial: f(x) = s + a1*x + a2*x^2 + ... + a_{t-1}*x^{t-1}
    """

    def __init__(self, prime: int = 2**127 - 1):
        self.field = FiniteField(prime)
        self.prime = prime
        self.shares = []
        self.coefficients = []
        self.commitments = []
        self.share_commitments = {}
        self.secret = None
        self.threshold = None
        self.total_shares = None

    def generate_polynomial(self, secret: int, threshold: int) -> List[int]:
        self.secret = secret
        self.threshold = threshold
        coeffs = [secret % self.prime]
        for _ in range(threshold - 1):
            coeff = random.randint(1, self.prime - 1)
            coeffs.append(coeff)
        self.coefficients = coeffs
        return coeffs

    def evaluate_polynomial(self, x: int) -> int:
        result = 0
        for coeff in reversed(self.coefficients):
            result = self.field.add(self.field.mul(result, x), coeff)
        return result

    def generate_shares(self, n: int) -> List[Tuple[int, int]]:
        self.total_shares = n
        self.shares = []
        for i in range(1, n + 1):
            y = self.evaluate_polynomial(i)
            self.shares.append((i, y))
        return self.shares

    def create_commitments(self) -> List[int]:
        self.commitments = []
        for coeff in self.coefficients:
            commitment = int(hashlib.sha256(str(coeff).encode()).hexdigest(), 16) % self.prime
            self.commitments.append(commitment)
        return self.commitments

    @staticmethod
    def _share_digest(share: Tuple[int, int]) -> str:
        x, y = share
        return hashlib.sha256(f"{x}:{y}".encode()).hexdigest()

    def create_share_commitments(self, shares: Optional[List[Tuple[int, int]]] = None) -> Dict[int, str]:
        share_list = shares if shares is not None else self.shares
        self.share_commitments = {x: self._share_digest((x, y)) for x, y in share_list}
        return dict(self.share_commitments)

    def verify_share(self, share: Tuple[int, int], commitments: Dict[int, str]) -> bool:
        if not commitments:
            return False
        x, y = share
        expected_digest = commitments.get(x)
        if expected_digest is None:
            return False
        return expected_digest == self._share_digest((x, y))

    def verify_shares(self, shares: List[Tuple[int, int]], commitments: Dict[int, str]) -> bool:
        return all(self.verify_share(share, commitments) for share in shares)

    @staticmethod
    def lagrange_interpolation(shares: List[Tuple[int, int]], prime: int, x: int = 0) -> int:
        field = FiniteField(prime)
        result = 0
        for i, (xi, yi) in enumerate(shares):
            numerator = 1
            denominator = 1
            for j, (xj, _) in enumerate(shares):
                if i != j:
                    numerator = field.mul(numerator, field.sub(x, xj))
                    denominator = field.mul(denominator, field.sub(xi, xj))
            li_x = field.div(numerator, denominator)
            term = field.mul(yi, li_x)
            result = field.add(result, term)
        return result

    @staticmethod
    def lagrange_interpolation_steps(shares: List[Tuple[int, int]], prime: int) -> Tuple[int, List[str]]:
        """
        Same as lagrange_interpolation at x=0, but returns step-by-step log lines
        showing exactly how each share contributes to the reconstruction.
        """
        field = FiniteField(prime)
        steps = []
        steps.append(f"Reconstructing secret using {len(shares)} shares via Lagrange interpolation:")
        steps.append(f"  Shares used: {shares}")
        steps.append(f"  Evaluating polynomial at x=0 (the secret lives at f(0))")
        steps.append("")

        result = 0
        for i, (xi, yi) in enumerate(shares):
            numerator = 1
            denominator = 1
            for j, (xj, _) in enumerate(shares):
                if i != j:
                    numerator = field.mul(numerator, field.sub(0, xj))
                    denominator = field.mul(denominator, field.sub(xi, xj))
            li_x = field.div(numerator, denominator)
            term = field.mul(yi, li_x)
            result = field.add(result, term)
            steps.append(f"  Share {i+1}: x={xi}, y={yi}")
            steps.append(f"    Lagrange basis L_{i}(0) = {li_x}")
            steps.append(f"    Contribution = y * L_{i}(0) = {yi} * {li_x} = {term} (mod p)")

        steps.append("")
        steps.append(f"  Sum of all contributions = {result}")
        steps.append(f"  => Recovered secret: {result}")
        return result, steps

    def reconstruct_secret(self, shares: List[Tuple[int, int]]) -> int:
        if len(shares) < self.threshold:
            raise ValueError(f"Need at least {self.threshold} shares, got {len(shares)}")
        secret = self.lagrange_interpolation(shares, self.prime, 0)
        return secret