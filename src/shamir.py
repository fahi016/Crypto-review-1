import hashlib
import random
from typing import List, Tuple

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

    def verify_share(self, share: Tuple[int, int], commitments: List[int]) -> bool:
        x, y = share
        expected_y = self.evaluate_polynomial(x)
        return y == expected_y

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

    def reconstruct_secret(self, shares: List[Tuple[int, int]]) -> int:
        if len(shares) < self.threshold:
            raise ValueError(f"Need at least {self.threshold} shares, got {len(shares)}")
        secret = self.lagrange_interpolation(shares, self.prime, 0)
        return secret

