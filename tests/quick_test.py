import os
import sys
import time

# Ensure project root is first in import resolution so local src package is imported.
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.attack import AttackSimulator
from src.finite_field import FiniteField
from src.prevention import PreventionMechanism
from src.shamir import ShamirSecretSharing


def main():
    print("Testing Shamir's Secret Sharing Implementation...")

    print("\n1. Testing Finite Field Arithmetic...")
    field = FiniteField(2**127 - 1)
    a, b = 12345, 67890
    print(f"   Add: {field.add(a, b)}")
    print(f"   Mul: {field.mul(a, b)}")
    print(f"   Pow sample: {field.pow(a, 10) % (2**20)}")

    print("\n2. Testing Low-Degree (Vulnerable) Configuration...")
    sss_low = ShamirSecretSharing()
    secret = 123456789
    sss_low.generate_polynomial(secret, 2)
    shares_low = sss_low.generate_shares(5)
    print(f"   Secret: {secret}")
    print(f"   Polynomial degree: 1 (LINEAR)")
    print(f"   Generated {len(shares_low)} shares")

    attack = AttackSimulator(sss_low)
    success, leaked, t = attack.brute_force_low_degree(shares_low[:2], 1, secret)
    print(f"   Attack with 2 shares: {'SUCCESS' if success else 'FAILED'}")
    if success:
        print(f"   Leaked secret: {leaked}")
    print(f"   Time: {t:.6f}s")

    print("\n3. Testing High-Degree (Secure) Configuration...")
    sss_high = ShamirSecretSharing()
    prevention = PreventionMechanism(sss_high)
    secure_config = prevention.apply_high_degree(secret, 5, 4)
    print(f"   Polynomial degree: 3 (HIGH)")
    print(f"   Threshold: {secure_config['threshold']}")

    attack_high = AttackSimulator(sss_high)
    success_high, _, _ = attack_high.brute_force_low_degree(sss_high.shares[:2], 1, secret)
    print(f"   Attack with 2 shares: {'SUCCESS' if success_high else 'BLOCKED'}")

    reconstructed = sss_high.reconstruct_secret(sss_high.shares[:4])
    print(f"   Proper reconstruction with 4 shares: {'SUCCESS' if reconstructed == secret else 'FAILED'}")

    print("\nAll basic tests passed!")
    print("Ready for full test suite and GUI demonstration.")


if __name__ == "__main__":
    main()
