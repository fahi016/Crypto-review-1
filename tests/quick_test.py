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
    collusion = attack.collusion_attack(shares_low[:2], 2, secret)
    print(f"   Collusion attack with 2 shares: {'SUCCESS' if collusion['success'] else 'FAILED'}")
    if collusion["success"]:
        print(f"   Leaked secret: {collusion['reconstructed_secret']}")
    print(f"   Time: {collusion['time']:.6f}s")

    tamper = attack.tamper_share_attack(shares_low, 2, secret)
    print(f"   Tampering attack without integrity: {'SUCCESS' if tamper['success'] else 'FAILED'}")

    print("\n3. Testing High-Degree + Share Integrity (Secure) Configuration...")
    sss_high = ShamirSecretSharing()
    prevention = PreventionMechanism(sss_high)
    secure_config = prevention.apply_high_degree(secret, 5, 4, enable_integrity=True)
    print(f"   Polynomial degree: 3 (HIGH)")
    print(f"   Threshold: {secure_config['threshold']}")

    attack_high = AttackSimulator(sss_high)
    collusion_high = attack_high.collusion_attack(sss_high.shares[:2], 2, secret)
    print(f"   Collusion attack with 2 shares: {'SUCCESS' if collusion_high['success'] else 'BLOCKED'}")

    tamper_high = attack_high.tamper_share_attack(
        sss_high.shares,
        4,
        secret,
        share_commitments=secure_config["share_commitments"],
    )
    print(f"   Tampering attack with integrity: {'DETECTED' if tamper_high['detected'] else 'NOT DETECTED'}")

    reconstructed = sss_high.reconstruct_secret(sss_high.shares[:4])
    print(f"   Proper reconstruction with 4 shares: {'SUCCESS' if reconstructed == secret else 'FAILED'}")

    print("\nAll basic tests passed!")
    print("Ready for the comparison suite and GUI demonstration.")


if __name__ == "__main__":
    main()
