class FiniteField:
    """Prime field arithmetic for Shamir's Secret Sharing."""

    def __init__(self, prime: int):
        self.prime = prime

    def add(self, a: int, b: int) -> int:
        return (a + b) % self.prime

    def sub(self, a: int, b: int) -> int:
        return (a - b) % self.prime

    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.prime

    def pow(self, a: int, e: int) -> int:
        """Modular exponentiation."""
        result = 1
        a = a % self.prime
        while e > 0:
            if e & 1:
                result = (result * a) % self.prime
            a = (a * a) % self.prime
            e >>= 1
        return result

    def inv(self, a: int) -> int:
        """Modular multiplicative inverse using Fermat's little theorem."""
        if a == 0:
            raise ValueError("Cannot invert 0")
        return self.pow(a, self.prime - 2)

    def div(self, a: int, b: int) -> int:
        return self.mul(a, self.inv(b))

