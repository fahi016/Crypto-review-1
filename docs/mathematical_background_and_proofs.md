# Mathematical Background & Proofs
### Shamir's Secret Sharing Scheme

---

## 1. Variables and Parameters

| Symbol | Description |
|--------|-------------|
| s ∈ ℤ_p | The secret to be shared, where s ∈ [0, p−1] |
| p | Large prime number, p > s &nbsp;&nbsp;(typically p = 2¹²⁷ − 1) |
| n | Total number of shares to generate |
| t | Threshold — minimum shares needed for reconstruction (t ≤ n) |
| d = t − 1 | Degree of the polynomial |

---

## 2. Polynomial Construction

The secret is embedded as the constant term of a random polynomial over ℤ_p:

$$f(x) = s + a_1 x + a_2 x^2 + \cdots + a_{t-1} x^{t-1} \pmod{p}$$

Where:

- **a₀ = s** — the secret itself
- **a₁, a₂, …, a_{t−1}** — coefficients chosen uniformly at random from ℤ_p
- All arithmetic is performed in the finite field **ℤ_p**

---

## 3. Proof 1 — Why Low Degree Allows Reconstruction with Fewer Shares

### Theorem: Polynomial Interpolation Uniqueness

> Given d+1 distinct points (x₀, y₀), (x₁, y₁), …, (x_d, y_d) where xᵢ ≠ xⱼ for i ≠ j,
> there exists **exactly one** polynomial P(x) of degree at most d such that P(xᵢ) = yᵢ for all i.

&nbsp;

### Proof

**Existence** — Constructed via Lagrange interpolation:

$$P(x) = \sum_{i=0}^{d} \, y_i \cdot L_i(x)$$

Where the Lagrange basis polynomials are defined as:

$$L_i(x) = \prod_{j \neq i} \frac{x - x_j}{x_i - x_j}$$

&nbsp;

**Uniqueness** — Suppose Q(x) is another polynomial of degree ≤ d with Q(xᵢ) = yᵢ. Define:

$$R(x) = P(x) - Q(x)$$

Then R(x) has degree ≤ d and has d+1 roots (one at each xᵢ).
By the **Fundamental Theorem of Algebra** over fields, a non-zero polynomial of degree d has at most d roots.
Therefore R(x) = 0, which implies **P(x) = Q(x)**. ∎

&nbsp;

### Attack Implication

For a polynomial of degree d = t − 1:

- If the threshold is **t = 2** (degree 1, linear), an attacker needs only **2 shares**
- With 2 points (x₁, y₁) and (x₂, y₂), the attacker uniquely determines the line
- The secret is the y-intercept:

$$s = f(0) = y_1 - x_1 \cdot \frac{y_2 - y_1}{x_2 - x_1}$$

> ⚠️ **Security Breach:** With a low threshold t, an attacker needs to compromise only t participants — significantly weakening security.

---

## 4. Proof 2 — Why High Degree + Commitments Prevent the Attack

### Theorem: Information-Theoretic Security

> For a (t, n)-threshold scheme with a degree t−1 polynomial, any set of **t−1 or fewer** shares provides **zero information** about the secret s.

&nbsp;

### Proof

Given any t−1 shares { (x₁,y₁), …, (x_{t−1}, y_{t−1}) }, we show that for **any** candidate secret s′ ∈ ℤ_p, there exists exactly one polynomial of degree t−1 consistent with those shares and satisfying f(0) = s′.

**Construction:**

1. Choose an arbitrary value s′ for f(0)
2. We now have t conditions: &nbsp; f(0) = s′ &nbsp;and&nbsp; f(xᵢ) = yᵢ &nbsp;for i = 1, …, t−1
3. These t points uniquely determine a polynomial of degree t−1
4. Since s′ was arbitrary, **all p possible secrets are equally likely**

**Probability Analysis:**

$$\Pr[S = s \mid t{-}1 \text{ shares}] = \Pr[S = s] = \frac{1}{p}$$

Since p ≈ 2¹²⁷, the probability of guessing the secret is **negligible**. ∎

&nbsp;

### Commitment Scheme Security

Using **Pedersen commitments** (simplified):

$$C_i = g^{a_i} \bmod p \quad \text{for each coefficient } a_i$$

| Property | Guarantee |
|----------|-----------|
| **Binding** | Cannot open Cᵢ to a different value aᵢ′ ≠ aᵢ — this would require solving the discrete logarithm, which is computationally infeasible |
| **Hiding** | Cᵢ reveals no information about aᵢ (under the DDH hardness assumption) |

&nbsp;

### Combined Security

| Layer | Effect |
|-------|--------|
| High degree (t close to n) | Attacker must compromise nearly **all** shares |
| Verifiable commitments | Forged or tampered shares are **detected** |
| Information-theoretic bound | Even with n−1 shares, attacker gains **no information** |

---

## 5. Complexity Analysis

### Low-Degree Attack

| Metric | Value |
|--------|-------|
| Time complexity | O(t²) for Lagrange interpolation |
| For t = 2 | O(1) — instantaneous reconstruction |
| Success probability | **100%** with t shares |

&nbsp;

### High-Degree Prevention

| Operation | Complexity |
|-----------|------------|
| Setup (generate n shares) | O(nt) |
| Verification (per share) | O(t) using commitments |
| Reconstruction | O(t²) |
| Attacker's success probability | 1/p ≈ **2⁻¹²⁷** (negligible) |

&nbsp;

### Latency Overhead

The additional cost of the secure scheme comes from three sources:

1. Generating more random coefficients (t−1 coefficients vs. a small constant)
2. Computing t polynomial commitments (t modular exponentiations)
3. Running verification steps per share

Despite this overhead, the scheme achieves an **exponential security improvement** — from an O(1) attack to a 2⁻¹²⁷ success probability.

---

## 6. Summary Table

| Parameter | Vulnerable System | Secure System |
|-----------|:-----------------:|:-------------:|
| Polynomial degree d | 1 or 2 *(low)* | n−1 or n−2 *(high)* |
| Threshold t | 2 or 3 | n−1 or n |
| Shares needed to reconstruct | 2 or 3 | n−1 or n |
| Attack complexity | O(1) | O(2¹²⁷) |
| Information leakage | Complete | None *(info-theoretic)* |

---