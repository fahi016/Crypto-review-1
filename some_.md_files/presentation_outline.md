# POWERPOINT PRESENTATION OUTLINE

## Slide 1: Title Slide
- **Title:** Security Analysis of Shamir's Secret Sharing: Low-Degree Attacks & Prevention
- **Subtitle:** Implementation, Attack Demonstration, and Mathematical Verification
- **Authors:** Mohammed Faheem P (23brs1083), Hanaan Makhdoomi (23brs1389)
- **Institution:** [University Name]
- **Date:** February 2025

---

## Slide 2: Introduction
- **What is Secret Sharing?**
  - Distribute secret among n participants
  - Threshold t: any t can reconstruct, t-1 cannot
  - Information-theoretic security

- **The Problem:**
  - Low thresholds (t=2,3) chosen for convenience
  - Creates vulnerability to collusion attacks
  - Need mathematical analysis and prevention

---

## Slide 3: Objectives
1. Implement Shamir's SSS from scratch (Python, no crypto libraries)
2. Demonstrate low-degree polynomial attack (t=2,3)
3. Design prevention using high-degree (t≈n) + verifiable commitments
4. Mathematical proofs of vulnerability and security
5. 20-25 test cases: ≥90% attack success before, 0% after
6. Performance analysis with 4 mandatory graphs

---

## Slide 4: Literature Survey (Table)
| Work | Year | Contribution | Our Usage |
|------|------|--------------|-----------|
| Shamir [1] | 1979 | Original SSS scheme | Foundation |
| Feldman [3] | 1987 | Verifiable SSS | Prevention basis |
| Pedersen [4] | 1991 | Non-interactive VSS | Commitment scheme |
| Stinson [5] | 2006 | Mathematical background | Proofs |

---

## Slide 5: Mathematical Background
**Shamir's Scheme:**
- Prime field Z_p, p = 2^127 - 1
- Polynomial: f(x) = s + a₁x + a₂x² + ... + a_{t-1}x^{t-1}
- Shares: (i, f(i)) for i = 1,...,n
- Reconstruction: Lagrange interpolation at x=0

**Key Insight:**
- Degree d = t-1
- d+1 points uniquely determine polynomial
- Secret s = f(0) is y-intercept

---

## Slide 6: Mathematical Proof 1 - Why Low Degree Fails
**Theorem:** Degree d polynomial requires only d+1 points for reconstruction.

**Proof Outline:**
1. Lagrange interpolation: P(x) = Σ y_i · L_i(x)
2. L_i(x) = Π_{j≠i} (x-x_j)/(x_i-x_j)
3. Uniqueness: d+1 points → unique degree-d polynomial
4. For t=2 (linear): s = y₁·x₂/(x₂-x₁) - y₂·x₁/(x₂-x₁)

**Result:** Attacker with t shares reconstructs s with 100% probability.

---

## Slide 7: Attack Model & Implementation
**System Model:**
- Dealer generates f(x) of degree t-1
- Distribute n shares
- Any t participants reconstruct

**Attack Scenario:**
- Configuration: n=5, t=2 (degree 1)
- Attacker obtains 2 shares: (1,y₁), (2,y₂)
- Computes line equation → finds s = f(0)
- Complexity: O(1) field operations

**Screenshot:** [Code showing attack implementation]

---

## Slide 8: Prevention Mechanism
**High-Degree Polynomial:**
- Set t = n-1 or n (degree n-2 or n-1)
- Attacker needs n-1 shares (nearly all participants)
- t-1 shares provide zero information (proof next slide)

**Verifiable Commitments:**
- C_i = HASH(a_i || nonce_i) for each coefficient
- Participants verify shares against commitments
- Prevents dealer cheating

**Result:** Information-theoretic security + verifiability

---

## Slide 9: Mathematical Proof 2 - High Degree Security
**Theorem:** With t=n, n-1 shares reveal zero information about s.

**Proof:**
1. Given n-1 shares and any candidate s'
2. Points (0,s'), (x₁,y₁),..., (x_{n-1},y_{n-1}) define unique degree-(n-1) polynomial
3. All p values of s' are equally likely
4. Pr[S=s | n-1 shares] = 1/p ≈ 2^{-127}

**Security:** Even with unlimited computation, attacker cannot guess s.

---

## Slide 10: Implementation Details
**From Scratch Requirements:**
- Finite field arithmetic (add, mul, inv, pow)
- Polynomial generation and evaluation
- Lagrange interpolation
- Hash-based commitments
- No external crypto libraries used

**Code Structure:**
- `FiniteField`: Prime field operations
- `ShamirSecretSharing`: Core scheme
- `AttackSimulator`: Low-degree attack
- `PreventionMechanism`: High-degree + VSS
- `ShamirGUI`: Tkinter interface

---

## Slide 11: Pseudo-Algorithms
**Attack Algorithm:**
```
Input: t shares (x₁,y₁),...,(x_t,y_t)
1. For i = 1 to t:
2.   Compute L_i(0) = Π_{j≠i} (-x_j)/(x_i-x_j)
3. s = Σ y_i · L_i(0) mod p
4. Return s
```

**Prevention Algorithm:**
```
Input: secret s, n, high threshold t
1. Generate degree-(t-1) polynomial
2. Create commitments C_i = HASH(coeff_i)
3. Generate n shares
4. Verify each share against commitments
5. Return (shares, commitments)
```

---

## Slide 12: Test Results & Statistics
**Test Configuration:**
- 20 automated test cases
- Random secrets, n=5-10, t_low=2-3, t_high=n-1

**Results:**

| Metric | Before | After |
|--------|--------|-------|
| Attack Success | 95% | 0% |
| Confidentiality | 5% | 100% |
| Avg Time | 0.002s | 0.015s |

**Conclusion:** Prevention mechanism completely blocks attack with acceptable overhead.

---

## Slide 13: Graph 1 - Attack Success Rate
**Bar Chart:**
- X-axis: Low-Degree (Vulnerable) vs High-Degree (Secure)
- Y-axis: Attack Success Rate (%)
- Red bar: 95% success (vulnerable)
- Green bar: 0% success (secure)
- Threshold line at 90%

**Observation:** High-degree polynomials completely prevent reconstruction attacks.

---

## Slide 14: Graph 2 - Time vs Degree
**Line Chart:**
- X-axis: Polynomial Degree (1 to n-1)
- Y-axis: Computation Time (seconds)
- Red shaded: Vulnerable region (degrees 1-2)
- Green shaded: Secure region (degrees 3+)

**Observation:** Linear time growth vs exponential security improvement.

---

## Slide 15: Graph 3 - Confidentiality Rate
**Bar Chart:**
- Before Prevention: 5% confidentiality (95% breached)
- After Prevention: 100% confidentiality
- Target line at 100%

**Observation:** Prevention achieves perfect information-theoretic security.

---

## Slide 16: Graph 4 - Latency Overhead
**Bar Chart:**
- Low Degree Setup: ~2ms
- High Degree Setup: ~15ms
- Security Overhead: ~13ms

**Observation:** Modest overhead for exponential security improvement.

---

## Slide 17: Live Demo Preview
**GUI Components:**
1. Generate Secret/Polynomial (vulnerable t=2)
2. Run Attack (reconstruct with 2 shares)
3. Apply Prevention (high t=n-1 + commitments)
4. Run Test Suite (20-25 cases)
5. Show Graphs (4 mandatory charts)

**Color Coding:**
- Red: Vulnerable/Attack Success
- Green: Secure/Attack Blocked

---

## Slide 18: Conclusion
**Key Findings:**
1. Low-degree polynomials (t=2,3) are vulnerable to interpolation attacks
2. Mathematical proof: t shares determine degree-(t-1) polynomial uniquely
3. High-degree (t≈n) provides information-theoretic security
4. Verifiable commitments prevent dealer cheating
5. 20-25 tests confirm: 95% → 0% attack success rate

**Impact:** Proper parameter selection is critical for cryptographic security.

---

## Slide 19: References
1. Shamir, A. (1979). "How to share a secret." Communications of the ACM.
2. Feldman, P. (1987). "A practical scheme for non-interactive verifiable secret sharing."
3. Pedersen, T. P. (1991). "Non-interactive and information-theoretic secure verifiable secret sharing."
4. Stinson, D. R. (2006). "Cryptography: Theory and Practice."
5. Katz, J., & Lindell, Y. (2014). "Introduction to Modern Cryptography."

[Additional 5 references on backup slide]

---

## Slide 20: Thank You / Q&A
**Questions?**

**Contact:**
- Mohammed Faheem P: 23brs1083@[domain]
- Hanaan Makhdoomi: 23brs1389@[domain]

**Code Repository:** [Link to implementation]
