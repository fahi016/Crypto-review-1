# PROJECT REPORT: Shamir's Secret Sharing - Low Degree Attack & Prevention

## Authors: Mohammed Faheem P (23brs1083), Hanaan Makhdoomi (23brs1389)

---

## 1. TITLE PAGE
**Project Title:** Analysis and Prevention of Low-Degree Polynomial Attacks in Shamir's Secret Sharing Scheme

**Course:** [Course Name]
**Date:** February 2025
**Team Members:** Mohammed Faheem P, Hanaan Makhdoomi

---

## 2. ABSTRACT

This project demonstrates a critical vulnerability in improperly configured Shamir's Secret Sharing (SSS) schemes where low-degree polynomials (t=2 or 3) allow attackers to reconstruct secrets with minimal shares. We implement SSS from scratch in Python, demonstrate the attack through interpolation-based reconstruction, and propose a prevention mechanism using high-degree polynomials (t close to n) combined with verifiable commitments. Through 20-25 automated test cases, we show 90%+ attack success on low-degree configurations versus 0% success after applying our prevention mechanism. The project includes mathematical proofs of vulnerability and security, along with comprehensive performance analysis showing the trade-off between security and computational overhead.

**Keywords:** Shamir's Secret Sharing, Polynomial Interpolation, Lagrange Interpolation, Verifiable Secret Sharing, Information-Theoretic Security

---

## 3. INTRODUCTION & PROBLEM STATEMENT

### 3.1 Background
Secret sharing schemes, introduced independently by Blakley and Shamir in 1979, are fundamental cryptographic primitives for distributing trust. Shamir's scheme uses polynomial interpolation over finite fields to achieve information-theoretic security.

### 3.2 Problem Statement
In practical deployments, administrators may choose low threshold values (t=2 or 3) for convenience, creating vulnerability:
- With degree-1 polynomial (linear), only 2 shares determine the secret
- An attacker compromising any 2 participants can reconstruct the secret
- This defeats the purpose of distribution when n is large but t is small

### 3.3 Research Questions
1. How does polynomial degree affect reconstruction security?
2. Can we quantify the information leakage in low-degree configurations?
3. What prevention mechanisms maintain security without sacrificing functionality?

---

## 4. OBJECTIVES

1. **Implement Shamir's Secret Sharing from scratch** using only basic Python constructs and finite field arithmetic
2. **Demonstrate the low-degree attack** showing secret reconstruction with t shares where degree is insufficient
3. **Design and implement prevention** using high-degree polynomials (t ≈ n) and Pedersen-like commitments
4. **Mathematically prove** vulnerability of low-degree and security of high-degree configurations
5. **Evaluate through 20-25 test cases** showing ≥90% attack success before fix, 0% after
6. **Analyze performance** through 4 mandatory graphs showing security/efficiency trade-offs

---

## 5. LITERATURE SURVEY

### Key References:

| Author(s) | Year | Contribution | Relevance |
|-----------|------|--------------|-----------|
| Shamir, A. | 1979 | Original SSS scheme using polynomial interpolation | Foundation of our implementation |
| Blakley, G.R. | 1979 | Alternative geometric secret sharing | Comparison of approaches |
| Feldman, P. | 1987 | Verifiable Secret Sharing (VSS) | Commitment scheme basis |
| Pedersen, T.P. | 1991 | Non-interactive VSS | Commitment construction |
| Stinson, D.R. | 2006 | Cryptography: Theory and Practice | Mathematical background |
| Shoup, V. | 2008 | A Computational Introduction to Number Theory | Finite field arithmetic |
| Katz, J. & Lindell, Y. | 2014 | Introduction to Modern Cryptography | Security proofs |
| Koblitz, N. | 1994 | A Course in Number Theory and Cryptography | Mathematical foundations |
| Beimel, A. | 2011 | Secret-Sharing Schemes: A Survey | Advanced constructions |
| Schneier, B. | 1996 | Applied Cryptography | Practical considerations |

### Comparison Table:

| Scheme | Threshold | Verification | Computational Cost | Our Implementation |
|--------|-----------|--------------|-------------------|-------------------|
| Basic SSS | t-of-n | No | Low | Vulnerable version |
| Feldman's VSS | t-of-n | Yes (discrete log) | Medium | Prevention base |
| Pedersen's VSS | t-of-n | Yes (unconditional) | High | Reference |
| Our High-Degree | (n-1)-of-n | Hash commitments | Medium | Prevention mechanism |

---

## 6. MATHEMATICAL BACKGROUND & JUSTIFICATION

### 6A. Mathematical Model

**Variables:**
- p: Prime defining field Z_p (p = 2^127 - 1 in our implementation)
- s ∈ Z_p: Secret value
- n: Number of participants (shares)
- t: Threshold (1 < t ≤ n)
- d = t-1: Polynomial degree
- f(x) = Σ_{i=0}^{d} a_i x^i: Sharing polynomial where a_0 = s

**Assumptions:**
1. p is large enough that brute-force search is infeasible (p > 2^100)
2. Random coefficients are uniformly distributed in Z_p*
3. Honest dealer during share distribution
4. Synchronous communication channel

**Equations:**
1. Share generation: share_i = (i, f(i) mod p) for i = 1,...,n
2. Lagrange interpolation: f(0) = Σ_{i∈S} y_i · λ_i where λ_i = Π_{j∈S,j≠i} j/(j-i)
3. Commitment: C_i = H(a_i || r_i) for random nonce r_i

### 6B. Mathematical Analysis

**Why Baseline System is Insecure:**
When t is small (2 or 3), degree d = t-1 is 1 or 2. By the uniqueness of polynomial interpolation:
- A degree-d polynomial is uniquely determined by d+1 points
- With t = d+1 shares, the attacker has exactly enough information to determine f(0) = s
- The system provides no security beyond the threshold

**How Attack Exploits It:**
The attacker:
1. Collects t shares (x_1,y_1),...,(x_t,y_t)
2. Constructs Lagrange basis polynomials L_i(x)
3. Computes s = Σ y_i · L_i(0)
4. Complexity is O(t²) field operations - negligible for small t

**Why High Degree + Commitments Fix It:**
1. **Information-theoretic security**: With t = n-1 or n, attacker needs nearly all shares
2. **Commitment binding**: Prevents dealer from cheating about coefficients
3. **Share verification**: Each share can be verified against public commitments
4. **No information leakage**: t-1 shares reveal nothing about s (probability 1/p for any guess)

### 6C. Proof Requirements

**Proof 1: Low-Degree Vulnerability (Attack)**

*Theorem:* For a (t,n)-threshold scheme with polynomial degree d = t-1, possession of t shares allows complete secret reconstruction in O(t²) time.

*Proof:*
Given t distinct points (x_1,y_1),...,(x_t,y_t) on polynomial f of degree d = t-1.

By Lagrange interpolation formula:
f(x) = Σ_{i=1}^{t} y_i · L_i(x)

Where the Lagrange basis polynomial L_i(x) is:
L_i(x) = Π_{j≠i} (x - x_j)/(x_i - x_j)

Evaluating at x = 0:
s = f(0) = Σ_{i=1}^{t} y_i · L_i(0) = Σ_{i=1}^{t} y_i · Π_{j≠i} (-x_j)/(x_i - x_j)

Since all x_i are known (typically x_i = i), the denominators are known constants.
The attacker computes each L_i(0) in O(t) time, total O(t²).

For t = 2 (linear): s = y_1 - x_1(y_2-y_1)/(x_2-x_1) = y_1·x_2/(x_2-x_1) - y_2·x_1/(x_2-x_1)

This is a deterministic computation requiring only 2 shares, proving the system is vulnerable when t is small.

**Proof 2: High-Degree Security (Prevention)**

*Theorem:* For a (t,n)-threshold scheme with t = n (degree n-1), any set of t-1 = n-1 shares provides zero information (statistically) about secret s.

*Proof:*
Consider any n-1 shares S' = {(x_1,y_1),...,(x_{n-1},y_{n-1})}.

We show that for any candidate secret s' ∈ Z_p, there exists exactly one degree-(n-1) polynomial f' consistent with S' and f'(0) = s'.

Construction: The n points (0,s'), (x_1,y_1),...,(x_{n-1},y_{n-1}) are distinct (since x_i ≠ 0).
By the uniqueness of polynomial interpolation, these n points define a unique degree-(n-1) polynomial.

Since this holds for all p possible values of s', and each is equally likely:
Pr[S = s | S'] = 1/p for all s ∈ Z_p

The conditional entropy H(S|S') = log₂(p) = H(S), meaning zero information leakage.

Combined with commitments that bind the dealer to specific coefficients (preventing manipulation), the scheme achieves:
1. Correctness: t shares always reconstruct s
2. Security: t-1 shares reveal nothing about s
3. Verifiability: Participants can verify share validity

---

## 7. SYSTEM & ATTACK MODEL

### 7.1 System Architecture

[Diagram Description]
```
┌─────────────────────────────────────────────────────────────┐
│                    DEALER (Trusted)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Secret s   │→ │  Polynomial  │→ │    Shares    │      │
│  │              │  │  f(x) mod p  │  │  (i,f(i))    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                              ↓
        ┌─────────┬─────────┬─────────┬─────────┐
        ↓         ↓         ↓         ↓         ↓
      P₁        P₂        P₃        ...       Pₙ
    (1,y₁)    (2,y₂)    (3,y₃)            (n,yₙ)
        ↑         ↑         ↑         ↑         ↑
        └─────────┴─────────┴─────────┴─────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│              RECONSTRUCTION (Any t participants)            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   t Shares   │→ │   Lagrange   │→ │   Secret s   │      │
│  │              │  │Interpolation │  │   f(0)       │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 Attack Model

**Attacker Capabilities:**
- Passive adversary: Can observe up to t-1 shares (for low-degree attack)
- Active adversary: Can attempt to submit forged shares (prevented by commitments)
- Computational power: Polynomial-time bounded, cannot break cryptographic hashes

**Attack Scenario (Low-Degree):**
1. System configured with t=2, n=5, degree-1 polynomial
2. Attacker compromises 2 participants (40% of total)
3. With 2 shares, attacker interpolates line and finds y-intercept
4. Secret recovered with 100% success rate

**Attack Prevention (High-Degree):**
1. System configured with t=4, n=5, degree-3 polynomial
2. Attacker compromises 3 participants (60% of total)
3. With only 3 shares, infinite polynomials of degree 3 pass through them
4. Each possible secret value equally likely - zero information

---

## 8. IMPLEMENTATION

### 8.1 Vulnerable System (Low-Degree)

```python
# Core vulnerable implementation
class ShamirSecretSharing:
    def generate_polynomial(self, secret, threshold):
        # threshold t = 2 means degree 1 (LINEAR - VULNERABLE)
        coeffs = [secret]
        for _ in range(threshold - 1):
            coeffs.append(random.randint(1, p-1))
        return coeffs

    def evaluate(self, x):
        # Horner's method evaluation
        result = 0
        for coeff in reversed(coeffs):
            result = (result * x + coeff) % p
        return result
```

**Vulnerability:** With t=2, polynomial is f(x) = s + a₁x. Two points determine line uniquely.

### 8.2 Attack Implementation

```python
class AttackSimulator:
    def brute_force_low_degree(self, shares, guessed_degree, secret):
        # Attacker knows degree is low (1 or 2)
        # Uses Lagrange interpolation with available shares
        reconstructed = lagrange_interpolate(shares[:guessed_degree+1])
        return reconstructed == secret
```

**Attack Success:** 100% with t shares for degree t-1 polynomial.

### 8.3 Prevention Mechanism

```python
class PreventionMechanism:
    def apply_high_degree(self, secret, n, t_high):
        # t_high = n-1 or n (HIGH DEGREE - SECURE)
        coeffs = generate_polynomial(secret, t_high)
        shares = generate_shares(n)
        commitments = [hash(coeff) for coeff in coeffs]
        return {
            'shares': shares,
            'commitments': commitments,
            'threshold': t_high
        }

    def verify_share(self, share, commitments):
        # Verify share against commitment
        # Prevents submission of invalid shares
        return check_commitment(share, commitments)
```

**Security:** Information-theoretic - t-1 shares reveal nothing.

### 8.4 Pseudo-Algorithms

**Algorithm 1: Low-Degree Attack**
```
Input: List of shares S = [(x₁,y₁),...,(x_k,y_k)] where k ≥ t
Output: Secret s or FAILURE

1. IF length(S) < t:
2.     RETURN FAILURE  // Insufficient shares
3. Select first t shares from S
4. FOR i = 1 to t:
5.     Compute Lagrange basis L_i(0) = Π_{j≠i} (-x_j)/(x_i - x_j)
6.     // O(t²) field operations
7. s ← Σ_{i=1}^{t} y_i · L_i(0) mod p
8. RETURN s
```

**Algorithm 2: High-Degree Prevention with Verification**
```
Input: Secret s, number of participants n, high threshold t ≈ n
Output: Shares and commitments

1. // Setup Phase
2. coeffs[0] ← s
3. FOR i = 1 to t-1:
4.     coeffs[i] ← random(1, p-1)
5.     commitments[i] ← HASH(coeffs[i] || nonce_i)
6.
7. // Share Generation
8. FOR x = 1 to n:
9.     y ← EVALUATE_POLYNOMIAL(coeffs, x)  // Horner's method
10.    shares[x] ← (x, y)
11.
12. // Verification
13. FOR each share (x, y):
14.    IF NOT VERIFY(y, commitments):
15.        RETURN ERROR
16.
17. RETURN (shares, commitments)
```

---

## 9. RESULTS & GRAPHS

### 9.1 Test Configuration
- **Test Cases:** 20 automated runs
- **Parameters Varied:** n (5-10), t_low (2-3), t_high (n-1), secret (random)
- **Metrics:** Attack success rate, reconstruction time, confidentiality rate, latency

### 9.2 Statistics Summary

| Metric | Before Prevention | After Prevention | Improvement |
|--------|------------------|------------------|-------------|
| Attack Success Rate | 95% | 0% | 100% block |
| Avg. Reconstruction Time | 0.002s | 0.015s | 7.5x (acceptable) |
| Confidentiality Rate | 5% | 100% | Complete |
| Latency Overhead | Baseline | +12ms | Minimal |

### 9.3 Graph Explanations

**Graph 1: Attack Success Rate Comparison**
- Shows 95% success on low-degree (t=2,3) vs 0% on high-degree (t=n-1)
- Demonstrates effectiveness of prevention mechanism
- Red bar (vulnerable) vs Green bar (secure)
![alt text](image-3.png)


**Graph 2: Time vs Polynomial Degree**
- X-axis: Degree (1 to n-1)
- Y-axis: Computation time
- Shows linear growth in setup time vs exponential security gain
- Highlights vulnerable region (degrees 1-2) in red
![alt text](image-2.png)

**Graph 3: Confidentiality Rate**
- Before: 5% (secret exposed in 95% of attacks)
- After: 100% (perfect confidentiality)
- Demonstrates information-theoretic security of high-degree scheme
![alt text](image-1.png)

**Graph 4: Latency Overhead**
- Compares setup times: Low-degree vs High-degree vs Security overhead
- Shows security comes with modest computational cost
- Overhead is acceptable for security gain
![alt text](image-4.png)

---

## 10. LIMITATIONS & CONCLUSION

### 10.1 Limitations
1. **Dealer Trust:** Assumes honest dealer during setup (addressed by VSS)
2. **Prime Size:** Used 2^127-1; larger primes increase security but slow computation
3. **Synchronous Model:** Assumes all participants available simultaneously
4. **Storage:** Commitments require additional storage space

### 10.2 Conclusion

We successfully demonstrated that low-degree polynomials in Shamir's Secret Sharing (t=2 or 3) are vulnerable to reconstruction attacks requiring only t shares. Through mathematical proofs based on polynomial interpolation uniqueness, we showed that:

1. **Vulnerability:** Degree d polynomial requires only d+1 points for unique determination
2. **Prevention:** High-degree polynomials (t ≈ n) provide information-theoretic security
3. **Verification:** Commitments prevent dealer cheating and share forgery

Our implementation from scratch (without cryptographic libraries) achieved:
- 95% attack success rate on vulnerable configurations
- 0% attack success after applying high-degree + commitments
- 4 comprehensive graphs showing security/performance trade-offs

The project validates the critical importance of proper parameter selection in cryptographic protocols and demonstrates that convenience (low threshold) must be balanced against security requirements.

---

## 11. REFERENCES

[1] Shamir, A. (1979). "How to share a secret." Communications of the ACM, 22(11), 612-613.
[2] Blakley, G. R. (1979). "Safeguarding cryptographic keys." In Proceedings of AFIPS, 313-317.
[3] Feldman, P. (1987). "A practical scheme for non-interactive verifiable secret sharing." FOCS, 427-438.
[4] Pedersen, T. P. (1991). "Non-interactive and information-theoretic secure verifiable secret sharing." CRYPTO, 129-140.
[5] Stinson, D. R. (2006). "Cryptography: Theory and Practice." 3rd Ed., CRC Press.
[6] Shoup, V. (2008). "A Computational Introduction to Number Theory and Algebra." Cambridge.
[7] Katz, J., & Lindell, Y. (2014). "Introduction to Modern Cryptography." 2nd Ed., CRC Press.
[8] Koblitz, N. (1994). "A Course in Number Theory and Cryptography." Springer.
[9] Beimel, A. (2011). "Secret-Sharing Schemes: A Survey." Coding and Cryptology, 11-46.
[10] Schneier, B. (1996). "Applied Cryptography." 2nd Ed., Wiley.

---

## APPENDIX: Code Listings

[Full source code available in implementation files]
