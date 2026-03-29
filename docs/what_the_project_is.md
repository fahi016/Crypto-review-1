# What This Project Is

## 1. Overall Idea

This project is a complete study of **Shamir's Secret Sharing (SSS)** with three main goals:

1. Implement the scheme from scratch.
2. Show how weak configurations can be attacked.
3. Show how better configuration and integrity protection can prevent those attacks.

In simple words, we built a system that can:
- split a secret into multiple shares,
- reconstruct the secret when enough valid shares are provided,
- demonstrate attacks on weak or non-verified setups,
- apply protections,
- compare multiple solution profiles using automated tests, graphs, and a Tkinter GUI.

## 2. What We Achieved Through This Project

Through this project, we achieved the following:

- Implemented finite field arithmetic and Shamir's Secret Sharing fully from scratch in Python.
- Demonstrated that **low threshold choice** makes the system vulnerable to collusion-based secret reconstruction.
- Demonstrated that **lack of share verification** makes the system vulnerable to forged-share tampering.
- Implemented a prevention strategy using:
  - a **high threshold** to improve confidentiality, and
  - **share-integrity commitments** to detect tampered shares.
- Built a Tkinter GUI that can:
  - generate parameters,
  - run attacks,
  - apply prevention,
  - run full test cases,
  - display graphs.
- Ran automated comparison tests across multiple solution profiles.
- Generated graphs showing attack success, security improvement, and performance trade-offs.

In one current 25-test run of the project:
- Collusion attack success before prevention: `100%`
- Collusion attack success after prevention: `0%`
- Tampering attack success before prevention: `100%`
- Tampering attack success after prevention: `0%`
- Confidentiality after prevention: `100%`
- Integrity after prevention: `100%`
- Authentication/detection after prevention: `100%`
- Honest reconstruction rate across all tested profiles: `100%`

The exact percentages are stable, while timing values can vary slightly from machine to machine.

## 3. What Is Shamir's Secret Sharing?

Shamir's Secret Sharing is a method to divide one secret into multiple pieces called **shares**.

- There are `n` total shares.
- Any `t` shares can reconstruct the secret.
- Fewer than `t` shares should reveal nothing useful about the secret.

When the secret is a cryptographic key, people often informally call it **secret key sharing**. In this project, the secret can be treated as the key material being protected.

### Core Mathematical Idea

The secret is placed as the constant term of a polynomial over a finite field:

`f(x) = s + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1) mod p`

Where:
- `s` is the secret,
- `p` is a large prime,
- `t` is the threshold,
- degree of the polynomial is `t - 1`.

Then shares are generated as:

- `(1, f(1))`
- `(2, f(2))`
- ...
- `(n, f(n))`

To recover the secret, the receiver uses **Lagrange interpolation** on enough shares and evaluates the polynomial at `x = 0`, because:

- `f(0) = s`

## 4. What We Implemented

The project contains these major parts:

- `src/finite_field.py`
  - modular arithmetic in a prime field
- `src/shamir.py`
  - polynomial generation, share generation, interpolation, reconstruction
- `src/attack.py`
  - collusion attack
  - tampering / forged-share attack
- `src/prevention.py`
  - high-threshold secure configuration
  - share-integrity commitments and verification
- `src/test_runner.py`
  - automated comparison test suite
- `src/graphs.py`
  - graph generation
- `src/gui.py`
  - full GUI workflow

The project uses the prime:

- `p = 2^127 - 1`

and the automated suite varies:

- random secret values,
- `n` from `5` to `10`,
- low threshold `t` in `{2, 3}`,
- secure threshold `high_t = max(n - 1, low_t + 2)`

## 5. The Attacks We Performed

We implemented **two different attack types** because the project studies two different security problems:

1. **Confidentiality attack**
2. **Integrity attack**

### 5.1 Collusion / Interpolation Attack

This is the main confidentiality attack in the project.

#### What problem it targets

It targets systems where the threshold is too small, such as `t = 2` or `t = 3`.

#### How it works

If the attacker compromises enough participants to collect the threshold number of shares:

- the shares become points on the secret polynomial,
- those points uniquely determine the polynomial,
- the attacker interpolates the polynomial,
- then computes `f(0)` to recover the secret.

#### Why it works

A degree-`d` polynomial is uniquely determined by `d + 1` points.

Since `d = t - 1`, any `t` correct shares are enough to reconstruct the secret.

So if `t` is very small:
- the system is easy to reconstruct,
- the secret is easy to leak through collusion.

#### What this attack means

This is not saying Shamir's scheme is broken in general.

It shows that:
- **bad parameter choice** creates weak confidentiality,
- especially when administrators prioritize convenience and choose low thresholds.

### 5.2 Forged-Share / Tampering Attack

This is the main integrity attack in the project.

#### What problem it targets

It targets systems where shares are accepted without verification.

#### How it works

The attacker:
- takes one of the shares used for reconstruction,
- changes its `y` value,
- submits the forged share with the same `x`,
- causes the interpolation step to use incorrect data.

Possible results:
- wrong secret reconstruction,
- integrity failure,
- lack of trust in the recovered secret.

#### Why it works

Standard basic secret sharing ensures reconstruction correctness only if the shares are honest.

If the system has no integrity check:
- the receiver cannot know whether a share was modified,
- a forged share can distort the interpolation result.

## 6. How We Prevented the Attacks

We did not use only one prevention. We used **two protections for two different problems**.

### 6.1 High Threshold Protection

This protects against the collusion/interpolation attack.

#### Idea

Instead of using a small threshold like `2` or `3`, we use a threshold close to `n`, for example:

- `t = n - 1`

#### Effect

Now the attacker must compromise nearly all participants before interpolation becomes possible.

This dramatically improves confidentiality because the same attacker budget that worked before no longer works.

#### Example

If the vulnerable system uses:
- `n = 5`, `t = 2`

then 2 compromised shares are enough.

If the protected system uses:
- `n = 5`, `t = 4`

then the same 2-share attacker can no longer reconstruct the secret.

### 6.2 Share-Integrity Commitments

This protects against tampering.

#### Idea

The system publishes a digest for each generated share.

When reconstruction is attempted:
- each incoming share is checked against its expected digest,
- if a share was modified, the digest will not match,
- the forged share is rejected.

#### Effect

This adds:
- integrity protection,
- tamper detection,
- a simple authentication layer for shares.

### 6.3 Combined Protection

When we combine:
- **high threshold** and
- **share-integrity commitments**

we protect both:
- confidentiality against collusion,
- integrity/authentication against tampering.

## 7. The Multiple Solutions We Compared

The project compares **four solution profiles**, all solving the same secret-sharing problem in different ways.

| Profile | Threshold Style | Integrity Check | What It Solves | Main Weakness |
|---|---|---|---|---|
| Low Threshold / No Integrity | Low | No | Fast and simple | Fails against collusion and tampering |
| Low Threshold / Share Integrity | Low | Yes | Detects tampering | Still leaks secret under collusion |
| High Threshold / No Integrity | High | No | Protects confidentiality | Still vulnerable to forged shares |
| High Threshold / Share Integrity | High | Yes | Protects confidentiality and integrity | Slightly higher overhead |

This is the core comparison framework of the project.

## 8. Our Attacks vs Existing Approaches

### 8.1 Our Collusion Attack vs Brute-Force Guessing

Both try to obtain the secret, but they are very different.

| Method | Uses Share Structure? | Complexity | Practicality |
|---|---|---|---|
| Brute-force secret guessing | No | Extremely high over a large prime field | Not practical |
| Our collusion/interpolation attack | Yes | Polynomial-time interpolation | Very practical if threshold is low |

Interpretation:
- brute force ignores the mathematics of the scheme,
- our attack exploits the scheme structure directly,
- therefore our attack is much stronger when the threshold is chosen badly.

### 8.2 Our Collusion Attack vs Standard Literature Collusion Attack

Our collusion attack is not claiming novelty.

It is a direct implementation of the **standard interpolation/collusion weakness** discussed in secret-sharing literature:
- if an attacker has enough valid shares,
- the polynomial can be reconstructed.

What our project contributes is:
- a working demo,
- automated measurement,
- a GUI,
- before/after prevention evaluation.

### 8.3 Our Tampering Attack vs Generic Dishonest-Participant Attack

In verifiable secret sharing literature, dishonest participants or dishonest dealers may submit invalid shares.

Our tampering attack is a simple practical version of that idea:
- modify one share,
- attempt reconstruction,
- observe wrong output if no verification exists.

Compared with more advanced adversarial models:
- ours is simpler,
- easier to demonstrate live,
- still effective for showing why integrity verification is necessary.

## 9. Our Prevention vs Existing Methods

### 9.1 Compared with Basic Shamir's Secret Sharing

Basic SSS gives:
- secret splitting,
- threshold reconstruction,
- no share authentication by default.

Our prevention is stronger because it adds:
- higher resistance to collusion,
- share tampering detection.

### 9.2 Compared with High-Threshold SSS Alone

High-threshold SSS alone improves confidentiality, but not integrity.

That means:
- collusion becomes difficult,
- forged shares can still damage reconstruction.

Our combined method is stronger because it handles both problems.

### 9.3 Compared with Feldman VSS

Feldman Verifiable Secret Sharing uses **public coefficient commitments** so participants can verify consistency of shares with the underlying polynomial.

Compared with Feldman:
- our method is simpler to implement,
- easier to explain in a classroom/demo setting,
- effective for this project's attack model,
- but less mathematically rich than full coefficient-based public verification.

So:
- Feldman is stronger and more formal,
- our method is more practical and lightweight for this project.

### 9.4 Compared with Pedersen VSS

Pedersen VSS provides stronger commitment properties, especially hiding and binding, and is a more complete cryptographic solution.

Compared with Pedersen:
- our implementation is lighter,
- easier to build from scratch,
- easier to demonstrate visually,
- but not as strong or as general as a full Pedersen-style system.

So our prevention should be understood as:
- a strong project-level defense,
- not a replacement for full production-grade VSS.

## 10. Performance Comparison

The project compares performance mainly through setup, verification, and attack latency.

### Current Measured Averages from a 25-Test Run

Values below are approximate averages from one run.

| Profile | Setup + Verification Overhead | Avg Collusion Attack Time | Avg Tampering Attack Time |
|---|---:|---:|---:|
| Low Threshold / No Integrity | `0.063 ms` | `0.285 ms` | `0.332 ms` |
| Low Threshold / Share Integrity | `0.164 ms` | `0.324 ms` | `0.034 ms` |
| High Threshold / No Integrity | `0.117 ms` | `0.288 ms` | `1.961 ms` |
| High Threshold / Share Integrity | `0.275 ms` | `0.606 ms` | `0.093 ms` |

### Interpretation

- The secure profile has the highest overhead, as expected.
- Even then, the extra protection cost is still small in absolute terms.
- The combined secure profile adds only about `0.212 ms` average extra protection overhead over the weakest baseline in this run.
- So the security improvement is large while the time cost remains modest.

## 11. Security Strength Comparison

### Security Results Across Profiles

| Profile | Collusion Attack Success | Tampering Attack Success | Tampering Detection | Confidentiality Rate | Integrity Rate | Authentication Rate |
|---|---:|---:|---:|---:|---:|---:|
| Low Threshold / No Integrity | `100%` | `100%` | `0%` | `0%` | `0%` | `0%` |
| Low Threshold / Share Integrity | `100%` | `0%` | `100%` | `0%` | `100%` | `100%` |
| High Threshold / No Integrity | `0%` | `100%` | `0%` | `100%` | `0%` | `0%` |
| High Threshold / Share Integrity | `0%` | `0%` | `100%` | `100%` | `100%` | `100%` |

### Interpretation

- Low threshold alone is weak for confidentiality.
- Integrity checking alone does not solve confidentiality.
- High threshold alone does not solve tampering.
- The combined method is the only profile that addresses both attack families at the same time.

## 12. Efficiency Comparison

Efficiency here means how well each solution balances:
- security gained,
- computational cost,
- simplicity of implementation,
- ease of live demonstration.

| Method | Security Benefit | Overhead | Implementation Effort | Overall Efficiency for This Project |
|---|---|---|---|---|
| Low Threshold / No Integrity | Very low | Very low | Very easy | Poor security, only useful as vulnerable baseline |
| Low Threshold / Share Integrity | Good integrity only | Low | Easy | Efficient if integrity is the only concern |
| High Threshold / No Integrity | Good confidentiality only | Low to medium | Easy | Efficient if collusion is the only concern |
| High Threshold / Share Integrity | Strong on both axes | Medium | Moderate | Best overall trade-off in this project |
| Feldman/Pedersen VSS | Stronger formal verification | Medium to high | High | Best cryptographic rigor, but heavier for this project |

## 13. The Graphs Explained

The project generates **4 mandatory graphs** and **1 additional comparison graph**.

### Graph 1: Before vs After Attack Success Rate

File:
- `output/graph_success_rate.png`

#### Parameters

- X-axis:
  - Before prevention
  - After prevention
- Y-axis:
  - Collusion attack success rate (%)

#### Result

- Before prevention: `100%`
- After prevention: `0%`

#### Meaning

This graph shows that the same attack capability that fully breaks the low-threshold system fails completely after prevention.

### Graph 2: Time vs Degree Across Solution Profiles

File:
- `output/graph_time_vs_degree.png`

#### Parameters

- X-axis:
  - polynomial degree = `threshold - 1`
- Y-axis:
  - average end-to-end time in seconds
- Separate lines:
  - each solution profile

#### Result

- low-degree systems are faster,
- higher-degree systems take more time,
- integrity-enabled profiles add more overhead than no-integrity profiles.

#### Meaning

This graph captures the core trade-off:
- stronger security usually costs more time,
- but the increase is still manageable in this project.

### Graph 3: Confidentiality / Integrity / Authentication Rate

File:
- `output/graph_confidentiality.png`

#### Parameters

- X-axis:
  - Confidentiality
  - Integrity
  - Authentication
- Y-axis:
  - security rate (%)
- Two bars per category:
  - before prevention
  - after prevention

#### Result

- Before prevention:
  - confidentiality `0%`
  - integrity `0%`
  - authentication `0%`
- After prevention:
  - confidentiality `100%`
  - integrity `100%`
  - authentication `100%`

#### Meaning

This graph summarizes the total security improvement:
- confidentiality improved because the threshold was raised,
- integrity and authentication improved because forged shares are detected.

### Graph 4: Attack vs Prevention Latency Overhead

File:
- `output/graph_latency.png`

#### Parameters

- X-axis:
  - the four compared solution profiles
- Y-axis:
  - time in milliseconds
- Two bars per profile:
  - attack latency
  - protection overhead

#### Result

- secure profiles cost more than the weakest baseline,
- but the overhead remains low in absolute time.

#### Meaning

This graph supports the argument that:
- better protection is not free,
- but the extra cost is acceptable for the security gained.

### Graph 5: Attack Success Comparison Across Different Solutions

File:
- `output/graph_attack_comparison.png`

#### Parameters

- X-axis:
  - the four solution profiles
- Y-axis:
  - attack success rate (%)
- Two bars per profile:
  - collusion attack success
  - tampering attack success

#### Result

- Low / No Integrity: `100%` collusion, `100%` tampering
- Low / Share Integrity: `100%` collusion, `0%` tampering
- High / No Integrity: `0%` collusion, `100%` tampering
- High / Share Integrity: `0%` collusion, `0%` tampering

#### Meaning

This is the clearest comparison graph in the project because it shows exactly which defense solves which attack.

## 14. Final Understanding of the Project

This project shows one important security lesson:

**A cryptographic scheme is not secure only because the algorithm is correct. It is secure only when the parameters and validation mechanisms are chosen correctly.**

In this project:
- the low-threshold system fails on confidentiality,
- the non-verified system fails on integrity,
- a higher threshold improves confidentiality,
- integrity commitments improve tamper resistance,
- combining both gives the strongest overall result in our implementation.

## 15. Honest Final Position

This project should be presented honestly as:

- a full implementation and analysis of Shamir's Secret Sharing,
- a demonstration of two practical attack families,
- a comparison of multiple solution profiles,
- a defense model that is strong and effective for this project,
- a bridge between basic SSS and more advanced verifiable secret-sharing methods.

It should **not** be presented as:
- a claim that Shamir's Secret Sharing is fundamentally broken,
- or a claim that our prevention is stronger than full Feldman/Pedersen VSS.

The correct conclusion is:
- Shamir's Secret Sharing is mathematically elegant and secure when configured well,
- but weak parameter choices and missing verification open the door to real attacks,
- and our project demonstrates that clearly with implementation, experiments, graphs, and a live GUI.
