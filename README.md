# Shamir Secret Sharing Attack and Prevention Lab

This repository contains a from-scratch implementation of **Shamir's Secret Sharing (SSS)** along with:

- a **collusion / interpolation attack** on weak low-threshold configurations
- a **forged-share / tampering attack** on non-verified reconstruction
- prevention using:
  - **high threshold** for confidentiality, and
  - **share-integrity commitments** for tamper detection
- a Tkinter GUI for live demonstration
- an automated comparison suite across multiple solution profiles
- graph generation for security and performance analysis

## What the Project Demonstrates

The project compares these four solution profiles:

| Profile | Threshold | Integrity Check | Main Outcome |
|---|---|---|---|
| Low Threshold / No Integrity | Low | No | Vulnerable to collusion and tampering |
| Low Threshold / Share Integrity | Low | Yes | Tampering blocked, collusion still succeeds |
| High Threshold / No Integrity | High | No | Collusion blocked, tampering still succeeds |
| High Threshold / Share Integrity | High | Yes | Both attacks blocked/detected |

## Folder Structure

```
review1/
  code.py
  requirements.txt
  README.md
  output/
    graph_success_rate.png
    graph_time_vs_degree.png
    graph_confidentiality.png
    graph_latency.png
    graph_attack_comparison.png
  src/
    __init__.py
    main.py
    finite_field.py
    shamir.py
    attack.py
    prevention.py
    test_runner.py
    graphs.py
    gui.py
  docs/
    mathematical_background_and_proofs.md
    deliverables_audit.md
    what_the_project_is.md
    shamir_report_ieee.docx
    Shamir_Secret_Sharing_Presentation.pptx
  some_.md_files/
    project_report.md
    presentation_outline.md
  tests/
    quick_test.py
```

## Setup

1. Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

## Run

### 1. Quick Sanity Check

```powershell
python tests\quick_test.py
```

This verifies:
- finite field arithmetic
- collusion attack success on a vulnerable profile
- tampering attack success without integrity protection
- collusion attack failure on a secure profile
- tampering detection with integrity protection

### 2. Launch the GUI

```powershell
python -m src.main
```

Backward-compatible launcher:

```powershell
python code.py
```

### 3. Optional Headless Comparison Run

This generates the graphs and prints the aggregated statistics without opening the GUI:

```powershell
@'
from src.test_runner import TestRunner
from src.graphs import GraphGenerator

runner = TestRunner()
runner.run_full_test_suite(25)
stats = runner.calculate_statistics()

graphs = GraphGenerator(runner)
graphs.generate_all_graphs()
graphs.save_all()

print(stats)
'@ | python -
```

## GUI Demo Flow

Recommended demo parameters:

- `Participants (n)` = `5`
- `Vulnerable Threshold` = `2`
- `Secure Threshold` = `4`

Suggested button sequence:

1. `Generate Vulnerable Setup`
2. `Run Collusion Attack`
3. `Run Tampering Attack`
4. `Apply Prevention`
5. `Run Collusion Attack` again
6. `Run Tampering Attack` again
7. `Run Full Test Suite`
8. `Show Graphs`

What to highlight during the demo:

- In the vulnerable baseline:
  - low threshold allows secret reconstruction through collusion
  - no integrity check allows forged-share tampering
- After prevention:
  - the same collusion budget is no longer enough
  - forged shares are detected before reconstruction
- The graph set shows:
  - attack success reduction
  - time vs degree trade-off
  - confidentiality / integrity / authentication improvement
  - attack vs protection overhead
  - comparison across all solution profiles

## Generated Graphs

Graphs are saved under `output/`:

- `graph_success_rate.png`
- `graph_time_vs_degree.png`
- `graph_confidentiality.png`
- `graph_latency.png`
- `graph_attack_comparison.png`

## Documentation Files

- Mathematical explanation and proofs:
  - `docs/mathematical_background_and_proofs.md`
- Full project overview:
  - `docs/what_the_project_is.md`
- Current implementation / deliverables audit:
  - `docs/deliverables_audit.md`
- Draft report content:
  - `some_.md_files/project_report.md`
- Draft slide outline:
  - `some_.md_files/presentation_outline.md`
- Binary report / presentation assets:
  - `docs/shamir_report_ieee.docx`
  - `docs/Shamir_Secret_Sharing_Presentation.pptx`

## Current Test Suite Behavior

The automated suite currently:

- runs `25` randomized cases
- varies:
  - secret values
  - `n` from `5` to `10`
  - vulnerable threshold `t` in `{2, 3}`
  - secure threshold `high_t = max(n - 1, low_t + 2)`
- compares all four solution profiles

Typical current outcomes:

- collusion success before prevention: `100%`
- collusion success after prevention: `0%`
- tampering success before prevention: `100%`
- tampering success after prevention: `0%`
- honest reconstruction rate: `100%`

## Important Positioning

This project should be presented as:

- an implementation and evaluation of Shamir's Secret Sharing
- a demonstration of how weak parameter choice and missing verification create attacks
- a comparison of multiple defense profiles
- a practical bridge between basic SSS and stronger verifiable secret-sharing ideas

It should not be presented as a claim that Shamir's Secret Sharing is fundamentally broken. The key lesson is that **security depends heavily on parameter choice and validation mechanisms**.
