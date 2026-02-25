# Shamir Secret Sharing Review Project

This repository contains the complete implementation and documentation for:
- Low-degree polynomial attack demonstration in Shamir's Secret Sharing
- Prevention using high-degree threshold + verifiable commitments
- GUI demo, test suite, and mandatory graph generation

## Folder Structure

```
review1/
  code.py
  requirements.txt
  README.md
  output/
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
    project_report.md
    presentation_outline.md
    deliverables_summary.md
  tests/
    quick_test.py
```

## Setup

1. Create and activate a virtual environment (recommended):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

## Run

1. Quick functionality test:

```powershell
python tests\quick_test.py
```

2. Launch GUI:

```powershell
python -m src.main
```

Backward-compatible launcher also works:

```powershell
python code.py
```

## How to Showcase (Live Demo Flow)

In the GUI, click buttons in this sequence:

1. `Generate Secret/Polynomial`
2. `Run Attack (Low Degree)`  
3. `Apply Prevention (High Degree)`
4. `Run Full Test Suite (20-25 cases)`
5. `Show Graphs`

What to highlight during demo:
- Low threshold (`t=2` or `t=3`) is vulnerable
- Reconstruction attack succeeds in low-degree setup
- High-degree threshold blocks same style attack
- Confidentiality and attack-success metrics improve in test suite
- Graphs are saved under `output/graph_*.png`

## Documentation Files

- Mathematical background and proofs: `docs/mathematical_background_and_proofs.md`
- Full project report content: `docs/project_report.md`
- PPT slide-by-slide outline: `docs/presentation_outline.md`
- Deliverables summary: `docs/deliverables_summary.md`
