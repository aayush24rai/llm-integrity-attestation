# LLM Integrity Attestation

A security tool that detects tampering in local LLM deployments across four attack surfaces.

## Adversary Model
- Attacker is a **non-root local user**
- Can modify user-owned files and run arbitrary user-level processes
- Cannot modify root-owned files or the verification system

## Attack Surface Coverage

| Attack | Layer | Status |
|--------|-------|--------|
| A1 — Model file replacement | Disk | 🔨 In progress |
| A2 — Tokenizer tampering | Disk | 🔨 In progress |
| A3 — In-memory weight tampering | Memory | 🔨 In progress |
| A4 — Runtime parameter manipulation | Runtime | 🔨 In progress |
| A5 — Logits/KV cache tampering | Execution | 📋 Planned |

## Project Structure
```
llm_attest/
├── src/
│   ├── baseline/       # Baseline storage and management
│   ├── attacks/        # Attack simulation scripts
│   ├── defenses/       # Verification and defense logic
│   └── utils/          # Shared utilities (hashing etc.)
├── scripts/            # Setup and run scripts
├── tests/              # Test suite
└── docs/               # Architecture and setup docs
```

## Replication
See [docs/SETUP.md](docs/SETUP.md) for full VM setup and replication instructions.

## Demo
See [docs/architecture.md](docs/architecture.md) for system design and adversary model.

## Author
Aayush Rai — Kansas State University Capstone 2025-2026
