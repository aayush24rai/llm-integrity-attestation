# LLM Integrity Attestation

A capstone project on integrity attestation for locally deployed large language models, exploring how to detect tampering with model artifacts and runtime state under realistic adversarial conditions.

**Author:** Aayush Rai — Kansas State University Capstone 2025–2026
**Advisor:** Dr. Eugene Vasserman

---

## Status: Design Phase

This project is currently in its design phase. Implementation is paused pending advisor review of the redesigned threat model and architecture.

The previous iteration of the design — which assumed a non-root attacker and focused on disk and memory attestation — has been archived at `docs/archive/original-adversary-model.md`. The redesign strengthens the adversary model to assume the model process itself is attacker-controlled, and introduces a privilege-separated architecture with kernel-level enforcement.

## Reading Order

The design documents are numbered for reading order:

1. [`docs/00-glossary.md`](docs/00-glossary.md) — Terms and roles used throughout the design
2. [`docs/01-threat-model.md`](docs/01-threat-model.md) — Adversary model and trust boundaries
3. [`docs/02-architecture.md`](docs/02-architecture.md) — Three-domain privilege-separated architecture
4. [`docs/03-defense-spec.md`](docs/03-defense-spec.md) — Defenses against each identified attack
5. [`docs/04-limitations.md`](docs/04-limitations.md) — What the architecture does not defend against
6. [`docs/05-implementation-plan.md`](docs/05-implementation-plan.md) — Phased implementation plan for the post-approval period

## Repository Structure

```
llm-integrity-attestation/
├── README.md                    # This file
├── docs/
│   ├── 00-glossary.md
│   ├── 01-threat-model.md
│   ├── 02-architecture.md
│   ├── 03-defense-spec.md
│   ├── 04-limitations.md
│   ├── 05-implementation-plan.md
│   ├── diagrams/                # SVG and image assets
│   └── archive/                 # Earlier design iterations
└── .gitignore
```

## Tags

- `v0-old-design` — Snapshot of the original design (non-root adversary model) before redesign
