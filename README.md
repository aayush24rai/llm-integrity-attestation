# LLMGuard: An Integrity Attestation Framework for Large Language Models

**Author:** Aayush Rai — Kansas State University
**Advisor:** Dr. Eugene Vasserman
**Capstone:** CIS 598, Spring 2026

---

## About

LLMGuard is a design contribution to the problem of verifying the integrity of large language models deployed on commodity Linux hardware. Once an LLM is loaded into a process, most systems treat it as trusted — but the model is just data on disk that becomes tensors in memory, and any user with access to the process can tamper with either. LLMGuard defines a threat model for this setting, surveys the attestation literature, and specifies a layered design that combines two attestation primitives:

- **TPM + IMA** for hardware-rooted file integrity at load time
- **TEE-protected behavioral attestation** (AttestLLM-style) for runtime integrity

The two layers cover complementary points in the model's lifecycle and together close a time-of-check-to-time-of-use gap that neither approach handles alone. The framework is realizable on commodity Linux with a TPM, and the TEE can be provided in hardware (Intel SGX, AMD SEV-SNP, ARM TrustZone) or in software (a hypervisor-based isolation domain).

## Deliverables

| Artifact | File |
|---|---|
| Final Paper (IEEE conference format) | [`LLMGuard-Paper.pdf`](LLMGuard-Paper.pdf) |
| Capstone Presentation (30 min) | [`LLMGuard-Presentation.pdf`](LLMGuard-Presentation.pdf) |
| Capstone Poster (36" × 48") | [`LLMGuard-Poster.pdf`](LLMGuard-Poster.pdf) |

The paper is the authoritative description of the design. The presentation and poster are the versions presented at the CS Department capstone showcase.

## What the Paper Covers

- **Threat Model.** A userspace adversary who fully owns the LLM process. Five attack categories on the model's lifecycle (A1–A5) covering at-rest tampering, tokenizer tampering, in-memory tampering, runtime parameter manipulation, and execution-state tampering. A precise scoping of what is and isn't defended.
- **Related Work.** Grounded in three recent systematization-of-knowledge papers: Ammar et al. (IEEE S&P 2025) on runtime integrity, Schneider et al. (2022) on hardware-supported TEEs, and Li et al. (ASIA CCS 2024) on TEE design pitfalls.
- **Design.** Five candidate attestation approaches (TPM+IMA, AttestLLM, PracAttest, software-based attestation, zkML) compared against the threat model. The rationale for combining TPM+IMA with TEE-based behavioral attestation, including the TOCTOU argument.
- **Architecture.** Three trust domains on a single Linux machine, four verifier-side components, and a three-stage attestation flow (load-time measurement → evidence collection → evaluation).
- **Limitations.** Honest scoping of what the design does not defend against — kernel-level adversaries, side channels, physical attacks — with reference to the documented vulnerabilities of hardware TEEs.

## Repository Structure

```
llm-integrity-attestation/
├── README.md                       # This file
├── LLMGuard-Paper.pdf              # Final paper — authoritative
├── LLMGuard-Presentation.pdf       # Capstone presentation
├── LLMGuard-Poster.pdf             # Capstone poster
├── docs/                           # Design-process notes leading to the paper
│   ├── 00-glossary.md              # Terms and roles
│   ├── 01-threat-model.md          # Detailed threat model notes
│   ├── 03-defense-spec.md          # Analysis of five attestation approaches
│   └── archive/                    # Earlier design iterations (superseded)
│       ├── original-adversary-model.md
│       ├── architecture-original.md
│       └── architecture-original.svg
└── .gitignore
```

The documents under `docs/` are the working notes that fed into the paper. They are kept in the repository as a record of the design process; the paper supersedes them where they differ.

## Reading Order

1. **[The paper](LLMGuard-Paper.pdf)** — start here. This is the finished design.
2. **[The presentation](LLMGuard-Presentation.pdf)** — for a shorter walkthrough of the same design.
3. **[The poster](LLMGuard-Poster.pdf)** — for the one-page visual summary.
4. `docs/01-threat-model.md` and `docs/03-defense-spec.md` — for deeper notes on the threat model and the candidate analysis than the paper had space for.

## Status

This is a design-phase capstone. The contribution is the threat model, the comparative analysis of attestation approaches, and the layered architecture. Implementation, empirical evaluation, and stronger constructions for the runtime layer are left as future work — outlined in Section VIII of the paper.

## Acknowledgments

Thanks to Dr. Eugene Vasserman for advising this project and for the guidance on the systematization literature that shaped the final design. Diagrams in the presentation and poster were produced with AI-assisted tooling; all design decisions, technical content, and final wording are my own.
