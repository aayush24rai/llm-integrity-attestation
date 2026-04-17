# Architecture

## Overview

LLMGuard is a privilege-separated integrity attestation system for locally deployed large language models. It partitions the host into three trust domains — root, user, and attacker — and places the model under attestation in the attacker domain while placing the defense outside it. The attestation system detects tampering across four attack layers (disk, memory, runtime, and execution) by combining kernel-enforced confinement of the model process, an out-of-process verifier that holds the baseline and signing key, and a root-owned runtime monitor that records policy-evasion attempts.

This document specifies the architecture in detail: the three trust domains and what each contains, the components that run in each domain, the communication protocol between them, the kernel-level enforcement and monitoring mechanisms that make the separation real, and the initialization procedure that establishes the baseline at setup time.

## Reference diagram

The system's overall structure is shown in the diagram at `docs/diagrams/architecture.svg`. The diagram renders the three trust domains as horizontal tiers with dashed trust boundaries between them: root and the eBPF monitor at the top, the verifier and its protected assets (baseline, signing key, audit log) in the middle, and the attacker's model process at the bottom. Communication between the model process and the verifier crosses the lower trust boundary through a Unix-domain socket; kernel-level observation of the model process is shown as a passive downward link from the monitor.


