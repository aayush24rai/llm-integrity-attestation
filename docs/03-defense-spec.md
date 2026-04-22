# Defense Specification — Attestation Approaches Analyzed Against the Threat Model

## Purpose

This document analyzes five attestation approaches against the threat model defined in `01-threat-model.md`. Each approach is evaluated specifically in the context of this project's adversary model: the attacker is the Linux user account that owns and runs the model process, has full read and write access to their own process's memory, can attach debuggers to their own processes, can modify files they own, and can monkey-patch any code loaded inside their process. The attacker cannot become root, cannot become the verifier user, and cannot modify kernel-enforced policies.

For each approach, this document specifies what is protected, how the protection mechanism operates, and — most importantly — which specific attacker capabilities the mechanism neutralizes and which it does not. 

The five approaches analyzed are:

1. TPM with Integrity Measurement Architecture (IMA) — hardware-rooted static measurement
2. TEE-based attestation with activation watermarking (AttestLLM) — hardware-isolated execution with model identity verification
3. Runtime segmented attestation (PracAttest) — periodic randomized integrity checks on in-memory model state
4. Software-based attestation (memory-printing) — no-hardware-trust timing-based verification
5. Zero-knowledge machine learning (zkML) — cryptographic proof of correct inference

---

## Approach 1: TPM + IMA (Hardware-Rooted Static Measurement)

### Reference

[1]“13th USENIX Security Symposium � Technical Paper,” Usenix.org, 2026. https://www.usenix.org/legacy/event/sec04/tech/full_papers/sailer/sailer_html/ (accessed Apr. 22, 2026).
‌
### Mechanism

The Linux kernel's IMA module hooks into the file-loading code paths (`mmap`, `execve`, and related syscalls). When any process asks the kernel to load a file into memory, IMA intercepts the operation before the file is actually mapped. It reads the file, computes a SHA-256 hash, extends the hash into a Platform Configuration Register (PCR) inside the Trusted Platform Module (TPM) chip, and appends an entry to an in-kernel measurement log recording the file path, hash, and timestamp. Only then does the kernel complete the file load.

PCRs are hardware registers inside the TPM that can only be extended, never written arbitrarily. Extension means the new value equals the SHA-256 hash of the old value concatenated with the new measurement. PCRs reset to zero only on hardware power cycle. This property means the current PCR value is a cryptographic summary of every measurement that has been extended into it since boot, in order.

When a remote verifier requests attestation, the machine asks the TPM to produce a signed quote of the PCR value bound to a verifier-provided nonce. The quote is signed with a key that is burned into the TPM hardware at manufacture and can never be extracted. The machine also sends the measurement log. The verifier checks the signature using the TPM's certified public key, checks the nonce for freshness, and replays the measurement log to confirm the log is consistent with the signed PCR. The verifier then evaluates whether the sequence of measurements matches a known-good baseline.

### How this interacts with the threat model's attacker

The attacker in this threat model runs as an unprivileged Linux account. The attacker owns and controls the model process, meaning they can modify files they own, read and write their own process's memory via `/proc/self/mem`, replace libraries via `LD_PRELOAD`, and monkey-patch Python code. The attacker cannot modify kernel code, cannot access the TPM's signing key, and cannot alter PCRs except through legitimate extension operations.

IMA operates inside the kernel. The measurement hooks are installed as part of kernel initialization and cannot be disabled or bypassed by unprivileged userspace code. When the attacker's Python process asks the kernel to load `tinyllama.gguf`, the IMA hook fires inside kernel space, before the file's bytes are returned to userspace. The attacker has no opportunity to intercept this hashing because it happens in a privilege domain they cannot reach. The hash is extended into the TPM over a direct kernel-to-TPM channel that userspace processes cannot observe or tamper with.

The measurement log lives in kernel memory. The attacker cannot directly read or write kernel memory from an unprivileged process. They cannot insert fake entries, cannot remove entries corresponding to tampered files, and cannot reorder entries.


### Coverage against each attack

**A1 (model file replacement) — protected.** If the attacker replaces `tinyllama.gguf` on disk with a backdoored model and then starts the model process, the kernel loads the new file and IMA hashes it at load time. The measurement log records the hash of whatever file was actually loaded, which is the backdoored file's hash. The verifier sees this hash does not match the baseline and rejects the attestation. The attacker cannot avoid the measurement by any software-only means because the measurement happens in kernel space before the file is made available to userspace. The only way to avoid measurement is to not load the file at all, which defeats the attacker's goal.

**A2 (tokenizer tampering) — protected.** The tokenizer is just another file. When llama-cpp-python loads `tokenizer.json`, the kernel's IMA hook hashes it the same way. Tampered tokenizer produces a different hash, which appears in the log, which the verifier compares to the baseline.

**A3 (in-memory weight tampering) — not protected.** This is the critical limitation. IMA measures files at load time. Once the model file's bytes have been loaded into the attacker's process memory, IMA stops caring about that file. The attacker has full write access to their own process's memory. They can modify the weights in RAM using `ptrace`, through `/proc/self/mem`, or by simply assigning to the Python objects that hold the tensors. None of these operations trigger any IMA hook, because none of them involve loading a file.

The measurement log will continue to show the correct hash of the original model file. The PCR will contain the correct value. The verifier will see a clean attestation. But the tensors actually being used for inference are different from the tensors the file contained. IMA has no visibility into post-load memory state.

This is not a flaw in IMA. IMA is a *static* attestation technique by design. It answers the question "what files were loaded into this system?" and answers it well. It does not answer "what is currently in memory right now?" That is a different question requiring a different technique.

**A4 (runtime parameter manipulation) — not protected.** Runtime inference parameters (temperature, top_p, max_tokens, system prompt) are not files. The attacker passes them as arguments to `Llama.create_completion()` or equivalent Python calls. IMA does not hook function arguments because that is not what IMA does. The attacker can pass any parameters they want; IMA will not notice.

**A5 (execution state) — not protected.** Logits, KV cache, and intermediate activations are in-memory values produced during inference. IMA does not measure runtime state.

### What the attacker's process-ownership capability means for this approach

The attacker's ability to modify their own process memory is what makes IMA insufficient for the full threat model. IMA is perfectly strong against *file-level* tampering, because files exist in a domain the attacker cannot reach inside of (the kernel's load path, the TPM hardware). But the attacker does not have to tamper with files if they can tamper with memory directly. The gap between "file on disk" and "bits in RAM" is the gap IMA cannot close, and it is exactly the gap the attacker's process ownership exposes.

IMA also does not protect against the attacker choosing to skip verification entirely. The attacker could request a TPM quote, see that it reports the correct state, and then tamper with memory and run inference. The attestation itself is trustworthy, but a one-time attestation does not guarantee anything about subsequent state. This is addressable by continuous attestation, which IMA is not designed for.

### Role in the overall defense

IMA provides the foundation for A1 and A2 with hardware-rooted evidence. It does not address A3 or A4. A complete defense requires layering a runtime mechanism on top of IMA for A3, and a separate policy enforcement mechanism for A4.

---



## Approach 2: TEE-Based Attestation with Activation Watermarking

### Reference

[2] R. Zhang, Y. Zhao, N. Javidnia, M. Zheng, and F. Koushanfar, “AttestLLM: Efficient Attestation Framework for Billion-scale On-device LLMs,” arXiv.org, 2025. https://arxiv.org/abs/2509.06326 (accessed Apr. 22, 2026).
‌
### Mechanism

A Trusted Execution Environment (TEE) is a region of the CPU that runs code in hardware-enforced isolation from the rest of the system. Specific implementations include Intel SGX (small enclaves), Intel TDX and AMD SEV-SNP (whole VMs), and Arm TrustZone (secure world vs. normal world). The critical property is that code and memory inside the TEE cannot be read or modified by anything outside it — not the operating system, not other processes, not root. Hardware enforces this isolation.

TEEs support remote attestation natively. The TEE can produce a signed measurement of itself stating what code is loaded inside and what initial data was provisioned. The signature uses a key burned into the CPU at manufacture. A remote verifier checks this signature against the CPU vendor's certification chain (Intel, AMD, Arm) and learns that they are talking to a genuine TEE containing specific code.

AttestLLM adds an LLM-specific layer on top of this hardware attestation. The problem AttestLLM addresses is that LLMs are too large to fit entirely inside a first-generation TEE like SGX (which is capped around 128 MB). Running the full model outside the TEE while keeping something useful inside requires a cryptographic binding between the model and the TEE.

AttestLLM's binding uses activation-based watermarking. At setup time, the model is fine-tuned so that specific secret trigger inputs produce specific expected activation patterns at certain internal layers. The triggers and expected activations are secrets. These secrets are stored inside the TEE; the model itself runs in normal memory (the rich execution environment, REE). Periodically, the TEE sends trigger inputs through the model, observes the activations, and verifies they match the expected patterns. If the watermark is present, the model running in the REE is the legitimate one. If it has been replaced or tampered with, the activations diverge and the TEE raises an alert.

### How this interacts with the threat model's attacker

The attacker still owns the model process in the REE. They still have full access to the weights in their own process memory. Crucially, however, the trigger inputs and expected activation patterns are not in the attacker's address space. They are inside the TEE, which is hardware-isolated.

When the TEE runs a watermark check, it sends a trigger input through the model. The model — running in the REE under attacker control — processes the input and produces output activations. The TEE observes these activations and compares them to the expected pattern. The attacker cannot preemptively know which trigger inputs will be used, so they cannot prepare a tampered model that responds correctly to those specific inputs. The attacker cannot see the expected activation patterns, so they cannot reverse-engineer the watermark scheme from outside the TEE.

The TEE's attestation also covers the verification code itself. The remote verifier learns not just "the model claims to have the watermark" but "a genuine TEE containing the correct verification logic confirmed the watermark was present."

### Coverage against each attack

**A1 (model file replacement) — protected.** If the attacker swaps the model file for a different model, that different model does not contain the watermark. When the TEE runs a trigger input through the replaced model, the activations will not match the expected pattern. Detection is immediate on the next attestation round.

**A2 (tokenizer tampering) — partially protected.** The tokenizer is not directly watermarked in the AttestLLM scheme. A tampered tokenizer could alter the inputs to the model in a way that still produces plausible activations. This is a genuine gap. A full deployment would need to pair AttestLLM with file-level tokenizer integrity (such as IMA hashing the tokenizer file at load) to close A2.

**A3 (in-memory weight tampering) — protected.** This is the approach's strongest contribution. If the attacker modifies weights in RAM using `ptrace` or `/proc/self/mem`, the modified weights produce different activations for the trigger inputs. The TEE's watermark check catches the discrepancy. Because the check runs on the live model state, not on a static file, it detects tampering regardless of whether the original file is unchanged.

The frequency of checks determines the detection window. AttestLLM recommends periodic checks throughout inference, which bounds how long tampering can remain undetected.

**A4 (runtime parameter manipulation) — partially protected.** If the TEE is also the entity that serves inference requests — enforcing parameter policy before forwarding to the REE model — then A4 is protected at the TEE boundary. If the TEE only handles watermark verification and the attacker can call the model directly with their own parameters, A4 is not covered. The coverage depends on the deployment architecture.

**A5 (execution state) — partially protected.** Watermark checks during ongoing inference would detect some forms of activation tampering, but the paper does not claim full execution-state coverage. This remains an open area.

### What the attacker's process-ownership capability means for this approach

The attacker owning the model process no longer matters for the secrets protecting attestation. The triggers, the expected activations, the verification code, and the signing key all live in the TEE. The attacker's process ownership gives them no leverage there.

What the attacker's ownership still affects is the model itself. The model runs in their process, in memory they can write. But they cannot tamper with the model without breaking the watermark — which is exactly the point. The attacker's capability to tamper is not removed; it is rendered detectable.

The key architectural insight is that AttestLLM does not try to prevent the attacker from having access to the model. It allows the attacker to have everything they would normally have, and instead creates a cryptographic fingerprint that cannot survive tampering. This is a shift from "protect the model from being touched" to "detect any effective tampering."

### Role in the overall defense

TEE-based attestation with watermarking covers A1 and A3 strongly, with partial coverage of A2 and A4 depending on architecture. It requires TEE hardware, which is not universal on developer workstations. The primary cost for this project is hardware availability; the primary strength is that it covers A3, which no software-only approach can fully handle.

---

## Approach 3: Runtime Segmented Attestation

### Reference

[3] I. Abidi, V. Kumar, and R. Sen, “Practical Attestation for Edge Devices Running Compute Heavy Machine Learning Applications,” Annual Computer Security Applications Conference, pp. 323–336, Dec. 2021, doi: https://doi.org/10.1145/3485832.3485909.
‌
### Mechanism

The core observation behind runtime segmented attestation is that full-model hashing is infeasible at high frequency. An LLM with several gigabytes of weights cannot be hashed every second without destroying inference performance. But infrequent hashing leaves long windows where an attacker can tamper with memory and escape detection.

The technique's solution is segmentation plus randomization. The model is divided into many small segments, each a few megabytes. On each attestation round, a random subset of segments is selected and hashed. The subset is small enough that hashing completes quickly. The selection is randomized and not known to the attacker in advance.

Attestation rounds run at a high frequency (every few seconds or faster). Over many rounds, each segment gets checked repeatedly, but the attacker cannot predict which segments will be checked next.

The security argument is probabilistic. If the attacker modifies segment 47 and wants the modification to persist for duration D across rounds of length t, they need segment 47 to escape selection in D/t consecutive rounds. If each round samples a fraction f of segments, the probability of escape is (1 - f)^(D/t), which shrinks rapidly. The parameters (sampling rate, round interval) are tunable, giving a direct performance-vs-detection-latency tradeoff.

The technique is generic and does not depend on specific hardware. Any trusted location can run the attestation logic — a separate Linux user, a TEE, a kernel module.

### How this interacts with the threat model's attacker

The attestation code runs somewhere. That somewhere must be outside the attacker's reach; otherwise the attacker can simply disable or modify the attestation logic. This is the critical architectural question for this approach.

If the attestation code runs inside the attacker's own process, the approach fails completely. The attacker owns the process and can rewrite the hashing function to always return the correct hash, can disable the random segment selection, or can replace the baseline values in memory. (In-process attestation against a process-owning attacker is equivalent to our original flawed design.)

If the attestation code runs as a different Linux user (the verifier user from the project's architecture), the attacker cannot modify the attestation code. But the attestation code still needs to hash segments of the attacker's process memory. The verifier user would need the ability to read the attacker's process memory, which on Linux requires root privileges or specific capabilities. This is the practical constraint: the attestation logic needs both to be outside the attacker's reach *and* have a way to observe the attacker's memory.

The cleanest solution is to run the attestation logic inside a TEE, which has hardware-enforced access to memory it chooses to monitor (if the TEE is designed to permit this) while being isolated from the attacker. Without a TEE, implementing this approach on Linux requires careful use of privileged system calls like `process_vm_readv` from a root-owned helper, which expands the trusted computing base considerably.

### Coverage against each attack

**A1 (model file replacement) — partially protected.** The segmented hashing operates on in-memory segments, not on the file on disk. If the attacker swaps the file before the model is loaded, the segments will hash to whatever the new file produced. If the baseline was established when the good file was loaded, the hashes will not match the baseline and detection occurs. If the baseline is established fresh each time the model loads (which would be a design error), the approach does not catch file replacement.

In practice, segmented runtime attestation is typically paired with load-time file integrity (IMA or similar) to close this gap cleanly.

**A2 (tokenizer tampering) — partially protected.** Similar to A1. The tokenizer is small enough that it can be hashed whole rather than segmented, but the same in-memory versus on-disk question applies.

**A3 (in-memory weight tampering) — protected.** This is the approach's primary target. If the attacker modifies any segment of the model in memory, that segment's hash changes. On the next attestation round where that segment is sampled, the hash mismatch is detected. The randomized sampling means the attacker cannot time their tampering around the checks. Over a few rounds, detection becomes statistically near-certain.

The critical assumption is that the attestation code has read access to the attacker's memory. The attacker cannot block this access if the accessing party has higher privilege (root, TEE).

**A4 (runtime parameter manipulation) — not protected.** Parameters are not part of the model weights being hashed. This approach says nothing about A4.

**A5 (execution state) — partially protected.** The same randomized-sampling idea could in principle extend to activation state or KV cache, but the published work focuses on weight integrity. Extending to execution state would be an additional design step.

### What the attacker's process-ownership capability means for this approach

The attacker's process ownership determines where the attestation logic must live. Inside the attacker's process, the approach is dead. In a separate Linux user or TEE, the approach works — but requires the separate entity to have the ability to read the attacker's memory.

This is the practical tension of runtime attestation on general-purpose Linux. The kernel provides `process_vm_readv` and similar calls, but using them from a non-root user to read another user's process memory requires the right capabilities. A clean implementation typically requires the attestation daemon to have `CAP_SYS_PTRACE` or to run as root, which expands the trusted computing base.

Alternatively, the attestation can be implemented as a TEE-hosted service that has a memory-access channel into the REE, as some modern confidential computing architectures support.

### Role in the overall defense

Runtime segmented attestation is the direct answer to A3 for deployments where continuous runtime verification is required but full hashing is infeasible. It requires a trusted host for the attestation logic and a memory-access channel to the model process. Layered on top of IMA (for A1/A2) and parameter policy enforcement (for A4), it closes the A3 gap.

---


## Approach 4: Software-Based Attestation (Memory-Printing)

### Reference

[4] M. Jakobsson and K.-A. Johansson, “Practical and Secure Software-Based Attestation,” CiteSeer X (The Pennsylvania State University), Mar. 2011, doi: https://doi.org/10.1109/lightsec.2011.8.

### Mechanism

Software-based attestation is the family of techniques that provide integrity verification without any trusted hardware. No TPM, no TEE, no dedicated security chip. The trust anchor is physical timing properties of the device's memory subsystem.

The core idea is a challenge-response protocol where the prover must perform a computation that uses all available RAM in an unpredictable pattern, completing within a tight time window. The computation is designed so that malware — which must hide in RAM while remaining active — cannot complete the computation in the expected time. If malware is present, it must either store its displaced RAM contents in secondary storage (slow) or recompute them on the fly (very slow). Either way, the timing test fails.

Jakobsson-Johansson's specific technique, memory-printing, works as follows. First, the prover fills all free RAM with a pseudo-random pattern derived from a seed provided by the verifier. The pattern is constructed so that recomputing any individual memory cell's value requires hundreds of hash computations. Second, the prover runs a checksum computation that reads RAM in an access order determined by a step value the verifier provides at challenge time. The checksum is accumulated in CPU registers. The access pattern traverses all RAM exactly once, in an order the attacker could not have predicted before the step value was released.

The verifier times the entire computation. A clean machine completes in a known time window (around 3 seconds for a 256 MB device in the original paper). An infected machine — where some RAM is occupied by malware and the displaced pseudo-random pattern must be retrieved or regenerated — is measurably slower, because flash is much slower than RAM.

RealSWATT extends this by using a dedicated CPU core for the attestation, providing stronger timing guarantees without needing to freeze the rest of the system.

### How this interacts with the threat model's attacker

This is where the approach runs into serious trouble for this project's threat model.

Software-based attestation was designed for embedded and mobile devices. Its security assumptions include: small RAM (a few hundred megabytes), a single-user device, the ability to swap out all other processes during attestation, and timing precision measured in microseconds. The attacker is typically modeled as malware that has infected the device, not as a legitimate user actively computing on the device.

The project's threat model differs on every one of these points. The deployment is a Linux workstation with many gigabytes of RAM. Multiple processes run simultaneously. The attacker is not hiding malware; the attacker is the legitimate user running their own model. The attacker has full control of the system under their UID. They can run arbitrary processes, allocate arbitrary memory, and perform arbitrary computations at any time.

The specific threat-model mismatch is severe. Software-based attestation asks: is there active malware hiding in RAM? The project's threat model asks: is the legitimate user's model tampered with? These are different questions. The attacker in this project is not trying to hide an extra process; they are openly running the model and potentially modifying its state.

The timing argument also becomes weak. On a workstation with 16+ GB of RAM, memory-printing the entire RAM would take much longer than the original paper's 3-second window. More importantly, the attacker can legitimately run other processes during attestation, which would cause timing variations indistinguishable from the presence of malware. There is no stable baseline timing to compare against.

### Coverage against each attack

**A1 (model file replacement) — partially protected, in principle.** If the attacker swapped the model file and the tampered model is now loaded in RAM, a memory-printing scheme could in principle notice that the RAM contents differ from the expected pseudo-random pattern plus the expected model bytes. In practice, this requires the attestation to know what the "correct" RAM state should look like, which for an LLM is highly variable (inference produces intermediate state constantly).

**A2 (tokenizer tampering) — similar to A1.** Same limitations apply.

**A3 (in-memory weight tampering) — partially protected, in principle.** Tampering changes RAM contents. Memory-printing hashes RAM. In principle, tampering changes the hash. In practice, the volume of non-weight RAM (OS state, other processes, inference intermediates) makes isolating weight changes from other changes very difficult.

**A4 (runtime parameter manipulation) — not protected.** Parameters do not reside in RAM in a way this approach monitors.

**A5 (execution state) — not protected.** Same issue; execution state changes constantly during inference.

### What the attacker's process-ownership capability means for this approach

The attacker's process ownership gives them a fatal capability against this approach: the ability to legitimately occupy RAM and CPU during the attestation window. Software-based attestation fundamentally requires the prover's system to be in a quiescent state during attestation. On an embedded device this is enforceable. On a multi-user Linux workstation where the attacker is the legitimate user running inference, quiescence cannot be enforced.

The attacker does not need to hide anything. They are not an infection to be detected. They are a user computing on their own machine. Software-based attestation's core security argument — that active malware cannot hide — does not apply, because the thing being examined is not malware; it is the legitimate workload itself.

### Role in the overall defense

Software-based attestation is included in this analysis because it represents an important conceptual category (no-hardware-trust attestation) and because the literature on it is foundational. It is not a viable primary technique for this deployment scenario. It is cited as the canonical example of what attestation looks like when hardware trust anchors are unavailable, and to document the reasoning for why this project does not use it.

---

## Approach 5: Zero-Knowledge Machine Learning (zkML)

### Reference

[5] H. Sun, J. Li, and H. Zhang, “zkLLM: Zero Knowledge Proofs for Large Language Models,” pp. 4405–4419, Dec. 2024, doi: https://doi.org/10.1145/3658644.3670334.

### Mechanism

Zero-knowledge proofs are cryptographic protocols where one party (the prover) convinces another (the verifier) that a mathematical statement is true, without revealing any information beyond the truth of the statement. For zkML, the statement is "inference computation C was performed correctly on model M with input X, producing output Y."

The prover produces a proof object — a small cryptographic blob. The verifier runs a mathematical check on the proof. If the check passes, the verifier is mathematically certain the computation was performed correctly using the specified model and input. The verifier learns nothing about the model weights or the input beyond what the output reveals. The proof cannot be forged without breaking the underlying cryptographic assumptions (such as hardness of certain lattice problems or elliptic curve operations).

No hardware is required. No trusted execution environment. No trusted Linux account. The security rests entirely on cryptographic hardness.

zkLLM specifically adapts the zk-SNARK machinery to LLM inference, dealing with the scale and specific operations (attention, layer normalization, matrix multiplications) that LLMs require.

### How this interacts with the threat model's attacker

The attacker's process ownership is essentially irrelevant to zkML's security. The attacker can own the model process, modify memory, patch code, do anything they want. None of these capabilities help them forge a valid zero-knowledge proof.

If the attacker tampers with the model and then produces a proof of inference, the proof will either:
- Fail verification, because it does not correspond to a correct computation under the claimed model
- Succeed verification but for the tampered model's computation, not the expected model's — and the proof necessarily commits to which model was used, so the verifier learns the wrong model was used

The attacker cannot produce a proof that a computation happened when it did not, or that a different computation happened than actually did. The cryptography prevents it.

### Coverage against each attack

**A1, A2, A3, A4 — all protected in theory.** The proof binds the exact model (including weights and tokenizer), the exact input (including all parameters), and the exact output. Any tampering at any layer either produces an invalid proof or produces a valid proof for the tampered configuration that the verifier can identify.

**A5 — protected in theory.** Execution state is part of the computation being proved. Any deviation would invalidate the proof.

### What the attacker's process-ownership capability means for this approach

Nothing. This is the approach's strongest property — it does not care what the attacker can do to their own process, because the security does not rest on any property of the attacker's system.

### The catastrophic practical limitation

zkML is currently orders of magnitude slower than native inference. Published zkLLM results show proof generation times of approximately 15 minutes per token for a 13B parameter model, with verification times in the seconds. For a model producing hundreds of tokens per response, this is completely impractical for real-time use.

This is not a matter of engineering optimization. The cryptographic machinery is inherently expensive when applied to billions of floating-point operations. Active research may reduce this overhead, but the current state of the art does not support practical deployment of zkML for LLM inference.

### Role in the overall defense

zkML is included as the theoretical ceiling for attestation. It represents what attestation looks like when no trust assumptions about the prover's environment are made at all. Its current impracticality for LLMs is a feasibility issue, not a security issue. This approach is documented to show that the project is aware of the cryptographic frontier and has made a reasoned decision to prefer hardware-rooted approaches for practical reasons.

---




