# Threat Model

## 1. Scope and purpose

This document defines the adversary model, assets, and attack surface that the LLMGuard attestation system is designed to defend against. It is the foundation for every design decision in the architecture and defense specification: each defense exists because this threat model identifies a specific attack, and each architectural choice exists because this threat model identifies a specific capability the attacker has.

This threat model targets a specific deployment pattern: a local large language model running on a machine where an unprivileged user has direct control over the model process. This includes a developer running llama.cpp on their own workstation, an application shipping an embedded LLM where the model runs under the application's own account, a researcher loading a model through Python libraries in their home directory, and any similar setup where the model's executable, weights, tokenizer, and configuration are all owned by an ordinary Linux user.

The threat model does not target cloud deployments with hardware attestation, model-serving APIs behind a trust boundary, or any setup where the model process runs under an account the attacker cannot become. Those deployments have different threat models, and their own existing defenses. LLMGuard's contribution is specifically for the local-deployment case.

## 2. Adversary model

### The attacker

The attacker is the Linux account that owns and runs the model process. In a typical local deployment this is an ordinary user account — the developer running the model, the application's service account, or the unprivileged user who launched a local inference job. The attacker is not remote, not a separate process on the same machine trying to break in, and not a compromised dependency. The attacker is the account under which the model is running, and the design assumes that account is actively hostile to the integrity of the model.

This framing is the central departure from the prior adversary model. In earlier versions of this design, the model process was implicitly trusted — integrity checks ran inside it, and the attacker was imagined as some separate actor trying to tamper with artifacts the model process used. That assumption does not survive contact with real local deployments, where the model process and any would-be attacker are the same Linux account. This threat model treats the model process as part of the attacker's trust domain from the outset.

### Capabilities

The attacker has the full set of capabilities that a Linux account has over its own resources. This is more extensive than it may appear at first, because Linux accounts have very broad authority over processes and memory they own.

1. On the filesystem, the attacker can read, modify, replace, or delete any file owned by their account. This includes the model weights on disk, the tokenizer file, any configuration files, any Python packages installed in a user-writable location, and the model-runtime executable itself if it is not owned by a different account. The attacker can also read any file on the system that is world-readable, including configuration files for other services, system binaries, and any attestation artifacts that are not specifically protected.

2. On process control, the attacker can start, stop, and modify any process they own. They can attach debuggers such as `gdb` or use the `ptrace` system call to inspect and manipulate the running process. They can send signals, open the process's `/proc/[pid]/mem` to read or write its memory, and use `process_vm_readv` and `process_vm_writev` to read and write another process's memory when both processes are owned by the same account. They can fork, exec, and spawn arbitrary helper processes under their own account.

3. On memory, the attacker has complete read and write access to the memory of any process they own, including the model process. This means the weights loaded into memory, the tokenizer's in-memory representation, the Python interpreter's object graph, and any variables holding cryptographic values, expected hashes, or policy configuration are all under attacker control. Memory-mapped files can be modified in place. Executable memory regions can be remapped as writable, modified, and remapped as executable, allowing runtime code patching.

4. On code injection, the attacker can load arbitrary shared libraries into their own processes via `LD_PRELOAD`, can modify any Python module before it is imported, can monkey-patch any function or class at runtime, and can replace any installed package with a modified version. Any security logic that runs inside the attacker's process — an integrity check, a parameter validator, a hash comparator — can be disabled, rewritten, or replaced by the attacker before or during its execution. This is the specific capability that invalidates any in-process defense.

5. On interprocess communication, the attacker can open and use any Unix-domain socket, named pipe, or other IPC endpoint that their account has permission to access. They can intercept and modify data their own processes send and receive. They can stand up imposter processes that mimic legitimate services and redirect communication to them, as long as the impersonation does not require privileges the attacker lacks.

6. On networking, the attacker can initiate arbitrary network connections under their account, listen on unprivileged ports, and make any outbound request the host's network policy allows. They can observe all network traffic their own processes send and receive.

### Limitations

The attacker has none of the capabilities that require a different Linux account or elevated kernel privileges. These limitations are what make defense possible, and each defense in the architecture relies on at least one of them.

1. The attacker cannot become root. They cannot execute code as UID 0, cannot invoke privileged system calls that require `CAP_SYS_ADMIN` or similar capabilities, cannot load or unload kernel modules, and cannot modify any file owned by root that is not writable by their account. Privilege escalation is outside the attacker's capability set by definition: a system where the attacker can become root is a different, harder threat model that this design does not attempt to address.

2. The attacker cannot become the user (verifier) account. The verifier runs under a separate Linux account with its own UID, and the attacker cannot switch to that account without root privileges. The verifier's files — the baseline, the signing key, and the audit log — are owned by the user account with file permissions that deny read and write access to the attacker. The attacker cannot attach a debugger to the verifier process, cannot read the verifier's memory, and cannot inject code into the verifier, because all of these operations cross a Linux account boundary.

3. The attacker cannot modify kernel state or kernel-enforced policies. They cannot disable AppArmor profiles applied to their processes, cannot detach eBPF probes installed by root, cannot turn off kernel audit subsystems, and cannot alter kernel tracing configurations. Any security decision made by the kernel on the basis of policy installed by root is, from the attacker's perspective, a constant of the environment. The attacker can attempt operations the kernel will deny, but cannot change the denial.

4. The attacker cannot forge cryptographic signatures produced by the verifier's signing key. This is a consequence of the previous two limitations combined: the signing key is stored in a file the attacker cannot read, and the verifier process holding the key in memory is one the attacker cannot attach to or inspect. Without the private key, the attacker cannot produce a signature that will verify against the corresponding public key. The attacker can copy signed messages, replay old ones, or attempt to fabricate new ones, but a signature on any forgery will fail verification.

### The trust boundary

The trust boundary in this design is the line separating the attacker's Linux account from every other Linux account on the system, combined with the line separating userspace from the kernel. Everything inside the attacker's account is untrusted. Everything outside it — the verifier running as a different user, the monitor running as root, and the kernel itself — is trusted to the extent that the mechanisms protecting it from the attacker are sound.

### Who the attacker is not

Several attacker types are explicitly outside this threat model and are not addressed by the design:

1. A remote network attacker with no local account on the machine is not the attacker modeled here. The design assumes local code execution under an unprivileged account as the starting condition. Network-based attacks, if any, are the concern of other layers of the system.

2. A supply-chain attacker who compromises the model file, tokenizer, or a dependency before the baseline is established is not addressed. The baseline records the hashes of whatever files exist at initialization time, and attests them thereafter. If those files were already malicious when the baseline was taken, the system will faithfully attest the malicious version. Baseline initialization must be performed from a trusted source.

3. An insider with root access is not addressed. Root can modify baseline files, verifier code, AppArmor policies, and kernel state. The design assumes root is not hostile. A deployment environment where the administrator is not trusted requires a different threat model, typically involving hardware attestation.

4. A physical attacker with access to the machine's hardware is not addressed. Cold-boot attacks, hardware-level memory tampering, and similar physical attacks are outside the software threat model. Protection against physical attacks requires TPM-backed measured boot and encrypted memory, which this design does not specify.


## 3. Assets and trust domains

### Assets

This section enumerates the specific things the attestation system protects. Each asset is something the attacker has a reason to target and the defense has a reason to preserve. Naming the assets explicitly is what lets the defense specification later reason about which attacks threaten which assets, and which defenses cover which attacks.

The model weights are the primary asset. These are the trained parameters that determine the model's behavior. An attacker who modifies the weights, either on disk or in memory, can change the model's outputs on specific inputs — introducing bias, creating a backdoor that triggers on a particular phrase, or causing the model to leak information. The weights are what makes the model the model, and tampering with them is the most direct way to corrupt its behavior without the corruption being obvious from the outside.

The tokenizer is the second asset. The tokenizer converts text into the numeric tokens the model actually consumes. Modifying the tokenizer — remapping specific words to different token IDs — changes how the model interprets input without touching the weights. A tampered tokenizer can silently rewrite prompts at the preprocessing layer, bypassing any safety filters that operate on the surface text.

The model configuration is the third asset. Configuration files specify architectural details like the number of layers, attention heads, and hidden dimensions. These rarely change during normal operation, and unexpected changes to them suggest tampering with the model's identity rather than its parameters.

The runtime parameters are the fourth asset. These are the inference-time knobs — temperature, top-p, maximum token length, system prompt — that shape how the model generates output from any given input. What is protected is not that these parameters never change, but that every inference call uses parameters within the range the deployer authorized. The deployer establishes this range at setup time when the baseline is initialized; for a research deployment the range may be wide (any temperature, any system prompt), while for a production deployment it may be narrow (temperature between 0.3 and 1.0, fixed system prompt). An attacker who calls the model with parameters outside the authorized range can neutralize safety prompts, remove output limits, or push the model into operating conditions the deployer never sanctioned, without touching any file on disk. The defense catches the unauthorized call rather than preventing the model from being configurable.

The attestation secrets are the fifth asset. These are the artifacts the verifier itself depends on to do its job: the baseline file recording the authoritative hashes, the signing key used to produce unforgeable verdicts, and the audit log recording all verification activity. These are not assets of the model, they are assets of the defense system. If the attacker can tamper with any of them, the defense itself is compromised and the model's integrity can no longer be attested.

### Trust domains

The design partitions the system into three trust domains corresponding to the three roles defined in the glossary. Each domain is a distinct Linux account with its own privileges, files, and processes, and the assets above are distributed across the domains according to what each domain needs to do its job.

The attacker domain runs under the attacker's Linux account. It contains the model process, the model weights and tokenizer as loaded in memory, the Python interpreter and any application code, and any runtime state associated with inference. On disk, this domain contains the copies of the model weights, tokenizer, and configuration files that the model process loads from. These on-disk copies are assets the defense protects, but they live in attacker-owned storage because the model runtime needs to read them, and in this deployment pattern the runtime runs under the attacker. The attacker can modify any of these files freely; the defense catches the modification rather than preventing it.

The user domain runs under a dedicated unprivileged account and contains the verifier daemon and its protected assets: the baseline file, the signing key, the audit log, and the authorized parameter policy. These assets must be readable and writable by the verifier but not by the attacker, which is exactly the guarantee Linux file permissions provide when the verifier and attacker are different accounts. The user domain has no interest in the model artifacts themselves — it holds hashes, signatures, and policies that describe them, not copies of them.

The root domain contains the kernel, the AppArmor policy that confines the attacker's processes, the eBPF probes that monitor the attacker's syscalls, and the monitor daemon that reads probe output. Root also acts as the deployer at setup time, when the attestation system is first installed and the baseline and authorized parameter policy are initialized. After setup, root does not hold copies of any model assets or attestation secrets. Its role is to enforce and observe, not to store. This separation is intentional: the smaller root's trusted responsibilities, the smaller the consequences if any root-level component has a bug.

### Asset placement summary

The following table records which trust domain each asset lives in. This mapping is what the architecture and defense specification will refer back to when reasoning about specific attacks and defenses.

| Asset | Primary location | Trust domain |
|---|---|---|
| Model weights (on disk) | Model file path | Attacker |
| Model weights (in memory) | Model process address space | Attacker |
| Tokenizer (on disk) | Tokenizer file path | Attacker |
| Tokenizer (in memory) | Model process address space | Attacker |
| Model configuration | Configuration file path | Attacker |
| Per-call parameter values | Inference call arguments | Attacker |
| Baseline | Baseline file | User |
| Signing key | Key file | User |
| Audit log | Log file | User |
| Authorized parameter policy | Policy file | User |
| AppArmor policy | Kernel policy store | Root |
| eBPF probes | Kernel | Root |

The pattern is intentional: every asset related to the model itself lives in the attacker domain, and every asset related to the defense of the model lives outside it. This is the concrete application of the privilege-separation principle to the LLM integrity problem. The attacker can reach the model, because the model runs under the attacker; the attacker cannot reach the defense, because the defense runs elsewhere.


## 4. Attack Surface

This section enumerates the specific attacks the attestation system is designed to detect or prevent. Each attack is stated in terms of the adversary model and assets defined in the previous sections: what the attacker does, which asset the attacker targets, and what capability from the adversary model makes the attack possible. The defenses for each attack are specified separately in the defense specification document; this section is the attack catalog, not the defense plan.

The attacks are labeled A1 through A5 and grouped by the layer at which the tampering occurs: disk, memory, runtime, or execution. This layering matters because different layers require different defense strategies, and the same asset can be attacked at multiple layers (for example, the weights can be tampered with on disk or in memory, and these are distinct attacks with distinct defenses).

### A1 — Model file replacement

**Layer:** Disk

**Target asset:** Model weights (on disk)

**Required capability:** Filesystem write access to the model file

The attacker replaces the legitimate model file with a different one at the same path. The substitute file may be a visibly different model with different capabilities, or a subtly modified version of the original with specific backdoors — weights adjusted to produce biased outputs on targeted inputs, or to leak information when a trigger phrase appears in the prompt. Because the model file lives in attacker-owned storage, the attacker has direct write access and needs no special privileges to perform the replacement.

This attack succeeds silently from the model's perspective: the model process loads whatever file is at the configured path, with no built-in mechanism to distinguish "the file I was supposed to load" from "a file someone swapped in." Detection requires an external reference — a record of what the legitimate file's contents should hash to — against which the current file can be compared.

### A2 — Tokenizer tampering

**Layer:** Disk

**Target asset:** Tokenizer (on disk)

**Required capability:** Filesystem write access to the tokenizer file

The attacker modifies the tokenizer file to change how text is converted to tokens before being fed to the model. By remapping specific tokens, the attacker can alter the model's interpretation of inputs without touching the model weights themselves. A specific example: if the tokenizer maps the word "dangerous" to the token that originally meant "safe," then any prompt containing the word "dangerous" is silently reinterpreted by the model as if it said "safe."

This attack is subtler than A1 because the model weights are unchanged and would pass any weight integrity check. The attack operates at the input preprocessing layer, making it harder to attribute to tampering if detection only watches the weights. Safety filters that rely on pattern matching in the surface text can be bypassed entirely because the tokens reaching the model have been rewritten.

A1 and A2 are distinct attacks because they target different assets and because an attacker may choose to tamper with one and not the other. An attack that modifies only the tokenizer passes any defense limited to the model file, and vice versa.

### A3 — In-memory weight tampering

**Layer:** Memory

**Target asset:** Model weights (in memory)

**Required capability:** Write access to the memory of the attacker's own process, or another process owned by the same account

The attacker modifies model tensor values after the model has been loaded into memory but before inference runs. This bypasses any defense that operates only on the disk-level file: the file on disk is unchanged and would pass any hash check, but the weights actually used for inference are different from what the file contains.

The attacker performs this tampering through any of several mechanisms from the adversary model's memory capabilities: direct writes to their own process's memory, writes to `/proc/[pid]/mem`, debugger attachment via `ptrace`, or `process_vm_writev` against another process under the same account. All of these require only ordinary user-level access, because the target process is owned by the attacker.

A3 is important because it is the first attack that invalidates any disk-only defense. The existence of A3 is what forces the design to extend beyond file hashing into runtime state.

### A4 — Runtime parameter manipulation

**Layer:** Runtime

**Target asset:** Per-call parameter values (against the authorized parameter policy)

**Required capability:** The ability to make inference calls with arbitrary arguments

The attacker invokes the model with inference parameters — temperature, top-p, maximum token length, system prompt — outside the range the deployer authorized. This may mean neutralizing a safety-oriented system prompt, setting temperature high enough to produce chaotic output, removing output length limits, or otherwise driving the model into operating conditions the deployer never sanctioned.

Unlike A1 through A3, this attack does not tamper with any stored artifact. The model weights, tokenizer, and configuration are all untouched. The attack happens entirely at the inference call site, by passing unauthorized arguments. Any defense that verifies only the stored artifacts will pass A4 without noticing.

A4 is a fundamentally different shape of attack from A1–A3. Those are tampering attacks — the attacker changes something that is supposed to be stable. A4 is a policy-violation attack — the attacker uses something that is supposed to be configurable, but uses it in a way the deployer did not authorize. The defense for A4 accordingly looks different: not hash comparison, but parameter-against-policy validation.

### A5 — Execution state tampering (planned)

**Layer:** Execution

**Target asset:** Intermediate computational state (logits, KV cache, activations)

**Required capability:** Memory write access during an active inference call

**Status: Planned.** This attack is identified in the threat model but the design does not yet specify a defense for it. It is included here so the attack surface is complete and the limitation is explicit.

The attacker manipulates the model's internal computational state during inference — modifying the raw logits (the output probabilities before sampling), corrupting the KV cache (the stored attention state used for context), or altering activations between layers. This attack happens inside the forward pass itself, after the model has been loaded, after any parameter validation has passed, and after any memory snapshot comparison would have been taken.

A5 is strictly harder than A1–A4 to defend against because the tampered state is a normal part of inference — logits and activations are supposed to change constantly during generation. A defense cannot simply check that these values are stable; it must distinguish legitimate computation from malicious modification of legitimate computation. Possible approaches include statistical monitoring of logit distributions for anomalous entropy patterns and integrity checksums over the KV cache between generation steps, but none of these are specified in the current design.

The decision to include A5 as "planned" rather than excluding it from the threat model entirely is deliberate. An honest threat model names threats it does not yet defend against, so the scope of the current defenses is clear. A5 is where future work on this system would begin.


### Attack surface summary

| Attack | Layer | Target asset | Status |
|---|---|---|---|
| A1 | Disk | Model weights (on disk) | Defended |
| A2 | Disk | Tokenizer (on disk) | Defended |
| A3 | Memory | Model weights (in memory) | Defended |
| A4 | Runtime | Per-call parameters vs. policy | Defended |
| A5 | Execution | Intermediate computational state | Planned |

The attack surface covered spans four of the five layers the threat model identifies. A1 and A2 cover the on-disk artifacts that exist before the model is loaded. A3 covers the in-memory state that exists after load but before inference. A4 covers the parameters that control each inference call. A5 covers the computational state during inference itself, and is the open problem the design leaves for future work.


## 5. Out of Scope

This section lists threats and concerns that are deliberately outside the scope of this threat model. Some are adjacent problems handled by other parts of a security stack; others are genuinely unsolved and would require a different architecture to address. Being explicit about what this design does not cover is part of a complete threat model: it establishes the boundary of the claim the design makes, and it identifies where future work or complementary defenses would be needed.

### Root compromise

The design assumes root is trusted. If an attacker gains root privileges — through a kernel exploit, a misconfigured setuid binary, a stolen root credential, or a cooperative insider — every defense in this system can be disabled or forged. Root can modify the baseline, replace the signing key, rewrite the AppArmor policy, disable eBPF probes, and tamper with the audit log. A threat model where the attacker can become root requires hardware attestation (TPM, Intel SGX, AMD SEV) or a different deployment architecture altogether, and is not what this design addresses.

### Supply chain compromise

The design attests to whatever the baseline records. If the model file, tokenizer, or any configuration file was malicious at the moment the baseline was initialized, the system will faithfully attest the malicious version — the baseline will simply hash the compromised artifact and treat that hash as authoritative. The defense against supply chain compromise is outside this threat model. It requires trust decisions made before the baseline is taken: verifying model provenance, checking cryptographic signatures from the model's publisher, running the model against a curated evaluation set before deployment, and so on. The attestation system guards the model as it exists after deployment, not the process of deciding which model to deploy.

### Remote network attacks

The threat model assumes the attacker has local code execution on the machine. Network-based attacks — someone without a local account trying to compromise the model through a network interface — are not addressed. If the model is served over a network, the network-facing layer is expected to handle authentication, authorization, rate limiting, and input validation through separate mechanisms. Once an attacker gains code execution under a local account, they fall within the scope of this threat model; until then, they do not.

### Physical attacks

Attacks requiring physical access to the hardware — cold-boot memory extraction, direct memory access through a peripheral bus, probing of the motherboard, or extraction of the disk — are outside the software threat model. Defense against physical attacks requires hardware-level protections such as encrypted memory, secure boot, TPM-backed key sealing, and physical tamper-evidence. This design addresses software threats only.

### Denial of service

An attacker under the deployment's adversary model can trivially deny service to the model: they own the model process and can simply refuse to run it, kill it, starve it of resources, or delete the model file. Availability is not a property the attestation system attempts to preserve. The goal is that any inference that does run is verifiably authentic, not that every requested inference must run. Denial of service is a separate concern addressed by other layers (process supervisors, resource limits, monitoring).

### Side-channel attacks on the model itself

Extracting information from the model through its legitimate outputs — membership inference, model extraction, prompt injection, jailbreaking — is not addressed. The attestation system verifies that the model is the model the deployer authorized; it does not constrain what that model will say when asked. Defenses against side channels on the model's behavior belong to a separate field (model alignment, output filtering, prompt firewalls) and are complementary to integrity attestation rather than substitutable for it.

### A5 (execution state tampering)

A5 is named in the attack surface as a known threat and explicitly marked planned rather than defended. The design does not currently specify a defense for tampering with logits, KV cache, or intermediate activations during inference. It is included in the threat model for completeness and is the primary direction for future work on this system.

### The scope of the claim

The claim this design makes is: given a deployment of the described pattern, the attestation system detects tampering at layers A1 through A4 under the adversary model specified in section 2, and logs evidence of detected tampering in an audit log the attacker cannot forge. The claim does not extend to the threats listed above. Any deployment requiring protection against those threats requires additional mechanisms beyond this design.















































