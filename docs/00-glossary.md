# Glossary

This glossary defines the roles, components, and technical terms used throughout the LLMGuard design documents. All subsequent documents reference these definitions. When any term is ambiguous in standard usage (for example, "user" can mean either a trusted service account or an unprivileged attacker), this glossary resolves the ambiguity.

## Roles

The design recognizes three roles, distinguished by privilege level and what each is trusted to do. These terms appear throughout the threat model, architecture, and defense specification.

### root

The system administrator role. Corresponds to UID 0 on a Linux system. Responsible for installing and configuring the attestation system, loading the kernel-level security policy that confines the model process, and running the kernel-level monitoring daemon. Root is the ultimate trust anchor: if root is compromised, the entire system's integrity is void. The design assumes root is not hostile.

### user

A dedicated Linux account that runs the verifier daemon. This account is not root — it has no special system privileges — but it is also not the attacker. It sits between them as a third, trusted-but-limited party.

The user account owns three files that no other account can read or modify: the baseline, the signing key, and the audit log. File permissions on a Linux system are enough to protect these files from the attacker, because the attacker and the user are different Linux accounts.

The reason for using a separate account instead of running the verifier as root is the principle of least privilege. The verifier does not need root to do its job, so it should not have root. If the verifier has a bug that the attacker manages to exploit, the damage is limited to what the user account can access — the attestation secrets — rather than the entire machine. This is the same pattern used by production security services like OpenSSH and PostgreSQL.

When this document or any other uses the term "user" without qualification, it refers to this role — the verifier service account — not to any end-user of the LLM.

### attacker

A Linux account that is hostile to the attestation system. The attacker owns and runs the model process, meaning the model's executable, Python interpreter, loaded libraries, and the model weights in memory are all under their control.

The attacker can do anything a normal Linux account can do with its own resources. This includes modifying any file they own, reading and writing the memory of their own processes, attaching a debugger to their own processes, replacing libraries, swapping the model file on disk, and monkey-patching any Python code before or while it runs. In particular, the attacker can tamper with any security code that happens to run inside the model process, because that code is running in memory they own. This is the central assumption that the new design is built on: the model process is not trusted, because the model process is the attacker.

The attacker cannot do anything that requires a different Linux account or kernel privileges. They cannot become root. They cannot become the user (verifier) account. They cannot load or unload kernel modules, disable AppArmor policies, detach eBPF probes, or otherwise reach past the kernel boundary. Every defense in this design is placed somewhere the attacker cannot reach for exactly this reason.


## Components

### Model process

The operating-system process that loads the language model and performs inference. In this design, the model process is untrusted — it runs as the attacker's account, and any security logic executing inside it is assumed to be under the attacker's control.

### Verifier

A daemon running as the user role. Holds the baseline file, the signing key, and the audit log. Answers verification requests from the model process over a local Unix-domain socket. Because the verifier runs under a different account than the attacker, the attacker cannot read its secrets, attach a debugger to it, or modify its code.

### Monitor

A daemon running as root. Attaches kernel-level probes (via eBPF or equivalent kernel tracing facilities) to watch the model process from outside for signs of tampering-related syscalls. Logs suspicious activity to an append-only record owned by root. The monitor is a detection layer; it does not prevent attacks, but it records attempts for audit.

### Baseline

A signed JSON file, owned by the verifier user, recording the authoritative cryptographic hashes of the legitimate model artifacts (model weights, tokenizer, configuration files). Produced during an initialization step at a time when the model is trusted. The baseline is the "ground truth" that all later verification checks against.

### Signing key

A private cryptographic key (Ed25519) held exclusively by the verifier, stored in a file owned by the user account. Used to sign verdicts, audit log entries, and the baseline file. See "Signing" in the technical terms section.

### Audit log

An append-only record of every verification request, verdict, and detected anomaly. Owned by the verifier and signed per entry so that entries cannot be silently removed or altered after the fact.


## Technical terms

### Mandatory Access Control (MAC)

A kernel-enforced security model in which access rules are defined by a system administrator and cannot be overridden by the process they apply to. Contrast with Discretionary Access Control (DAC), where the owner of a resource decides who can access it. This design uses AppArmor, a Linux MAC implementation, to constrain the model process regardless of what code runs inside it.

### AppArmor profile

A text file defining a MAC policy for a specific executable. Loaded into the kernel by root. Once loaded, every syscall from a process running the confined executable is checked against the profile, and disallowed syscalls are refused by the kernel without the process being able to object.

### eBPF

Extended Berkeley Packet Filter — a Linux kernel facility that lets small programs run inside the kernel, attached to events like syscalls. Used in this design to observe the model process's syscall activity from a vantage point the model process cannot reach. eBPF programs are loaded by root and cannot be disabled or modified from userspace.

### Privilege separation

The design principle of splitting a security-sensitive system across multiple accounts or processes, each with only the privileges it needs for its specific job. The classical example is OpenSSH, which runs most of its logic as an unprivileged account and only invokes root-privileged operations through a narrow, audited interface. This design applies the same principle: the model process, the verifier, and the monitor each live in their own privilege domain.

### Signing (digital signatures)

A cryptographic technique the verifier uses to produce messages that cannot be forged, even by an attacker who can read the messages. Signing is how the design achieves the property that a verdict from the verifier is trustworthy: an attacker who controls the model process cannot fabricate a "pass" verdict and pass it off as coming from the verifier.

The security of signing depends entirely on the private key remaining secret. In this design, the private key is protected by Linux file permissions: the file is owned by the user account, and the attacker runs under a different account. The architecture also denies the attacker other paths to the key (debugger attachment, library injection, memory reading of the verifier process) through the kernel-level confinement described in the architecture document.

### Trust boundary

A conceptual line between two entities that trust each other differently. Data or control that crosses a trust boundary must be validated, authenticated, or otherwise checked before being acted upon. This design has two primary trust boundaries: between the attacker and the verifier, and between the verifier and root.

### Trust domain

The set of processes, files, and other resources operating under a single trust assumption. This design has three trust domains, corresponding to the three roles defined above: the root domain, the user (verifier) domain, and the attacker domain.

### Attestation

The act of producing evidence that a system is in an expected state. In this design, attestation refers specifically to the verifier producing signed verdicts about the integrity of model artifacts and runtime state, based on comparing current measurements against the baseline.

### TOCTOU

Time-Of-Check to Time-Of-Use. A class of security bug where a system checks a resource's state, and then uses the resource, but the state can be changed between those two moments. In this design, TOCTOU is a concern because an attacker could, in principle, swap a file after it is hashed but before it is loaded. The architecture addresses this by ensuring that hashing and loading are performed by the same trusted party (the verifier), not by the attacker.


















