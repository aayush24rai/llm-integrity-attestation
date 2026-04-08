# Adversary Model & Attack-Defense Specification

## 1. Adversary Model

### Who is the attacker?
A **non-root local user** on the machine running the LLM.

### What can the attacker do?
| Capability | Example |
|---|---|
| Read any world-readable file | Read `baseline.json` to learn expected hashes |
| Write to any user-owned file | Modify model files in `~/models/` |
| Run arbitrary processes | Execute Python scripts, shell commands |
| Interact with the model | Send prompts, observe outputs |
| Replace user-owned files | Swap `tinyllama.gguf` with a different model |

### What can the attacker NOT do?
| Limitation | Why it matters |
|---|---|
| Cannot write to root-owned files | Cannot tamper with `baseline.json` |
| Cannot escalate to root | Cannot bypass privilege separation |
| Cannot modify the verification system | Attestation results are trustworthy |

### Concrete scenario
A company runs a local LLM assistant on a shared Linux workstation.
Alice is an authorized user. She has shell access and owns her home directory.
The verification system and baseline are managed by the system administrator (root).
Alice is the attacker — she attempts to manipulate the LLM's behavior without
the administrator detecting it.

---

## 2. Deployment Context

### Why is this threat model realistic?
Most local LLM deployments today are NOT privilege-separated. Examples:

- A developer running `llama.cpp` with a `.gguf` file in `~/models/` — the model
  file is owned by them and writable by any process they run
- A company shipping an LLM-powered desktop app where model files sit in the
  app directory owned by the running user
- A researcher using Python (`llama-cpp-python`, `ctransformers`) to load a
  model file directly — no service, no privilege boundary
- Edge/IoT deployments where a single user owns all application files

In all of these cases, a local attacker has direct write access to the model
artifacts. Our system aims to detects tampering in this exact scenario.

### Our deployment configuration
We configure Ollama with `OLLAMA_MODELS=~/models/` so model files are stored
in a user-owned directory. This is intentional — it matches the common
real-world deployment pattern and keeps the adversary model internally
consistent and fully demonstrable.

---

## 3. Attacks & Defenses

---

### A1 — Model File Replacement

**Layer:** Disk (model artifact)

**Attack description:**
The attacker replaces the legitimate model file with a different one at the
same path. The substitute model may be a backdoored version that produces
biased outputs, leaks information, or behaves differently on specific inputs.

**Concrete example:**
```
Legitimate model
~/models/tinyllama.gguf  (SHA-256: abc123...)
Attacker replaces it
cp ~/evil_models/tinyllama-backdoored.gguf ~/models/tinyllama.gguf
The model server loads the backdoored file at next startup
No visible indication to the user that anything changed
```

**Why this is dangerous:**
The model produces different outputs than the one the administrator authorized.
The behavior change may be subtle — slightly altered responses on specific
topics — making it hard to detect through output inspection alone.

**Defense mechanism:**
At baseline initialization (run by root), compute SHA-256 of the legitimate
model file and store it in `/var/lib/llm_attest/baseline.json`.

Before each inference session, recompute the SHA-256 of the model file and
compare against the stored baseline. Any difference — even a single bit —
produces a completely different hash, making the tamper detectable.

```
Baseline:  {"model": {"sha256": "abc123..."}}
At verify:  hash(~/models/tinyllama.gguf) → "xyz999..."  ← MISMATCH → ALERT
```

**Why SHA-256 is sufficient here:**
SHA-256 is a cryptographic hash function. Finding two different files that
produce the same hash (a collision) requires approximately 2^128 operations —
computationally infeasible. The attacker cannot produce a backdoored model
that passes the hash check.

**Detection guarantee:**
Any modification to the model file, however small, is detected with
probability 1 - 2^(-256) ≈ 1.

---

### A2 — Tokenizer Tampering

**Layer:** Disk (tokenizer artifact)

**Attack description:**
The attacker modifies `tokenizer.json` to change how text is converted to
tokens before being fed to the model. By remapping specific tokens, the
attacker can alter the model's interpretation of inputs without touching the
model weights themselves.

**Concrete example:**
```json
// Original tokenizer.json
{"model": {"vocab": {"hello": 15043, "dangerous": 14831}}}

// Tampered tokenizer.json — "dangerous" now maps to token for "safe"
{"model": {"vocab": {"hello": 15043, "dangerous": 9962}}}

// Effect: any prompt containing "dangerous" is silently reinterpreted
// The model never "sees" the word dangerous — it sees "safe" instead
```

**Why this is dangerous:**
Tokenizer tampering is subtler than model replacement. The model weights are
unchanged and would pass a weight integrity check. The attack operates at the
input preprocessing layer, making it harder to attribute to tampering.
Safety filters that rely on detecting specific tokens can be bypassed entirely.

**Defense mechanism:**
Same hashing approach as A1, applied to `tokenizer.json`. The SHA-256 of the
legitimate tokenizer is stored in `baseline.json` at initialization and
recomputed at verification time.

```
Baseline:  {"tokenizer": {"sha256": "def456..."}}
At verify:  hash(tokenizer.json) → "uvw888..."  ← MISMATCH → ALERT
```

**Key distinction from A1:**
A1 and A2 are separate checks because they protect different artifacts that
could be tampered with independently. An attacker might leave the model file
intact (passing the A1 check) while only modifying the tokenizer (bypassing
safety via A2). Both checks must pass for the system to be considered clean.

---

### A3 — In-Memory Weight Tampering

**Layer:** Memory (runtime model state)

**Attack description:**
The attacker modifies model tensor values after the model has been loaded into
memory but before inference runs. This bypasses disk-level checks entirely —
the file on disk is unchanged and passes the A1 hash check, but the weights
actually used for inference are different.

**Concrete example:**
```python
# After model loads into memory, attacker process writes to shared memory
# or uses ptrace to modify the attention weights of layer 0

# Original weight tensor (layer 0, attention):
[0.021, -0.134, 0.087, ...]

# After in-memory tampering:
[0.021, -0.134, 99.999, ...]  ← single value changed

# The model file on disk is untouched — A1 check passes
# But inference behavior is now different
```

**Why this is dangerous:**
This attack is invisible to disk-level integrity checks. A system that only
checks file hashes at startup would miss this entirely. The attack surface
exists for the entire duration the model is loaded in memory.

**Defense mechanism:**
After the model loads into memory, compute a checksum over all model tensors
by serializing them to bytes and computing SHA-256. Store this in-memory
checksum. Immediately before each inference call, recompute the checksum and
compare. Any modification to any tensor value changes the checksum.

```
At load time:   checksum(all tensors serialized) → "ghi789..."  [stored]
Before inference: recompute → "ghi789..."  ← MATCH → proceed
recompute → "rst555..."  ← MISMATCH → block inference
```

**Important assumption:**
The verification logic runs inside the same process as the model. The adversary
model states the attacker cannot modify the verification system itself. If the
verifier were in a separate process, an attacker could potentially intercept
the IPC between them.

**Limitation acknowledged:**
This defense requires access to the model's internal tensor representation.
With Ollama (which serves the model as a black-box HTTP API), we cannot
directly access tensors. For A3 demonstration, we load the model directly
in Python using `llama-cpp-python`, which exposes the tensor interface.

---

### A4 — Runtime Parameter Manipulation

**Layer:** Runtime configuration (inference parameters)

**Attack description:**
The attacker modifies inference parameters — temperature, system prompt,
top_p, max_tokens — either by intercepting API calls or by directly calling
the model's generate function with unauthorized parameters, bypassing the
application's intended configuration.

**Concrete example:**
```python
# Authorized configuration (set by administrator)
ALLOWED_PARAMS = {
    "temperature": 0.7,
    "system_prompt": "You are a helpful assistant. Never discuss X.",
    "top_p": 0.9,
    "max_tokens": 512
}

# Attacker bypasses the wrapper and calls model directly:
model.generate(
    prompt="How do I do X?",
    temperature=2.0,          # max randomness — unpredictable outputs
    system_prompt="",         # removes safety instructions entirely
    max_tokens=99999          # removes output length limits
)
```

**Why this is dangerous:**
Parameter manipulation can neutralize safety instructions, remove content
filters, cause the model to produce outputs the administrator never authorized,
and consume unbounded resources. The model weights and tokenizer are completely
untouched — A1, A2, and A3 checks all pass.

**Defense mechanism:**
All inference requests MUST go through a parameter wrapper. The wrapper:
1. Enforces allowed ranges for numeric parameters (e.g. temperature must be
   between 0.1 and 1.0)
2. Enforces a fixed system prompt that cannot be overridden by callers
3. Raises an exception and blocks inference if any parameter is out of range
4. Logs all inference requests with their parameter hash for audit

Direct access to `model.generate()` is not exposed outside the wrapper.

```python
# BLOCKED — direct call raises exception
model.generate(prompt, temperature=2.0)

# ALLOWED — goes through wrapper, parameters validated
verified_inference(prompt, temperature=0.7)
```

**Audit trail:**
Every inference call produces a parameter hash:

```
hash('{"temperature":0.7,"system_prompt":"You are helpful...","top_p":0.9}')
→ "jkl012..."
```

This hash is logged alongside the inference timestamp, creating an auditable
record that the model was invoked with authorized parameters only.

---

### A5 — Runtime Execution State Tampering (Planned)

**Layer:** Execution (logits, KV cache, activations)

**Status:** Planned — not yet implemented.

**Attack description:**
The attacker manipulates the model's internal computational state during
inference — modifying logits (the raw output probabilities before sampling),
corrupting the KV cache (the stored attention state for context), or altering
intermediate activations between layers.

**Why this is harder:**
This attack happens inside the forward pass itself, after parameters are
validated and after weights are loaded. A1 through A4 defenses are all
bypassed. Detection requires monitoring the computational graph at runtime.

**Planned defense:**
Statistical monitoring of logit distributions — significant deviations from
expected entropy patterns indicate manipulation. KV cache checksumming between
generation steps.

---

## 4. Defense Coverage Summary

```
Attack Surface        A1    A2    A3    A4    A5
─────────────────────────────────────────────────
Model file (disk)     ✓
Tokenizer (disk)            ✓
Memory weights              ✓     ✓
Inference params                        ✓
Execution state                               ○
✓ = implemented    ○ = planned
```

## 5. What the system cannot defend against

Being explicit about limitations is part of a complete security analysis:

- **Root-level attacker** — an attacker with root can modify `baseline.json`,
  the verification scripts, and the model files. Our system assumes root is
  trusted.
- **Compromised verification system** — if the attacker can modify the verifier
  code itself, all guarantees are void. The verifier must be root-owned.
- **Supply chain attacks** — if the original model file was malicious before
  the baseline was created, we attest to a malicious baseline. Baseline
  initialization must happen from a trusted source.
- **A5 (in-execution tampering)** — not yet fully addressed.


















