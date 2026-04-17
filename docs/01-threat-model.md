# Threat Model

## Scope and purpose

This document defines the adversary model, assets, and attack surface that the LLMGuard attestation system is designed to defend against. It is the foundation for every design decision in the architecture and defense specification: each defense exists because this threat model identifies a specific attack, and each architectural choice exists because this threat model identifies a specific capability the attacker has.

This threat model targets a specific deployment pattern: a local large language model running on a machine where an unprivileged user has direct control over the model process. This includes a developer running llama.cpp on their own workstation, an application shipping an embedded LLM where the model runs under the application's own account, a researcher loading a model through Python libraries in their home directory, and any similar setup where the model's executable, weights, tokenizer, and configuration are all owned by an ordinary Linux user.

The threat model does not target cloud deployments with hardware attestation, model-serving APIs behind a trust boundary, or any setup where the model process runs under an account the attacker cannot become. Those deployments have different threat models, and their own existing defenses. LLMGuard's contribution is specifically for the local-deployment case.


