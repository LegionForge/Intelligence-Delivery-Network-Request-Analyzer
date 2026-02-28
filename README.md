# idn-analyzer

> *Universal LLM Prompt Profiler — lightweight, cross-platform, offline-capable.*

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Status: Pre-Alpha](https://img.shields.io/badge/Status-Pre--Alpha-orange.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)]()
[![Part of IDN](https://img.shields.io/badge/Part%20of-Intelligence%20Delivery%20Network-purple.svg)](https://github.com/jp-cruz/Intelligence-Delivery-Network)

---

## What Is This?

`idn-analyzer` is a lightweight, cross-platform prompt profiler for LLM applications.
It analyzes any natural language prompt and returns structured metadata about its
complexity, domain, PII risk, routing tier, and execution requirements — before any
LLM call is made.

```
prompt → [idn-analyzer] → routing metadata (JSON)
```

It is the analytical foundation of the
[Intelligence Delivery Network (IDN)](https://github.com/jp-cruz/Intelligence-Delivery-Network)
— a CDN-style routing system for LLM workloads — but is designed to be **fully
independent** and useful in any LLM application or gateway.

---

## Why Does This Exist?

Every LLM application today routes all requests to the same model regardless of what
the request actually needs. A question like "what time is it in Tokyo?" gets sent to
the same frontier model as "design a fault-tolerant distributed database." This wastes
money, adds unnecessary latency, and exposes private data to cloud services when it
doesn't need to be.

`idn-analyzer` solves the first and most important part of that problem: **knowing what
a request actually needs before you serve it.**

```python
from idn_analyzer import analyze

result = analyze("Refactor this Python module for horizontal scalability")
# {
#   "complexity_score": 0.74,
#   "domain_tags": ["coding"],
#   "reasoning_hops": 2,
#   "pii_risk": "none",
#   "recommended_tier": "L2",
#   "confidence": 0.91
# }

result = analyze("My patient John DOB 01/01/1980 has a blood pressure of 140/90")
# {
#   "pii_risk": "high",
#   "pii_classes": ["health", "name", "dob"],
#   "compliance_flags": ["HIPAA"],
#   "data_egress_permitted": false,
#   "recommended_tier": "L0",
#   "forced": true,
#   "confidence": 0.99
# }
```

---

## Key Features

- **Zero dependencies for Layer 1** — pure Python/JS/C heuristics, no model required
- **Offline-capable** — never requires a network call to analyze a prompt
- **Cross-platform** — runs on mobile, desktop, browser, server, Raspberry Pi, ESP32
- **PII & compliance aware** — detects PHI, PII, GDPR/HIPAA signals and flags egress
- **Tiered accuracy** — fast heuristics (Layer 1) + optional ONNX ML model (Layer 2)
- **Configurable** — routing thresholds, domain taxonomy, and compliance rules are
  plain JSON files you can override
- **Gateway-agnostic** — works with LiteLLM, Portkey, OpenRouter, or any custom stack
- **Open standard** — the output schema is designed to be a shared contract any router
  can consume

---

## Routing Tiers

`idn-analyzer` maps requests to four tiers matching the IDN model:

| Tier | Location | Use Case |
|------|----------|----------|
| **L0** | On-device | Offline, privacy-forced, instant, PII-containing |
| **L1** | Edge | Fast extraction, classification, simple RAG |
| **L2** | Regional cloud | Code generation, summarization, tool agents |
| **L3** | Global frontier | Deep reasoning, research, multi-agent planning |

---

## Platform Support

| Platform | Layer 1 Heuristics | Layer 2 ML Model | Runtime |
|----------|--------------------|-----------------|---------|
| Python (server / desktop / RPi) | ✅ | ✅ ONNX Runtime | `pip install idn-analyzer` |
| JavaScript (browser / Node.js) | ✅ | ✅ ONNX.js + WASM | `npm install idn-analyzer` |
| Swift (iOS / macOS) | ✅ | ✅ Core ML | Swift Package |
| Kotlin (Android) | ✅ | ✅ LiteRT | Maven / Gradle |
| C / C++ (ESP32, Arduino, RP2040) | ✅ | ⚠️ TFLite Micro (S3 only) | Header-only lib |
| WebAssembly (edge workers) | ✅ | ✅ WASM | Cloudflare / Deno / Fastly |
| Embedded Linux (OpenWRT, gateways) | ✅ | ✅ ONNX Runtime ARM | Binary |

---

## Output Schema

```json
{
  "analyzer_version": "0.1.0",
  "layers_run": [1],
  "analysis_latency_ms": 1.4,

  "token_estimate": 312,
  "complexity_score": 0.74,
  "reasoning_hops": 2,
  "task_multiplicity": 1,
  "output_volume_estimate": "medium",

  "domain_tags": ["coding"],
  "latency_sensitivity": "medium",
  "quality_sensitivity": "high",

  "pii_risk": "none",
  "pii_classes": [],
  "compliance_flags": [],
  "data_egress_permitted": true,

  "recommended_tier": "L2",
  "candidate_tiers": ["L2", "L3"],
  "confidence": 0.91
}
```

Full schema specification: [SCHEMA.md](SCHEMA.md)

---

## Quick Start

```bash
pip install idn-analyzer
```

```python
from idn_analyzer import analyze

# Simple usage
result = analyze("Summarize this document and extract action items")
print(result.recommended_tier)   # "L1"
print(result.complexity_score)   # 0.31
print(result.domain_tags)        # ["general"]

# With context and preferences
result = analyze(
    prompt="Design a distributed event streaming system",
    context="We are building a fintech platform handling 1M events/sec",
    preferences={"quality_preference": "thorough", "max_latency_ms": 5000}
)
print(result.recommended_tier)   # "L3"
print(result.reasoning_hops)     # 4

# PII / compliance detection
result = analyze("Patient: Jane Doe, SSN 123-45-6789, prescribed 20mg Lisinopril")
print(result.compliance_flags)        # ["HIPAA"]
print(result.data_egress_permitted)   # False
print(result.recommended_tier)        # "L0"
```

### CLI

```bash
# Analyze a prompt
idn-analyzer analyze --prompt "What is the capital of France?"
# → {"recommended_tier": "L0", "complexity_score": 0.04, "confidence": 0.97}

# Analyze with full output
idn-analyzer analyze --prompt "Refactor this Python module" --full

# Analyze from stdin
echo "Write a unit test for this function" | idn-analyzer analyze

# Run against a file of prompts (batch mode)
idn-analyzer batch --input prompts.txt --output results.json
```

---

## Architecture

`idn-analyzer` uses a tiered analysis model — fastest and cheapest first:

```
Layer 1: Heuristics     < 2ms    pure code, zero deps, runs everywhere
    ↓ confidence < 0.85?
Layer 2: ML Classifier  < 20ms   ONNX/WASM, on-device NPU or CPU
    ↓ confidence < 0.85?
Layer 3: Semantic       < 80ms   optional, server-side, for hard cases
```

Full architecture details: [ARCHITECTURE.md](ARCHITECTURE.md)

---

## Configuration

Override any default via JSON config:

```json
// .idn-analyzer/config.json
{
  "routing_rules": {
    "L0_complexity_max": 0.25,
    "L1_complexity_max": 0.45,
    "L2_complexity_max": 0.72
  },
  "compliance": {
    "HIPAA": true,
    "GDPR": true,
    "force_L0_on_compliance": true
  },
  "layer2_model_path": "./models/idn_classifier_int4.onnx"
}
```

---

## Roadmap

### v0.1 — Layer 1 MVP
- [ ] Python heuristics engine
- [ ] Domain taxonomy (8 domains)
- [ ] PII regex patterns (6 classes)
- [ ] Compliance keyword triggers (HIPAA, GDPR, PCI-DSS)
- [ ] CLI: `idn-analyzer analyze`
- [ ] 20 golden test examples
- [ ] PyPI publish

### v0.2 — Cross-Platform Layer 1
- [ ] JavaScript port (browser + Node.js)
- [ ] C port (ESP32, Arduino, RP2040)
- [ ] WASM build (Cloudflare Workers, Deno)
- [ ] npm publish

### v0.3 — Layer 2 ML Classifier
- [ ] DistilBERT multi-head training
- [ ] ONNX INT8 export
- [ ] INT4 mobile quantization
- [ ] LiteRT (Android) + Core ML (iOS) wrappers
- [ ] TFLite Micro build for ESP32-S3

### v1.0 — Production Ready
- [ ] Layer 3 semantic profiler (server-side)
- [ ] Swift package + Kotlin package
- [ ] Full benchmark suite
- [ ] Gateway integration examples (LiteLLM, Portkey)

---

## Contributing

Easiest ways to contribute:
- Add or improve domain keyword lists (`policy/domain_keywords.json`)
- Add PII patterns for non-English / non-US formats
- Port heuristics to a new language (Swift, Kotlin, Rust, Go)
- Add golden test examples with labeled routing
- Build a gateway integration example

---

## Relationship to IDN

`idn-analyzer` is the analytical core of the
[Intelligence Delivery Network](https://github.com/jp-cruz/Intelligence-Delivery-Network).
IDN uses this library as its routing signal source. They are separate projects with
separate versioning — `idn-analyzer` has no dependency on IDN and can be used
independently in any LLM stack.

---

## License

GNU Affero General Public License v3 with Section 7 attribution terms.
See [LICENSE](LICENSE) for full terms.

Attribution required in all derivative works:

> *"Based on idn-analyzer by John Paul Cruz —
> https://github.com/jp-cruz/idn-analyzer"*

---

*Part of the [Intelligence Delivery Network](https://github.com/jp-cruz/Intelligence-Delivery-Network) project.*
*"Know what your prompt needs before you serve it."*
