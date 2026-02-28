# idn-analyzer — Vision & Design Philosophy
*Last updated: Feb 28, 2026*

---

## The Problem

Every LLM application today treats routing as an afterthought — if it's considered at
all. The default behavior is to send every request, regardless of complexity or
sensitivity, to the same large frontier model. This creates three compounding problems:

**1. Cost waste at scale.**
Sending "what's the capital of France?" to GPT-4o costs roughly 100x more than it
needs to. At any meaningful volume, this becomes significant. The vast majority of LLM
requests in production — autocomplete, classification, extraction, simple Q&A — do not
require frontier model intelligence.

**2. Latency where it doesn't need to exist.**
A frontier model call takes 1–5 seconds. Most L0/L1 tasks can be answered in
milliseconds on-device or at the edge. Users experience unnecessary latency on every
simple request because the application never asked "how hard is this, really?"

**3. Privacy exposure by default.**
Every request sent to a cloud model is a potential data exposure event. PHI, PII, legal
privilege, trade secrets — all of it gets sent to third-party infrastructure by default
because the application has no mechanism to detect sensitive content before egress.

## The Root Cause

These three problems share a single root cause: **LLM applications don't know what
their requests need before they route them.** There is no standard, lightweight,
cross-platform mechanism to analyze a prompt and produce actionable routing metadata.
Existing solutions are either gateway-specific, cloud-dependent, or require an LLM call
to decide where to send an LLM call — which is absurd.

---

## The Solution: A Universal Prompt Profiler

`idn-analyzer` is a standalone, open-source prompt analysis library that answers one
question before every LLM call:

> **"What does this request actually need?"**

It produces structured, standardized routing metadata that any LLM gateway, router, or
application can consume to make smarter decisions about model selection, tier routing,
privacy enforcement, and cost optimization.

It is:
- **Offline-capable** — the most important analysis (PII detection, compliance flags,
  basic complexity) runs entirely on-device with zero network dependency
- **Cross-platform** — the same logic runs on an iPhone, a Raspberry Pi, an ESP32,
  a browser, a Cloudflare Worker, and a data center
- **Dependency-free at its core** — Layer 1 is pure code in any target language;
  no models, no pip installs, no API keys required to get started
- **An open standard** — the output schema is designed to be a shared contract, not
  a proprietary format, so the ecosystem can build on it

---

## Design Philosophy

### 1. Never require a network call to decide whether to make a network call
This is the foundational constraint. Any analysis that requires calling a remote
service to decide routing is self-defeating — it adds latency, cost, and a failure
mode before the actual request even starts. All analysis that can be done locally,
must be done locally.

### 2. Fastest and cheapest path first
Analysis is itself tiered. Heuristics run first (<2ms). ML classifier runs only if
heuristics aren't confident enough (<20ms). Server-side semantic analysis runs only
for genuinely ambiguous or compliance-critical cases (<80ms). The median request
resolves in under 2ms with zero model inference.

### 3. Privacy is a hard constraint, not a preference
PII and compliance detection are not optional features — they are first-class outputs
of the analyzer. If a request contains HIPAA-covered PHI, that is not a routing
suggestion; it is a hard constraint. The analyzer must detect this before any cloud
egress decision is made, and it must do so on-device.

### 4. The output schema is a contract
The JSON output of `idn-analyzer` is designed to be stable, versioned, and
consumable by any downstream system — IDN's router, LiteLLM, Portkey, a custom
gateway, or application code. Breaking changes to the schema are major version bumps.
Fields are never removed without a deprecation cycle.

### 5. Platform capability is a first-class concept
Not every platform can run the same analysis. An ESP32 cannot run a DistilBERT model.
A browser has memory constraints. `idn-analyzer` is honest about this — it exposes
which layers ran, what hardware was used, and what confidence level was achieved. A
consumer of the output always knows how thorough the analysis was.

### 6. The library must be independently useful
`idn-analyzer` has no runtime dependency on IDN. It does not know or care what router
consumes its output. It is a general-purpose prompt analysis tool that happens to be
the foundation of IDN — not a component that only makes sense inside IDN. This keeps
the design honest and maximizes adoption.

---

## What idn-analyzer Is Not

**It is not a router.** It produces routing metadata but makes no network calls and
does not select providers, manage API keys, or execute requests. Routing is IDN's job.

**It is not a guardrail system.** It detects PII and compliance signals but does not
block, filter, or rewrite content. Content moderation is a separate concern.

**It is not a prompt optimizer.** It analyzes prompts as given and does not rewrite,
compress, or improve them.

**It is not cloud-dependent.** It will never require a cloud service for its core
functionality. Optional Layer 3 server-side profiling is an enhancement, not a
requirement.

---

## The Platform Spectrum

One of the most important design decisions in `idn-analyzer` is the commitment to
running on the full hardware spectrum — from frontier cloud infrastructure down to
microcontrollers with 256KB of RAM.

This matters because:
- **IoT and edge devices are increasingly the origin point of LLM requests** — smart
  home devices, industrial sensors, medical monitors, wearables. These devices need
  local routing decisions before deciding whether to call cloud services.
- **The privacy argument is strongest at the device edge** — the most sensitive data
  (health metrics, location, biometrics) originates on-device. Analyzing it for PII
  before it ever leaves the device is the strongest possible privacy guarantee.
- **A universal library creates a universal standard** — if the same analysis runs
  on an ESP32 and a data center, the output schema becomes a genuine cross-ecosystem
  contract.

The capability model is honest about what each class of device can do:

```
Class A: Mobile / Desktop / SBC (Raspberry Pi, Jetson)
  → Layer 1 heuristics + Layer 2 ONNX ML model
  → Full routing metadata

Class B: Browser / Edge Workers (Cloudflare, Deno, Fastly)
  → Layer 1 + Layer 2 via WebAssembly
  → Full routing metadata

Class C: Capable MCUs (ESP32-S3, Arduino Nano BLE, nRF52840)
  → Layer 1 + tiny TFLite Micro model (~100–500KB)
  → Reduced routing metadata (no tool plan, no async decomp)

Class D: Minimal MCUs (ESP32, RP2040, Arduino Uno R4)
  → Layer 1 heuristics only (pure C, ~2KB RAM)
  → Basic signal: {tier_suggestion, domain, pii_flag, complexity_bucket}
```

The Layer 1 C implementation is the universal baseline — it is the one piece of code
that must run on every platform, including bare-metal hardware with no OS.

---

## Relationship to the Intelligence Delivery Network

`idn-analyzer` was created as the analytical foundation of the
[Intelligence Delivery Network (IDN)](https://github.com/jp-cruz/Intelligence-Delivery-Network),
a CDN-inspired system for routing LLM workloads to the optimal compute tier.

IDN's core thesis is that LLM inference should work like content delivery: requests
should be routed to the closest, cheapest, fastest resource capable of handling them —
not blindly sent to the most powerful (and expensive) model available.

`idn-analyzer` is the piece that makes this possible. It is the "traffic classifier"
that sits at the entry point and says: *this request needs L0, this one needs L2, this
one must stay on-device because it contains PHI.*

However, `idn-analyzer` was intentionally designed to be separable from IDN from day
one — because the analysis problem is universal, and a tightly coupled library would
limit its usefulness and adoption. Any LLM application can benefit from knowing what
its prompts actually need, whether or not they use IDN for routing.

---

## Success Metrics

`idn-analyzer` will be considered successful when:

1. **Accuracy**: Layer 1 correctly classifies tier for >85% of common prompts;
   Layer 1+2 achieves >95%
2. **Latency**: Layer 1 completes in <2ms on all Class A/B/C/D platforms;
   Layer 2 in <20ms on Class A/B
3. **Coverage**: PII/compliance detection has <1% false negative rate on standard
   PHI/PII test sets
4. **Portability**: Layer 1 runs unmodified on Python, JavaScript, C, Swift, Kotlin
   from a single source-of-truth keyword/pattern JSON
5. **Adoption**: consumed by at least one production LLM gateway outside of IDN
6. **Standard**: output schema adopted or referenced by at least one other
   open-source routing project

---

## Attribution

`idn-analyzer` was created by John Paul Cruz as part of the Intelligence Delivery
Network project. Research and architecture developed with Perplexity AI.

Licensed under GNU AGPL v3 with Section 7 attribution terms.
See LICENSE for full terms.

> *"Know what your prompt needs before you serve it."*
