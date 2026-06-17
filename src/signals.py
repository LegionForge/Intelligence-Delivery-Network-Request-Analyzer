"""
signals.py — Python ctypes wrapper for signals_core.so
IDN Request Analyzer v0.1.0

Copyright (C) 2026 John Paul "Jp" Cruz
https://github.com/LegionForge/Intelligence-Delivery-Network-Request-Analyzer
Licensed under GNU AGPL v3 with Section 7 attribution terms.

Usage:
    from src.signals import analyze
    result = analyze("Refactor this Python module for horizontal scalability")
    print(result)
"""

import ctypes
import json
import os
import platform
from dataclasses import dataclass, asdict
from typing import Optional

# ── Locate compiled shared library ──────────────────────────────────────────

def _find_lib() -> Optional[str]:
    base = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base, "signals_core.so"),          # Linux / macOS
        os.path.join(base, "signals_core.dylib"),        # macOS explicit
        os.path.join(base, "signals_core.dll"),          # Windows
        os.path.join(base, "..", "build", "signals_core.so"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None

# ── ctypes struct mirrors ─────────────────────────────────────────────────────

class _IDNAnalyzerConfig(ctypes.Structure):
    _fields_ = [
        ("offline_mode",         ctypes.c_int),
        ("complexity_l0_max",    ctypes.c_float),
        ("complexity_l1_max",    ctypes.c_float),
        ("complexity_l2_max",    ctypes.c_float),
        ("confidence_threshold", ctypes.c_float),
    ]

class _IDNAnalysisResult(ctypes.Structure):
    _fields_ = [
        ("tier",                ctypes.c_int),
        ("confidence",          ctypes.c_float),
        ("complexity_score",    ctypes.c_float),
        ("layer",               ctypes.c_int),
        ("analyzer_version",    ctypes.c_char * 8),
        ("token_estimate",      ctypes.c_int),
        ("char_count",          ctypes.c_int),
        ("word_count",          ctypes.c_int),
        ("sentence_count",      ctypes.c_int),
        ("question_count",      ctypes.c_int),
        ("list_item_count",     ctypes.c_int),
        ("verb_count",          ctypes.c_int),
        ("primary_domain",      ctypes.c_int),
        ("domain_match_count",  ctypes.c_int),
        ("pii_flags",           ctypes.c_uint16),
        ("compliance_flags",    ctypes.c_uint8),
        ("data_egress_blocked", ctypes.c_int),
        ("offline_mode",        ctypes.c_int),
    ]

# ── Tier / Domain / PII mappings ──────────────────────────────────────────────

TIER_NAMES    = {0: "L0", 1: "L1", 2: "L2", 3: "L3"}
DOMAIN_NAMES  = {0: "coding", 1: "research", 2: "legal", 3: "health",
                 4: "finance", 5: "creative", 6: "agentic", 7: "general"}
PII_FLAG_NAMES = {
    0x0001: "email", 0x0002: "phone", 0x0004: "ssn", 0x0008: "credit_card",
    0x0010: "dob",   0x0020: "medical", 0x0040: "financial", 0x0080: "location",
    0x0100: "ip",    0x0200: "name"
}
COMPLIANCE_FLAG_NAMES = {
    0x01: "HIPAA", 0x02: "GDPR", 0x04: "PCI_DSS",
    0x08: "ATTORNEY_CLIENT", 0x10: "FERPA"
}

def _decode_flags(flags: int, mapping: dict) -> list:
    return [name for bit, name in mapping.items() if flags & bit]

# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    analyzer_version:     str
    layer:                int
    tier:                 str
    confidence:           float
    complexity_score:     float
    token_estimate:       int
    word_count:           int
    sentence_count:       int
    question_count:       int
    list_item_count:      int
    verb_count:           int
    primary_domain:       str
    domain_match_count:   int
    pii_classes:          list
    compliance_flags:     list
    data_egress_blocked:  bool
    offline_mode:         bool

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def __str__(self) -> str:
        return self.to_json()

# ── Pure-Python fallback (no compiled lib) ────────────────────────────────────

def _python_analyze(prompt: str, offline: bool = False) -> AnalysisResult:
    """
    Pure-Python Layer 1 heuristic fallback.
    Used when signals_core.so is not compiled yet.
    Matches C logic — same keywords, same scoring formula.
    """
    import re

    lower = prompt.lower()
    words = lower.split()
    token_est     = int(len(words) * 1.3)
    sentence_count = lower.count('.') + lower.count('?') + lower.count('!')
    question_count = lower.count('?')
    list_count     = lower.count('-') + lower.count('*')

    ACTION_VERBS = [
        "analyze","design","build","create","implement","refactor","debug",
        "evaluate","compare","summarize","explain","generate","write","review",
        "optimize","test","deploy","migrate","integrate","automate","calculate",
        "translate","convert","extract","classify","predict","recommend",
        "plan","schedule","monitor","alert","send","fetch","execute",
    ]
    verb_count = sum(1 for v in ACTION_VERBS if v in lower)

    DOMAIN_KW = {
        "coding":   [("refactor",0.9),("function",0.6),("class",0.6),("bug",0.8),
                     ("debug",0.9),("compile",1.0),("algorithm",1.0),("api",0.7),
                     ("database",0.8),("docker",0.9),("kubernetes",1.0),("git",0.7),
                     ("python",0.8),("javascript",0.8),("typescript",0.9),("rust",0.9),
                     ("inference",0.9),("embedding",0.9),("llm",0.8),("deploy",0.9)],
        "research": [("analyze",0.8),("literature",1.0),("hypothesis",1.0),("dataset",0.9),
                     ("correlation",1.0),("peer review",1.0),("methodology",1.0),("research",0.8)],
        "legal":    [("contract",1.0),("liability",1.0),("attorney",1.0),("litigation",1.0),
                     ("statute",1.0),("jurisdiction",1.0),("nda",1.0),("patent",0.9)],
        "health":   [("patient",1.0),("diagnosis",1.0),("medication",1.0),("prescription",1.0),
                     ("clinical",1.0),("blood pressure",1.0),("glucose",1.0),("ehr",1.0)],
        "finance":  [("portfolio",1.0),("revenue",0.9),("roi",1.0),("balance sheet",1.0),
                     ("ebitda",1.0),("cash flow",1.0),("valuation",1.0),("earnings",0.9)],
        "creative": [("poem",1.0),("screenplay",1.0),("fiction",1.0),("narrative",0.9),
                     ("rhyme",1.0),("copywriting",1.0),("story",0.8),("essay",0.8)],
        "agentic":  [("automate",1.0),("workflow",1.0),("webhook",1.0),("cron",1.0),
                     ("agent",0.9),("autonomous",1.0),("pipeline",0.9),("schedule",0.9)],
        "general":  [("what is",0.3),("who is",0.3),("explain",0.5),("define",0.4)],
    }
    DOMAIN_WEIGHTS = {"legal":1.2,"health":1.2,"coding":1.0,"research":1.0,
                      "finance":1.0,"agentic":1.0,"creative":0.9,"general":0.5}

    domain_scores = {}
    for domain, kws in DOMAIN_KW.items():
        score = sum(w for kw, w in kws if kw in lower)
        domain_scores[domain] = score + (0.1 if domain == "general" else 0)

    primary_domain = max(domain_scores, key=domain_scores.get)
    domain_match_count = sum(1 for s in domain_scores.values() if s > 0.5)
    domain_weight = DOMAIN_WEIGHTS.get(primary_domain, 0.5)

    def clamp(v, lo, hi): return max(lo, min(hi, v))
    complexity = clamp(
        (token_est/4000)*0.25 + (verb_count/20)*0.20 + (question_count/10)*0.10 +
        (list_count/20)*0.10 + (sentence_count/40)*0.15 + (domain_weight/1.2)*0.20,
        0.0, 1.0
    )

    # PII detection
    pii = []
    if re.search(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', lower): pii.append("email")
    if any(k in lower for k in ["ssn","social security","tax id"]) and re.search(r'\d{4,}', lower): pii.append("ssn")
    if any(k in lower for k in ["credit card","card number","cvv","cvc","visa","mastercard","amex"]) and re.search(r'\d{4,}', lower): pii.append("credit_card")
    if any(k in lower for k in ["patient","diagnosis","prescription","medication","blood pressure","glucose","lab result"]): pii.append("medical")
    if any(k in lower for k in ["date of birth","dob","born on"]): pii.append("dob")
    if any(k in lower for k in ["account number","routing number","iban","swift code"]) and re.search(r'\d{6,}', lower): pii.append("financial")

    # Compliance
    compliance = []
    if any(k in lower for k in ["patient","phi","hipaa","ehr","emr","medical record"]) or "medical" in pii:
        compliance.append("HIPAA")
    if any(k in lower for k in ["gdpr","personal data","data subject","right to erasure"]):
        compliance.append("GDPR")
    if any(k in lower for k in ["pci","pci dss","cardholder","payment card"]) or "credit_card" in pii:
        compliance.append("PCI_DSS")
    if any(k in lower for k in ["attorney-client","privileged","work product"]):
        compliance.append("ATTORNEY_CLIENT")

    egress_blocked = len(compliance) > 0

    # Confidence
    conf = 1.0
    if 400 <= token_est <= 600:              conf -= 0.15
    if domain_match_count > 1:               conf -= 0.20 * (domain_match_count - 1)
    if pii:                                  conf -= 0.30
    if 0.40 <= complexity <= 0.55:           conf -= 0.20
    if question_count > 3:                   conf -= 0.15
    if list_count > 5:                       conf -= 0.10
    conf = clamp(conf, 0.0, 1.0)

    # Tier
    if offline or compliance:                tier = "L0"
    elif primary_domain == "legal" and complexity > 0.3: tier = "L3"
    elif complexity > 0.72 or token_est > 4000:          tier = "L3"
    elif complexity > 0.45 or token_est > 500:           tier = "L2"
    elif complexity > 0.25 or token_est > 200:           tier = "L1"
    else:                                                 tier = "L0"

    return AnalysisResult(
        analyzer_version="0.1.0", layer=1,
        tier=tier, confidence=round(conf,4),
        complexity_score=round(complexity,4),
        token_estimate=token_est, word_count=len(words),
        sentence_count=sentence_count, question_count=question_count,
        list_item_count=list_count, verb_count=verb_count,
        primary_domain=primary_domain, domain_match_count=domain_match_count,
        pii_classes=pii, compliance_flags=compliance,
        data_egress_blocked=egress_blocked, offline_mode=offline
    )

# ── Main entry point ──────────────────────────────────────────────────────────

def analyze(prompt: str, offline: bool = False) -> AnalysisResult:
    """
    Analyze a prompt and return routing metadata.

    Falls back to pure-Python implementation if signals_core.so
    is not compiled. Outputs are identical either way.

    Args:
        prompt:  The user prompt string to analyze.
        offline: If True, forces tier to L0 regardless of complexity.

    Returns:
        AnalysisResult dataclass with all routing signals.
    """
    lib_path = _find_lib()
    if lib_path:
        try:
            lib = ctypes.CDLL(lib_path)
            lib.idn_analyze.restype  = _IDNAnalysisResult
            lib.idn_analyze.argtypes = [ctypes.c_char_p,
                                        ctypes.POINTER(_IDNAnalyzerConfig)]
            cfg = _IDNAnalyzerConfig(offline_mode=int(offline),
                                     complexity_l0_max=0.25,
                                     complexity_l1_max=0.45,
                                     complexity_l2_max=0.72,
                                     confidence_threshold=0.85)
            raw = lib.idn_analyze(prompt.encode("utf-8"), ctypes.byref(cfg))
            return AnalysisResult(
                analyzer_version=raw.analyzer_version.decode(),
                layer=raw.layer,
                tier=TIER_NAMES.get(raw.tier, "L0"),
                confidence=round(raw.confidence, 4),
                complexity_score=round(raw.complexity_score, 4),
                token_estimate=raw.token_estimate,
                word_count=raw.word_count,
                sentence_count=raw.sentence_count,
                question_count=raw.question_count,
                list_item_count=raw.list_item_count,
                verb_count=raw.verb_count,
                primary_domain=DOMAIN_NAMES.get(raw.primary_domain, "general"),
                domain_match_count=raw.domain_match_count,
                pii_classes=_decode_flags(raw.pii_flags, PII_FLAG_NAMES),
                compliance_flags=_decode_flags(raw.compliance_flags, COMPLIANCE_FLAG_NAMES),
                data_egress_blocked=bool(raw.data_egress_blocked),
                offline_mode=bool(raw.offline_mode),
            )
        except Exception:
            pass
    return _python_analyze(prompt, offline=offline)
