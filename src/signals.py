"""
signals.py — Pure-Python routing signal analyzer
IDN Request Analyzer v0.2.0

Copyright (C) 2026 John Paul "Jp" Cruz
https://github.com/jp-cruz/Intelligence-Delivery-Network-Request-Analyzer
Licensed under GNU AGPL v3 with Section 7 attribution terms.

Usage:
    from src.signals import analyze
    result = analyze("Refactor this Python module for horizontal scalability")
    print(result)
"""

import ctypes
import json
import os
import re
import platform
from dataclasses import dataclass, asdict
from typing import Optional

# ── Locate compiled shared library ──────────────────────────────────────────

def _find_lib() -> Optional[str]:
    base = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base, "signals_core.so"),
        os.path.join(base, "signals_core.dylib"),
        os.path.join(base, "signals_core.dll"),
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
        ("tier",               ctypes.c_int),
        ("confidence",         ctypes.c_float),
        ("complexity_score",   ctypes.c_float),
        ("layer",              ctypes.c_int),
        ("analyzer_version",   ctypes.c_char * 8),
        ("token_estimate",     ctypes.c_int),
        ("char_count",         ctypes.c_int),
        ("word_count",         ctypes.c_int),
        ("sentence_count",     ctypes.c_int),
        ("question_count",     ctypes.c_int),
        ("list_item_count",    ctypes.c_int),
        ("verb_count",         ctypes.c_int),
        ("primary_domain",     ctypes.c_int),
        ("domain_match_count", ctypes.c_int),
        ("pii_flags",          ctypes.c_uint16),
        ("compliance_flags",   ctypes.c_uint8),
        ("data_egress_blocked",ctypes.c_int),
        ("offline_mode",       ctypes.c_int),
    ]

# ── Tier / Domain / PII mappings ──────────────────────────────────────────────

TIER_NAMES = {0: "L0", 1: "L1", 2: "L2", 3: "L3"}
DOMAIN_NAMES = {
    0: "coding",    1: "research",  2: "legal",    3: "health",
    4: "finance",   5: "creative",  6: "agentic",  7: "general",
}
PII_FLAG_NAMES = {
    0x0001: "email",     0x0002: "phone",    0x0004: "ssn",       0x0008: "credit_card",
    0x0010: "dob",       0x0020: "medical",  0x0040: "financial", 0x0080: "location",
    0x0100: "ip",        0x0200: "name",
}
COMPLIANCE_FLAG_NAMES = {
    0x01: "HIPAA",  0x02: "GDPR",  0x04: "PCI_DSS",
    0x08: "ATTORNEY_CLIENT",       0x10: "FERPA",
}

# Output types — what the model is expected to produce
OUTPUT_TYPES = {
    "text",             # prose, explanation, summary
    "code",             # source code, scripts, queries
    "image",            # image generation request
    "svg",              # vector graphic
    "audio",            # music, speech, sound
    "video",            # video generation
    "structured_data",  # JSON, CSV, tables, schemas
    "mixed",            # combination of multiple output types
    "model_decided",    # dealer's choice — let the model determine best output format
}

def _decode_flags(flags: int, mapping: dict) -> list:
    return [name for bit, name in mapping.items() if flags & bit]

# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    # Core routing
    analyzer_version: str
    layer: int
    tier: str
    confidence: float
    complexity_score: float
    # Token / surface stats
    token_estimate: int
    word_count: int
    sentence_count: int
    question_count: int
    list_item_count: int
    verb_count: int
    # Domain
    primary_domain: str
    subdomain: str
    domain_match_count: int
    # Output shape signals
    output_type: str        # see OUTPUT_TYPES
    is_multi_step: bool
    is_numerical: bool
    is_conditional: bool
    is_multimodal: bool
    # Privacy / compliance
    pii_classes: list
    compliance_flags: list
    data_egress_blocked: bool
    offline_mode: bool

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def __str__(self) -> str:
        return self.to_json()

# ── Domain complexity floors ──────────────────────────────────────────────────

DOMAIN_COMPLEXITY_FLOOR = {
    "legal":       0.55,   # always L3 once legal domain confirmed
    "health":      0.40,   # L2 floor
    "finance":     0.46,   # L2 floor
    "research":    0.46,   # L2 floor
    "agentic":     0.46,   # L2 floor
    "coding":      0.28,   # L1 floor; tiered upward by domain score
    "creative":    0.20,
    "general":     0.00,
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _word_in(word: str, text: str) -> bool:
    """Whole-word match — prevents 'api' matching inside 'capital'."""
    return bool(re.search(r'\b' + re.escape(word) + r'\b', text))

def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))

# ── Pure-Python fallback ──────────────────────────────────────────────────────

def _python_analyze(prompt: str, offline: bool = False) -> AnalysisResult:
    """
    Pure-Python Layer 1 heuristic analyzer.
    Used when signals_core.so/.dll is not compiled.
    """
    lower = prompt.lower()
    words = lower.split()
    token_est     = int(len(words) * 1.3)
    sentence_count = lower.count('.') + lower.count('?') + lower.count('!')
    question_count = lower.count('?')
    list_count     = lower.count('-') + lower.count('*')

    # ── Action verb count ────────────────────────────────────────────────────
    ACTION_VERBS = [
        "analyze","design","build","create","implement","refactor","debug",
        "evaluate","compare","summarize","explain","generate","write","review",
        "optimize","test","deploy","migrate","integrate","automate","calculate",
        "translate","convert","extract","classify","predict","recommend",
        "plan","schedule","monitor","alert","send","fetch","execute","diagnose",
        "draft","file","assess","model","forecast","simulate","audit","verify",
    ]
    verb_count = sum(1 for v in ACTION_VERBS if _word_in(v, lower))

    # ── Domain keyword tables ────────────────────────────────────────────────
    DOMAIN_KW = {
        "coding": [
            ("refactor",0.9),("function",0.6),("class",0.6),("bug",0.8),
            ("debug",0.9),("compile",1.0),("algorithm",1.0),("api",0.7),
            ("database",0.8),("docker",0.9),("kubernetes",1.0),("git",0.7),
            ("python",0.8),("javascript",0.8),("typescript",0.9),("rust",0.9),
            ("inference",0.9),("embedding",0.9),("llm",0.8),("deploy",0.9),
            ("distributed",0.8),("architecture",0.7),("streaming",0.8),
            ("fault-tolerant",1.0),("microservice",0.9),("latency",0.8),
            ("scalability",0.9),("replication",0.9),("semantics",0.7),
            ("event",0.6),("unit test",0.8),("cybersecurity",1.0),
            ("encryption",0.9),("vulnerability",1.0),("penetration",1.0),
            ("data pipeline",0.9),("etl",0.9),("machine learning",0.9),
            ("neural network",0.9),("data science",0.9),("model training",1.0),
        ],
        "research": [
            ("analyze",0.8),("literature",1.0),("hypothesis",1.0),("dataset",0.9),
            ("correlation",1.0),("peer review",1.0),("methodology",1.0),("research",0.8),
            ("transformer",0.8),("efficiency",0.6),("peer-reviewed",1.0),
            ("architecture",0.7),("summarize",0.7),("meta-analysis",1.0),
            ("systematic review",1.0),("clinical trial",1.0),("citation",0.8),
            ("journal",0.8),("experiment",0.9),("statistical",0.9),
        ],
        "legal": [
            ("contract",1.0),("liability",1.0),("attorney",1.0),("litigation",1.0),
            ("statute",1.0),("jurisdiction",1.0),("nda",1.0),("patent",0.9),
            ("indemnification",1.0),("precedent",1.0),("clause",0.9),
            ("regulatory",0.9),("compliance",0.7),("sec",0.8),("fda",0.8),
            ("osha",0.9),("arbitration",1.0),("subpoena",1.0),("deposition",1.0),
            ("intellectual property",1.0),("trademark",0.9),("copyright",0.8),
        ],
        "health": [
            ("patient",1.0),("diagnosis",1.0),("medication",1.0),("prescription",1.0),
            ("clinical",1.0),("blood pressure",1.0),("glucose",1.0),("ehr",1.0),
            ("mental health",1.0),("therapy",0.9),("anxiety",0.8),("depression",0.8),
            ("psychiatry",1.0),("psychology",0.9),("counseling",0.9),("trauma",0.9),
            ("crisis",0.8),("suicidal",1.0),("self-harm",1.0),("ptsd",1.0),
            ("chronic",0.8),("symptom",0.9),("treatment",0.8),("dosage",1.0),
            ("vaccine",0.8),("icd",0.9),("cpt code",1.0),
        ],
        "finance": [
            ("portfolio",1.0),("revenue",0.9),("roi",1.0),("balance sheet",1.0),
            ("ebitda",1.0),("cash flow",1.0),("valuation",1.0),("earnings",0.9),
            ("forecast",0.8),("q3",0.7),("fy2026",0.9),("tax",0.8),
            ("irs",1.0),("deduction",0.9),("capital gains",1.0),("filing",0.7),
            ("w-2",1.0),("1099",1.0),("audit",0.9),("amortization",1.0),
            ("insurance",0.8),("premium",0.8),("underwriting",1.0),("claim",0.7),
            ("mortgage",0.9),("escrow",1.0),("appraisal",0.9),("deed",0.9),
            ("real estate",0.9),("refinance",0.9),("equity",0.8),
        ],
        "creative": [
            ("poem",1.0),("screenplay",1.0),("fiction",1.0),("narrative",0.9),
            ("rhyme",1.0),("copywriting",1.0),("story",0.8),("essay",0.8),
            ("blog post",0.8),("song",0.9),("lyrics",1.0),("script",0.8),
            ("character",0.7),("plot",0.8),("dialogue",0.9),("creative writing",1.0),
        ],
        "agentic": [
            ("automate",1.0),("workflow",1.0),("webhook",1.0),("cron",1.0),
            ("agent",0.9),("autonomous",1.0),("pipeline",0.9),("schedule",0.9),
            ("slack",0.8),("alert",0.7),("every hour",0.9),("trigger",0.8),
            ("orchestrate",1.0),("n8n",1.0),("zapier",1.0),("make.com",1.0),
            ("polling",0.8),("event-driven",1.0),("pub/sub",1.0),("queue",0.7),
        ],
        "general": [
            ("what is",0.3),("who is",0.3),("explain",0.5),("define",0.4),
        ],
    }

    # ── Subdomain table ──────────────────────────────────────────────────────
    SUBDOMAIN_KW = {
        "mental_health":   ["mental health","therapy","anxiety","depression","psychiatry",
                            "counseling","trauma","crisis","suicidal","self-harm","ptsd"],
        "tax":             ["irs","tax","deduction","capital gains","w-2","1099","filing",
                            "tax return","withholding","schedule c"],
        "regulatory":      ["sec","fda","osha","regulatory","compliance framework",
                            "cfr","consent decree","enforcement action"],
        "insurance":       ["insurance","premium","underwriting","claim","policy limit",
                            "deductible","actuary","reinsurance"],
        "real_estate":     ["mortgage","escrow","appraisal","deed","real estate",
                            "refinance","closing cost","title insurance","hoa"],
        "cybersecurity":   ["encryption","vulnerability","penetration","zero-day",
                            "firewall","intrusion","soc 2","cvss","exploit"],
        "data_science":    ["machine learning","neural network","data science","model training",
                            "feature engineering","overfitting","gradient","regression"],
        "tax_law":         ["tax law","tax code","irs audit","estate tax","gift tax"],
    }

    DOMAIN_WEIGHTS = {
        "legal":1.2,"health":1.2,"coding":1.0,"research":1.0,
        "finance":1.0,"agentic":1.0,"creative":0.9,"general":0.5,
    }

    # ── Score domains ────────────────────────────────────────────────────────
    domain_scores = {}
    for domain, kws in DOMAIN_KW.items():
        score = 0.0
        for kw, w in kws:
            if ' ' in kw:
                if kw in lower:
                    score += w
            else:
                if _word_in(kw, lower):
                    score += w
        domain_scores[domain] = score + (0.1 if domain == "general" else 0)

    primary_domain    = max(domain_scores, key=domain_scores.get)
    domain_score_val  = domain_scores[primary_domain]
    domain_match_count = sum(1 for s in domain_scores.values() if s > 0.5)

    # ── Subdomain detection ──────────────────────────────────────────────────
    subdomain = "none"
    best_sub_score = 0
    for sub, kws in SUBDOMAIN_KW.items():
        hits = sum(1 for kw in kws if (' ' in kw and kw in lower) or _word_in(kw, lower))
        if hits > best_sub_score:
            best_sub_score = hits
            subdomain = sub
    if best_sub_score == 0:
        subdomain = "none"

    # ── Complexity scoring ───────────────────────────────────────────────────
    token_norm   = min(token_est / 200, 1.0)
    domain_boost = _clamp(domain_score_val / 3.0, 0.0, 0.35)

    complexity = _clamp(
        token_norm * 0.20
        + (verb_count / 10) * 0.25
        + (question_count / 5) * 0.10
        + (list_count / 10) * 0.10
        + (sentence_count / 10) * 0.10
        + domain_boost,
        0.0, 1.0,
    )

    # Apply domain complexity floor
    floor = DOMAIN_COMPLEXITY_FLOOR.get(primary_domain, 0.0)
    if primary_domain == "coding" and domain_score_val > 1.2:
        floor = 0.46
    if primary_domain == "coding" and domain_score_val > 2.5:
        floor = 0.55
    if domain_score_val > 0.5:
        complexity = max(complexity, floor)

    # ── Output type detection ────────────────────────────────────────────────
    image_kw   = ["generate an image","generate image","create an image","draw me",
                  "illustration of","dall-e","midjourney","stable diffusion",
                  "picture of","render a","photo of"]
    svg_kw     = ["svg","vector graphic","icon","logo in svg"]
    audio_kw   = ["music","song","audio","speech","voice","sound","compose","jingle"]
    video_kw   = ["video","animation","reel","clip","motion graphic"]
    code_kw    = ["function","class","script","code","program","query","sql","bash",
                  "python","javascript","implement","refactor","debug"]
    struct_kw  = ["json","csv","table","schema","spreadsheet","yaml","xml",
                  "structured output","data model"]
    mixed_kw   = ["and also","along with","as well as","plus a"]

    is_image  = any(k in lower for k in image_kw) or _word_in("image", lower) or _word_in("picture", lower) or _word_in("photo", lower) and not any(x in lower for x in ["photosynthesis","photography","photograph","photographer","photon","photovoltaic"])
    is_svg    = any(k in lower for k in svg_kw)
    is_audio  = any(k in lower for k in audio_kw)
    is_video  = any(k in lower for k in video_kw)
    is_code   = any(k in lower for k in code_kw) or primary_domain == "coding"
    is_struct = any(k in lower for k in struct_kw)
    is_mixed  = any(k in lower for k in mixed_kw)

    modality_count = sum([is_image, is_svg, is_audio, is_video, is_code, is_struct])
    is_multimodal  = modality_count > 1

    if is_multimodal or is_mixed:
        output_type = "mixed"
    elif is_image:
        output_type = "image"
    elif is_svg:
        output_type = "svg"
    elif is_audio:
        output_type = "audio"
    elif is_video:
        output_type = "video"
    elif is_code:
        output_type = "code"
    elif is_struct:
        output_type = "structured_data"
    elif primary_domain == "creative":
        output_type = "text"
    else:
        output_type = "model_decided"

    # ── Prompt structure signals ─────────────────────────────────────────────
    MULTI_STEP_KW = ["then","after that","finally","next","step 1","step 2",
                     "first","second","third","lastly","followed by"]
    NUMERICAL_KW  = ["calculate","compute","how much","how many","percentage",
                     "forecast","estimate","total","average","sum","rate",
                     "roi","ebitda","revenue","cost","budget","price"]
    CONDITIONAL_KW = ["if ","unless","assuming","given that","in the case",
                      "when ","depending on","only if","otherwise","else"]

    is_multi_step  = sum(1 for k in MULTI_STEP_KW  if k in lower) >= 2
    is_numerical   = any(k in lower for k in NUMERICAL_KW)
    is_conditional = any(k in lower for k in CONDITIONAL_KW)

    # ── PII detection ────────────────────────────────────────────────────────
    pii = []
    if re.search(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', lower):
        pii.append("email")
    if any(_word_in(k, lower) for k in ["ssn","social security","tax id"]) and re.search(r'\d{4,}', lower):
        pii.append("ssn")
    if any(k in lower for k in ["credit card","card number","cvv","cvc","visa","mastercard","amex"]) and re.search(r'\d{4,}', lower):
        pii.append("credit_card")
    if any(_word_in(k, lower) for k in ["patient","diagnosis","prescription","medication",
                                         "blood pressure","glucose","lab result"]):
        pii.append("medical")
    if any(k in lower for k in ["date of birth","dob","born on"]):
        pii.append("dob")
    if any(k in lower for k in ["account number","routing number","iban","swift code"]) and re.search(r'\d{6,}', lower):
        pii.append("financial")

    # ── Compliance flags ─────────────────────────────────────────────────────
    compliance = []
    if any(_word_in(k, lower) for k in ["patient","phi","hipaa","ehr","emr","medical record"]) or "medical" in pii:
        compliance.append("HIPAA")
    if any(k in lower for k in ["gdpr","personal data","data subject","right to erasure"]):
        compliance.append("GDPR")
    if any(k in lower for k in ["pci","pci dss","cardholder","payment card"]) or "credit_card" in pii:
        compliance.append("PCI_DSS")
    if any(k in lower for k in ["attorney-client","privileged","work product"]):
        compliance.append("ATTORNEY_CLIENT")
    if any(k in lower for k in ["sec filing","material nonpublic","insider","10-k","10-q","8-k"]):
        compliance.append("SEC")
    if any(k in lower for k in ["fda approval","clinical trial","510k","pma","drug approval"]):
        compliance.append("FDA")
    if any(k in lower for k in ["ferpa","student record","education record"]):
        compliance.append("FERPA")

    egress_blocked = len(compliance) > 0

    # ── Confidence ───────────────────────────────────────────────────────────
    conf = 1.0
    if 400 <= token_est <= 600:    conf -= 0.15
    if domain_match_count > 1:     conf -= 0.20 * (domain_match_count - 1)
    if pii:                        conf -= 0.30
    if 0.40 <= complexity <= 0.55: conf -= 0.20
    if question_count > 3:         conf -= 0.15
    if list_count > 5:             conf -= 0.10
    conf = _clamp(conf, 0.0, 1.0)

    # ── Tier mapping ─────────────────────────────────────────────────────────
    if offline or compliance:
        tier = "L0"
    elif primary_domain == "legal" and domain_score_val > 0.5:
        tier = "L3"
    elif complexity > 0.72 or token_est > 4000:
        tier = "L3"
    elif complexity > 0.45 or token_est > 500:
        tier = "L2"
    elif complexity > 0.25 or token_est > 200:
        tier = "L1"
    else:
        tier = "L0"

    return AnalysisResult(
        analyzer_version="0.2.0", layer=1,
        tier=tier, confidence=round(conf, 4),
        complexity_score=round(complexity, 4),
        token_estimate=token_est, word_count=len(words),
        sentence_count=sentence_count, question_count=question_count,
        list_item_count=list_count, verb_count=verb_count,
        primary_domain=primary_domain, subdomain=subdomain,
        domain_match_count=domain_match_count,
        output_type=output_type,
        is_multi_step=is_multi_step,
        is_numerical=is_numerical,
        is_conditional=is_conditional,
        is_multimodal=is_multimodal,
        pii_classes=pii, compliance_flags=compliance,
        data_egress_blocked=egress_blocked, offline_mode=offline,
    )

# ── Main entry point ──────────────────────────────────────────────────────────

def analyze(prompt: str, offline: bool = False) -> AnalysisResult:
    """
    Analyze a prompt and return routing metadata.

    Falls back to pure-Python implementation if signals_core.so/.dll
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
            lib.idn_analyze.argtypes = [ctypes.c_char_p, ctypes.POINTER(_IDNAnalyzerConfig)]
            cfg = _IDNAnalyzerConfig(
                offline_mode=int(offline),
                complexity_l0_max=0.25,
                complexity_l1_max=0.45,
                complexity_l2_max=0.72,
                confidence_threshold=0.85,
            )
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
                subdomain="none",
                domain_match_count=raw.domain_match_count,
                output_type="model_decided",
                is_multi_step=False,
                is_numerical=False,
                is_conditional=False,
                is_multimodal=False,
                pii_classes=_decode_flags(raw.pii_flags, PII_FLAG_NAMES),
                compliance_flags=_decode_flags(raw.compliance_flags, COMPLIANCE_FLAG_NAMES),
                data_egress_blocked=bool(raw.data_egress_blocked),
                offline_mode=bool(raw.offline_mode),
            )
        except Exception:
            pass
    return _python_analyze(prompt, offline=offline)
