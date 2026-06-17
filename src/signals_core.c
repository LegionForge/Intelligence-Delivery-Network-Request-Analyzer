/*
 * signals_core.c — IDN Request Analyzer, Layer 1 Heuristic Engine
 *
 * Copyright (C) 2026 John Paul "Jp" Cruz
 * https://github.com/LegionForge/Intelligence-Delivery-Network-Request-Analyzer
 *
 * Licensed under GNU AGPL v3 with Section 7 attribution terms.
 * See LICENSE for full terms.
 *
 * Pure C99. No malloc. No file I/O. No dynamic memory.
 * Compiles on: x86_64, ARM, RISC-V, Xtensa (ESP32), AVR (Arduino)
 * Target RAM usage: < 2KB stack
 * Target latency:   < 2ms on any Class A/B/C/D platform
 */

#include "signals_core.h"
#include <string.h>
#include <ctype.h>
#include <stdint.h>

/* ── Internal utilities ─────────────────────────────────────────────────── */

static void str_lower(const char *src, char *dst, int max_len) {
    int i = 0;
    while (src[i] && i < max_len - 1) {
        dst[i] = (char)tolower((unsigned char)src[i]);
        i++;
    }
    dst[i] = '\0';
}

static int str_contains(const char *haystack, const char *needle) {
    return strstr(haystack, needle) != NULL;
}

static int count_char(const char *s, char c) {
    int count = 0;
    while (*s) { if (*s == c) count++; s++; }
    return count;
}

static int count_words(const char *s) {
    int count = 0, in_word = 0;
    while (*s) {
        if (isspace((unsigned char)*s)) { in_word = 0; }
        else if (!in_word) { in_word = 1; count++; }
        s++;
    }
    return count;
}

static float clampf(float v, float lo, float hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

/* ── Domain keyword tables ──────────────────────────────────────────────── */

typedef struct { const char *word; float weight; } Keyword;

static const Keyword KW_CODING[] = {
    {"refactor",0.9f},{"function",0.6f},{"class",0.6f},{"method",0.6f},
    {"bug",0.8f},{"debug",0.9f},{"compile",1.0f},{"syntax",0.9f},
    {"algorithm",1.0f},{"repository",0.8f},{"deploy",0.9f},{"api",0.7f},
    {"endpoint",0.8f},{"database",0.8f},{"schema",0.8f},{"query",0.7f},
    {"unit test",1.0f},{"integration test",1.0f},{"pull request",0.9f},
    {"git",0.7f},{"docker",0.9f},{"kubernetes",1.0f},{"microservice",1.0f},
    {"architecture",0.8f},{"scalability",1.0f},{"performance",0.7f},
    {"latency",0.8f},{"throughput",0.9f},{"async",0.8f},{"concurrency",1.0f},
    {"thread",0.8f},{"memory leak",1.0f},{"stack overflow",1.0f},
    {"null pointer",0.9f},{"exception",0.7f},{"runtime error",0.9f},
    {"import",0.5f},{"library",0.6f},{"framework",0.7f},{"python",0.8f},
    {"javascript",0.8f},{"typescript",0.9f},{"rust",0.9f},{"golang",0.9f},
    {"llm",0.8f},{"inference",0.9f},{"embedding",0.9f},
    {NULL,0.0f}
};

static const Keyword KW_RESEARCH[] = {
    {"analyze",0.8f},{"analysis",0.8f},{"study",0.7f},{"compare",0.7f},
    {"comparison",0.8f},{"summarize",0.7f},{"literature",1.0f},
    {"evidence",0.9f},{"findings",0.9f},{"cite",0.9f},{"citation",0.9f},
    {"paper",0.7f},{"research",0.8f},{"hypothesis",1.0f},{"methodology",1.0f},
    {"dataset",0.9f},{"statistics",0.9f},{"correlation",1.0f},
    {"peer review",1.0f},{"meta-analysis",1.0f},{"systematic review",1.0f},
    {"survey",0.7f},{"evaluate",0.7f},{"benchmark",0.8f},{"experiment",0.9f},
    {NULL,0.0f}
};

static const Keyword KW_LEGAL[] = {
    {"contract",1.0f},{"clause",1.0f},{"liability",1.0f},{"compliance",1.0f},
    {"statute",1.0f},{"regulation",0.9f},{"attorney",1.0f},{"counsel",0.8f},
    {"litigation",1.0f},{"lawsuit",1.0f},{"plaintiff",1.0f},{"defendant",1.0f},
    {"jurisdiction",1.0f},{"precedent",1.0f},{"indemnification",1.0f},
    {"arbitration",1.0f},{"nda",1.0f},{"non-disclosure",1.0f},
    {"intellectual property",1.0f},{"copyright",0.9f},{"trademark",0.9f},
    {"patent",0.9f},{"gdpr",1.0f},{"hipaa",1.0f},{"pci",0.9f},
    {"terms of service",1.0f},{"privacy policy",0.9f},{"force majeure",1.0f},
    {"warranty",0.8f},{"breach",0.9f},{"damages",0.9f},{"injunction",1.0f},
    {"deposition",1.0f},{"subpoena",1.0f},
    {NULL,0.0f}
};

static const Keyword KW_HEALTH[] = {
    {"patient",1.0f},{"diagnosis",1.0f},{"symptom",1.0f},{"symptoms",1.0f},
    {"medication",1.0f},{"prescription",1.0f},{"dosage",1.0f},{"clinical",1.0f},
    {"medical",0.9f},{"treatment",0.9f},{"therapy",0.9f},{"surgery",1.0f},
    {"hospital",0.8f},{"physician",1.0f},{"doctor",0.8f},{"nurse",0.7f},
    {"blood pressure",1.0f},{"heart rate",1.0f},{"glucose",1.0f},
    {"insulin",1.0f},{"chronic",0.9f},{"acute",0.8f},{"prognosis",1.0f},
    {"pharmacy",0.9f},{"vaccine",0.8f},{"allergy",0.8f},{"lab result",1.0f},
    {"biopsy",1.0f},{"ehr",1.0f},{"emr",1.0f},
    {NULL,0.0f}
};

static const Keyword KW_FINANCE[] = {
    {"portfolio",1.0f},{"revenue",0.9f},{"roi",1.0f},{"tax",0.8f},
    {"invoice",0.9f},{"balance sheet",1.0f},{"investment",0.9f},{"equity",0.9f},
    {"stock",0.8f},{"bond",0.8f},{"dividend",1.0f},{"valuation",1.0f},
    {"cash flow",1.0f},{"ebitda",1.0f},{"profit",0.8f},{"budget",0.7f},
    {"forecast",0.8f},{"audit",0.9f},{"payroll",0.9f},{"amortization",1.0f},
    {"depreciation",1.0f},{"liquidity",1.0f},{"hedge",1.0f},{"ipo",1.0f},
    {"market cap",1.0f},{"earnings",0.9f},
    {NULL,0.0f}
};

static const Keyword KW_CREATIVE[] = {
    {"poem",1.0f},{"poetry",1.0f},{"screenplay",1.0f},{"novel",1.0f},
    {"fiction",1.0f},{"narrative",0.9f},{"dialogue",0.9f},{"brainstorm",0.8f},
    {"imagine",0.8f},{"metaphor",0.9f},{"rhyme",1.0f},{"blog post",0.8f},
    {"essay",0.8f},{"copywriting",1.0f},{"slogan",0.9f},{"story",0.8f},
    {NULL,0.0f}
};

static const Keyword KW_AGENTIC[] = {
    {"schedule",0.9f},{"automate",1.0f},{"execute",0.9f},{"workflow",1.0f},
    {"pipeline",0.9f},{"trigger",0.8f},{"monitor",0.8f},{"webhook",1.0f},
    {"cron",1.0f},{"integration",0.8f},{"search the web",1.0f},{"scrape",1.0f},
    {"agent",0.9f},{"autonomous",1.0f},{"batch",0.8f},{"iterate",0.8f},
    {"for each",0.8f},{"for all",0.7f},{"send email",0.9f},{"send message",0.8f},
    {NULL,0.0f}
};

static const Keyword KW_GENERAL[] = {
    {"what is",0.3f},{"who is",0.3f},{"when is",0.3f},{"where is",0.3f},
    {"how do i",0.4f},{"tell me",0.3f},{"explain",0.5f},{"define",0.4f},
    {"translate",0.5f},{"hello",0.1f},{"hi",0.1f},{"thanks",0.1f},
    {NULL,0.0f}
};

/* ── PII context keywords ────────────────────────────────────────────────── */

static const char *PII_SSN_CONTEXT[]     = {"ssn", "social security", "tax id", NULL};
static const char *PII_CARD_CONTEXT[]    = {"credit card", "card number", "cvv", "cvc", "visa", "mastercard", "amex", NULL};
static const char *PII_MEDICAL_CONTEXT[] = {"patient", "diagnosis", "prescription", "medication", "dosage", "blood pressure", "heart rate", "glucose", "lab result", "biopsy", NULL};
static const char *PII_DOB_CONTEXT[]     = {"date of birth", "dob", "born on", "born in", NULL};
static const char *PII_FINANCIAL[]       = {"account number", "routing number", "iban", "swift code", "bank account", NULL};

/* ── Compliance keyword tables ──────────────────────────────────────────── */

static const char *COMPLIANCE_HIPAA[] = {"patient", "phi", "protected health", "hipaa", "ehr", "emr", "medical record", "clinical trial", NULL};
static const char *COMPLIANCE_GDPR[]  = {"gdpr", "personal data", "data subject", "right to erasure", "data controller", NULL};
static const char *COMPLIANCE_PCI[]   = {"pci", "pci dss", "cardholder", "payment card", "primary account number", NULL};
static const char *COMPLIANCE_LEGAL[] = {"attorney-client", "privileged", "work product", "litigation hold", NULL};

/* ── Action verbs ────────────────────────────────────────────────────────── */

static const char *ACTION_VERBS[] = {
    "analyze","design","build","create","implement","refactor","debug",
    "evaluate","compare","summarize","explain","generate","write","review",
    "optimize","test","deploy","migrate","integrate","automate","calculate",
    "translate","convert","extract","classify","predict","recommend",
    "plan","schedule","monitor","alert","send","fetch","execute",
    NULL
};

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static float score_domain(const char *lower, const Keyword *kws) {
    float score = 0.0f;
    for (int i = 0; kws[i].word != NULL; i++) {
        if (str_contains(lower, kws[i].word)) score += kws[i].weight;
    }
    return score;
}

static IDNDomain dominant_domain(float scores[IDN_DOMAIN_COUNT]) {
    IDNDomain best = DOMAIN_GENERAL;
    float best_score = 0.0f;
    for (int i = 0; i < IDN_DOMAIN_COUNT; i++) {
        if (scores[i] > best_score) { best_score = scores[i]; best = (IDNDomain)i; }
    }
    return best;
}

static int contains_any(const char *lower, const char **terms) {
    for (int i = 0; terms[i] != NULL; i++) {
        if (str_contains(lower, terms[i])) return 1;
    }
    return 0;
}

static int has_email_pattern(const char *lower) {
    const char *at = strchr(lower, '@');
    if (!at || at == lower) return 0;
    return (str_contains(at, ".com") || str_contains(at, ".org") ||
            str_contains(at, ".net") || str_contains(at, ".io")  ||
            str_contains(at, ".edu") || str_contains(at, ".gov"));
}

static int has_digit_sequence(const char *s, int len) {
    int count = 0;
    while (*s) {
        if (isdigit((unsigned char)*s)) { count++; if (count >= len) return 1; }
        else count = 0;
        s++;
    }
    return 0;
}

static float clamp_compute_complexity(int token_est, int verb_count, int question_count,
                                       int list_count, int sentence_count, float domain_weight) {
    float t = clampf((float)token_est / 4000.0f, 0.0f, 1.0f);
    float v = clampf((float)verb_count / 20.0f,  0.0f, 1.0f);
    float q = clampf((float)question_count / 10.0f, 0.0f, 1.0f);
    float l = clampf((float)list_count / 20.0f,  0.0f, 1.0f);
    float s = clampf((float)sentence_count / 40.0f, 0.0f, 1.0f);
    float d = clampf(domain_weight / 1.2f, 0.0f, 1.0f);
    return clampf(t*0.25f + v*0.20f + q*0.10f + l*0.10f + s*0.15f + d*0.20f, 0.0f, 1.0f);
}

static float compute_confidence(int token_est, int domain_count, int pii_detected,
                                  float complexity, int question_count, int list_count) {
    float conf = 1.0f;
    if (token_est >= 400 && token_est <= 600)        conf -= 0.15f;
    if (domain_count > 1)                            conf -= 0.20f * (domain_count - 1);
    if (pii_detected)                                conf -= 0.30f;
    if (complexity >= 0.40f && complexity <= 0.55f)  conf -= 0.20f;
    if (question_count > 3)                          conf -= 0.15f;
    if (list_count > 5)                              conf -= 0.10f;
    return clampf(conf, 0.0f, 1.0f);
}

static IDNTier map_tier(float complexity, int token_est, IDNDomain domain,
                         IDNComplianceFlags flags, int offline) {
    if (offline || (flags & IDN_COMPLIANCE_ANY))       return TIER_L0;
    if (domain == DOMAIN_LEGAL && complexity > 0.3f)   return TIER_L3;
    if (complexity > 0.72f || token_est > 4000)        return TIER_L3;
    if (complexity > 0.45f || token_est > 500)         return TIER_L2;
    if (complexity > 0.25f || token_est > 200)         return TIER_L1;
    return TIER_L0;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

IDNAnalysisResult idn_analyze(const char *prompt, const IDNAnalyzerConfig *cfg) {
    IDNAnalysisResult r;
    memset(&r, 0, sizeof(r));

    if (!prompt || prompt[0] == '\0') {
        r.tier = TIER_L0; r.confidence = 1.0f; return r;
    }

    char lower[IDN_MAX_PROMPT_LEN];
    str_lower(prompt, lower, IDN_MAX_PROMPT_LEN);

    int word_count     = count_words(lower);
    int token_estimate = (int)(word_count * 1.3f);
    int sentence_count = count_char(lower,'.') + count_char(lower,'?') + count_char(lower,'!');
    int question_count = count_char(lower, '?');
    int list_count     = count_char(lower, '-') + count_char(lower, '*');
    int verb_count     = 0;
    for (int i = 0; ACTION_VERBS[i] != NULL; i++) {
        if (str_contains(lower, ACTION_VERBS[i])) verb_count++;
    }

    float domain_scores[IDN_DOMAIN_COUNT] = {0};
    domain_scores[DOMAIN_CODING]    = score_domain(lower, KW_CODING);
    domain_scores[DOMAIN_RESEARCH]  = score_domain(lower, KW_RESEARCH);
    domain_scores[DOMAIN_LEGAL]     = score_domain(lower, KW_LEGAL);
    domain_scores[DOMAIN_HEALTH]    = score_domain(lower, KW_HEALTH);
    domain_scores[DOMAIN_FINANCE]   = score_domain(lower, KW_FINANCE);
    domain_scores[DOMAIN_CREATIVE]  = score_domain(lower, KW_CREATIVE);
    domain_scores[DOMAIN_AGENTIC]   = score_domain(lower, KW_AGENTIC);
    domain_scores[DOMAIN_GENERAL]   = score_domain(lower, KW_GENERAL) + 0.1f;

    IDNDomain primary_domain = dominant_domain(domain_scores);
    int domain_match_count = 0;
    for (int i = 0; i < IDN_DOMAIN_COUNT; i++) {
        if (domain_scores[i] > 0.5f) domain_match_count++;
    }

    IDNPIIFlags pii = IDN_PII_NONE;
    if (has_email_pattern(lower))                          pii |= IDN_PII_EMAIL;
    if (contains_any(lower, PII_SSN_CONTEXT) &&
        has_digit_sequence(lower, 4))                      pii |= IDN_PII_SSN;
    if (contains_any(lower, PII_CARD_CONTEXT) &&
        has_digit_sequence(lower, 4))                      pii |= IDN_PII_CREDIT_CARD;
    if (contains_any(lower, PII_MEDICAL_CONTEXT))          pii |= IDN_PII_MEDICAL;
    if (contains_any(lower, PII_DOB_CONTEXT))              pii |= IDN_PII_DOB;
    if (contains_any(lower, PII_FINANCIAL) &&
        has_digit_sequence(lower, 6))                      pii |= IDN_PII_FINANCIAL;

    IDNComplianceFlags compliance = IDN_COMPLIANCE_NONE;
    if (contains_any(lower, COMPLIANCE_HIPAA) || (pii & IDN_PII_MEDICAL))
        compliance |= IDN_COMPLIANCE_HIPAA;
    if (contains_any(lower, COMPLIANCE_GDPR))
        compliance |= IDN_COMPLIANCE_GDPR;
    if (contains_any(lower, COMPLIANCE_PCI) || (pii & IDN_PII_CREDIT_CARD))
        compliance |= IDN_COMPLIANCE_PCI;
    if (contains_any(lower, COMPLIANCE_LEGAL))
        compliance |= IDN_COMPLIANCE_ATTORNEY_CLIENT;

    int offline = cfg ? cfg->offline_mode : 0;

    float domain_weight = 0.5f;
    if (primary_domain == DOMAIN_LEGAL || primary_domain == DOMAIN_HEALTH) domain_weight = 1.2f;
    else if (primary_domain == DOMAIN_CODING   || primary_domain == DOMAIN_RESEARCH ||
             primary_domain == DOMAIN_FINANCE  || primary_domain == DOMAIN_AGENTIC)  domain_weight = 1.0f;
    else if (primary_domain == DOMAIN_CREATIVE) domain_weight = 0.9f;

    float complexity = clamp_compute_complexity(token_estimate, verb_count, question_count,
                                                list_count, sentence_count, domain_weight);
    int   pii_any    = (pii != IDN_PII_NONE) ? 1 : 0;
    float confidence = compute_confidence(token_estimate, domain_match_count, pii_any,
                                          complexity, question_count, list_count);
    IDNTier tier     = map_tier(complexity, token_estimate, primary_domain, compliance, offline);

    r.tier = tier; r.confidence = confidence; r.complexity_score = complexity;
    r.token_estimate = token_estimate; r.char_count = (int)strlen(prompt);
    r.word_count = word_count; r.sentence_count = sentence_count;
    r.question_count = question_count; r.list_item_count = list_count;
    r.verb_count = verb_count; r.primary_domain = primary_domain;
    r.domain_match_count = domain_match_count; r.pii_flags = pii;
    r.compliance_flags = compliance;
    r.data_egress_blocked = (compliance != IDN_COMPLIANCE_NONE) ? 1 : 0;
    r.offline_mode = offline; r.layer = 1;
    r.analyzer_version[0]='0'; r.analyzer_version[1]='.';
    r.analyzer_version[2]='1'; r.analyzer_version[3]='.';
    r.analyzer_version[4]='0'; r.analyzer_version[5]='\0';
    return r;
}

const char *idn_tier_name(IDNTier tier) {
    switch(tier){ case TIER_L0:return"L0"; case TIER_L1:return"L1";
                  case TIER_L2:return"L2"; case TIER_L3:return"L3"; default:return"L0"; }
}

const char *idn_domain_name(IDNDomain domain) {
    switch(domain){
        case DOMAIN_CODING:   return "coding";
        case DOMAIN_RESEARCH: return "research";
        case DOMAIN_LEGAL:    return "legal";
        case DOMAIN_HEALTH:   return "health";
        case DOMAIN_FINANCE:  return "finance";
        case DOMAIN_CREATIVE: return "creative";
        case DOMAIN_AGENTIC:  return "agentic";
        case DOMAIN_GENERAL:  return "general";
        default:              return "general";
    }
}
