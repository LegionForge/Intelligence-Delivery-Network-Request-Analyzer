/*
 * signals_core.h — IDN Request Analyzer Public API
 *
 * Copyright (C) 2026 John Paul "Jp" Cruz
 * https://github.com/jp-cruz/Intelligence-Delivery-Network-Request-Analyzer
 *
 * Licensed under GNU AGPL v3 with Section 7 attribution terms.
 */

#ifndef IDN_SIGNALS_CORE_H
#define IDN_SIGNALS_CORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IDN_ANALYZER_VERSION    "0.1.0"
#define IDN_MAX_PROMPT_LEN      16384
#define IDN_DOMAIN_COUNT        8

typedef enum { TIER_L0=0, TIER_L1=1, TIER_L2=2, TIER_L3=3 } IDNTier;

typedef enum {
    DOMAIN_CODING=0, DOMAIN_RESEARCH=1, DOMAIN_LEGAL=2,   DOMAIN_HEALTH=3,
    DOMAIN_FINANCE=4, DOMAIN_CREATIVE=5, DOMAIN_AGENTIC=6, DOMAIN_GENERAL=7
} IDNDomain;

typedef uint16_t IDNPIIFlags;
#define IDN_PII_NONE        0x0000
#define IDN_PII_EMAIL       0x0001
#define IDN_PII_PHONE       0x0002
#define IDN_PII_SSN         0x0004
#define IDN_PII_CREDIT_CARD 0x0008
#define IDN_PII_DOB         0x0010
#define IDN_PII_MEDICAL     0x0020
#define IDN_PII_FINANCIAL   0x0040
#define IDN_PII_LOCATION    0x0080
#define IDN_PII_IP          0x0100
#define IDN_PII_NAME        0x0200
#define IDN_PII_ANY         0xFFFF

typedef uint8_t IDNComplianceFlags;
#define IDN_COMPLIANCE_NONE             0x00
#define IDN_COMPLIANCE_HIPAA            0x01
#define IDN_COMPLIANCE_GDPR             0x02
#define IDN_COMPLIANCE_PCI              0x04
#define IDN_COMPLIANCE_ATTORNEY_CLIENT  0x08
#define IDN_COMPLIANCE_FERPA            0x10
#define IDN_COMPLIANCE_ANY              0xFF

typedef struct {
    int   offline_mode;
    float complexity_l0_max;
    float complexity_l1_max;
    float complexity_l2_max;
    float confidence_threshold;
} IDNAnalyzerConfig;

typedef struct {
    IDNTier             tier;
    float               confidence;
    float               complexity_score;
    int                 layer;
    char                analyzer_version[8];
    int                 token_estimate;
    int                 char_count;
    int                 word_count;
    int                 sentence_count;
    int                 question_count;
    int                 list_item_count;
    int                 verb_count;
    IDNDomain           primary_domain;
    int                 domain_match_count;
    IDNPIIFlags         pii_flags;
    IDNComplianceFlags  compliance_flags;
    int                 data_egress_blocked;
    int                 offline_mode;
} IDNAnalysisResult;

IDNAnalysisResult idn_analyze(const char *prompt, const IDNAnalyzerConfig *cfg);
const char       *idn_tier_name(IDNTier tier);
const char       *idn_domain_name(IDNDomain domain);

#ifdef __cplusplus
}
#endif

#endif /* IDN_SIGNALS_CORE_H */
