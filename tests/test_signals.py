"""
test_signals.py — Golden example test suite for IDN Request Analyzer
20 labeled examples covering all tiers, domains, PII, and compliance cases.
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.signals import analyze


# ── Tier L0 — simple / trivial ───────────────────────────────────────────────

def test_l0_simple_question():
    r = analyze("What is the capital of France?")
    assert r.tier == "L0"
    assert r.complexity_score < 0.25
    assert r.primary_domain == "general"

def test_l0_greeting():
    r = analyze("Hello! How are you?")
    assert r.tier == "L0"
    assert r.complexity_score < 0.25

def test_l0_simple_translation():
    r = analyze("Translate 'good morning' to Spanish.")
    assert r.tier in ("L0", "L1")
    assert r.complexity_score < 0.40

def test_l0_empty_prompt():
    r = analyze("")
    assert r.tier == "L0"
    assert r.confidence == 1.0


# ── Tier L1 — light coding / creative ───────────────────────────────────────

def test_l1_simple_code():
    r = analyze("Write a Python function that reverses a string.")
    assert r.tier in ("L1", "L2")
    assert r.primary_domain == "coding"

def test_l1_blog_post():
    r = analyze("Write a short blog post about the benefits of daily exercise.")
    assert r.tier in ("L0","L1","L2")
    assert r.primary_domain in ("creative","general")


# ── Tier L2 — complex coding / research / finance / health ───────────────────

def test_l2_refactor():
    r = analyze("Refactor this Python module for horizontal scalability and add unit tests.")
    assert r.tier in ("L2", "L3")
    assert r.primary_domain == "coding"
    assert r.complexity_score > 0.35

def test_l2_research():
    r = analyze("Summarize the latest peer-reviewed research on transformer architecture efficiency.")
    assert r.tier in ("L2","L3")
    assert r.primary_domain in ("research","coding")

def test_l2_finance():
    r = analyze("Analyze our Q3 cash flow statement and produce an EBITDA forecast for FY2026.")
    assert r.tier in ("L2","L3")
    assert r.primary_domain == "finance"

def test_l2_agentic():
    r = analyze("Schedule a webhook to run every hour, fetch our sales data, and send a Slack alert if revenue drops below $10k.")
    assert r.tier in ("L2","L3")
    assert r.primary_domain == "agentic"


# ── Tier L3 — deep reasoning / legal ─────────────────────────────────────────

def test_l3_legal():
    r = analyze("Review this NDA clause for indemnification liability and jurisdictional precedent.")
    assert r.tier == "L3"
    assert r.primary_domain == "legal"

def test_l3_distributed_systems():
    r = analyze(
        "Design a fault-tolerant distributed event streaming architecture "
        "handling 1M events/sec with exactly-once semantics, "
        "geo-replication, and sub-10ms p99 latency."
    )
    assert r.tier in ("L2","L3")
    assert r.primary_domain == "coding"
    assert r.complexity_score > 0.50


# ── PII detection ─────────────────────────────────────────────────────────────

def test_pii_email_detected():
    r = analyze("Send the report to john.doe@example.com by Friday.")
    assert "email" in r.pii_classes

def test_pii_medical_detected():
    r = analyze("Patient is prescribed 20mg Lisinopril. Blood pressure 140/90.")
    assert "medical" in r.pii_classes
    assert r.data_egress_blocked is True

def test_pii_credit_card_detected():
    r = analyze("Charge the Visa card number 4111 1111 1111 1111 for $99.")
    assert "credit_card" in r.pii_classes
    assert r.data_egress_blocked is True


# ── Compliance flags ──────────────────────────────────────────────────────────

def test_compliance_hipaa_forced_l0():
    r = analyze("The patient's EHR shows a diagnosis of Type 2 diabetes.")
    assert "HIPAA" in r.compliance_flags
    assert r.tier == "L0"
    assert r.data_egress_blocked is True

def test_compliance_pci():
    r = analyze("The cardholder data must comply with PCI DSS standards.")
    assert "PCI_DSS" in r.compliance_flags

def test_compliance_gdpr():
    r = analyze("Under GDPR the data subject has the right to erasure of personal data.")
    assert "GDPR" in r.compliance_flags


# ── Offline mode ──────────────────────────────────────────────────────────────

def test_offline_forces_l0():
    r = analyze("Design a microservices architecture for a fintech platform.", offline=True)
    assert r.tier == "L0"
    assert r.offline_mode is True


# ── Output schema integrity ───────────────────────────────────────────────────

def test_result_schema():
    r = analyze("Explain how transformers work in NLP.")
    assert isinstance(r.tier, str)
    assert isinstance(r.confidence, float)
    assert isinstance(r.complexity_score, float)
    assert isinstance(r.pii_classes, list)
    assert isinstance(r.compliance_flags, list)
    assert 0.0 <= r.confidence <= 1.0
    assert 0.0 <= r.complexity_score <= 1.0
    assert r.tier in ("L0","L1","L2","L3")
    j = r.to_json()
    import json
    parsed = json.loads(j)
    assert "tier" in parsed
    assert "complexity_score" in parsed
