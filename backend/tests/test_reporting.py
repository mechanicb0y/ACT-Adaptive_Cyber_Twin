"""Incident reports: the HTML preview and the dependency-free PDF."""

import pytest

from app.api.engine import AnalysisEngine


@pytest.fixture
def engine(bruteforce_log):
    e = AnalysisEngine()
    e.ingest_file(str(bruteforce_log))
    return e


def test_html_report_has_every_required_section(engine):

    html, media_type, filename = engine.report("192.168.1.50", fmt="html")

    assert media_type.startswith("text/html")
    assert filename.endswith(".html")

    for heading in ("Summary", "Assessment", "MITRE ATT&amp;CK techniques",
                    "Kill-chain progression", "Event timeline", "Response"):
        assert heading in html

    assert "192.168.1.50" in html
    assert "T1110" in html                       # a brute-force technique id
    assert "BLOCK IP" in html                    # the action ACT took
    assert "Severity" in html and "Decision confidence" in html   # classification bar


def test_pdf_report_is_a_well_formed_pdf(engine):

    pdf, media_type, filename = engine.report("192.168.1.50", fmt="pdf")

    assert media_type == "application/pdf"
    assert filename.endswith(".pdf")
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert b"/Type /Catalog" in pdf
    assert b"MITRE ATT&CK TECHNIQUES" in pdf


def test_report_for_an_unknown_actor_is_none(engine):
    assert engine.report("10.0.0.254", fmt="html") is None


def test_report_contains_the_ai_section_even_without_a_model(engine):
    #the suite runs with ACT_LLM_PROVIDER=none, so the report must still render
    html, _, _ = engine.report("192.168.1.50", fmt="html")
    assert "deterministic engine alone" in html


def test_report_payload_is_serialisable(engine):
    import json
    from datetime import datetime

    from app.reporting import build_report

    graph = engine.attack_graph()
    path = graph.paths[0]
    assessment = engine.assessments()[0]

    data = build_report(assessment, path, generated_at=datetime(2026, 9, 3))

    #every field must survive a round trip so the shape is API-safe too
    assert json.loads(json.dumps(data)) == data
    assert data["mitre_techniques"]
    assert data["kill_chain"]
    assert data["timeline"]
    assert data["actions_taken"]["decision"] == "block_ip"
