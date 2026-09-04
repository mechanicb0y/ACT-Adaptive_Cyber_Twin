#Analyst-ready incident reports for one attacker: MITRE ATT&CK techniques, the
#kill-chain stages reached, an event timeline, the risk score and confidence,
#the AI's contribution, and the action ACT took (or would take).
#
#`build_report` turns a TwinAssessment + AttackPath into a plain dict.
#`render_html` renders it as a standalone, print-friendly HTML page.
#`render_pdf` renders the same content as a PDF with no third-party dependency.

from app.reporting.report_data import build_report
from app.reporting.html_report import render_html
from app.reporting.pdf_report import render_pdf

__all__ = ["build_report", "render_html", "render_pdf"]
