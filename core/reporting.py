"""Report generation for RACON.

Produces HTML, JSON, CSV and PDF reports from a completed scan. Every report
includes an executive summary, findings with informational severity labels,
a screenshots placeholder, metadata and a timestamp.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.config import Config
from core.logger import get_logger

log = get_logger()

#: Supported output formats.
FORMATS = ("html", "json", "csv", "pdf")


class ReportGenerator:
    """Builds reports in one or more formats for a completed scan."""

    def __init__(
        self,
        config: Config,
        results: list[Any],
        target: str,
        metadata: dict[str, Any],
        templates_dir: str | Path,
    ) -> None:
        self.config = config
        self.results = results
        self.target = target
        self.metadata = metadata
        self.env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(["html"]),
        )
        self.package = self._build_report_package()

    # ---------------------------------------------------------------- package
    def _build_report_package(self) -> dict[str, Any]:
        module_data: dict[str, Any] = {}
        findings: list[dict[str, Any]] = []
        total_time = 0.0
        completed = 0

        for result in self.results:
            module_data[result.module] = result.data
            if result.status == "success":
                completed += 1
            total_time += result.elapsed
            for finding in result.findings:
                findings.append({
                    "module": result.module,
                    **finding.to_dict(),
                })

        # Executive summary stats.
        severity_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary = {
            "target": self.target,
            "modules_completed": completed,
            "modules_total": len(self.results),
            "findings_total": len(findings),
            "severity_counts": severity_counts,
            "elapsed_total": round(total_time, 2),
        }

        return {
            "metadata": self.metadata,
            "summary": summary,
            "modules": module_data,
            "findings": findings,
        }

    # ------------------------------------------------------------------ write
    def generate(self, fmt: str, out_dir: str | Path) -> list[Path]:
        """Generate reports for the requested format(s).

        ``fmt`` may be a single format or comma-separated list; use ``all``
        for every supported format. Returns the list of written file paths.
        """
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        requested = self._parse_formats(fmt)
        paths: list[Path] = []
        for format_name in requested:
            path = self._generate_one(format_name, out_dir)
            if path:
                paths.append(path)
        return paths

    def _parse_formats(self, fmt: str) -> list[str]:
        fmt = (fmt or "html").lower().strip()
        if fmt == "all":
            return list(FORMATS)
        return [f.strip() for f in fmt.split(",") if f.strip() in FORMATS]

    def _generate_one(self, format_name: str, out_dir: Path) -> Path | None:
        base = f"{self._safe_target()}_report"
        try:
            if format_name == "html":
                path = out_dir / f"{base}.html"
                self._write_html(path)
            elif format_name == "json":
                path = out_dir / f"{base}.json"
                self._write_json(path)
            elif format_name == "csv":
                path = out_dir / f"{base}.csv"
                self._write_csv(path)
            elif format_name == "pdf":
                path = out_dir / f"{base}.pdf"
                self._write_pdf(path)
            else:
                return None
            log.info("Generated %s report: %s", format_name.upper(), path)
            return path
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to generate %s report: %s", format_name, exc)
            return None

    def _safe_target(self) -> str:
        import re

        return re.sub(r"[^A-Za-z0-9._-]+", "_", self.target)

    # -------------------------------------------------------------- individual
    def _write_html(self, path: Path) -> None:
        template = self.env.get_template("report.html.j2")
        html = template.render(
            package=self.package,
            config_screenshots=self.config.screenshots_placeholder,
        )
        path.write_text(html, encoding="utf-8")

    def _write_json(self, path: Path) -> None:
        payload = self.package
        path.write_text(
            json.dumps(payload, indent=2, default=str), encoding="utf-8"
        )

    def _write_csv(self, path: Path) -> None:
        buffer = io.StringIO()
        fieldnames = ["module", "title", "severity", "description",
                      "evidence", "recommendation"]
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        for finding in self.package["findings"]:
            writer.writerow({k: finding.get(k, "") for k in fieldnames})
        # Metadata rows.
        meta = self.package["metadata"]
        writer.writerow({})
        writer.writerow({"title": "Report Metadata", "description": "---"})
        for key, value in meta.items():
            writer.writerow({"title": key, "description": value})
        path.write_text(buffer.getvalue(), encoding="utf-8")

    def _write_pdf(self, path: Path) -> None:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer,
                                        Table, TableStyle)

        doc = SimpleDocTemplate(
            str(path), pagesize=A4,
            rightMargin=inch, leftMargin=inch,
            topMargin=inch, bottomMargin=inch,
        )
        styles = getSampleStyleSheet()
        title_style = styles["Title"]
        heading_style = styles["Heading1"]
        sub_style = styles["Heading2"]
        body_style = ParagraphStyle(
            "BodySmall", parent=styles["BodyText"], fontSize=9, leading=12,
        )

        story: list[Any] = [Paragraph("RACON Scan Report", title_style)]
        story.append(Spacer(1, 0.2 * inch))

        # Executive summary.
        summary = self.package["summary"]
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Paragraph(
            f"This report documents the reconnaissance and asset inventory "
            f"assessment performed against <b>{self.target}</b>. "
            f"{summary['modules_completed']} of {summary['modules_total']} "
            f"modules completed and {summary['findings_total']} finding(s) "
            f"were recorded. All findings are informational in nature.",
            body_style,
        ))
        story.append(Spacer(1, 0.2 * inch))

        # Metadata.
        story.append(Paragraph("Metadata", heading_style))
        meta_rows = [[k.title(), str(v)] for k, v in self.package["metadata"].items()]
        meta_table = Table(meta_rows, colWidths=[2 * inch, 4 * inch])
        meta_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.3 * inch))

        # Findings.
        story.append(Paragraph("Findings", heading_style))
        findings = self.package["findings"]
        if findings:
            for f in findings:
                story.append(Paragraph(
                    f"[{f['severity'].upper()}] {f['title']} ({f['module']})",
                    sub_style,
                ))
                if f.get("description"):
                    story.append(Paragraph(f["description"], body_style))
                if f.get("evidence"):
                    story.append(Paragraph(
                        f"<i>Evidence:</i> {f['evidence']}", body_style,
                    ))
                if f.get("recommendation"):
                    story.append(Paragraph(
                        f"<i>Recommendation:</i> {f['recommendation']}", body_style,
                    ))
                story.append(Spacer(1, 0.12 * inch))
        else:
            story.append(Paragraph("No findings were recorded.", body_style))

        # Screenshots placeholder.
        if self.config.screenshots_placeholder:
            story.append(Paragraph("Screenshots", heading_style))
            story.append(Paragraph(
                "Screenshots are captured separately and can be attached to "
                "this report during archival. See the HTML report for the "
                "screenshots placeholder section.",
                body_style,
            ))

        doc.build(story)
