from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


def generate_scan_pdf(scan, previous_scan=None, comparison_stats=None):

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=25,
        leading=30,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0f5132"),
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=11,
        leading=15,
        alignment=TA_CENTER,
        textColor=colors.grey,
        spaceAfter=20
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=17,
        leading=21,
        textColor=colors.HexColor("#0f5132"),
        spaceBefore=10,
        spaceAfter=10
    )

    subheading_style = ParagraphStyle(
        "FindingHeading",
        parent=styles["Heading3"],
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#111827"),
        spaceBefore=8,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#374151"),
        spaceAfter=7
    )

    small_style = ParagraphStyle(
        "ReportSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#374151")
    )

    story = []

    # ==================================================
    # COVER PAGE
    # ==================================================

    story.append(
        Spacer(1, 35 * mm)
    )

    story.append(
        Paragraph(
            "SENTINELSCAN",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Web Application Security Assessment",
            subtitle_style
        )
    )

    story.append(
        Spacer(1, 10 * mm)
    )

    cover_data = [
        [
            Paragraph("<b>Target</b>", body_style),
            Paragraph(
                str(scan.target_url),
                body_style
            )
        ],
        [
            Paragraph("<b>Scan ID</b>", body_style),
            Paragraph(
                str(scan.id),
                body_style
            )
        ],
        [
            Paragraph("<b>Status</b>", body_style),
            Paragraph(
                str(scan.status),
                body_style
            )
        ],
        [
            Paragraph("<b>Started</b>", body_style),
            Paragraph(
                str(scan.started_at or "-"),
                body_style
            )
        ],
        [
            Paragraph("<b>Completed</b>", body_style),
            Paragraph(
                str(scan.completed_at or "-"),
                body_style
            )
        ],
        [
            Paragraph("<b>Scan Duration (s)</b>", body_style),
            Paragraph(
                str(int((scan.completed_at - scan.started_at).total_seconds()) if scan.completed_at and scan.started_at else "-"),
                body_style
            )
        ],
        [
            Paragraph("<b>Pages Scanned</b>", body_style),
            Paragraph(
                str(scan.pages_scanned),
                body_style
            )
        ],
        [
            Paragraph("<b>Forms Discovered</b>", body_style),
            Paragraph(
                str(scan.forms_discovered),
                body_style
            )
        ],
        [
            Paragraph("<b>Requests Made</b>", body_style),
            Paragraph(
                str(scan.requests_made),
                body_style
            )
        ]
    ]

    cover_table = Table(
        cover_data,
        colWidths=[
            35 * mm,
            125 * mm
        ]
    )

    cover_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#e8f3ee")
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.7,
                colors.HexColor("#cbd5d1")
            ),
            (
                "INNERGRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor("#dfe5e2")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                10
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                10
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                8
            )
        ])
    )

    story.append(
        cover_table
    )

    story.append(
        Spacer(1, 20 * mm)
    )

    story.append(
        Paragraph(
            "Generated by SentinelScan",
            subtitle_style
        )
    )

    story.append(
        PageBreak()
    )

    # ==================================================
    # EXECUTIVE SUMMARY
    # ==================================================

    findings = scan.findings

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    for finding in findings:

        if finding.severity in severity_counts:

            severity_counts[
                finding.severity
            ] += 1

    story.append(
        Paragraph(
            "Executive Summary",
            heading_style
        )
    )

    story.append(
        Paragraph(
            (
                f"SentinelScan performed a security assessment on "
                f"<b>{scan.target_url}</b>. The crawler discovered "
                f"<b>{scan.pages_scanned}</b> pages and <b>{scan.forms_discovered}</b> forms. "
                f"In total, {scan.requests_made} HTTP requests were made. "
                f"The scanner identified <b>{len(findings)}</b> security findings."
            ),
            body_style
        )
    )

    summary_data = [
        [
            Paragraph(
                "<b>Severity</b>",
                body_style
            ),
            Paragraph(
                "<b>Findings</b>",
                body_style
            )
        ],
        [
            "Critical",
            str(severity_counts["Critical"])
        ],
        [
            "High",
            str(severity_counts["High"])
        ],
        [
            "Medium",
            str(severity_counts["Medium"])
        ],
        [
            "Low",
            str(severity_counts["Low"])
        ],
        [
            "Informational",
            str(severity_counts["Info"])
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[
            80 * mm,
            40 * mm
        ]
    )

    summary_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#0f7a4d")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#d1d5db")
            ),
            (
                "ALIGN",
                (1, 1),
                (1, -1),
                "CENTER"
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    colors.white,
                    colors.HexColor("#f8faf9")
                ]
            )
        ])
    )

    story.append(
        summary_table
    )

    story.append(
        Spacer(1, 12 * mm)
    )

    # ==================================================
    # FINDINGS
    # ==================================================

    if comparison_stats:
        story.append(
            Paragraph(
                "Comparison Summary",
                heading_style
            )
        )
        story.append(
            Paragraph(
                f"This scan was compared with the previous Scan #{previous_scan.id}.",
                body_style
            )
        )
        
        comp_data = [
            [Paragraph("<b>Metric</b>", body_style), Paragraph("<b>Count</b>", body_style)],
            ["New Findings", str(len(comparison_stats["new_findings"]))],
            ["Fixed Findings", str(len(comparison_stats["fixed_findings"]))],
            ["Severity Increased", str(len(comparison_stats["severity_increase"]))],
            ["Severity Decreased", str(len(comparison_stats["severity_decrease"]))],
            ["Unchanged Findings", str(len(comparison_stats["unchanged_findings"]))]
        ]
        
        comp_table = Table(comp_data, colWidths=[80 * mm, 40 * mm])
        comp_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563eb")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("ALIGN", (1, 1), (1, -1), "CENTER"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8faf9")])
            ])
        )
        story.append(comp_table)
        story.append(Spacer(1, 12 * mm))

    story.append(
        Paragraph(
            "Detailed Findings",
            heading_style
        )
    )

    if not findings:

        story.append(
            Paragraph(
                "No security findings were detected.",
                body_style
            )
        )

    else:

        for index, finding in enumerate(
            findings,
            start=1
        ):

            story.append(
                Paragraph(
                    (
                        f"{index}. "
                        f"{finding.vulnerability_type}"
                    ),
                    subheading_style
                )
            )

            metadata = [
                [
                    Paragraph(
                        "<b>Severity</b>",
                        small_style
                    ),
                    Paragraph(
                        str(finding.severity),
                        small_style
                    ),
                    Paragraph(
                        "<b>Confidence</b>",
                        small_style
                    ),
                    Paragraph(
                        str(
                            finding.confidence
                            or "—"
                        ),
                        small_style
                    )
                ],
                [
                    Paragraph(
                        "<b>URL</b>",
                        small_style
                    ),
                    Paragraph(
                        str(finding.url),
                        small_style
                    ),
                    Paragraph(
                        "<b>Parameter</b>",
                        small_style
                    ),
                    Paragraph(
                        str(
                            finding.parameter
                            or "—"
                        ),
                        small_style
                    )
                ]
            ]

            metadata_table = Table(
                metadata,
                colWidths=[
                    25 * mm,
                    60 * mm,
                    25 * mm,
                    50 * mm
                ]
            )

            metadata_table.setStyle(
                TableStyle([
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, -1),
                        colors.HexColor("#f0f5f2")
                    ),
                    (
                        "BACKGROUND",
                        (2, 0),
                        (2, -1),
                        colors.HexColor("#f0f5f2")
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.HexColor("#d1d5db")
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP"
                    )
                ])
            )

            story.append(
                metadata_table
            )

            story.append(
                Spacer(1, 4 * mm)
            )

            if finding.description:

                story.append(
                    Paragraph(
                        "<b>Description</b>",
                        body_style
                    )
                )

                story.append(
                    Paragraph(
                        str(finding.description),
                        body_style
                    )
                )

            if finding.impact:

                story.append(
                    Paragraph(
                        "<b>Potential Impact</b>",
                        body_style
                    )
                )

                story.append(
                    Paragraph(
                        str(finding.impact),
                        body_style
                    )
                )

            if finding.evidence:

                story.append(
                    Paragraph(
                        "<b>Evidence</b>",
                        body_style
                    )
                )

                evidence_table = Table(
                    [[
                        Paragraph(
                            str(finding.evidence),
                            small_style
                        )
                    ]],
                    colWidths=[
                        160 * mm
                    ]
                )

                evidence_table.setStyle(
                    TableStyle([
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, -1),
                            colors.HexColor("#f3f4f6")
                        ),
                        (
                            "BOX",
                            (0, 0),
                            (-1, -1),
                            0.5,
                            colors.HexColor("#d1d5db")
                        ),
                        (
                            "LEFTPADDING",
                            (0, 0),
                            (-1, -1),
                            8
                        ),
                        (
                            "RIGHTPADDING",
                            (0, 0),
                            (-1, -1),
                            8
                        ),
                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            7
                        ),
                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            7
                        )
                    ])
                )

                story.append(
                    evidence_table
                )

                story.append(
                    Spacer(1, 4 * mm)
                )

            if finding.remediation:

                story.append(
                    Paragraph(
                        "<b>Remediation</b>",
                        body_style
                    )
                )

                remediation_table = Table(
                    [[
                        Paragraph(
                            str(finding.remediation),
                            small_style
                        )
                    ]],
                    colWidths=[
                        160 * mm
                    ]
                )

                remediation_table.setStyle(
                    TableStyle([
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, -1),
                            colors.HexColor("#ecfdf5")
                        ),
                        (
                            "BOX",
                            (0, 0),
                            (-1, -1),
                            0.5,
                            colors.HexColor("#86efac")
                        ),
                        (
                            "LEFTPADDING",
                            (0, 0),
                            (-1, -1),
                            8
                        ),
                        (
                            "RIGHTPADDING",
                            (0, 0),
                            (-1, -1),
                            8
                        ),
                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            7
                        ),
                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            7
                        )
                    ])
                )

                story.append(
                    remediation_table
                )

            story.append(
                Spacer(1, 8 * mm)
            )

    # ==================================================
    # FOOTER
    # ==================================================

    def add_page_number(canvas, document):

        canvas.saveState()

        canvas.setFont(
            "Helvetica",
            8
        )

        canvas.setFillColor(
            colors.grey
        )

        canvas.drawCentredString(
            A4[0] / 2,
            10 * mm,
            f"SentinelScan • Page {document.page}"
        )

        canvas.restoreState()

    document.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
    )

    buffer.seek(0)

    return buffer