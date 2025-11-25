"""
Incident Report Generator
Creates PDF reports for DNS tunneling detection incidents.
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict
import io

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image as RLImage
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.database import get_db_context
from api.models import Alert, DNSQuery


class IncidentReportGenerator:
    """Generates PDF incident reports for DNS tunneling detections."""
    
    def __init__(self, output_path: str = "./reports/incident_report.pdf"):
        """
        Args:
            output_path: Path to save the PDF report
        """
        self.output_path = output_path
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Create PDF document
        self.doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()
        self.story = []
    
    def _create_custom_styles(self):
        """Create custom paragraph styles."""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#CC0000'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#333333'),
            spaceAfter=12,
            spaceBefore=12
        ))
    
    def add_title_page(self, alert_count: int, severity: str):
        """Add title page to report."""
        # Title
        title = Paragraph(
            "DNS TUNNELING DETECTION<br/>INCIDENT REPORT",
            self.styles['CustomTitle']
        )
        self.story.append(title)
        self.story.append(Spacer(1, 0.5*inch))
        
        # Report metadata
        info_data = [
            ['Report Generated:', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Alert Count:', str(alert_count)],
            ['Highest Severity:', severity],
            ['Report ID:', f"DNS-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"]
        ]
        
        info_table = Table(info_data, colWidths=[2.5*inch, 3.5*inch])
        info_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        
        self.story.append(info_table)
        self.story.append(Spacer(1, 0.5*inch))
        
        # Confidentiality notice
        notice = Paragraph(
            "<b>CONFIDENTIAL - SECURITY INCIDENT REPORT</b><br/>"
            "This report contains sensitive security information. "
            "Distribution is restricted to authorized personnel only.",
            self.styles['Normal']
        )
        self.story.append(notice)
        self.story.append(PageBreak())
    
    def add_executive_summary(self, summary_data: Dict):
        """Add executive summary section."""
        header = Paragraph("Executive Summary", self.styles['SectionHeader'])
        self.story.append(header)
        
        summary_text = f"""
        This report documents DNS tunneling activity detected by the automated 
        detection system over the past 24 hours. The system identified 
        <b>{summary_data['total_alerts']}</b> suspicious DNS queries, including 
        <b>{summary_data['high_severity']}</b> high-severity alerts requiring 
        immediate attention.
        <br/><br/>
        <b>Key Findings:</b><br/>
        • Total Suspicious Queries: {summary_data['total_alerts']}<br/>
        • High Severity Alerts: {summary_data['high_severity']}<br/>
        • Suspicious Alerts: {summary_data['suspicious_severity']}<br/>
        • Affected Systems: {summary_data['affected_hosts']}<br/>
        • Malicious Domains: {summary_data['malicious_domains']}<br/>
        <br/>
        <b>Recommended Actions:</b><br/>
        • Investigate affected hosts for malware infection<br/>
        • Block identified malicious domains<br/>
        • Review DNS logs for similar patterns<br/>
        • Consider network segmentation for compromised systems<br/>
        """
        
        summary_para = Paragraph(summary_text, self.styles['Normal'])
        self.story.append(summary_para)
        self.story.append(Spacer(1, 0.3*inch))
    
    def add_alert_timeline_chart(self, alerts: List[Alert]):
        """Add alert timeline visualization."""
        header = Paragraph("Alert Timeline", self.styles['SectionHeader'])
        self.story.append(header)
        
        # Create timeline chart
        df = pd.DataFrame([
            {'timestamp': a.timestamp, 'severity': a.severity, 'score': a.anomaly_score}
            for a in alerts
        ])
        
        if len(df) > 0:
            fig, ax = plt.subplots(figsize=(8, 4))
            
            # Plot by severity
            for severity, color in [('HIGH', 'red'), ('SUSPICIOUS', 'orange')]:
                subset = df[df['severity'] == severity]
                if len(subset) > 0:
                    ax.scatter(subset['timestamp'], subset['score'], 
                             c=color, label=severity, alpha=0.6, s=100)
            
            ax.set_xlabel('Time')
            ax.set_ylabel('Anomaly Score')
            ax.set_title('DNS Tunneling Detection Timeline')
            ax.legend()
            ax.grid(True, alpha=0.3)
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            # Save to buffer
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
            img_buffer.seek(0)
            plt.close()
            
            # Add to PDF
            img = RLImage(img_buffer, width=6*inch, height=3*inch)
            self.story.append(img)
            self.story.append(Spacer(1, 0.3*inch))
    
    def add_alert_details_table(self, alerts: List[Alert]):
        """Add detailed alert information table."""
        header = Paragraph("Alert Details", self.styles['SectionHeader'])
        self.story.append(header)
        
        # Prepare table data
        table_data = [['Timestamp', 'Domain', 'Client IP', 'Score', 'Severity']]
        
        for alert in alerts[:20]:  # Limit to top 20
            table_data.append([
                alert.timestamp.strftime('%Y-%m-%d %H:%M'),
                alert.domain[:40],  # Truncate long domains
                alert.client_ip,
                f"{alert.anomaly_score:.3f}",
                alert.severity
            ])
        
        # Create table
        table = Table(table_data, colWidths=[1.3*inch, 2.2*inch, 1.2*inch, 0.7*inch, 1*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
        ]))
        
        self.story.append(table)
        self.story.append(Spacer(1, 0.3*inch))
    
    def add_technical_analysis(self, alerts: List[Alert]):
        """Add technical analysis section."""
        header = Paragraph("Technical Analysis", self.styles['SectionHeader'])
        self.story.append(header)
        
        # Calculate statistics
        avg_entropy = sum(a.alert_data.get('features', {}).get('entropy', 0) for a in alerts) / len(alerts) if alerts else 0
        avg_length = sum(a.alert_data.get('features', {}).get('len_q', 0) for a in alerts) / len(alerts) if alerts else 0
        
        analysis_text = f"""
        <b>Behavioral Analysis:</b><br/>
        The detected queries exhibit characteristics consistent with DNS tunneling:<br/><br/>
        
        • <b>High Entropy:</b> Average entropy of {avg_entropy:.2f} indicates random-looking subdomains<br/>
        • <b>Excessive Length:</b> Average query length of {avg_length:.0f} characters exceeds normal patterns<br/>
        • <b>High Query Rate:</b> Abnormal query frequency from affected hosts<br/>
        • <b>Unusual Character Distribution:</b> High ratio of alphanumeric characters in subdomains<br/><br/>
        
        <b>Detection Method:</b><br/>
        Isolation Forest machine learning model trained on baseline benign DNS traffic. 
        The model identifies anomalies based on query entropy, length, label count, 
        character distribution, and temporal patterns.<br/><br/>
        
        <b>Confidence Level:</b> HIGH<br/>
        The combination of multiple anomalous features provides high confidence in the detection.
        """
        
        analysis_para = Paragraph(analysis_text, self.styles['Normal'])
        self.story.append(analysis_para)
        self.story.append(Spacer(1, 0.3*inch))
    
    def add_recommendations(self):
        """Add recommendations section."""
        header = Paragraph("Incident Response Recommendations", self.styles['SectionHeader'])
        self.story.append(header)
        
        recommendations = """
        <b>Immediate Actions (0-24 hours):</b><br/>
        1. Isolate affected systems from the network<br/>
        2. Block identified malicious domains at DNS and firewall level<br/>
        3. Collect forensic evidence from affected hosts<br/>
        4. Run antimalware scans on compromised systems<br/>
        5. Review authentication logs for lateral movement<br/><br/>
        
        <b>Short-term Actions (1-7 days):</b><br/>
        1. Conduct full incident investigation<br/>
        2. Identify root cause and initial infection vector<br/>
        3. Reimagine compromised systems if necessary<br/>
        4. Update detection rules based on findings<br/>
        5. Brief stakeholders on incident status<br/><br/>
        
        <b>Long-term Actions (1-3 months):</b><br/>
        1. Implement additional DNS monitoring controls<br/>
        2. Deploy DNS filtering/sinkholing solutions<br/>
        3. Conduct security awareness training<br/>
        4. Review and update incident response procedures<br/>
        5. Consider network segmentation improvements<br/>
        """
        
        rec_para = Paragraph(recommendations, self.styles['Normal'])
        self.story.append(rec_para)
    
    def generate(self, hours: int = 24):
        """Generate the complete PDF report."""
        print(f"Generating incident report for past {hours} hours...")
        
        # Fetch data from database
        with get_db_context() as db:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            
            # Get alerts
            alerts = db.query(Alert).filter(
                Alert.timestamp >= cutoff
            ).order_by(Alert.anomaly_score.desc()).all()
            
            if not alerts:
                print("No alerts found in the specified time period.")
                return False
            
            # Calculate summary data
            summary_data = {
                'total_alerts': len(alerts),
                'high_severity': len([a for a in alerts if a.severity == 'HIGH']),
                'suspicious_severity': len([a for a in alerts if a.severity == 'SUSPICIOUS']),
                'affected_hosts': len(set(a.client_ip for a in alerts)),
                'malicious_domains': len(set(a.domain for a in alerts))
            }
            
            highest_severity = 'HIGH' if summary_data['high_severity'] > 0 else 'SUSPICIOUS'
            
            # Build report
            self.add_title_page(len(alerts), highest_severity)
            self.add_executive_summary(summary_data)
            self.add_alert_timeline_chart(alerts)
            self.add_alert_details_table(alerts)
            self.add_technical_analysis(alerts)
            self.add_recommendations()
            
            # Generate PDF
            self.doc.build(self.story)
            
            print(f"✅ Report generated successfully: {self.output_path}")
            print(f"   Total alerts: {len(alerts)}")
            print(f"   High severity: {summary_data['high_severity']}")
            print(f"   Affected hosts: {summary_data['affected_hosts']}")
            
            return True


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Generate DNS tunneling incident report")
    parser.add_argument(
        '--hours',
        type=int,
        default=24,
        help='Time period in hours to include in report (default: 24)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='./reports/incident_report.pdf',
        help='Output PDF file path'
    )
    
    args = parser.parse_args()
    
    generator = IncidentReportGenerator(output_path=args.output)
    generator.generate(hours=args.hours)


if __name__ == "__main__":
    main()

