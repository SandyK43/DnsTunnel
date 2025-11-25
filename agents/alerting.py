"""
Alerting Agent
Sends alerts through multiple channels: Slack, Teams, Email, JIRA.
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import asyncio
import httpx
from loguru import logger

try:
    from jira import JIRA
    JIRA_AVAILABLE = True
except ImportError:
    JIRA_AVAILABLE = False


class AlertThrottler:
    """Prevents alert spam by throttling repeated alerts."""
    
    def __init__(self, throttle_seconds: int = 300):
        """
        Args:
            throttle_seconds: Minimum time between alerts for same domain
        """
        self.throttle_seconds = throttle_seconds
        self.last_alert_time: Dict[str, datetime] = {}
    
    def should_alert(self, domain: str) -> bool:
        """Check if enough time has passed since last alert for this domain."""
        now = datetime.utcnow()
        
        if domain in self.last_alert_time:
            time_since_last = (now - self.last_alert_time[domain]).total_seconds()
            if time_since_last < self.throttle_seconds:
                return False
        
        self.last_alert_time[domain] = now
        return True


class AlertingAgent:
    """
    Sends security alerts through multiple channels.
    
    Supports:
    - Slack webhooks
    - Microsoft Teams webhooks
    - Email (SMTP)
    - JIRA ticket creation
    """
    
    def __init__(
        self,
        slack_webhook_url: Optional[str] = None,
        teams_webhook_url: Optional[str] = None,
        email_config: Optional[Dict] = None,
        jira_config: Optional[Dict] = None,
        throttle_seconds: int = 300,
        min_score_to_alert: float = 0.6
    ):
        """
        Args:
            slack_webhook_url: Slack incoming webhook URL
            teams_webhook_url: Teams incoming webhook URL
            email_config: Dict with SMTP settings
            jira_config: Dict with JIRA connection settings
            throttle_seconds: Alert throttling interval
            min_score_to_alert: Minimum anomaly score to trigger alert
        """
        self.slack_webhook_url = slack_webhook_url or os.getenv('SLACK_WEBHOOK_URL')
        self.teams_webhook_url = teams_webhook_url or os.getenv('TEAMS_WEBHOOK_URL')
        self.email_config = email_config or self._load_email_config()
        self.jira_config = jira_config or self._load_jira_config()
        self.min_score_to_alert = min_score_to_alert
        self.throttler = AlertThrottler(throttle_seconds)
        self.jira_client = None
        
        if self.jira_config and JIRA_AVAILABLE:
            self._init_jira_client()
    
    def _load_email_config(self) -> Dict:
        """Load email configuration from environment."""
        return {
            'smtp_host': os.getenv('EMAIL_SMTP_HOST', 'smtp.gmail.com'),
            'smtp_port': int(os.getenv('EMAIL_SMTP_PORT', '587')),
            'from_addr': os.getenv('EMAIL_FROM', ''),
            'to_addr': os.getenv('EMAIL_TO', ''),
            'username': os.getenv('EMAIL_USERNAME', ''),
            'password': os.getenv('EMAIL_PASSWORD', '')
        }
    
    def _load_jira_config(self) -> Optional[Dict]:
        """Load JIRA configuration from environment."""
        url = os.getenv('JIRA_URL')
        if not url:
            return None
        
        return {
            'url': url,
            'username': os.getenv('JIRA_USERNAME', ''),
            'api_token': os.getenv('JIRA_API_TOKEN', ''),
            'project_key': os.getenv('JIRA_PROJECT_KEY', 'SEC')
        }
    
    def _init_jira_client(self):
        """Initialize JIRA client."""
        if not self.jira_config:
            return
        
        try:
            self.jira_client = JIRA(
                server=self.jira_config['url'],
                basic_auth=(
                    self.jira_config['username'],
                    self.jira_config['api_token']
                )
            )
            logger.info("JIRA client initialized")
        except Exception as e:
            logger.error(f"Failed to initialize JIRA client: {e}")
    
    async def send_alert(self, alert_data: Dict) -> Dict[str, bool]:
        """
        Send alert through all configured channels.
        
        Args:
            alert_data: Dict with alert information
            
        Returns:
            Dict indicating success/failure for each channel
        """
        # Check if we should alert
        if alert_data.get('anomaly_score', 0) < self.min_score_to_alert:
            logger.debug(f"Score {alert_data.get('anomaly_score')} below threshold, skipping alert")
            return {}
        
        domain = alert_data.get('domain', 'unknown')
        if not self.throttler.should_alert(domain):
            logger.debug(f"Alert throttled for domain: {domain}")
            return {}
        
        results = {}
        
        # Send to all channels concurrently
        tasks = []
        
        if self.slack_webhook_url:
            tasks.append(('slack', self._send_slack_alert(alert_data)))
        
        if self.teams_webhook_url:
            tasks.append(('teams', self._send_teams_alert(alert_data)))
        
        if self.email_config.get('from_addr') and self.email_config.get('to_addr'):
            tasks.append(('email', self._send_email_alert(alert_data)))
        
        if self.jira_client:
            tasks.append(('jira', self._create_jira_ticket(alert_data)))
        
        # Execute all tasks
        for channel, task in tasks:
            try:
                success = await task
                results[channel] = success
            except Exception as e:
                logger.error(f"Failed to send {channel} alert: {e}")
                results[channel] = False
        
        return results
    
    async def _send_slack_alert(self, alert_data: Dict) -> bool:
        """Send alert to Slack."""
        try:
            severity = alert_data.get('severity', 'UNKNOWN')
            score = alert_data.get('anomaly_score', 0)
            domain = alert_data.get('domain', 'unknown')
            client_ip = alert_data.get('client_ip', 'unknown')
            
            # Choose color based on severity
            color_map = {
                'HIGH': '#ff0000',
                'SUSPICIOUS': '#ffa500',
                'NORMAL': '#00ff00'
            }
            color = color_map.get(severity, '#808080')
            
            # Choose emoji
            emoji_map = {
                'HIGH': '🚨',
                'SUSPICIOUS': '⚠️',
                'NORMAL': 'ℹ️'
            }
            emoji = emoji_map.get(severity, '❓')
            
            payload = {
                "text": f"{emoji} DNS Tunneling Detection Alert",
                "attachments": [
                    {
                        "color": color,
                        "title": f"{severity} Severity Alert",
                        "fields": [
                            {
                                "title": "Domain",
                                "value": f"`{domain}`",
                                "short": True
                            },
                            {
                                "title": "Client IP",
                                "value": f"`{client_ip}`",
                                "short": True
                            },
                            {
                                "title": "Anomaly Score",
                                "value": f"{score:.3f}",
                                "short": True
                            },
                            {
                                "title": "Timestamp",
                                "value": alert_data.get('timestamp', datetime.utcnow()).strftime('%Y-%m-%d %H:%M:%S UTC'),
                                "short": True
                            }
                        ],
                        "footer": "DNS Tunneling Detection Service",
                        "ts": int(datetime.utcnow().timestamp())
                    }
                ]
            }
            
            # Add feature details if available
            if 'features' in alert_data:
                features = alert_data['features']
                feature_text = "\n".join([
                    f"• Entropy: {features.get('entropy', 0):.2f}",
                    f"• Length: {features.get('len_q', 0)}",
                    f"• QPS: {features.get('qps', 0):.2f}"
                ])
                payload["attachments"][0]["fields"].append({
                    "title": "Key Features",
                    "value": feature_text,
                    "short": False
                })
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.slack_webhook_url,
                    json=payload,
                    timeout=10.0
                )
                response.raise_for_status()
            
            logger.info(f"Sent Slack alert for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False
    
    async def _send_teams_alert(self, alert_data: Dict) -> bool:
        """Send alert to Microsoft Teams."""
        try:
            severity = alert_data.get('severity', 'UNKNOWN')
            score = alert_data.get('anomaly_score', 0)
            domain = alert_data.get('domain', 'unknown')
            client_ip = alert_data.get('client_ip', 'unknown')
            
            # Teams adaptive card
            payload = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": f"DNS Tunneling Alert: {severity}",
                "themeColor": "FF0000" if severity == "HIGH" else "FFA500",
                "title": "🚨 DNS Tunneling Detection Alert",
                "sections": [
                    {
                        "activityTitle": f"{severity} Severity Detection",
                        "facts": [
                            {"name": "Domain", "value": domain},
                            {"name": "Client IP", "value": client_ip},
                            {"name": "Anomaly Score", "value": f"{score:.3f}"},
                            {"name": "Timestamp", "value": alert_data.get('timestamp', datetime.utcnow()).strftime('%Y-%m-%d %H:%M:%S UTC')}
                        ]
                    }
                ]
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.teams_webhook_url,
                    json=payload,
                    timeout=10.0
                )
                response.raise_for_status()
            
            logger.info(f"Sent Teams alert for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Teams alert: {e}")
            return False
    
    async def _send_email_alert(self, alert_data: Dict) -> bool:
        """Send alert via email."""
        try:
            severity = alert_data.get('severity', 'UNKNOWN')
            score = alert_data.get('anomaly_score', 0)
            domain = alert_data.get('domain', 'unknown')
            client_ip = alert_data.get('client_ip', 'unknown')
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{severity}] DNS Tunneling Alert: {domain}"
            msg['From'] = self.email_config['from_addr']
            msg['To'] = self.email_config['to_addr']
            
            # HTML body
            html_body = f"""
            <html>
            <body>
                <h2 style="color: {'red' if severity == 'HIGH' else 'orange'};">
                    DNS Tunneling Detection Alert
                </h2>
                <p><strong>Severity:</strong> {severity}</p>
                <p><strong>Domain:</strong> <code>{domain}</code></p>
                <p><strong>Client IP:</strong> <code>{client_ip}</code></p>
                <p><strong>Anomaly Score:</strong> {score:.3f}</p>
                <p><strong>Timestamp:</strong> {alert_data.get('timestamp', datetime.utcnow()).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                
                <h3>Recommended Actions:</h3>
                <ul>
                    <li>Investigate client system for malware</li>
                    <li>Review DNS query logs for pattern</li>
                    <li>Consider blocking domain if confirmed malicious</li>
                </ul>
                
                <hr>
                <p><small>DNS Tunneling Detection Service v1.0</small></p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html_body, 'html'))
            
            # Send email (run in thread to avoid blocking)
            await asyncio.get_event_loop().run_in_executor(
                None,
                self._send_smtp_email,
                msg
            )
            
            logger.info(f"Sent email alert for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False
    
    def _send_smtp_email(self, msg: MIMEMultipart):
        """Send email via SMTP (blocking)."""
        with smtplib.SMTP(self.email_config['smtp_host'], self.email_config['smtp_port']) as server:
            server.starttls()
            if self.email_config['username'] and self.email_config['password']:
                server.login(self.email_config['username'], self.email_config['password'])
            server.send_message(msg)
    
    async def _create_jira_ticket(self, alert_data: Dict) -> bool:
        """Create JIRA ticket for high-severity alerts."""
        if not self.jira_client:
            return False
        
        try:
            severity = alert_data.get('severity', 'UNKNOWN')
            
            # Only create tickets for HIGH severity
            if severity != 'HIGH':
                return True
            
            score = alert_data.get('anomaly_score', 0)
            domain = alert_data.get('domain', 'unknown')
            client_ip = alert_data.get('client_ip', 'unknown')
            
            # Create ticket description
            description = f"""
DNS Tunneling activity detected with HIGH confidence.

*Domain:* {domain}
*Client IP:* {client_ip}
*Anomaly Score:* {score:.3f}
*Timestamp:* {alert_data.get('timestamp', datetime.utcnow()).strftime('%Y-%m-%d %H:%M:%S UTC')}

*Recommended Actions:*
# Investigate client system {client_ip} for malware
# Review full DNS query logs for the past 24 hours
# Check for data exfiltration indicators
# Consider quarantining the affected system
# Block domain {domain} if confirmed malicious

*Detection Method:* Isolation Forest ML Model
            """
            
            issue_dict = {
                'project': {'key': self.jira_config['project_key']},
                'summary': f'DNS Tunneling Detected: {domain}',
                'description': description,
                'issuetype': {'name': 'Bug'},
                'priority': {'name': 'High'},
                'labels': ['security', 'dns-tunneling', 'automated-detection']
            }
            
            # Create ticket in thread
            await asyncio.get_event_loop().run_in_executor(
                None,
                self.jira_client.create_issue,
                issue_dict
            )
            
            logger.info(f"Created JIRA ticket for {domain}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create JIRA ticket: {e}")
            return False


# Example usage
async def main():
    """Example usage."""
    alerting = AlertingAgent(
        slack_webhook_url="https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
        min_score_to_alert=0.6
    )
    
    alert_data = {
        'severity': 'HIGH',
        'anomaly_score': 0.87,
        'domain': 'aaaaaabbbbbbccccccdddddd.evil.com',
        'client_ip': '10.0.1.50',
        'timestamp': datetime.utcnow(),
        'features': {
            'entropy': 4.2,
            'len_q': 67,
            'qps': 15.3
        }
    }
    
    results = await alerting.send_alert(alert_data)
    print(f"Alert results: {results}")


if __name__ == "__main__":
    asyncio.run(main())

