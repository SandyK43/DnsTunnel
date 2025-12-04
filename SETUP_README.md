# DNS Tunnel Detection Service - Setup Guide

## System Requirements

**Windows:**
- Windows 10 or Windows Server 2016 (or newer)
- Python 3.11 or higher
- 2GB RAM minimum, 1GB disk space
- Administrator privileges

**Linux:**
- Ubuntu 20.04+, CentOS 8+, or equivalent
- Python 3.11 or higher
- 2GB RAM minimum, 1GB disk space
- Root/sudo access

## Installation Methods

### Method 1: Windows Installer (Recommended for Windows)

**Step 1: Install Python**
1. Download Python 3.11+ from https://www.python.org/downloads/
2. Run installer and check "Add Python to PATH"
3. Verify: `python --version`

**Step 2: Run Installer**
1. Run `DNSTunnelDetection-Setup.exe` as Administrator
2. Follow the configuration wizard:
   - **Components**: Select what to install (Core is required)
   - **Database**: Choose SQLite (easy) or PostgreSQL (scalable)
   - **Thresholds**: Set detection sensitivity (default: 0.70 / 0.85)
   - **Alerting**: Configure Slack/Email notifications (optional)
   - **API**: Set host and port (default: 0.0.0.0:8000)
3. Installer will:
   - Install files to Program Files
   - Install Python dependencies
   - Train ML model (30-60 seconds)
   - Install Windows Service
   - Create Start Menu shortcuts

**Step 3: Verify Installation**
```cmd
# Check service is running
sc query DNSTunnelDetection

# Test API
curl http://localhost:8000/api/v1/health
```

**Access Points:**
- API Documentation: http://localhost:8000/docs
- Dashboard: http://localhost:8501 (if installed)
- Configuration: C:\Program Files\DNSTunnelDetection\config.yaml
- Logs: C:\Program Files\DNSTunnelDetection\logs

### Method 2: Python Installer (Cross-Platform)

**Step 1: Install Python**
- Download Python 3.11+ from https://www.python.org/downloads/
- Verify: `python --version` or `python3 --version`

**Step 2: Run Interactive Installer**

Windows:
```cmd
cd DnsTunnel
python install.py
```

Linux:
```bash
cd DnsTunnel
python3 install.py
```

**Step 3: Follow Prompts**

The installer will ask:
1. **Detection thresholds** (default: 0.70 / 0.85)
2. **Database** (SQLite or PostgreSQL)
3. **Slack notifications** (optional)
4. **Email notifications** (optional)
5. **JIRA integration** (optional)
6. **Automated blocking** (recommended: disabled initially)
7. **Log collection** (file-based, PCAP, or API-only)
8. **API settings** (default: 0.0.0.0:8000)

**Step 4: Install Service**

Windows:
```cmd
# Run as Administrator
install_service_windows.bat
net start DNSTunnelDetection
```

Linux:
```bash
sudo ./install_service_linux.sh
sudo systemctl start dns-tunnel-detection
```

**Step 5: Verify**
```bash
curl http://localhost:8000/api/v1/health
```

## Configuration

### Edit Settings

After installation, edit `config.yaml`:

**Location:**
- Windows: `C:\Program Files\DNSTunnelDetection\config.yaml`
- Linux: `/path/to/DnsTunnel/config.yaml`

**Common Changes:**

**Adjust Detection Sensitivity:**
```yaml
detection:
  threshold_suspicious: 0.75  # Higher = less sensitive (fewer alerts)
  threshold_high: 0.90        # Higher = only critical threats
```

**Enable Slack Alerts:**
```yaml
alerting:
  slack:
    enabled: true
    webhook_url: https://hooks.slack.com/services/YOUR/WEBHOOK
```

**Switch to PostgreSQL:**
```yaml
database:
  type: postgresql
  host: your-db-server.com
  port: 5432
  database: dns_tunnel_db
  username: dnsadmin
  password: your-password
```

**After editing config.yaml, restart service:**

Windows:
```cmd
net stop DNSTunnelDetection
net start DNSTunnelDetection
```

Linux:
```bash
sudo systemctl restart dns-tunnel-detection
```

## Adaptive Thresholds

The system automatically adjusts detection thresholds based on analyst feedback.

### How It Works

1. **Analyst Reviews Alert** → Marks as False Positive or True Positive
2. **System Tracks Feedback** → Calculates false positive rate
3. **Automatic Adjustment** → Every 6-24 hours:
   - If FP rate > 10%: Increase thresholds (less sensitive)
   - If FP rate < 1%: Decrease thresholds (more sensitive)
   - If FP rate 1-10%: No change (optimal)

### Submit Feedback

```bash
# Mark alert as false positive
curl -X POST http://localhost:8000/api/v1/feedback \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": 123,
    "is_false_positive": true,
    "analyst": "john.doe",
    "notes": "Benign CDN traffic"
  }'

# Mark alert as true positive
curl -X POST http://localhost:8000/api/v1/feedback \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": 124,
    "is_false_positive": false,
    "analyst": "jane.smith",
    "notes": "Confirmed DNS tunneling"
  }'
```

### Check Threshold Status

```bash
curl http://localhost:8000/api/v1/thresholds/status
```

Returns:
- Current threshold values
- False positive rate
- Recent threshold adjustments
- Performance metrics

### Disable Adaptive Thresholds

If you prefer manual threshold management:

```yaml
# config.yaml
adaptive_thresholds:
  enabled: false
```

Restart service to apply changes.

## API Endpoints

### Analyze DNS Query
```bash
curl -X POST http://localhost:8000/api/v1/dns/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "query": "www.example.com",
    "client_ip": "192.168.1.100"
  }'
```

### Get Statistics
```bash
curl http://localhost:8000/api/v1/stats
```

### List Alerts
```bash
# All alerts
curl http://localhost:8000/api/v1/alerts

# High severity only
curl "http://localhost:8000/api/v1/alerts?severity=HIGH"

# Unacknowledged only
curl "http://localhost:8000/api/v1/alerts?acknowledged=false"
```

### Acknowledge Alert
```bash
curl -X POST "http://localhost:8000/api/v1/alerts/123/acknowledge?acknowledged_by=john.doe"
```

### Submit Feedback
```bash
curl -X POST http://localhost:8000/api/v1/feedback \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": 123,
    "is_false_positive": true,
    "analyst": "john.doe",
    "notes": "CDN traffic"
  }'
```

### Get Threshold Status
```bash
curl http://localhost:8000/api/v1/thresholds/status
```

**Full API Documentation:** http://localhost:8000/docs

## Integration with Your Network

### Option 1: API Integration
Configure your DNS servers or SIEM to push queries to the API:
```bash
POST http://your-server:8000/api/v1/dns/analyze
Content-Type: application/json

{
  "query": "domain.com",
  "client_ip": "192.168.1.100"
}
```

### Option 2: Log File Monitoring
Point the collector at your DNS logs:

```yaml
# config.yaml
collector:
  enabled: true
  sources:
    - type: file
      path: /var/log/zeek/dns.log
      format: zeek  # or: bind, json
```

Supported formats:
- **Zeek** - Zeek DNS logs
- **Bind9** - Bind query logs
- **JSON** - Custom JSON format

### Option 3: Network Capture
Capture DNS traffic directly from network (requires root):

```yaml
collector:
  enabled: true
  sources:
    - type: pcap
      interface: eth0
      filter: "port 53"
```

## Monitoring and Logs

### View Service Logs

**Windows:**
```cmd
# Application logs
type C:\Program Files\DNSTunnelDetection\logs\dns_tunnel_*.log

# Service logs
eventvwr.msc
# Navigate to: Windows Logs → Application
```

**Linux:**
```bash
# Application logs
tail -f logs/dns_tunnel_*.log

# Service logs
sudo journalctl -u dns-tunnel-detection -f
```

### Check Service Status

**Windows:**
```cmd
sc query DNSTunnelDetection
# Or: Services.msc
```

**Linux:**
```bash
sudo systemctl status dns-tunnel-detection
```

### View Live Metrics

Access API documentation with live metrics:
```
http://localhost:8000/docs
```

## Training the ML Model

The installer trains an initial model with sample data. For better accuracy, retrain on YOUR network's DNS traffic:

### From Zeek Logs
```bash
python scripts/train_model.py --format zeek --input /path/to/dns.log
```

### From Bind9 Logs
```bash
python scripts/train_model.py --format bind --input /path/to/query.log
```

### From JSON
```bash
python scripts/train_model.py --format json --input /path/to/queries.json
```

### Generate Sample Data
```bash
python scripts/train_model.py --format sample --num-samples 10000
```

**Restart service after training:**
```bash
# Windows
net stop DNSTunnelDetection && net start DNSTunnelDetection

# Linux
sudo systemctl restart dns-tunnel-detection
```

## Troubleshooting

### Service Won't Start

**Check Logs:**
```bash
# Windows
type C:\Program Files\DNSTunnelDetection\logs\dns_tunnel_*.log

# Linux
tail -50 logs/dns_tunnel_*.log
```

**Common Issues:**
- **Port 8000 in use**: Change port in config.yaml
- **Model not found**: Run `python scripts/train_model.py --format sample`
- **Database connection failed**: Check database settings in config.yaml
- **Python not found**: Ensure Python 3.11+ is installed and in PATH

### High False Positive Rate

**Short-term fix:**
```yaml
# config.yaml
detection:
  threshold_suspicious: 0.75  # Increase from 0.70
  threshold_high: 0.90        # Increase from 0.85
```

**Long-term fix:**
1. Retrain model on your actual DNS traffic
2. Let adaptive thresholds learn (100+ feedback samples)
3. Whitelist known high-entropy domains (CDNs, cloud services)

### No Alerts Triggering

1. **Test with high-entropy query:**
   ```bash
   curl -X POST http://localhost:8000/api/v1/dns/analyze \
     -H "Content-Type: application/json" \
     -d '{"query": "a3d8f9b2c1e4g7h6j9k8l5m2n1o0p3q6r9s8.test.com", "client_ip": "10.0.0.1"}'
   ```
2. **Lower thresholds in config.yaml**
3. **Check alerting configuration** (Slack/Email credentials)

### Database Connection Issues

**SQLite:**
- Check file permissions on `data/dns_tunnel.db`
- Ensure `data/` directory exists and is writable

**PostgreSQL:**
- Verify host/port/credentials in config.yaml
- Test connection: `psql -h host -U username -d database`
- Check PostgreSQL is running and accessible

### Permission Denied Errors

**Windows:**
- Run Command Prompt as Administrator
- Check folder permissions in Program Files

**Linux:**
- Run installer with `sudo`
- Check file ownership: `ls -la`
- Fix permissions: `sudo chown -R username:username /path/to/DnsTunnel`

## Uninstallation

### Windows Installer

1. **Control Panel** → Programs → Uninstall a program
2. Select "DNS Tunnel Detection Service"
3. Click Uninstall

Or via Start Menu → DNS Tunnel Detection Service → Uninstall

### Manual Uninstall

**Windows:**
```cmd
# Stop service
net stop DNSTunnelDetection

# Remove service
sc delete DNSTunnelDetection

# Delete files
rmdir /s /q "C:\Program Files\DNSTunnelDetection"
```

**Linux:**
```bash
# Stop service
sudo systemctl stop dns-tunnel-detection

# Disable service
sudo systemctl disable dns-tunnel-detection

# Remove service file
sudo rm /etc/systemd/system/dns-tunnel-detection.service
sudo systemctl daemon-reload

# Delete files
sudo rm -rf /path/to/DnsTunnel
```

## Production Deployment Checklist

Before deploying to production:

- [ ] Change default passwords in config.yaml
- [ ] Set appropriate detection thresholds for your network
- [ ] Configure at least one alerting channel (Slack/Email/JIRA)
- [ ] Test alerting with sample high-entropy queries
- [ ] Train model on your actual DNS traffic
- [ ] Document incident response procedures
- [ ] Configure firewall rules (restrict API access)
- [ ] Set up log rotation (automatic by default)
- [ ] Schedule weekly model retraining
- [ ] Test backup and restore procedures
- [ ] Enable SSL/TLS for API endpoint (production)
- [ ] Configure monitoring/alerting for service health

## Security Considerations

### API Access Control
Restrict API access using firewall rules:

**Windows:**
```cmd
netsh advfirewall firewall add rule name="DNS Tunnel API" dir=in action=allow protocol=TCP localport=8000 remoteip=192.168.1.0/24
```

**Linux:**
```bash
sudo iptables -A INPUT -p tcp --dport 8000 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8000 -j DROP
```

### Configuration File Security
Protect config.yaml (contains passwords):

**Windows:**
- Right-click config.yaml → Properties → Security
- Remove all users except SYSTEM and Administrators

**Linux:**
```bash
chmod 600 config.yaml
chown root:root config.yaml
```

### Enable SSL/TLS (Production)
For production, enable HTTPS:

1. Obtain SSL certificate
2. Configure in config.yaml:
   ```yaml
   api:
     ssl_enabled: true
     ssl_cert: /path/to/cert.pem
     ssl_key: /path/to/key.pem
   ```
3. Restart service

## Getting Help

- **API Documentation:** http://localhost:8000/docs (when service is running)
- **GitHub Issues:** https://github.com/SandyK43/DnsTunnel/issues
- **Main README:** See README.md in installation directory

## Quick Reference

### Service Commands

| Task | Windows | Linux |
|------|---------|-------|
| Start | `net start DNSTunnelDetection` | `sudo systemctl start dns-tunnel-detection` |
| Stop | `net stop DNSTunnelDetection` | `sudo systemctl stop dns-tunnel-detection` |
| Restart | `net stop ... && net start ...` | `sudo systemctl restart dns-tunnel-detection` |
| Status | `sc query DNSTunnelDetection` | `sudo systemctl status dns-tunnel-detection` |
| Logs | `type C:\...\logs\*.log` | `sudo journalctl -u dns-tunnel-detection -f` |

### Common Configuration Changes

| Change | Config.yaml Section | Restart Required |
|--------|---------------------|------------------|
| Detection thresholds | `detection:` | Yes |
| Database settings | `database:` | Yes |
| Slack webhook | `alerting: slack:` | Yes |
| Email settings | `alerting: email:` | Yes |
| API port | `api: port:` | Yes |
| Adaptive thresholds | `adaptive_thresholds:` | Yes |

### Default Ports

- **API**: 8000
- **Dashboard**: 8501 (if installed)
- **Prometheus**: 9090 (if installed)

---

**Installation complete?** Access API documentation at http://localhost:8000/docs
