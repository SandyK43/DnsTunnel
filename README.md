# DNS Tunneling Detection Microservice

A production-grade, enterprise-ready microservice for detecting DNS tunneling attacks using machine learning and agentic architecture.

## 🎯 Overview

This system analyzes DNS traffic logs in real-time to detect covert tunneling behavior (dnscat2, iodine, custom exfiltration) using an Isolation Forest anomaly detection model. It provides real-time SOC alerts with optional automated remediation actions.

## 🏗️ Architecture

The solution uses an **agentic architecture** with autonomous components:

- **Log Collector Agent** — Ingests Zeek/Suricata DNS logs
- **Feature Extraction Agent** — Computes entropy, character ratios, and behavioral metrics
- **Anomaly Scoring Agent** — Isolation Forest ML model scoring
- **Alerting Agent** — Multi-channel notifications (Slack/Teams/Email/JIRA)
- **Dashboard Agent** — Real-time visual analytics with Grafana
- **Response Agent** — Automated remediation (firewall blocking, quarantine)

## 📊 Detection Features

Per-query features:
- Query length (`len_q`)
- Shannon entropy (`entropy`)
- Number of DNS labels (`num_labels`)
- Maximum label length (`max_label_len`)
- Digits ratio (`digits_ratio`)
- Non-alphanumeric ratio (`non_alnum_ratio`)

Time-window features:
- Queries per second (`qps`)
- Unique subdomains (`unique_subdomains`)
- Average entropy (`avg_entropy`)
- Maximum entropy (`max_entropy`)

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Zeek or Suricata DNS logs

### 1. Clone and Configure

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 2. Start Services

```bash
docker-compose up -d
```

This starts:
- API Server (port 8000)
- PostgreSQL database
- Redis cache
- Grafana dashboard (port 3000)
- All agent services

### 3. Train Initial Model

```bash
docker-compose exec api python scripts/train_model.py --input data/baseline_dns.log
```

### 4. Access Dashboard

Navigate to http://localhost:3000 (admin/admin123)

## 📡 API Endpoints

```
POST   /api/v1/dns/analyze          - Analyze single DNS query
POST   /api/v1/dns/batch             - Batch analysis
GET    /api/v1/alerts                - List alerts
GET    /api/v1/alerts/{id}           - Get alert details
GET    /api/v1/stats                 - System statistics
POST   /api/v1/response/block        - Manual block action
GET    /api/v1/health                - Health check
```

## 🔧 Configuration

Edit `config.yaml` for:
- Model parameters (contamination, estimators)
- Severity thresholds
- Alert channels
- Auto-response rules

Edit `.env` for:
- Database credentials
- Slack/Teams webhooks
- JIRA integration
- Email SMTP settings

## 📈 Model Training

Train on baseline (benign) DNS traffic:

```bash
python scripts/train_model.py \
  --input /path/to/benign_dns.log \
  --output models/isolation_forest.pkl \
  --contamination 0.01
```

## 🎬 Demo

```bash
# Start dashboard
docker-compose up -d

# Run demo attack simulation
python demo/simulate_attack.py --type dnscat2

# Watch alerts appear in Slack and Grafana
```

## 📊 Grafana Dashboards

Pre-configured panels:
- Anomaly score time series
- Top suspicious domains
- Query volume by severity
- Alert heatmap
- Feature distribution plots

## 🔔 Alert Example

```json
{
  "severity": "HIGH",
  "domain": "aaaaaabbbbbbccccccdddddd.evil.com",
  "anomaly_score": 0.87,
  "client_ip": "10.0.1.50",
  "timestamp": "2025-11-25T10:30:45Z",
  "features": {
    "entropy": 4.2,
    "len_q": 67,
    "qps": 15.3
  },
  "action_taken": "quarantined"
}
```

## 🛡️ Response Actions

When `ENABLE_AUTO_RESPONSE=true`:
- **Score ≥ 0.8**: Automatic firewall block
- **Score ≥ 0.6**: Alert SOC team
- **Score < 0.6**: Log only

## 🧪 Testing

```bash
pytest tests/ --cov=agents --cov-report=html
```

## 📦 Project Structure

```
DnsTunnel/
├── agents/              # Agent modules
│   ├── collector.py
│   ├── feature_extractor.py
│   ├── scorer.py
│   ├── alerting.py
│   └── response.py
├── api/                 # FastAPI application
│   ├── main.py
│   ├── routes/
│   └── models.py
├── models/              # ML models
├── scripts/             # Training and utilities
├── tests/               # Test suite
├── grafana/             # Dashboard configs
├── docker-compose.yml
└── README.md
```

## 🎓 Resume Bullet Point

> Designed and implemented a production-ready DNS tunneling detection microservice leveraging Zeek log ingestion, feature engineering, and Isolation Forest–based anomaly detection with real-time Slack alerting and automated response workflows, deployable via Docker for enterprise SOC environments.

## 📝 License

Internal Company Use Only

## 🤝 Contributing

Contact Security Engineering team for contributions.

## 📞 Support

Slack: #security-engineering
Email: security@company.com

