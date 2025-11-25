# DNS Tunneling Detection - Quick Start Guide

Get the DNS tunneling detection system running in 5 minutes!

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose installed
- 8GB+ RAM recommended
- Ports 3000, 5432, 8000 available

### Option 1: Using Makefile (Recommended)

```bash
# One command to build, start, and train
make quickstart

# Access the services:
# - API Docs: http://localhost:8000/docs
# - Grafana: http://localhost:3000 (admin/admin123)
```

### Option 2: Manual Setup

```bash
# 1. Build and start services
docker-compose up -d

# 2. Wait for services to start (30 seconds)
sleep 30

# 3. Train the ML model
docker-compose exec api python scripts/train_model.py --format sample --num-samples 2000

# 4. Done! Access at http://localhost:8000/docs
```

## 🎬 Run Demo

See the detection in action:

```bash
# Run full attack simulation demo
docker-compose exec api python demo/simulate_attack.py --type full

# Watch alerts appear in Grafana: http://localhost:3000
```

## 📊 View Results

1. **API Documentation**: http://localhost:8000/docs
   - Interactive API testing
   
2. **Grafana Dashboard**: http://localhost:3000
   - Username: `admin`
   - Password: `admin123`
   - Dashboard: "DNS Tunneling Detection Dashboard"
   
3. **Prometheus Metrics**: http://localhost:9090

4. **Get System Stats**:
   ```bash
   curl http://localhost:8000/api/v1/stats | jq
   ```

5. **List Alerts**:
   ```bash
   curl http://localhost:8000/api/v1/alerts | jq
   ```

## 🧪 Test Detection

### Test with curl

```bash
# Normal query (should be NORMAL)
curl -X POST http://localhost:8000/api/v1/dns/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "query": "www.google.com",
    "client_ip": "192.168.1.100"
  }'

# Suspicious query (should be HIGH)
curl -X POST http://localhost:8000/api/v1/dns/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "query": "aaabbbcccdddeeefffggghhh123456.evil.com",
    "client_ip": "10.0.1.50"
  }'
```

### Simulate Different Attacks

```bash
# dnscat2 simulation
docker-compose exec api python demo/simulate_attack.py --type dnscat2 --queries 20

# iodine simulation
docker-compose exec api python demo/simulate_attack.py --type iodine --queries 20

# Custom exfiltration
docker-compose exec api python demo/simulate_attack.py --type custom --queries 15
```

## 📈 Generate Sample Data

```bash
# Generate mixed benign + malicious DNS logs
docker-compose exec api python scripts/generate_sample_logs.py \
  --benign 1000 \
  --malicious 50 \
  --tunnel-type dnscat2 \
  --output /app/data/sample_dns.log
```

## 📄 Generate Incident Report

```bash
# Create PDF report for last 24 hours
docker-compose exec api python scripts/report_generator.py \
  --hours 24 \
  --output /app/reports/incident_report.pdf

# Download report
docker cp dns-tunnel-api:/app/reports/incident_report.pdf ./incident_report.pdf
```

## 🔧 Configuration

### Enable Slack Alerts

Edit `.env`:
```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

Restart services:
```bash
docker-compose restart api
```

### Enable Auto-Response

⚠️ **Use with caution in production!**

Edit `.env`:
```bash
ENABLE_AUTO_RESPONSE=true
ANOMALY_THRESHOLD_HIGH=0.8
```

### Adjust Detection Sensitivity

Edit `.env`:
```bash
# More sensitive (more alerts)
ANOMALY_THRESHOLD_SUSPICIOUS=0.5
ANOMALY_THRESHOLD_HIGH=0.7

# Less sensitive (fewer alerts)
ANOMALY_THRESHOLD_SUSPICIOUS=0.7
ANOMALY_THRESHOLD_HIGH=0.85
```

## 🔍 Monitoring

### View Logs

```bash
# All services
docker-compose logs -f

# API only
docker-compose logs -f api

# Specific service
docker-compose logs -f collector
```

### Health Check

```bash
curl http://localhost:8000/api/v1/health
```

## 🛑 Stop Services

```bash
# Stop but keep data
docker-compose down

# Stop and remove all data
docker-compose down -v
```

## 🧹 Clean Up

```bash
# Remove everything (containers, volumes, models, data)
make clean
```

## ⚡ Common Commands

```bash
# View real-time stats
watch -n 5 'curl -s http://localhost:8000/api/v1/stats | jq'

# Count alerts
curl -s http://localhost:8000/api/v1/alerts | jq '.total'

# Open shell in API container
docker-compose exec api /bin/bash

# Retrain model with new data
docker-compose exec api python scripts/train_model.py --input /app/data/baseline.log
```

## 🐛 Troubleshooting

### Services won't start
```bash
# Check if ports are in use
lsof -i :8000
lsof -i :3000
lsof -i :5432

# Check Docker resources
docker stats
```

### Model not found
```bash
# Train the model
make train-model
```

### Database connection error
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# View PostgreSQL logs
docker-compose logs postgres
```

### No alerts appearing
```bash
# Check threshold settings
echo $ANOMALY_THRESHOLD_SUSPICIOUS

# Send test suspicious query
curl -X POST http://localhost:8000/api/v1/dns/analyze \
  -H "Content-Type: application/json" \
  -d '{"query":"test123456789abcdefghijk.evil.com","client_ip":"10.0.1.99"}'
```

## 📚 Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Configure Slack/Teams/Email alerts
- Integrate with your Zeek DNS logs
- Customize detection thresholds
- Set up JIRA ticket creation
- Enable automated response actions

## 🎯 Production Deployment

For production use:

1. Change default passwords in `.env`
2. Use proper SSL/TLS certificates
3. Set up proper logging and monitoring
4. Configure backups for PostgreSQL
5. Review and adjust security settings
6. Test alert channels thoroughly
7. Document your incident response procedures

---

**Questions?** Check the full documentation or create an issue!

