# Deployment Checklist - DNS Tunneling Detection

Use this checklist when deploying the system to production or demo environments.

## 📋 Pre-Deployment

### Infrastructure Requirements
- [ ] Docker 20.10+ installed
- [ ] Docker Compose 2.0+ installed
- [ ] Minimum 4GB RAM available
- [ ] 20GB disk space available
- [ ] Ports available: 3000, 5432, 6379, 8000, 9090

### Configuration Files
- [ ] Copy `.env.example` to `.env`
- [ ] Update database passwords in `.env`
- [ ] Configure Slack webhook URL (if using)
- [ ] Configure email SMTP settings (if using)
- [ ] Configure JIRA credentials (if using)
- [ ] Review `config.yaml` settings
- [ ] Set appropriate anomaly thresholds

### Security Review
- [ ] Change default database password
- [ ] Change default Grafana password
- [ ] Review CORS settings in API
- [ ] Configure firewall rules
- [ ] Set up SSL/TLS (if internet-facing)
- [ ] Review response agent permissions
- [ ] Disable auto-response in production (until tested)

## 🚀 Deployment Steps

### 1. Initial Setup
```bash
# Clone/copy project files
cd DnsTunnel

# Configure environment
cp .env.example .env
nano .env  # Edit configuration

# Build images
make build
```

### 2. Start Services
```bash
# Start all services
make up

# Verify services started
docker-compose ps
```

### 3. Initialize System
```bash
# Train ML model with sample data (for testing)
make train-model

# OR train with real baseline data
docker-compose exec api python scripts/train_model.py \
  --input /path/to/baseline_dns.log \
  --format zeek

# Verify model created
ls -lh models/
```

### 4. Verification
```bash
# Run verification script
docker-compose exec api python scripts/verify_installation.py

# Check health endpoint
curl http://localhost:8000/api/v1/health | jq

# Test API
curl -X POST http://localhost:8000/api/v1/dns/analyze \
  -H "Content-Type: application/json" \
  -d '{"query":"www.google.com","client_ip":"192.168.1.100"}' | jq
```

### 5. Access Interfaces
- [ ] API Documentation: http://localhost:8000/docs
- [ ] Grafana Dashboard: http://localhost:3000
- [ ] Prometheus Metrics: http://localhost:9090
- [ ] API Stats: http://localhost:8000/api/v1/stats

## 🧪 Testing

### Smoke Tests
```bash
# Generate test data
docker-compose exec api python scripts/generate_sample_logs.py \
  --benign 100 --malicious 10 --output /app/data/test.log

# Run demo attack simulation
docker-compose exec api python demo/simulate_attack.py --type full

# Check alerts generated
curl http://localhost:8000/api/v1/alerts | jq '.total'

# View Grafana dashboard
# Navigate to http://localhost:3000
```

### Alert Channel Tests
```bash
# If Slack configured, test alert
curl -X POST http://localhost:8000/api/v1/dns/analyze \
  -H "Content-Type: application/json" \
  -d '{"query":"aaaabbbbccccdddd.evil.com","client_ip":"10.0.1.99"}' | jq

# Check Slack channel for alert
```

### Report Generation Test
```bash
# Generate incident report
docker-compose exec api python scripts/report_generator.py \
  --hours 1 --output /app/reports/test_report.pdf

# Download report
docker cp dns-tunnel-api:/app/reports/test_report.pdf ./
```

## 📊 Production Integration

### Log Ingestion
- [ ] Configure Zeek log path in `.env`
- [ ] Mount Zeek log directory in `docker-compose.yml`
- [ ] Restart collector service
- [ ] Verify log ingestion in API logs

### Alert Routing
- [ ] Test Slack notifications
- [ ] Test email notifications
- [ ] Test JIRA ticket creation
- [ ] Configure alert throttling
- [ ] Set up on-call rotation

### Monitoring
- [ ] Add Grafana to monitoring dashboards
- [ ] Set up Prometheus alerting rules
- [ ] Configure log aggregation
- [ ] Set up uptime monitoring
- [ ] Configure backup strategy

### Response Actions
- [ ] **DO NOT enable auto-response initially**
- [ ] Test manual blocking in isolated environment
- [ ] Configure firewall API (if available)
- [ ] Test IP blocking without affecting production
- [ ] Document approval workflow
- [ ] Train SOC team on response procedures

## 🔧 Post-Deployment

### Day 1-7 (Baseline Period)
- [ ] Monitor for false positives
- [ ] Tune anomaly thresholds if needed
- [ ] Review all HIGH severity alerts
- [ ] Document false positive patterns
- [ ] Retrain model if necessary

### Week 2-4 (Optimization)
- [ ] Analyze detection accuracy
- [ ] Adjust alert throttling
- [ ] Fine-tune severity thresholds
- [ ] Add custom domain whitelists (if needed)
- [ ] Optimize query performance

### Ongoing Operations
- [ ] Review alerts weekly
- [ ] Retrain model monthly
- [ ] Update documentation
- [ ] Backup database weekly
- [ ] Review and update threat patterns

## 🛡️ Security Hardening

### Network Security
- [ ] Place behind VPN/private network
- [ ] Configure firewall rules
- [ ] Enable SSL/TLS for API
- [ ] Use secure database connections
- [ ] Restrict Grafana access

### Application Security
- [ ] Enable API authentication (JWT/OAuth2)
- [ ] Implement rate limiting
- [ ] Enable audit logging
- [ ] Secure webhook URLs
- [ ] Rotate API keys regularly

### Data Security
- [ ] Encrypt database connections
- [ ] Set up database encryption at rest
- [ ] Configure log retention policies
- [ ] Implement data anonymization (if needed)
- [ ] Regular security audits

## 📈 Scaling Considerations

### Vertical Scaling
- [ ] Increase container CPU limits
- [ ] Increase container memory limits
- [ ] Optimize PostgreSQL settings
- [ ] Add database indexes
- [ ] Enable query caching

### Horizontal Scaling
- [ ] Deploy multiple API instances
- [ ] Set up load balancer
- [ ] Configure Redis for session storage
- [ ] Enable Kafka for message queuing
- [ ] Set up database replication

## 🔄 Backup & Recovery

### Backup Strategy
- [ ] Database backups (daily)
- [ ] Model file backups (after retraining)
- [ ] Configuration backups
- [ ] Log archives
- [ ] Grafana dashboard exports

### Disaster Recovery
- [ ] Document recovery procedures
- [ ] Test restore process
- [ ] Maintain offline backups
- [ ] Set up monitoring for backup failures
- [ ] Define RTO/RPO targets

## 📞 Support & Maintenance

### Documentation
- [ ] Document custom configurations
- [ ] Create runbook for common issues
- [ ] Document alert response procedures
- [ ] Maintain change log
- [ ] Update architecture diagrams

### Team Training
- [ ] Train SOC analysts on system
- [ ] Document escalation procedures
- [ ] Create FAQ for common questions
- [ ] Schedule regular refresher training
- [ ] Maintain contact list

### Maintenance Windows
- [ ] Schedule regular updates
- [ ] Plan model retraining schedule
- [ ] Database maintenance windows
- [ ] System health checks
- [ ] Performance reviews

## ✅ Sign-off

### Deployment Approval
- [ ] Technical lead sign-off: _________________ Date: _______
- [ ] Security team sign-off: _________________ Date: _______
- [ ] Operations sign-off: _________________ Date: _______

### Go-Live Checklist
- [ ] All tests passed
- [ ] Monitoring configured
- [ ] Alerts configured
- [ ] Documentation complete
- [ ] Team trained
- [ ] Rollback plan documented
- [ ] Support contacts confirmed

### Post-Deployment Review (1 week)
- [ ] False positive rate acceptable
- [ ] True positive confirmations
- [ ] Performance metrics met
- [ ] No major incidents
- [ ] Team comfortable with operations

---

## 🆘 Emergency Contacts

**System Issues:**
- Technical Lead: __________________
- DevOps: __________________
- Database Admin: __________________

**Security Incidents:**
- Security Lead: __________________
- Incident Commander: __________________
- SOC Manager: __________________

**Escalation:**
- On-call rotation: __________________
- Emergency hotline: __________________

---

## 📝 Notes

[Add deployment-specific notes here]

---

**Deployment Date:** ____________
**Deployed By:** ____________
**Environment:** ☐ Development ☐ Staging ☐ Production
**Version:** 1.0.0

