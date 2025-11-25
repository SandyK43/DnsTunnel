# Demo Script - DNS Tunneling Detection System

This script walks through a live demonstration of the DNS tunneling detection system.

## 🎯 Demo Objectives

1. Show baseline normal DNS traffic monitoring
2. Demonstrate real-time detection of DNS tunneling attacks
3. Display multi-channel alerting (Slack, dashboard)
4. Show automated response capabilities
5. Generate incident report

**Duration**: ~10-15 minutes

---

## 📋 Pre-Demo Setup (5 minutes before)

### 1. Start Services

```bash
cd DnsTunnel
docker-compose up -d
```

### 2. Verify Services

```bash
# Check all services are healthy
docker-compose ps

# Expected: All services should be "healthy" or "running"
```

### 3. Train Model (if not already trained)

```bash
make train-model
```

### 4. Open Dashboard

- Navigate to http://localhost:3000
- Login: admin / admin123
- Open "DNS Tunneling Detection Dashboard"

### 5. Prepare Terminal Windows

Open 3 terminal windows:
- **Terminal 1**: For running demo commands
- **Terminal 2**: For tailing logs (`docker-compose logs -f api`)
- **Terminal 3**: For checking stats

---

## 🎬 Demo Script

### Phase 1: Introduction (2 minutes)

**Talk Track:**
> "Today I'm demonstrating a production-grade DNS tunneling detection system. DNS tunneling is a technique where attackers abuse DNS queries to exfiltrate data or establish command-and-control channels, bypassing traditional security controls."
>
> "This system uses an agentic architecture with specialized agents for log collection, feature extraction, ML-based anomaly detection, alerting, and automated response."

**Show:**
- Architecture diagram (from README.md or presentation)
- Grafana dashboard showing baseline state
- API documentation at http://localhost:8000/docs

---

### Phase 2: Baseline Normal Traffic (2 minutes)

**Talk Track:**
> "Let's start by generating normal DNS traffic to establish a baseline. The system uses an Isolation Forest ML model trained on benign DNS patterns."

**Command (Terminal 1):**
```bash
docker-compose exec api python demo/simulate_attack.py --type normal --queries 30 --delay 0.5
```

**Show:**
- Terminal 2 showing logs (queries marked as NORMAL)
- Grafana dashboard updating with queries
- Point out: Low anomaly scores (< 0.5)

**Talk Track:**
> "As you can see, legitimate traffic like google.com and github.com receives low anomaly scores and NORMAL severity classification."

---

### Phase 3: dnscat2 Attack Detection (3 minutes)

**Talk Track:**
> "Now let's simulate a dnscat2 DNS tunneling attack. dnscat2 is a popular tool that creates an encrypted C2 channel over DNS. Watch how the system detects this in real-time."

**Command (Terminal 1):**
```bash
docker-compose exec api python demo/simulate_attack.py --type dnscat2 --queries 20 --delay 1.5
```

**Show (as attacks happen):**
1. **Terminal 2**: Red warning messages showing detections
   - Point out HIGH severity
   - Point out high anomaly scores (> 0.8)

2. **Grafana Dashboard**:
   - Anomaly score spikes on timeline graph
   - New entries in "Top Suspicious Queries" table
   - Alert count increasing
   - HIGH severity alert counter

3. **Terminal 3** - Check stats:
```bash
curl -s http://localhost:8000/api/v1/stats | jq
```

**Talk Track:**
> "The system immediately detected the tunneling behavior. Notice the high entropy, unusual subdomain patterns, and elevated query rates that triggered HIGH severity alerts."

---

### Phase 4: iodine Attack Detection (2 minutes)

**Talk Track:**
> "Let's try a different tunneling tool - iodine, which uses base32 encoding. The ML model generalizes well to different tools."

**Command (Terminal 1):**
```bash
docker-compose exec api python demo/simulate_attack.py --type iodine --queries 15 --delay 2.0
```

**Show:**
- Similar detection pattern
- Different domain but same HIGH severity
- Grafana dashboard continuing to populate

---

### Phase 5: View Alerts (2 minutes)

**Talk Track:**
> "Let's examine the alerts the system generated."

**Command (Terminal 3):**
```bash
# List recent alerts
curl -s http://localhost:8000/api/v1/alerts?page=1&page_size=10 | jq

# Get specific alert details
curl -s http://localhost:8000/api/v1/alerts/1 | jq
```

**Show in Grafana:**
- "Top Alert Domains" table
- "Top Alert Sources" table
- "Alerts by Severity" pie chart
- "High Entropy Domains" table with feature values

**Talk Track:**
> "The system provides rich context for each alert including the anomaly score, detected features like entropy and query length, and affected client IPs."

---

### Phase 6: Alerting Channels (1 minute)

**Talk Track:**
> "In production, these alerts are sent through multiple channels for SOC team notification."

**Show:**
- Slack webhook configuration in code/config
- Teams integration
- Email alerting
- JIRA ticket creation (if configured)

**If Slack is configured:**
```bash
# Trigger a test alert
curl -X POST http://localhost:8000/api/v1/dns/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "query": "super-suspicious-tunnel-domain-12345678abcdef.evil.com",
    "client_ip": "10.0.1.99"
  }'
```

---

### Phase 7: Incident Report Generation (2 minutes)

**Talk Track:**
> "For compliance and forensics, we can generate detailed PDF incident reports."

**Command (Terminal 1):**
```bash
docker-compose exec api python scripts/report_generator.py \
  --hours 1 \
  --output /app/reports/demo_incident_report.pdf
```

**Download and show report:**
```bash
docker cp dns-tunnel-api:/app/reports/demo_incident_report.pdf ./
open demo_incident_report.pdf
```

**Show in PDF:**
- Executive summary with statistics
- Alert timeline chart
- Detailed alert table
- Technical analysis section
- Incident response recommendations

**Talk Track:**
> "The report includes an executive summary, timeline visualization, technical details of detected queries, and recommended response actions."

---

### Phase 8: Response Actions (Optional - 2 minutes)

**Talk Track:**
> "The system can take automated response actions when configured."

**Show:**
```bash
# View pending response actions
curl -s http://localhost:8000/api/v1/response/pending | jq

# Manual block (if auto-response is enabled)
curl -X POST http://localhost:8000/api/v1/response/block \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": 1,
    "action_type": "block_ip",
    "duration_minutes": 60
  }'
```

**Talk Track:**
> "Response actions include IP blocking via firewall APIs, host quarantine, and domain blacklisting. These require manual approval by default for safety."

---

### Phase 9: System Statistics (1 minute)

**Talk Track:**
> "Let's look at overall system performance."

**Command (Terminal 3):**
```bash
curl -s http://localhost:8000/api/v1/stats | jq
```

**Show:**
- Total queries processed
- Alert counts by severity
- Detection rate
- Top suspicious domains
- Top affected clients

---

### Phase 10: Architecture Recap (1 minute)

**Talk Track:**
> "To recap, this system provides:
> - Real-time DNS tunneling detection using ML
> - Multi-channel alerting (Slack, Teams, Email, JIRA)
> - Automated incident reporting
> - Optional automated response
> - Full observability through Grafana
> - Production-ready Docker deployment"

**Show:**
- Architecture diagram again
- Key components:
  - Log Collector Agent
  - Feature Extraction Agent
  - Anomaly Scoring Agent (Isolation Forest)
  - Alerting Agent
  - Response Agent
  - Dashboard Agent

---

## 🎓 Q&A Topics

Be prepared to discuss:

### Technical
- **Q**: How does the ML model work?
  - **A**: Isolation Forest trains on benign DNS traffic to learn normal patterns. It scores queries based on how "isolated" they are - unusual queries score higher.

- **Q**: What features does it use?
  - **A**: Query length, Shannon entropy, label count, character ratios, query rate, and time-window aggregations.

- **Q**: Can it detect zero-day tunneling tools?
  - **A**: Yes, it's unsupervised learning based on behavioral patterns, not signatures. Any tunneling that creates unusual DNS patterns will be detected.

### Deployment
- **Q**: How do you deploy this?
  - **A**: Docker Compose for single-node, Kubernetes for scale. One command deployment with `docker-compose up`.

- **Q**: How does it integrate with existing infrastructure?
  - **A**: Ingests Zeek/Suricata logs, sends alerts to existing tools (Slack/JIRA), can trigger firewall APIs.

- **Q**: Performance at scale?
  - **A**: Designed for microservice architecture. Can use Kafka for message queuing and scale horizontally.

### Operations
- **Q**: False positive rate?
  - **A**: Tunable via contamination parameter. Typical 1% on baseline. Further reduced through alert throttling and confidence thresholds.

- **Q**: How to tune sensitivity?
  - **A**: Adjust `ANOMALY_THRESHOLD_SUSPICIOUS` and `ANOMALY_THRESHOLD_HIGH` environment variables.

- **Q**: Training requirements?
  - **A**: Train on 1-7 days of benign DNS traffic. Retrain monthly or when network patterns change.

---

## 🧹 Post-Demo Cleanup

```bash
# Stop services
docker-compose down

# Full cleanup (optional)
make clean
```

---

## 💡 Demo Tips

1. **Rehearse**: Run through the demo 2-3 times beforehand
2. **Timing**: Adjust `--delay` parameters if demo is too slow/fast
3. **Backups**: Have screenshots ready in case of technical issues
4. **Engagement**: Pause at key detection moments to let the impact sink in
5. **Context**: Relate to real-world incidents (e.g., "this is how APT groups exfiltrate data")

---

## 📊 Success Metrics to Highlight

- ✅ Real-time detection (< 5 second latency)
- ✅ High detection accuracy (catches dnscat2, iodine, custom tools)
- ✅ Low false positive rate (normal traffic not flagged)
- ✅ Production-ready deployment (one command)
- ✅ Enterprise integrations (Slack, JIRA, etc.)
- ✅ Automated reporting for compliance

---

**Good luck with your demo! 🚀**

