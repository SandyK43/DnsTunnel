# Automated Model Retraining

## Overview

The DNS Tunneling Detection system includes automated weekly model retraining to keep the ML model updated with the latest legitimate traffic patterns.

## Features

✅ **Weekly Scheduled Training** - Runs every Sunday at 2:00 AM
✅ **Automatic Data Collection** - Uses NORMAL queries from past 7 days
✅ **Model Validation** - Tests new model before deployment
✅ **Human Review** - Generates detailed HTML reports
✅ **Automatic Backup** - Keeps old models for 30 days
✅ **Notifications** - Alerts via Slack/Email when training completes

## Setup

### 1. Install the Weekly Cron Job

```bash
docker-compose exec api /app/scripts/setup_weekly_training.sh
```

This will configure the system to automatically retrain every Sunday at 2:00 AM.

### 2. Manual Training (Optional)

To manually trigger training at any time:

```bash
docker-compose exec api python scripts/automated_retraining.py
```

## How It Works

### Training Process

1. **Backup Current Model**
   - Creates timestamped backup in `/app/models/backups/`
   - Preserves current model in case rollback is needed

2. **Collect Training Data**
   - Queries database for NORMAL severity queries from past 7 days
   - Filters for anomaly_score < 0.5
   - Collects up to 10,000 samples
   - Falls back to sample data if insufficient real data

3. **Train New Model**
   - Extracts features from collected queries
   - Trains Isolation Forest model
   - Calculates training statistics

4. **Validate Model**
   - Tests with known good queries (google.com, youtube.com)
   - Tests with known bad queries (long hex subdomains, high entropy)
   - Must pass all validation tests to be deployed

5. **Generate Report**
   - Creates beautiful HTML report with all statistics
   - Saved to `/app/reports/training_reports/`
   - Includes recommendations for deployment

6. **Send Notifications**
   - Sends alert to configured channels (Slack, Email, Teams)
   - Includes training summary and link to report

7. **Deploy or Reject**
   - If all tests pass: deploys new model automatically
   - If any test fails: preserves old model, notifies admin

## Training Reports

Reports are saved as HTML files and can be viewed in any browser:

**Location:** `/app/reports/training_reports/training_report_YYYYMMDD_HHMMSS.html`

### Report Contents

- **Training Statistics**: Sample count, score distribution, severity breakdown
- **Validation Results**: Test results for known good/bad queries
- **Recommendations**: Whether to deploy or investigate issues
- **Model Information**: Paths, algorithm details, feature list

### Viewing Reports

```bash
# List all training reports
docker-compose exec api ls -lh /app/reports/training_reports/

# Copy latest report to local machine
docker cp dns-tunnel-api:/app/reports/training_reports/training_report_XXXXXXXX_XXXXXX.html ./

# Open in browser
open training_report_XXXXXXXX_XXXXXX.html
```

## Model Backups

Old models are automatically backed up before retraining.

**Location:** `/app/models/backups/model_backup_YYYYMMDD_HHMMSS.pkl`

### Restoring a Backup

If the new model performs poorly, restore a previous version:

```bash
# List backups
docker-compose exec api ls -lh /app/models/backups/

# Restore a specific backup
docker-compose exec api cp /app/models/backups/model_backup_20231125_020000.pkl /app/models/isolation_forest.pkl

# Restart API to load restored model
docker-compose restart api
```

### Cleanup Old Backups

Keep last 4 weeks (recommended):

```bash
docker-compose exec api find /app/models/backups/ -name "*.pkl" -mtime +30 -delete
```

## Notifications

Configure notification channels in `.env`:

### Slack

```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### Email

```bash
EMAIL_SMTP_HOST=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_FROM=alerts@yourcompany.com
EMAIL_TO=ml-team@yourcompany.com
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
```

### Microsoft Teams

```bash
TEAMS_WEBHOOK_URL=https://your-teams-webhook-url
```

## Monitoring

### View Training Logs

```bash
# Real-time logs
docker-compose exec api tail -f /app/logs/retraining.log

# Full log history
docker-compose exec api cat /app/logs/retraining.log
```

### Check Cron Status

```bash
# View installed cron jobs
docker-compose exec api crontab -l

# View cron service status
docker-compose exec api service cron status
```

## Validation Tests

The automated retraining performs these validation tests:

| Query | Expected Severity | Purpose |
|-------|------------------|---------|
| www.google.com | NORMAL | Verify common legitimate domain |
| youtube.com | NORMAL | Verify common legitimate domain |
| a3f8b2...e3.evil.com (64 char hex) | HIGH | Verify detection of data exfil pattern |
| aaabbb...ggg.malware.net (28 chars) | HIGH | Verify detection of high entropy |

**All 4 tests must pass** for automatic deployment.

## Troubleshooting

### Training Fails

**Check logs:**
```bash
docker-compose exec api cat /app/logs/retraining.log
```

**Common issues:**
- Database connection timeout → Check DATABASE_URL in .env
- Insufficient training data → Wait for more NORMAL queries to accumulate
- Out of memory → Increase Docker memory limit

### Model Not Deployed

If validation tests fail, the new model is **not deployed**. Review the training report to see which tests failed and why.

**Possible causes:**
- Poor quality training data (too much malicious traffic in "NORMAL" queries)
- Database not properly collecting queries
- Thresholds need adjustment

### No Notifications Received

1. Check notification settings in `.env`
2. Test notification manually:
   ```bash
   docker-compose exec api python -c "from agents.alerting import AlertManager; import asyncio; am = AlertManager(); asyncio.run(am.send_slack_alert('test', '1.2.3.4', 0.9, 'HIGH', {}))"
   ```

## Best Practices

✅ **Review Reports** - Always review training reports before trusting new model
✅ **Monitor Performance** - Watch for false positives/negatives after deployment
✅ **Keep Backups** - Maintain at least 4 weeks of model backups
✅ **Quality Data** - Ensure database only stores truly NORMAL queries with low scores
✅ **Test Manually** - Run manual training once before enabling cron job
✅ **Alert Channels** - Configure at least 2 notification channels

## Configuration Options

Edit `scripts/automated_retraining.py` to customize:

- **Training data window**: Default 7 days
  ```python
  training_data = collect_training_data(days=7)  # Change to 14, 30, etc.
  ```

- **Sample size**: Default 10,000 queries
  ```python
  LIMIT 10000  # Increase for more data
  ```

- **Validation tests**: Add custom tests
  ```python
  test_cases = [
      ("your-custom-domain.com", "192.168.1.1", "should be NORMAL"),
      # Add more...
  ]
  ```

## Production Recommendations

For production deployments:

1. ✅ Start with **monthly** retraining, not weekly
2. ✅ Require **manual approval** before deployment
3. ✅ Implement **A/B testing** (10% traffic to new model first)
4. ✅ Monitor **false positive rate** for 48 hours
5. ✅ Keep **8 weeks** of model backups
6. ✅ Document model versions in change log
7. ✅ Test on **staging environment** first

---

**Questions?** Check the main [README.md](../README.md) or open an issue.
