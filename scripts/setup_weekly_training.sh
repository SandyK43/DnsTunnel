#!/bin/bash
#
# Setup Weekly Automated Model Retraining
# Runs every Sunday at 2:00 AM
#

echo "Setting up weekly automated model retraining..."

# Create cron job entry
CRON_ENTRY="0 2 * * 0 cd /app && python scripts/automated_retraining.py >> /app/logs/retraining.log 2>&1"

# Add to crontab
(crontab -l 2>/dev/null; echo "$CRON_ENTRY") | crontab -

echo "✓ Cron job installed:"
echo "  Schedule: Every Sunday at 2:00 AM"
echo "  Script: /app/scripts/automated_retraining.py"
echo "  Logs: /app/logs/retraining.log"
echo ""
echo "To view current cron jobs:"
echo "  crontab -l"
echo ""
echo "To manually trigger training:"
echo "  docker-compose exec api python scripts/automated_retraining.py"
echo ""
echo "To view training reports:"
echo "  ls -lh /app/reports/training_reports/"
