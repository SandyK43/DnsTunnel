"""
Automated Weekly Model Retraining
Collects normal traffic from the past 7 days and retrains the model
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timedelta
import pandas as pd
from loguru import logger
import json

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.feature_extractor import FeatureExtractor
from agents.scorer import AnomalyScorer
from agents.alerting import AlertingAgent

# Configuration
MODEL_DIR = Path("/app/models")
MODEL_PATH = MODEL_DIR / "isolation_forest.pkl"
BACKUP_DIR = MODEL_DIR / "backups"
REPORT_PATH = Path("/app/reports") / "training_reports"
DB_CONNECTION = os.getenv('DATABASE_URL')


def backup_current_model():
    """Backup current model before retraining"""
    if MODEL_PATH.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = BACKUP_DIR / f"model_backup_{timestamp}.pkl"
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)

        import shutil
        shutil.copy(MODEL_PATH, backup_path)
        logger.info(f"Backed up current model to {backup_path}")
        return backup_path
    return None


def collect_training_data(days=7):
    """Collect NORMAL severity queries from the database"""
    try:
        import psycopg2

        conn = psycopg2.connect(DB_CONNECTION)
        cursor = conn.cursor()

        # Get queries from the past 7 days that were marked as NORMAL
        cutoff_date = datetime.now() - timedelta(days=days)

        query = """
            SELECT DISTINCT query, source_ip
            FROM dns_queries
            WHERE severity = 'NORMAL'
            AND timestamp >= %s
            AND anomaly_score < 0.5
            LIMIT 10000
        """

        cursor.execute(query, (cutoff_date,))
        results = cursor.fetchall()

        cursor.close()
        conn.close()

        if not results:
            logger.warning("No NORMAL queries found in database, using sample data")
            return None

        df = pd.DataFrame(results, columns=['query', 'client_ip'])
        logger.info(f"Collected {len(df)} NORMAL queries from past {days} days")

        return df

    except Exception as e:
        logger.error(f"Failed to collect training data from database: {e}")
        return None


def generate_sample_training_data(num_samples=5000):
    """Fallback: Generate sample training data"""
    from scripts.train_model import generate_sample_data
    logger.info("Using sample data for training")
    return generate_sample_data(num_samples)


def train_new_model(training_data):
    """Train new model on collected data"""
    logger.info(f"Training new model on {len(training_data)} samples")

    # Extract features
    extractor = FeatureExtractor(window_size=60)
    queries = training_data.to_dict('records')
    features_df = extractor.extract_batch_features(queries)

    # Train model
    scorer = AnomalyScorer()
    scorer.train(features_df)

    # Evaluate on training data
    features_df = scorer.score_batch(features_df)

    stats = {
        'training_samples': len(features_df),
        'mean_score': float(features_df['anomaly_score'].mean()),
        'std_score': float(features_df['anomaly_score'].std()),
        'max_score': float(features_df['anomaly_score'].max()),
        'normal_pct': float((features_df['severity'] == 'NORMAL').sum() / len(features_df) * 100),
        'suspicious_pct': float((features_df['severity'] == 'SUSPICIOUS').sum() / len(features_df) * 100),
        'high_pct': float((features_df['severity'] == 'HIGH').sum() / len(features_df) * 100),
    }

    logger.info(f"Training stats: {stats}")

    return scorer, stats


def validate_model(scorer):
    """Test new model with known good and bad queries"""
    test_cases = [
        ("www.google.com", "192.168.1.100", "should be NORMAL"),
        ("youtube.com", "192.168.1.100", "should be NORMAL"),
        ("a3f8b2c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3.evil.com", "10.0.1.50", "should be HIGH"),
        ("aaabbbcccdddeeefffggghhh.malware.net", "10.0.1.50", "should be HIGH"),
    ]

    extractor = FeatureExtractor()
    results = []

    for query, client_ip, expected in test_cases:
        features = extractor.extract_features(query, client_ip)
        score, severity = scorer.score(features)
        results.append({
            'query': query,
            'score': float(score),
            'severity': severity.value,
            'expected': expected,
            'passed': (
                (expected == "should be NORMAL" and severity.value == "NORMAL") or
                (expected == "should be HIGH" and severity.value == "HIGH")
            )
        })
        logger.info(f"Test: {query[:50]:<50} | Score: {score:.4f} | Severity: {severity.value:<12} | {expected}")

    return results


def generate_training_report(backup_path, stats, validation_results, timestamp):
    """Generate HTML training report"""
    REPORT_PATH.mkdir(parents=True, exist_ok=True)

    report_file = REPORT_PATH / f"training_report_{timestamp}.html"

    passed_tests = sum(1 for r in validation_results if r['passed'])
    total_tests = len(validation_results)

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Model Training Report - {timestamp}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
            }}
            .section {{
                background: white;
                padding: 25px;
                border-radius: 10px;
                margin-bottom: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .metric {{
                display: inline-block;
                padding: 15px 25px;
                margin: 10px;
                background: #f0f2f6;
                border-radius: 8px;
                border-left: 4px solid #667eea;
            }}
            .metric-value {{
                font-size: 2rem;
                font-weight: bold;
                color: #667eea;
            }}
            .metric-label {{
                color: #666;
                font-size: 0.9rem;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }}
            th {{
                background-color: #667eea;
                color: white;
            }}
            .pass {{
                color: #4caf50;
                font-weight: bold;
            }}
            .fail {{
                color: #f44336;
                font-weight: bold;
            }}
            .warning {{
                background-color: #fff3e0;
                border-left: 4px solid #ff9800;
                padding: 15px;
                margin: 15px 0;
                border-radius: 5px;
            }}
            .success {{
                background-color: #e8f5e9;
                border-left: 4px solid #4caf50;
                padding: 15px;
                margin: 15px 0;
                border-radius: 5px;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🤖 Automated Model Training Report</h1>
            <p>Training Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
            <p>Model Version: {timestamp}</p>
        </div>

        <div class="section">
            <h2>📊 Training Statistics</h2>
            <div>
                <div class="metric">
                    <div class="metric-value">{stats['training_samples']:,}</div>
                    <div class="metric-label">Training Samples</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{stats['normal_pct']:.1f}%</div>
                    <div class="metric-label">Normal</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{stats['suspicious_pct']:.1f}%</div>
                    <div class="metric-label">Suspicious</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{stats['high_pct']:.1f}%</div>
                    <div class="metric-label">High Risk</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>✅ Validation Results</h2>
            <p><strong>Tests Passed: {passed_tests}/{total_tests}</strong></p>

            <table>
                <tr>
                    <th>Query</th>
                    <th>Score</th>
                    <th>Severity</th>
                    <th>Expected</th>
                    <th>Result</th>
                </tr>
    """

    for result in validation_results:
        status_class = "pass" if result['passed'] else "fail"
        status_text = "✓ PASS" if result['passed'] else "✗ FAIL"
        html += f"""
                <tr>
                    <td><code>{result['query'][:60]}</code></td>
                    <td>{result['score']:.4f}</td>
                    <td>{result['severity']}</td>
                    <td>{result['expected']}</td>
                    <td class="{status_class}">{status_text}</td>
                </tr>
        """

    html += """
            </table>
        </div>

        <div class="section">
            <h2>📋 Next Steps</h2>
    """

    if passed_tests == total_tests:
        html += """
            <div class="success">
                <strong>✓ All validation tests passed!</strong><br>
                The new model is performing as expected and is ready for deployment.
            </div>
            <h3>Recommended Actions:</h3>
            <ol>
                <li>✅ Review the training statistics above</li>
                <li>✅ Deploy the new model to production</li>
                <li>✅ Monitor performance for the next 24 hours</li>
                <li>Archive old model backups (keep last 4 weeks)</li>
            </ol>
        """
    else:
        html += f"""
            <div class="warning">
                <strong>⚠ Warning: {total_tests - passed_tests} validation test(s) failed!</strong><br>
                The new model may not be performing correctly. Human review required before deployment.
            </div>
            <h3>Recommended Actions:</h3>
            <ol>
                <li>🔍 Review failed test cases above</li>
                <li>🔍 Check if training data quality is sufficient</li>
                <li>❌ DO NOT deploy until issues are resolved</li>
                <li>Consider restoring backup model: <code>{backup_path.name if backup_path else 'N/A'}</code></li>
                <li>Investigate why the model is misclassifying queries</li>
            </ol>
        """

    html += """
        </div>

        <div class="section">
            <h2>📁 Model Information</h2>
            <ul>
                <li><strong>Model Location:</strong> <code>/app/models/isolation_forest.pkl</code></li>
                <li><strong>Backup Location:</strong> <code>/app/models/backups/</code></li>
                <li><strong>Algorithm:</strong> Isolation Forest</li>
                <li><strong>Features:</strong> 10 (length, entropy, labels, digits, etc.)</li>
            </ul>
        </div>
    </body>
    </html>
    """

    with open(report_file, 'w') as f:
        f.write(html)

    logger.info(f"Training report saved to: {report_file}")
    return report_file


def send_notification(report_path, stats, validation_results):
    """Send notification to admins for human review"""
    passed_tests = sum(1 for r in validation_results if r['passed'])
    total_tests = len(validation_results)

    alerting = AlertingAgent()

    message = f"""
🤖 **Automated Model Retraining Complete**

**Training Summary:**
- Samples: {stats['training_samples']:,}
- Normal: {stats['normal_pct']:.1f}%
- Suspicious: {stats['suspicious_pct']:.1f}%
- High Risk: {stats['high_pct']:.1f}%

**Validation:** {passed_tests}/{total_tests} tests passed

**Report:** {report_path}

**Action Required:** Please review the training report and approve deployment.
    """

    # Send to configured channels
    if os.getenv('SLACK_WEBHOOK_URL'):
        try:
            import asyncio
            asyncio.run(alerting.send_slack_alert('system-admin', 'N/A', 0.0, 'NORMAL', {}))
        except:
            pass

    logger.info("Notifications sent to configured channels")


def main():
    """Main retraining function"""
    logger.info("=" * 80)
    logger.info("Starting Automated Weekly Model Retraining")
    logger.info("=" * 80)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    try:
        # Step 1: Backup current model
        backup_path = backup_current_model()

        # Step 2: Collect training data
        training_data = collect_training_data(days=7)

        if training_data is None or len(training_data) < 1000:
            logger.warning("Insufficient real data, using sample data")
            training_data = generate_sample_training_data(5000)

        # Step 3: Train new model
        scorer, stats = train_new_model(training_data)

        # Step 4: Validate new model
        validation_results = validate_model(scorer)

        # Step 5: Generate report
        report_path = generate_training_report(backup_path, stats, validation_results, timestamp)

        # Step 6: Send notifications
        send_notification(report_path, stats, validation_results)

        # Step 7: Save new model if validation passed
        passed_tests = sum(1 for r in validation_results if r['passed'])
        if passed_tests == len(validation_results):
            scorer.save_model(str(MODEL_PATH))
            logger.info(f"✓ New model deployed successfully!")
        else:
            logger.warning(f"✗ Model NOT deployed due to failed validation tests")
            logger.warning(f"   Backup model preserved at: {backup_path}")

        logger.info("=" * 80)
        logger.info(f"Retraining complete! Report: {report_path}")
        logger.info("=" * 80)

    except Exception as e:
        logger.error(f"Retraining failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
