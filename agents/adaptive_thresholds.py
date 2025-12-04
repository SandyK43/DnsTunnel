"""
Adaptive Threshold Manager
Continuously adjusts detection thresholds based on real-time performance and analyst feedback
"""

import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import deque
import json

import numpy as np
from loguru import logger


@dataclass
class ThresholdChange:
    """Record of a threshold change."""
    timestamp: datetime
    old_suspicious: float
    new_suspicious: float
    old_high: float
    new_high: float
    reason: str
    fp_rate: float
    alert_volume: int


@dataclass
class PerformanceMetrics:
    """Performance metrics for threshold optimization."""
    total_queries: int
    total_alerts: int
    false_positives: int
    true_positives: int
    false_positive_rate: float
    alert_rate: float
    avg_score: float
    score_stddev: float


class AdaptiveThresholdManager:
    """
    Manages dynamic threshold adjustment based on:
    - False positive rate from analyst feedback
    - Alert volume and distribution
    - Score distribution over time
    - Historical performance
    """

    def __init__(
        self,
        initial_suspicious: float = 0.70,
        initial_high: float = 0.85,
        target_fp_rate: float = 0.03,  # Target 3% false positive rate
        max_fp_rate: float = 0.10,      # Maximum tolerable FP rate
        min_fp_rate: float = 0.01,      # Minimum FP rate (too low = missing threats)
        adjustment_increment: float = 0.02,  # How much to adjust per iteration
        min_threshold: float = 0.50,    # Minimum threshold (safety limit)
        max_threshold: float = 0.95,    # Maximum threshold (safety limit)
        evaluation_window_hours: int = 24,  # How far back to look
        min_samples_for_adjustment: int = 100,  # Minimum alerts before adjusting
        max_adjustment_frequency_hours: int = 6,  # Don't adjust too frequently
    ):
        # Current thresholds
        self.threshold_suspicious = initial_suspicious
        self.threshold_high = initial_high

        # Configuration
        self.target_fp_rate = target_fp_rate
        self.max_fp_rate = max_fp_rate
        self.min_fp_rate = min_fp_rate
        self.adjustment_increment = adjustment_increment
        self.min_threshold = min_threshold
        self.max_threshold = max_threshold
        self.evaluation_window_hours = evaluation_window_hours
        self.min_samples_for_adjustment = min_samples_for_adjustment
        self.max_adjustment_frequency_hours = max_adjustment_frequency_hours

        # State tracking
        self.last_adjustment_time: Optional[datetime] = None
        self.adjustment_history: deque = deque(maxlen=100)  # Keep last 100 changes
        self.score_history: deque = deque(maxlen=10000)  # Keep last 10k scores

        # Feedback tracking
        self.feedback_data: List[Dict] = []  # Analyst feedback

        # Statistics
        self.total_adjustments = 0
        self.total_increases = 0
        self.total_decreases = 0

        logger.info(f"Adaptive Threshold Manager initialized")
        logger.info(f"Initial thresholds - Suspicious: {self.threshold_suspicious}, High: {self.threshold_high}")
        logger.info(f"Target FP rate: {self.target_fp_rate:.1%}, Max: {self.max_fp_rate:.1%}, Min: {self.min_fp_rate:.1%}")

    def record_score(self, score: float, severity: str, timestamp: Optional[datetime] = None):
        """Record an anomaly score for distribution tracking."""
        self.score_history.append({
            'score': score,
            'severity': severity,
            'timestamp': timestamp or datetime.utcnow()
        })

    def add_feedback(
        self,
        alert_id: int,
        is_false_positive: bool,
        score: float,
        analyst: str,
        notes: Optional[str] = None
    ):
        """
        Record analyst feedback on an alert.

        Args:
            alert_id: ID of the alert
            is_false_positive: True if analyst determined it was false positive
            score: The anomaly score that triggered the alert
            analyst: Username of analyst providing feedback
            notes: Optional notes about the feedback
        """
        feedback = {
            'alert_id': alert_id,
            'is_false_positive': is_false_positive,
            'score': score,
            'analyst': analyst,
            'notes': notes,
            'timestamp': datetime.utcnow()
        }

        self.feedback_data.append(feedback)

        logger.info(
            f"Feedback recorded - Alert {alert_id}: "
            f"{'FALSE POSITIVE' if is_false_positive else 'TRUE POSITIVE'} "
            f"(score: {score:.3f}) by {analyst}"
        )

        # Trim old feedback (keep last 30 days)
        cutoff = datetime.utcnow() - timedelta(days=30)
        self.feedback_data = [
            f for f in self.feedback_data
            if f['timestamp'] > cutoff
        ]

    def get_performance_metrics(self, hours: int = None) -> PerformanceMetrics:
        """
        Calculate performance metrics over a time window.

        Args:
            hours: Number of hours to look back (default: evaluation_window_hours)
        """
        hours = hours or self.evaluation_window_hours
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        # Filter recent scores and feedback
        recent_scores = [
            s for s in self.score_history
            if s['timestamp'] > cutoff
        ]

        recent_feedback = [
            f for f in self.feedback_data
            if f['timestamp'] > cutoff
        ]

        # Calculate metrics
        total_queries = len(recent_scores)
        total_alerts = sum(1 for s in recent_scores if s['severity'] in ['SUSPICIOUS', 'HIGH'])

        # Count FPs and TPs from analyst feedback
        false_positives = sum(1 for f in recent_feedback if f['is_false_positive'])
        true_positives = sum(1 for f in recent_feedback if not f['is_false_positive'])

        # Calculate rates
        fp_rate = false_positives / (false_positives + true_positives) if (false_positives + true_positives) > 0 else 0.0
        alert_rate = total_alerts / total_queries if total_queries > 0 else 0.0

        # Score statistics
        scores = [s['score'] for s in recent_scores]
        avg_score = np.mean(scores) if scores else 0.0
        score_stddev = np.std(scores) if scores else 0.0

        return PerformanceMetrics(
            total_queries=total_queries,
            total_alerts=total_alerts,
            false_positives=false_positives,
            true_positives=true_positives,
            false_positive_rate=fp_rate,
            alert_rate=alert_rate,
            avg_score=avg_score,
            score_stddev=score_stddev
        )

    def should_adjust_thresholds(self) -> bool:
        """
        Determine if thresholds should be adjusted now.

        Returns:
            True if adjustment should occur
        """
        # Don't adjust too frequently
        if self.last_adjustment_time:
            time_since_last = datetime.utcnow() - self.last_adjustment_time
            if time_since_last < timedelta(hours=self.max_adjustment_frequency_hours):
                return False

        # Need minimum feedback samples
        recent_feedback = [
            f for f in self.feedback_data
            if f['timestamp'] > datetime.utcnow() - timedelta(hours=self.evaluation_window_hours)
        ]

        if len(recent_feedback) < self.min_samples_for_adjustment:
            logger.debug(
                f"Not enough feedback samples for adjustment "
                f"({len(recent_feedback)} < {self.min_samples_for_adjustment})"
            )
            return False

        return True

    def calculate_threshold_adjustment(self) -> Optional[Tuple[float, float, str]]:
        """
        Calculate new threshold values based on current performance.

        Returns:
            Tuple of (new_suspicious, new_high, reason) or None if no adjustment needed
        """
        metrics = self.get_performance_metrics()

        logger.info(f"Performance metrics - FP rate: {metrics.false_positive_rate:.2%}, "
                   f"Alert rate: {metrics.alert_rate:.2%}, "
                   f"Alerts: {metrics.total_alerts}, "
                   f"FPs: {metrics.false_positives}, TPs: {metrics.true_positives}")

        fp_rate = metrics.false_positive_rate

        # No adjustment needed if within target range
        if self.min_fp_rate <= fp_rate <= self.max_fp_rate:
            # Close to target - no adjustment
            if abs(fp_rate - self.target_fp_rate) < 0.01:
                logger.debug(f"FP rate ({fp_rate:.2%}) is optimal, no adjustment needed")
                return None

        # Calculate adjustment
        adjustment = 0.0
        reason = ""

        # FP rate too high - raise thresholds
        if fp_rate > self.max_fp_rate:
            # Larger adjustment for severe FP rate
            if fp_rate > 0.15:
                adjustment = self.adjustment_increment * 2
            else:
                adjustment = self.adjustment_increment

            reason = f"High false positive rate ({fp_rate:.2%} > {self.max_fp_rate:.2%})"

        # FP rate too low - lower thresholds (might be missing threats)
        elif fp_rate < self.min_fp_rate and metrics.total_alerts < 10:
            adjustment = -self.adjustment_increment
            reason = f"Very low FP rate ({fp_rate:.2%}) with few alerts - may be missing threats"

        # Alert volume extremely high - raise thresholds
        elif metrics.alert_rate > 0.10:  # More than 10% of queries are alerts
            adjustment = self.adjustment_increment
            reason = f"Alert volume too high ({metrics.alert_rate:.1%} of queries)"

        # Alert volume extremely low - lower thresholds
        elif metrics.alert_rate < 0.001 and fp_rate < self.target_fp_rate:  # Less than 0.1% alerts
            adjustment = -self.adjustment_increment * 0.5  # Smaller decrease
            reason = f"Very few alerts ({metrics.alert_rate:.2%}), safe to be more sensitive"

        if adjustment == 0.0:
            return None

        # Apply adjustment with safety limits
        new_suspicious = np.clip(
            self.threshold_suspicious + adjustment,
            self.min_threshold,
            self.max_threshold
        )

        new_high = np.clip(
            self.threshold_high + adjustment,
            self.min_threshold,
            self.max_threshold
        )

        # Ensure high threshold is always higher than suspicious
        if new_high <= new_suspicious:
            new_high = min(new_suspicious + 0.10, self.max_threshold)

        # Only return if thresholds actually changed
        if new_suspicious != self.threshold_suspicious or new_high != self.threshold_high:
            return (new_suspicious, new_high, reason)

        return None

    async def adjust_thresholds(self) -> bool:
        """
        Perform threshold adjustment if needed.

        Returns:
            True if thresholds were adjusted, False otherwise
        """
        if not self.should_adjust_thresholds():
            return False

        adjustment = self.calculate_threshold_adjustment()

        if not adjustment:
            return False

        new_suspicious, new_high, reason = adjustment

        # Get current metrics for logging
        metrics = self.get_performance_metrics()

        # Record the change
        change = ThresholdChange(
            timestamp=datetime.utcnow(),
            old_suspicious=self.threshold_suspicious,
            new_suspicious=new_suspicious,
            old_high=self.threshold_high,
            new_high=new_high,
            reason=reason,
            fp_rate=metrics.false_positive_rate,
            alert_volume=metrics.total_alerts
        )

        self.adjustment_history.append(change)

        # Apply the change
        old_suspicious = self.threshold_suspicious
        old_high = self.threshold_high

        self.threshold_suspicious = new_suspicious
        self.threshold_high = new_high
        self.last_adjustment_time = datetime.utcnow()
        self.total_adjustments += 1

        if new_suspicious > old_suspicious:
            self.total_increases += 1
            direction = "INCREASED"
        else:
            self.total_decreases += 1
            direction = "DECREASED"

        # Log the change
        logger.warning(
            f"🔧 THRESHOLDS {direction}: "
            f"Suspicious: {old_suspicious:.3f} → {new_suspicious:.3f}, "
            f"High: {old_high:.3f} → {new_high:.3f}"
        )
        logger.warning(f"   Reason: {reason}")
        logger.warning(
            f"   Metrics: FP rate={metrics.false_positive_rate:.2%}, "
            f"Alerts={metrics.total_alerts}, FPs={metrics.false_positives}, TPs={metrics.true_positives}"
        )

        return True

    def get_current_thresholds(self) -> Tuple[float, float]:
        """Get current threshold values."""
        return (self.threshold_suspicious, self.threshold_high)

    def get_statistics(self) -> Dict:
        """Get statistics about threshold adjustments."""
        recent_changes = list(self.adjustment_history)[-10:]  # Last 10 changes

        metrics = self.get_performance_metrics()

        return {
            'current_thresholds': {
                'suspicious': self.threshold_suspicious,
                'high': self.threshold_high
            },
            'performance': asdict(metrics),
            'adjustment_stats': {
                'total_adjustments': self.total_adjustments,
                'increases': self.total_increases,
                'decreases': self.total_decreases,
                'last_adjustment': self.last_adjustment_time.isoformat() if self.last_adjustment_time else None
            },
            'recent_changes': [
                {
                    'timestamp': c.timestamp.isoformat(),
                    'suspicious': f"{c.old_suspicious:.3f} → {c.new_suspicious:.3f}",
                    'high': f"{c.old_high:.3f} → {c.new_high:.3f}",
                    'reason': c.reason,
                    'fp_rate': f"{c.fp_rate:.2%}"
                }
                for c in recent_changes
            ],
            'feedback_summary': {
                'total_feedback': len(self.feedback_data),
                'false_positives': sum(1 for f in self.feedback_data if f['is_false_positive']),
                'true_positives': sum(1 for f in self.feedback_data if not f['is_false_positive']),
                'last_24h': len([f for f in self.feedback_data if f['timestamp'] > datetime.utcnow() - timedelta(hours=24)])
            }
        }

    async def run_continuous_monitoring(self, check_interval_minutes: int = 60):
        """
        Run continuous threshold monitoring and adjustment.

        Args:
            check_interval_minutes: How often to check for adjustments
        """
        logger.info(f"Starting continuous threshold monitoring (check every {check_interval_minutes} min)")

        while True:
            try:
                await asyncio.sleep(check_interval_minutes * 60)

                logger.debug("Checking if threshold adjustment is needed...")
                adjusted = await self.adjust_thresholds()

                if not adjusted:
                    logger.debug("No threshold adjustment needed")

            except Exception as e:
                logger.error(f"Error in continuous monitoring: {e}", exc_info=True)
                await asyncio.sleep(300)  # Wait 5 minutes on error

    def export_history(self, filepath: str):
        """Export adjustment history to JSON file."""
        data = {
            'current_thresholds': {
                'suspicious': self.threshold_suspicious,
                'high': self.threshold_high
            },
            'adjustment_history': [
                {
                    'timestamp': c.timestamp.isoformat(),
                    'old_suspicious': c.old_suspicious,
                    'new_suspicious': c.new_suspicious,
                    'old_high': c.old_high,
                    'new_high': c.new_high,
                    'reason': c.reason,
                    'fp_rate': c.fp_rate,
                    'alert_volume': c.alert_volume
                }
                for c in self.adjustment_history
            ]
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Adjustment history exported to {filepath}")
