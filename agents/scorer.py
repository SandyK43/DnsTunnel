"""
Anomaly Scoring Agent
Uses Isolation Forest to score DNS queries for tunneling behavior.
"""

import pickle
import os
from typing import Dict, List, Tuple, Optional
from enum import Enum
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from loguru import logger


class Severity(str, Enum):
    """Alert severity levels."""
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"


class AnomalyScorer:
    """
    Scores DNS queries using Isolation Forest model.
    
    Converts anomaly scores to severity levels based on thresholds.
    """
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        threshold_suspicious: float = 0.70,
        threshold_high: float = 0.85
    ):
        """
        Args:
            model_path: Path to trained Isolation Forest model
            threshold_suspicious: Score threshold for SUSPICIOUS severity
            threshold_high: Score threshold for HIGH severity
        """
        self.model: Optional[IsolationForest] = None
        self.threshold_suspicious = threshold_suspicious
        self.threshold_high = threshold_high
        self.baseline_scores = None  # Store baseline for normalization
        self.feature_names = [
            'len_q',
            'entropy',
            'num_labels',
            'max_label_len',
            'digits_ratio',
            'non_alnum_ratio',
            'qps',
            'unique_subdomains',
            'avg_entropy',
            'max_entropy'
        ]

        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
        else:
            logger.warning(f"Model not found at {model_path}, creating default model")
            self.create_default_model()
    
    def create_default_model(self):
        """Create a default Isolation Forest model."""
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.01,
            random_state=42,
            max_samples='auto',
            warm_start=False
        )
        logger.info("Created default Isolation Forest model")
    
    def load_model(self, model_path: str):
        """Load trained model and baseline scores from disk."""
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)

            # Handle both old and new format
            if isinstance(model_data, dict):
                self.model = model_data['model']
                baseline = model_data.get('baseline_scores')

                # Handle old format (array) vs new format (dict)
                if baseline is not None and isinstance(baseline, np.ndarray):
                    # Convert old array format to new dict format
                    self.baseline_scores = {
                        'min': float(np.min(baseline)),
                        'max': float(np.max(baseline)),
                        'mean': float(np.mean(baseline)),
                        'std': float(np.std(baseline))
                    }
                    logger.info("Converted old baseline format to new dict format")
                else:
                    self.baseline_scores = baseline

                self.threshold_suspicious = model_data.get('threshold_suspicious', self.threshold_suspicious)
                self.threshold_high = model_data.get('threshold_high', self.threshold_high)
            else:
                # Old format: just the model
                self.model = model_data
                self.baseline_scores = None

            logger.info(f"Loaded model from {model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.create_default_model()
    
    def save_model(self, model_path: str):
        """Save model and baseline scores to disk."""
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        model_data = {
            'model': self.model,
            'baseline_scores': self.baseline_scores,
            'threshold_suspicious': self.threshold_suspicious,
            'threshold_high': self.threshold_high
        }
        with open(model_path, 'wb') as f:
            pickle.dump(model_data, f)
        logger.info(f"Saved model to {model_path}")
    
    def train(self, features_df: pd.DataFrame):
        """
        Train the Isolation Forest model on baseline (benign) data.

        Args:
            features_df: DataFrame with feature columns
        """
        if self.model is None:
            self.create_default_model()

        # Select feature columns in correct order
        X = features_df[self.feature_names].values

        # Train model
        self.model.fit(X)

        # Store baseline scores for normalization (store as dict with min/max)
        baseline_raw = self.model.decision_function(X)
        self.baseline_scores = {
            'min': float(np.min(baseline_raw)),
            'max': float(np.max(baseline_raw)),
            'mean': float(np.mean(baseline_raw)),
            'std': float(np.std(baseline_raw))
        }

        logger.info(f"Trained model on {len(features_df)} samples")
        logger.info(f"Baseline score range: [{self.baseline_scores['min']:.4f}, {self.baseline_scores['max']:.4f}]")
    
    def score(self, features: Dict[str, float]) -> Tuple[float, Severity]:
        """
        Score a single query and determine severity.
        
        Args:
            features: Dictionary of feature values
            
        Returns:
            Tuple of (anomaly_score, severity)
        """
        if self.model is None:
            logger.error("Model not loaded")
            return 0.0, Severity.NORMAL
        
        # Prepare features in correct order
        X = np.array([[features[name] for name in self.feature_names]])
        
        # Get anomaly score
        # decision_function: positive = normal (inlier), negative = anomaly (outlier)
        anomaly_score_raw = self.model.decision_function(X)[0]

        # Min-max normalization with inversion using baseline
        if self.baseline_scores is not None and isinstance(self.baseline_scores, dict):
            # Normalize to 0-1 range, inverted so high score = anomalous
            baseline_min = self.baseline_scores['min']
            baseline_max = self.baseline_scores['max']
            baseline_range = baseline_max - baseline_min

            if baseline_range > 0:
                # Invert: (max - score) so that low raw score → high anomaly score
                anomaly_score = (baseline_max - anomaly_score_raw) / baseline_range
                # Clip to 0-1 range
                anomaly_score = np.clip(anomaly_score, 0.0, 1.0)
            else:
                anomaly_score = 0.5
        else:
            # Fallback: use sigmoid
            anomaly_score = 1 / (1 + np.exp(5 * anomaly_score_raw))
        
        # Determine severity
        severity = self._determine_severity(anomaly_score)
        
        return float(anomaly_score), severity
    
    def score_batch(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """
        Score a batch of queries.
        
        Args:
            features_df: DataFrame with feature columns
            
        Returns:
            DataFrame with added 'anomaly_score' and 'severity' columns
        """
        if self.model is None:
            logger.error("Model not loaded")
            features_df['anomaly_score'] = 0.0
            features_df['severity'] = Severity.NORMAL
            return features_df
        
        # Prepare features
        X = features_df[self.feature_names].values
        
        # Get anomaly scores
        anomaly_scores_raw = self.model.decision_function(X)

        # Min-max normalization with inversion
        if self.baseline_scores is not None and isinstance(self.baseline_scores, dict):
            # Normalize to 0-1 range, inverted so high score = anomalous
            baseline_min = self.baseline_scores['min']
            baseline_max = self.baseline_scores['max']
            baseline_range = baseline_max - baseline_min

            if baseline_range > 0:
                # Invert: (max - score) so that low raw score → high anomaly score
                anomaly_scores = (baseline_max - anomaly_scores_raw) / baseline_range
                # Clip to 0-1 range
                anomaly_scores = np.clip(anomaly_scores, 0.0, 1.0)
            else:
                anomaly_scores = np.full(len(anomaly_scores_raw), 0.5)
        else:
            # Fallback: use sigmoid
            anomaly_scores = 1 / (1 + np.exp(5 * anomaly_scores_raw))
        
        # Add to dataframe
        features_df['anomaly_score'] = anomaly_scores
        features_df['severity'] = features_df['anomaly_score'].apply(
            self._determine_severity
        )
        
        return features_df
    
    def _determine_severity(self, score: float) -> Severity:
        """Determine severity level based on anomaly score."""
        if score >= self.threshold_high:
            return Severity.HIGH
        elif score >= self.threshold_suspicious:
            return Severity.SUSPICIOUS
        else:
            return Severity.NORMAL
    
    def get_feature_importance(self) -> Dict[str, float]:
        """
        Get relative importance of features (experimental).
        
        Returns:
            Dictionary of feature names to importance scores
        """
        # Isolation Forest doesn't have native feature importance
        # This is a simplified heuristic
        if self.model is None:
            return {}
        
        # Use average path length as proxy for importance
        # Features that create more splits are more important
        importance = {name: 1.0 / (i + 1) for i, name in enumerate(self.feature_names)}
        
        # Normalize
        total = sum(importance.values())
        importance = {k: v / total for k, v in importance.items()}
        
        return importance


# Example usage
if __name__ == "__main__":
    # Create scorer
    scorer = AnomalyScorer()
    
    # Example features from a normal query
    normal_features = {
        'len_q': 15,
        'entropy': 2.5,
        'num_labels': 3,
        'max_label_len': 6,
        'digits_ratio': 0.0,
        'non_alnum_ratio': 0.0,
        'qps': 1.5,
        'unique_subdomains': 3,
        'avg_entropy': 2.4,
        'max_entropy': 2.6
    }
    
    # Example features from suspicious query
    suspicious_features = {
        'len_q': 65,
        'entropy': 4.8,
        'num_labels': 4,
        'max_label_len': 48,
        'digits_ratio': 0.3,
        'non_alnum_ratio': 0.05,
        'qps': 25.0,
        'unique_subdomains': 50,
        'avg_entropy': 4.5,
        'max_entropy': 4.9
    }
    
    # Train on some baseline data (normally would be real data)
    baseline_data = pd.DataFrame([normal_features] * 100)
    scorer.train(baseline_data)
    
    # Score queries
    score1, severity1 = scorer.score(normal_features)
    print(f"Normal query: score={score1:.3f}, severity={severity1}")
    
    score2, severity2 = scorer.score(suspicious_features)
    print(f"Suspicious query: score={score2:.3f}, severity={severity2}")

