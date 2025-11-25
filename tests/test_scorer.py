"""
Unit tests for Anomaly Scoring Agent
"""

import pytest
import pandas as pd
from agents.scorer import AnomalyScorer, Severity
from agents.feature_extractor import FeatureExtractor


def test_scorer_initialization():
    """Test scorer initialization."""
    scorer = AnomalyScorer()
    
    assert scorer.model is not None
    assert scorer.threshold_suspicious == 0.6
    assert scorer.threshold_high == 0.8


def test_model_training():
    """Test model training."""
    scorer = AnomalyScorer()
    
    # Create dummy training data
    features_df = pd.DataFrame([
        {
            'len_q': 15,
            'entropy': 2.5,
            'num_labels': 3,
            'max_label_len': 6,
            'digits_ratio': 0.0,
            'non_alnum_ratio': 0.0,
            'qps': 1.0,
            'unique_subdomains': 5,
            'avg_entropy': 2.4,
            'max_entropy': 2.6
        }
        for _ in range(100)
    ])
    
    scorer.train(features_df)
    
    # Model should be trained
    assert hasattr(scorer.model, 'estimators_')


def test_scoring():
    """Test anomaly scoring."""
    # Train scorer
    scorer = AnomalyScorer()
    extractor = FeatureExtractor()
    
    # Generate baseline training data
    baseline = []
    for i in range(100):
        features = extractor.extract_features(
            query="www.example.com",
            client_ip="192.168.1.100"
        )
        baseline.append(features)
    
    scorer.train(pd.DataFrame(baseline))
    
    # Test normal query
    normal_features = extractor.extract_features(
        query="www.google.com",
        client_ip="192.168.1.100"
    )
    score, severity = scorer.score(normal_features)
    
    assert 0 <= score <= 1
    assert severity in [Severity.NORMAL, Severity.SUSPICIOUS, Severity.HIGH]
    
    # Test suspicious query
    suspicious_features = extractor.extract_features(
        query="a3f8b2c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3.evil.com",
        client_ip="10.0.1.50"
    )
    score2, severity2 = scorer.score(suspicious_features)
    
    # Suspicious should have higher score
    assert score2 > score


def test_severity_determination():
    """Test severity level determination."""
    scorer = AnomalyScorer(threshold_suspicious=0.6, threshold_high=0.8)
    
    assert scorer._determine_severity(0.5) == Severity.NORMAL
    assert scorer._determine_severity(0.7) == Severity.SUSPICIOUS
    assert scorer._determine_severity(0.9) == Severity.HIGH


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

