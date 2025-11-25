"""
Unit tests for Feature Extraction Agent
"""

import pytest
from datetime import datetime
from agents.feature_extractor import FeatureExtractor


def test_basic_features():
    """Test basic feature extraction."""
    extractor = FeatureExtractor()
    
    features = extractor.extract_features(
        query="www.google.com",
        client_ip="192.168.1.100"
    )
    
    assert features['len_q'] == 14
    assert features['num_labels'] == 3
    assert features['entropy'] > 0
    assert features['digits_ratio'] == 0.0
    assert 0 <= features['non_alnum_ratio'] <= 1


def test_high_entropy_query():
    """Test detection of high entropy query."""
    extractor = FeatureExtractor()
    
    # Random-looking subdomain
    features = extractor.extract_features(
        query="a3f8b2c9d4e5f6a7b8c9d0e1f2a3b4c5.evil.com",
        client_ip="10.0.1.50"
    )
    
    assert features['entropy'] > 4.0  # High entropy
    assert features['len_q'] > 30  # Long query
    assert features['digits_ratio'] > 0.3  # Many digits


def test_window_features():
    """Test time-window aggregated features."""
    extractor = FeatureExtractor(window_size=60)
    
    # Send multiple queries from same IP
    client_ip = "192.168.1.100"
    
    for i in range(10):
        features = extractor.extract_features(
            query=f"query{i}.example.com",
            client_ip=client_ip
        )
    
    # Check window features
    assert features['qps'] > 0
    assert features['unique_subdomains'] == 10
    assert features['avg_entropy'] > 0


def test_empty_query():
    """Test handling of edge cases."""
    extractor = FeatureExtractor()
    
    features = extractor.extract_features(
        query="a.b",
        client_ip="192.168.1.1"
    )
    
    assert features['len_q'] == 3
    assert features['num_labels'] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

