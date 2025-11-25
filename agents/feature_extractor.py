"""
Feature Extraction Agent
Computes DNS query features for anomaly detection.
"""

import math
import re
from collections import defaultdict
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import pandas as pd
import numpy as np


class FeatureExtractor:
    """
    Extracts features from DNS queries for ML-based anomaly detection.
    
    Features:
    - len_q: Query length
    - entropy: Shannon entropy
    - num_labels: Number of domain labels (dots + 1)
    - max_label_len: Maximum label length
    - digits_ratio: Ratio of digits to total characters
    - non_alnum_ratio: Ratio of non-alphanumeric characters
    - qps: Queries per second (window-based)
    - unique_subdomains: Unique subdomain count (window-based)
    - avg_entropy: Average entropy in time window
    - max_entropy: Maximum entropy in time window
    """
    
    def __init__(self, window_size: int = 60):
        """
        Args:
            window_size: Time window in seconds for aggregated features
        """
        self.window_size = window_size
        self.query_history: Dict[str, List[Dict]] = defaultdict(list)
        
    def extract_features(self, query: str, client_ip: str, 
                        timestamp: Optional[datetime] = None) -> Dict[str, float]:
        """
        Extract all features from a DNS query.
        
        Args:
            query: DNS query string (e.g., "subdomain.example.com")
            client_ip: Source IP address
            timestamp: Query timestamp (defaults to now)
            
        Returns:
            Dictionary of feature values
        """
        if timestamp is None:
            timestamp = datetime.utcnow()
            
        # Per-query features
        features = {
            'len_q': self._get_length(query),
            'entropy': self._calculate_entropy(query),
            'num_labels': self._count_labels(query),
            'max_label_len': self._max_label_length(query),
            'digits_ratio': self._digits_ratio(query),
            'non_alnum_ratio': self._non_alphanumeric_ratio(query),
        }
        
        # Store query in history for window-based features
        query_record = {
            'query': query,
            'timestamp': timestamp,
            'entropy': features['entropy']
        }
        self.query_history[client_ip].append(query_record)
        
        # Clean old queries outside window
        self._clean_old_queries(client_ip, timestamp)
        
        # Window-based features
        window_features = self._extract_window_features(client_ip)
        features.update(window_features)
        
        return features
    
    def _get_length(self, query: str) -> int:
        """Get query length."""
        return len(query)
    
    def _calculate_entropy(self, query: str) -> float:
        """
        Calculate Shannon entropy of the query string.
        Higher entropy indicates more randomness (common in tunneling).
        """
        if not query:
            return 0.0
            
        # Count character frequencies
        char_counts = defaultdict(int)
        for char in query:
            char_counts[char] += 1
            
        # Calculate entropy
        length = len(query)
        entropy = 0.0
        for count in char_counts.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)
                
        return entropy
    
    def _count_labels(self, query: str) -> int:
        """Count number of DNS labels (subdomains)."""
        return query.count('.') + 1
    
    def _max_label_length(self, query: str) -> int:
        """Get maximum length of any label in the domain."""
        labels = query.split('.')
        return max(len(label) for label in labels) if labels else 0
    
    def _digits_ratio(self, query: str) -> float:
        """Calculate ratio of digits to total characters."""
        if not query:
            return 0.0
        digit_count = sum(1 for char in query if char.isdigit())
        return digit_count / len(query)
    
    def _non_alphanumeric_ratio(self, query: str) -> float:
        """Calculate ratio of non-alphanumeric characters (excluding dots)."""
        if not query:
            return 0.0
        non_alnum_count = sum(1 for char in query if not char.isalnum() and char != '.')
        return non_alnum_count / len(query)
    
    def _clean_old_queries(self, client_ip: str, current_time: datetime):
        """Remove queries outside the time window."""
        cutoff_time = current_time - timedelta(seconds=self.window_size)
        self.query_history[client_ip] = [
            q for q in self.query_history[client_ip]
            if q['timestamp'] > cutoff_time
        ]
    
    def _extract_window_features(self, client_ip: str) -> Dict[str, float]:
        """Extract time-window aggregated features."""
        queries = self.query_history[client_ip]
        
        if not queries:
            return {
                'qps': 0.0,
                'unique_subdomains': 0,
                'avg_entropy': 0.0,
                'max_entropy': 0.0
            }
        
        # Queries per second
        if len(queries) > 1:
            time_span = (queries[-1]['timestamp'] - queries[0]['timestamp']).total_seconds()
            qps = len(queries) / max(time_span, 1.0)
        else:
            qps = 1.0
        
        # Unique subdomains (full queries)
        unique_domains = len(set(q['query'] for q in queries))
        
        # Entropy statistics
        entropies = [q['entropy'] for q in queries]
        avg_entropy = np.mean(entropies)
        max_entropy = np.max(entropies)
        
        return {
            'qps': qps,
            'unique_subdomains': unique_domains,
            'avg_entropy': avg_entropy,
            'max_entropy': max_entropy
        }
    
    def extract_batch_features(self, queries: List[Dict]) -> pd.DataFrame:
        """
        Extract features from a batch of queries.
        
        Args:
            queries: List of dicts with 'query', 'client_ip', 'timestamp'
            
        Returns:
            DataFrame with features
        """
        features_list = []
        
        for q in queries:
            features = self.extract_features(
                query=q['query'],
                client_ip=q['client_ip'],
                timestamp=q.get('timestamp')
            )
            features['query'] = q['query']
            features['client_ip'] = q['client_ip']
            features['timestamp'] = q.get('timestamp', datetime.utcnow())
            features_list.append(features)
        
        return pd.DataFrame(features_list)
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names used by the model."""
        return [
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


# Example usage
if __name__ == "__main__":
    extractor = FeatureExtractor(window_size=60)
    
    # Normal query
    normal_features = extractor.extract_features(
        query="www.google.com",
        client_ip="192.168.1.100"
    )
    print("Normal query features:", normal_features)
    
    # Suspicious query (high entropy, long subdomain)
    suspicious_features = extractor.extract_features(
        query="a3f8b2c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3.evil.com",
        client_ip="192.168.1.100"
    )
    print("\nSuspicious query features:", suspicious_features)

