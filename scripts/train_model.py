"""
Model Training Script
Train Isolation Forest on baseline DNS traffic for anomaly detection.
"""

import argparse
import os
import sys
from pathlib import Path
import pandas as pd
from loguru import logger

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.feature_extractor import FeatureExtractor
from agents.scorer import AnomalyScorer


def load_zeek_log(log_path: str) -> pd.DataFrame:
    """Load and parse Zeek DNS log file."""
    logger.info(f"Loading Zeek log from: {log_path}")
    
    records = []
    
    with open(log_path, 'r') as f:
        for line in f:
            # Skip comments
            if line.startswith('#'):
                continue
            
            fields = line.strip().split('\t')
            
            # Basic Zeek dns.log has these fields
            if len(fields) >= 10:
                try:
                    record = {
                        'query': fields[9],  # query field
                        'client_ip': fields[2],  # id.orig_h
                    }
                    
                    # Filter out empty queries
                    if record['query'] and record['query'] != '-':
                        records.append(record)
                except:
                    continue
    
    df = pd.DataFrame(records)
    logger.info(f"Loaded {len(df)} DNS records")
    
    return df


def load_json_log(log_path: str) -> pd.DataFrame:
    """Load JSON log file (one record per line)."""
    logger.info(f"Loading JSON log from: {log_path}")
    
    df = pd.read_json(log_path, lines=True)
    
    # Ensure required columns
    if 'query' not in df.columns or 'client_ip' not in df.columns:
        raise ValueError("JSON log must contain 'query' and 'client_ip' fields")
    
    logger.info(f"Loaded {len(df)} DNS records")
    
    return df


def generate_sample_data(num_samples: int = 1000) -> pd.DataFrame:
    """Generate sample baseline DNS data for testing."""
    logger.info(f"Generating {num_samples} sample DNS records")
    
    import random
    
    # Common legitimate domains
    domains = [
        "www.google.com",
        "www.facebook.com",
        "www.youtube.com",
        "www.amazon.com",
        "www.wikipedia.org",
        "www.twitter.com",
        "api.github.com",
        "stackoverflow.com",
        "www.linkedin.com",
        "mail.google.com",
        "drive.google.com",
        "docs.google.com",
        "www.reddit.com",
        "www.netflix.com",
        "www.microsoft.com",
        "www.apple.com",
        "www.cloudflare.com",
        "www.mozilla.org",
        "www.ubuntu.com",
        "www.python.org",
    ]
    
    # Generate subdomains variations
    subdomains = ["www", "api", "cdn", "static", "mail", "ftp", "dev", "staging"]
    
    records = []
    
    for i in range(num_samples):
        # Mix direct domains and subdomain variations
        if random.random() < 0.7:
            query = random.choice(domains)
        else:
            subdomain = random.choice(subdomains)
            base = random.choice(domains).replace("www.", "")
            query = f"{subdomain}.{base}"
        
        record = {
            'query': query,
            'client_ip': f"192.168.1.{random.randint(1, 254)}"
        }
        records.append(record)
    
    return pd.DataFrame(records)


def extract_features_from_data(df: pd.DataFrame) -> pd.DataFrame:
    """Extract features from DNS query data."""
    logger.info("Extracting features from DNS queries...")
    
    extractor = FeatureExtractor(window_size=60)
    
    # Convert to list of dicts for batch processing
    queries = df.to_dict('records')
    
    # Extract features
    features_df = extractor.extract_batch_features(queries)
    
    logger.info(f"Extracted features for {len(features_df)} queries")
    
    return features_df


def train_model(features_df: pd.DataFrame, output_path: str, contamination: float = 0.01):
    """Train Isolation Forest model."""
    logger.info(f"Training Isolation Forest model with contamination={contamination}")
    
    # Initialize scorer
    scorer = AnomalyScorer()
    scorer.model.contamination = contamination
    
    # Train on features
    scorer.train(features_df)
    
    # Save model
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    scorer.save_model(output_path)
    
    logger.info(f"Model saved to: {output_path}")
    
    # Evaluate on training data to show baseline
    logger.info("Evaluating model on training data...")
    features_df = scorer.score_batch(features_df)
    
    # Show statistics
    logger.info(f"Mean anomaly score: {features_df['anomaly_score'].mean():.4f}")
    logger.info(f"Std anomaly score: {features_df['anomaly_score'].std():.4f}")
    logger.info(f"Max anomaly score: {features_df['anomaly_score'].max():.4f}")
    
    severity_counts = features_df['severity'].value_counts()
    logger.info(f"Severity distribution:\n{severity_counts}")
    
    return scorer


def main():
    """Main training function."""
    parser = argparse.ArgumentParser(description="Train DNS tunneling detection model")
    parser.add_argument(
        '--input',
        type=str,
        help='Path to input log file (Zeek or JSON format)'
    )
    parser.add_argument(
        '--format',
        type=str,
        choices=['zeek', 'json', 'sample'],
        default='zeek',
        help='Input log format (default: zeek)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='./models/isolation_forest.pkl',
        help='Path to save trained model (default: ./models/isolation_forest.pkl)'
    )
    parser.add_argument(
        '--contamination',
        type=float,
        default=0.01,
        help='Expected proportion of anomalies (default: 0.01 = 1%%)'
    )
    parser.add_argument(
        '--num-samples',
        type=int,
        default=1000,
        help='Number of samples to generate (if using sample data)'
    )
    
    args = parser.parse_args()
    
    # Load data
    if args.format == 'sample' or not args.input:
        logger.info("Generating sample baseline data...")
        df = generate_sample_data(args.num_samples)
    elif args.format == 'zeek':
        df = load_zeek_log(args.input)
    elif args.format == 'json':
        df = load_json_log(args.input)
    else:
        raise ValueError(f"Unknown format: {args.format}")
    
    # Extract features
    features_df = extract_features_from_data(df)
    
    # Train model
    scorer = train_model(features_df, args.output, args.contamination)
    
    logger.info("Training complete!")
    
    # Test with some examples
    logger.info("\n=== Testing Model ===")
    
    # Test normal query
    test_extractor = FeatureExtractor()
    normal_features = test_extractor.extract_features(
        query="www.google.com",
        client_ip="192.168.1.100"
    )
    score, severity = scorer.score(normal_features)
    logger.info(f"Normal query (www.google.com): score={score:.4f}, severity={severity}")
    
    # Test suspicious query
    suspicious_features = test_extractor.extract_features(
        query="a3f8b2c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3.evil.com",
        client_ip="192.168.1.100"
    )
    score, severity = scorer.score(suspicious_features)
    logger.info(f"Suspicious query (long subdomain): score={score:.4f}, severity={severity}")
    
    # Test high entropy query
    entropy_features = test_extractor.extract_features(
        query="aaabbbcccdddeeefff.xyz",
        client_ip="192.168.1.100"
    )
    score, severity = scorer.score(entropy_features)
    logger.info(f"High entropy query: score={score:.4f}, severity={severity}")


if __name__ == "__main__":
    main()

