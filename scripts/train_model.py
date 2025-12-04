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


def load_bind_log(log_path: str) -> pd.DataFrame:
    """Load and parse Bind9 query log file."""
    logger.info(f"Loading Bind9 log from: {log_path}")

    import re

    records = []

    # Bind9 query log format:
    # client @0x7f8b4c001f30 192.168.1.100#52847 (www.example.com): query: www.example.com IN A + (192.168.1.1)
    # OR
    # queries: info: client 192.168.1.100#52847: query: www.example.com IN A + (192.168.1.1)

    query_pattern = re.compile(
        r'client\s+(?:@[^\s]+\s+)?'  # Optional object pointer
        r'([\d\.]+)#\d+.*?'           # IP address
        r'query:\s+([^\s]+)\s+'       # Query domain
    )

    with open(log_path, 'r') as f:
        for line in f:
            match = query_pattern.search(line)
            if match:
                client_ip = match.group(1)
                query = match.group(2)

                # Filter out localhost and empty queries
                if query and client_ip and client_ip != '127.0.0.1':
                    records.append({
                        'query': query,
                        'client_ip': client_ip
                    })

    df = pd.DataFrame(records)
    logger.info(f"Loaded {len(df)} DNS records")

    return df


def generate_sample_data(num_samples: int = 1000) -> pd.DataFrame:
    """Generate sample baseline DNS data for testing with high diversity."""
    logger.info(f"Generating {num_samples} sample DNS records")

    import random
    import string

    # Common legitimate domains (40% of traffic)
    common_domains = [
        "www.google.com", "google.com", "youtube.com", "www.youtube.com",
        "facebook.com", "www.facebook.com", "amazon.com", "www.amazon.com",
        "mail.google.com", "drive.google.com", "docs.google.com",
        "api.github.com", "github.com", "www.wikipedia.org",
        "stackoverflow.com", "www.reddit.com"
    ]

    # Cloud/CDN services (15% of traffic)
    cloud_services = [
        "s3.amazonaws.com", "cloudfront.net", "azureedge.net",
        "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
        "fonts.googleapis.com", "ajax.googleapis.com", "gstatic.com",
        "doubleclick.net", "googletagmanager.com", "analytics.google.com"
    ]

    # Corporate/internal patterns (20% of traffic)
    corporate_prefixes = ["mail", "webmail", "portal", "intranet", "vpn", "gitlab", "jenkins",
                          "confluence", "jira", "wiki", "docs", "api", "app", "dev", "staging"]
    corporate_bases = ["company.com", "corp.local", "internal.net", "enterprise.io",
                       "business.org", "office365.com"]

    # Various TLDs for diversity (15% of traffic)
    tlds = ["com", "org", "net", "edu", "gov", "co.uk", "io", "ai", "dev", "app"]
    short_domains = ["cnn", "bbc", "msn", "espn", "imdb", "imgur", "twitch"]

    # Subdomains with numbers/IDs (10% of traffic)
    numbered_patterns = ["server{}", "node{}", "api-{}", "cdn{}", "cache{}",
                         "lb{}", "web{}", "app{}", "db{}"]

    records = []

    for i in range(num_samples):
        dice = random.random()

        if dice < 0.40:
            # Common domains
            query = random.choice(common_domains)
        elif dice < 0.55:
            # Cloud services
            query = random.choice(cloud_services)
        elif dice < 0.75:
            # Corporate/internal
            prefix = random.choice(corporate_prefixes)
            base = random.choice(corporate_bases)
            query = f"{prefix}.{base}"
        elif dice < 0.90:
            # Short domains with various TLDs
            domain = random.choice(short_domains)
            tld = random.choice(tlds)
            query = f"{domain}.{tld}"
        else:
            # Numbered/ID-based subdomains
            pattern = random.choice(numbered_patterns)
            num = random.randint(1, 99)
            base = random.choice(["example.com", "service.net", "cloud.io"])
            query = f"{pattern.format(num)}.{base}"

        record = {
            'query': query,
            'client_ip': f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
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
        choices=['zeek', 'bind', 'json', 'sample'],
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
    elif args.format == 'bind':
        df = load_bind_log(args.input)
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

