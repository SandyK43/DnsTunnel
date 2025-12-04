#!/usr/bin/env python3
"""
Configuration helper for InnoSetup installer
Generates config.yaml based on user inputs
"""

import sys
import yaml
from pathlib import Path

def generate_config(install_path: str, **kwargs):
    """Generate config.yaml from installer inputs."""
    
    config = {
        'detection': {
            'threshold_suspicious': float(kwargs.get('threshold_suspicious', 0.70)),
            'threshold_high': float(kwargs.get('threshold_high', 0.85)),
            'window_size': 60,
            'model_path': 'models/isolation_forest.pkl'
        },
        'adaptive_thresholds': {
            'enabled': True,
            'target_fp_rate': 0.03,
            'max_fp_rate': 0.10,
            'min_fp_rate': 0.01,
            'adjustment_increment': 0.02,
            'min_samples_for_adjustment': 100,
            'check_interval_minutes': 60,
            'max_adjustment_frequency_hours': 6,
            'evaluation_window_hours': 24
        },
        'database': {
            'type': kwargs.get('db_type', 'sqlite'),
            'path': 'data/dns_tunnel.db' if kwargs.get('db_type', 'sqlite') == 'sqlite' else None
        },
        'alerting': {
            'throttle_seconds': 300,
            'slack': {
                'enabled': bool(kwargs.get('slack_webhook')),
                'webhook_url': kwargs.get('slack_webhook', '')
            },
            'email': {
                'enabled': bool(kwargs.get('email_to')),
                'smtp_host': kwargs.get('smtp_host', 'smtp.gmail.com'),
                'smtp_port': 587,
                'to_addresses': kwargs.get('email_to', '')
            }
        },
        'api': {
            'host': kwargs.get('api_host', '0.0.0.0'),
            'port': int(kwargs.get('api_port', 8000))
        }
    }
    
    config_path = Path(install_path) / 'config.yaml'
    with open(config_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    
    print(f"Configuration written to: {config_path}")
    return 0

if __name__ == '__main__':
    # Parse command line arguments
    args = dict(arg.split('=') for arg in sys.argv[1:] if '=' in arg)
    sys.exit(generate_config(**args))
