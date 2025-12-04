"""
DNS Tunnel Detection Service - Standalone Service
Single executable service for enterprise deployment
"""

import os
import sys
import time
import signal
import asyncio
from pathlib import Path
from typing import Optional
from datetime import datetime

from loguru import logger
import uvicorn
from fastapi import FastAPI

# Import agents
from agents.feature_extractor import FeatureExtractor
from agents.scorer import AnomalyScorer
from agents.alerting import AlertingAgent
from agents.response import ResponseAgent
from agents.collector import LogCollector


class DNSTunnelService:
    """Main service class that orchestrates all components."""

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = None
        self.running = False
        self.collector_task = None
        self.api_task = None

        # Components
        self.feature_extractor: Optional[FeatureExtractor] = None
        self.scorer: Optional[AnomalyScorer] = None
        self.alerting_agent: Optional[AlertingAgent] = None
        self.response_agent: Optional[ResponseAgent] = None
        self.log_collector: Optional[LogCollector] = None

        # Setup logging
        self._setup_logging()

    def _setup_logging(self):
        """Configure logging."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        # Remove default handler
        logger.remove()

        # Add file handler
        logger.add(
            log_dir / "dns_tunnel_{time}.log",
            rotation="10 MB",
            retention="30 days",
            level="INFO",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
        )

        # Add console handler
        logger.add(
            sys.stdout,
            level="INFO",
            format="<green>{time:HH:mm:ss}</green> | <level>{level}</level> | {message}"
        )

    def load_config(self):
        """Load configuration from file."""
        import yaml

        if not os.path.exists(self.config_path):
            logger.error(f"Configuration file not found: {self.config_path}")
            logger.error("Please run the installer first: python install.py")
            sys.exit(1)

        with open(self.config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        logger.info("Configuration loaded successfully")
        return self.config

    def initialize_components(self):
        """Initialize all detection components."""
        logger.info("Initializing DNS Tunnel Detection components...")

        # Feature Extractor
        self.feature_extractor = FeatureExtractor(
            window_size=self.config['detection'].get('window_size', 60)
        )
        logger.info("✓ Feature Extractor initialized")

        # Anomaly Scorer
        model_path = self.config['detection']['model_path']
        if not os.path.exists(model_path):
            logger.warning(f"Model not found at {model_path}. Creating default model...")
            self._create_default_model(model_path)

        self.scorer = AnomalyScorer(
            model_path=model_path,
            threshold_suspicious=self.config['detection']['threshold_suspicious'],
            threshold_high=self.config['detection']['threshold_high']
        )
        logger.info("✓ Anomaly Scorer initialized")

        # Alerting Agent
        self.alerting_agent = AlertingAgent(
            throttle_seconds=self.config['alerting'].get('throttle_seconds', 300),
            min_score_to_alert=self.config['detection']['threshold_suspicious']
        )
        logger.info("✓ Alerting Agent initialized")

        # Response Agent
        self.response_agent = ResponseAgent(
            auto_response_enabled=self.config['response'].get('auto_block', False),
            auto_block_threshold=self.config['detection']['threshold_high'],
            require_manual_approval=True
        )
        logger.info("✓ Response Agent initialized")

        # Log Collector (if enabled)
        if self.config['collector']['enabled']:
            self.log_collector = LogCollector(
                log_sources=self.config['collector']['sources'],
                api_endpoint=f"http://localhost:{self.config['api']['port']}/api/v1/dns/analyze"
            )
            logger.info("✓ Log Collector initialized")

        logger.info("All components initialized successfully")

    def _create_default_model(self, model_path: str):
        """Create a default ML model if none exists."""
        from sklearn.ensemble import IsolationForest
        import joblib

        logger.info("Training default model with sample data...")

        # Create models directory
        Path(model_path).parent.mkdir(parents=True, exist_ok=True)

        # Train on sample normal data
        from scripts.train_model import train_model
        train_model(format='sample', num_samples=5000, output_path=model_path)

        logger.info(f"Default model created at {model_path}")

    async def start_api_server(self):
        """Start the FastAPI server."""
        from api.main import app

        config = uvicorn.Config(
            app,
            host=self.config['api']['host'],
            port=self.config['api']['port'],
            log_level="info"
        )
        server = uvicorn.Server(config)

        logger.info(f"Starting API server on {self.config['api']['host']}:{self.config['api']['port']}")
        await server.serve()

    async def start_collector(self):
        """Start the log collector."""
        if not self.log_collector:
            return

        logger.info("Starting log collector...")

        while self.running:
            try:
                await self.log_collector.collect_and_analyze()
                await asyncio.sleep(1)  # Process logs every second
            except Exception as e:
                logger.error(f"Error in log collector: {e}")
                await asyncio.sleep(5)

    async def start_async(self):
        """Start all async components."""
        self.running = True

        # Start API server and collector concurrently
        tasks = [
            asyncio.create_task(self.start_api_server())
        ]

        if self.log_collector:
            tasks.append(asyncio.create_task(self.start_collector()))

        await asyncio.gather(*tasks)

    def start(self):
        """Start the service."""
        try:
            logger.info("=" * 60)
            logger.info("DNS Tunnel Detection Service Starting")
            logger.info("=" * 60)

            # Load configuration
            self.load_config()

            # Initialize components
            self.initialize_components()

            # Start service
            logger.info("Service started successfully")
            logger.info(f"API available at: http://{self.config['api']['host']}:{self.config['api']['port']}")
            logger.info("Press Ctrl+C to stop")

            # Run async event loop
            asyncio.run(self.start_async())

        except KeyboardInterrupt:
            logger.info("Received shutdown signal")
            self.stop()
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=True)
            sys.exit(1)

    def stop(self):
        """Stop the service gracefully."""
        logger.info("Shutting down DNS Tunnel Detection Service...")
        self.running = False

        # Cleanup
        if self.log_collector:
            self.log_collector.close()

        logger.info("Service stopped")
        sys.exit(0)


def main():
    """Main entry point for the service."""
    # Handle command line arguments
    config_path = "config.yaml"
    if len(sys.argv) > 1:
        config_path = sys.argv[1]

    # Create and start service
    service = DNSTunnelService(config_path=config_path)

    # Setup signal handlers
    signal.signal(signal.SIGINT, lambda s, f: service.stop())
    signal.signal(signal.SIGTERM, lambda s, f: service.stop())

    # Start service
    service.start()


if __name__ == "__main__":
    main()
