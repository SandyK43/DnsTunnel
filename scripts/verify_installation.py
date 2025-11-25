"""
Installation Verification Script
Checks that all components are properly configured and running.
"""

import sys
import os
import time
from typing import Tuple
import requests
from loguru import logger

# Suppress warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_service(name: str, url: str, timeout: int = 5) -> Tuple[bool, str]:
    """Check if a service is responding."""
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code < 500:
            return True, f"✅ {name} is running"
        else:
            return False, f"❌ {name} returned error: {response.status_code}"
    except requests.exceptions.ConnectionError:
        return False, f"❌ {name} is not reachable at {url}"
    except requests.exceptions.Timeout:
        return False, f"❌ {name} timed out"
    except Exception as e:
        return False, f"❌ {name} error: {str(e)}"


def check_api_health() -> Tuple[bool, str]:
    """Check API health endpoint."""
    try:
        response = requests.get("http://localhost:8000/api/v1/health", timeout=10)
        if response.status_code == 200:
            data = response.json()
            status = data.get('status', 'unknown')
            model_loaded = data.get('model_loaded', False)
            db_connected = data.get('database_connected', False)
            
            if status == 'healthy' and model_loaded and db_connected:
                return True, "✅ API is healthy (model loaded, database connected)"
            else:
                issues = []
                if not model_loaded:
                    issues.append("model not loaded")
                if not db_connected:
                    issues.append("database not connected")
                return False, f"⚠️  API is degraded: {', '.join(issues)}"
        else:
            return False, f"❌ API health check failed: {response.status_code}"
    except Exception as e:
        return False, f"❌ API health check error: {str(e)}"


def check_model_file() -> Tuple[bool, str]:
    """Check if ML model file exists."""
    model_path = "./models/isolation_forest.pkl"
    if os.path.exists(model_path):
        size = os.path.getsize(model_path)
        return True, f"✅ ML model found ({size} bytes)"
    else:
        return False, f"❌ ML model not found at {model_path}"


def test_api_endpoint() -> Tuple[bool, str]:
    """Test API with a sample query."""
    try:
        payload = {
            "query": "www.google.com",
            "client_ip": "192.168.1.100"
        }
        response = requests.post(
            "http://localhost:8000/api/v1/dns/analyze",
            json=payload,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            severity = data.get('severity')
            score = data.get('anomaly_score')
            return True, f"✅ API test successful (score: {score:.3f}, severity: {severity})"
        else:
            return False, f"❌ API test failed: {response.status_code}"
    except Exception as e:
        return False, f"❌ API test error: {str(e)}"


def main():
    """Run all verification checks."""
    logger.info("=" * 70)
    logger.info("🔍 DNS TUNNELING DETECTION - INSTALLATION VERIFICATION")
    logger.info("=" * 70)
    
    checks = []
    
    # Service checks
    logger.info("\n📡 Checking Services...")
    
    checks.append(check_service(
        "API Server",
        "http://localhost:8000"
    ))
    
    checks.append(check_service(
        "API Documentation",
        "http://localhost:8000/docs"
    ))
    
    checks.append(check_service(
        "Grafana Dashboard",
        "http://localhost:3000"
    ))
    
    checks.append(check_service(
        "Prometheus",
        "http://localhost:9090"
    ))
    
    checks.append(check_service(
        "PostgreSQL",
        "http://localhost:5432",
        timeout=2
    ))
    
    # Print service results
    for success, message in checks:
        if success:
            logger.info(message)
        else:
            logger.warning(message)
    
    # API-specific checks
    logger.info("\n🔧 Checking API Configuration...")
    
    health_ok, health_msg = check_api_health()
    logger.info(health_msg) if health_ok else logger.warning(health_msg)
    checks.append((health_ok, health_msg))
    
    model_ok, model_msg = check_model_file()
    logger.info(model_msg) if model_ok else logger.warning(model_msg)
    checks.append((model_ok, model_msg))
    
    # Functional test
    logger.info("\n🧪 Running Functional Tests...")
    
    test_ok, test_msg = test_api_endpoint()
    logger.info(test_msg) if test_ok else logger.error(test_msg)
    checks.append((test_ok, test_msg))
    
    # Summary
    logger.info("\n" + "=" * 70)
    total = len(checks)
    passed = sum(1 for ok, _ in checks if ok)
    failed = total - passed
    
    if failed == 0:
        logger.success(f"✅ ALL CHECKS PASSED ({passed}/{total})")
        logger.info("\n🎉 Installation verified successfully!")
        logger.info("\nNext steps:")
        logger.info("  1. Access API docs: http://localhost:8000/docs")
        logger.info("  2. View Grafana: http://localhost:3000 (admin/admin123)")
        logger.info("  3. Run demo: docker-compose exec api python demo/simulate_attack.py --type full")
        return 0
    else:
        logger.warning(f"⚠️  SOME CHECKS FAILED ({passed}/{total} passed, {failed} failed)")
        logger.info("\n🔧 Troubleshooting:")
        
        if not any(ok for ok, msg in checks if "API Server" in msg):
            logger.info("  • API not running: docker-compose up -d")
            logger.info("  • Check logs: docker-compose logs api")
        
        if not any(ok for ok, msg in checks if "model" in msg.lower()):
            logger.info("  • Train model: make train-model")
            logger.info("  • Or: docker-compose exec api python scripts/train_model.py --format sample")
        
        if not any(ok for ok, msg in checks if "database" in msg.lower()):
            logger.info("  • Check PostgreSQL: docker-compose logs postgres")
            logger.info("  • Restart: docker-compose restart postgres")
        
        return 1


if __name__ == "__main__":
    sys.exit(main())

