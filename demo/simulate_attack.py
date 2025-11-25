"""
DNS Tunneling Attack Simulator
Simulates various DNS tunneling attacks for demonstration and testing.
"""

import argparse
import asyncio
import random
import string
import time
from datetime import datetime
from typing import List
import httpx
from loguru import logger


class DNSTunnelSimulator:
    """Simulates DNS tunneling attacks for testing the detection system."""
    
    def __init__(self, api_url: str = "http://localhost:8000"):
        """
        Args:
            api_url: Base URL of the DNS detection API
        """
        self.api_url = api_url
        self.client_ip = "10.0.1.50"  # Simulated compromised host
        
    async def simulate_dnscat2(self, num_queries: int = 50, delay: float = 2.0):
        """
        Simulate dnscat2 DNS tunneling.
        
        dnscat2 characteristics:
        - Encoded subdomains with session IDs
        - High query rate
        - Mix of query types (A, TXT)
        """
        logger.info(f"🎯 Simulating dnscat2 attack with {num_queries} queries...")
        
        base_domain = "c2server.evil.com"
        session_id = f"{random.randint(1000, 9999):04x}"
        
        async with httpx.AsyncClient() as client:
            for i in range(num_queries):
                # Generate encoded payload
                data = ''.join(random.choices(string.hexdigits.lower(), k=32))
                query = f"{session_id}.{data}.{base_domain}"
                
                # Send query
                await self._send_query(client, query, qtype="TXT" if i % 3 == 0 else "A")
                
                if (i + 1) % 10 == 0:
                    logger.info(f"  Sent {i + 1}/{num_queries} queries...")
                
                await asyncio.sleep(delay)
        
        logger.success("✅ dnscat2 simulation complete")
    
    async def simulate_iodine(self, num_queries: int = 50, delay: float = 2.5):
        """
        Simulate iodine DNS tunneling.
        
        iodine characteristics:
        - Base32 encoded subdomains
        - Prefix character 't' for data
        - NULL records used
        """
        logger.info(f"🎯 Simulating iodine attack with {num_queries} queries...")
        
        base_domain = "tunnel.evil.net"
        
        async with httpx.AsyncClient() as client:
            for i in range(num_queries):
                # Generate base32 encoded data
                data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz234567', k=24))
                query = f"t{data}.{base_domain}"
                
                # Send query
                await self._send_query(client, query, qtype="NULL")
                
                if (i + 1) % 10 == 0:
                    logger.info(f"  Sent {i + 1}/{num_queries} queries...")
                
                await asyncio.sleep(delay)
        
        logger.success("✅ iodine simulation complete")
    
    async def simulate_custom_exfiltration(self, num_queries: int = 30, delay: float = 3.0):
        """
        Simulate custom data exfiltration via DNS.
        
        Characteristics:
        - Very long subdomains
        - High entropy
        - Base64-like encoding
        """
        logger.info(f"🎯 Simulating custom exfiltration with {num_queries} queries...")
        
        base_domain = "exfil.malicious.org"
        
        # Simulate exfiltrating data
        data_chunks = [
            ''.join(random.choices(string.ascii_letters + string.digits, k=40))
            for _ in range(num_queries)
        ]
        
        async with httpx.AsyncClient() as client:
            for i, chunk in enumerate(data_chunks):
                query = f"{chunk}.{base_domain}"
                
                await self._send_query(client, query)
                
                if (i + 1) % 10 == 0:
                    logger.info(f"  Sent {i + 1}/{num_queries} queries...")
                
                await asyncio.sleep(delay)
        
        logger.success("✅ Custom exfiltration simulation complete")
    
    async def simulate_normal_traffic(self, num_queries: int = 100, delay: float = 1.0):
        """
        Simulate normal DNS traffic as baseline.
        """
        logger.info(f"📊 Simulating normal traffic with {num_queries} queries...")
        
        normal_domains = [
            "www.google.com",
            "www.facebook.com",
            "www.youtube.com",
            "api.github.com",
            "www.stackoverflow.com",
            "mail.google.com",
            "www.reddit.com",
            "www.amazon.com",
            "www.netflix.com",
            "www.microsoft.com"
        ]
        
        async with httpx.AsyncClient() as client:
            for i in range(num_queries):
                query = random.choice(normal_domains)
                client_ip = f"192.168.1.{random.randint(10, 200)}"
                
                await self._send_query(client, query, client_ip=client_ip)
                
                if (i + 1) % 20 == 0:
                    logger.info(f"  Sent {i + 1}/{num_queries} queries...")
                
                await asyncio.sleep(delay)
        
        logger.success("✅ Normal traffic simulation complete")
    
    async def _send_query(self, client: httpx.AsyncClient, query: str, 
                         qtype: str = "A", client_ip: str = None):
        """Send a DNS query to the API."""
        payload = {
            "query": query,
            "client_ip": client_ip or self.client_ip,
            "qtype": qtype,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            response = await client.post(
                f"{self.api_url}/api/v1/dns/analyze",
                json=payload,
                timeout=10.0
            )
            
            if response.status_code == 200:
                data = response.json()
                severity = data.get('severity')
                score = data.get('anomaly_score')
                
                if severity in ['SUSPICIOUS', 'HIGH']:
                    logger.warning(
                        f"🚨 DETECTED: {query[:50]}... | "
                        f"Score: {score:.3f} | Severity: {severity}"
                    )
            else:
                logger.error(f"API error: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Failed to send query: {e}")
    
    async def run_full_demo(self):
        """Run complete demo showing detection capabilities."""
        logger.info("=" * 70)
        logger.info("🎭 DNS TUNNELING DETECTION DEMO")
        logger.info("=" * 70)
        
        # Phase 1: Normal traffic
        logger.info("\n📊 Phase 1: Establishing baseline with normal traffic...")
        await self.simulate_normal_traffic(num_queries=20, delay=0.5)
        await asyncio.sleep(5)
        
        # Phase 2: dnscat2 attack
        logger.info("\n🎯 Phase 2: Launching dnscat2 tunneling attack...")
        await self.simulate_dnscat2(num_queries=15, delay=1.0)
        await asyncio.sleep(5)
        
        # Phase 3: iodine attack
        logger.info("\n🎯 Phase 3: Launching iodine tunneling attack...")
        await self.simulate_iodine(num_queries=15, delay=1.0)
        await asyncio.sleep(5)
        
        # Phase 4: Custom exfiltration
        logger.info("\n🎯 Phase 4: Launching custom data exfiltration...")
        await self.simulate_custom_exfiltration(num_queries=10, delay=1.5)
        
        logger.info("\n" + "=" * 70)
        logger.success("✅ Demo complete! Check Grafana dashboard and alerts.")
        logger.info("=" * 70)
        logger.info("\n📊 View results:")
        logger.info(f"  • Dashboard: {self.api_url.replace('8000', '3000')}")
        logger.info(f"  • API Stats: {self.api_url}/api/v1/stats")
        logger.info(f"  • Alerts: {self.api_url}/api/v1/alerts")


async def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="DNS Tunneling Attack Simulator")
    parser.add_argument(
        '--type',
        type=str,
        choices=['dnscat2', 'iodine', 'custom', 'normal', 'full'],
        default='full',
        help='Type of attack to simulate (default: full demo)'
    )
    parser.add_argument(
        '--queries',
        type=int,
        default=50,
        help='Number of queries to send (default: 50)'
    )
    parser.add_argument(
        '--delay',
        type=float,
        default=2.0,
        help='Delay between queries in seconds (default: 2.0)'
    )
    parser.add_argument(
        '--api-url',
        type=str,
        default='http://localhost:8000',
        help='API endpoint URL (default: http://localhost:8000)'
    )
    
    args = parser.parse_args()
    
    simulator = DNSTunnelSimulator(api_url=args.api_url)
    
    if args.type == 'full':
        await simulator.run_full_demo()
    elif args.type == 'dnscat2':
        await simulator.simulate_dnscat2(args.queries, args.delay)
    elif args.type == 'iodine':
        await simulator.simulate_iodine(args.queries, args.delay)
    elif args.type == 'custom':
        await simulator.simulate_custom_exfiltration(args.queries, args.delay)
    elif args.type == 'normal':
        await simulator.simulate_normal_traffic(args.queries, args.delay)


if __name__ == "__main__":
    asyncio.run(main())

