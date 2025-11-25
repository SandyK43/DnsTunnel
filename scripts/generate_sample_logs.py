"""
Generate sample DNS logs for testing and demo purposes.
Includes both benign and malicious (tunneling) traffic.
"""

import argparse
import random
import json
from datetime import datetime, timedelta
from pathlib import Path


def generate_benign_queries(num_queries: int) -> list:
    """Generate benign DNS queries."""
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
        "cdn.cloudflare.com",
        "www.mozilla.org",
        "www.ubuntu.com",
        "www.python.org",
    ]
    
    queries = []
    start_time = datetime.utcnow() - timedelta(hours=1)
    
    for i in range(num_queries):
        query = {
            'timestamp': (start_time + timedelta(seconds=i*3.6)).isoformat(),
            'query': random.choice(domains),
            'client_ip': f"192.168.1.{random.randint(10, 200)}",
            'qtype': 'A'
        }
        queries.append(query)
    
    return queries


def generate_tunneling_queries(num_queries: int, tunnel_type: str = 'dnscat2') -> list:
    """Generate DNS tunneling queries simulating various tools."""
    queries = []
    start_time = datetime.utcnow() - timedelta(minutes=30)
    
    # Base domains for tunneling
    base_domains = ["evil.com", "malicious.net", "c2server.org"]
    base_domain = random.choice(base_domains)
    
    for i in range(num_queries):
        if tunnel_type == 'dnscat2':
            # dnscat2 uses encoded subdomains with session IDs
            session_id = f"{random.randint(1000, 9999):04x}"
            data = ''.join(random.choices('0123456789abcdef', k=32))
            subdomain = f"{session_id}.{data}.{base_domain}"
            
        elif tunnel_type == 'iodine':
            # iodine uses base32 encoding with prefix
            data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz234567', k=24))
            subdomain = f"t{data}.{base_domain}"
            
        elif tunnel_type == 'custom':
            # Custom exfiltration with high entropy
            data = ''.join(random.choices('0123456789abcdefghijklmnopqrstuvwxyz', k=40))
            subdomain = f"{data}.{base_domain}"
            
        else:
            subdomain = f"test.{base_domain}"
        
        query = {
            'timestamp': (start_time + timedelta(seconds=i*2)).isoformat(),
            'query': subdomain,
            'client_ip': f"10.0.1.{random.randint(50, 60)}",  # Different subnet for malicious
            'qtype': 'TXT' if random.random() < 0.3 else 'A'
        }
        queries.append(query)
    
    return queries


def save_as_json(queries: list, output_path: str):
    """Save queries as JSON lines format."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        for query in queries:
            f.write(json.dumps(query) + '\n')
    
    print(f"Saved {len(queries)} queries to {output_path}")


def save_as_zeek(queries: list, output_path: str):
    """Save queries as Zeek TSV format."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        # Write Zeek header
        f.write("#separator \\x09\n")
        f.write("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected\n")
        
        # Write queries
        for query in queries:
            ts = datetime.fromisoformat(query['timestamp'].replace('Z', '')).timestamp()
            uid = f"C{random.randint(10000, 99999)}"
            orig_h = query['client_ip']
            orig_p = random.randint(50000, 60000)
            resp_h = "8.8.8.8"
            resp_p = 53
            proto = "udp"
            trans_id = random.randint(1000, 9999)
            rtt = f"{random.uniform(0.01, 0.1):.3f}"
            qname = query['query']
            qclass = "1"
            qclass_name = "C_INTERNET"
            qtype = "1" if query['qtype'] == 'A' else "16"
            qtype_name = query['qtype']
            rcode = "0"
            rcode_name = "NOERROR"
            
            line = f"{ts}\t{uid}\t{orig_h}\t{orig_p}\t{resp_h}\t{resp_p}\t{proto}\t{trans_id}\t{rtt}\t{qname}\t{qclass}\t{qclass_name}\t{qtype}\t{qtype_name}\t{rcode}\t{rcode_name}\tF\tF\tT\tT\t0\t-\t-\tF\n"
            f.write(line)
    
    print(f"Saved {len(queries)} queries to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate sample DNS logs")
    parser.add_argument(
        '--benign',
        type=int,
        default=1000,
        help='Number of benign queries to generate'
    )
    parser.add_argument(
        '--malicious',
        type=int,
        default=100,
        help='Number of malicious queries to generate'
    )
    parser.add_argument(
        '--tunnel-type',
        type=str,
        choices=['dnscat2', 'iodine', 'custom'],
        default='dnscat2',
        help='Type of DNS tunnel to simulate'
    )
    parser.add_argument(
        '--format',
        type=str,
        choices=['json', 'zeek'],
        default='json',
        help='Output format'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='./data/sample_dns.log',
        help='Output file path'
    )
    
    args = parser.parse_args()
    
    # Generate queries
    print(f"Generating {args.benign} benign queries...")
    benign = generate_benign_queries(args.benign)
    
    print(f"Generating {args.malicious} malicious queries ({args.tunnel_type})...")
    malicious = generate_tunneling_queries(args.malicious, args.tunnel_type)
    
    # Combine and shuffle
    all_queries = benign + malicious
    random.shuffle(all_queries)
    
    # Sort by timestamp
    all_queries.sort(key=lambda x: x['timestamp'])
    
    # Save
    if args.format == 'json':
        save_as_json(all_queries, args.output)
    else:
        save_as_zeek(all_queries, args.output)
    
    print(f"\nGenerated log summary:")
    print(f"  Total queries: {len(all_queries)}")
    print(f"  Benign: {args.benign}")
    print(f"  Malicious: {args.malicious}")
    print(f"  Detection rate expected: ~{args.malicious/len(all_queries)*100:.2f}%")


if __name__ == "__main__":
    main()

