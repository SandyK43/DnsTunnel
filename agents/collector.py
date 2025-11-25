"""
Log Collector Agent
Ingests DNS logs from Zeek/Suricata and forwards them for processing.
"""

import asyncio
import json
from typing import Dict, List, Optional, Callable
from datetime import datetime
from pathlib import Path
import aiofiles
from loguru import logger


class ZeekLogParser:
    """Parser for Zeek DNS log format."""
    
    # Zeek dns.log field mapping (TSV format)
    ZEEK_FIELDS = [
        'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
        'proto', 'trans_id', 'rtt', 'query', 'qclass', 'qclass_name',
        'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD',
        'RA', 'Z', 'answers', 'TTLs', 'rejected'
    ]
    
    @staticmethod
    def parse_line(line: str) -> Optional[Dict]:
        """
        Parse a single line from Zeek dns.log.
        
        Args:
            line: TSV line from Zeek log
            
        Returns:
            Dictionary with parsed fields or None if invalid
        """
        # Skip comments and empty lines
        if not line or line.startswith('#'):
            return None
        
        try:
            fields = line.strip().split('\t')
            
            # Basic validation
            if len(fields) < len(ZeekLogParser.ZEEK_FIELDS):
                return None
            
            # Create record
            record = {}
            for i, field_name in enumerate(ZeekLogParser.ZEEK_FIELDS):
                value = fields[i] if i < len(fields) else '-'
                
                # Convert types
                if field_name == 'ts':
                    try:
                        record['timestamp'] = datetime.fromtimestamp(float(value))
                    except:
                        record['timestamp'] = datetime.utcnow()
                elif field_name == 'id.orig_h':
                    record['client_ip'] = value
                elif field_name == 'query':
                    record['query'] = value if value != '-' else ''
                elif field_name == 'qtype_name':
                    record['qtype'] = value
                elif field_name == 'rcode_name':
                    record['rcode'] = value
                else:
                    record[field_name] = value
            
            # Validation: must have query and client_ip
            if not record.get('query') or not record.get('client_ip'):
                return None
            
            return record
            
        except Exception as e:
            logger.debug(f"Failed to parse line: {e}")
            return None


class LogCollector:
    """
    Collects DNS logs from various sources and streams them for processing.
    
    Supports:
    - Zeek dns.log files (tail mode)
    - JSON log files
    - Direct API ingestion
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        """
        Args:
            callback: Async function to call with each parsed record
        """
        self.callback = callback
        self.running = False
        self.parser = ZeekLogParser()
    
    async def tail_zeek_log(self, log_path: str, interval: float = 1.0):
        """
        Tail a Zeek DNS log file and stream records.
        
        Args:
            log_path: Path to Zeek dns.log file
            interval: Polling interval in seconds
        """
        logger.info(f"Starting to tail Zeek log: {log_path}")
        self.running = True
        
        file_path = Path(log_path)
        
        # Wait for file to exist
        while not file_path.exists() and self.running:
            logger.warning(f"Log file not found: {log_path}, waiting...")
            await asyncio.sleep(interval)
        
        try:
            async with aiofiles.open(log_path, 'r') as f:
                # Seek to end of file (only read new lines)
                await f.seek(0, 2)
                
                while self.running:
                    line = await f.readline()
                    
                    if line:
                        # Parse and process line
                        record = self.parser.parse_line(line)
                        if record and self.callback:
                            await self.callback(record)
                    else:
                        # No new data, wait before next check
                        await asyncio.sleep(interval)
                        
        except Exception as e:
            logger.error(f"Error tailing log: {e}")
            self.running = False
    
    async def read_zeek_log_batch(self, log_path: str) -> List[Dict]:
        """
        Read entire Zeek log file and return all records.
        
        Args:
            log_path: Path to Zeek dns.log file
            
        Returns:
            List of parsed records
        """
        logger.info(f"Reading Zeek log batch from: {log_path}")
        records = []
        
        try:
            async with aiofiles.open(log_path, 'r') as f:
                async for line in f:
                    record = self.parser.parse_line(line)
                    if record:
                        records.append(record)
                        
            logger.info(f"Read {len(records)} records from {log_path}")
            return records
            
        except Exception as e:
            logger.error(f"Error reading log batch: {e}")
            return []
    
    async def ingest_json_log(self, log_path: str, interval: float = 1.0):
        """
        Tail a JSON log file (one JSON object per line).
        
        Args:
            log_path: Path to JSON log file
            interval: Polling interval in seconds
        """
        logger.info(f"Starting to tail JSON log: {log_path}")
        self.running = True
        
        file_path = Path(log_path)
        
        while not file_path.exists() and self.running:
            logger.warning(f"Log file not found: {log_path}, waiting...")
            await asyncio.sleep(interval)
        
        try:
            async with aiofiles.open(log_path, 'r') as f:
                await f.seek(0, 2)
                
                while self.running:
                    line = await f.readline()
                    
                    if line:
                        try:
                            record = json.loads(line.strip())
                            
                            # Ensure required fields exist
                            if 'query' in record and 'client_ip' in record:
                                # Parse timestamp if string
                                if isinstance(record.get('timestamp'), str):
                                    record['timestamp'] = datetime.fromisoformat(
                                        record['timestamp'].replace('Z', '+00:00')
                                    )
                                elif 'timestamp' not in record:
                                    record['timestamp'] = datetime.utcnow()
                                
                                if self.callback:
                                    await self.callback(record)
                                    
                        except json.JSONDecodeError as e:
                            logger.debug(f"Invalid JSON line: {e}")
                    else:
                        await asyncio.sleep(interval)
                        
        except Exception as e:
            logger.error(f"Error tailing JSON log: {e}")
            self.running = False
    
    def stop(self):
        """Stop the log collector."""
        logger.info("Stopping log collector")
        self.running = False
    
    def is_running(self) -> bool:
        """Check if collector is running."""
        return self.running


# Example usage
async def example_callback(record: Dict):
    """Example callback function."""
    print(f"Received DNS query: {record['query']} from {record['client_ip']}")


async def main():
    """Example usage."""
    collector = LogCollector(callback=example_callback)
    
    # Simulate a Zeek log file
    test_log = "/tmp/test_dns.log"
    
    # Create test log with sample data
    sample_lines = [
        "#separator \\x09",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected",
        "1700000000.123456\tC1234\t192.168.1.100\t54321\t8.8.8.8\t53\tudp\t12345\t0.025\twww.google.com\t1\tC_INTERNET\t1\tA\t0\tNOXERROR\tF\tF\tT\tT\t0\t142.250.80.46\t300\tF",
    ]
    
    with open(test_log, 'w') as f:
        for line in sample_lines:
            f.write(line + '\n')
    
    # Start collector
    task = asyncio.create_task(collector.tail_zeek_log(test_log, interval=0.5))
    
    # Let it run for a bit
    await asyncio.sleep(2)
    
    # Add more lines
    with open(test_log, 'a') as f:
        f.write("1700000001.123456\tC1235\t192.168.1.101\t54322\t8.8.8.8\t53\tudp\t12346\t0.030\taaaaabbbbbccccc.evil.com\t1\tC_INTERNET\t1\tA\t0\tNOXERROR\tF\tF\tT\tT\t0\t1.2.3.4\t300\tF\n")
    
    await asyncio.sleep(2)
    
    # Stop collector
    collector.stop()
    await task


if __name__ == "__main__":
    asyncio.run(main())

