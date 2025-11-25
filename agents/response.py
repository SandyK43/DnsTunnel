"""
Response Agent
Executes automated remediation actions for detected threats.
"""

import os
import asyncio
import subprocess
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from enum import Enum
import httpx
from loguru import logger


class ResponseAction(str, Enum):
    """Available response actions."""
    BLOCK_IP = "block_ip"
    QUARANTINE_HOST = "quarantine_host"
    BLOCK_DOMAIN = "block_domain"
    ALERT_ONLY = "alert_only"


class ResponseStatus(str, Enum):
    """Status of response actions."""
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    MANUAL_REQUIRED = "manual_required"


class ResponseAgent:
    """
    Executes automated remediation actions for DNS tunneling threats.
    
    Actions:
    - Block source IP via firewall API
    - Quarantine affected host
    - Block malicious domain in DNS server
    - Manual approval workflows
    """
    
    def __init__(
        self,
        auto_response_enabled: bool = False,
        auto_block_threshold: float = 0.8,
        firewall_api_url: Optional[str] = None,
        firewall_api_key: Optional[str] = None,
        require_manual_approval: bool = True
    ):
        """
        Args:
            auto_response_enabled: Enable automatic response actions
            auto_block_threshold: Anomaly score threshold for auto-blocking
            firewall_api_url: URL of firewall control API
            firewall_api_key: API key for firewall
            require_manual_approval: Require manual approval for actions
        """
        self.auto_response_enabled = auto_response_enabled
        self.auto_block_threshold = auto_block_threshold
        self.firewall_api_url = firewall_api_url or os.getenv('FIREWALL_API_URL')
        self.firewall_api_key = firewall_api_key or os.getenv('FIREWALL_API_KEY')
        self.require_manual_approval = require_manual_approval
        self.blocked_ips: Dict[str, datetime] = {}
        self.quarantined_hosts: Dict[str, datetime] = {}
        self.pending_approvals: List[Dict] = []
    
    async def handle_alert(self, alert_data: Dict) -> Dict:
        """
        Determine and execute appropriate response action.
        
        Args:
            alert_data: Alert information including severity and score
            
        Returns:
            Dict with action taken and status
        """
        severity = alert_data.get('severity', 'NORMAL')
        score = alert_data.get('anomaly_score', 0)
        client_ip = alert_data.get('client_ip', '')
        domain = alert_data.get('domain', '')
        
        response = {
            'action': ResponseAction.ALERT_ONLY,
            'status': ResponseStatus.SUCCESS,
            'timestamp': datetime.utcnow(),
            'details': {}
        }
        
        # Determine action based on severity and score
        if not self.auto_response_enabled:
            logger.info("Auto-response disabled, alert only")
            return response
        
        if score < self.auto_block_threshold:
            logger.info(f"Score {score:.3f} below auto-block threshold {self.auto_block_threshold}")
            return response
        
        # High severity - take action
        if severity == 'HIGH' and score >= self.auto_block_threshold:
            if self.require_manual_approval:
                # Queue for manual approval
                approval_request = {
                    'alert_data': alert_data,
                    'proposed_action': ResponseAction.BLOCK_IP,
                    'requested_at': datetime.utcnow(),
                    'approved': False
                }
                self.pending_approvals.append(approval_request)
                
                response['action'] = ResponseAction.BLOCK_IP
                response['status'] = ResponseStatus.MANUAL_REQUIRED
                response['details']['approval_id'] = len(self.pending_approvals) - 1
                
                logger.warning(f"Manual approval required for blocking {client_ip}")
            else:
                # Auto-block without approval
                block_result = await self.block_ip(client_ip, domain, duration_minutes=60)
                response['action'] = ResponseAction.BLOCK_IP
                response['status'] = ResponseStatus.SUCCESS if block_result else ResponseStatus.FAILED
                response['details'] = {'blocked_ip': client_ip, 'duration_minutes': 60}
        
        return response
    
    async def block_ip(self, ip_address: str, domain: str, duration_minutes: int = 60) -> bool:
        """
        Block an IP address via firewall.
        
        Args:
            ip_address: IP to block
            domain: Associated malicious domain
            duration_minutes: How long to block (0 = permanent)
            
        Returns:
            True if successful
        """
        logger.info(f"Attempting to block IP: {ip_address} for {duration_minutes} minutes")
        
        # Try firewall API first
        if self.firewall_api_url:
            try:
                success = await self._block_via_api(ip_address, duration_minutes)
                if success:
                    self.blocked_ips[ip_address] = datetime.utcnow()
                    logger.info(f"Successfully blocked {ip_address} via API")
                    return True
            except Exception as e:
                logger.error(f"Failed to block via API: {e}")
        
        # Fallback to iptables (Linux only)
        try:
            success = await self._block_via_iptables(ip_address)
            if success:
                self.blocked_ips[ip_address] = datetime.utcnow()
                
                # Schedule unblock if temporary
                if duration_minutes > 0:
                    asyncio.create_task(
                        self._schedule_unblock(ip_address, duration_minutes)
                    )
                
                logger.info(f"Successfully blocked {ip_address} via iptables")
                return True
        except Exception as e:
            logger.error(f"Failed to block via iptables: {e}")
        
        return False
    
    async def _block_via_api(self, ip_address: str, duration_minutes: int) -> bool:
        """Block IP via firewall REST API."""
        if not self.firewall_api_url:
            return False
        
        headers = {}
        if self.firewall_api_key:
            headers['Authorization'] = f'Bearer {self.firewall_api_key}'
        
        payload = {
            'action': 'block',
            'ip_address': ip_address,
            'duration_minutes': duration_minutes,
            'reason': 'DNS tunneling detected',
            'source': 'dns-tunnel-detection-service'
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.firewall_api_url}/block",
                json=payload,
                headers=headers,
                timeout=10.0
            )
            response.raise_for_status()
            
        return True
    
    async def _block_via_iptables(self, ip_address: str) -> bool:
        """Block IP via iptables (requires root/sudo)."""
        try:
            # Add iptables rule to DROP packets from IP
            cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
            
            # Run in executor to avoid blocking
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                subprocess.run,
                cmd.split(),
                {'capture_output': True, 'text': True}
            )
            
            return result.returncode == 0
        except Exception as e:
            logger.error(f"iptables command failed: {e}")
            return False
    
    async def _schedule_unblock(self, ip_address: str, duration_minutes: int):
        """Schedule automatic unblock after duration."""
        await asyncio.sleep(duration_minutes * 60)
        
        logger.info(f"Auto-unblocking {ip_address} after {duration_minutes} minutes")
        await self.unblock_ip(ip_address)
    
    async def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock a previously blocked IP.
        
        Args:
            ip_address: IP to unblock
            
        Returns:
            True if successful
        """
        logger.info(f"Unblocking IP: {ip_address}")
        
        # Try API first
        if self.firewall_api_url:
            try:
                await self._unblock_via_api(ip_address)
                if ip_address in self.blocked_ips:
                    del self.blocked_ips[ip_address]
                return True
            except Exception as e:
                logger.error(f"Failed to unblock via API: {e}")
        
        # Fallback to iptables
        try:
            cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                subprocess.run,
                cmd.split(),
                {'capture_output': True, 'text': True}
            )
            
            if result.returncode == 0:
                if ip_address in self.blocked_ips:
                    del self.blocked_ips[ip_address]
                logger.info(f"Successfully unblocked {ip_address}")
                return True
        except Exception as e:
            logger.error(f"Failed to unblock via iptables: {e}")
        
        return False
    
    async def _unblock_via_api(self, ip_address: str) -> bool:
        """Unblock IP via firewall REST API."""
        if not self.firewall_api_url:
            return False
        
        headers = {}
        if self.firewall_api_key:
            headers['Authorization'] = f'Bearer {self.firewall_api_key}'
        
        payload = {
            'action': 'unblock',
            'ip_address': ip_address
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.firewall_api_url}/unblock",
                json=payload,
                headers=headers,
                timeout=10.0
            )
            response.raise_for_status()
        
        return True
    
    async def quarantine_host(self, client_ip: str, duration_minutes: int = 60) -> bool:
        """
        Quarantine a host by isolating it to a restricted VLAN.
        
        Args:
            client_ip: IP of host to quarantine
            duration_minutes: Quarantine duration
            
        Returns:
            True if successful
        """
        logger.info(f"Quarantining host: {client_ip} for {duration_minutes} minutes")
        
        # This would integrate with network management systems
        # For now, we simulate by blocking
        result = await self.block_ip(client_ip, "quarantine", duration_minutes)
        
        if result:
            self.quarantined_hosts[client_ip] = datetime.utcnow()
        
        return result
    
    async def block_domain(self, domain: str) -> bool:
        """
        Block a domain in DNS server (sinkhole).
        
        Args:
            domain: Domain to block
            
        Returns:
            True if successful
        """
        logger.info(f"Blocking domain: {domain}")
        
        # This would integrate with DNS server (e.g., BIND, Unbound)
        # Could add to RPZ (Response Policy Zone) or blocklist
        
        # Placeholder implementation
        logger.warning("Domain blocking not yet implemented - requires DNS server integration")
        return False
    
    def approve_action(self, approval_id: int) -> bool:
        """
        Manually approve a pending response action.
        
        Args:
            approval_id: ID of pending approval
            
        Returns:
            True if approved
        """
        if approval_id < 0 or approval_id >= len(self.pending_approvals):
            logger.error(f"Invalid approval ID: {approval_id}")
            return False
        
        approval = self.pending_approvals[approval_id]
        approval['approved'] = True
        approval['approved_at'] = datetime.utcnow()
        
        logger.info(f"Action approved: {approval['proposed_action']}")
        
        # Execute the approved action asynchronously
        alert_data = approval['alert_data']
        asyncio.create_task(self._execute_approved_action(alert_data, approval['proposed_action']))
        
        return True
    
    async def _execute_approved_action(self, alert_data: Dict, action: ResponseAction):
        """Execute an approved response action."""
        client_ip = alert_data.get('client_ip', '')
        domain = alert_data.get('domain', '')
        
        if action == ResponseAction.BLOCK_IP:
            await self.block_ip(client_ip, domain, duration_minutes=60)
        elif action == ResponseAction.QUARANTINE_HOST:
            await self.quarantine_host(client_ip, duration_minutes=60)
        elif action == ResponseAction.BLOCK_DOMAIN:
            await self.block_domain(domain)
    
    def get_blocked_ips(self) -> List[Dict]:
        """Get list of currently blocked IPs."""
        return [
            {'ip': ip, 'blocked_at': timestamp}
            for ip, timestamp in self.blocked_ips.items()
        ]
    
    def get_pending_approvals(self) -> List[Dict]:
        """Get list of pending manual approvals."""
        return [
            {
                'id': i,
                'action': approval['proposed_action'],
                'ip': approval['alert_data'].get('client_ip'),
                'domain': approval['alert_data'].get('domain'),
                'score': approval['alert_data'].get('anomaly_score'),
                'requested_at': approval['requested_at'],
                'approved': approval['approved']
            }
            for i, approval in enumerate(self.pending_approvals)
            if not approval['approved']
        ]


# Example usage
async def main():
    """Example usage."""
    response_agent = ResponseAgent(
        auto_response_enabled=True,
        auto_block_threshold=0.8,
        require_manual_approval=True
    )
    
    # Simulate high-severity alert
    alert_data = {
        'severity': 'HIGH',
        'anomaly_score': 0.87,
        'domain': 'evil.com',
        'client_ip': '10.0.1.50',
        'timestamp': datetime.utcnow()
    }
    
    # Handle alert
    response = await response_agent.handle_alert(alert_data)
    print(f"Response: {response}")
    
    # Check pending approvals
    pending = response_agent.get_pending_approvals()
    print(f"Pending approvals: {pending}")
    
    # Approve action
    if pending:
        response_agent.approve_action(pending[0]['id'])
        await asyncio.sleep(1)  # Give time for action to execute


if __name__ == "__main__":
    asyncio.run(main())

