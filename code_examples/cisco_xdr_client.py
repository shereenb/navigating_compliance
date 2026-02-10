"""
Cisco XDR API Client
Demonstrates security orchestration, audit logging, and threat detection

API Documentation: https://developer.cisco.com/docs/xdr/
Authentication: OAuth2 client credentials

Credentials should be provided via environment variables:
- CISCO_XDR_CLIENT_ID: API client ID
- CISCO_XDR_CLIENT_SECRET: API client secret
- CISCO_XDR_URL: Base URL (defaults to https://visibility.amp.cisco.com)
"""

import os
import aiohttp
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta


class CiscoXDRAPI:
    """
    Client for Cisco XDR API
    https://developer.cisco.com/docs/xdr/

    Provides:
    - Security incident management
    - Audit event logging
    - Threat detection and response
    - Security orchestration workflows
    - Anomaly detection
    """

    def __init__(
        self,
        client_id: str = None,
        client_secret: str = None,
        base_url: str = None
    ):
        """
        Initialize Cisco XDR API client.

        Args:
            client_id: API client ID. If not provided,
                      reads from CISCO_XDR_CLIENT_ID environment variable.
            client_secret: API client secret. If not provided,
                          reads from CISCO_XDR_CLIENT_SECRET environment variable.
            base_url: API base URL. Defaults to https://visibility.amp.cisco.com
        """
        self.client_id = client_id or os.environ.get("CISCO_XDR_CLIENT_ID", "")
        self.client_secret = client_secret or os.environ.get("CISCO_XDR_CLIENT_SECRET", "")
        self.base_url = base_url or os.environ.get(
            "CISCO_XDR_URL",
            "https://visibility.amp.cisco.com"
        )
        self.token = None
        self.token_expires = None

    async def _get_token(self) -> str:
        """
        Get OAuth2 access token

        API: POST https://visibility.amp.cisco.com/iroh/oauth2/token
        """

        if self.token and self.token_expires > datetime.utcnow():
            return self.token

        async with aiohttp.ClientSession() as session:
            auth = aiohttp.BasicAuth(self.client_id, self.client_secret)

            async with session.post(
                f"{self.base_url}/iroh/oauth2/token",
                auth=auth,
                data={"grant_type": "client_credentials"}
            ) as response:
                response.raise_for_status()
                data = await response.json()

                self.token = data["access_token"]
                # Token valid for 1 hour
                self.token_expires = datetime.utcnow() + timedelta(hours=1)

                return self.token

    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """Make authenticated API request"""

        token = await self._get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        async with aiohttp.ClientSession() as session:
            url = f"{self.base_url}{endpoint}"
            async with session.request(
                method, url, headers=headers, **kwargs
            ) as response:
                response.raise_for_status()
                return await response.json()

    # Incident Management APIs

    async def create_incident(
        self,
        severity: str,
        title: str,
        description: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create security incident in XDR

        API: POST /iroh/iroh-response/respond/trigger

        Args:
            severity: "critical", "high", "medium", "low", "info"
            title: Incident title
            description: Detailed description
            context: Additional context data
        """
        # Demo mode: return simulated response if no credentials
        if not self.client_id or not self.client_secret:
            incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            return {
                "incident_id": incident_id,
                "status": "created",
                "severity": severity,
                "title": title,
                "url": f"{self.base_url}/investigate/incidents/{incident_id}",
                "demo_mode": True
            }

        endpoint = "/iroh/iroh-response/respond/trigger"

        incident_data = {
            "type": "incident",
            "data": {
                "title": title,
                "description": description,
                "severity": severity,
                "status": "new",
                "timestamp": datetime.utcnow().isoformat(),
                "source": "MCP_AI_Agent",
                "observables": self._extract_observables(context),
                "context": context
            }
        }

        response = await self._request("POST", endpoint, json=incident_data)

        return {
            "incident_id": response.get("id"),
            "status": "created",
            "severity": severity,
            "title": title,
            "url": f"{self.base_url}/investigate/incidents/{response.get('id')}"
        }

    async def log_event(
        self,
        event_type: str,
        severity: str,
        details: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Log security event to XDR

        API: POST /iroh/iroh-enrich/observe/observables

        Used for non-incident security events that need tracking
        """
        # Demo mode: return simulated response if no credentials
        if not self.client_id or not self.client_secret:
            return {
                "event_id": f"EVT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                "status": "logged",
                "event_type": event_type,
                "demo_mode": True
            }

        endpoint = "/iroh/iroh-enrich/observe/observables"

        event_data = {
            "type": "sighting",
            "observables": [
                {
                    "type": "custom",
                    "value": event_type
                }
            ],
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "source": "Spatial_AI_Agent",
            "details": details
        }

        response = await self._request("POST", endpoint, json=event_data)

        return {
            "event_id": response.get("id"),
            "status": "logged",
            "event_type": event_type
        }

    # Audit Logging APIs

    async def log_audit_event(self, audit_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Log audit event for compliance tracking

        Stores in XDR for long-term retention and analysis
        """
        # Demo mode: return simulated response if no credentials
        if not self.client_id or not self.client_secret:
            return {
                "audit_id": f"AUD-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                "status": "logged",
                "retention_period": "7 years",
                "demo_mode": True
            }

        endpoint = "/iroh/iroh-enrich/observe/observables"

        # Transform audit entry to XDR format
        observable_data = {
            "type": "sighting",
            "observables": [
                {
                    "type": "custom",
                    "value": f"audit_{audit_entry['action']}"
                }
            ],
            "severity": self._map_audit_severity(audit_entry),
            "timestamp": audit_entry.get("timestamp", datetime.utcnow().isoformat()),
            "source": "MCP_Compliance_Audit",
            "description": f"Audit: {audit_entry['action']} by {audit_entry.get('user_role')}",
            "details": {
                "action": audit_entry.get("action"),
                "user_role": audit_entry.get("user_role"),
                "resource": audit_entry.get("resource"),
                "status": audit_entry.get("status"),
                "compliance_event": True
            }
        }

        response = await self._request("POST", endpoint, json=observable_data)

        return {
            "audit_id": response.get("id"),
            "status": "logged",
            "retention_period": "7 years"  # Compliance requirement
        }

    def _map_audit_severity(self, audit_entry: Dict) -> str:
        """Map audit status to severity level"""

        status = audit_entry.get("status", "")

        if "DENIED_SECURITY_ALERT" in status:
            return "high"
        elif "DENIED" in status:
            return "medium"
        elif audit_entry.get("severity") == "HIGH":
            return "medium"
        else:
            return "info"

    # Threat Detection and Anomaly Detection

    async def detect_anomalies(
        self,
        audit_log: List[Dict],
        baseline_days: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Detect anomalies in access patterns using XDR analytics

        In production, this uses XDR's ML-based threat detection
        """

        # Analyze patterns
        anomalies = []

        # Pattern 1: Unusual access times
        time_anomalies = self._detect_time_anomalies(audit_log)
        anomalies.extend(time_anomalies)

        # Pattern 2: Unusual role behavior
        role_anomalies = self._detect_role_anomalies(audit_log)
        anomalies.extend(role_anomalies)

        # Pattern 3: Excessive denied requests
        denial_anomalies = self._detect_denial_spikes(audit_log)
        anomalies.extend(denial_anomalies)

        # Log anomalies to XDR
        for anomaly in anomalies:
            if anomaly["severity"] in ["high", "critical"]:
                await self.create_incident(
                    severity=anomaly["severity"],
                    title=f"Anomaly Detected: {anomaly['type']}",
                    description=anomaly["description"],
                    context=anomaly
                )

        return anomalies

    def _detect_time_anomalies(self, audit_log: List[Dict]) -> List[Dict]:
        """Detect access at unusual times"""

        anomalies = []

        # Count access by hour
        hour_counts = {}
        for entry in audit_log:
            timestamp = entry.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                hour = dt.hour

                # Flag access outside business hours (9am-6pm)
                if hour < 9 or hour > 18:
                    anomalies.append({
                        "type": "unusual_time_access",
                        "severity": "medium",
                        "timestamp": timestamp,
                        "user_role": entry.get("user_role"),
                        "action": entry.get("action"),
                        "description": f"Access at unusual time: {hour}:00"
                    })
            except:
                pass

        return anomalies

    def _detect_role_anomalies(self, audit_log: List[Dict]) -> List[Dict]:
        """Detect unusual behavior for a role"""

        anomalies = []

        # Track actions by role
        role_actions = {}
        for entry in audit_log:
            role = entry.get("user_role")
            action = entry.get("action")

            if role not in role_actions:
                role_actions[role] = {}

            role_actions[role][action] = role_actions[role].get(action, 0) + 1

        # Detect unusual patterns (simplified)
        for role, actions in role_actions.items():
            total = sum(actions.values())

            # Flag if any single action is > 80% of total (potential automation/attack)
            for action, count in actions.items():
                if count / total > 0.8 and total > 10:
                    anomalies.append({
                        "type": "repetitive_behavior",
                        "severity": "medium",
                        "user_role": role,
                        "action": action,
                        "count": count,
                        "percentage": count / total * 100,
                        "description": f"Unusual repetition: {role} performed {action} {count} times ({count/total*100:.1f}%)"
                    })

        return anomalies

    def _detect_denial_spikes(self, audit_log: List[Dict]) -> List[Dict]:
        """Detect spikes in denied requests (potential attack)"""

        anomalies = []

        # Count denials
        denials = [e for e in audit_log if "DENIED" in e.get("status", "")]

        if len(denials) > 5:  # Threshold for investigation
            # Group by role
            denial_by_role = {}
            for denial in denials:
                role = denial.get("user_role")
                denial_by_role[role] = denial_by_role.get(role, 0) + 1

            for role, count in denial_by_role.items():
                if count >= 3:  # Multiple denials for same role
                    anomalies.append({
                        "type": "excessive_denials",
                        "severity": "high",
                        "user_role": role,
                        "denial_count": count,
                        "description": f"Multiple access denials for {role}: {count} attempts",
                        "recommendation": "Review role permissions or investigate potential unauthorized access attempt"
                    })

        return anomalies

    # Compliance Reporting

    async def get_compliance_metrics(
        self,
        start_date: str,
        end_date: str
    ) -> Dict[str, Any]:
        """
        Get compliance metrics from XDR

        API: GET /iroh/iroh-response/respond/observables
        """

        endpoint = "/iroh/iroh-response/respond/observables"

        params = {
            "start_time": start_date,
            "end_time": end_date,
            "source": "MCP_Compliance_Audit"
        }

        response = await self._request("GET", endpoint, params=params)

        # Process and aggregate metrics
        metrics = {
            "total_events": response.get("count", 0),
            "by_severity": self._aggregate_by_severity(response.get("data", [])),
            "by_type": self._aggregate_by_type(response.get("data", [])),
            "compliance_score": self._calculate_compliance_score(response.get("data", []))
        }

        return metrics

    # Workflow Automation

    async def create_response_workflow(
        self,
        trigger: str,
        actions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Create automated response workflow in XDR

        API: POST /iroh/iroh-response/respond/workflows

        Example: Automatically lock down zone when anomaly detected
        """

        endpoint = "/iroh/iroh-response/respond/workflows"

        workflow = {
            "name": f"MCP_Auto_Response_{trigger}",
            "trigger": {
                "type": "observable",
                "value": trigger
            },
            "actions": actions,
            "enabled": True,
            "source": "MCP_AI_Agent"
        }

        response = await self._request("POST", endpoint, json=workflow)

        return {
            "workflow_id": response.get("id"),
            "status": "created",
            "trigger": trigger
        }

    # Helper methods

    def _extract_observables(self, context: Dict) -> List[Dict]:
        """Extract observable indicators from context"""

        observables = []

        if "zone_id" in context:
            observables.append({
                "type": "custom",
                "value": context["zone_id"]
            })

        if "user_role" in context:
            observables.append({
                "type": "user",
                "value": context["user_role"]
            })

        return observables

    def _aggregate_by_severity(self, events: List[Dict]) -> Dict[str, int]:
        """Aggregate events by severity"""

        by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for event in events:
            severity = event.get("severity", "info")
            by_severity[severity] = by_severity.get(severity, 0) + 1

        return by_severity

    def _aggregate_by_type(self, events: List[Dict]) -> Dict[str, int]:
        """Aggregate events by type"""

        by_type = {}

        for event in events:
            event_type = event.get("type", "unknown")
            by_type[event_type] = by_type.get(event_type, 0) + 1

        return by_type

    def _calculate_compliance_score(self, events: List[Dict]) -> float:
        """Calculate compliance score based on events"""

        if not events:
            return 100.0

        # Count violations
        violations = sum(
            1 for e in events
            if e.get("severity") in ["high", "critical"]
        )

        # Score decreases with violations
        score = max(0, 100 - (violations * 2))

        return round(score, 2)


# Example usage
async def example_usage():
    """Demonstrate XDR integration"""

    # Initialize with environment variables
    xdr = CiscoXDRAPI()

    # Check if credentials are configured
    if not xdr.client_id or not xdr.client_secret:
        print("Note: CISCO_SECUREX_CLIENT_ID/SECRET not set.")
        print("Some examples will simulate responses.\n")
        print("To connect to real XDR, set environment variables:")
        print("  export CISCO_SECUREX_CLIENT_ID='your-client-id'")
        print("  export CISCO_SECUREX_CLIENT_SECRET='your-client-secret'")
        print("  export CISCO_SECUREX_URL='https://visibility.amp.cisco.com'  # optional\n")

    print("=" * 60)
    print("EXAMPLE 1: Create Security Incident")
    print("=" * 60)

    incident = await xdr.create_incident(
        severity="medium",
        title="Unauthorized Environmental Control Attempt",
        description="Analyst role attempted to adjust HVAC settings without authorization",
        context={
            "zone_id": "zone-conference-wing",
            "user_role": "analyst",
            "attempted_action": "temperature_adjustment",
            "policy_violated": "environmental_control_write"
        }
    )

    print(json.dumps(incident, indent=2))

    print("\n" + "=" * 60)
    print("EXAMPLE 2: Log Audit Event")
    print("=" * 60)

    audit_log = await xdr.log_audit_event({
        "timestamp": datetime.utcnow().isoformat(),
        "action": "get_building_occupancy",
        "user_role": "facility_manager",
        "resource": "building-hq-01",
        "status": "SUCCESS"
    })

    print(json.dumps(audit_log, indent=2))

    print("\n" + "=" * 60)
    print("EXAMPLE 3: Detect Anomalies")
    print("=" * 60)

    sample_audit_log = [
        {
            "timestamp": "2024-11-15T02:30:00Z",  # Unusual time
            "action": "get_building_occupancy",
            "user_role": "analyst",
            "status": "SUCCESS"
        },
        {
            "timestamp": "2024-11-15T14:00:00Z",
            "action": "trigger_environmental_adjustment",
            "user_role": "analyst",
            "status": "DENIED"
        },
        {
            "timestamp": "2024-11-15T14:05:00Z",
            "action": "trigger_environmental_adjustment",
            "user_role": "analyst",
            "status": "DENIED"
        },
        {
            "timestamp": "2024-11-15T14:10:00Z",
            "action": "trigger_environmental_adjustment",
            "user_role": "analyst",
            "status": "DENIED"
        }
    ]

    anomalies = await xdr.detect_anomalies(sample_audit_log)

    print(f"Found {len(anomalies)} anomalies:")
    for anomaly in anomalies:
        print(f"\n  - {anomaly['type']}: {anomaly['description']}")
        print(f"    Severity: {anomaly['severity']}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(example_usage())
