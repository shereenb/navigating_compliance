"""
Cisco Identity Services Engine (ISE) API Client
Demonstrates policy enforcement and authorization for spatial AI agents

API Documentation: https://developer.cisco.com/docs/identity-services-engine/
Authentication: Basic auth with ERS admin credentials

Credentials should be provided via environment variables:
- CISCO_ISE_USERNAME: ERS admin username
- CISCO_ISE_PASSWORD: ERS admin password
- CISCO_ISE_URL: ISE server URL (e.g., https://ise.example.com:9060)

Note: This client demonstrates the authorization patterns used with ISE.
The policy matrix is defined locally for illustration. In production,
policies would be configured in ISE Policy Sets and evaluated via
pxGrid or RADIUS/TACACS+.
"""

import os
import aiohttp
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
import base64


class CiscoISEAPI:
    """
    Client for Cisco ISE External RESTful Services (ERS) API
    https://developer.cisco.com/docs/identity-services-engine/

    Provides:
    - Policy-based authorization
    - Role-based access control
    - Dynamic authorization decisions
    - Policy violation tracking
    """

    def __init__(
        self,
        username: str = None,
        password: str = None,
        base_url: str = None
    ):
        """
        Initialize Cisco ISE API client.

        Args:
            username: ERS admin username. If not provided,
                     reads from CISCO_ISE_USERNAME environment variable.
            password: ERS admin password. If not provided,
                     reads from CISCO_ISE_PASSWORD environment variable.
            base_url: ISE server URL. Defaults to CISCO_ISE_URL env var.
        """
        self.username = username or os.environ.get("CISCO_ISE_USERNAME", "")
        self.password = password or os.environ.get("CISCO_ISE_PASSWORD", "")
        self.base_url = base_url or os.environ.get(
            "CISCO_ISE_URL",
            "https://ise.example.com:9060"
        )

        # Create basic auth header
        credentials = f"{self.username}:{self.password}"
        encoded = base64.b64encode(credentials.encode()).decode()

        self.headers = {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """Make authenticated API request to ISE"""
        async with aiohttp.ClientSession() as session:
            url = f"{self.base_url}{endpoint}"
            async with session.request(
                method, url, headers=self.headers, ssl=False, **kwargs
            ) as response:
                if response.status == 204:  # No content
                    return {"status": "success"}
                response.raise_for_status()
                return await response.json()

    # Authorization APIs

    async def check_authorization(
        self,
        user_role: str,
        resource_type: str,
        action: str,
        context: Optional[Dict[str, Any]] = None
    ) -> 'AuthorizationResult':
        """
        Check if a role is authorized to perform an action

        Uses ISE Policy Sets to make dynamic authorization decisions

        API: POST /ers/config/profilerprofile (for policy evaluation)
        Real implementation would use RADIUS or TACACS+ for runtime decisions
        """

        # In production, this would integrate with ISE pxGrid or RADIUS
        # For demo purposes, showing the policy structure

        endpoint = "/api/v1/policy/authorization"

        # Build authorization request
        auth_request = {
            "subject": {
                "role": user_role,
                "attributes": self._get_role_attributes(user_role)
            },
            "resource": {
                "type": resource_type,
                "action": action
            },
            "environment": {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "MCP_AI_Agent"
            }
        }

        if context:
            auth_request["context"] = context

        # Evaluate against ISE policies
        decision = await self._evaluate_policy(auth_request)

        return AuthorizationResult(
            authorized=decision["authorized"],
            reason=decision.get("reason", ""),
            policy_matched=decision.get("policy_name"),
            context_approved=decision.get("context_approved", False),
            constraints=decision.get("constraints", {})
        )

    async def _evaluate_policy(self, auth_request: Dict) -> Dict:
        """
        Evaluate authorization request against ISE policy sets

        In production, this uses ISE's Policy Decision Point (PDP)
        """

        role = auth_request["subject"]["role"]
        resource_type = auth_request["resource"]["type"]
        action = auth_request["resource"]["action"]
        context = auth_request.get("context", {})

        # Define policy matrix (in production, this comes from ISE)
        policies = self._get_policy_matrix()

        # Find matching policy
        for policy in policies:
            if self._policy_matches(policy, role, resource_type, action):
                # Check additional context constraints
                if policy.get("requires_context"):
                    if not self._validate_context(policy, context):
                        return {
                            "authorized": False,
                            "reason": "Context requirements not met",
                            "policy_name": policy["name"]
                        }

                return {
                    "authorized": True,
                    "policy_name": policy["name"],
                    "context_approved": True,
                    "constraints": policy.get("constraints", {})
                }

        # No matching policy - deny by default
        return {
            "authorized": False,
            "reason": f"No policy allows {role} to {action} {resource_type}",
            "policy_name": "default_deny"
        }

    def _get_policy_matrix(self) -> List[Dict]:
        """
        Define authorization policies

        In production, these are configured in ISE Policy Sets
        """

        return [
            # Executive access
            {
                "name": "executive_read_aggregates",
                "role": "executive",
                "resource_type": "building_occupancy",
                "action": "read",
                "requires_context": False
            },
            {
                "name": "executive_read_utilization",
                "role": "executive",
                "resource_type": "space_utilization",
                "action": "read",
                "requires_context": False
            },

            # Facility Manager access
            {
                "name": "facility_manager_full_read",
                "role": "facility_manager",
                "resource_type": "*",
                "action": "read",
                "requires_context": False
            },
            {
                "name": "facility_manager_environmental_control",
                "role": "facility_manager",
                "resource_type": "environmental_control",
                "action": "write",
                "requires_context": True,
                "context_requirements": {
                    "parameters.value": {"type": "number", "required": True}
                },
                "constraints": {
                    "time_restrictions": "business_hours",
                    "approval_required": False
                }
            },

            # Department Lead access
            {
                "name": "dept_lead_occupancy_read",
                "role": "department_lead",
                "resource_type": "building_occupancy",
                "action": "read",
                "requires_context": False
            },
            {
                "name": "dept_lead_utilization_read",
                "role": "department_lead",
                "resource_type": "space_utilization",
                "action": "read",
                "requires_context": False
            },

            # Analyst access
            {
                "name": "analyst_historical_read",
                "role": "analyst",
                "resource_type": "building_occupancy",
                "action": "read",
                "requires_context": False
            },
            {
                "name": "analyst_trends_read",
                "role": "analyst",
                "resource_type": "space_utilization",
                "action": "read",
                "requires_context": True,
                "context_requirements": {
                    "include_trends": True
                }
            },

            # Compliance Officer access
            {
                "name": "compliance_officer_report_access",
                "role": "compliance_officer",
                "resource_type": "compliance_report",
                "action": "read",
                "requires_context": False
            },
            {
                "name": "compliance_officer_audit_access",
                "role": "compliance_officer",
                "resource_type": "audit_log",
                "action": "read",
                "requires_context": False
            }
        ]

    def _policy_matches(
        self,
        policy: Dict,
        role: str,
        resource_type: str,
        action: str
    ) -> bool:
        """Check if policy matches the request"""

        if policy["role"] != role:
            return False

        if policy["resource_type"] != "*" and policy["resource_type"] != resource_type:
            return False

        if policy["action"] != "*" and policy["action"] != action:
            return False

        return True

    def _validate_context(self, policy: Dict, context: Dict) -> bool:
        """Validate context against policy requirements"""

        requirements = policy.get("context_requirements", {})

        for key, requirement in requirements.items():
            # Navigate nested keys (e.g., "parameters.value")
            value = context
            for part in key.split("."):
                value = value.get(part)
                if value is None and requirement.get("required"):
                    return False

            # Type checking
            if "type" in requirement and value is not None:
                expected_type = requirement["type"]
                if expected_type == "number" and not isinstance(value, (int, float)):
                    return False
                elif expected_type == "string" and not isinstance(value, str):
                    return False
                elif expected_type == "boolean" and not isinstance(value, bool):
                    return False

        return True

    def _get_role_attributes(self, role: str) -> Dict[str, Any]:
        """Get attributes associated with a role"""

        role_attributes = {
            "executive": {
                "clearance_level": "high",
                "data_access_scope": "aggregate_only",
                "department": "leadership"
            },
            "facility_manager": {
                "clearance_level": "high",
                "data_access_scope": "detailed",
                "department": "facilities",
                "control_permissions": ["environmental", "access"]
            },
            "department_lead": {
                "clearance_level": "medium",
                "data_access_scope": "departmental",
                "department": "varies"
            },
            "analyst": {
                "clearance_level": "medium",
                "data_access_scope": "historical",
                "department": "analytics"
            },
            "compliance_officer": {
                "clearance_level": "high",
                "data_access_scope": "audit",
                "department": "compliance"
            }
        }

        return role_attributes.get(role, {})

    # Policy Management APIs

    async def get_role_permissions(self, role: str) -> 'RolePermissions':
        """
        Get all permissions for a role

        API: GET /ers/config/authorizationprofile
        """

        # Get all policies for this role
        policies = [p for p in self._get_policy_matrix() if p["role"] == role]

        allowed_data_types = set()
        restricted_data_types = set()
        actions = set()

        for policy in policies:
            if policy["action"] == "read":
                allowed_data_types.add(policy["resource_type"])
            actions.add(f"{policy['action']}:{policy['resource_type']}")

        # Define restricted types
        all_types = {
            "building_occupancy", "space_utilization",
            "environmental_control", "compliance_report",
            "audit_log", "individual_tracking", "device_data"
        }

        restricted_data_types = all_types - allowed_data_types

        return RolePermissions(
            role=role,
            allowed_data_types=list(allowed_data_types),
            restricted_data_types=list(restricted_data_types),
            allowed_actions=list(actions),
            attributes=self._get_role_attributes(role)
        )

    async def get_resource_policies(self, resource_id: str) -> List[Dict]:
        """
        Get all policies that apply to a resource

        API: GET /ers/config/authorizationprofile/name/{name}
        """

        # Parse resource ID (format: "type:id")
        if ":" in resource_id:
            resource_type, _ = resource_id.split(":", 1)
        else:
            resource_type = resource_id

        policies = [
            p for p in self._get_policy_matrix()
            if p["resource_type"] == resource_type or p["resource_type"] == "*"
        ]

        return policies

    async def list_active_policies(self) -> List[Dict]:
        """
        List all active authorization policies

        API: GET /ers/config/authorizationprofile
        """

        policies = self._get_policy_matrix()

        # Enrich with metadata
        for policy in policies:
            policy["status"] = "active"
            policy["created_at"] = "2024-01-01T00:00:00Z"
            policy["last_modified"] = datetime.utcnow().isoformat()

        return policies

    # Compliance and Auditing APIs

    async def get_policy_violations(
        self,
        start_date: str,
        end_date: str
    ) -> List[Dict]:
        """
        Get policy violations within date range

        In production, this queries ISE's RADIUS authentication logs
        and Live Log for denied access attempts
        """

        # Simulate violation data
        violations = [
            {
                "timestamp": "2024-11-15T14:23:45Z",
                "user_role": "analyst",
                "resource": "environmental_control",
                "action": "write",
                "policy_matched": "default_deny",
                "severity": "medium",
                "status": "blocked"
            },
            {
                "timestamp": "2024-11-16T09:15:22Z",
                "user_role": "department_lead",
                "resource": "compliance_report",
                "action": "read",
                "policy_matched": "default_deny",
                "severity": "low",
                "status": "blocked"
            }
        ]

        return violations

    async def create_policy(
        self,
        name: str,
        role: str,
        resource_type: str,
        action: str,
        constraints: Optional[Dict] = None
    ) -> Dict:
        """
        Create a new authorization policy

        API: POST /ers/config/authorizationprofile
        """

        endpoint = "/ers/config/authorizationprofile"

        policy = {
            "AuthorizationProfile": {
                "name": name,
                "accessType": "ACCESS_ACCEPT",
                "authzProfileType": "SWITCH",
                "vlan": {
                    "nameID": resource_type,
                    "tagID": 0
                },
                "advancedAttributes": [
                    {
                        "leftHandSideDictionaryAttribue": {
                            "dictionaryName": "Network Access",
                            "attributeName": "UserRole"
                        },
                        "rightHandSideAttribueValue": {
                            "value": role
                        }
                    }
                ]
            }
        }

        try:
            response = await self._request("POST", endpoint, json=policy)
            return {
                "status": "created",
                "policy_name": name,
                "policy_id": response.get("id")
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


# Helper Classes

class AuthorizationResult:
    """Result of an authorization check"""

    def __init__(
        self,
        authorized: bool,
        reason: str = "",
        policy_matched: str = "",
        context_approved: bool = False,
        constraints: Dict = None
    ):
        self.authorized = authorized
        self.reason = reason
        self.policy_matched = policy_matched
        self.context_approved = context_approved
        self.constraints = constraints or {}


class RolePermissions:
    """Permissions associated with a role"""

    def __init__(
        self,
        role: str,
        allowed_data_types: List[str],
        restricted_data_types: List[str],
        allowed_actions: List[str],
        attributes: Dict[str, Any]
    ):
        self.role = role
        self.allowed_data_types = allowed_data_types
        self.restricted_data_types = restricted_data_types
        self.allowed_actions = allowed_actions
        self.attributes = attributes


# Example usage
async def example_usage():
    """Demonstrate ISE authorization flows"""

    # Initialize with environment variables
    ise = CiscoISEAPI()

    # Check if credentials are configured
    if not ise.username or not ise.password:
        print("Note: CISCO_ISE_USERNAME/PASSWORD not set.")
        print("Using local policy matrix for demonstration.\n")
        print("To connect to real ISE, set environment variables:")
        print("  export CISCO_ISE_USERNAME='admin'")
        print("  export CISCO_ISE_PASSWORD='your-password'")
        print("  export CISCO_ISE_URL='https://ise.example.com:9060'\n")

    print("=" * 60)
    print("EXAMPLE 1: Check Facility Manager Authorization")
    print("=" * 60)

    auth = await ise.check_authorization(
        user_role="facility_manager",
        resource_type="environmental_control",
        action="write",
        context={"parameters": {"value": 22}}
    )

    print(f"Authorized: {auth.authorized}")
    print(f"Policy: {auth.policy_matched}")
    print(f"Reason: {auth.reason}\n")

    print("=" * 60)
    print("EXAMPLE 2: Check Analyst Authorization (Should Deny)")
    print("=" * 60)

    auth = await ise.check_authorization(
        user_role="analyst",
        resource_type="environmental_control",
        action="write",
        context={"parameters": {"value": 22}}
    )

    print(f"Authorized: {auth.authorized}")
    print(f"Reason: {auth.reason}\n")

    print("=" * 60)
    print("EXAMPLE 3: Get Role Permissions")
    print("=" * 60)

    permissions = await ise.get_role_permissions("facility_manager")

    print(f"Role: {permissions.role}")
    print(f"Allowed: {', '.join(permissions.allowed_data_types)}")
    print(f"Restricted: {', '.join(permissions.restricted_data_types)}\n")


if __name__ == "__main__":
    import asyncio
    asyncio.run(example_usage())
