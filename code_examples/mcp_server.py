"""
MCP Server for Cisco Spatial AI Integration
Demonstrates compliance-first approach to spatial AI agent deployment

Uses the current MCP Python SDK (FastMCP) syntax.
Credentials are loaded from environment variables.
"""

import os
import logging
from typing import Any, Dict, Optional
from datetime import datetime

# MCP SDK imports - current FastMCP syntax
from mcp.server.fastmcp import FastMCP

# Cisco API clients
from cisco_spaces_client import CiscoSpacesAPI
from cisco_ise_client import CiscoISEAPI
from cisco_xdr_client import CiscoXDRAPI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("cisco-spatial-compliance")

# Initialize Cisco API clients from environment variables
spaces = CiscoSpacesAPI(
    bearer_token=os.environ.get("CISCO_SPACES_TOKEN", ""),
    base_url=os.environ.get("CISCO_SPACES_URL", "https://dnaspaces.io/api/location/v1")
)

ise = CiscoISEAPI(
    username=os.environ.get("CISCO_ISE_USERNAME", ""),
    password=os.environ.get("CISCO_ISE_PASSWORD", ""),
    base_url=os.environ.get("CISCO_ISE_URL", "https://ise.example.com:9060")
)

xdr = CiscoXDRAPI(
    client_id=os.environ.get("CISCO_XDR_CLIENT_ID", ""),
    client_secret=os.environ.get("CISCO_XDR_CLIENT_SECRET", ""),
    base_url=os.environ.get("CISCO_XDR_URL", "https://visibility.amp.cisco.com")
)

# Audit log (in production, use persistent storage)
audit_log = []


def audit_action(
    action: str,
    user_role: str,
    resource: str,
    status: str = "INITIATED",
    **kwargs
):
    """Comprehensive audit logging - Surface 7: Reasoning Traces"""
    audit_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "user_role": user_role,
        "resource": resource,
        "status": status,
        **kwargs
    }

    audit_log.append(audit_entry)
    logger.info(f"AUDIT: {audit_entry}")

    # Real-time audit logging to XDR
    if status in ["DENIED", "DENIED_SECURITY_ALERT", "SUCCESS"]:
        # Fire and forget - don't await in sync context
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(xdr.log_audit_event(audit_entry))
        except RuntimeError:
            pass  # No event loop running


def filter_by_role(data: Dict, user_role: str) -> Dict:
    """Surface 1: Tool Boundaries - Role-based data filtering"""
    role_filters = {
        "executive": ["summary", "trends", "aggregates"],
        "facility_manager": ["summary", "trends", "aggregates", "details"],
        "department_lead": ["summary", "aggregates"],
        "analyst": ["summary", "trends", "aggregates", "historical"]
    }

    allowed_fields = role_filters.get(user_role, ["summary"])

    filtered = {}
    for field in allowed_fields:
        if field in data:
            filtered[field] = data[field]

    return filtered


class ValidationResult:
    """Result of parameter validation"""
    def __init__(self, valid: bool, reason: str = None, allowed_range: Dict = None):
        self.valid = valid
        self.reason = reason
        self.allowed_range = allowed_range


def validate_adjustment_parameters(
    adjustment_type: str,
    parameters: Dict[str, Any]
) -> ValidationResult:
    """Surface 3: Non-Deterministic Output - Deterministic safety bounds"""
    safety_bounds = {
        "temperature": {"min": 18, "max": 26, "unit": "celsius"},
        "lighting": {"min": 200, "max": 750, "unit": "lux"},
        "ventilation": {"min": 15, "max": 100, "unit": "percent"}
    }

    if adjustment_type not in safety_bounds:
        return ValidationResult(
            False,
            f"Unknown adjustment type: {adjustment_type}"
        )

    bounds = safety_bounds[adjustment_type]
    value = parameters.get("value")

    if value is None:
        return ValidationResult(False, "Missing 'value' parameter")

    if value < bounds["min"] or value > bounds["max"]:
        return ValidationResult(
            False,
            f"Value {value} outside safe range",
            allowed_range=bounds
        )

    return ValidationResult(True)


# MCP Tools - using current FastMCP decorator syntax

@mcp.tool()
async def get_building_occupancy(
    building_id: str,
    user_role: str,
    time_range: str = "current"
) -> dict:
    """
    Get aggregate occupancy data for a building (anonymized).

    Implements compliance surfaces:
    - Surface 1: Tool Boundaries - Only returns aggregated data, no individual tracking
    - Surface 2: Context Window - Scoped to building level, not specific locations

    Args:
        building_id: Cisco Spaces building identifier
        user_role: Role of the requesting user (executive, facility_manager, etc.)
        time_range: Time range for data - "current", "1h", "24h", "7d"
    """
    # Log the request
    audit_action(
        action="get_building_occupancy",
        user_role=user_role,
        resource=building_id,
        parameters={"time_range": time_range}
    )

    # Surface 1: Check authorization via Cisco ISE
    auth_result = await ise.check_authorization(
        user_role=user_role,
        resource_type="building_occupancy",
        action="read"
    )

    if not auth_result.authorized:
        audit_action(
            action="get_building_occupancy",
            user_role=user_role,
            resource=building_id,
            status="DENIED",
            reason=auth_result.reason
        )
        return {
            "error": "Unauthorized",
            "reason": auth_result.reason,
            "compliance_status": "Policy Violation Prevented"
        }

    # Get anonymized, aggregated data from Cisco Spaces
    occupancy_data = await spaces.get_building_occupancy(
        building_id=building_id,
        time_range=time_range,
        anonymized=True,
        aggregation_level="floor"
    )

    # Data filtering based on role
    filtered_data = filter_by_role(occupancy_data, user_role)

    # Log successful access
    audit_action(
        action="get_building_occupancy",
        user_role=user_role,
        resource=building_id,
        status="SUCCESS",
        data_fields=list(filtered_data.keys())
    )

    return filtered_data


@mcp.tool()
async def get_space_utilization(
    floor_id: str,
    user_role: str,
    include_trends: bool = False
) -> dict:
    """
    Get utilization metrics for meeting rooms and workspaces.

    Args:
        floor_id: Cisco Spaces floor identifier
        user_role: Role of the requesting user
        include_trends: Whether to include 30-day trend data
    """
    audit_action(
        action="get_space_utilization",
        user_role=user_role,
        resource=floor_id,
        parameters={"include_trends": include_trends}
    )

    # Authorization check
    auth_result = await ise.check_authorization(
        user_role=user_role,
        resource_type="space_utilization",
        action="read",
        context={"include_trends": include_trends}
    )

    if not auth_result.authorized:
        return {"error": "Unauthorized", "reason": auth_result.reason}

    # Get utilization data
    utilization = await spaces.get_floor_utilization(
        floor_id=floor_id,
        privacy_mode="high",
        metrics=["occupancy_rate", "duration", "peak_times"]
    )

    # Role-based filtering
    if user_role == "facility_manager":
        if include_trends and auth_result.context_approved:
            utilization["trends"] = await spaces.get_utilization_trends(
                floor_id=floor_id,
                days=30
            )
    elif user_role == "department_lead":
        utilization.pop("historical_data", None)

    audit_action(
        action="get_space_utilization",
        user_role=user_role,
        resource=floor_id,
        status="SUCCESS"
    )

    return utilization


@mcp.tool()
async def trigger_environmental_adjustment(
    zone_id: str,
    user_role: str,
    adjustment_type: str,
    value: float
) -> dict:
    """
    Adjust HVAC/lighting based on occupancy. Requires elevated privileges.

    Implements compliance surfaces:
    - Surface 1: Tool Boundaries - Only facility_manager can write
    - Surface 3: Non-Deterministic Output - Hard safety bounds enforced

    Args:
        zone_id: Cisco Spaces zone identifier
        user_role: Role of the requesting user (must be facility_manager)
        adjustment_type: Type of adjustment - "temperature", "lighting", "ventilation"
        value: Target value (must be within safety bounds)
    """
    parameters = {"value": value}

    audit_action(
        action="trigger_environmental_adjustment",
        user_role=user_role,
        resource=zone_id,
        parameters={
            "adjustment_type": adjustment_type,
            "value": value
        },
        severity="HIGH"
    )

    # Enhanced authorization for control actions
    auth_result = await ise.check_authorization(
        user_role=user_role,
        resource_type="environmental_control",
        action="write",
        context={
            "zone_id": zone_id,
            "adjustment_type": adjustment_type,
            "parameters": parameters
        }
    )

    if not auth_result.authorized:
        # Alert on unauthorized control attempts
        await xdr.create_incident(
            severity="medium",
            title="Unauthorized environmental control attempt",
            description=f"User with role {user_role} attempted unauthorized adjustment",
            context={"zone_id": zone_id, "adjustment_type": adjustment_type}
        )

        audit_action(
            action="trigger_environmental_adjustment",
            user_role=user_role,
            resource=zone_id,
            status="DENIED_SECURITY_ALERT",
            reason=auth_result.reason
        )

        return {"error": "Unauthorized", "incident_created": True}

    # Surface 3: Validate parameters against safety bounds
    validation = validate_adjustment_parameters(adjustment_type, parameters)

    if not validation.valid:
        return {
            "error": "Invalid parameters",
            "reason": validation.reason,
            "allowed_range": validation.allowed_range
        }

    # Execute adjustment via Cisco Spaces
    result = await spaces.adjust_environment(
        zone_id=zone_id,
        adjustment_type=adjustment_type,
        parameters=parameters,
        initiated_by=user_role,
        audit_trail=True
    )

    # Log to XDR for security monitoring
    await xdr.log_event(
        event_type="environmental_adjustment",
        severity="low",
        details={
            "zone_id": zone_id,
            "adjustment_type": adjustment_type,
            "user_role": user_role,
            "result": result
        }
    )

    audit_action(
        action="trigger_environmental_adjustment",
        user_role=user_role,
        resource=zone_id,
        status="SUCCESS",
        result=result
    )

    return result


@mcp.tool()
async def get_compliance_report(
    user_role: str,
    report_type: str,
    start_date: str,
    end_date: str
) -> dict:
    """
    Generate compliance report for audit purposes.

    Surface 7: Reasoning Traces - Comprehensive audit trail.

    Args:
        user_role: Role of requesting user (must be compliance_officer)
        report_type: Type of report - "access_summary", "violations", "anomalies"
        start_date: Start date in ISO format (YYYY-MM-DD)
        end_date: End date in ISO format (YYYY-MM-DD)
    """
    # Only compliance officers can generate reports
    auth_result = await ise.check_authorization(
        user_role=user_role,
        resource_type="compliance_report",
        action="read"
    )

    if not auth_result.authorized:
        return {"error": "Unauthorized - Compliance Officer role required"}

    date_range = {"start": start_date, "end": end_date}

    # Generate report from audit logs
    report = {
        "report_type": report_type,
        "date_range": date_range,
        "generated_at": datetime.utcnow().isoformat(),
        "generated_by": user_role,
        "summary": {
            "total_requests": len(audit_log),
            "authorized_requests": len([a for a in audit_log if a.get("status") == "SUCCESS"]),
            "denied_requests": len([a for a in audit_log if "DENIED" in a.get("status", "")]),
            "unique_roles": len(set(a.get("user_role", "") for a in audit_log)),
        },
        "audit_trail": audit_log[-100:],
        "policy_violations": await ise.get_policy_violations(
            start_date=start_date,
            end_date=end_date
        )
    }

    # Log report generation
    audit_action(
        action="get_compliance_report",
        user_role=user_role,
        resource=report_type,
        status="SUCCESS"
    )

    return report


@mcp.tool()
async def list_monitored_buildings() -> list:
    """
    List all buildings monitored by Cisco Spaces with compliance metadata.

    Returns building inventory with data classification and access policies.
    """
    buildings = await spaces.list_buildings()

    # Annotate with compliance metadata
    for building in buildings:
        building["data_classification"] = {
            "occupancy_aggregate": "public",
            "occupancy_realtime": "internal",
            "device_data": "restricted",
            "individual_tracking": "prohibited",
            "environmental_controls": "restricted"
        }

    return buildings


@mcp.tool()
async def detect_access_anomalies(
    baseline_days: int = 30
) -> list:
    """
    Detect anomalies in access patterns using XDR analytics.

    Surface 7: Reasoning Traces - Anomaly detection for security.

    Args:
        baseline_days: Number of days to use as baseline for anomaly detection
    """
    anomalies = await xdr.detect_anomalies(
        audit_log=audit_log,
        baseline_days=baseline_days
    )

    return anomalies


def main():
    """Start the MCP server"""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
