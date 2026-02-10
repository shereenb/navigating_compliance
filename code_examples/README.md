# Case Study Code Examples: Compliance-First Spatial AI

This directory contains working code examples demonstrating the real-world implementation discussed in the presentation **"Navigating Compliance: Deploying Secure Spatial AI Agents with Model Context Protocols"**.

## Overview

These examples show how to build a compliance-first spatial AI system using:
- **Model Context Protocol (MCP)** for standardized agent interactions
- **Cisco DNA Spaces** for spatial intelligence and occupancy data
- **Cisco Identity Services Engine (ISE)** for policy-based authorization
- **Cisco XDR** for security orchestration and audit logging

## Files

### Core Components

1. **`mcp_server.py`** - Main MCP server implementing the three pillars of compliance:
   - Clear Boundaries & Scope Control
   - Policy Enforcement & Authorization
   - Auditable Control & Traceability

2. **`cisco_spaces_client.py`** - Cisco DNA Spaces API client
   - Location analytics and occupancy data (anonymized)
   - Space utilization metrics
   - Environmental controls (HVAC, lighting)
   - Privacy-preserving data aggregation

3. **`cisco_ise_client.py`** - Cisco ISE API client
   - Policy-based authorization
   - Role-based access control (RBAC)
   - Dynamic authorization decisions
   - Policy violation tracking

4. **`cisco_xdr_client.py`** - Cisco XDR API client
   - Security incident management
   - Audit event logging
   - Threat detection and anomaly analysis
   - Security orchestration workflows

### Demonstration

5. **`case_study_demo.py`** - Complete end-to-end demonstration
   - Shows 4 real-world scenarios
   - Demonstrates compliance requirements
   - Shows business value and ROI
   - Includes results and metrics

## Installation

### Prerequisites

```bash
# Python 3.8 or higher
python --version

# Install dependencies
pip install aiohttp mcp-server-sdk
```

### Cisco API Access

You'll need access to:
- **Cisco DNA Spaces**: https://dnaspaces.io (sign up for API access)
- **Cisco ISE**: Your organization's ISE instance
- **Cisco XDR**: https://visibility.amp.cisco.com (formerly Threat Response)

### Configuration

Create a configuration file with your API credentials:

```python
# config.py
CONFIG = {
    # Cisco DNA Spaces
    "spaces_api_key": "your_spaces_api_key",
    "spaces_url": "https://api.dnaspaces.io",

    # Cisco ISE
    "ise_username": "admin",
    "ise_password": "your_ise_password",
    "ise_url": "https://ise.yourdomain.com:9060",

    # Cisco XDR
    "xdr_client_id": "your_client_id",
    "xdr_client_secret": "your_client_secret",
    "xdr_url": "https://visibility.amp.cisco.com"
}
```

## Usage

### Run the Complete Case Study Demo

```bash
python case_study_demo.py
```

This runs through 4 scenarios:
1. **Executive Dashboard** - Read-only aggregated data
2. **Facility Operations** - Environmental control with authorization
3. **Security Incident** - Unauthorized access attempt and response
4. **Compliance Reporting** - Quarterly audit report generation

### Run Individual Components

#### Test Cisco Spaces Integration
```bash
python cisco_spaces_client.py
```

Example output:
```
EXAMPLE 1: Get Building Occupancy (Privacy-Preserving)
{
  "aggregation_level": "floor",
  "privacy_preserved": true,
  "data_classification": "Public - Aggregated Only",
  "summary": {
    "total_count": 247,
    "active_zones": 12,
    "average_occupancy": 68
  }
}
```

#### Test Cisco ISE Authorization
```bash
python cisco_ise_client.py
```

Example output:
```
EXAMPLE 1: Check Facility Manager Authorization
Authorized: True
Policy: facility_manager_environmental_control
Reason:

EXAMPLE 2: Check Analyst Authorization (Should Deny)
Authorized: False
Reason: No policy allows analyst to write environmental_control
```

#### Test Cisco XDR Integration
```bash
python cisco_xdr_client.py
```

Example output:
```
EXAMPLE 1: Create Security Incident
{
  "incident_id": "incident-12345",
  "status": "created",
  "severity": "medium",
  "title": "Unauthorized Environmental Control Attempt",
  "url": "https://visibility.amp.cisco.com/investigate/incidents/incident-12345"
}
```

### Run the MCP Server

```bash
python mcp_server.py
```

The MCP server will start and expose tools that AI agents can use:
- `get_building_occupancy` - Get anonymized occupancy data
- `get_space_utilization` - Get workspace utilization metrics
- `trigger_environmental_adjustment` - Adjust HVAC/lighting (authorized roles only)
- `get_compliance_report` - Generate compliance reports

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AI AGENT (MCP-Based)                     │
│  • Natural language queries                                 │
│  • Compliance-aware prompts                                 │
│  • Policy-constrained actions                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              MODEL CONTEXT PROTOCOL (MCP)                   │
│  ┌──────────────┬──────────────────┬──────────────────┐    │
│  │   TOOLS      │    RESOURCES     │     PROMPTS      │    │
│  │  • Occupancy │  • Buildings     │  • Compliance    │    │
│  │  • Controls  │  • Policies      │    Guides        │    │
│  │  • Reports   │  • Audit Logs    │  • Safety Rules  │    │
│  └──────────────┴──────────────────┴──────────────────┘    │
└─────────────────────────────────────────────────────────────┘
        │                    │                    │
        ▼                    ▼                    ▼
┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ CISCO SPACES │  │   CISCO ISE      │  │ CISCO SECUREX    │
│              │  │                  │  │                  │
│ • Location   │  │ • Authorization  │  │ • Incident Mgmt  │
│   Analytics  │  │ • Policy Engine  │  │ • Audit Logs     │
│ • Occupancy  │  │ • RBAC          │  │ • Threat Detect  │
│ • IoT        │  │ • Context-Aware  │  │ • Orchestration  │
│   Control    │  │   Access         │  │ • Analytics      │
└──────────────┘  └──────────────────┘  └──────────────────┘
```

## Key Concepts Demonstrated

### 1. Privacy by Design

All spatial data is **aggregated and anonymized** by default:

```python
occupancy_data = await spaces.get_building_occupancy(
    building_id="building-hq-01",
    anonymized=True,           # No individual tracking
    aggregation_level="floor"  # Building/floor level only
)
```

**Result**: GDPR Article 9 compliance - no sensitive personal data (location) is tracked.

### 2. Policy-Based Authorization

Every action requires authorization through Cisco ISE:

```python
auth_result = await ise.check_authorization(
    user_role="facility_manager",
    resource_type="environmental_control",
    action="write",
    context={"parameters": {"value": 22}}
)

if not auth_result.authorized:
    return {"error": "Unauthorized"}
```

**Result**: Zero-trust architecture - no action without explicit policy approval.

### 3. Complete Audit Trail

All actions logged to Cisco XDR for compliance:

```python
await xdr.log_audit_event({
    "timestamp": datetime.utcnow().isoformat(),
    "action": "get_building_occupancy",
    "user_role": "executive",
    "resource": "building-hq-01",
    "status": "SUCCESS"
})
```

**Result**: MiFID II, SOC 2, ISO 27001 compliance with complete traceability.

### 4. Real-Time Threat Detection

Security incidents detected and responded to immediately:

```python
if not authorized:
    await xdr.create_incident(
        severity="medium",
        title="Unauthorized Control Attempt",
        description=f"User {role} attempted unauthorized action",
        context={"action": action, "resource": resource}
    )
```

**Result**: < 1 second incident response time.

## Role-Based Access Control

The system implements granular RBAC:

| Role | Building Occupancy | Space Utilization | Environmental Control | Compliance Reports |
|------|-------------------|-------------------|----------------------|-------------------|
| **Executive** | ✓ Aggregated | ✓ Aggregated | ✗ | ✗ |
| **Facility Manager** | ✓ Detailed | ✓ Detailed | ✓ | ✗ |
| **Department Lead** | ✓ Limited | ✓ Limited | ✗ | ✗ |
| **Analyst** | ✓ Historical | ✓ Trends | ✗ | ✗ |
| **Compliance Officer** | ✗ | ✗ | ✗ | ✓ |

Defined in `cisco_ise_client.py:_get_policy_matrix()`

## Compliance Frameworks Supported

These examples demonstrate compliance with:

- **✓ GDPR** - Privacy by design, data minimization, purpose limitation
- **✓ CCPA** - Consumer privacy rights, data transparency
- **✓ MiFID II** - Complete audit trail, 7-year retention
- **✓ ISO 27001** - Information security controls
- **✓ SOC 2 Type II** - Security, availability, confidentiality controls
- **✓ PCI-DSS** - Access control, audit logging

## API Documentation References

- **Cisco DNA Spaces API**: https://developer.cisco.com/docs/dna-spaces/
- **Cisco ISE ERS API**: https://developer.cisco.com/docs/identity-services-engine/
- **Cisco XDR API**: https://developer.cisco.com/docs/secure-x/
- **Model Context Protocol**: https://modelcontextprotocol.io/

## Metrics from Case Study

**Compliance Results** (6 months operation):
- Privacy violations: **0**
- Security incidents detected: **12** (all blocked)
- Authorization enforcement: **100%** (3,247 requests)
- Audit trail completeness: **100%**

**Business Value**:
- Real estate savings: **$1.2M/year**
- Energy savings: **$180K/year**
- Compliance costs avoided: **$500K**
- ROI: **1,253%** over 3 years
- Payback period: **2.9 months**

## Common Use Cases

### 1. Workspace Optimization
```python
# Get utilization trends to optimize real estate
utilization = await spaces.get_floor_utilization(
    floor_id="floor-3",
    privacy_mode="high"
)
```

### 2. Energy Management
```python
# Adjust HVAC based on occupancy (with authorization)
await spaces.adjust_environment(
    zone_id="zone-conference",
    adjustment_type="temperature",
    parameters={"value": 20}
)
```

### 3. Compliance Reporting
```python
# Generate quarterly compliance report
report = await generate_compliance_report(
    report_type="quarterly",
    date_range={"start": "2024-01-01", "end": "2024-03-31"}
)
```

### 4. Security Monitoring
```python
# Detect anomalies in access patterns
anomalies = await xdr.detect_anomalies(
    audit_log=audit_trail,
    baseline_days=30
)
```

## Testing

Run the test suite to verify all components:

```bash
# Test authorization flows
pytest test_authorization.py

# Test privacy preservation
pytest test_privacy.py

# Test audit logging
pytest test_audit.py

# Test end-to-end scenarios
pytest test_scenarios.py
```

## Troubleshooting

### API Authentication Issues

**Problem**: `401 Unauthorized` errors

**Solution**: Verify API credentials in config:
```python
# Test Spaces API
curl -H "X-API-Key: your_api_key" https://api.dnaspaces.io/api/partners/v1/locations/buildings

# Test ISE (basic auth)
curl -u admin:password https://ise.yourdomain.com:9060/ers/config/authorizationprofile

# Test XDR (OAuth2)
curl -X POST -u client_id:client_secret https://visibility.amp.cisco.com/iroh/oauth2/token
```

### SSL Certificate Errors

**Problem**: `SSL: CERTIFICATE_VERIFY_FAILED`

**Solution** (for development only):
```python
# Add to client initialization
async with session.request(..., ssl=False)
```

**Production**: Install proper SSL certificates.

### Policy Not Found

**Problem**: Authorization always returns "default_deny"

**Solution**: Check policy matrix in `cisco_ise_client.py:_get_policy_matrix()` and ensure role/resource/action matches.

## Security Considerations

⚠️ **Important**: These examples are for demonstration purposes. For production deployment:

1. **Never disable SSL verification** in production
2. **Store credentials securely** (use HashiCorp Vault, AWS Secrets Manager, etc.)
3. **Implement rate limiting** to prevent abuse
4. **Add input validation** for all user-provided data
5. **Use least-privilege principles** for service accounts
6. **Encrypt audit logs** at rest and in transit
7. **Implement log rotation** and retention policies
8. **Add monitoring and alerting** for all critical operations

## Contributing

To extend these examples:

1. Add new roles in `cisco_ise_client.py:_get_policy_matrix()`
2. Add new MCP tools in `mcp_server.py:_register_tools()`
3. Add new Cisco Spaces metrics in `cisco_spaces_client.py`
4. Add new security workflows in `cisco_xdr_client.py`

## License

These examples are provided for educational purposes as part of the conference presentation.

## Support

For questions about:
- **Cisco DNA Spaces**: https://developer.cisco.com/site/dna-spaces/
- **Cisco ISE**: https://developer.cisco.com/site/identity-services-engine/
- **Cisco XDR**: https://developer.cisco.com/xdr/
- **Model Context Protocol**: https://github.com/anthropics/mcp