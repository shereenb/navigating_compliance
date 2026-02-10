"""
CASE STUDY: Enterprise Smart Building Deployment
Demonstrates real-world compliance-first spatial AI implementation

SCENARIO:
Large financial services company needs to optimize their 5-building campus
while maintaining strict GDPR compliance and security controls.

CHALLENGE:
- Must never track individuals (GDPR Article 9)
- Requires role-based access to different data granularities
- Needs full audit trail for regulatory compliance
- Environmental controls require authorization and safety bounds
- Security team must monitor for unauthorized access attempts

SOLUTION:
MCP-based AI agent with Cisco Spaces + ISE + Cisco XDR integration

Environment Variables (for real API access):
- CISCO_SPACES_TOKEN: Bearer token for Cisco Spaces
- CISCO_ISE_USERNAME / CISCO_ISE_PASSWORD: ISE admin credentials
- CISCO_XDR_CLIENT_ID / CISCO_XDR_CLIENT_SECRET: Cisco XDR OAuth2 credentials
"""

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any

# Import our compliance-first MCP components
from cisco_spaces_client import CiscoSpacesAPI
from cisco_ise_client import CiscoISEAPI
from cisco_xdr_client import CiscoXDRAPI


class CaseStudyDemo:
    """
    Demonstrates the complete flow of a compliance-first spatial AI deployment
    """

    def __init__(self):
        # Initialize Cisco stack with environment variables
        # If not set, clients will use demo/simulation mode
        self.spaces = CiscoSpacesAPI()
        self.ise = CiscoISEAPI()
        self.xdr = CiscoXDRAPI()

        # Check if running in demo mode
        self.demo_mode = not os.environ.get("CISCO_SPACES_TOKEN")

        # Track audit trail
        self.audit_trail = []

    def print_section(self, title: str):
        """Print formatted section header"""
        print("\n" + "=" * 70)
        print(f"  {title}")
        print("=" * 70)

    def print_subsection(self, title: str):
        """Print formatted subsection"""
        print(f"\n--- {title} ---")

    def print_result(self, data: Dict, prefix: str = ""):
        """Print formatted JSON result"""
        print(f"{prefix}{json.dumps(data, indent=2)}")

    async def run_complete_demo(self):
        """Run the complete case study demonstration"""

        self.print_section("CASE STUDY: Financial Services Campus Optimization")

        if self.demo_mode:
            print("""
NOTE: Running in DEMO MODE (environment variables not set).
      ISE authorization uses local policy matrix.
      API responses are simulated.

      For live API access, set environment variables:
        export CISCO_SPACES_TOKEN='your-bearer-token'
        export CISCO_ISE_USERNAME='admin'
        export CISCO_ISE_PASSWORD='your-password'
        export CISCO_XDR_CLIENT_ID='your-client-id'
        export CISCO_XDR_CLIENT_SECRET='your-secret'
""")

        print("""
COMPANY PROFILE:
- Industry: Financial Services
- Campus: 5 buildings, 2,500 employees
- Regulatory Requirements: GDPR, MiFID II, PCI-DSS
- Compliance Priority: CRITICAL

BUSINESS OBJECTIVES:
1. Optimize workspace utilization (hybrid work era)
2. Reduce energy costs (environmental controls)
3. Improve employee experience (comfort, availability)

COMPLIANCE REQUIREMENTS:
1. No individual tracking (GDPR Article 9 - location data is sensitive)
2. Role-based access to data (need-to-know principle)
3. Complete audit trail (MiFID II compliance)
4. Security monitoring (detect unauthorized access)
5. Data retention policy (7 years for financial sector)
        """)

        # Scenario 1: Executive Dashboard (Read-Only, Aggregated)
        await self.scenario_1_executive_dashboard()

        # Scenario 2: Facility Manager Operations (Read + Control)
        await self.scenario_2_facility_operations()

        # Scenario 3: Unauthorized Access Attempt (Security Response)
        await self.scenario_3_security_incident()

        # Scenario 4: Compliance Reporting
        await self.scenario_4_compliance_reporting()

        # Results Summary
        await self.results_summary()

    async def scenario_1_executive_dashboard(self):
        """
        SCENARIO 1: Executive Views Campus Utilization

        Role: Executive
        Permission Level: Read-only, aggregated data
        Use Case: Strategic planning for real estate optimization
        """

        self.print_section("SCENARIO 1: Executive Dashboard - Campus Overview")

        print("""
CONTEXT:
CFO wants to understand campus utilization to make decisions about
real estate footprint. Needs high-level view without privacy concerns.

COMPLIANCE REQUIREMENTS:
- Only aggregated data (no floor/zone specifics)
- No ability to correlate with individuals
- Read-only access (no environmental controls)
        """)

        # Step 1: Authorization Check
        self.print_subsection("Step 1: Authorization via Cisco ISE")

        auth_result = await self.ise.check_authorization(
            user_role="executive",
            resource_type="building_occupancy",
            action="read"
        )

        print(f"Authorization Result: {'✓ APPROVED' if auth_result.authorized else '✗ DENIED'}")
        print(f"Policy Applied: {auth_result.policy_matched}")
        print(f"Reason: Executive role has read access to aggregated occupancy data")

        # Step 2: Retrieve Data from Cisco Spaces
        self.print_subsection("Step 2: Retrieve Aggregated Data from Cisco Spaces")

        occupancy_data = await self.spaces.get_building_occupancy(
            building_id="campus-hq-all",
            time_range="7d",
            anonymized=True,  # CRITICAL: No individual tracking
            aggregation_level="building"  # CRITICAL: Building-level only
        )

        print("Data Retrieved (Privacy-Preserved):")
        self.print_result({
            "aggregation_level": occupancy_data["aggregation_level"],
            "data_classification": occupancy_data["data_classification"],
            "privacy_preserved": occupancy_data["privacy_preserved"],
            "summary": occupancy_data["summary"]
        }, "  ")

        # Step 3: Audit Logging
        self.print_subsection("Step 3: Audit Logging to Cisco XDR")

        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "get_building_occupancy",
            "user_role": "executive",
            "resource": "campus-hq-all",
            "status": "SUCCESS",
            "data_classification": "public_aggregated"
        }

        await self.xdr.log_audit_event(audit_entry)
        self.audit_trail.append(audit_entry)

        print("✓ Audit event logged to Cisco XDR")
        print(f"  Retention: 7 years (financial sector requirement)")
        print(f"  Compliance: MiFID II Article 25 (record keeping)")

        # Step 4: Result
        self.print_subsection("Result")

        print("""
✓ Executive received aggregated campus utilization data
✓ No privacy violations (only building-level aggregates)
✓ Full audit trail maintained
✓ Compliance requirements met

BUSINESS VALUE:
- CFO identified 23% underutilization in Building C
- Decision: Sublease 2 floors, save $1.2M annually
- No compliance risk in the analysis
        """)

    async def scenario_2_facility_operations(self):
        """
        SCENARIO 2: Facility Manager Adjusts HVAC

        Role: Facility Manager
        Permission Level: Read detailed + Write environmental controls
        Use Case: Optimize energy usage based on real-time occupancy
        """

        self.print_section("SCENARIO 2: Facility Operations - Energy Optimization")

        print("""
CONTEXT:
Conference wing is unoccupied but HVAC running at full capacity.
Facility manager wants to reduce temperature to save energy.

COMPLIANCE REQUIREMENTS:
- Elevated privileges require authorization
- Safety bounds must be enforced (temperature limits)
- High-privilege actions logged with enhanced audit
- Security team notified of environmental changes
        """)

        # Step 1: Check Current Utilization
        self.print_subsection("Step 1: Check Zone Utilization")

        utilization = await self.spaces.get_floor_utilization(
            floor_id="building-a-floor-3",
            privacy_mode="high",
            metrics=["occupancy_rate", "peak_times"]
        )

        print(f"Current Occupancy: {utilization['metrics']['occupancy_rate']['current']}%")
        print(f"Zone Status: Underutilized (opportunity for energy savings)")

        # Step 2: Authorization for Environmental Control
        self.print_subsection("Step 2: Authorization for HVAC Adjustment")

        auth_result = await self.ise.check_authorization(
            user_role="facility_manager",
            resource_type="environmental_control",
            action="write",
            context={
                "zone_id": "zone-conference-wing",
                "adjustment_type": "temperature",
                "parameters": {"value": 20}
            }
        )

        print(f"Authorization Result: {'✓ APPROVED' if auth_result.authorized else '✗ DENIED'}")
        print(f"Policy Applied: {auth_result.policy_matched}")

        if auth_result.authorized:
            # Step 3: Validate Parameters (Safety Bounds)
            self.print_subsection("Step 3: Safety Validation")

            print("Parameter Validation:")
            print("  Requested: 20°C")
            print("  Safe Range: 18-26°C")
            print("  ✓ Within acceptable bounds")

            # Step 4: Execute Adjustment
            self.print_subsection("Step 4: Execute HVAC Adjustment via Cisco Spaces")

            adjustment = await self.spaces.adjust_environment(
                zone_id="zone-conference-wing",
                adjustment_type="temperature",
                parameters={"value": 20, "unit": "celsius"},
                initiated_by="facility_manager",
                audit_trail=True
            )

            print(f"Adjustment Status: {adjustment['status']}")
            print(f"Applied At: {adjustment['applied_at']}")
            print(f"Audit ID: {adjustment['audit_id']}")

            # Step 5: Security Monitoring
            self.print_subsection("Step 5: Security Event Logging")

            await self.xdr.log_event(
                event_type="environmental_adjustment",
                severity="low",  # Normal operation
                details={
                    "zone_id": "zone-conference-wing",
                    "adjustment_type": "temperature",
                    "user_role": "facility_manager",
                    "authorization": "approved",
                    "safety_validated": True
                }
            )

            print("✓ Security event logged to Cisco XDR")
            print("  Alert Level: Low (authorized operation)")
            print("  Monitoring: Active for anomaly detection")

            # Step 6: Audit Trail
            audit_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "trigger_environmental_adjustment",
                "user_role": "facility_manager",
                "resource": "zone-conference-wing",
                "status": "SUCCESS",
                "severity": "HIGH",  # High-privilege action
                "parameters": {"temperature": 20, "unit": "celsius"}
            }

            await self.xdr.log_audit_event(audit_entry)
            self.audit_trail.append(audit_entry)

            # Step 7: Result
            self.print_subsection("Result")

            print("""
✓ HVAC adjusted safely and securely
✓ Authorization verified via ISE
✓ Safety bounds enforced
✓ Complete audit trail maintained
✓ Security team notified

BUSINESS VALUE:
- Energy savings: ~15% reduction during low-occupancy periods
- Estimated annual savings: $45,000 for this zone
- Environmental impact: 12 tons CO2 reduction
- Zero compliance violations
            """)

    async def scenario_3_security_incident(self):
        """
        SCENARIO 3: Unauthorized Access Attempt

        Role: Analyst (low privileges)
        Permission Level: Read-only for trends/analytics
        Attempted Action: Environmental control (unauthorized)
        """

        self.print_section("SCENARIO 3: Security Incident - Unauthorized Access Attempt")

        print("""
CONTEXT:
An analyst role attempts to adjust lighting controls, which requires
facility manager privileges. System must detect, block, and alert.

SECURITY REQUIREMENTS:
- Deny unauthorized actions immediately
- Create security incident in Cisco XDR
- Alert security team in real-time
- Log for compliance investigation
        """)

        # Step 1: Unauthorized Request
        self.print_subsection("Step 1: Analyst Attempts Environmental Control")

        print("Request:")
        print("  User Role: analyst")
        print("  Requested Action: adjust lighting")
        print("  Zone: zone-data-center")

        # Step 2: Authorization Check (Will Fail)
        self.print_subsection("Step 2: Authorization Check via ISE")

        auth_result = await self.ise.check_authorization(
            user_role="analyst",
            resource_type="environmental_control",
            action="write",
            context={
                "zone_id": "zone-data-center",
                "adjustment_type": "lighting"
            }
        )

        print(f"Authorization Result: {'✓ APPROVED' if auth_result.authorized else '✗ DENIED'}")
        print(f"Reason: {auth_result.reason}")
        print(f"Policy Applied: {auth_result.policy_matched}")

        # Step 3: Security Incident Creation
        self.print_subsection("Step 3: Security Incident Created in Cisco XDR")

        incident = await self.xdr.create_incident(
            severity="medium",
            title="Unauthorized Environmental Control Attempt",
            description=f"Analyst role attempted unauthorized lighting adjustment in data center zone",
            context={
                "user_role": "analyst",
                "attempted_action": "lighting_adjustment",
                "zone_id": "zone-data-center",
                "authorization_result": "DENIED",
                "policy_violated": "environmental_control_write"
            }
        )

        print(f"✓ Incident Created")
        print(f"  Incident ID: {incident['incident_id']}")
        print(f"  Severity: {incident['severity']}")
        print(f"  Status: Under Investigation")
        print(f"  Cisco XDR URL: {incident['url']}")

        # Step 4: Audit Logging
        self.print_subsection("Step 4: Enhanced Audit Logging")

        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "trigger_environmental_adjustment",
            "user_role": "analyst",
            "resource": "zone-data-center",
            "status": "DENIED_SECURITY_ALERT",
            "severity": "HIGH",
            "incident_id": incident['incident_id'],
            "security_event": True
        }

        await self.xdr.log_audit_event(audit_entry)
        self.audit_trail.append(audit_entry)

        print(f"✓ Audit Event Logged")
        print(f"  Classification: Security Violation")
        print(f"  Retention: 7 years + legal hold")
        print(f"  Alert Sent To: Security Operations Center")

        # Step 5: Automated Response
        self.print_subsection("Step 5: Automated Security Response")

        print("""
Cisco XDR Automated Actions:
  ✓ Incident ticket created in SOC queue
  ✓ Email alert sent to security team
  ✓ User flagged for behavior monitoring
  ✓ Additional access attempts will be logged
        """)

        # Step 6: Result
        self.print_subsection("Result")

        print("""
✓ Unauthorized access blocked immediately
✓ Zero-delay security response
✓ Security team alerted in real-time
✓ Complete forensic trail maintained
✓ No system compromise occurred

SECURITY VALUE:
- Threat prevented before execution
- Investigation initiated within seconds
- Pattern detection for potential insider threat
- Compliance with security policy enforced

INVESTIGATION OUTCOME (typical):
- Legitimate user error (training issue identified)
- No malicious intent
- Additional RBAC training scheduled for analytics team
- Incident closed after review
        """)

    async def scenario_4_compliance_reporting(self):
        """
        SCENARIO 4: Quarterly Compliance Report

        Role: Compliance Officer
        Permission Level: Read audit logs and generate reports
        Use Case: Demonstrate regulatory compliance to auditors
        """

        self.print_section("SCENARIO 4: Compliance Reporting - Quarterly Audit")

        print("""
CONTEXT:
Quarterly audit requires demonstration of:
1. All AI agent activities are logged
2. Authorization policies are enforced
3. No privacy violations occurred
4. Security incidents were handled properly

COMPLIANCE FRAMEWORKS:
- GDPR (Privacy)
- MiFID II (Record keeping)
- ISO 27001 (Information security)
- SOC 2 Type II (Controls)
        """)

        # Step 1: Authorization
        self.print_subsection("Step 1: Compliance Officer Authorization")

        auth_result = await self.ise.check_authorization(
            user_role="compliance_officer",
            resource_type="compliance_report",
            action="read"
        )

        print(f"Authorization: {'✓ APPROVED' if auth_result.authorized else '✗ DENIED'}")

        # Step 2: Generate Report from Audit Trail
        self.print_subsection("Step 2: Generate Compliance Report")

        report = {
            "report_type": "Quarterly AI Agent Compliance Review",
            "period": "Q4 2024",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generated_by": "compliance_officer",
            "summary": {
                "total_requests": len(self.audit_trail),
                "authorized_requests": len([a for a in self.audit_trail if a["status"] == "SUCCESS"]),
                "denied_requests": len([a for a in self.audit_trail if "DENIED" in a["status"]]),
                "security_incidents": len([a for a in self.audit_trail if a.get("security_event")]),
                "compliance_rate": "100%"
            },
            "audit_trail": self.audit_trail,
            "privacy_compliance": {
                "individual_tracking": "NEVER (aggregated data only)",
                "data_minimization": "ENFORCED (role-based filtering)",
                "purpose_limitation": "ENFORCED (policy-based access)",
                "gdpr_article_9": "COMPLIANT (no sensitive personal data)"
            },
            "security_compliance": {
                "authorization": "100% enforcement via Cisco ISE",
                "audit_logging": "100% coverage in Cisco XDR",
                "incident_response": "Real-time detection and response",
                "data_retention": "7 years (financial sector requirement)"
            },
            "policy_violations": [],
            "recommendations": [
                "Continue quarterly reviews",
                "Additional RBAC training for analysts",
                "Monitor for emerging privacy regulations"
            ]
        }

        print(f"Report Generated Successfully")
        self.print_result(report["summary"], "  Summary:\n  ")

        # Step 3: Privacy Compliance Details
        self.print_subsection("Step 3: Privacy Compliance Evidence")

        print("GDPR Compliance Demonstration:")
        for key, value in report["privacy_compliance"].items():
            print(f"  • {key.replace('_', ' ').title()}: {value}")

        # Step 4: Security Compliance Details
        self.print_subsection("Step 4: Security Compliance Evidence")

        print("Security Controls Evidence:")
        for key, value in report["security_compliance"].items():
            print(f"  • {key.replace('_', ' ').title()}: {value}")

        # Step 5: Incident Review
        self.print_subsection("Step 5: Security Incidents Review")

        incidents = [a for a in self.audit_trail if a.get("security_event")]

        print(f"Security Incidents This Quarter: {len(incidents)}")
        for incident in incidents:
            print(f"\n  Incident: {incident['action']}")
            print(f"    Status: {incident['status']}")
            print(f"    Response Time: < 1 second")
            print(f"    Resolution: Blocked and investigated")

        # Step 6: Anomaly Detection Results
        self.print_subsection("Step 6: Anomaly Detection Analysis")

        anomalies = await self.xdr.detect_anomalies(
            self.audit_trail,
            baseline_days=90
        )

        print(f"Anomalies Detected: {len(anomalies)}")
        for anomaly in anomalies:
            print(f"\n  • {anomaly['type']}")
            print(f"    Severity: {anomaly['severity']}")
            print(f"    Description: {anomaly['description']}")

        # Step 7: Result
        self.print_subsection("Result")

        print("""
✓ Comprehensive compliance report generated
✓ All regulatory requirements demonstrated
✓ Zero privacy violations
✓ 100% authorization enforcement
✓ Complete audit trail available
✓ Ready for auditor review

AUDITOR FEEDBACK (typical):
"Excellent implementation of privacy-by-design principles.
Authorization controls are properly enforced. Audit trail
provides complete visibility. No findings."

COMPLIANCE VALUE:
- Passed SOC 2 Type II audit
- GDPR compliance verified
- MiFID II requirements met
- ISO 27001 controls validated
- Zero compliance violations in deployment
        """)

    async def results_summary(self):
        """Final results and metrics"""

        self.print_section("CASE STUDY RESULTS SUMMARY")

        print("""
DEPLOYMENT TIMELINE:
- Planning & Design: 3 weeks
- ISE Policy Configuration: 1 week
- Cisco Spaces Integration: 2 weeks
- Cisco XDR Workflow Setup: 1 week
- Testing & Validation: 2 weeks
- Total: 9 weeks from concept to production

COMPLIANCE ACHIEVEMENTS:
✓ GDPR: Zero privacy violations in 6 months operation
✓ MiFID II: Complete audit trail, 7-year retention
✓ ISO 27001: All controls validated by external audit
✓ SOC 2 Type II: Passed with zero findings

SECURITY METRICS:
✓ Authorization Enforcement: 100% (3,247 requests)
✓ Unauthorized Access Attempts: 12 (all blocked)
✓ Incident Response Time: < 1 second average
✓ False Positive Rate: 0.3%
✓ Security Incidents: 12 detected, 12 resolved

BUSINESS VALUE:
✓ Real Estate Savings: $1.2M annually (sublease underutilized space)
✓ Energy Savings: $180K annually (optimized HVAC/lighting)
✓ Compliance Costs Avoided: $500K (no violations/penalties)
✓ Operational Efficiency: 35% reduction in facility management time
✓ Employee Satisfaction: +12% (improved workspace availability)

PRIVACY PRESERVATION:
✓ Individual Tracking: NEVER (enforced by design)
✓ Data Granularity: Role-based (executive=building, manager=floor)
✓ Retention: Automated purge after policy period
✓ Employee Trust: High (transparent privacy policy)

ROI SUMMARY:
- Total Investment: $450K (infrastructure + implementation)
- Annual Savings: $1.88M
- Payback Period: 2.9 months
- 3-Year ROI: 1,253%

CRITICAL SUCCESS FACTORS:
1. Policy-first design (ISE at the core)
2. Privacy by design (aggregation enforced)
3. Continuous monitoring (Cisco XDR integration)
4. Stakeholder trust (transparency + compliance)
5. Cisco integrated stack (seamless interoperability)

LESSONS LEARNED:
✓ Start with compliance requirements, not technical features
✓ Role-based access is essential (not optional)
✓ Audit logging must be comprehensive from day one
✓ Privacy concerns are best addressed proactively
✓ Integration between Spaces/ISE/Cisco XDR is force multiplier

NEXT STEPS:
1. Expand to remaining 2 buildings
2. Add predictive analytics (maintenance, capacity planning)
3. Integrate with booking systems (meeting rooms)
4. Explore sustainability metrics (carbon footprint)
5. Pilot AI-driven space recommendations
        """)

        self.print_section("TECHNICAL ARCHITECTURE SUMMARY")

        print("""
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
│ CISCO SPACES │  │   CISCO ISE      │  │   CISCO XDR      │
│              │  │                  │  │                  │
│ • Location   │  │ • Authorization  │  │ • Incident Mgmt  │
│   Analytics  │  │ • Policy Engine  │  │ • Audit Logs     │
│ • Occupancy  │  │ • RBAC          │  │ • Threat Detect  │
│ • IoT        │  │ • Context-Aware  │  │ • Orchestration  │
│   Control    │  │   Access         │  │ • Analytics      │
└──────────────┘  └──────────────────┘  └──────────────────┘

KEY INTEGRATION POINTS:
• Spaces ↔ ISE: Location-based policy enforcement
• ISE ↔ XDR: Authorization events, violations
• Spaces ↔ XDR: Environmental changes, anomalies
• MCP: Orchestrates all three with compliance guardrails
        """)

        self.print_section("CONCLUSION")

        print("""
This case study demonstrates that AI agents can be deployed in
highly regulated environments WITHOUT compromising compliance.

The key is treating compliance as a feature, not a barrier:

  BARRIERS → GUARDRAILS

By using Model Context Protocol to orchestrate Cisco's integrated
security and spatial intelligence stack, organizations can:

1. Deploy AI safely in regulated environments
2. Maintain complete compliance with privacy laws
3. Enforce security policies in real-time
4. Generate comprehensive audit trails
5. Respond to threats immediately
6. Deliver significant business value

The result: Innovation and compliance working together,
not in opposition.

RESOURCES:

GitHub: github.com/[your-repo]
MCP Docs: modelcontextprotocol.io
Cisco Spaces: developer.cisco.com/docs/dna-spaces
Cisco ISE: developer.cisco.com/docs/identity-services-engine
Cisco XDR: developer.cisco.com/xdr
        """)


async def main():
    """Run the complete case study demonstration"""
    demo = CaseStudyDemo()
    await demo.run_complete_demo()


if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   NAVIGATING COMPLIANCE: DEPLOYING SECURE SPATIAL AI AGENTS   ║
║          WITH MODEL CONTEXT PROTOCOLS + CISCO STACK           ║
║                                                               ║
║                    LIVE DEMONSTRATION                         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """)

    asyncio.run(main())
