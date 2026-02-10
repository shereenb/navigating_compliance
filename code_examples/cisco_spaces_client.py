"""
Cisco DNA Spaces API Client
Real Cisco Spaces API integration for spatial AI

API Documentation: https://developer.cisco.com/docs/dna-spaces/
Base URL: https://dnaspaces.io/api/location/v1
Authentication: Bearer token

Credentials should be provided via environment variables:
- CISCO_SPACES_TOKEN: Bearer token from Cisco Spaces portal
- CISCO_SPACES_URL: Base URL (defaults to https://dnaspaces.io/api/location/v1)
"""

import os
import aiohttp
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta


class CiscoSpacesAPI:
    """
    Client for Cisco DNA Spaces API
    https://developer.cisco.com/docs/dna-spaces/

    Provides access to:
    - Location analytics
    - Occupancy data
    - Asset tracking
    - Environmental sensors
    """

    def __init__(
        self,
        bearer_token: str = None,
        base_url: str = None
    ):
        """
        Initialize Cisco Spaces API client.

        Args:
            bearer_token: Bearer token from Cisco Spaces. If not provided,
                         reads from CISCO_SPACES_TOKEN environment variable.
            base_url: API base URL. Defaults to https://dnaspaces.io/api/location/v1
        """
        self.bearer_token = bearer_token or os.environ.get("CISCO_SPACES_TOKEN", "")
        self.base_url = base_url or os.environ.get(
            "CISCO_SPACES_URL",
            "https://dnaspaces.io/api/location/v1"
        )

        self.headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """Make authenticated API request"""
        async with aiohttp.ClientSession() as session:
            url = f"{self.base_url}{endpoint}"
            async with session.request(
                method, url, headers=self.headers, **kwargs
            ) as response:
                response.raise_for_status()
                return await response.json()

    # Location Analytics APIs

    async def get_building_occupancy(
        self,
        building_id: str,
        time_range: str = "current",
        anonymized: bool = True,
        aggregation_level: str = "floor"
    ) -> Dict[str, Any]:
        """
        Get building occupancy using Cisco Spaces Location Analytics.

        API: GET /clients/count
        Docs: https://developer.cisco.com/docs/dna-spaces/#!active-clients-location

        Args:
            building_id: Cisco Spaces building/location identifier
            time_range: "current", "1h", "24h", "7d"
            anonymized: Return aggregated data only (no device tracking)
            aggregation_level: "building", "floor", "zone"
        """
        # Demo mode: return simulated data if no token
        if not self.bearer_token:
            return self._mock_occupancy_data(building_id, aggregation_level, anonymized)

        # Map time range to actual timestamps
        end_time = datetime.utcnow()
        time_ranges = {
            "current": timedelta(minutes=5),
            "1h": timedelta(hours=1),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7)
        }
        start_time = end_time - time_ranges.get(time_range, timedelta(minutes=5))

        # Cisco Spaces API endpoint for client count
        endpoint = "/clients/count"
        params = {
            "locationId": building_id,
        }

        try:
            response = await self._request("GET", endpoint, params=params)

            # Process and anonymize the response
            occupancy_data = self._process_occupancy_data(
                response,
                aggregation_level,
                anonymized
            )

            return occupancy_data

        except aiohttp.ClientError as e:
            return {
                "error": "API request failed",
                "details": str(e),
                "building_id": building_id
            }

    def _mock_occupancy_data(
        self,
        building_id: str,
        aggregation_level: str,
        anonymized: bool
    ) -> Dict[str, Any]:
        """Return simulated occupancy data for demo mode"""
        return {
            "aggregation_level": aggregation_level,
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_count": 847,
                "active_zones": 12,
                "average_occupancy": 68
            },
            "by_floor": [
                {"zone_id": "floor-1", "zone_name": "Floor 1", "occupancy_count": 156},
                {"zone_id": "floor-2", "zone_name": "Floor 2", "occupancy_count": 203},
                {"zone_id": "floor-3", "zone_name": "Floor 3", "occupancy_count": 178},
                {"zone_id": "floor-4", "zone_name": "Floor 4", "occupancy_count": 142},
                {"zone_id": "floor-5", "zone_name": "Floor 5", "occupancy_count": 168},
            ],
            "privacy_preserved": anonymized,
            "data_classification": "Public - Aggregated Only",
            "demo_mode": True
        }

    async def get_active_clients(
        self,
        location_id: str = None,
        associated: bool = True
    ) -> Dict[str, Any]:
        """
        Get active client locations.

        API: GET /clients
        Docs: https://developer.cisco.com/docs/dna-spaces/#!active-clients-location

        Args:
            location_id: Filter by location ID
            associated: Only return associated (connected) clients
        """
        endpoint = "/clients"
        params = {}

        if location_id:
            params["locationId"] = location_id
        if associated:
            params["associated"] = "true"

        response = await self._request("GET", endpoint, params=params)
        return response

    async def get_floor_utilization(
        self,
        floor_id: str,
        privacy_mode: str = "high",
        metrics: List[str] = None
    ) -> Dict[str, Any]:
        """
        Get floor utilization metrics.

        API: GET /clients/count with floor-level filtering

        Args:
            floor_id: Cisco Spaces floor identifier
            privacy_mode: "high" (aggregated only), "medium" (zone-level), "low" (detailed)
            metrics: List of metrics to include
        """
        if metrics is None:
            metrics = ["occupancy_rate", "duration", "peak_times"]

        # Demo mode: return simulated data if no token
        if not self.bearer_token:
            return {
                "floor_id": floor_id,
                "timestamp": datetime.utcnow().isoformat(),
                "privacy_mode": privacy_mode,
                "metrics": {
                    "occupancy_rate": {"current": 23, "unit": "percent"},
                    "average_duration": {"value": 45, "unit": "minutes"},
                    "peak_times": ["09:00-10:00", "14:00-15:00"]
                },
                "compliance_notes": "Data aggregated to preserve privacy",
                "demo_mode": True
            }

        endpoint = "/clients/count"
        params = {
            "locationId": floor_id
        }

        response = await self._request("GET", endpoint, params=params)

        return {
            "floor_id": floor_id,
            "timestamp": datetime.utcnow().isoformat(),
            "privacy_mode": privacy_mode,
            "metrics": self._calculate_utilization_metrics(response, metrics),
            "compliance_notes": "Data aggregated to preserve privacy"
        }

    async def get_utilization_trends(
        self,
        floor_id: str,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get historical utilization trends.

        API: GET /history/clients/count

        Args:
            floor_id: Cisco Spaces floor identifier
            days: Number of days of history
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        endpoint = "/history/clients/count"
        params = {
            "locationId": floor_id,
            "startTime": int(start_date.timestamp() * 1000),
            "endTime": int(end_date.timestamp() * 1000),
        }

        response = await self._request("GET", endpoint, params=params)

        return {
            "floor_id": floor_id,
            "period": f"{days} days",
            "trends": response.get("results", []),
            "summary": self._summarize_trends(response)
        }

    async def get_location_history(
        self,
        device_id: str,
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, Any]:
        """
        Get location history for a device.

        API: GET /history/clients/{deviceId}
        Docs: https://developer.cisco.com/docs/dna-spaces/#!location-history

        Args:
            device_id: Device MAC address or ID
            start_time: Start of time range
            end_time: End of time range
        """
        endpoint = f"/history/clients/{device_id}"
        params = {
            "startTime": int(start_time.timestamp() * 1000),
            "endTime": int(end_time.timestamp() * 1000),
        }

        response = await self._request("GET", endpoint, params=params)
        return response

    # Environmental Control APIs (IoT Integration)

    async def adjust_environment(
        self,
        zone_id: str,
        adjustment_type: str,
        parameters: Dict[str, Any],
        initiated_by: str,
        audit_trail: bool = True
    ) -> Dict[str, Any]:
        """
        Adjust environmental controls via Cisco Spaces IoT integration.

        Note: This requires Cisco Spaces IoT Services and connected
        BMS (Building Management System) integration.

        Args:
            zone_id: Cisco Spaces zone identifier
            adjustment_type: "temperature", "lighting", "ventilation"
            parameters: Adjustment parameters (e.g., {"value": 22})
            initiated_by: User role initiating the adjustment
            audit_trail: Whether to enable audit logging
        """
        # Demo mode: return simulated response if no token
        if not self.bearer_token:
            return {
                "zone_id": zone_id,
                "adjustment_type": adjustment_type,
                "status": "applied",
                "applied_at": datetime.utcnow().isoformat(),
                "audit_id": f"AUDIT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                "message": "Environmental adjustment applied (demo mode)",
                "demo_mode": True
            }

        # IoT actuator endpoint (requires IoT Services add-on)
        endpoint = "/iot/actuators"

        payload = {
            "zoneId": zone_id,
            "actuatorType": adjustment_type,
            "parameters": parameters,
            "initiatedBy": initiated_by,
            "timestamp": datetime.utcnow().isoformat()
        }

        if audit_trail:
            payload["auditEnabled"] = True
            payload["auditMetadata"] = {
                "source": "MCP_AI_Agent",
                "compliance": "ISO27001,GDPR"
            }

        try:
            response = await self._request("POST", endpoint, json=payload)

            return {
                "zone_id": zone_id,
                "adjustment_type": adjustment_type,
                "status": response.get("status", "submitted"),
                "applied_at": response.get("appliedAt"),
                "audit_id": response.get("auditId"),
                "message": "Environmental adjustment submitted"
            }
        except aiohttp.ClientError as e:
            return {
                "zone_id": zone_id,
                "status": "error",
                "error": str(e)
            }

    # Building and Floor Management

    async def list_buildings(self) -> List[Dict[str, Any]]:
        """
        List all buildings/locations in Cisco Spaces.

        API: GET /map/hierarchy
        Docs: https://developer.cisco.com/docs/dna-spaces/#!map
        """
        endpoint = "/map/hierarchy"
        response = await self._request("GET", endpoint)

        buildings = []

        # Parse hierarchy to extract buildings
        for item in response.get("results", []):
            if item.get("type") == "building":
                building = {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "address": item.get("address", {}),
                    "country": item.get("address", {}).get("country"),
                    "floors": item.get("childCount", 0),
                    "compliance_metadata": {
                        "data_residency": item.get("address", {}).get("country", "Unknown"),
                        "privacy_framework": self._get_privacy_framework(
                            item.get("address", {}).get("country")
                        ),
                        "retention_policy": "90 days aggregated, real-time anonymized"
                    }
                }
                buildings.append(building)

        return buildings

    async def get_floor_map(self, floor_id: str) -> Dict[str, Any]:
        """
        Get floor map and zone definitions.

        API: GET /map/elements/{floorId}
        Docs: https://developer.cisco.com/docs/dna-spaces/#!map
        """
        endpoint = f"/map/elements/{floor_id}"
        response = await self._request("GET", endpoint)

        return {
            "floor_id": floor_id,
            "name": response.get("name"),
            "zones": response.get("zones", []),
            "dimensions": response.get("dimensions"),
            "sensor_coverage": response.get("accessPoints", [])
        }

    async def get_access_points(self, location_id: str = None) -> List[Dict[str, Any]]:
        """
        Get access points for a location.

        API: GET /accessPoints
        Docs: https://developer.cisco.com/docs/dna-spaces/#!access-points
        """
        endpoint = "/accessPoints"
        params = {}

        if location_id:
            params["locationId"] = location_id

        response = await self._request("GET", endpoint, params=params)
        return response.get("results", [])

    # Notifications API

    async def create_notification_rule(
        self,
        name: str,
        trigger_type: str,
        location_id: str,
        webhook_url: str
    ) -> Dict[str, Any]:
        """
        Create a notification rule for location events.

        API: POST /notifications
        Docs: https://developer.cisco.com/docs/dna-spaces/#!notifications
        """
        endpoint = "/notifications"
        payload = {
            "name": name,
            "triggerType": trigger_type,
            "locationId": location_id,
            "deliveryMechanism": {
                "type": "webhook",
                "url": webhook_url
            },
            "enabled": True
        }

        response = await self._request("POST", endpoint, json=payload)
        return response

    # Data Processing Helpers

    def _process_occupancy_data(
        self,
        raw_data: Dict,
        aggregation_level: str,
        anonymized: bool
    ) -> Dict[str, Any]:
        """Process and anonymize occupancy data"""
        if anonymized:
            # Remove all device-level identifiers
            processed = {
                "aggregation_level": aggregation_level,
                "timestamp": datetime.utcnow().isoformat(),
                "summary": {
                    "total_count": raw_data.get("count", 0),
                    "active_zones": len(raw_data.get("results", [])),
                },
                "by_floor": [],
                "privacy_preserved": True,
                "data_classification": "Public - Aggregated Only"
            }

            # Aggregate by floor/zone without individual tracking
            for zone in raw_data.get("results", []):
                processed["by_floor"].append({
                    "zone_id": zone.get("locationId"),
                    "zone_name": zone.get("locationName", "Unknown"),
                    "occupancy_count": zone.get("count", 0),
                })

            return processed

        return raw_data

    def _calculate_utilization_metrics(
        self,
        raw_data: Dict,
        metrics: List[str]
    ) -> Dict[str, Any]:
        """Calculate utilization metrics from raw data"""
        calculated = {}
        count = raw_data.get("count", 0)

        if "occupancy_rate" in metrics:
            calculated["occupancy_rate"] = {
                "current": count,
                "unit": "devices"
            }

        if "duration" in metrics:
            calculated["average_duration"] = {
                "value": raw_data.get("averageDuration", 0),
                "unit": "minutes"
            }

        if "peak_times" in metrics:
            calculated["peak_times"] = raw_data.get("peakTimes", [])

        return calculated

    def _summarize_trends(self, trend_data: Dict) -> Dict[str, Any]:
        """Summarize trend data for easy consumption"""
        results = trend_data.get("results", [])

        if not results:
            return {"message": "No trend data available"}

        counts = [r.get("count", 0) for r in results]

        return {
            "average_count": sum(counts) / len(counts) if counts else 0,
            "peak_count": max(counts) if counts else 0,
            "low_count": min(counts) if counts else 0,
            "data_points": len(results)
        }

    def _get_privacy_framework(self, country: str) -> str:
        """Determine applicable privacy framework by country"""
        if not country:
            return "Local Privacy Laws"

        frameworks = {
            "EU": "GDPR",
            "UK": "UK GDPR",
            "US": "CCPA/State Laws",
            "CA": "PIPEDA",
            "AU": "Privacy Act 1988"
        }

        # EU countries
        eu_countries = [
            "DE", "FR", "ES", "IT", "NL", "BE", "AT", "PL",
            "SE", "DK", "FI", "NO", "IE", "PT", "GR", "CZ"
        ]

        if country in eu_countries:
            return frameworks["EU"]
        elif country in frameworks:
            return frameworks[country]
        else:
            return "Local Privacy Laws"


# Example usage
async def example_usage():
    """Example of using Cisco Spaces API with compliance controls"""

    # Initialize with environment variables
    spaces = CiscoSpacesAPI()

    # Check if token is configured
    if not spaces.bearer_token:
        print("ERROR: CISCO_SPACES_TOKEN environment variable not set")
        print("\nTo use this client, set the following environment variables:")
        print("  export CISCO_SPACES_TOKEN='your-bearer-token'")
        print("  export CISCO_SPACES_URL='https://dnaspaces.io/api/location/v1'  # optional")
        return

    print("=" * 60)
    print("EXAMPLE 1: List Buildings")
    print("=" * 60)

    buildings = await spaces.list_buildings()
    print(json.dumps(buildings, indent=2))

    print("\n" + "=" * 60)
    print("EXAMPLE 2: Get Building Occupancy (Privacy-Preserving)")
    print("=" * 60)

    if buildings:
        building_id = buildings[0]["id"]
        occupancy = await spaces.get_building_occupancy(
            building_id=building_id,
            time_range="current",
            anonymized=True,
            aggregation_level="floor"
        )
        print(json.dumps(occupancy, indent=2))

    print("\n" + "=" * 60)
    print("EXAMPLE 3: Get Access Points")
    print("=" * 60)

    access_points = await spaces.get_access_points()
    print(f"Found {len(access_points)} access points")


if __name__ == "__main__":
    import asyncio
    asyncio.run(example_usage())
