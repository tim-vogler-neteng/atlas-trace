#!/usr/bin/env python3
"""
RIPE Atlas Traceroute Measurement Tool

Performs traceroute measurements from geographically diverse probes to a target IP,
with result polling and ISP/regional issue analysis.
"""

import os
import sys
import time
import json
import requests
import argparse
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ProbeInfo:
    """Information about a probe"""
    probe_id: int
    country: str
    asn: int
    isp: str
    latitude: float
    longitude: float


@dataclass
class RegionGroup:
    """Geographic region grouping"""
    name: str
    countries: List[str]
    probe_count: int = 0


class RIPEAtlasTracer:
    """RIPE Atlas traceroute measurement client"""
    
    API_BASE_URL = "https://atlas.ripe.net/api/v2"
    REGIONS = [
        RegionGroup("Europe", ["NL", "DE", "FR", "GB", "IT", "SE", "CH", "AT", "PL", "RU"]),
        RegionGroup("North America", ["US", "CA", "MX"]),
        RegionGroup("South America", ["BR", "AR", "CL", "CO"]),
        RegionGroup("Asia-Pacific", ["JP", "CN", "IN", "AU", "SG", "KR", "TW", "NZ"]),
        RegionGroup("Middle East & Africa", ["AE", "SA", "ZA", "NG", "EG", "IL"]),
    ]
    
    def __init__(self, api_token: Optional[str] = None):
        """Initialize the RIPE Atlas tracer
        
        Args:
            api_token: RIPE Atlas API token (or None to use env var)
        """
        self.api_token = api_token or os.getenv("ripe_atlas_api_token")
        if not self.api_token:
            raise ValueError("No API token provided and RIPE_ATLAS_API_TOKEN env var not set")
        
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})
    
    def _get_region_for_country(self, country_code: str) -> str:
        """Get region name for a country code"""
        for region in self.REGIONS:
            if country_code in region.countries:
                return region.name
        return "Other"
    
    def get_diverse_probes(self, target_ip: str, count: int = 50) -> List[int]:
        """Get geographically diverse probes
        
        Args:
            target_ip: Target IP address
            count: Target number of probes
            
        Returns:
            List of probe IDs
        """
        print(f"Selecting {count} geographically diverse probes...")
        
        # Initialize region probe counts
        region_targets = {region.name: count // len(self.REGIONS) for region in self.REGIONS}
        
        all_probes = []
        success_count = 0
        
        # Get probes from each region
        for region in self.REGIONS:
            target_count = region_targets[region.name]
            filters = {
                "country": region.countries,
                "status": 1,  # Connected
                "tags": {"include": ["WifiTag"]},  # Prefer WiFi for diverse ISPs
            }
            
            try:
                url = f"{self.API_BASE_URL}/probes/"
                params = {
                    "limit": target_count * 2,  # Request more to account for filtering
                    "format": "json",
                }
                # Add filters to params
                for key, value in filters.items():
                    if isinstance(value, list):
                        params[f"country_code"] = ",".join(value) if key == "country" else None
                    elif isinstance(value, int):
                        params[key] = value
                
                response = self.session.get(url, params=params, timeout=10)
                response.raise_for_status()
                
                probes = response.json().get("results", [])[:target_count]
                all_probes.extend([p["id"] for p in probes])
                success_count += len(probes)
                print(f"  {region.name}: selected {len(probes)} probes")
                
            except Exception as e:
                print(f"  Warning: Failed to get probes for {region.name}: {e}")
        
        print(f"Total probes selected: {success_count}\n")
        return all_probes[:count]
    
    def create_measurement(self, target_ip: str, probe_ids: List[int], 
                          address_family: int = 4) -> int:
        """Create a traceroute measurement
        
        Args:
            target_ip: Target IP address
            probe_ids: List of probe IDs
            address_family: 4 for IPv4, 6 for IPv6
            
        Returns:
            Measurement ID
        """
        print(f"Creating traceroute measurement to {target_ip}...")
        
        measurement_data = {
            "definitions": [
                {
                    "type": "traceroute",
                    "target": target_ip,
                    "address_family": address_family,
                    "protocol": "ICMP",
                    "timeout": 4000,
                    "paris": 1,
                }
            ],
            "probes": [
                {
                    "type": "probes",
                    "value": ",".join(map(str, probe_ids)),
                }
            ],
        }
        
        try:
            url = f"{self.API_BASE_URL}/measurements/"
            headers = {"Authorization": f"Key {self.api_token}"}
            response = self.session.post(url, json=measurement_data, headers=headers, timeout=10)
            response.raise_for_status()
            
            measurement_id = response.json()["measurements"][0]
            print(f"Measurement created: ID {measurement_id}\n")
            return measurement_id
            
        except requests.exceptions.RequestException as e:
            print(f"Error creating measurement: {e}")
            if hasattr(e.response, 'text'):
                print(f"Response: {e.response.text}")
            sys.exit(1)
    
    def get_measurement_results(self, measurement_id: int, max_retries: int = 30, 
                                retry_delay: int = 5) -> Dict:
        """Get measurement results with retry logic
        
        Args:
            measurement_id: Measurement ID
            max_retries: Maximum number of retries
            retry_delay: Delay between retries in seconds
            
        Returns:
            Results dictionary
        """
        print(f"Polling for results (max {max_retries * retry_delay} seconds)...\n")
        
        for attempt in range(max_retries):
            try:
                url = f"{self.API_BASE_URL}/measurements/{measurement_id}/results/"
                response = self.session.get(url, timeout=10)
                response.raise_for_status()
                
                results = response.json()
                result_count = len(results)
                
                if result_count > 0:
                    print(f"Retrieved {result_count} results\n")
                    return results
                
                elapsed = (attempt + 1) * retry_delay
                remaining = (max_retries - attempt - 1) * retry_delay
                print(f"[{elapsed}s] No results yet ({attempt + 1}/{max_retries}). "
                      f"Retrying in {retry_delay}s (max {remaining}s remaining)...", 
                      end="\r")
                time.sleep(retry_delay)
                
            except requests.exceptions.RequestException as e:
                print(f"Error fetching results: {e}")
                sys.exit(1)
        
        print(f"\nTimeout: Could not retrieve results after {max_retries * retry_delay} seconds")
        return []
    
    def analyze_results(self, results: List[Dict]) -> Dict:
        """Analyze traceroute results for issues
        
        Args:
            results: List of measurement results
            
        Returns:
            Analysis dictionary
        """
        analysis = {
            "total_probes": len(results),
            "successful_probes": 0,
            "failed_probes": 0,
            "by_region": defaultdict(lambda: {"total": 0, "failed": 0, "issues": []}),
            "by_asn": defaultdict(lambda: {"total": 0, "failed": 0, "issues": []}),
            "by_country": defaultdict(lambda: {"total": 0, "failed": 0, "issues": []}),
            "timeouts": [],
            "routing_anomalies": [],
        }
        
        for result in results:
            probe_id = result.get("prb_id")
            country = result.get("from", {}).get("country_code", "XX")
            region = self._get_region_for_country(country)
            asn = result.get("from", {}).get("asn", -1)
            result_data = result.get("result", [])
            
            # Track by region, country, ASN
            analysis["by_region"][region]["total"] += 1
            analysis["by_country"][country]["total"] += 1
            if asn > 0:
                analysis["by_asn"][asn]["total"] += 1
            
            # Check for issues
            if not result_data:
                analysis["failed_probes"] += 1
                analysis["by_region"][region]["failed"] += 1
                analysis["by_country"][country]["failed"] += 1
                if asn > 0:
                    analysis["by_asn"][asn]["failed"] += 1
                analysis["timeouts"].append({
                    "probe_id": probe_id,
                    "country": country,
                    "region": region,
                    "asn": asn,
                })
            else:
                analysis["successful_probes"] += 1
                
                # Check for routing anomalies (long paths, stars, etc.)
                hop_count = len(result_data)
                has_stars = any("*" in str(hop.get("result", [])) for hop in result_data)
                
                if hop_count > 20:
                    anomaly = {
                        "probe_id": probe_id,
                        "type": "long_path",
                        "hops": hop_count,
                        "country": country,
                        "region": region,
                        "asn": asn,
                    }
                    analysis["routing_anomalies"].append(anomaly)
                    analysis["by_region"][region]["issues"].append(anomaly)
                
                if has_stars:
                    anomaly = {
                        "probe_id": probe_id,
                        "type": "stars_detected",
                        "country": country,
                        "region": region,
                        "asn": asn,
                    }
                    analysis["routing_anomalies"].append(anomaly)
                    analysis["by_region"][region]["issues"].append(anomaly)
        
        return analysis
    
    def print_results(self, results: List[Dict], analysis: Dict):
        """Print formatted results
        
        Args:
            results: List of measurement results
            analysis: Analysis dictionary
        """
        success_rate = (analysis["successful_probes"] / analysis["total_probes"] * 100 
                       if analysis["total_probes"] > 0 else 0)
        
        print("=" * 80)
        print("TRACEROUTE MEASUREMENT RESULTS")
        print("=" * 80)
        print(f"\nOverall Statistics:")
        print(f"  Total Probes:       {analysis['total_probes']}")
        print(f"  Successful:         {analysis['successful_probes']}")
        print(f"  Failed/Timeouts:    {analysis['failed_probes']}")
        print(f"  Success Rate:       {success_rate:.1f}%")
        
        print(f"\n" + "=" * 80)
        print("RESULTS BY REGION")
        print("=" * 80)
        for region in [r.name for r in self.REGIONS]:
            if region in analysis["by_region"]:
                data = analysis["by_region"][region]
                if data["total"] > 0:
                    region_success = ((data["total"] - data["failed"]) / data["total"] * 100)
                    print(f"\n{region}:")
                    print(f"  Probes: {data['total']}, Success: {region_success:.1f}%, Failed: {data['failed']}")
                    if data["issues"]:
                        print(f"  ⚠️  Issues detected: {len(data['issues'])}")
                        for issue in data["issues"][:3]:  # Show top 3
                            print(f"      - {issue['type']} (Probe {issue['probe_id']})")
        
        if analysis["timeouts"]:
            print(f"\n" + "=" * 80)
            print("FAILED PROBES (Timeouts/Errors)")
            print("=" * 80)
            print(f"\nTotal: {len(analysis['timeouts'])}")
            
            # Group by region
            by_region = defaultdict(list)
            for timeout in analysis["timeouts"]:
                by_region[timeout["region"]].append(timeout)
            
            for region, timeouts in sorted(by_region.items()):
                print(f"  {region}: {len(timeouts)} probes")
                countries = defaultdict(int)
                for t in timeouts:
                    countries[t["country"]] += 1
                for country, count in sorted(countries.items(), key=lambda x: -x[1])[:3]:
                    print(f"    - {country}: {count}")
        
        if analysis["routing_anomalies"]:
            print(f"\n" + "=" * 80)
            print("ROUTING ANOMALIES")
            print("=" * 80)
            print(f"\nTotal: {len(analysis['routing_anomalies'])}")
            
            # Group by type
            by_type = defaultdict(list)
            for anomaly in analysis["routing_anomalies"]:
                by_type[anomaly["type"]].append(anomaly)
            
            for anomaly_type, anomalies in by_type.items():
                print(f"\n  {anomaly_type.upper()}: {len(anomalies)} instances")
                # Group by region
                by_region = defaultdict(list)
                for a in anomalies:
                    by_region[a["region"]].append(a)
                
                for region, items in sorted(by_region.items()):
                    print(f"    {region}: {len(items)}")
        
        print(f"\n" + "=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description="RIPE Atlas traceroute measurement tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8              # Trace to Google DNS
  %(prog)s -p 100 1.1.1.1       # Use 100 probes for Cloudflare DNS
  %(prog)s 2001:4860:4860::8888 # IPv6 address (auto-detected)
        """
    )
    parser.add_argument("target", help="Target IP address (IPv4 or IPv6)")
    parser.add_argument("-p", "--probes", type=int, default=50,
                       help="Number of probes to use (default: 50)")
    parser.add_argument("-r", "--retries", type=int, default=30,
                       help="Max retry attempts for results (default: 30)")
    parser.add_argument("-d", "--delay", type=int, default=5,
                       help="Delay between retries in seconds (default: 5)")
    parser.add_argument("-t", "--token", help="API token (or use RIPE_ATLAS_API_TOKEN env var)")
    
    args = parser.parse_args()
    
    try:
        # Detect address family
        address_family = 6 if ":" in args.target else 4
        
        # Initialize tracer
        tracer = RIPEAtlasTracer(api_token=args.token)
        
        # Get probes and create measurement
        probes = tracer.get_diverse_probes(args.target, count=args.probes)
        if not probes:
            print("Error: Could not select any probes")
            sys.exit(1)
        
        measurement_id = tracer.create_measurement(args.target, probes, address_family)
        
        # Poll for results
        results = tracer.get_measurement_results(
            measurement_id, 
            max_retries=args.retries,
            retry_delay=args.delay
        )
        
        # Analyze and display results
        analysis = tracer.analyze_results(results)
        tracer.print_results(results, analysis)
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
