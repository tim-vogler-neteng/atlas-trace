#!/usr/bin/env python3
"""
RIPE Atlas Traceroute Measurement Tool

Performs traceroute measurements from geographically diverse probes to a target IP,
with result polling and ISP/regional issue analysis.
"""

import os
import sys
import time
import random
import requests
import argparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass



@dataclass
class RegionGroup:
    """Geographic region grouping"""
    name: str
    countries: List[str]
    probe_count: int = 0
    # Optional bounding box (lat_min, lat_max, lon_min, lon_max) for sub-country filtering
    bounds: Optional[Tuple[float, float, float, float]] = None


class RIPEAtlasTracer:
    """RIPE Atlas traceroute measurement client"""
    
    API_BASE_URL = "https://atlas.ripe.net/api/v2"
    REGIONS = [
        # North America sub-regions (bounds = lat_min, lat_max, lon_min, lon_max)
        RegionGroup("US-Northeast",  ["US"], bounds=(37.0, 49.0, -88.0,  -67.0)),
        RegionGroup("US-Southeast",  ["US"], bounds=(24.0, 37.0, -95.0,  -75.0)),
        RegionGroup("US-Central",    ["US"], bounds=(26.0, 49.0, -104.0, -88.0)),
        RegionGroup("US-West",       ["US"], bounds=(32.0, 49.0, -125.0, -104.0)),
        RegionGroup("Canada",        ["CA"]),
        # Latin America
        RegionGroup("Latin America",   ["MX", "BR", "AR", "CL", "CO", "PE", "VE", "EC", "UY", "BO"]),
        # Europe split
        RegionGroup("Western Europe",  ["GB", "IE", "FR", "DE", "NL", "BE", "AT", "CH", "IT", "ES", "PT", "SE", "NO", "DK", "FI"]),
        RegionGroup("Eastern Europe",  ["PL", "CZ", "SK", "HU", "RO", "BG", "UA", "RS", "HR", "SI", "BY", "LT", "LV", "EE", "RU"]),
        # Middle East (separate from Africa)
        RegionGroup("Middle East",     ["AE", "SA", "IL", "JO", "KW", "QA", "BH", "OM", "IQ", "LB", "TR", "IR"]),
        # Africa
        RegionGroup("Africa",          ["ZA", "NG", "EG", "KE", "MA", "GH", "TZ", "ET"]),
        # Asia-Pacific
        RegionGroup("Asia-Pacific",    ["JP", "SG", "KR", "TW", "HK", "ID", "TH", "MY", "PH", "VN"]),
        # India
        RegionGroup("India",           ["IN"]),
        #AUZ - Australia and New Zealand
        RegionGroup("AUZ",             ["AU", "NZ"]),
        #China 
        RegionGroup("China",           ["CN"]),
    ]
    
    def __init__(self, api_token: Optional[str] = None):
        """Initialize the RIPE Atlas tracer
        
        Args:
            api_token: RIPE Atlas API token (or None to use env var)
        """
        self.api_token = api_token or os.getenv("RIPE_ATLAS_API_TOKEN")
        if not self.api_token:
            raise ValueError("No API token provided and RIPE_ATLAS_API_TOKEN env var not set")
        
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})
    
    def _lookup_asns(self, results: List[Dict]) -> Dict[str, str]:
        """Look up ASNs for all unique hop IPs via RIPE Stat API.

        Returns:
            Dict mapping IP -> "AS<num>" (or "" if not found)
        """
        # Collect all unique non-* IPs across all hops
        unique_ips = set()
        for result in results:
            for hop in result.get("result", []):
                for pkt in hop.get("result", []):
                    ip = pkt.get("from")
                    if ip and ip != "*":
                        unique_ips.add(ip)

        print(f"Looking up ASNs for {len(unique_ips)} unique IPs...")
        asn_map: Dict[str, str] = {}

        def _fetch(ip: str) -> tuple:
            try:
                url = "https://stat.ripe.net/data/network-info/data.json"
                resp = self.session.get(url, params={"resource": ip}, timeout=5)
                resp.raise_for_status()
                data = resp.json().get("data", {})
                asns = data.get("asns") or []
                return ip, f"AS{asns[0]}" if asns else ""
            except Exception:
                return ip, ""

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(_fetch, ip): ip for ip in unique_ips}
            for future in as_completed(futures):
                ip, asn = future.result()
                asn_map[ip] = asn

        return asn_map

    def _get_region_for_country(self, country_code: str) -> str:
        """Get region name for a country code"""
        for region in self.REGIONS:
            if country_code in region.countries:
                return region.name
        return "Other"
    
    def _fetch_probe_pool(self, params: Dict) -> List[Dict]:
        """Fetch a pool of probes from the RIPE Atlas API."""
        url = f"{self.API_BASE_URL}/probes/"
        params = {**params, "status": 1, "limit": 2000, "format": "json"}
        response = self.session.get(url, params=params, timeout=10)
        response.raise_for_status()
        return response.json().get("results", [])

    def _probe_in_bounds(self, p: Dict, bounds: Tuple[float, float, float, float]) -> bool:
        coords = (p.get("geometry") or {}).get("coordinates")
        if not coords or len(coords) < 2:
            return False
        lon, lat = coords[0], coords[1]
        lat_min, lat_max, lon_min, lon_max = bounds
        return lat_min <= lat <= lat_max and lon_min <= lon <= lon_max

    def get_probes_by_asn(self, asn: int, count: int) -> Tuple[List[int], Dict[int, str]]:
        """Get probes from a specific ASN.

        Args:
            asn: Autonomous System Number
            count: Number of probes to select

        Returns:
            Tuple of (list of probe IDs, dict mapping probe_id -> region name)
        """
        print(f"Selecting {count} probes from AS{asn}...")
        try:
            pool = self._fetch_probe_pool({"asn_v4": asn})
            probes = random.sample(pool, min(count, len(pool)))
            label = f"AS{asn}"
            probe_region_map = {p["id"]: label for p in probes}
            print(f"  {label}: selected {len(probes)} probes")
            print(f"Total probes selected: {len(probes)}\n")
            return [p["id"] for p in probes], probe_region_map
        except Exception as e:
            print(f"  Warning: Failed to fetch probes for AS{asn}: {e}")
            return [], {}

    def get_probes_by_country(self, country_code: str, count: int) -> Tuple[List[int], Dict[int, str]]:
        """Get probes from a specific country.

        Args:
            country_code: ISO 3166-1 alpha-2 country code (e.g. 'US', 'DE')
            count: Number of probes to select

        Returns:
            Tuple of (list of probe IDs, dict mapping probe_id -> region name)
        """
        code = country_code.upper()
        print(f"Selecting {count} probes from {code}...")
        try:
            pool = self._fetch_probe_pool({"country_code": code})
            probes = random.sample(pool, min(count, len(pool)))
            region = self._get_region_for_country(code)
            probe_region_map = {p["id"]: region for p in probes}
            print(f"  {code}: selected {len(probes)} probes")
            print(f"Total probes selected: {len(probes)}\n")
            return [p["id"] for p in probes], probe_region_map
        except Exception as e:
            print(f"  Warning: Failed to fetch probes for {code}: {e}")
            return [], {}

    def get_probes_by_region(self, region_name: str, count: int) -> Tuple[List[int], Dict[int, str]]:
        """Get probes from a specific named region.

        Args:
            region_name: Region name matching one of REGIONS (case-insensitive)
            count: Number of probes to select

        Returns:
            Tuple of (list of probe IDs, dict mapping probe_id -> region name)
        """
        region = next(
            (r for r in self.REGIONS if r.name.lower() == region_name.lower()), None
        )
        if region is None:
            names = ", ".join(r.name for r in self.REGIONS)
            raise ValueError(f"Unknown region '{region_name}'. Valid regions: {names}")

        print(f"Selecting {count} probes from {region.name}...")
        try:
            pool = self._fetch_probe_pool({"country_code__in": ",".join(region.countries)})
            if region.bounds is not None:
                pool = [p for p in pool if self._probe_in_bounds(p, region.bounds)]
            probes = random.sample(pool, min(count, len(pool)))
            probe_region_map = {p["id"]: region.name for p in probes}
            print(f"  {region.name}: selected {len(probes)} probes")
            print(f"Total probes selected: {len(probes)}\n")
            return [p["id"] for p in probes], probe_region_map
        except Exception as e:
            print(f"  Warning: Failed to fetch probes for {region.name}: {e}")
            return [], {}

    def get_diverse_probes(self, count: int = 20) -> Tuple[List[int], Dict[int, str]]:
        """Get geographically diverse probes across all regions.

        Args:
            count: Target number of probes

        Returns:
            Tuple of (list of probe IDs, dict mapping probe_id -> region name)
        """
        print(f"Selecting {count} geographically diverse probes...")

        # Distribute probes across regions: at least 1 each, then spread remainder round-robin
        base = max(1, count // len(self.REGIONS))
        remainder = max(0, count - base * len(self.REGIONS))
        region_targets = {region.name: base for region in self.REGIONS}
        for region in self.REGIONS[:remainder]:
            region_targets[region.name] += 1

        all_probes = []
        probe_region_map: Dict[int, str] = {}
        success_count = 0

        # Pre-fetch a large probe pool per unique country set (avoids re-fetching for US sub-regions)
        country_pool: Dict[str, list] = {}
        for region in self.REGIONS:
            key = ",".join(sorted(region.countries))
            if key not in country_pool:
                try:
                    country_pool[key] = self._fetch_probe_pool({"country_code__in": ",".join(region.countries)})
                except Exception as e:
                    print(f"  Warning: Failed to fetch probes for {region.countries}: {e}")
                    country_pool[key] = []

        # Get probes from each region
        for region in self.REGIONS:
            target_count = region_targets[region.name]
            key = ",".join(sorted(region.countries))
            pool = country_pool.get(key, [])

            if region.bounds is not None:
                pool = [p for p in pool if self._probe_in_bounds(p, region.bounds)]

            probes = random.sample(pool, min(target_count, len(pool)))
            for p in probes:
                all_probes.append(p["id"])
                probe_region_map[p["id"]] = region.name
            success_count += len(probes)
            print(f"  {region.name}: selected {len(probes)} probes")

        print(f"Total probes selected: {success_count}\n")
        return all_probes, probe_region_map
    
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
                    "description": f"Traceroute to {target_ip}",
                    "af": address_family,
                    "is_oneoff": True,
                }
            ],
            "probes": [
                {
                    "type": "probes",
                    "value": ",".join(map(str, probe_ids)),
                    "requested": len(probe_ids),
                }
            ],
        }
        
        try:
            url = f"{self.API_BASE_URL}/measurements/"
            headers = {"Authorization": f"Key {self.api_token}"}
            response = self.session.post(url, json=measurement_data, headers=headers, timeout=5)
            response.raise_for_status()
            
            measurement_id = response.json()["measurements"][0]
            print(f"Measurement created: ID {measurement_id}\n")
            return measurement_id
            
        except requests.exceptions.RequestException as e:
            print(f"Error creating measurement: {e}")
            if hasattr(e.response, 'text'):
                print(f"Response: {e.response.text}")
            sys.exit(1)
    
    def get_measurement_results(self, measurement_id: int, expected_count: int,
                                max_retries: int = 10, retry_delay: int = 6) -> Dict:
        """Get measurement results with retry logic

        Args:
            measurement_id: Measurement ID
            expected_count: Number of probe results to wait for
            max_retries: Maximum number of retries
            retry_delay: Delay between retries in seconds

        Returns:
            Results dictionary
        """
        print(f"Polling for results (expecting {expected_count}, max {max_retries * retry_delay} seconds)...\n")

        last_results = []
        for attempt in range(max_retries):
            try:
                url = f"{self.API_BASE_URL}/measurements/{measurement_id}/results/"
                response = self.session.get(url, timeout=5)
                response.raise_for_status()

                last_results = response.json()
                result_count = len(last_results)

                if result_count >= expected_count:
                    print(f"Retrieved {result_count} results\n")
                    return last_results

                elapsed = (attempt + 1) * retry_delay
                remaining = (max_retries - attempt - 1) * retry_delay
                print(f"[{elapsed}s] {result_count}/{expected_count} results so far ({attempt + 1}/{max_retries}). "
                      f"Retrying in {retry_delay}s (max {remaining}s remaining)...",
                      end="\r")
                time.sleep(retry_delay)

            except requests.exceptions.RequestException as e:
                print(f"Error fetching results: {e}")
                sys.exit(1)

        print(f"\nTimeout: returning {len(last_results)}/{expected_count} results after {max_retries * retry_delay} seconds")
        return last_results
    
    def analyze_results(self, results: List[Dict], probe_region_map: Dict[int, str]) -> Dict:
        """Analyze traceroute results

        Args:
            results: List of measurement results
            probe_region_map: Mapping of probe_id -> region name from get_diverse_probes

        Returns:
            Analysis dictionary
        """
        analysis = {
            "total_probes": len(results),
            "successful_probes": 0,
            "failed_probes": 0,
            "by_region": defaultdict(lambda: {"total": 0, "failed": 0}),
            "timeouts": [],
        }

        for result in results:
            probe_id = result.get("prb_id")
            region = probe_region_map.get(probe_id, "Other")
            result_data = result.get("result", [])
            dst_addr = result.get("dst_addr")

            analysis["by_region"][region]["total"] += 1

            reached = dst_addr and any(
                pkt.get("from") == dst_addr
                for hop in result_data
                for pkt in hop.get("result", [])
            )

            if not result_data or not reached:
                analysis["failed_probes"] += 1
                analysis["by_region"][region]["failed"] += 1
                analysis["timeouts"].append({"probe_id": probe_id, "region": region})
            else:
                analysis["successful_probes"] += 1

        return analysis
    
    def print_results(self, results: List[Dict], analysis: Dict, probe_region_map: Dict[int, str]):
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
        for region in self.REGIONS:
            data = analysis["by_region"].get(region.name)
            if data and data["total"] > 0:
                region_success = ((data["total"] - data["failed"]) / data["total"] * 100)
                print(f"\n{region.name}:")
                print(f"  Probes: {data['total']}, Success: {region_success:.1f}%, Failed: {data['failed']}")

        if analysis["timeouts"]:
            print(f"\n" + "=" * 80)
            print("FAILED PROBES (Timeouts/Errors)")
            print("=" * 80)
            print(f"\nTotal: {len(analysis['timeouts'])}")
            by_region: Dict[str, list] = defaultdict(list)
            for timeout in analysis["timeouts"]:
                by_region[timeout["region"]].append(timeout)
            for region, timeouts in sorted(by_region.items()):
                print(f"  {region}: {len(timeouts)} probe(s)")
        
        asn_map = self._lookup_asns(results)

        print(f"\n" + "=" * 80)
        print("TRACEROUTE HOPS BY PROBE")
        print("=" * 80)
        for result in results:
            probe_id = result.get("prb_id", "?")
            src = result.get("from", "unknown")
            region = probe_region_map.get(probe_id, "Other")
            hops = result.get("result", [])
            dst_addr = result.get("dst_addr")
            reached = dst_addr and any(
                pkt.get("from") == dst_addr
                for hop in hops
                for pkt in hop.get("result", [])
            )
            status = "" if reached else "  [INCOMPLETE]"
            print(f"\nProbe {probe_id} [{region}] (src: {src}){status}")
            if not hops:
                print("  (no results)")
                continue
            for hop in hops:
                hop_num = hop.get("hop", "?")
                packets = hop.get("result", [])
                addrs = []
                rtts = []
                for pkt in packets:
                    if "x" in pkt:
                        addrs.append("*")
                        rtts.append("*")
                    else:
                        addrs.append(pkt.get("from", "*"))
                        rtt = pkt.get("rtt")
                        rtts.append(f"{rtt:.3f} ms" if rtt is not None else "*")
                addr = addrs[0] if addrs else "*"
                asn = asn_map.get(addr, "") if addr != "*" else ""
                rtt_str = "  ".join(rtts)
                asn_col = f"  {asn:<12}" if asn else ""
                print(f"  {hop_num:>3}.  {addr:<40}{asn_col}  {rtt_str}")
        print(f"\n" + "=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description="RIPE Atlas traceroute measurement tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8                          # Diverse probes to Google DNS
  %(prog)s -p 30 1.1.1.1                    # 30 diverse probes to Cloudflare
  %(prog)s --region US-Southeast 8.8.8.8    # Probes only from US-Southeast
  %(prog)s --country DE 8.8.8.8             # Probes only from Germany
  %(prog)s --asn 15169 8.8.8.8              # Probes only from AS15169 (Google)
  %(prog)s 2001:4860:4860::8888             # IPv6 address (auto-detected)
        """
    )
    parser.add_argument("target", help="Target IP address (IPv4 or IPv6)")
    parser.add_argument("-p", "--probes", type=int, default=20,
                       help="Number of probes to use (default: 20)")
    parser.add_argument("-r", "--retries", type=int, default=10,
                       help="Max retry attempts for results (default: 10)")
    parser.add_argument("-d", "--delay", type=int, default=6,
                       help="Delay between retries in seconds (default: 6)")
    parser.add_argument("-t", "--token", help="API token (or use RIPE_ATLAS_API_TOKEN env var)")
    parser.add_argument("--region", help="Restrict probes to a specific region (e.g. 'US-Southeast')")
    parser.add_argument("--asn", type=int, help="Restrict probes to a specific ASN (e.g. 15169)")
    parser.add_argument("--country", help="Restrict probes to a specific country code (e.g. 'DE')")

    args = parser.parse_args()

    try:
        # Detect address family
        address_family = 6 if ":" in args.target else 4

        # Initialize tracer
        tracer = RIPEAtlasTracer(api_token=args.token)

        # Get probes and create measurement
        if args.asn:
            probes, probe_region_map = tracer.get_probes_by_asn(args.asn, count=args.probes)
        elif args.region:
            probes, probe_region_map = tracer.get_probes_by_region(args.region, count=args.probes)
        elif args.country:
            probes, probe_region_map = tracer.get_probes_by_country(args.country, count=args.probes)
        else:
            probes, probe_region_map = tracer.get_diverse_probes(count=args.probes)
        if not probes:
            print("Error: Could not select any probes")
            sys.exit(1)

        measurement_id = tracer.create_measurement(args.target, probes, address_family)

        # Wait for probes to run before polling
        print("Waiting 20s for probes to complete before polling...")
        time.sleep(20)

        # Poll for results
        results = tracer.get_measurement_results(
            measurement_id,
            expected_count=len(probes),
            max_retries=args.retries,
            retry_delay=args.delay
        )
        
        # Analyze and display results
        analysis = tracer.analyze_results(results, probe_region_map)
        tracer.print_results(results, analysis, probe_region_map)
        
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
