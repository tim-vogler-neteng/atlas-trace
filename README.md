# RIPE Atlas Traceroute Measurement Tool

A Python tool for performing traceroute measurements from geographically diverse RIPE Atlas probes with result polling, analysis, and ISP/regional issue highlighting.

## Features
- **Geographic Diversity**: Automatically selects probes from 14 global regions 
	(US-Northeast, US-Southeast, US-Central, US-West, Canada, Latin America, Western Europe, 
	Eastern Europe, Middle East, Africa, Asia-Pacific, India, AUZ, China)
- **Result Polling**: Built-in retry logic with configurable delays to wait for measurement results
- **Comprehensive Analysis**: 
  - Success rates by region, country, and ASN
  - Timeout tracking and failure analysis
  - Routing anomaly detection (long paths, routing blackholes)
  - ISP-level issue identification
- 🎯 **User-Friendly Output**: Clear, organized results with regional breakdowns and anomaly highlights

## Requirements

- Python 3.8+
- RIPE Atlas API token (get one at https://atlas.ripe.net)

## Installation

Python 3.13+ requires a virtual environment. Create and activate one, then install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

To activate the virtual environment in future sessions:

```bash
source .venv/bin/activate
```

## Setup

Set your RIPE Atlas API token as an environment variable:

```bash
export RIPE_ATLAS_API_TOKEN="your-api-key-here"
```

Or pass it directly with the `-t` flag.

## Usage

### Basic Usage

Trace to a single IP address using 20 diverse probes:

```bash
python atlas_trace.py 8.8.8.8
```

### Advanced Options

```bash
python atlas_trace.py 8.8.8.8 -p 100 -r 60 -d 3
```

Options:
- `-p, --probes N`: Number of probes to use (default: 20)
- `-r, --retries N`: Maximum retry attempts for results (default: 10)
- `-d, --delay N`: Delay between retries in seconds (default: 6)
- `-t, --token TOKEN`: API token (or use `ripe_atlas_api_token` env var)

### Examples

```bash
# Trace to Google DNS with default settings
python atlas_trace.py 8.8.8.8

# Trace to Cloudflare DNS with 100 probes
python atlas_trace.py 1.1.1.1 -p 100

# Trace to IPv6 address with custom retry settings
python atlas_trace.py 2001:4860:4860::8888 -r 60 -d 3

# Use specific API token
python atlas_trace.py 8.8.8.8 -t "your-api-key"
```

## Output

The tool provides a comprehensive report including:

1. **Overall Statistics**
   - Total probes, successful probes, failures
   - Overall success rate

2. **Results by Region**
   - Per-region success rates
   - Issues detected per region (if any)

3. **Failed Probes Analysis** (if applicable)
   - Timeout and error breakdown
   - Failed probes grouped by region and country

## Example Output

```
================================================================================
TRACEROUTE MEASUREMENT RESULTS
================================================================================

Overall Statistics:
  Total Probes:       50
  Successful:         48
  Failed/Timeouts:    2
  Success Rate:       96.0%

================================================================================
RESULTS BY REGION
================================================================================

Europe:
  Probes: 10, Success: 100.0%, Failed: 0
  
North America:
  Probes: 10, Success: 100.0%, Failed: 0
  
Asia-Pacific:
  Probes: 10, Success: 90.0%, Failed: 1
  ⚠️  Issues detected: 2
      - long_path (Probe 12345)
      - routing_asymmetry (Probe 12346)

...
```

## Bonus Features

### Regional Issue Highlighting

Issues are automatically grouped and highlighted by:
- **Region**: See which parts of the world are experiencing problems
- **ISP/ASN**: Identify problematic autonomous systems
- **Country**: Pinpoint specific country-level issues

### Issue Types Tracked

- **Timeouts**: Complete measurement failures
- **Long Paths**: Unusually long traceroute paths (>20 hops)
- **Stars Detected**: Potential routing blackholes or ICMP filtering

## How It Works

1. **Probe Selection**: Queries RIPE Atlas API to select probes balanced across 5 geographic regions
2. **Measurement Creation**: Sends traceroute measurement request to selected probes
3. **Result Polling**: Polls the API with configurable retries until results are available
4. **Analysis**: Processes results to identify issues by region and ISP
5. **Reporting**: Displays comprehensive results with highlights for issues

## Troubleshooting

### "No API token provided"
- Ensure `ripe_atlas_api_token` environment variable is set, or use `-t` flag

### "Measurement created but no results"
- Results can take time to collect from all probes
- Increase retry count with `-r` option
- Increase retry delay with `-d` option

### Authentication errors
- Verify your API token is valid at https://atlas.ripe.net
- Ensure you have API access enabled for your account

## API Documentation

For more information about RIPE Atlas API:
- https://atlas.ripe.net/docs/
- https://atlas.ripe.net/docs/api/v2/


