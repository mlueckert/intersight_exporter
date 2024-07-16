# Intersight API Prometheus Exporter

This script exports device metrics of Cisco UCS Blades and Profiles from the Cisco Intersight API. The format of the exported metrics is compatible with Prometheus. This script is well suited to be called from `exporter_exporter`.

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Metrics](#metrics)
- [Logging](#logging)
- [Error Handling](#error-handling)
- [Metric Examples](#metric-examples)

## Requirements

- Python 3.x
- `intersight` Python package
- `urllib3` Python package

## Installation

1. Clone the repository or download the script.
2. Install the required Python packages:

   ```sh
   pip install intersight-client urllib3
   ```

## Usage

To run the script, use the following command:

```sh
./intersight_exporter.py --api_key_id YOUR_API_KEY_ID --api_secret_file YOUR_API_SECRET_FILE
```

### Command Line Arguments

- `--api_key_id` (required): API Key ID.
- `--api_secret_file` (required): Path to the API Secret File in V2 Key Format.
- `--ignore_ssl`: Ignore self-signed certificates in the chain. Default is `False`.
- `--log_fullpath`: Location of the logfile. Logs will be rotated at 5MB with 5 backups. Default is `intersight_exporter.log`.
- `--debug`: Set log level to debug. Prints out detailed logs. Default is `False`.
- `--include_acknowledged_alarms`: Include acknowledged alarms in the metrics. Default is `False`.
- `--baseurl`: API URL if not in the EU region. Default is `https://eu-central-1.intersight.com`.

## Configuration

- Ensure you have a valid API Key and Secret File from Cisco Intersight.
- Configure the base URL if you are not using the default EU region.

## Metrics

The script retrieves various metrics from the Cisco Intersight API and formats them for Prometheus. Some of the metrics include:

- Chassis health and information
- Conditional alarms
- Server profile information and deployment status
- Compute blade information and health
- API Key Metrics

The metrics are printed to `stdout` in a format that Prometheus can scrape.

## Logging

- Logs are written to the specified logfile (`intersight_exporter.log` by default).
- Log rotation is configured to rotate at 5MB with up to 5 backups.
- Use the `--debug` flag to enable detailed logging for debugging purposes.

## Error Handling

If an error occurs during execution, the script will log the exception details and print `intersight_exporter_status 0` to `stdout`. On successful execution, it will print `intersight_exporter_status 1`.

## Example

```sh
./intersight_exporter.py --api_key_id my_api_key_id --api_secret_file /path/to/secret_file --debug
```

This command runs the exporter with detailed debug logs, using the provided API key and secret file.

## Metric Examples

```text
ucsx_alarms{code="adapterhostfcinterfacedown", severity="critical", affected_mo_display_name="asdf/chassis-1/server-5/adapter-ucsx-ml-v5d200g_asdf/vsi-a", description="vhba asdf/chassis-1/server-5/adapter-ucsx-ml-v5d200g_asdf/vsi-a is not operational.", hostname="asdf"} 2
ucsx_chassis_info{model="ucsx-9508", serial="asdf", hostname="asdf", name="asdf-1", moid="asdf"} 1
ucsx_chassis_health{health="healthy", hostname="asdf", name="asdf-11", moid="asdf"} 0
ucsx_compute_blade_info{serial="asdf", total_memory="8388608", model="UCSX-410C-M7", num_cpus="4", hostname="asdf", moid="asdf"} 1
ucsx_compute_blade_health{health="healthy", hostname="asdf", moid="asdf"} 0
ucsx_compute_blade_power_state{power_state="on", hostname="asdf", moid="asdf"} 0
ucsx_server_profile_deploy_status{assigned_server_moid="False", hostname="asdf", moid="asdf", deploy_status="none"} 0
ucsx_server_profile_info{assigned_server_moid="False", hostname="asdf", moid="asdf"} 1
ucsx_api_key_oper_status{api_key_oper_status="enabled", purpose="monitoring", moid="asdf", account_moid="asdf"} 0
ucsx_api_key_remaining_days{purpose="monitoring", moid="asdf", account_moid="asdf", is_never_expiring="false", start_time="2024-05-15 09:20:12", expiry_date_time="2024-11-05 10:29:00+00:00"} 111
intersight_exporter_status 1
```

## Author

- Last Change: 22.05.2024 by M. Lueckert
