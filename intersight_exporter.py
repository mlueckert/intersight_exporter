#!/usr/bin/env python3

"""Intersight API Prometheus exporter.

This script will export device metrics of Cisco UCS Blades and Profiles from the Cisco Intersight API.
The format of the exported metrics can be used in Prometheus.
This script is well suited to be called from exporter_exporter.

Last Change: 16.07.2024 M. Lueckert

"""

# Alarms
# https://www.cisco.com/c/en/us/td/docs/unified_computing/Intersight/IMM_Alarms_Guide/b_cisco_intersight_alarms_reference_guide/m_intersight_server_alarms.html

import argparse
import datetime
import logging
from logging.handlers import RotatingFileHandler
import re
import sys
from dateutil import parser
from intersight.api import server_api, compute_api, cond_api, equipment_api, iam_api
import intersight.api
import intersight.api_client
import urllib3


def main(arguments):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--api_key_id", help="API Key ID", required=True)
    parser.add_argument(
        "--api_secret_file",
        help="API Secret File in V2 Key Format",
        required=True,
        default="api_secret_file",
    )
    parser.add_argument(
        "--ignore_ssl",
        help="Ignore self signed certificates in chain.",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--log_fullpath",
        help="Location of logfile. Will be rotated 5MB with 5 backups.",
        default="intersight_exporter.log",
    )
    parser.add_argument(
        "--debug",
        help="Set loglevel to debug. Prints out a lot of json.",
        action="store_true",
    )
    parser.add_argument(
        "--include_acknowledged_alarms",
        help="Include acknowledged alarms",
        action="store_true",
    )
    parser.add_argument(
        "--baseurl",
        help="API URL if not EU",
        default="https://eu-central-1.intersight.com",
    )
    args = parser.parse_args(arguments)

    try:
        baseurl = args.baseurl
        api_key_id = args.api_key_id
        api_secret_file = args.api_secret_file
        include_acknowledged_alarms = args.include_acknowledged_alarms
        log_fullpath = args.log_fullpath
        logformat = "%(asctime)s:%(levelname)s:%(funcName)s:%(message)s"
        handler = RotatingFileHandler(
            filename=log_fullpath, maxBytes=(5242880), backupCount=5, encoding="utf-8"
        )
        logging.basicConfig(handlers=[handler], level=logging.INFO, format=logformat)
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            for myhandler in logging.getLogger().handlers:
                myhandler.setLevel(logging.DEBUG)
        logging.info("Intersight Exporter starting")
        if args.ignore_ssl:
            logging.info("Disable SSL verification")
            urllib3.disable_warnings()
            verify_ssl = False
        else:
            verify_ssl = True

        with open(api_secret_file, "r") as file:
            private_key = file.read()
        regex = re.compile(r"\s*-----BEGIN (.*)-----\s+")
        match = regex.match(private_key)
        if not match:
            raise ValueError("API key file does not have a valid PEM pre boundary")
        pem_header = match.group(1)
        # HTTP signature scheme.
        if pem_header == "RSA PRIVATE KEY":
            signing_scheme = intersight.signing.SCHEME_RSA_SHA256
            signing_algorithm = intersight.signing.ALGORITHM_RSASSA_PKCS1v15
        elif pem_header == "EC PRIVATE KEY":
            signing_scheme = intersight.signing.SCHEME_HS2019
            signing_algorithm = intersight.signing.ALGORITHM_ECDSA_MODE_FIPS_186_3
        else:
            raise Exception("Unsupported key: {0}".format(pem_header))

        configuration = intersight.Configuration(
            host=baseurl,
            signing_info=intersight.HttpSigningConfiguration(
                key_id=api_key_id,
                private_key_path=api_secret_file,
                signing_scheme=signing_scheme,
                signing_algorithm=signing_algorithm,
                hash_algorithm=intersight.signing.HASH_SHA256,
                signed_headers=[
                    intersight.signing.HEADER_REQUEST_TARGET,
                    intersight.signing.HEADER_CREATED,
                    intersight.signing.HEADER_EXPIRES,
                    intersight.signing.HEADER_HOST,
                    intersight.signing.HEADER_DATE,
                    intersight.signing.HEADER_DIGEST,
                ],
                signature_max_validity=datetime.timedelta(minutes=5),
            ),
        )
        configuration.verify_ssl = verify_ssl
        api_client = intersight.ApiClient(configuration)
        chassis_metrics = get_chassis_metrics(api_client)
        api_key_metrics = get_api_key_metrics(api_client)
        server_profile_metrics = get_server_profile_metrics(api_client, [])
        compute_blade_metrics = get_compute_blade_metrics(
            api_client, server_profile_metrics
        )
        all_metrics = (
            server_profile_metrics
            + compute_blade_metrics
            + chassis_metrics
            + api_key_metrics
        )
        alarm_metrics = get_cond_alarm_metrics(
            api_client, include_acknowledged_alarms, all_metrics
        )
        all_metrics += alarm_metrics
        metrics = []
        for metric in all_metrics:
            metrics.append(format_metric(metric[0], metric[1], metric[2]))

        metrics.append("intersight_exporter_status 1")
        print("\n".join(metrics))
        logging.info(
            f"All went fine. {len(metrics)} Prometheus metrics printed to stdout."
        )

    except:
        print("intersight_exporter_status 0")
        logging.exception("An error occured. See error details.")

    logging.info("Intersight Exporter finished")


def get_chassis_metrics(api_client: intersight.api_client) -> list:
    """
    Retrieves and processes chassis metrics to be formatted for Prometheus.

    Args:
    api_client (intersight.ApiClient): The client object for connecting to the Intersight API.

    Returns:
    list: A list of tuples where each tuple contains metric name, associated labels, and their value.
    """
    api_instance = equipment_api.EquipmentApi(api_client)
    response = api_instance.get_equipment_chassis_list()
    metrics_list = []
    for result in response.results:
        hostname = get_value_from_path(result, "name").split("-")[0].upper()
        all_labels_dict = {
            "hostname": hostname,
            "name": get_value_from_path(result, "name"),
            "moid": get_value_from_path(result, "moid"),
        }
        details_labels_dict = {
            "model": get_value_from_path(result, "model"),
            "serial": get_value_from_path(result, "serial"),
        }
        health_metric_dict = {
            "health": get_value_from_path(result, "alarm_summary.health")
        }
        metrics_list.append(
            [
                "ucsx_chassis_health",
                {**health_metric_dict, **all_labels_dict},
                map_string_value_to_int(health_metric_dict["health"]),
            ]
        )
        metrics_list.append(
            [
                "ucsx_chassis_info",
                {**details_labels_dict, **all_labels_dict},
                1,
            ]
        )
    return metrics_list


def get_cond_alarm_metrics(
    api_client: intersight.api_client, include_acknowledged_alarms: bool, metrics: list
) -> list:
    """
    Retrieves and processes conditional alarm metrics to be formatted for Prometheus.

    Args:
    api_client (intersight.ApiClient): The client object for connecting to the Intersight API.
    include_acknowledged_alarms (bool): A flag to determine if acknowledged alarms should be included.
    metrics (list): A pre-existing list of metrics for mapping purposes.

    Returns:
    list: A list of alarm metrics including alarm details and severity mapped to integers.
    """
    query_filter = f"Severity eq Critical"
    if not include_acknowledged_alarms:
        query_filter = query_filter + " and Acknowledge eq None"
    api_instance = cond_api.CondApi(api_client)
    response = api_instance.get_cond_alarm_list(filter=query_filter)
    alarm_metrics_list = []
    for result in response.results:
        hostname = (
            get_value_from_path(result, "affected_mo_display_name")
            .split("/")[0]
            .upper()
        )
        ancestor_mo_id = get_value_from_path(result, "ancestor_mo_id")
        for metric in metrics:
            if metric[1].get("moid") == ancestor_mo_id:
                hostname = metric[1]["hostname"]
                break
        all_labels_dict = {"hostname": hostname}
        details_labels_dict = {
            "code": get_value_from_path(result, "code"),
            "severity": get_value_from_path(result, "severity"),
            "affected_mo_display_name": get_value_from_path(
                result, "affected_mo_display_name"
            ),
            "description": get_value_from_path(result, "description"),
        }
        alarm_metrics_list.append(
            [
                "ucsx_alarms",
                {**details_labels_dict, **all_labels_dict},
                map_string_value_to_int(details_labels_dict["severity"]),
            ]
        )
    return alarm_metrics_list


def parse_date_string(date_string) -> str:
    """
    Parses a date string and converts it to a formatted date-time string.

    Parameters:
    date_string (str): The date string to be parsed.

    Returns:
    str: The formatted date-time string in the format "YYYY-MM-DD HH:MM:SS".
    """
    return parser.parse(date_string, ignoretz=True).strftime("%Y-%m-%d %H:%M:%S")


def get_api_key_metrics(api_client: intersight.api_client) -> list:
    """
    Fetches API key metrics from Intersight and processes the data into a list of metrics.

    Parameters:
    api_client (intersight.api_client): An instance of the Intersight API client.

    Returns:
    List: A list of metrics where each metric is represented as a list containing:
          - A string identifier for the metric.
          - A dictionary of labels and their values.
          - An integer value mapped from the API key's operational status.
    """
    api_instance = iam_api.IamApi(api_client)
    response = api_instance.get_iam_api_key_list()
    metrics_list = []
    for result in response.results:
        all_labels_dict = {
            "purpose": get_value_from_path(result, "purpose"),
            "moid": get_value_from_path(result, "moid"),
            "account_moid": get_value_from_path(result, "account_moid"),
        }
        details_labels_dict = {
            "is_never_expiring": get_value_from_path(result, "is_never_expiring"),
            "start_time": parse_date_string(get_value_from_path(result, "start_time")),
            "expiry_date_time": parse_date_string(get_value_from_path(result, "expiry_date_time")),
        }
        apikeystatus_dict = {
            "api_key_oper_status": get_value_from_path(result, "oper_status"),
        }
        metrics_list.append(
            [
                "ucsx_api_key_oper_status",
                {**apikeystatus_dict, **all_labels_dict},
                map_string_value_to_int(apikeystatus_dict["api_key_oper_status"]),
            ]
        )
        metrics_list.append(
            [
                "ucsx_api_key_remaining_days",
                {**all_labels_dict, **details_labels_dict},
                (
                    parser.parse(details_labels_dict["expiry_date_time"], ignoretz=True)
                    - datetime.datetime.now()
                ).days,
            ]
        )
    return metrics_list


def get_server_profile_metrics(
    api_client: intersight.api_client, metrics_list: list
) -> list:
    """
    Retrieves and processes server profile metrics to be formatted for Prometheus.

    Args:
    api_client (intersight.ApiClient): The client object for connecting to the Intersight API.
    metrics_list (list): A list used to append server profile metrics.

    Returns:
    list: An updated list with server profile metrics included.
    """
    api_instance = server_api.ServerApi(api_client)
    response = api_instance.get_server_profile_list()
    for result in response.results:
        all_labels_dict = {
            "hostname": get_value_from_path(result, "name").upper(),
            "moid": get_value_from_path(result, "moid"),
        }
        details_labels_dict = {
            "assigned_server_moid": get_value_from_path(result, "assigned_server.moid"),
        }
        metrics_list.append(
            ["ucsx_server_profile_info", {**details_labels_dict, **all_labels_dict}, 1]
        )
        deploystatus_dict = {
            "deploy_status": get_value_from_path(result, "deploy_status")
        }
        metrics_list.append(
            [
                "ucsx_server_profile_deploy_status",
                {**details_labels_dict, **all_labels_dict, **deploystatus_dict},
                map_string_value_to_int(deploystatus_dict["deploy_status"]),
            ]
        )
    return metrics_list


def get_compute_blade_metrics(
    api_client: intersight.api_client, profiles_metrics_list
) -> list:
    """
    Retrieves and processes compute blade metrics to be formatted for Prometheus.

    Args:
    api_client (intersight.ApiClient): The client object for connecting to the Intersight API.
    profiles_metrics_list (list): A list containing metrics related to server profiles.

    Returns:
    list: A list of compute blade metrics including hardware health and other details.
    """
    api_instance = compute_api.ComputeApi(api_client)
    response = api_instance.get_compute_blade_list()
    blade_metrics_list = []
    for result in response.results:
        for metric in profiles_metrics_list:
            if metric[1]["assigned_server_moid"] == result["moid"]:
                all_labels_dict = {
                    "hostname": metric[1]["hostname"],
                    "moid": get_value_from_path(result, "moid"),
                }
                details_labels_dict = {
                    "serial": result["serial"],
                    "total_memory": result["total_memory"],
                    "model": result["model"],
                    "num_cpus": result["num_cpus"],
                }
                blade_metrics_list.append(
                    [
                        "ucsx_compute_blade_info",
                        {**details_labels_dict, **all_labels_dict},
                        1,
                    ]
                )
                health_metric_dict = {
                    "health": get_value_from_path(result, "alarm_summary.health")
                }
                blade_metrics_list.append(
                    [
                        "ucsx_compute_blade_health",
                        {**health_metric_dict, **all_labels_dict},
                        map_string_value_to_int(health_metric_dict["health"]),
                    ]
                )
                power_state_metric_dict = {
                    "power_state": get_value_from_path(result, "oper_power_state")
                }
                blade_metrics_list.append(
                    [
                        "ucsx_compute_blade_power_state",
                        {**power_state_metric_dict, **all_labels_dict},
                        map_string_value_to_int(power_state_metric_dict["power_state"]),
                    ]
                )
                break
    return blade_metrics_list


def format_metric(metric_name: str, labeldict: dict, value: str) -> str:
    """Creates a Prometheus metric string.

    Returns a string in Prometheus format with metric, labels and value

    Args:
        metric_name: The metric name.
        labeldic: Dictionary with multiple label:labelvalue pairs.
        value: The value of the metric

    Returns:
        A valid Prometheus metric string
        mist_device_info{hostname="testdevice"} 255
    """
    string_labels = ""
    if labeldict:
        formatted_labels = [f'{x[0].lower()}="{x[1]}"' for x in labeldict.items()]
        string_labels = ", ".join(formatted_labels)
    time_series = f"{metric_name.lower()}{{{string_labels}}} {value}"
    return time_series


def get_value_from_path(dictionary, parts):
    """
    Retrieves a nested value from a dictionary given a 'dotted' access path.

    Args:
    dictionary (dict): The dictionary to retrieve the value from.
    parts (str or list): A dot-delimited string or a list representing the nested access path.

    Returns:
    str: Value retrieved from the dictionary at the specified path, returned as a lowercase string.
    """
    if type(parts) is str:
        parts = parts.split(".")
    try:
        if len(parts) > 1:
            return get_value_from_path(dictionary[parts[0]], parts[1:])
        return str(dictionary[parts[0]]).lower()
    except (KeyError, TypeError):
        return "False"


def map_string_value_to_int(metric_value: str):
    """
    Map string values to bool.

    Some string values from the API needs to be mapped to int because we
    want to use them as values for our metric.

    Args:
        metric_name: String metric value (e.g. connected).

    Returns:
        Mapped int for the value defined
    """
    if metric_value in [
        "healthy",
        "cleared",
        "complete",
        "inprogress",
        "none",
        "on",
        "enabled",
    ]:
        return 0
    elif metric_value in [
        "disconnected",
        "true",
        "warning",
        "notstarted",
        "off",
        "partial",
    ]:
        return 1
    elif metric_value in ["critical", "failed", "disabled", "expired"]:
        return 2
    elif metric_value in ["restarting"]:
        return 3
    else:
        return metric_value


def format_time(dt):
    """
    Formats a datetime object as an ISO-8601 string suitable for use with Intersight API queries.

    Args:
    dt (datetime): A datetime object to format.

    Returns:
    str: Formatted date string in ISO-8601 format with 'Z' time zone designator.
    """
    s = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
    return f"{s[:-3]}Z"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
