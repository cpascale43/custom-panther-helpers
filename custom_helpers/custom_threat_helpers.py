# from panther_oss_helpers import get_dictionary, put_dictionary
# from custom_boto3_helpers import get_papaya_aws_credentials, get_stored_secret
import json
import requests
import boto3
from datetime import datetime, timedelta

# check if a record exists
# if no data, store new data
# if older than 1 day, refresh cache
# return dict from vt, use in detection

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"
# add an API key for testing purposes (get a free one here: https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key)
# eventually, remove this line and use boto3 helpers to fetch secret
VT_API_KEY = "<YOUR-API-KEY>"


def is_within_last_24_hours(timestamp):
    current_time = datetime.utcnow()
    timestamp = datetime.strptime(timestamp, TIMESTAMP_FORMAT)
    time_difference = current_time - timestamp
    return time_difference <= timedelta(hours=24)


# query VT using API key, return as Python dictionary
def query_virustotal_ip_report(ip_address, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key, "Content-Type": "application/json"}

    response = requests.get(url, headers=headers)
    response_json = response.json()

    return response_json


def cache_vt(key, vt_results):
    # timestamp = datetime.strptime(timestamp, TIMESTAMP_FORMAT)
    new_vt_cache = {"time": datetime.utcnow(), "vt_results": vt_results}
    # put_dictionary(key, new_vt_cache)


def vt_search(ip):
    # generate key
    key = "vt-" + str(ip)

    # fetch cache
    # {
    #     time: current_time,
    #     vt_results: {
    #         ...
    #     }
    # }
    # vt_cache = get_dictionary(key)

    vt_cache = {}

    # if cache exists and is from within last 24 hours, use it
    if vt_cache and is_within_last_24_hours(vt_cache.get("time")):
        return vt_cache.get("vt_results")

    # if not, execute another call to VT & refresh cache
    vt_results = query_virustotal_ip_report(ip, VT_API_KEY)
    cache_vt(key, vt_results)

    return vt_results

print(vt_search('54.71.85.177'))