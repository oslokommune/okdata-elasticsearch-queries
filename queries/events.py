import os
import json
import requests

from botocore.session import Session
from aws_xray_sdk.core import patch_all, xray_recorder
from dataplatform.awslambda.logging import logging_wrapper, log_add, log_exception
from auth import SimpleAuth

from aws.sign import AwsSignV4

patch_all()

ES_ENDPOINT = os.environ["ES_ENDPOINT"]
ES_REGION = os.environ["ES_REGION"]

ES_HOST = f"{ES_ENDPOINT}.{ES_REGION}.es.amazonaws.com"


def _response(status, data):
    return {
        "isBase64Encoded": False,
        "statusCode": status,
        "body": json.dumps(data),
    }


def _error_response(status, msg):
    return _response(status, {"message": msg})


def _format(bucket):
    return {
        "from": bucket["from_as_string"],
        "to": bucket["to_as_string"],
        "events": bucket["events"]["value"],
    }


@logging_wrapper("elasticsearch-queries")
@xray_recorder.capture("event_stat")
def event_stat(event, context):
    log_add(es_host=ES_HOST)

    dataset_id = event["pathParameters"]["datasetId"]
    log_add(dataset_id=dataset_id)

    is_owner = SimpleAuth().is_owner(event, dataset_id)
    log_add(is_owner=is_owner)

    if not is_owner:
        return _error_response(403, "Forbidden")

    credentials = Session().get_credentials().get_frozen_credentials()
    auth = AwsSignV4(
        access_key=credentials.access_key,
        secret_key=credentials.secret_key,
        token=credentials.token,
        host=ES_HOST,
        region=ES_REGION,
        service="es",
    )

    r = requests.get(
        f"https://{ES_HOST}/_search",
        auth=auth,
        json={
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": "now-7d/d",
                                    "lt": "now",
                                    "time_zone": "Europe/Oslo",
                                }
                            }
                        },
                        {"match": {"service_name": "event-collector"}},
                        {"match": {"dataset_id": dataset_id}},
                    ]
                }
            },
            "aggs": {
                "dataset": {
                    "terms": {"field": "dataset_id.keyword"},
                    "aggs": {
                        "ranges": {
                            "date_range": {
                                "field": "timestamp",
                                "time_zone": "Europe/Oslo",
                                "keyed": True,
                                "ranges": [
                                    {
                                        "key": "week",
                                        "from": "now-6d/d",
                                        "to": "now+1d/d",
                                    },
                                    {
                                        "key": "day",
                                        "from": "now-23h/h",
                                        "to": "now+1h/h",
                                    },
                                    {"key": "hour", "from": "now-1h", "to": "now"},
                                ],
                            },
                            "aggs": {"events": {"sum": {"field": "num_events"}}},
                        }
                    },
                }
            },
        },
    )

    log_add(request_status=r.status_code)

    if r.status_code != 200:
        log_add(request_error=r.text)
        return _error_response(400, "Request failed")

    data = r.json()

    last_hour = {}
    last_day = {}
    last_week = {}

    buckets = data["aggregations"]["dataset"]["buckets"]
    bucket = None
    for b in buckets:
        if b["key"] == dataset_id:
            bucket = b["ranges"]["buckets"]
            break

    if not bucket:
        return _error_response(404, "No events found")

    try:
        last_hour = _format(bucket["hour"])
        last_day = _format(bucket["day"])
        last_week = _format(bucket["week"])
    except KeyError as e:
        log_exception(e)

    return _response(
        200,
        {
            "dataset_id": dataset_id,
            "last_hour": last_hour,
            "last_day": last_day,
            "last_week": last_week,
        },
    )
