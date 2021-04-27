import re

import pytest

from okdata.resource_auth import ResourceAuthorizer

from queries.events import event_stat, _error_response, _response


access_token = "abc1234"
access_token_unauthorized = "def5678"
dataset_id = "some-events"


def es_search_response(dataset_id, ranges):
    return {
        "aggregations": {
            "dataset": {
                "buckets": [
                    {
                        "key": dataset_id,
                        "ranges": {"buckets": ranges},
                    }
                ]
            }
        }
    }


@pytest.fixture(autouse=True)
def authorizer(monkeypatch):
    def check_token(self, token, scope, resource_name):
        return (
            token == access_token
            and scope == "okdata:dataset:read"
            and resource_name == f"okdata:dataset:{dataset_id}"
        )

    monkeypatch.setattr(ResourceAuthorizer, "has_access", check_token)


@pytest.fixture
def api_gateway_event():
    def _event(
        authorization_header=access_token,
        body={},
    ):
        return {
            "body": body,
            "httpMethod": "GET",
            "queryStringParameters": {},
            "pathParameters": {"datasetId": dataset_id},
            "headers": {"Authorization": authorization_header},
            "requestContext": {},
        }

    return _event


def test_event_stat(requests_mock, api_gateway_event):
    requests_mock.register_uri(
        "GET",
        re.compile("/_search"),
        json=es_search_response(
            dataset_id,
            {
                "hour": {
                    "from_as_string": "2021-04-27T13:33:45.167+02:00",
                    "to_as_string": "2021-04-27T14:33:45.167+02:00",
                    "events": {"value": 0.0},
                },
                "day": {
                    "from_as_string": "2021-04-26T15:00:00.000+02:00",
                    "to_as_string": "2021-04-27T15:00:00.000+02:00",
                    "events": {"value": 1.0},
                },
                "week": {
                    "from_as_string": "2021-04-21T00:00:00.000+02:00",
                    "to_as_string": "2021-04-28T00:00:00.000+02:00",
                    "events": {"value": 9.0},
                },
            },
        ),
    )

    response = event_stat(api_gateway_event(), None)
    assert response == _response(
        200,
        {
            "dataset_id": dataset_id,
            "last_hour": {
                "from": "2021-04-27T13:33:45.167+02:00",
                "to": "2021-04-27T14:33:45.167+02:00",
                "events": 0.0,
            },
            "last_day": {
                "from": "2021-04-26T15:00:00.000+02:00",
                "to": "2021-04-27T15:00:00.000+02:00",
                "events": 1.0,
            },
            "last_week": {
                "from": "2021-04-21T00:00:00.000+02:00",
                "to": "2021-04-28T00:00:00.000+02:00",
                "events": 9.0,
            },
        },
    )


def test_event_stat_no_events(requests_mock, api_gateway_event):
    requests_mock.register_uri(
        "GET",
        re.compile("/_search"),
        json=es_search_response(dataset_id, []),
    )

    response = event_stat(api_gateway_event(authorization_header=access_token), None)
    assert response == _error_response(404, "No events found")


def test_event_stat_unauthorized(api_gateway_event):
    response = event_stat(
        api_gateway_event(authorization_header=access_token_unauthorized), None
    )
    assert response == _error_response(403, "Forbidden")
