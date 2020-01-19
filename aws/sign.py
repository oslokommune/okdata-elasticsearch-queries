import hmac
import hashlib
import datetime
import urllib


class AwsSignV4:
    def __init__(self, *, access_key, secret_key, token, host, region, service):
        self.access_key = access_key
        self.secret_key = secret_key
        self.token = token

        self.host = host
        self.region = region
        self.service = service

    def __call__(self, r):
        t = datetime.datetime.utcnow()
        amz_date = t.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = t.strftime("%Y%m%d")  # Date w/o time, used in credential scope

        parsed_url = urllib.parse.urlparse(r.url)

        canonical_uri = urllib.parse.quote(
            parsed_url.path if parsed_url.path else "/", safe="/-_.~"
        )

        qsl = sorted(urllib.parse.parse_qsl(parsed_url.query))
        canonical_querystring = "&".join(map(lambda x: f"{x[0]}={x[1]}", qsl))

        canonical_headers = f"host:{self.host}\nx-amz-date:{amz_date}\n"
        signed_headers = "host;x-amz-date"

        if self.token:
            canonical_headers += f"x-amz-security-token:{self.token}\n"
            signed_headers += ";x-amz-security-token"

        body = r.body if r.body else bytes()
        payload_hash = hashlib.sha256(body).hexdigest()

        canonical_request = "\n".join(
            [
                r.method,
                canonical_uri,
                canonical_querystring,
                canonical_headers,
                signed_headers,
                payload_hash,
            ]
        )

        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = "/".join(
            [date_stamp, self.region, self.service, "aws4_request"]
        )
        string_to_sign = "\n".join(
            [
                algorithm,
                amz_date,
                credential_scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )

        signing_key = getSignatureKey(
            self.secret_key, date_stamp, self.region, self.service
        )
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        authorization_header = f"{algorithm} Credential={self.access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

        headers = {
            "Authorization": authorization_header,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
        }

        if self.token:
            headers["x-amz-security-token"] = self.token

        r.headers.update(headers)
        return r


# Key derivation functions. See:
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def getSignatureKey(key, date_stamp, regionName, serviceName):
    kDate = sign(("AWS4" + key).encode("utf-8"), date_stamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, "aws4_request")
    return kSigning
