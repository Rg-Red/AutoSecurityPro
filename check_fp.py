import hashlib
import uuid
import requests

base = "https://talk.pod.ir"
paths = [
    "/",
    "/.env",
    "/.git/HEAD",
    "/backup.zip",
    "/dump.sql",
    "/swagger.json",
    f"/definitely-not-a-real-path-{uuid.uuid4().hex}.txt",
]

s = requests.Session()
s.headers["User-Agent"] = "authorized-security-check/1.0"

for path in paths:
    try:
        r = s.get(base + path, timeout=10, allow_redirects=True)
        body = r.content
        hash_val = hashlib.sha256(body).hexdigest()[:16]
        print(
            f"{path:55} status={r.status_code} "
            f"type={r.headers.get('Content-Type', '-')} "
            f"bytes={len(body)} sha256={hash_val} "
            f"final={r.url}"
        )
    except requests.RequestException as e:
        print(f"{path:55} error={type(e).__name__}: {e}")
