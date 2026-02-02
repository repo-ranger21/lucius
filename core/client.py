import threading
import time
from typing import Any

import requests


class SafetyException(Exception):
    pass


class LuciusClient:
    def __init__(self, rate_limit: int = 50) -> None:
        self.session = requests.Session()
        self.session.headers.update({"X-HackerOne-Research": "[lucius-log]"})
        self.rate_limit = rate_limit
        self.tokens = float(rate_limit)
        self.last_check = time.time()
        self._lock = threading.Lock()

    def _refill_tokens(self) -> None:
        now = time.time()
        elapsed = now - self.last_check
        self.tokens = min(
            self.rate_limit,
            self.tokens + elapsed * self.rate_limit,
        )
        self.last_check = now

    def _acquire_token(self) -> None:
        while True:
            with self._lock:
                self._refill_tokens()
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
            time.sleep(0.01)

    def _request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> requests.Response:
        headers = kwargs.pop("headers", {})
        if "X-HackerOne-Research" not in headers:
            headers["X-HackerOne-Research"] = "[lucius-log]"
        kwargs["headers"] = headers

        if "X-HackerOne-Research" not in headers:
            raise SafetyException("Missing required header: X-HackerOne-Research")

        self._acquire_token()
        response = self.session.request(method, url, **kwargs)
        if "X-HackerOne-Research" not in response.request.headers:
            raise SafetyException("Missing required header: X-HackerOne-Research")
        return response

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("DELETE", url, **kwargs)
