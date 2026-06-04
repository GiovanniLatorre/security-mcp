"""Splunk Cloud REST API client for security investigations.

Supports token auth (preferred) or basic auth (service account).
All operations are read-only (search only).
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Optional
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)

class SplunkClient:
    """Read-only Splunk REST client."""

    def __init__(self):
        base = os.environ.get("SPLUNK_BASE_URL", "").strip()
        if not base:
            self.base_url = ""
        else:
            self.base_url = base.rstrip("/")
        self.token = os.environ.get("SPLUNK_TOKEN")
        self.username = os.environ.get("SPLUNK_USERNAME")
        self.password = os.environ.get("SPLUNK_PASSWORD")

    @property
    def is_configured(self) -> bool:
        if not self.base_url:
            return False
        return bool(self.token or (self.username and self.password))

    def _headers(self) -> dict:
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}

    def _auth(self) -> Optional[tuple]:
        if not self.token and self.username and self.password:
            return (self.username, self.password)
        return None

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{path}"
        kwargs.setdefault("headers", {}).update(self._headers())
        auth = self._auth()
        if auth:
            kwargs["auth"] = auth
        kwargs["verify"] = True
        kwargs.setdefault("timeout", 30)
        return requests.request(method, url, **kwargs)

    def search(
        self,
        query: str,
        earliest: str = "-1h",
        latest: str = "now",
        max_results: int = 50,
        timeout: int = 120,
    ) -> dict:
        """Run a one-shot search and return results.

        Args:
            query: SPL query (e.g. 'index=pritunl "authorizer callback"')
            earliest: Time range start (e.g. '-1h', '-24h', '2024-01-01T00:00:00')
            latest: Time range end (default 'now')
            max_results: Maximum results to return
            timeout: HTTP response timeout in seconds (default 120)
        """
        if not self.is_configured:
            return {
                "error": "SPLUNK_NOT_CONFIGURED",
                "message": "Splunk nao esta configurado. Coloca SPLUNK_TOKEN (ou SPLUNK_USERNAME + SPLUNK_PASSWORD) no .env",
            }

        if not query.strip().startswith("search") and not query.strip().startswith("|"):
            query = f"search {query}"

        try:
            resp = self._request(
                "POST",
                "/services/search/jobs",
                data={
                    "search": query,
                    "earliest_time": earliest,
                    "latest_time": latest,
                    "output_mode": "json",
                    "max_count": str(max_results),
                    "exec_mode": "oneshot",
                },
                timeout=timeout,
            )

            if resp.status_code == 401:
                return {
                    "error": "SPLUNK_AUTH_FAILED",
                    "message": "Token/credenciais do Splunk invalidos ou expirados.",
                }

            if resp.status_code != 200:
                return {
                    "error": f"SPLUNK_HTTP_{resp.status_code}",
                    "message": resp.text[:500],
                }

            data = resp.json()
            results = data.get("results", [])

            return {
                "count": len(results),
                "results": results[:max_results],
            }

        except requests.exceptions.ConnectionError:
            return {
                "error": "SPLUNK_CONNECTION_ERROR",
                "message": f"Nao conseguiu conectar em {self.base_url}. Verifica o URL e se a porta 8089 esta acessivel.",
            }
        except Exception as exc:
            return {"error": str(exc)}

    def search_async(
        self,
        query: str,
        earliest: str = "-1h",
        latest: str = "now",
        max_results: int = 100,
        poll_interval: int = 2,
        timeout: int = 60,
    ) -> dict:
        """Run an async search (for heavier queries) and poll for results."""
        if not self.is_configured:
            return {
                "error": "SPLUNK_NOT_CONFIGURED",
                "message": "Splunk nao esta configurado.",
            }

        if not query.strip().startswith("search") and not query.strip().startswith("|"):
            query = f"search {query}"

        try:
            resp = self._request(
                "POST",
                "/services/search/jobs",
                data={
                    "search": query,
                    "earliest_time": earliest,
                    "latest_time": latest,
                    "output_mode": "json",
                    "max_count": str(max_results),
                },
            )

            if resp.status_code not in (200, 201):
                return {"error": f"HTTP {resp.status_code}", "message": resp.text[:500]}

            sid = resp.json().get("sid")
            if not sid:
                return {"error": "No search ID returned"}

            elapsed = 0
            while elapsed < timeout:
                time.sleep(poll_interval)
                elapsed += poll_interval

                status_resp = self._request(
                    "GET",
                    f"/services/search/jobs/{quote(sid)}",
                    params={"output_mode": "json"},
                )
                job = status_resp.json().get("entry", [{}])[0].get("content", {})
                dispatch_state = job.get("dispatchState", "")

                if dispatch_state == "DONE":
                    results_resp = self._request(
                        "GET",
                        f"/services/search/jobs/{quote(sid)}/results",
                        params={"output_mode": "json", "count": str(max_results)},
                    )
                    data = results_resp.json()
                    return {
                        "count": len(data.get("results", [])),
                        "results": data.get("results", [])[:max_results],
                    }

                if dispatch_state == "FAILED":
                    return {"error": "Search failed", "details": job}

            return {"error": "Search timed out", "sid": sid}

        except Exception as exc:
            return {"error": str(exc)}
