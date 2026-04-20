"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CUSTOM EDR — VELOCIRAPTOR REST API CLIENT                                  ║
║                                                                              ║
║  Wraps Velociraptor's HTTP API so your Python engine can:                   ║
║    - Query artifacts (VQL) against connected endpoints                      ║
║    - Launch hunts                                                            ║
║    - Collect specific event data on demand                                  ║
║    - Trigger automated responses via server artifacts                       ║
║                                                                              ║
║  SETUP:                                                                      ║
║  1. Generate API key:                                                        ║
║     velociraptor.exe --config server.config.yaml config api_client          ║
║         --name python_edr --role administrator api_client.yaml              ║
║  2. Set api_key_file in config.yaml                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    requests = None  # type: ignore
import yaml

log = logging.getLogger("edr.velociraptor")


class VelociraptorClient:
    """
    HTTP client for Velociraptor's REST-like API.

    Velociraptor exposes a gRPC API but also provides an HTTP gateway.
    We use the HTTP gateway with JWT token authentication.
    """

    def __init__(self, config: dict):
        vc = config.get("velociraptor", {})
        self.server_url = vc.get("server_url", "https://localhost:8889").rstrip("/")
        self.username = vc.get("username", "admin")
        self.password = vc.get("password", "")
        self.verify_tls = vc.get("verify_tls", False)
        self.api_key_file = vc.get("api_key_file", "")
        self.org_id = vc.get("org_id", "")

        self._token: Optional[str] = None
        self._token_expiry: float = 0
        self._session = requests.Session()

        if not self.verify_tls:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ─── AUTHENTICATION ───────────────────────────────────────────────────────

    def _get_token(self) -> str:
        """Get a fresh JWT token from Velociraptor."""
        if self._token and time.time() < self._token_expiry:
            return self._token

        try:
            resp = self._session.post(
                f"{self.server_url}/api/v1/GetJWT",
                json={"username": self.username, "password": self.password},
                verify=self.verify_tls,
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data.get("token", "")
            # Tokens typically last 24h — refresh after 23h
            self._token_expiry = time.time() + (23 * 3600)
            log.debug("Velociraptor: JWT token obtained successfully.")
            return self._token

        except requests.exceptions.ConnectionError:
            log.warning("Velociraptor server not reachable. Is it running?")
            return ""
        except Exception as e:
            log.warning(f"Velociraptor authentication failed: {e}")
            return ""

    def _headers(self) -> Dict[str, str]:
        token = self._get_token()
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if self.org_id:
            headers["grpc-metadata-orgid"] = self.org_id
        return headers

    def is_connected(self) -> bool:
        """Check if we can reach the Velociraptor server."""
        try:
            resp = self._session.get(
                f"{self.server_url}/api/v1/GetVersion",
                verify=self.verify_tls,
                timeout=5,
            )
            return resp.status_code == 200
        except Exception:
            return False

    # ─── VQL QUERIES ─────────────────────────────────────────────────────────

    def run_vql(self, vql: str, env: Optional[Dict] = None) -> List[Dict]:
        """
        Execute a VQL query on the Velociraptor server.

        Args:
            vql: VQL query string
            env: Optional dict of environment variables for the query

        Returns:
            List of result dicts
        """
        token = self._get_token()
        if not token:
            log.warning("No auth token — cannot run VQL query.")
            return []

        payload = {"query": [{"vql": vql}]}
        if env:
            payload["env"] = [{"key": k, "value": str(v)} for k, v in env.items()]

        try:
            resp = self._session.post(
                f"{self.server_url}/api/v1/Query",
                headers=self._headers(),
                json=payload,
                verify=self.verify_tls,
                timeout=30,
                stream=True,  # VQL results stream as NDJSON
            )
            resp.raise_for_status()

            results = []
            for line in resp.iter_lines():
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    # Velociraptor streams results as {"Response": "[{...}]"}
                    if "Response" in row:
                        inner = json.loads(row["Response"])
                        if isinstance(inner, list):
                            results.extend(inner)
                    elif isinstance(row, dict):
                        results.append(row)
                except json.JSONDecodeError:
                    pass

            return results

        except requests.exceptions.ConnectionError:
            log.debug("Velociraptor not reachable for VQL query.")
            return []
        except Exception as e:
            log.error(f"VQL query failed: {e}")
            return []

    # ─── ARTIFACT COLLECTION ─────────────────────────────────────────────────

    def collect_artifact(
        self,
        client_id: str,
        artifact_name: str,
        parameters: Optional[Dict] = None,
        wait_for_completion: bool = True,
        timeout: int = 60
    ) -> List[Dict]:
        """
        Collect a named artifact from a specific client (endpoint).

        Args:
            client_id: Velociraptor client ID (e.g., "C.1234567890abcdef")
            artifact_name: Name of artifact to collect
            parameters: Dict of artifact parameters
            wait_for_completion: Block until collection is done
            timeout: Maximum seconds to wait

        Returns:
            List of result rows
        """
        # Schedule the collection
        schedule_vql = f"""
        SELECT collect_client(
            client_id='{client_id}',
            artifacts=['{artifact_name}'],
            env=dict({", ".join(f"{k}='{v}'" for k, v in (parameters or {}).items())})
        ) AS result
        FROM scope()
        """

        results = self.run_vql(schedule_vql)
        if not results:
            return []

        flow_id = results[0].get("result", {}).get("flow_id", "")
        if not flow_id:
            return []

        log.info(f"Collection flow {flow_id} started for {artifact_name} on {client_id}")

        if not wait_for_completion:
            return [{"flow_id": flow_id}]

        # Poll until flow completes
        start_time = time.time()
        while time.time() - start_time < timeout:
            status_vql = f"""
            SELECT state FROM flows(client_id='{client_id}', flow_id='{flow_id}')
            """
            status = self.run_vql(status_vql)
            if status and status[0].get("state") == "FINISHED":
                break
            time.sleep(2)

        # Retrieve results
        results_vql = f"""
        SELECT * FROM source(
            client_id='{client_id}',
            flow_id='{flow_id}',
            artifact='{artifact_name}'
        )
        """
        return self.run_vql(results_vql)

    # ─── HUNT MANAGEMENT ─────────────────────────────────────────────────────

    def create_hunt(self, artifact_name: str, description: str = "") -> str:
        """
        Create a hunt that runs an artifact across all endpoints.
        Returns the hunt ID.
        """
        vql = f"""
        SELECT hunt(
            description='{description or artifact_name}',
            artifacts=['{artifact_name}']
        ) AS hunt_id
        FROM scope()
        """
        results = self.run_vql(vql)
        if results:
            return results[0].get("hunt_id", "")
        return ""

    # ─── ENDPOINT MANAGEMENT ─────────────────────────────────────────────────

    def get_clients(self) -> List[Dict]:
        """List all connected endpoints."""
        return self.run_vql("SELECT * FROM clients()")

    def get_client_by_hostname(self, hostname: str) -> Optional[str]:
        """Find a client ID by hostname."""
        vql = f"SELECT client_id FROM clients() WHERE os_info.hostname =~ '{hostname}'"
        results = self.run_vql(vql)
        if results:
            return results[0].get("client_id")
        return None

    # ─── RESPONSE ACTIONS VIA VELOCIRAPTOR ───────────────────────────────────

    def kill_process_remote(self, client_id: str, process_id: int) -> bool:
        """
        Use Velociraptor to kill a process on a remote endpoint.
        Uses the Windows.System.KillProcess artifact.
        """
        vql = f"""
        SELECT collect_client(
            client_id='{client_id}',
            artifacts=['Windows.System.KillProcess'],
            env=dict(PidToKill='{process_id}')
        ) FROM scope()
        """
        results = self.run_vql(vql)
        success = bool(results)
        if success:
            log.info(f"Remote kill sent: PID {process_id} on {client_id}")
        return success

    def get_recent_sysmon_events(
        self,
        client_id: str,
        event_ids: str = "1,3,10,11,12,13,22",
        hours_back: int = 1,
        max_events: int = 100
    ) -> List[Dict]:
        """
        Query recent Sysmon events from an endpoint using our custom artifact.
        Requires CustomEDR.Sysmon.Events to be installed on the server.
        """
        return self.collect_artifact(
            client_id=client_id,
            artifact_name="CustomEDR.Sysmon.Events",
            parameters={
                "EventIDs": event_ids,
                "HoursBack": str(hours_back),
                "MaxEvents": str(max_events),
            }
        )

    # ─── SERVER INFO ─────────────────────────────────────────────────────────

    def get_server_version(self) -> str:
        """Get Velociraptor server version."""
        results = self.run_vql("SELECT version() AS v FROM scope()")
        if results:
            return str(results[0].get("v", "unknown"))
        return "unknown"
