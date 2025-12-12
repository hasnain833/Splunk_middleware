import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SplunkConnector:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)

    def _post(self, path, data):
        return requests.post(
            f"{self.base_url}{path}",
            auth=self.auth,
            data=data,
            verify=False,
            timeout=30
        )

    def _get(self, path, params):
        return requests.get(
            f"{self.base_url}{path}",
            auth=self.auth,
            params=params,
            verify=False,
            timeout=30
        )

    def search(self, query, limit=500):
        try:
            job_resp = self._post(
                "/services/search/jobs",
                {
                    "search": f"search {query}",
                    "output_mode": "json",
                    "exec_mode": "blocking",
                    "count": limit
                }
            ).json()

            sid = job_resp.get("sid")
            if not sid:
                return []

            result_resp = self._get(
                f"/services/search/jobs/{sid}/results",
                {"output_mode": "json", "count": limit}
            ).json()

            return result_resp.get("results", [])

        except Exception:
            return []

    def fetch_security_logs(self, index="*", minutes=1, limit=5, sourcetypes=None):
        time_clause = (
            "earliest=0 latest=now"
            if minutes is None else
            f"earliest=-{minutes}m latest=now"
        )

        query = (
            f"index={index} {time_clause} "
            "| fields _time host sourcetype source src dest user signature action _raw "
            f"| head {limit}"
        )

        return self.search(query, limit=limit)
