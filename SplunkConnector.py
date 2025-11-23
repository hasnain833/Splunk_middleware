import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SplunkConnector:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password

    def run_search(self, spl_query, count=500):
        """
        Execute a blocking Splunk search job and return results.
        """
        job_data = {
            "search": f"search {spl_query}",
            "output_mode": "json",
            "exec_mode": "blocking",
            "count": count
        }

        # Create search job
        try:
            resp = requests.post(
                f"{self.base_url}/services/search/jobs",
                auth=(self.username, self.password),
                data=job_data,
                verify=False,
                timeout=30
            )
        except Exception as e:
            print("Error: failed to create Splunk search job:", e)
            return []

        try:
            job = resp.json()
        except Exception:
            print("Warning: Splunk job creation returned non-JSON response:", resp.status_code)
            print("Response text:", resp.text[:400])
            return []

        sid = job.get("sid")
        if not sid:
            print("Warning: Splunk did not return a search sid. Job response:", job)
            return []

        # Fetch job results
        try:
            resp2 = requests.get(
                f"{self.base_url}/services/search/jobs/{sid}/results",
                auth=(self.username, self.password),
                params={"output_mode": "json", "count": count},
                verify=False,
                timeout=30
            )
        except Exception as e:
            print("Error: failed to fetch Splunk job results:", e)
            return []

        try:
            results = resp2.json()
        except Exception:
            print("Warning: Splunk results endpoint returned non-JSON response:", resp2.status_code)
            print("Response text:", resp2.text[:400])
            return []

        return results.get("results", [])

    def fetch_latest_logs(self, index, minutes=5, limit=500):
        """
        Fetch logs from the past N minutes from specified index.
        """
        query = f"""
        index={index} earliest=-{minutes}m latest=now 
        | fields *
        """
        return self.run_search(query, count=limit)

    def fetch_all_time_head(self, index, head=50):
        """
        Fetch logs from the specified index for all time and return the first `head` results.
        Uses `earliest=0` to request all-time from Splunk.
        """
        query = f"index={index} earliest=0 latest=now | fields * | head {head}"
        return self.run_search(query, count=head)
