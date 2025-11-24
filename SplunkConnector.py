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
            # Try the request - if it fails with SSL error, try HTTP instead
            try:
                resp = requests.post(
                    f"{self.base_url}/services/search/jobs",
                    auth=(self.username, self.password),
                    data=job_data,
                    verify=False,
                    timeout=30
                )
            except requests.exceptions.SSLError as ssl_err:
                # If SSL error and URL is HTTPS, try HTTP instead
                if self.base_url.startswith("https://"):
                    http_url = self.base_url.replace("https://", "http://")
                    print(f"⚠️  HTTPS failed, trying HTTP: {http_url}")
                    resp = requests.post(
                        f"{http_url}/services/search/jobs",
                        auth=(self.username, self.password),
                        data=job_data,
                        verify=False,
                        timeout=30
                    )
                    # Update base_url for future requests
                    self.base_url = http_url
                else:
                    raise ssl_err
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

    def fetch_security_logs(self, index="botsv3", minutes=5, limit=5000):
        """
        Fetch security logs from botsv3 index with specific sourcetypes.
        This is the main query used for security monitoring.
        
        Args:
            index: Splunk index name (default: botsv3)
            minutes: Number of minutes to look back (default: 5)
            limit: Maximum number of results to return (default: 5000)
        
        Returns:
            List of log events matching the security query
        """
        query = f"""
        index={index}
        earliest=-{minutes}m latest=now
        sourcetype IN (
          "aws:cloudtrail",
          "aws:cloudwatchlogs:vpcflow",
          "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
          "XmlWinEventLog:Security",
          "suricata:alert",
          "stream:http",
          "stream:dns"
        )
        | fields _time host sourcetype source src dest user signature action _raw
        | head {limit}
        """
        return self.run_search(query, count=limit)

    def fetch_security_logs_all_time(self, index="botsv3", limit=5000):
        """
        Fetch all existing security logs from botsv3 index with specific sourcetypes (all-time).
        Used for initial scan of historical data.
        
        Args:
            index: Splunk index name (default: botsv3)
            limit: Maximum number of results to return (default: 5000)
        
        Returns:
            List of log events matching the security query
        """
        query = f"""
        index={index}
        earliest=0 latest=now
        sourcetype IN (
          "aws:cloudtrail",
          "aws:cloudwatchlogs:vpcflow",
          "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
          "XmlWinEventLog:Security",
          "suricata:alert",
          "stream:http",
          "stream:dns"
        )
        | fields _time host sourcetype source src dest user signature action _raw
        | head {limit}
        """
        return self.run_search(query, count=limit)
