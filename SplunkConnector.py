import json

class SplunkConnector:
    def __init__(self, service):
        self.service = service

    def search(self, query, limit=500):
        try:
            job = self.service.jobs.create(f"search {query}", count=limit, exec_mode="blocking")
            results = []
            for result in job.results(count=limit, output_mode="json"):
                if isinstance(result, bytes):
                    result = json.loads(result.decode('utf-8'))
                if isinstance(result, dict):
                    results.append(result)
            return results
        except Exception:
            return []

    def fetch_security_logs(self, index="*", minutes=1, limit=5):
        time_clause = "earliest=0 latest=now" if minutes is None else f"earliest=-{minutes}m latest=now"
        query = f"index={index} {time_clause} | fields _time host sourcetype source src dest user signature action _raw | head {limit}"
        return self.search(query, limit=limit)
