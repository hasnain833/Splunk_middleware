import json

class SplunkConnector:
    def __init__(self, service):
        self.service = service

    def fetch_security_logs(self, index="*", minutes=1, limit=5):
        time_clause = "earliest=0 latest=now" if minutes is None else f"earliest=-{minutes}m latest=now"
        query = f"index={index} {time_clause} | fields _time host sourcetype source src dest user signature action _raw | head {limit}"
        
        try:
            job = self.service.jobs.create(f"search {query}", count=limit, exec_mode="blocking")
            results = []
            for result in job.results(count=limit, output_mode="json"):
                if isinstance(result, bytes):
                    result = json.loads(result.decode('utf-8'))
                if isinstance(result, dict):
                    results.append(result)
            return results
        except:
            return []
