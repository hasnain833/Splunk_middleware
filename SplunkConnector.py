import json

class SplunkConnector:
    def __init__(self, service):
        self.service = service

    def fetch_security_logs(self, index="*", minutes=1, limit=5):
        time_clause = "earliest=0 latest=now" if minutes is None else f"earliest=-{minutes}m latest=now"
        query = f"search index={index} {time_clause} | fields _time host sourcetype source src dest user signature action _raw | head {limit}"
        
        try:
            job = self.service.jobs.create(query, count=limit, exec_mode="blocking")
            results = []
            
            try:
                for event in job.events(count=limit):
                    if isinstance(event, dict) and ("_raw" in event or "_time" in event):
                        results.append(event)
                if results:
                    return results
            except Exception:
                pass
            
            for result in job.results(count=limit, output_mode="json"):
                if isinstance(result, bytes):
                    result = json.loads(result.decode('utf-8'))
                
                if not isinstance(result, dict):
                    continue
                
                if "results" in result and isinstance(result["results"], list):
                    results.extend([e for e in result["results"] if isinstance(e, dict) and ("_raw" in e or "_time" in e)])
                elif "_raw" in result or "_time" in result:
                    results.append(result)
            
            return results
        except Exception as e:
            print(f"  ERROR fetching logs: {e}")
            return []
