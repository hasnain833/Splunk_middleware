class LogPreprocessor:
    def __init__(self, fields=None):
        self.fields = fields or ["_time", "host", "sourcetype", "source",
                                 "src", "dest", "user", "signature",
                                 "action", "_raw"]

    def event_to_text(self, event: dict) -> str:
        """
        Convert Splunk event dict to a unified text line.
        """
        parts = []
        for key in self.fields:
            if key in event and event[key] not in (None, ""):
                parts.append(f"{key}={event[key]}")
        return " | ".join(parts)
