from twilio.rest import Client

class AlertManager:
    def __init__(self, sid, auth_token, wa_from, wa_to):
        self.client = Client(sid, auth_token)
        self.wa_from = wa_from
        self.wa_to = wa_to

    def send_alert(self, message):
        """
        Send WhatsApp alert message.
        """
        try:
            msg = self.client.messages.create(
                from_=self.wa_from,
                to=self.wa_to,
                body=message
            )
            sid = getattr(msg, 'sid', None)
            print(f"🚨 WhatsApp alert sent! message SID={sid}")
            return True
        except Exception as e:
            print("Error sending WhatsApp alert:", e)
            return False
