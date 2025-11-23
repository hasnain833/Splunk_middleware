import os
from twilio.rest import Client

# Try to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, skip loading .env

class AlertManager:
    def __init__(self, sid, auth_token, wa_from=None, wa_to=None):
        """
        Initialize AlertManager with Twilio credentials for WhatsApp alerts.
        
        Args:
            sid: Twilio Account SID
            auth_token: Twilio Auth Token
            wa_from: WhatsApp sender number (e.g., whatsapp:+14155238886) - Twilio WhatsApp number
            wa_to: WhatsApp recipient number - Your personal number
        """
        if not sid or not auth_token:
            raise ValueError("Twilio Account SID and Auth Token are required")
        self.client = Client(sid, auth_token)
        self.wa_from = wa_from
        self.wa_to = wa_to

    def send_whatsapp(self, message):
        """
        Send WhatsApp alert message.
        """
        if not self.wa_from or not self.wa_to:
            print("⚠️  WhatsApp not configured (missing wa_from or wa_to)")
            return False
        
        try:
            msg = self.client.messages.create(
                from_=self.wa_from,
                to=self.wa_to,
                body=message
            )
            sid = getattr(msg, 'sid', None)
            print(f"🚨 WhatsApp alert sent! Message SID={sid}")
            return True
        except Exception as e:
            error_msg = str(e)
            print(f"❌ Error sending WhatsApp alert: {error_msg}")
            
            # Provide helpful error messages for common Twilio errors
            if "63007" in error_msg or "63007" in str(e):
                print("\n💡 Troubleshooting Tips:")
                print("   - Error 63007: WhatsApp messaging not enabled or recipient not opted in")
                print("   - Make sure your Twilio WhatsApp number is enabled for messaging")
                print("   - The recipient must send 'join <your-keyword>' to your Twilio WhatsApp number first")
                print("   - For Twilio Sandbox: Send 'join <sandbox-keyword>' to whatsapp:+14155238886")
            elif "21211" in error_msg or "21211" in str(e):
                print("\n💡 Troubleshooting Tips:")
                print("   - Error 21211: Invalid 'To' phone number format")
                print("   - Make sure ALERT_WHATSAPP_TO is in format: whatsapp:+1234567890")
            elif "21212" in error_msg or "21212" in str(e):
                print("\n💡 Troubleshooting Tips:")
                print("   - Error 21212: Invalid 'From' phone number")
                print("   - Make sure TWILIO_WHATSAPP_FROM is your valid Twilio WhatsApp number")
            
            return False

    def send_alert(self, message):
        """
        Send alert via WhatsApp.
        
        Args:
            message: Alert message text
        
        Returns:
            bool: True if message was sent successfully, False otherwise
        """
        return self.send_whatsapp(message)

    @classmethod
    def from_env(cls, whatsapp_from=None, whatsapp_to=None):
        """
        Create an AlertManager instance from environment variables.
        
        This is a convenience factory method that reads Twilio credentials from environment
        variables and creates a configured AlertManager instance ready to use.
        
        Required Environment Variables:
        - TWILIO_ACCOUNT_SID: Your Twilio Account SID
        - TWILIO_AUTH_TOKEN: Your Twilio Auth Token
        - TWILIO_WHATSAPP_FROM: Twilio WhatsApp number (format: whatsapp:+14155238886)
        - ALERT_WHATSAPP_TO: Your personal phone number (format: whatsapp:+923318787833)
        
        Args:
            whatsapp_from: Twilio WhatsApp number (e.g., whatsapp:+14155238886) - Use Twilio number
                          If not provided, uses TWILIO_WHATSAPP_FROM from environment
            whatsapp_to: Your personal phone number for WhatsApp (e.g., whatsapp:+923318787833) - Use YOUR number
                        If not provided, uses ALERT_WHATSAPP_TO from environment
        
        Returns:
            AlertManager instance configured for WhatsApp alerts
        
        Example:
            alert_manager = AlertManager.from_env()
            alert_manager.send_alert('Test message')
        """
        twilio_sid = os.environ.get("TWILIO_ACCOUNT_SID", "")
        twilio_token = os.environ.get("TWILIO_AUTH_TOKEN", "")
        wa_from = whatsapp_from or os.environ.get("TWILIO_WHATSAPP_FROM", "")
        wa_to = whatsapp_to or os.environ.get("ALERT_WHATSAPP_TO", "")
        
        if not twilio_sid or not twilio_token:
            raise ValueError("TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN must be set in environment variables")
        
        if not wa_from:
            raise ValueError("TWILIO_WHATSAPP_FROM must be set in environment variables or passed as parameter")
        
        if not wa_to:
            raise ValueError("ALERT_WHATSAPP_TO must be set in environment variables or passed as parameter")
        
        return cls(
            sid=twilio_sid,
            auth_token=twilio_token,
            wa_from=wa_from,  # Twilio WhatsApp number (FROM)
            wa_to=wa_to  # Your personal number (TO)
        )
