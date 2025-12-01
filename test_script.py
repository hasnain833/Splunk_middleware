"""
Utility script to verify the WhatsApp alert pipeline without running the full
security monitoring stack.
"""
import argparse
import sys

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    # .env loading is optional; continue if python-dotenv is absent
    pass

from AlertManager import AlertManager


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send a test alert message via the configured AlertManager."
    )
    parser.add_argument(
        "--message",
        default="🔔 Test alert from Splunk security monitoring",
        help="Text to send in the WhatsApp alert.",
    )
    parser.add_argument(
        "--wa-from",
        dest="wa_from",
        default=None,
        help="Override the WhatsApp sender (Twilio) number, format whatsapp:+123456789.",
    )
    parser.add_argument(
        "--wa-to",
        dest="wa_to",
        default=None,
        help="Override the WhatsApp recipient number, format whatsapp:+123456789.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        alert_manager = AlertManager.from_env(
            whatsapp_from=args.wa_from,
            whatsapp_to=args.wa_to,
        )
    except ValueError as exc:
        print(f"❌ Configuration error: {exc}")
        print(
            "   Ensure TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, "
            "TWILIO_WHATSAPP_FROM, and ALERT_WHATSAPP_TO are set."
        )
        return 1

    print("🚨 Sending test alert...")
    if alert_manager.send_alert(args.message):
        print("✅ Test alert sent successfully.")
        return 0

    print("⚠️  Test alert failed. Check the logs above for troubleshooting tips.")
    return 2


if __name__ == "__main__":
    sys.exit(main())


