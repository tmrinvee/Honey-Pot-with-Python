import os
import smtplib
from flask import Flask, request, jsonify, render_template
import logging
from datetime import datetime
import requests

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(
    filename="advanced_honeypot.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Email alert configuration
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
EMAIL_USERNAME = "your-email@example.com"
EMAIL_PASSWORD = "your-email-password"
ALERT_EMAIL = "alert-recipient@example.com"

# GeoIP Lookup API 
GEOIP_API = "http://ip-api.com/json/"

# Function to log activity
def log_attempt(endpoint: str, ip: str, user_agent: str, geo_info: dict = None):
    location = f"{geo_info.get('country', 'Unknown')}, {geo_info.get('city', 'Unknown')}" if geo_info else "Unknown"
    log_message = (
        f"Access attempt: Endpoint: {endpoint}, IP: {ip}, User-Agent: {user_agent}, Location: {location}"
    )
    logging.info(log_message)
    print(log_message)

# To send alerts
def send_alert(ip: str, endpoint: str, geo_info: dict):
    subject = f"Honeypot Alert: Unauthorized Access Detected!"
    body = (
        f"Suspicious activity detected:\n"
        f"- Endpoint: {endpoint}\n"
        f"- IP: {ip}\n"
        f"- Location: {geo_info.get('country', 'Unknown')}, {geo_info.get('city', 'Unknown')}\n"
        f"- Time: {datetime.utcnow()}\n"
    )
    message = f"Subject: {subject}\n\n{body}"
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USERNAME, ALERT_EMAIL, message)
    except Exception as e:
        logging.error(f"Failed to send alert: {e}")

# To perform GeoIP lookup
def get_geoip(ip: str):
    try:
        response = requests.get(GEOIP_API + ip)
        return response.json()
    except Exception as e:
        logging.error(f"GeoIP lookup failed: {e}")
        return {}

# Honeypot endpoints
@app.route("/admin", methods=["GET", "POST"])
@app.route("/config", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
@app.route("/api/v1/secret", methods=["GET", "POST"])
def honeypot():
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "Unknown")
    endpoint = request.path

    # Perform GeoIP lookup
    geo_info = get_geoip(ip)

    # Log and alert
    log_attempt(endpoint, ip, user_agent, geo_info)
    send_alert(ip, endpoint, geo_info)

    # Fake response to mimic a real system
    if endpoint == "/admin":
        return render_template("fake_admin.html"), 403
    elif endpoint == "/api/v1/secret":
        fake_data = {"data": "This is classified data. Access denied."}
        return jsonify(fake_data), 403
    else:
        return "Unauthorized access detected. Your activity has been logged.", 403

# Default route
@app.route("/")
def default_route():
    return "404 Not Found", 404

# Run the honeypot
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
