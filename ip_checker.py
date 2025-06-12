# ip_checker.py
import pandas as pd
import requests

class IPChecker:
    """
    Checks IP addresses against offline CSV or online API.
    """
    def __init__(self,
                 offline_file: str = "Malicious_IP.csv",
                 api_key: str | None = None):
        self.offline_file = offline_file
        self.api_key = api_key

    def check_offline(self, ip: str) -> bool:
        print("Checking IP offline...")
        try:
            df = pd.read_csv(self.offline_file)
            if ip in df['src_ip'].values:
                print(f"Found malicious IP: {ip}")
                return True
            else:
                print(f"IP is not malicious: {ip}")
                return False
        except FileNotFoundError:
            print(f"Offline data file '{self.offline_file}' not found.")

    def check_online(self, ip: str) -> bool:
        if not self.api_key:
            print("API key not provided for online check.")
            return
        print("Checking IP online...")
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip}
        resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
        data = resp.json().get('data', {})
        if data.get('totalReports', 0) > 0:
            print(f"Found malicious IP: {ip}")
            return True
        else:
            print(f"IP is not malicious: {ip}")
            return False

