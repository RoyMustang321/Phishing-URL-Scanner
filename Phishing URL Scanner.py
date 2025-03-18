try:
    import requests
    from tld import get_tld
except ImportError:
    print("Error: The 'requests' and 'tld' libraries are required to run this script.")
    print("Please install them using 'pip install requests tld'")
    exit()

import re
import socket
import ssl
import argparse
import datetime
import urllib.parse
import warnings
import numpy as np
from collections import Counter

# Suppress SSL verification warnings for analysis purposes
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class PhishingURLScanner:
    def __init__(self):
        # Common brands often targeted in phishing attacks
        self.common_targets = [
            'paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'google', 'facebook',
            'instagram', 'bank', 'wells', 'chase', 'citi', 'amex', 'gmail', 'outlook',
            'icloud', 'linkedin', 'twitter', 'ebay', 'walmart', 'dropbox', 'adobe',
            'steam', 'github', 'bitcoin', 'coinbase', 'binance', 'crypto', 'wallet'
        ]
        # Common suspicious terms in phishing URLs
        self.suspicious_terms = [
            'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
            'validation', 'authenticate', 'recover', 'unlock', 'password', 'credential',
            'access', 'limited', 'suspend', 'unusual', 'activity', 'verify',
        ]

    def extract_domain(self, url):
        try:
            tld_result = get_tld(url, as_object=True)
            if tld_result:
              return tld_result.fld
            return None
        except Exception:
            return None

    def contains_common_target(self, domain):
      if domain is None:
        return False
      domain_lower = domain.lower()
      for target in self.common_targets:
          if target in domain_lower:
            return True
      return False

    def contains_suspicious_terms(self, url):
      if not url:
        return False
      url_lower = url.lower()
      for term in self.suspicious_terms:
        if term in url_lower:
          return True
      return False

    def fetch_website_data(self, url):
      try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response
      except requests.exceptions.RequestException:
        return None

    def assess_risk(self, url):
        risk_score = 0
        domain = self.extract_domain(url)

        if not domain:
            return "Invalid URL", "High", "Check URL formatting and retry"
        if self.contains_common_target(domain):
           risk_score += 3
        if self.contains_suspicious_terms(url):
          risk_score += 2

        response = self.fetch_website_data(url)
        if not response:
          risk_score += 2


        if risk_score >= 5:
          risk_level = "High"
          solution = "URGENT: High security risk detected! Do not click, enter credentials, or share personal information. This URL exhibits multiple suspicious characteristics typical of phishing attempts. Report this URL to your IT security team or relevant authorities immediately. If you've already interacted with this link, change your passwords and monitor your accounts for suspicious activity."
        elif risk_score >= 3:
          risk_level = "Medium"
          solution = "Proceed with caution, verify the link source, be careful about entering personal info"
        else:
          risk_level = "Low"
          solution = "The risk is low, proceed with caution."
        return f"Risk Score: {risk_score}", risk_level, solution


def main():

#  print("Phishing URL Scanner")
    scanner = PhishingURLScanner()
    while True:
      print("Ready to accept URL input...")
      url = input("Enter a URL to scan (or 'exit' to quit): ")
      if url.lower() == 'exit':
        break
      risk_score, risk_level, solution = scanner.assess_risk(url)
      print("-------------------------------")
      print(f"URL: {url}")
      print(f"{risk_score}")
      print(f"Risk Level: {risk_level}")
      print(f"Solution: {solution}")
      print("-------------------------------")


if __name__ == "__main__":
    main()
