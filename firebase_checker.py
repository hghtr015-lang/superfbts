#!/usr/bin/env python3
"""
Firebase Security Checker - Tests for misconfigurations
"""

import requests
import json
import time
from typing import Dict, List, Any


class FirebaseChecker:
    """Check Firebase database for security misconfigurations"""

    def __init__(self, firebase_url: str, api_key: str = None):
        self.base_url = firebase_url.rstrip('/')
        self.api_key = api_key
        self.results = {
            "url": firebase_url,
            "public_read": False,
            "public_write": False,
            "auth_required": True,
            "data_found": False,
            "error": None,
            "details": []
        }

    def check_public_access(self) -> Dict[str, Any]:
        """Check if the database is publicly accessible"""
        try:
            url = f"{self.base_url}/.json"
            if self.api_key:
                url += f"?auth={self.api_key}"

            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                self.results["public_read"] = True
                self.results["auth_required"] = False
                self.results["data_found"] = data is not None and data != {}
                self.results["details"].append({
                    "type": "public_read",
                    "status": "VULNERABLE",
                    "message": "Database is publicly readable!",
                    "data_preview": str(data)[:200] + "..." if data else "Empty"
                })

            elif response.status_code == 403:
                self.results["auth_required"] = True
                self.results["details"].append({
                    "type": "auth_required",
                    "status": "SECURE",
                    "message": "Authentication required to access"
                })

            else:
                self.results["error"] = f"HTTP {response.status_code}"
                self.results["details"].append({
                    "type": "error",
                    "status": "UNKNOWN",
                    "message": f"HTTP {response.status_code}: {response.text[:100]}"
                })

        except Exception as e:
            self.results["error"] = str(e)
            self.results["details"].append({
                "type": "connection_error",
                "status": "ERROR",
                "message": str(e)
            })

        return self.results

    def check_public_write(self) -> Dict[str, Any]:
        """Test if the database allows public writes"""
        try:
            test_node = f"/test_{int(time.time())}"
            url = f"{self.base_url}{test_node}.json"
            if self.api_key:
                url += f"?auth={self.api_key}"

            test_data = {"test": True, "timestamp": int(time.time())}
            response = requests.put(url, json=test_data, timeout=10)

            if response.status_code == 200:
                self.results["public_write"] = True
                self.results["details"].append({
                    "type": "public_write",
                    "status": "VULNERABLE",
                    "message": "Database allows public write access!"
                })
                requests.delete(url, timeout=5)
            else:
                self.results["details"].append({
                    "type": "public_write",
                    "status": "SECURE",
                    "message": "Write operations require authentication"
                })

        except Exception as e:
            pass

        return self.results

    def full_scan(self) -> Dict[str, Any]:
        self.check_public_access()
        self.check_public_write()
        return self.results


def check_firebase_configs(configs: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    results = []

    urls = configs.get('firebase_urls', [])
    api_keys = configs.get('api_keys', [])

    for url in urls:
        checker = FirebaseChecker(url, api_keys[0] if api_keys else None)
        results.append(checker.full_scan())

    return results


def generate_security_report(check_results: List[Dict[str, Any]]) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append("  🔒 FIREBASE SECURITY CHECK REPORT")
    lines.append("=" * 60)

    for result in check_results:
        url = result.get('url', 'Unknown')
        lines.append(f"\n📍 URL: {url}")

        for detail in result.get('details', []):
            status = detail.get('status', 'UNKNOWN')
            if 'VULNERABLE' in status:
                icon = "🔴"
            elif 'SECURE' in status:
                icon = "✅"
            else:
                icon = "⚪"

            lines.append(f"   {icon} {detail.get('type', '').upper()}: {detail.get('message', '')}")

        if result.get('data_found'):
            lines.append(f"   📊 Data preview: {result.get('data_preview', '')}")

        if result.get('error'):
            lines.append(f"   ❌ Error: {result.get('error')}")

        summary = []
        if result.get('public_read'):
            summary.append("🔴 Public Read")
        else:
            summary.append("✅ Private")

        if result.get('public_write'):
            summary.append("🔴 Public Write")
        else:
            summary.append("✅ Protected")

        lines.append(f"   📝 Summary: {' | '.join(summary)}")

    lines.append("\n" + "=" * 60)
    return '\n'.join(lines)
