#!/usr/bin/env python3
"""
Firebase & API Key Extractor for APK Files
Extracts Firebase URLs, API Keys, Project IDs, and other credentials from APK
Supports bulk extraction
"""

import os
import re
import json
import zipfile
import hashlib
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from androguard.core.bytecodes.apk import APK
except ImportError:
    print("Error: androguard not installed. Run: pip install androguard")
    raise


class FirebaseExtractor:
    """Extract Firebase configs and API keys from APK files"""

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.apk_name = Path(apk_path).stem
        self.results = {
            "firebase_urls": [],
            "api_keys": [],
            "project_ids": [],
            "app_ids": [],
            "storage_buckets": [],
            "google_services": [],
            "suspicious_strings": [],
            "all_secrets": [],
            "apk_info": {}
        }
        self.apk = None

    def extract_apk_info(self):
        """Extract basic APK information"""
        try:
            self.apk = APK(self.apk_path)
            self.results["apk_info"] = {
                "package_name": self.apk.get_package(),
                "app_name": self.apk.get_app_name(),
                "version_name": self.apk.get_android_version_name(),
                "version_code": self.apk.get_android_version_code(),
                "min_sdk": self.apk.get_min_sdk_version(),
                "target_sdk": self.apk.get_target_sdk_version(),
                "permissions": self.apk.get_permissions(),
                "sha256": hashlib.sha256(open(self.apk_path, 'rb').read()).hexdigest()[:16]
            }
            return True
        except Exception as e:
            print(f"Error extracting APK info: {e}")
            return False

    def extract_from_strings(self, text: str) -> Dict[str, List[str]]:
        """Extract Firebase-related strings using regex patterns"""
        patterns = {
            "firebase_urls": [
                r'https?://[a-zA-Z0-9\-]+\.firebaseio\.com',
                r'https?://[a-zA-Z0-9\-]+\.firebasedatabase\.app',
                r'https?://[a-zA-Z0-9\-]+\.firebaseapp\.com',
            ],
            "api_keys": [
                r'AIza[A-Za-z0-9_\-]{35,45}',
                r'AIzaSy[A-Za-z0-9_\-]{35,45}',
                r'AIza[A-Za-z0-9_\-]{40,50}',
            ],
            "project_ids": [
                r'project-[a-zA-Z0-9\-]+',
                r'[a-z0-9\-]+\.appspot\.com',
                r'[a-z0-9\-]{6,}-[a-z0-9\-]{2,}',
            ],
            "app_ids": [
                r'\d+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9\-]+\.google\.com',
                r'[0-9]{8,}:[a-zA-Z0-9_\-]+',
            ],
            "storage_buckets": [
                r'[a-zA-Z0-9\-]+\.appspot\.com',
                r'gs://[a-zA-Z0-9\-]+\.appspot\.com',
            ],
            "google_api_keys": [
                r'AIza[A-Za-z0-9_\-]{35,45}',
                r'AIzaSy[A-Za-z0-9_\-]{35,45}',
            ],
            "google_app_id": [
                r'\d+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9\-]+\.google\.com',
            ],
        }

        results = {}
        for key, pattern_list in patterns.items():
            matches = []
            for pattern in pattern_list:
                matches.extend(re.findall(pattern, text, re.IGNORECASE))
            if matches:
                results[key] = list(set(matches))

        return results

    def extract_from_manifest(self) -> Dict[str, List[str]]:
        """Extract from AndroidManifest.xml"""
        try:
            manifest_xml = self.apk.get_android_manifest_xml()
            if manifest_xml is not None:
                tree = ET.parse(manifest_xml)
                root = tree.getroot()
                text = ET.tostring(root, encoding='unicode', method='text')
                return self.extract_from_strings(text)
        except:
            pass
        return {}

    def extract_from_resources(self) -> Dict[str, List[str]]:
        """Extract from resource files (strings.xml, etc.)"""
        results = {}
        try:
            for file_path in self.apk.get_files():
                if file_path.endswith('.xml') or file_path.endswith('.json'):
                    try:
                        content = self.apk.get_file(file_path)
                        if content:
                            text = content.decode('utf-8', errors='ignore')
                            extracted = self.extract_from_strings(text)
                            for key, values in extracted.items():
                                if key not in results:
                                    results[key] = []
                                results[key].extend(values)
                    except:
                        pass
        except:
            pass
        return results

    def extract_from_dex(self) -> Dict[str, List[str]]:
        """Extract from DEX files (Dalvik bytecode)"""
        results = {}
        try:
            for dex in self.apk.get_all_dex():
                for string in dex.get_strings():
                    text = str(string)
                    extracted = self.extract_from_strings(text)
                    for key, values in extracted.items():
                        if key not in results:
                            results[key] = []
                        results[key].extend(values)
        except:
            pass
        return results

    def extract_google_services_json(self) -> Dict[str, Any]:
        """Extract google-services.json if embedded in the APK"""
        services = {}
        try:
            for file_path in self.apk.get_files():
                if 'google-services.json' in file_path:
                    content = self.apk.get_file(file_path)
                    if content:
                        data = json.loads(content)
                        client = data.get('client', [{}])[0]
                        client_info = client.get('client_info', {})
                        firebase = client.get('services', {}).get('firebase_service', {})
                        services = {
                            "project_id": client_info.get('mobilesdk_app_id', {}).get('project_id'),
                            "app_id": client_info.get('mobilesdk_app_id'),
                            "api_key": client.get('api_key', [{}])[0].get('current_key'),
                            "firebase_url": firebase.get('database_url'),
                            "storage_bucket": firebase.get('storage_bucket'),
                        }
        except:
            pass
        return services

    def extract_all(self) -> Dict[str, Any]:
        """Run all extraction methods and compile results"""
        print(f"[+] Analyzing APK: {self.apk_path}")

        self.extract_apk_info()

        manifest_results = self.extract_from_manifest()
        resource_results = self.extract_from_resources()
        dex_results = self.extract_from_dex()
        google_services = self.extract_google_services_json()

        all_extracted = {}
        for results in [manifest_results, resource_results, dex_results]:
            for key, values in results.items():
                if key not in all_extracted:
                    all_extracted[key] = []
                all_extracted[key].extend(values)

        for key in all_extracted:
            all_extracted[key] = list(set(all_extracted[key]))

        if google_services:
            for key, value in google_services.items():
                if value:
                    if key not in self.results:
                        self.results[key] = []
                    self.results[key].append(value)

        self.results.update(all_extracted)

        self.results["all_secrets"] = []
        for key, values in self.results.items():
            if key in ['firebase_urls', 'api_keys', 'project_ids', 'app_ids', 'storage_buckets', 'google_api_keys', 'google_app_id']:
                if values:
                    for val in values:
                        if val not in self.results["all_secrets"]:
                            self.results["all_secrets"].append({
                                "type": key.replace('_', ' ').title(),
                                "value": val
                            })

        return self.results

    def generate_report(self) -> str:
        """Generate a human-readable report"""
        if not self.results or not self.results.get('apk_info'):
            return "Error: Could not extract APK information."

        lines = []
        lines.append("=" * 60)
        lines.append("  🔥 FIREBASE & API KEY EXTRACTION REPORT")
        lines.append("=" * 60)

        info = self.results.get('apk_info', {})
        lines.append(f"\n📱 APK INFORMATION:")
        lines.append(f"   Package: {info.get('package_name', 'N/A')}")
        lines.append(f"   App Name: {info.get('app_name', 'N/A')}")
        lines.append(f"   Version: {info.get('version_name', 'N/A')}")
        lines.append(f"   SHA256: {info.get('sha256', 'N/A')}")

        urls = self.results.get('firebase_urls', [])
        if urls:
            lines.append(f"\n🔥 FIREBASE DATABASE URLs ({len(urls)}):")
            for i, url in enumerate(urls, 1):
                lines.append(f"   {i}. {url}")

        keys = self.results.get('api_keys', []) + self.results.get('google_api_keys', [])
        if keys:
            keys = list(set(keys))
            lines.append(f"\n🔑 API KEYS ({len(keys)}):")
            for i, key in enumerate(keys, 1):
                lines.append(f"   {i}. {key}")

        projects = self.results.get('project_ids', [])
        if projects:
            lines.append(f"\n📋 PROJECT IDs ({len(projects)}):")
            for i, proj in enumerate(projects, 1):
                lines.append(f"   {i}. {proj}")

        app_ids = self.results.get('app_ids', []) + self.results.get('google_app_id', [])
        if app_ids:
            app_ids = list(set(app_ids))
            lines.append(f"\n📱 APP IDs ({len(app_ids)}):")
            for i, app_id in enumerate(app_ids, 1):
                lines.append(f"   {i}. {app_id}")

        buckets = self.results.get('storage_buckets', [])
        if buckets:
            lines.append(f"\n🗄️ STORAGE BUCKETS ({len(buckets)}):")
            for i, bucket in enumerate(buckets, 1):
                lines.append(f"   {i}. {bucket}")

        secrets = self.results.get('all_secrets', [])
        if secrets:
            lines.append(f"\n📦 TOTAL SECRETS FOUND: {len(secrets)}")

        lines.append("\n" + "=" * 60)

        return '\n'.join(lines)

    def save_json_report(self, output_path: str = None) -> str:
        if not output_path:
            output_path = f"{self.apk_name}_firebase_report.json"

        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)

        return output_path


def extract_from_apk(apk_path: str) -> Dict[str, Any]:
    extractor = FirebaseExtractor(apk_path)
    results = extractor.extract_all()
    return results


def generate_summary_report(apk_path: str) -> str:
    try:
        extractor = FirebaseExtractor(apk_path)
        extractor.extract_all()
        return extractor.generate_report()
    except Exception as e:
        return f"❌ Error analyzing APK: {str(e)}"


def get_firebase_configs_only(apk_path: str) -> Dict[str, List[str]]:
    extractor = FirebaseExtractor(apk_path)
    results = extractor.extract_all()

    firebase_config = {
        "firebase_urls": list(set(results.get('firebase_urls', []))),
        "api_keys": list(set(results.get('api_keys', []) + results.get('google_api_keys', []))),
        "project_ids": list(set(results.get('project_ids', []))),
        "app_ids": list(set(results.get('app_ids', []) + results.get('google_app_id', []))),
        "storage_buckets": list(set(results.get('storage_buckets', [])))
    }
    return firebase_config


def extract_multiple_apks(apk_paths: List[str]) -> Dict[str, Any]:
    """Extract from multiple APKs in parallel"""
    all_results = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_apk = {executor.submit(extract_from_apk, path): path for path in apk_paths}
        for future in as_completed(future_to_apk):
            apk_path = future_to_apk[future]
            try:
                results = future.result()
                all_results[Path(apk_path).name] = results
            except Exception as e:
                all_results[Path(apk_path).name] = {"error": str(e)}
    return all_results
