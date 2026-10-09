import os
import re
import json
from typing import List, Dict, Any, Optional

# Curated vulnerability database for common high-impact CVEs in web & cloud ecosystems
KNOWN_CVE_DATABASE: List[Dict[str, Any]] = [
    {
        "ecosystem": "npm",
        "package": "lodash",
        "vulnerable_below": "4.17.21",
        "cve_id": "CVE-2021-23337",
        "severity": "HIGH",
        "cvss": 7.5,
        "title": "Command Injection in lodash.template",
        "remediation": "Upgrade lodash to >= 4.17.21",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"
    },
    {
        "ecosystem": "npm",
        "package": "axios",
        "vulnerable_below": "1.7.4",
        "cve_id": "CVE-2023-45857",
        "severity": "HIGH",
        "cvss": 7.5,
        "title": "Cross-Site Request Forgery / SSRF in Axios",
        "remediation": "Upgrade axios to >= 1.7.4",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2023-45857"
    },
    {
        "ecosystem": "npm",
        "package": "jsonwebtoken",
        "vulnerable_below": "9.0.0",
        "cve_id": "CVE-2022-23529",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "title": "Remote Code Execution via insecure secret or options verification",
        "remediation": "Upgrade jsonwebtoken to >= 9.0.0",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2022-23529"
    },
    {
        "ecosystem": "npm",
        "package": "express",
        "vulnerable_below": "4.19.2",
        "cve_id": "CVE-2024-29041",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "title": "Open Redirect vulnerability in Express res.location",
        "remediation": "Upgrade express to >= 4.19.2",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2024-29041"
    },
    {
        "ecosystem": "pypi",
        "package": "requests",
        "vulnerable_below": "2.31.0",
        "cve_id": "CVE-2023-32681",
        "severity": "MEDIUM",
        "cvss": 6.1,
        "title": "Unintended Proxy-Authorization header leak across redirects",
        "remediation": "Upgrade requests to >= 2.31.0",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"
    },
    {
        "ecosystem": "pypi",
        "package": "urllib3",
        "vulnerable_below": "2.0.7",
        "cve_id": "CVE-2023-45803",
        "severity": "HIGH",
        "cvss": 7.5,
        "title": "Request body not stripped during HTTP redirect leading to data leak",
        "remediation": "Upgrade urllib3 to >= 2.0.7",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2023-45803"
    },
    {
        "ecosystem": "pypi",
        "package": "pyyaml",
        "vulnerable_below": "5.4",
        "cve_id": "CVE-2020-14343",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "title": "Arbitrary Code Execution through yaml.load without Loader spec",
        "remediation": "Upgrade pyyaml to >= 5.4 and use safe_load",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2020-14343"
    },
    {
        "ecosystem": "pypi",
        "package": "django",
        "vulnerable_below": "4.2.11",
        "cve_id": "CVE-2024-27351",
        "severity": "HIGH",
        "cvss": 7.5,
        "title": "Regular Expression Denial of Service in django.utils.text.Truncator",
        "remediation": "Upgrade django to >= 4.2.11",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2024-27351"
    },
    {
        "ecosystem": "maven",
        "package": "log4j-core",
        "vulnerable_below": "2.17.1",
        "cve_id": "CVE-2021-44228",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "title": "Log4Shell: JNDI Remote Code Execution in Log4j",
        "remediation": "Upgrade log4j-core to >= 2.17.1",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    },
    {
        "ecosystem": "golang",
        "package": "golang.org/x/crypto",
        "vulnerable_below": "0.1.0",
        "cve_id": "CVE-2022-27191",
        "severity": "HIGH",
        "cvss": 7.5,
        "title": "Denial of Service via SSH handshake in x/crypto/ssh",
        "remediation": "Upgrade golang.org/x/crypto to >= v0.1.0",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2022-27191"
    }
]

def parse_semver(v_str: str) -> List[int]:
    clean = re.sub(r'^[^\d]*', '', v_str.strip())
    parts = []
    for p in clean.split('.'):
        digits = re.match(r'^\d+', p)
        if digits:
            parts.append(int(digits.group(0)))
        else:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return parts[:3]

def is_vulnerable(detected_ver: str, vulnerable_below: str) -> bool:
    try:
        det = parse_semver(detected_ver)
        vuln = parse_semver(vulnerable_below)
        return det < vuln
    except Exception:
        return False

class DependencyScanner:
    """
    Performs Software Composition Analysis (SCA) on working tree manifest files.
    """

    @staticmethod
    def scan_dependencies(repo_path: str) -> Dict[str, Any]:
        manifest_files_found = []
        all_dependencies = []
        vulnerabilities = []

        # 1. Inspect package.json
        pkg_json_path = os.path.join(repo_path, "package.json")
        if os.path.exists(pkg_json_path):
            manifest_files_found.append("package.json")
            try:
                with open(pkg_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    deps = {}
                    if "dependencies" in data and isinstance(data["dependencies"], dict):
                        deps.update(data["dependencies"])
                    if "devDependencies" in data and isinstance(data["devDependencies"], dict):
                        deps.update(data["devDependencies"])

                    for name, ver in deps.items():
                        clean_ver = str(ver).replace('^', '').replace('~', '').replace('>=', '').strip()
                        dep_entry = {
                            "ecosystem": "npm",
                            "name": name,
                            "version": clean_ver or "1.0.0",
                            "file": "package.json"
                        }
                        all_dependencies.append(dep_entry)

                        # Match with vulnerability database
                        for vuln_rule in KNOWN_CVE_DATABASE:
                            if vuln_rule["ecosystem"] == "npm" and vuln_rule["package"] == name.lower():
                                if is_vulnerable(clean_ver, vuln_rule["vulnerable_below"]):
                                    vulnerabilities.append({
                                        "package": name,
                                        "installed_version": clean_ver,
                                        "cve_id": vuln_rule["cve_id"],
                                        "severity": vuln_rule["severity"],
                                        "cvss": vuln_rule["cvss"],
                                        "title": vuln_rule["title"],
                                        "remediation": vuln_rule["remediation"],
                                        "advisory": vuln_rule["advisory"],
                                        "manifest_file": "package.json"
                                    })
            except Exception:
                pass

        # 2. Inspect requirements.txt
        req_txt_path = os.path.join(repo_path, "requirements.txt")
        if os.path.exists(req_txt_path):
            manifest_files_found.append("requirements.txt")
            try:
                with open(req_txt_path, "r", encoding="utf-8") as f:
                    for line in f:
                        clean = line.strip()
                        if not clean or clean.startswith("#"):
                            continue
                        m = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)?\s*([0-9a-zA-Z\.\-]+)?', clean)
                        if m:
                            pkg_name = m.group(1).lower()
                            pkg_ver = m.group(2) or "1.0.0"
                            all_dependencies.append({
                                "ecosystem": "pypi",
                                "name": pkg_name,
                                "version": pkg_ver,
                                "file": "requirements.txt"
                            })

                            for vuln_rule in KNOWN_CVE_DATABASE:
                                if vuln_rule["ecosystem"] == "pypi" and vuln_rule["package"] == pkg_name:
                                    if is_vulnerable(pkg_ver, vuln_rule["vulnerable_below"]):
                                        vulnerabilities.append({
                                            "package": pkg_name,
                                            "installed_version": pkg_ver,
                                            "cve_id": vuln_rule["cve_id"],
                                            "severity": vuln_rule["severity"],
                                            "cvss": vuln_rule["cvss"],
                                            "title": vuln_rule["title"],
                                            "remediation": vuln_rule["remediation"],
                                            "advisory": vuln_rule["advisory"],
                                            "manifest_file": "requirements.txt"
                                        })
            except Exception:
                pass

        # 3. Inspect pom.xml or go.mod if present
        go_mod_path = os.path.join(repo_path, "go.mod")
        if os.path.exists(go_mod_path):
            manifest_files_found.append("go.mod")

        pom_xml_path = os.path.join(repo_path, "pom.xml")
        if os.path.exists(pom_xml_path):
            manifest_files_found.append("pom.xml")

        # Counts
        crit_count = sum(1 for v in vulnerabilities if v["severity"] == "CRITICAL")
        high_count = sum(1 for v in vulnerabilities if v["severity"] == "HIGH")
        med_count = sum(1 for v in vulnerabilities if v["severity"] == "MEDIUM")
        low_count = sum(1 for v in vulnerabilities if v["severity"] == "LOW")

        return {
            "manifest_files": manifest_files_found,
            "total_dependencies": len(all_dependencies),
            "vulnerabilities_count": len(vulnerabilities),
            "severity_counts": {
                "CRITICAL": crit_count,
                "HIGH": high_count,
                "MEDIUM": med_count,
                "LOW": low_count
            },
            "vulnerabilities": vulnerabilities,
            "dependencies": all_dependencies[:30] # Sample up to 30 for view
        }
