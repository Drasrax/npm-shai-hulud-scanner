#!/usr/bin/env python3

"""
NPM Supply Chain Attack Detector
Detects supply chain vulnerabilities in NPM projects
Based on the 2025 CrowdStrike/Shai-Hulud attack
"""

import json
import os
import sys
import subprocess
import hashlib
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple
import argparse

class NPMSecurityScanner:
    def __init__(self, project_path: str = ".", verbose: bool = False):
        self.project_path = Path(project_path).resolve()
        self.verbose = verbose
        self.findings = []
        self.high_risk_packages = set()
        self.suspicious_patterns = []
        self.load_iocs()
        
        #(CrowdStrike attack 2025)
        self.known_compromised = {
            "@crowdstrike/commitlint": ["8.1.1", "8.1.2"],
            "@crowdstrike/falcon-shoelace": ["0.4.2"],
            "@crowdstrike/foundry-js": ["0.19.2"],
            "@crowdstrike/glide-core": ["0.34.2", "0.34.3"],
            "@crowdstrike/logscale-dashboard": ["1.205.2"],
            "@crowdstrike/logscale-file-editor": ["1.205.2"],
            "@crowdstrike/logscale-parser-edit": ["1.205.1", "1.205.2"],
            "tailwind-toucan-base": ["5.0.2"],
            "browser-webdriver-downloader": ["3.0.8"],
            "monorepo-next": ["13.0.2"],
            "remark-preset-lint-crowdstrike": ["4.0.2"],
            "verror-extra": ["6.0.1"],
            "yargs-help-output": ["5.0.3"],
            "eslint-config-prettier": ["*"],  # CVE-2025-54313
            "@ctrl/tinycolor": ["*"]  # Initial compromise
        }
        
        # Patterns
        self.malicious_patterns = [
            (r"process\.env\.\w+.*fetch\(", "Potential credential exfiltration"),
            (r"fs\.readFileSync.*\.ssh", "SSH key access attempt"),
            (r"fs\.readFileSync.*\.aws", "AWS credential access"),
            (r"fs\.readFileSync.*\.npmrc", "NPM token access"),
            
            (r'"postinstall".*curl.*\|.*sh', "Suspicious postinstall script"),
            (r'"preinstall".*wget.*\|.*bash', "Suspicious preinstall script"),
            (r'eval\(.*atob\(', "Obfuscated eval execution"),
            (r'eval\(.*Buffer\.from\(.*base64', "Base64 decoded eval"),
            
            (r'bundle\.js.*3\.\d+\s*MB', "Large bundled file (Shai-Hulud indicator)"),
            (r'TruffleHog|trufflehog', "TruffleHog scanner usage"),
            (r'npm.*publish.*--access.*public', "Automated npm publishing"),
            
            (r'net\.connect|tls\.connect.*\d{1,3}\.\d{1,3}', "Direct IP connection"),
            (r'dns\.resolve.*exec|spawn', "DNS resolution with command execution"),
            
            # Typosquatting indicators
            (r'crowdstrlke|cr0wdstrike|crowdstr1ke', "Potential typosquatting"),
        ]
        
        self.suspicious_domains = [
            r'npmjs\.org(?!$)',  
            r'nprnjs\.',
            r'npmj5\.',
            r'npn-js\.',
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IPs
        ]
        
        # Hash (Shai-Hulud)
        self.malicious_hashes = {
            "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6": "Shai-Hulud v1",
            "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3": "Shai-Hulud v2",
            "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e": "Shai-Hulud v3",
            "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db": "Shai-Hulud v4",
            "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c": "Shai-Hulud v5",
            "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09": "Shai-Hulud v6",
            "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777": "Shai-Hulud v7"
        }
    
    def load_iocs(self):
        """Loads IOCs from the shai-hulud-iocs.json file if available"""
        ioc_file = Path(__file__).parent / "shai-hulud-iocs.json"
        if ioc_file.exists():
            try:
                with open(ioc_file) as f:
                    iocs = json.load(f)
                    
                if "known_compromised_packages" in iocs:
                    self.known_compromised.update(iocs["known_compromised_packages"])
                    
                if "bundle_js_hashes" in iocs:
                    for version, hash_val in iocs["bundle_js_hashes"].items():
                        self.malicious_hashes[hash_val] = f"Shai-Hulud {version}"
                        
                if "malicious_code_patterns" in iocs:
                    for pattern_data in iocs["malicious_code_patterns"]:
                        self.malicious_patterns.append((pattern_data[0], pattern_data[1]))
                        
                print(f" Loaded {len(self.known_compromised)} compromised packages from IOCs")
            except Exception as e:
                if self.verbose:
                    print(f"Warning: Could not load IOCs: {e}")

    def scan(self) -> Dict:
        """Launch project scan"""
        print(f"🔍 Scanning project: {self.project_path}")
        
        results = {
            "scan_date": datetime.now().isoformat(),
            "project_path": str(self.project_path),
            "findings": [],
            "statistics": {}
        }
        
        self.check_package_files()
        
        if (self.project_path / "node_modules").exists():
            self.scan_node_modules()
        
        self.check_install_hooks()
        
        self.detect_typosquatting()
        
        self.scan_source_code()
        
        self.verify_package_integrity()
        
        self.check_github_workflows()
        
        results["findings"] = self.findings
        results["statistics"] = self.generate_statistics()
        
        return results

    def check_package_files(self):
        """Verify package.json and package-lock.json"""
        package_json = self.project_path / "package.json"
        
        if not package_json.exists():
            self.add_finding("error", "No package.json found", str(package_json))
            return
            
        try:
            with open(package_json) as f:
                pkg_data = json.load(f)
                
            for dep_type in ["dependencies", "devDependencies", "peerDependencies"]:
                if dep_type in pkg_data:
                    for pkg_name, version in pkg_data[dep_type].items():
                        self.check_compromised_package(pkg_name, version)
                        
            if "scripts" in pkg_data:
                for script_name, script_cmd in pkg_data["scripts"].items():
                    if any(hook in script_name.lower() for hook in ["preinstall", "postinstall", "prepare"]):
                        self.analyze_script(script_name, script_cmd)
                        
        except Exception as e:
            self.add_finding("error", f"Failed to parse package.json: {e}", str(package_json))

    def scan_node_modules(self):
        """Scan the node_modules folder for suspicious files"""
        node_modules = self.project_path / "node_modules"
        suspicious_files = ["bundle.js", "webpack.config.js", ".npmrc"]
        
        print("📦 Scanning node_modules...")
        
        for root, dirs, files in os.walk(node_modules):
            root_path = Path(root)
            
            if ".bin" in root or "@types" in root:
                continue
                
            for file in files:
                file_path = root_path / file
                
                if file in suspicious_files:
                    self.analyze_file(file_path)
                    
                if file.endswith(".js"):
                    try:
                        size_mb = file_path.stat().st_size / (1024 * 1024)
                        if size_mb > 3: 
                            self.add_finding(
                                "warning",
                                f"Large JS file detected ({size_mb:.1f}MB) - potential bundled malware",
                                str(file_path)
                            )
                            self.analyze_file(file_path)
                            
                        if file == "bundle.js":
                            file_hash = self.calculate_file_hash(file_path)
                            if file_hash in self.malicious_hashes:
                                self.add_finding(
                                    "critical",
                                    f"KNOWN MALICIOUS FILE: {self.malicious_hashes[file_hash]}",
                                    str(file_path),
                                    {"sha256": file_hash, "variant": self.malicious_hashes[file_hash]}
                                )
                    except:
                        pass

    def check_install_hooks(self):
        """Checks for installation hooks in all package.json"""
        print("🪝 Checking install hooks...")
        
        for pkg_json in self.project_path.rglob("package.json"):
            try:
                with open(pkg_json) as f:
                    data = json.load(f)
                    
                if "scripts" in data:
                    hooks = ["preinstall", "install", "postinstall", "prepare", "prepublish"]
                    for hook in hooks:
                        if hook in data["scripts"]:
                            script = data["scripts"][hook]
                            if self.is_suspicious_script(script):
                                self.add_finding(
                                    "critical",
                                    f"Suspicious {hook} hook detected",
                                    str(pkg_json),
                                    {"script": script}
                                )
            except:
                pass

    def detect_typosquatting(self):
        """Detects potential typosquatted packages"""
        print(" Detecting typosquatting...")
        
        # Liste de paquets populaires à vérifier
        popular_packages = [
            "react", "express", "lodash", "axios", "webpack", "babel",
            "typescript", "eslint", "jest", "prettier", "crowdstrike"
        ]
        
        package_lock = self.project_path / "package-lock.json"
        if package_lock.exists():
            try:
                with open(package_lock) as f:
                    lock_data = json.load(f)
                    
                if "packages" in lock_data:
                    for pkg_path, pkg_info in lock_data["packages"].items():
                        pkg_name = pkg_path.replace("node_modules/", "")
                        
                        for popular in popular_packages:
                            if self.is_typosquatted(pkg_name, popular):
                                self.add_finding(
                                    "critical",
                                    f"Potential typosquatting: {pkg_name} (similar to {popular})",
                                    pkg_path
                                )
            except:
                pass

    def scan_source_code(self):
        """Scan source code for malicious patterns"""
        print("Scanning source code...")
        
        extensions = [".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"]
        
        for ext in extensions:
            for file_path in self.project_path.rglob(f"*{ext}"):
                if "node_modules" not in str(file_path):
                    self.analyze_file(file_path)

    def analyze_file(self, file_path: Path):
        """Analyzes a file for malicious patterns"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                
            for pattern, description in self.malicious_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    self.add_finding(
                        "warning",
                        description,
                        str(file_path),
                        {"pattern": pattern}
                    )
                    
            for domain_pattern in self.suspicious_domains:
                if re.search(domain_pattern, content):
                    self.add_finding(
                        "critical",
                        "Suspicious domain detected",
                        str(file_path),
                        {"domain_pattern": domain_pattern}
                    )
                    
        except Exception as e:
            if self.verbose:
                print(f"Error analyzing {file_path}: {e}")

    def check_github_workflows(self):
        """Checks for suspicious GitHub workflows"""
        github_dir = self.project_path / ".github" / "workflows"
        
        if github_dir.exists():
            print(" Checking GitHub workflows...")
            
            suspicious_workflow_names = [
                "shai-hulud.yaml",
                "shai-hulud.yml", 
                "shai-hulud-workflow.yml",
                "shai-hulud-workflow.yaml"
            ]
            
            for workflow_file in github_dir.glob("*.y*ml"):
                if workflow_file.name.lower() in suspicious_workflow_names:
                    self.add_finding(
                        "critical",
                        f"SHAI-HULUD WORKFLOW DETECTED: {workflow_file.name}",
                        str(workflow_file),
                        {"attack": "Shai-Hulud", "type": "GitHub Actions persistence"}
                    )
                
                try:
                    with open(workflow_file) as f:
                        content = f.read()
                        
                    if "webhook.site/bb8ca5f6" in content:
                        self.add_finding(
                            "critical",
                            "Known Shai-Hulud exfiltration webhook in workflow",
                            str(workflow_file)
                        )
                        
                    if re.search(r"curl.*\|.*sh|wget.*\|.*bash", content):
                        self.add_finding(
                            "critical",
                            "Remote code execution in GitHub workflow",
                            str(workflow_file)
                        )
                except:
                    pass
    
    def verify_package_integrity(self):
        """integrity of installed packages"""
        print("Verifying package integrity...")
        
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=self.project_path,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0 and result.stdout:
                audit_data = json.loads(result.stdout)
                
                if "vulnerabilities" in audit_data:
                    vulns = audit_data["vulnerabilities"]
                    for vuln_id, vuln_data in vulns.items():
                        severity = vuln_data.get("severity", "unknown")
                        if severity in ["high", "critical"]:
                            self.add_finding(
                                severity,
                                f"NPM Audit: {vuln_data.get('title', 'Vulnerability detected')}",
                                vuln_id,
                                vuln_data
                            )
        except:
            pass

    def check_compromised_package(self, pkg_name: str, version: str):
        """"is listed suspicious package"""
        if pkg_name in self.known_compromised:
            compromised_versions = self.known_compromised[pkg_name]
            
            # Nettoyer la version
            clean_version = version.strip("^~>=<")
            
            if "*" in compromised_versions or clean_version in compromised_versions:
                self.add_finding(
                    "critical",
                    f"KNOWN COMPROMISED PACKAGE: {pkg_name}@{version}",
                    "package.json",
                    {"package": pkg_name, "version": version, "attack": "CrowdStrike/Shai-Hulud 2025"}
                )
                self.high_risk_packages.add(pkg_name)

    def analyze_script(self, script_name: str, script_cmd: str):
        """suspicious orders"""
        suspicious_patterns = [
            (r"curl.*\|.*sh", "Remote script execution"),
            (r"wget.*\|.*bash", "Remote script execution"),
            (r"eval\(", "Eval usage in script"),
            (r"npm.*token", "NPM token manipulation"),
            (r"npm.*publish", "Package publishing in script"),
        ]
        
        for pattern, description in suspicious_patterns:
            if re.search(pattern, script_cmd, re.IGNORECASE):
                self.add_finding(
                    "warning",
                    f"Suspicious script '{script_name}': {description}",
                    "package.json",
                    {"script": script_cmd}
                )

    def is_suspicious_script(self, script: str) -> bool:
        """Check suspicious script"""
        suspicious_keywords = [
            "curl", "wget", "eval", "base64", "atob", "Buffer.from",
            "child_process", "exec", "spawn", "npm publish"
        ]
        
        return any(keyword in script.lower() for keyword in suspicious_keywords)

    def calculate_file_hash(self, file_path: Path) -> str:
        """Calculate hash SHA-256 for file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def is_typosquatted(self, pkg_name: str, target: str) -> bool:
        if len(pkg_name) == len(target):
            differences = sum(c1 != c2 for c1, c2 in zip(pkg_name, target))
            return 0 < differences <= 2
            
        typo_patterns = [
            ("0", "o"), ("1", "i"), ("l", "i"), ("rn", "m"),
            ("-", "_"), ("_", "-")
        ]
        
        for old, new in typo_patterns:
            if pkg_name.replace(old, new) == target or pkg_name.replace(new, old) == target:
                return True
                
        return False

    def add_finding(self, severity: str, message: str, location: str, details: Dict = None):
        """Ajoute une découverte à la liste"""
        finding = {
            "severity": severity,
            "message": message,
            "location": location,
            "timestamp": datetime.now().isoformat()
        }
        
        if details:
            finding["details"] = details
            
        self.findings.append(finding)
        
        emoji = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️", "error": "❌"}.get(severity, "•")
        print(f"{emoji} [{severity.upper()}] {message}")
        if self.verbose and location:
            print(f"   Location: {location}")

    def generate_statistics(self) -> Dict:
        """Génère des statistiques sur le scan"""
        stats = {
            "total_findings": len(self.findings),
            "critical": sum(1 for f in self.findings if f["severity"] == "critical"),
            "warning": sum(1 for f in self.findings if f["severity"] == "warning"),
            "info": sum(1 for f in self.findings if f["severity"] == "info"),
            "error": sum(1 for f in self.findings if f["severity"] == "error"),
            "high_risk_packages": list(self.high_risk_packages)
        }
        
        return stats

    def generate_report(self, results: Dict, output_format: str = "json") -> str:
        """Génère un rapport des résultats"""
        if output_format == "json":
            return json.dumps(results, indent=2)
            
        elif output_format == "text":
            report = []
            report.append("=" * 60)
            report.append("NPM SUPPLY CHAIN SECURITY SCAN REPORT")
            report.append("=" * 60)
            report.append(f"Scan Date: {results['scan_date']}")
            report.append(f"Project: {results['project_path']}")
            report.append("")
            
            stats = results["statistics"]
            report.append("SUMMARY:")
            report.append(f"  Total Findings: {stats['total_findings']}")
            report.append(f"  Critical: {stats['critical']}")
            report.append(f"  Warnings: {stats['warning']}")
            report.append(f"  Info: {stats['info']}")
            report.append(f"  Errors: {stats['error']}")
            
            if stats["high_risk_packages"]:
                report.append("")
                report.append("HIGH RISK PACKAGES DETECTED:")
                for pkg in stats["high_risk_packages"]:
                    report.append(f"  • {pkg}")
            
            report.append("")
            report.append("DETAILED FINDINGS:")
            report.append("-" * 60)
            
            for finding in results["findings"]:
                report.append(f"\n[{finding['severity'].upper()}] {finding['message']}")
                report.append(f"Location: {finding['location']}")
                if "details" in finding:
                    report.append(f"Details: {json.dumps(finding['details'], indent=2)}")
                    
            return "\n".join(report)
            
        elif output_format == "markdown":
            report = []
            report.append("# NPM Supply Chain Security Scan Report")
            report.append("")
            report.append(f"**Scan Date:** {results['scan_date']}")
            report.append(f"**Project:** `{results['project_path']}`")
            report.append("")
            
            stats = results["statistics"]
            report.append("## Summary")
            report.append("")
            report.append("| Severity | Count |")
            report.append("|----------|-------|")
            report.append(f"| Critical | {stats['critical']} |")
            report.append(f"| Warning | {stats['warning']} |")
            report.append(f"| Info | {stats['info']} |")
            report.append(f"| Error | {stats['error']} |")
            report.append(f"| **Total** | **{stats['total_findings']}** |")
            
            if stats["high_risk_packages"]:
                report.append("")
                report.append("## High Risk Packages")
                for pkg in stats["high_risk_packages"]:
                    report.append(f"- `{pkg}`")
            
            report.append("")
            report.append("## Detailed Findings")
            
            for finding in results["findings"]:
                severity_emoji = {
                    "critical": "🚨",
                    "warning": "⚠️",
                    "info": "ℹ️",
                    "error": "❌"
                }.get(finding["severity"], "•")
                
                report.append("")
                report.append(f"### {severity_emoji} {finding['message']}")
                report.append(f"- **Severity:** {finding['severity']}")
                report.append(f"- **Location:** `{finding['location']}`")
                if "details" in finding:
                    report.append(f"- **Details:**")
                    report.append("```json")
                    report.append(json.dumps(finding['details'], indent=2))
                    report.append("```")
                    
            return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(
        description="NPM Supply Chain Attack Detector - Detect vulnerabilities in NPM projects"
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to the NPM project to scan (default: current directory)"
    )
    parser.add_argument(
        "-o", "--output",
        choices=["json", "text", "markdown"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "-f", "--file",
        help="Save report to file"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--webhook",
        help="Send critical findings to webhook URL"
    )
    
    args = parser.parse_args()
    
    scanner = NPMSecurityScanner(args.path, args.verbose)
    
    print("\nStarting NPM Supply Chain Security Scan...")
    print("-" * 60)
    
    results = scanner.scan()
    
    report = scanner.generate_report(results, args.output)
    
    if args.file:
        with open(args.file, "w") as f:
            f.write(report)
        print(f"\nReport saved to: {args.file}")
    else:
        print("\n" + report)
    
    if args.webhook and results["statistics"]["critical"] > 0:
        send_webhook_notification(args.webhook, results)
    
    exit_code = min(results["statistics"]["critical"], 1)
    
    print("\n" + "=" * 60)
    if exit_code == 0:
        print(" Scan completed - No critical issues found")
    else:
        print(f" Scan completed - {results['statistics']['critical']} critical issues found")
    
    sys.exit(exit_code)

def send_webhook_notification(webhook_url: str, results: Dict):
    """Envoie une notification webhook pour les findings critiques"""
    try:
        import urllib.request
        import urllib.parse
        
        critical_findings = [f for f in results["findings"] if f["severity"] == "critical"]
        
        message = {
            "text": f"NPM Security Alert: {len(critical_findings)} critical vulnerabilities detected",
            "findings": critical_findings[:5]  # 5 findings
        }
        
        data = json.dumps(message).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                print(f"Webhook notification sent successfully")
    except Exception as e:
        print(f" Failed to send webhook notification: {e}")

if __name__ == "__main__":
    main()
