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
        self.pypi_compromised = {}
        self.hijacked_actions = {}
        self.extra_payload_files = set()
        self._rules = None

        # Known compromised packages (Shai-Hulud + CVE-2025-54313)
        self.known_compromised = {
            "@crowdstrike/commitlint": ["8.1.1", "8.1.2"],
            "@crowdstrike/falcon-shoelace": ["0.4.2"],
            "@crowdstrike/foundry-js": ["0.19.2"],
            "@crowdstrike/glide-core": ["0.34.2", "0.34.3"],
            "@crowdstrike/logscale-dashboard": ["1.205.2"],
            "@crowdstrike/logscale-file-editor": ["1.205.2"],
            "@crowdstrike/logscale-parser-edit": ["1.205.1", "1.205.2"],
            "@crowdstrike/node-exporter": ["0.2.2"],
            "@crowdstrike/threat-center": ["1.205.2"],
            "tailwind-toucan-base": ["5.0.2"],
            "browser-webdriver-downloader": ["3.0.8"],
            "monorepo-next": ["13.0.2"],
            "remark-preset-lint-crowdstrike": ["4.0.2"],
            "verror-extra": ["6.0.1"],
            "yargs-help-output": ["5.0.3"],
            "@ctrl/tinycolor": ["*"],
            "eslint-config-prettier": ["8.10.1", "9.1.1", "10.1.6", "10.1.7"],
            "eslint-plugin-prettier": ["4.2.2", "4.2.3"],
            "synckit": ["0.11.9"],
            "@pkgr/core": ["0.2.8"],
            "napi-postinstall": ["0.3.1"],
            "got-fetch": ["5.1.11", "5.1.12"],
            "is": ["3.3.1", "5.0.0"]
        }
        
        self.malicious_patterns = [
            # Reading one environment variable and calling fetch is what every SDK
            # does; serialising the *whole* environment and shipping it is not.
            # The sink may come before or after the copy, and it is usually a
            # method call (axios.post) rather than a bare one, so both orders and
            # both call shapes have to be covered. Object.keys(process.env) is
            # deliberately not included: listing variable names is ordinary.
            (r"(?:(?:JSON\.stringify|Object\.(?:entries|assign))\s*\([^)\n]{0,40}process\.env\s*\)"
             r"[\s\S]{0,300}?\b(?:fetch|axios|got|request|https?\.request)(?:\.\w+)?\s*\("
             r"|\b(?:fetch|axios|got|request|https?\.request)(?:\.\w+)?\s*\("
             r"[\s\S]{0,300}?(?:JSON\.stringify|Object\.(?:entries|assign))\s*\([^)\n]{0,40}process\.env\s*\))",
             "Entire process environment serialised and sent to the network", "critical"),
            (r"fs\.readFileSync.*\.ssh", "SSH key access attempt"),
            (r"fs\.readFileSync.*\.aws", "AWS credential access"),
            (r"fs\.readFileSync.*\.npmrc", "NPM token access"),
            
            (r'"postinstall".*curl.*\|.*sh', "Suspicious postinstall script"),
            (r'"preinstall".*wget.*\|.*bash', "Suspicious preinstall script"),
            (r'eval\(.*atob\(', "Obfuscated eval execution"),
            (r'eval\(.*Buffer\.from\(.*base64', "Base64 decoded eval"),
            
            (r'bundle\.js.*3\.\d+\s*MB', "Large bundled file (Shai-Hulud indicator)"),
            # The bare name matches any mention in a comment or README snippet.
            # What matters is the worm actually running or fetching the scanner.
            (r'trufflehog(?:3)?\s+(?:filesystem|git|github|gitlab|s3|--\w)'
             r'|trufflesecurity/trufflehog/releases/download|\btrufflehog_[\d.]+_',
             "TruffleHog secret scanner invoked or downloaded", "critical"),
            # "npm publish --access public" is the standard release command for any
            # scoped package. Publishing from inside code is the worm behaviour.
            (r'(?:child_process|execSync|spawnSync|execFileSync|exec)\s*\('
             r'[^)\n]{0,120}\bnpm\s+publish\b',
             "npm publish invoked from code (worm self-propagation)"),
            
            (r'169\.254\.169\.254', "AWS metadata endpoint access"),
            (r'http://169\.254\.169\.254', "AWS IMDS full URL"),
            (r'fd00:ec2::254', "AWS metadata IPv6"),
            (r'\[fd00:ec2::254\]', "AWS metadata IPv6 brackets"),
            (r'metadata\.google\.internal', "GCP metadata endpoint"),
            (r'http://metadata\.google\.internal', "GCP metadata full URL"),
            (r'metadata\.azure\.com', "Azure metadata endpoint"),
            (r'/latest/meta-data/', "AWS IMDS path"),
            (r'/computeMetadata/v1/', "GCP metadata path"),
            
            # Ungrouped alternation before: the pattern collapsed to "net.connect"
            # and fired on any socket code. A full dotted quad is now required, and
            # loopback / link-local / RFC1918 addresses are excluded because those
            # are ordinary development configuration.
            (r'(?:net|tls)\.connect\s*\([^)\n]{0,160}?'
             r'(?!(?:127|10|0)\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)'
             r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
             "Direct connection to a hardcoded public IP"),
            # The alternation used to be ungrouped ('...exec|spawn'), so the whole
            # pattern reduced to the bare word "spawn" and fired on any package
            # that starts a child process - which is most CLI wrappers.
            (r'dns\.resolve\w*\([\s\S]{0,300}?(exec|spawn)\w*\(',
             "DNS resolution feeding command execution"),

            (r'logDiskSpace', "Scavenger malware indicator function"),
            (r'FuckOff', "Scavenger malware XOR key"),
            (r'node-gyp\.dll|loader\.dll|version\.dll|umpdc\.dll|profapi\.dll', "Scavenger malicious DLL"),
            (r'node-gyp\.so|loader\.so|version\.so|libumpdc\.so|libprofapi\.so', "Scavenger malicious SO"),
            (r'rundll32|regsvr32', "Windows DLL execution"),

            (r's1ngularity.*Nx', "s1ngularity/Nx campaign"),
            (r'MUT-8694|mut-8694', "MUT-8694 campaign"),
            (r'crypto.*wallet.*drain|metamask.*seed|ledger.*recovery', "Cryptocurrency wallet drainer"),
            (r'rxnt-authentication.*0\.0\.3', "Patient zero package"),

            (r'crowdstrlke|cr0wdstrike|crowdstr1ke', "Potential typosquatting"),
            (r'setup_bun\.js|bun_environment\.js', "Shai-Hulud 2.0 Bun payload file", "critical"),
            (r'preinstall.*bun_environment\.js', "Shai-Hulud 2.0 preinstall hook", "warning"),
            (r'Sha1-Hulud: The Second Coming', "Shai-Hulud 2.0 GitHub exfil description", "critical"),
            (r'rm -rf\s+(~|\$HOME)', "Shai-Hulud 2.0 destructive fallback wiping home", "critical"),
        ]
        
        # A match here is reported as critical, so every entry must be a host no
        # honest dependency would contact. npmjs.org is deliberately absent:
        # registry.npmjs.org is the official npm registry, and matching it flagged
        # ordinary code. The registry typosquats below cover the actual threat.
        self.suspicious_domains = [
            r'nprnjs\.',
            r'npmj5\.',
            r'npn-js\.',
            r'npnjs\.com',
            r'firebase\.su',
            r'dieorsuffer\.com',
            r'smartscreen-api\.com',
            # 2026 Mini Shai-Hulud / TeamPCP C2 & exfil infra
            r't\.m-kosche\.com',
            r'm-kosche\.com',
            r'filev2\.getsession\.org',
            r'api\.masscan\.cloud',
            r'git-tanstack\.com',
            r'audit\.checkmarx\.cx',
            # Hardcoded public IP endpoint. Loopback, link-local and RFC1918
            # ranges are excluded: those are normal development configuration,
            # and a bare dotted quad also matched four-part version strings.
            r'https?://(?!(?:127|10|0)\.|192\.168\.|169\.254\.'
            r'|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        ]
        
        # Malicious file hashes (Shai-Hulud + CVE-2025-54313)
        self.malicious_hashes = {
            "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6": "Shai-Hulud v1",
            "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3": "Shai-Hulud v2",
            "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e": "Shai-Hulud v3",
            "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db": "Shai-Hulud v4",
            "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c": "Shai-Hulud v5",
            "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09": "Shai-Hulud v6",
            "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777": "Shai-Hulud v7",
            "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0": "Shai-Hulud 2.0 bun_environment.js v1",
            "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068": "Shai-Hulud 2.0 bun_environment.js v2",
            "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd": "Shai-Hulud 2.0 bun_environment.js v3",
            "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a": "Shai-Hulud 2.0 setup_bun.js",
            "c68e42f416f482d43653f36cd14384270b54b68d6496a8e34ce887687de5b441": "Scavenger node-gyp.dll",
            "5bed39728e404838ecd679df65048abcb443f8c7a9484702a2ded60104b8c4a9": "Scavenger malware stage 2",
            "32d0dbdfef0e5520ba96a2673244267e204b94a49716ea13bf635fa9af6f66bf": "Scavenger install.js"
        }

        # Load the external IOC database LAST, once every base attribute above
        # exists (calling it earlier silently fails - the attributes it augments
        # would not be defined yet).
        self.load_iocs()

    def _is_own_file(self, file_path: Path) -> bool:
        """True for the scanner's own sources and IOC databases.

        Those files quote every campaign marker verbatim, so scanning a
        directory that contains the scanner otherwise reports the tool itself as
        malware. Matched by resolved absolute path, never by name, so a file
        called update-patterns.py in the scanned project is still analysed.
        """
        here = Path(__file__).resolve().parent
        own = {
            here / "npm-supply-chain-detector.py",
            here / "update-patterns.py",
            here / "shai-hulud-iocs.json",
            here / "malicious-patterns.json",
            here / "scan-npm-security.sh",
        }
        try:
            return file_path.resolve() in own
        except OSError:
            return False

    def load_iocs(self):
        """Loads IOCs from the shai-hulud-iocs.json file if available"""
        ioc_file = Path(__file__).parent / "shai-hulud-iocs.json"
        if not ioc_file.exists():
            return
        try:
            with open(ioc_file) as f:
                iocs = json.load(f)

            if "known_compromised_packages" in iocs:
                self.known_compromised.update(iocs["known_compromised_packages"])

            # Legacy Shai-Hulud bundle.js hashes (keyed by version label)
            if "bundle_js_hashes" in iocs:
                for version, hash_val in iocs["bundle_js_hashes"].items():
                    self.malicious_hashes[hash_val] = f"Shai-Hulud {version}"

            # Every campaign section (mini_shai_hulud_2026, pypi_hades_2026,
            # npm_campaigns_h2_2026, ...) publishes its hashes and C2 hosts under
            # the same two keys, so covering a new wave means adding a section to
            # the JSON - no change needed here. Hashes are lowercased because
            # vendor IOC tables are inconsistent about case.
            sha256_re = re.compile(r"[0-9a-fA-F]{64}")
            for section in iocs.values():
                if not isinstance(section, dict):
                    continue
                for key, value in section.get("file_hashes_sha256", {}).items():
                    # Sections disagree on orientation: most map hash -> label,
                    # the Scavenger one maps filename -> hash. Trust whichever
                    # side actually looks like a digest.
                    if sha256_re.fullmatch(str(key)):
                        self.malicious_hashes[key.lower()] = value
                    elif sha256_re.fullmatch(str(value)):
                        self.malicious_hashes[value.lower()] = key
                for domain in section.get("c2_domains", []):
                    pattern = re.escape(domain)
                    if pattern not in self.suspicious_domains:
                        self.suspicious_domains.append(pattern)

            self.pypi_compromised.update(
                iocs.get("pypi_hades_2026", {}).get("compromised_packages", {})
            )

            # GitHub Actions whose upstream tags were force-pushed to malicious
            # commits, so that adding one to the JSON is enough to cover it.
            for section in iocs.values():
                if not isinstance(section, dict):
                    continue
                for action, meta in section.get("hijacked_github_actions", {}).items():
                    note = meta.get("note", "upstream tags rewritten") if isinstance(meta, dict) else str(meta)
                    date = meta.get("date", "") if isinstance(meta, dict) else ""
                    self.hijacked_actions[action] = f"{note}{f' ({date})' if date else ''}"

            # Extra payload/loader filenames worth opening and hashing. Campaigns
            # that rotate their loader name (Flooding Dropper ships the same
            # dropper as _adapter.js, _shim.js, _bootstrap.js and a dozen more)
            # declare them here instead of hardcoding the list below. These names
            # are never a finding on their own: the file still has to match a
            # pattern or a known hash.
            for section in iocs.values():
                if not isinstance(section, dict):
                    continue
                for name in section.get("loader_filenames", []):
                    self.extra_payload_files.add(str(name))

            # Code patterns (skip ones already present to avoid duplicate findings).
            # Entries are [pattern, description, severity]; severity is preserved
            # so critical campaign markers surface as critical findings.
            if "malicious_code_patterns" in iocs:
                existing = {p[0] for p in self.malicious_patterns}
                for pattern_data in iocs["malicious_code_patterns"]:
                    if pattern_data[0] not in existing:
                        severity = pattern_data[2] if len(pattern_data) > 2 else "warning"
                        self.malicious_patterns.append((pattern_data[0], pattern_data[1], severity))
                        existing.add(pattern_data[0])

            print(f" Loaded {len(self.known_compromised)} compromised npm packages, "
                  f"{len(self.pypi_compromised)} PyPI packages, "
                  f"{len(self.malicious_hashes)} hashes from IOCs")
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

        self.check_lockfile_and_installed()

        if (self.project_path / "node_modules").exists():
            self.scan_node_modules()
        
        self.check_install_hooks()
        
        self.detect_typosquatting()
        
        self.scan_source_code()
        
        self.verify_package_integrity()

        self.check_build_scripts()

        self.check_github_workflows()

        self.check_agent_config_persistence()

        self.check_pypi_dependencies()

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
                
            for dep_type in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]:
                for pkg_name, version in (pkg_data.get(dep_type) or {}).items():
                    self.check_compromised_package(pkg_name, version)
                    # GitHub commit-pinned tarball dep (TanStack-style injection vector)
                    if isinstance(version, str) and re.match(r'github:.+#[0-9a-f]{40}$', version):
                        self.add_finding(
                            "warning",
                            f"Dependency pinned to a GitHub commit tarball: {pkg_name} -> {version}",
                            "package.json",
                            {"package": pkg_name, "ref": version}
                        )
                    self.check_offregistry_dependency(pkg_name, version, "package.json")

            if "scripts" in pkg_data:
                for script_name, script_cmd in pkg_data["scripts"].items():
                    if any(hook in script_name.lower() for hook in ["preinstall", "postinstall", "prepare"]):
                        self.analyze_script(script_name, script_cmd)

            # Run the malicious-pattern/domain engine over package.json itself so
            # injected install hooks and attacker dependencies are caught too.
            self.analyze_file(package_json)

        except Exception as e:
            self.add_finding("error", f"Failed to parse package.json: {e}", str(package_json))

    # Hosts that serve arbitrary files and are never a package registry. A
    # dependency resolved from one of these has bypassed npm entirely: no
    # registry review, no integrity history, and the bytes can be swapped at any
    # time without republishing. Private registries (Artifactory, Verdaccio,
    # GitHub Packages) are deliberately absent - those are ordinary in
    # enterprises and would drown the finding in noise.
    _FILE_HOSTS = re.compile(
        r"^https?://[^/]*?("
        r"storage\.googleapis\.com|s3[.-][\w-]*\.amazonaws\.com|s3\.amazonaws\.com"
        r"|blob\.core\.windows\.net|\.r2\.dev|\.b-cdn\.net|cdn\.discordapp\.com"
        r"|transfer\.sh|temp\.sh|file\.io|anonfiles\.com|gofile\.io|bashupload\.com"
        r"|oss-[\w-]+\.aliyuncs\.com|cos\.[\w-]+\.myqcloud\.com"
        r")",
        re.IGNORECASE,
    )
    _TARBALL_SPEC = re.compile(r"^https?://.+\.(?:tgz|tar\.gz|tar)(?:[?#].*)?$", re.IGNORECASE)

    # A registry tarball URL is what every lockfile "resolved" field holds, and
    # private registries are ordinary in enterprises. Neither is a finding; only
    # a URL that bypasses registries altogether is.
    _REGISTRY_URL = re.compile(
        r"^https?://("
        r"registry\.(?:npmjs\.org|npmjs\.com|yarnpkg\.com|npmmirror\.com)"
        r"|npm\.pkg\.github\.com|[^/]*\.jfrog\.io|[^/]*\.pkg\.dev"
        r"|[^/]*\.myget\.org|[^/]*/artifactory/|[^/]*/repository/npm"
        r"|[^/]*(?:nexus|verdaccio|npm|registry)[\w.-]*/)",
        re.IGNORECASE,
    )

    # Vendors whose GitHub organisation is worth impersonating. A package that
    # claims one as its repository while not being published under that vendor's
    # npm scope is misrepresenting where its code comes from.
    _VENDOR_ORGS = {
        "anthropics": ("@anthropic-ai/",),
        "openai": ("@openai/", "openai"),
        "googleapis": ("@google-cloud/", "@googleapis/"),
        "microsoft": ("@microsoft/", "@azure/", "@typescript/"),
        "vercel": ("@vercel/",),
        "facebook": ("@facebook/", "react", "@react-native/"),
    }

    def check_offregistry_dependency(self, pkg_name, spec, location):
        """Flag a dependency whose version spec is a direct tarball URL.

        npm accepts `"dep": "https://host/pkg.tgz"` and installs whatever bytes
        are served, running the tarball's lifecycle scripts. The August 2026
        `ltidisafe` cluster used exactly this: hollow packages at inflated 99.x
        versions whose only dependency pointed at a Google Cloud Storage bucket.
        """
        if not isinstance(spec, str) or not self._TARBALL_SPEC.match(spec.strip()):
            return
        spec = spec.strip()
        on_file_host = bool(self._FILE_HOSTS.match(spec))
        # The npm "/-/" tarball path and any registry host are normal.
        if not on_file_host and (self._REGISTRY_URL.match(spec) or "/-/" in spec):
            return
        self.add_finding(
            "critical" if on_file_host else "warning",
            f"Dependency resolved from a direct tarball URL instead of a registry: "
            f"{pkg_name} -> {spec}",
            location,
            {"package": pkg_name, "url": spec, "generic_file_host": on_file_host},
        )

    def check_declared_provenance(self, info, location):
        """Flag a package claiming a well-known vendor's repository as its own."""
        repo = info.get("repository")
        if isinstance(repo, dict):
            repo = repo.get("url")
        if not isinstance(repo, str):
            return
        match = re.search(r"github\.com[/:]([\w.-]+)/", repo)
        if not match:
            return
        org = match.group(1).lower()
        prefixes = self._VENDOR_ORGS.get(org)
        if not prefixes:
            return
        name = info.get("name") or ""
        if any(name == p or name.startswith(p) for p in prefixes):
            return
        self.add_finding(
            "warning",
            f"Package claims a {org} repository but is not published under its "
            f"scope: {name} -> {repo}",
            location,
            {"package": name, "declared_repository": repo},
        )

    def check_lockfile_and_installed(self):
        """Check TRANSITIVE dependencies against the known-compromised database.

        package.json only lists direct dependencies; a compromised package pulled
        in three levels deep never appears there. This pass covers package-lock.json
        (v1 "dependencies" tree and v2/v3 "packages" map) and the package.json of
        every installed package under node_modules.
        """
        print(" Checking lockfile and installed packages (transitive deps)...")
        seen = set()
        inflated_seen = set()

        # Dependency confusion works by publishing a public package under an
        # internal name at a version high enough to win resolution, which is why
        # so many of them land on 9999.0.0, 99.0.2 or 1.0.999. Only runs of three
        # or more nines count, plus a two-nine major: 1.99.0 is a plausible real
        # release, 1.0.999 is not. CalVer majors like 2024.1.0 are untouched.
        inflated_re = re.compile(r"^(?:9{2,}(?:\.|$)|\d+\.(?:9{3,}|\d+\.9{3,})(?:\.|$|[-+]))")

        def flag_inflated(pkg_name, version, location):
            if not pkg_name or not version or not inflated_re.match(version):
                return
            if pkg_name in self.known_compromised:
                return  # already reported as a confirmed compromise
            key = (pkg_name, version)
            if key in inflated_seen:
                return
            inflated_seen.add(key)
            self.add_finding(
                "warning",
                f"Version-inflated dependency (dependency-confusion pattern): "
                f"{pkg_name}@{version}",
                location,
                {"package": pkg_name, "version": version}
            )

        def flag(pkg_name, version, location, source):
            flag_inflated(pkg_name, version, location)
            if pkg_name not in self.known_compromised or not version:
                return
            versions = self.known_compromised[pkg_name]
            if "*" in versions or version in versions:
                key = (pkg_name, version)
                if key in seen:
                    return
                seen.add(key)
                self.add_finding(
                    "critical",
                    f"KNOWN COMPROMISED PACKAGE ({source}): {pkg_name}@{version}",
                    location,
                    {"package": pkg_name, "version": version, "source": source}
                )
                self.high_risk_packages.add(pkg_name)

        lockfile = self.project_path / "package-lock.json"
        if lockfile.exists():
            try:
                with open(lockfile) as f:
                    lock_data = json.load(f)
            except Exception:
                lock_data = None
            if lock_data:
                # Lockfile v2/v3: flat "packages" map keyed by install path
                for pkg_path, info in (lock_data.get("packages") or {}).items():
                    if not pkg_path or not isinstance(info, dict):
                        continue  # "" is the root project itself
                    name = info.get("name") or pkg_path.split("node_modules/")[-1]
                    flag(name, info.get("version"), "package-lock.json", "lockfile")
                    self.check_offregistry_dependency(
                        name, info.get("resolved"), "package-lock.json")

                # Lockfile v1: nested "dependencies" tree
                def walk_deps(deps):
                    for name, info in (deps or {}).items():
                        if not isinstance(info, dict):
                            continue
                        flag(name, info.get("version"), "package-lock.json", "lockfile")
                        self.check_offregistry_dependency(
                            name, info.get("resolved"), "package-lock.json")
                        walk_deps(info.get("dependencies"))
                walk_deps(lock_data.get("dependencies"))

        node_modules = self.project_path / "node_modules"
        if node_modules.exists():
            for pkg_json in node_modules.rglob("package.json"):
                parent = pkg_json.parent
                # Only package roots: node_modules/<name> or node_modules/@scope/<name>
                is_root = parent.parent.name == "node_modules" or (
                    parent.parent.name.startswith("@")
                    and parent.parent.parent.name == "node_modules"
                )
                if not is_root:
                    continue
                try:
                    with open(pkg_json) as f:
                        info = json.load(f)
                except Exception:
                    continue
                if isinstance(info, dict):
                    flag(info.get("name"), info.get("version"), str(pkg_json), "installed")
                    self.check_declared_provenance(info, str(pkg_json))
                    # This file is already open, so hashing it is nearly free -
                    # and the hollow dependency-confusion lures are identified by
                    # their package.json rather than by any code they ship.
                    self.check_known_hash(pkg_json)
                    for dep_type in ("dependencies", "optionalDependencies"):
                        for dep, spec in (info.get(dep_type) or {}).items():
                            self.check_offregistry_dependency(dep, spec, str(pkg_json))

    def scan_node_modules(self):
        """Scan the node_modules folder for suspicious files"""
        node_modules = self.project_path / "node_modules"
        suspicious_files = [
            "bundle.js", "bun_environment.js", "setup_bun.js", "webpack.config.js", ".npmrc",
            # 2026 Mini Shai-Hulud / TeamPCP payload & loader filenames
            "setup.mjs", "execution.js", "bw1.js", "bw_setup.js",
            "router_init.js", "tanstack_runner.js", "_index.js",
            # June-July 2026 campaigns (Mastra, IronWorm/jscrambler, aone-cli)
            "protocal.cjs", "setup.cjs", "intro.js", "aone-cli.js",
            # August 2026: ChainDrop stage 2, Flooding Dropper cover-story module
            "Math_Symbol.js", "math_init.js", "telemetry.js",
        ]
        # Loader names declared by the IOC file (Flooding Dropper rotates through
        # a dozen of them). Opening the file is harmless - it is only reported if
        # a pattern or a known hash matches.
        suspicious_files += sorted(self.extra_payload_files)
        # Exact-hash lookups carry no false-positive risk, so this set can also
        # cover ordinary bundle filenames - that is how the Joyfill implants,
        # which live inside dist bundles rather than a dedicated payload file,
        # get caught.
        hash_check_files = {
            "bundle.js", "bun_environment.js", "setup_bun.js",
            "setup.mjs", "execution.js", "bw1.js", "bw_setup.js",
            "router_init.js", "tanstack_runner.js", "_index.js",
            "protocal.cjs", "setup.cjs", "intro.js", "aone-cli.js",
            "index.cjs.js", "index.es.js", "index.esm.js", "joyfill.min.js",
            "Math_Symbol.js", "math_init.js",
        }
        hash_check_files |= self.extra_payload_files
        
        print(" Scanning node_modules...")
        
        for root, dirs, files in os.walk(node_modules):
            root_path = Path(root)
            
            if ".bin" in root or "@types" in root:
                continue
                
            for file in files:
                file_path = root_path / file
                
                if file in suspicious_files:
                    self.analyze_file(file_path)
                    
                # Hash first, and independently of the extension: the 2026
                # payloads ship as .cjs as well as .js.
                if file in hash_check_files:
                    try:
                        file_hash = self.calculate_file_hash(file_path)
                    except Exception:
                        file_hash = None
                    if file_hash and file_hash.lower() in self.malicious_hashes:
                        variant = self.malicious_hashes[file_hash.lower()]
                        self.add_finding(
                            "critical",
                            f"KNOWN MALICIOUS FILE: {variant}",
                            str(file_path),
                            {"sha256": file_hash, "variant": variant}
                        )

                if file.endswith((".js", ".cjs", ".mjs")):
                    try:
                        size_mb = file_path.stat().st_size / (1024 * 1024)
                        if size_mb > 3:
                            self.add_finding(
                                "warning",
                                f"Large JS file detected ({size_mb:.1f}MB) - potential bundled malware",
                                str(file_path)
                            )
                            self.analyze_file(file_path)
                    except Exception:
                        pass

        self.scan_package_entry_points(node_modules, suspicious_files)

    def scan_package_entry_points(self, node_modules, already_scanned):
        """Analyse the entry point of every installed package.

        Implants that run at import time do not sit in a file with a suspicious
        name: the jscrambler and Joyfill payloads shipped inside the dist bundle
        named by "main", and the Flooding Dropper's index.js is a one-line
        require of the dropper. Neither has an install hook, so nothing else in
        this scanner would open them. One file per package keeps the cost
        bounded - pattern-matching everything under node_modules would not be.
        """
        # Names the node_modules walk already opens, so they are not analysed twice.
        skip_names = set(already_scanned)
        seen = set()
        for pkg_json in node_modules.rglob("package.json"):
            parent = pkg_json.parent
            is_root = parent.parent.name == "node_modules" or (
                parent.parent.name.startswith("@")
                and parent.parent.parent.name == "node_modules"
            )
            if not is_root or "@types" in str(parent):
                continue
            try:
                with open(pkg_json) as f:
                    info = json.load(f)
            except Exception:
                continue
            if not isinstance(info, dict):
                continue

            candidates = []
            main = info.get("main")
            if isinstance(main, str) and main.strip():
                candidates.append(main.strip())
            candidates.append("index.js")

            for rel in candidates:
                try:
                    target = (parent / rel).resolve()
                    if target.is_dir():
                        target = target / "index.js"
                    # "main" is attacker-controlled text; never follow it out of
                    # the package directory.
                    target.relative_to(parent.resolve())
                    if target.name in skip_names or target in seen:
                        continue
                    if not target.is_file():
                        continue
                    # Anything over 3MB was already analysed by the walk above.
                    if target.stat().st_size > 3 * 1024 * 1024:
                        continue
                except Exception:
                    continue
                self.analyze_file(target)
                self.check_known_hash(target)
                seen.add(target)
                break

    def check_install_hooks(self):
        """Checks for installation hooks in all package.json"""
        print(" Checking install hooks...")
        
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
        
        # Python and .pth are included because the Hades PyPI wave hides its
        # startup hook in a *-setup.pth file and the aone-cli cluster injects
        # into the .skills Python scripts of AI developer tools.
        extensions = [".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".py", ".pth"]

        for ext in extensions:
            for file_path in self.project_path.rglob(f"*{ext}"):
                if "node_modules" not in str(file_path):
                    self.analyze_file(file_path)

    # Escapes that stand for a character class rather than a literal character.
    _CLASS_ESCAPES = set("dDwWsSbBAZnrtfvNxuU0123456789")
    _REGEX_META = set("([{|?*+.^$")

    @staticmethod
    def _has_top_level_alternation(pattern: str) -> bool:
        """True if the pattern has a | outside any group or character class."""
        depth = i = 0
        in_class = False
        while i < len(pattern):
            char = pattern[i]
            if char == "\\":
                i += 2
                continue
            if in_class:
                if char == "]":
                    in_class = False
            elif char == "[":
                in_class = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char == "|" and depth == 0:
                return True
            i += 1
        return False

    @classmethod
    def _required_prefix(cls, pattern: str):
        """Return a lowercase literal every match of `pattern` must start with.

        Roughly three quarters of the pattern set begins with a distinctive
        literal (Math_Symbol, dotnet_diag_, metadata\\.tencentyun\\.com, ...).
        Testing that substring first lets the regex engine skip the file
        entirely, which matters now that a per-package entry point is analysed.
        Returns None when no safe prefix can be derived, in which case the
        pattern is simply always run.
        """
        if cls._has_top_level_alternation(pattern):
            # Only the first branch starts with that literal; the others do not.
            return None
        out, i = [], 0
        while i < len(pattern):
            char = pattern[i]
            if char == "\\":
                if i + 1 >= len(pattern):
                    break
                nxt = pattern[i + 1]
                if nxt in cls._CLASS_ESCAPES:
                    break
                out.append(nxt)
                i += 2
                continue
            if char in cls._REGEX_META:
                break
            out.append(char)
            i += 1
        # A trailing character governed by ?, * or {0,n} is optional, so it
        # cannot be part of a required prefix.
        if out and i < len(pattern) and (pattern[i] in "?*" or pattern.startswith("{0", i)):
            out.pop()
        prefix = "".join(out)
        return prefix.lower() if len(prefix) >= 4 else None

    def check_known_hash(self, file_path: Path):
        """Report the file if its SHA-256 is a known malicious payload.

        An exact digest cannot false-positive, so this is safe to run on any
        file the scanner already has open.
        """
        try:
            digest = self.calculate_file_hash(file_path)
        except Exception:
            return
        if not digest:
            return
        variant = self.malicious_hashes.get(digest.lower())
        if variant:
            self.add_finding(
                "critical",
                f"KNOWN MALICIOUS FILE: {variant}",
                str(file_path),
                {"sha256": digest, "variant": variant},
            )

    def _compiled_rules(self):
        """Compile the pattern set once instead of on every file.

        Scanning a package entry point per installed dependency means the whole
        set runs thousands of times on a real tree, so the per-call compile cache
        lookup stops being free. Most C2 entries are re.escape()d literals, which
        a substring test settles far faster than the regex engine. A pattern that
        will not compile is dropped here rather than silently aborting the
        analysis of whichever file happened to hit it first.
        """
        if self._rules is None:
            rules = []
            for entry in self.malicious_patterns:
                severity = entry[2] if len(entry) > 2 else "warning"
                try:
                    rules.append((re.compile(entry[0], re.IGNORECASE),
                                  entry[1], severity, entry[0],
                                  self._required_prefix(entry[0])))
                except re.error as exc:
                    print(f" Skipping uncompilable pattern {entry[0]!r}: {exc}")
            literals, regexes = [], []
            for raw in self.suspicious_domains:
                unescaped = re.sub(r"\\(.)", r"\1", raw)
                if re.escape(unescaped) == raw:
                    literals.append((unescaped, raw))
                else:
                    try:
                        regexes.append((re.compile(raw), raw))
                    except re.error as exc:
                        print(f" Skipping uncompilable domain {raw!r}: {exc}")
            self._rules = (rules, literals, regexes)
        return self._rules

    def analyze_file(self, file_path: Path):
        """Analyzes a file for malicious patterns"""
        if self._is_own_file(file_path):
            return
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            rules, domain_literals, domain_regexes = self._compiled_rules()
            lowered = content.lower()

            for regex, description, severity, raw, prefix in rules:
                if prefix is not None and prefix not in lowered:
                    continue
                if regex.search(content):
                    self.add_finding(
                        severity,
                        description,
                        str(file_path),
                        {"pattern": raw}
                    )

            for literal, raw in domain_literals:
                if literal in content:  # domains are matched case-sensitively
                    self.add_finding(
                        "critical",
                        "Suspicious domain detected",
                        str(file_path),
                        {"domain_pattern": raw}
                    )
            for regex, raw in domain_regexes:
                if regex.search(content):
                    self.add_finding(
                        "critical",
                        "Suspicious domain detected",
                        str(file_path),
                        {"domain_pattern": raw}
                    )


        except Exception as e:
            if self.verbose:
                print(f"Error analyzing {file_path}: {e}")

    def check_build_scripts(self):
        """Inspect binding.gyp files for install-time command execution.

        The Miasma "Phantom Gyp" wave hides its loader in a binding.gyp rather
        than in a package.json script, because node-gyp evaluates GYP command
        expansion - `<!(cmd)` - while building. That runs even under
        `npm install --ignore-scripts` and under npm v12, which blocks lifecycle
        scripts by default. A pure-JS package shipping a binding.gyp that
        executes an interpreter and compiles nothing is the giveaway.
        """
        print(" Checking build scripts (binding.gyp)...")

        gyp_files = list(self.project_path.rglob("binding.gyp"))
        if not gyp_files:
            return

        # Legitimate addons use <!(...) to print a value: sharp resolves its
        # libvips paths with <!(node -p "require('../dist/libvips.cjs').x"), and
        # node-addon-api consumers do the same for include dirs. Matching a
        # script-file extension anywhere in the expansion flagged all of those.
        #
        # What separates Phantom Gyp is the *shape* of the command: it runs a
        # script file rather than printing an expression, chains shell commands,
        # or reaches outside its own package.
        # For a language runtime, -p/-e/-c introduce a quoted expression to
        # evaluate and print: sharp prints a require(), python prints a sysconfig
        # path, and a ";" inside that expression is language syntax rather than
        # shell chaining. For a shell, -c introduces a real command line, so no
        # such exemption applies there.
        runtime = r"(?:node|nodejs|bun|deno|python3?|perl|ruby)"
        shell = r"(?:sh|bash|zsh|npx|curl|wget|eval)"
        exec_expansion = re.compile(
            r"<!@?\(\s*(?:sudo\s+)?"
            r"(?:" + runtime + r"\b(?!\s+(?:-p|-e|-c|--print|--eval)\b)"
            r"|" + shell + r"\b)"
            r"(?:"
            # a script file executed directly
            r"[^)\n]*?\.(?:js|mjs|cjs|ts|py|sh|pl|rb)\b"
            r"|"
            # or shell chaining / output suppression
            r"[^)\n]*?(?:&&|\|\||;|>\s*/dev/null)"
            r")"
            r"[^)\n]*\)"
        )
        # A printed expression is exempt from the shape rules above, so it still
        # has to be checked for the things a value lookup never does.
        expression_exec = re.compile(
            r"<!@?\([^)\n]{0,60}?\s-{1,2}(?:p|e|c|print|eval)\b[^)\n]{0,200}?"
            r"(?:os\.system|subprocess|child_process|execSync|spawnSync"
            r"|\|\s*(?:sh|bash)\b|curl\s|wget\s|\.\./\.\./)"
        )
        # A build file has no business reaching above its own package root;
        # node-gyp already runs one level down, so "../" is normal and "../../"
        # is not.
        escapes_package = re.compile(r"<!@?\([^)\n]{0,200}(?:\.\./\.\./|/tmp/|\$HOME|%TEMP%)")
        compiles_nothing = re.compile(r'"type"\s*:\s*"none"')

        for gyp in gyp_files:
            try:
                content = gyp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            match = (exec_expansion.search(content)
                     or expression_exec.search(content)
                     or escapes_package.search(content))
            if match:
                self.add_finding(
                    "critical",
                    "Install-time command execution in binding.gyp "
                    "(Phantom Gyp - runs even with --ignore-scripts)",
                    str(gyp),
                    {"expansion": match.group(0)[:200]}
                )
            elif ("<!(" in content or "<!@(" in content) and compiles_nothing.search(content):
                # Bare command expansion is normal - node-addon-api users locate
                # their headers that way - so it is only reported when the target
                # compiles nothing at all, which no real addon does.
                self.add_finding(
                    "critical",
                    "binding.gyp runs a shell command while compiling nothing "
                    "(type: none) - build step used purely for execution",
                    str(gyp)
                )

            self.analyze_file(gyp)

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

            # Actions whose upstream tags were rewritten to point at malicious
            # commits. Referencing them by tag resolves to the imposter code, so
            # only a full 40-character commit SHA is safe. The list comes from
            # the IOC database, with a fallback for a missing or stale one.
            hijacked_actions = dict(self.hijacked_actions) or {
                "codfish/semantic-release-action":
                    "tags rewritten 2026-06-24 to deliver the Miasma loader",
            }

            for workflow_file in github_dir.glob("*.y*ml"):
                if workflow_file.name.lower() in suspicious_workflow_names:
                    self.add_finding(
                        "critical",
                        f"SHAI-HULUD WORKFLOW DETECTED: {workflow_file.name}",
                        str(workflow_file),
                        {"attack": "Shai-Hulud", "type": "GitHub Actions persistence"}
                    )

                try:
                    wf_content = workflow_file.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                for action, why in hijacked_actions.items():
                    for ref in re.finditer(
                        re.escape(action) + r"@(?P<ref>[^\s\"'#]+)", wf_content
                    ):
                        pinned = re.fullmatch(r"[0-9a-f]{40}", ref.group("ref"))
                        self.add_finding(
                            "warning" if pinned else "critical",
                            f"Compromised GitHub Action referenced: {action} ({why})",
                            str(workflow_file),
                            {
                                "action": action,
                                "ref": ref.group("ref"),
                                "pinned_to_sha": bool(pinned),
                            }
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

                    # Shai-Hulud 2.0 self-hosted runner abused as C2
                    if "SHA1HULUD" in content or "actions-runner-linux-x64-2.330.0" in content:
                        self.add_finding(
                            "critical",
                            "Shai-Hulud self-hosted runner / C2 marker in workflow",
                            str(workflow_file)
                        )

                    # Command injection via attacker-controlled discussion/issue body
                    if re.search(r"\$\{\{\s*github\.event\.(discussion|issue)\.body\s*\}\}", content):
                        self.add_finding(
                            "critical",
                            "Untrusted github.event.*.body interpolated into workflow run (injection)",
                            str(workflow_file)
                        )

                    # Apply the full malicious-pattern/domain engine to the workflow
                    self.analyze_file(workflow_file)
                except:
                    pass

    def check_agent_config_persistence(self):
        """Detect malware persistence written into agent/IDE config files.

        The 2026 Mini Shai-Hulud waves drop Bun loaders (setup.mjs/execution.js)
        and wire them into editor/agent configs so they re-run on folder open and
        survive `npm uninstall`. Only configs that actually reference those loaders
        are flagged - legitimate configs are left untouched.
        """
        print(" Checking agent/IDE config persistence...")

        config_files = [
            ".claude/settings.json", ".claude/settings.local.json",
            ".vscode/tasks.json", ".cursor/settings.json", ".cursor/tasks.json",
            # AI instruction files. The TrapDoor campaign poisons these with
            # attacker instructions - often hidden behind zero-width or
            # bidirectional Unicode - so the agent itself exfiltrates secrets.
            "CLAUDE.md", ".claude/CLAUDE.md", "AGENTS.md",
            ".cursorrules", ".cursor/rules", ".windsurfrules",
            ".github/copilot-instructions.md",
        ]
        for rel in config_files:
            cfg = self.project_path / rel
            if cfg.exists() and cfg.is_file():
                self.analyze_file(cfg)

        # Filenames unique to the campaigns: their presence alone is damning.
        loader_names = {"setup.mjs", "execution.js", "router_init.js",
                        "router_runtime.js", "tanstack_runner.js", "_index.js"}
        # Names the Miasma waves also drop, but which a project could plausibly
        # own. Reported only when the file looks like a payload rather than on
        # the name alone.
        ambiguous_names = {"index.js", "setup.js"}

        for d in [".claude", ".vscode", ".cursor", ".gemini", ".github"]:
            dpath = self.project_path / d
            if not dpath.exists():
                continue
            for f in dpath.iterdir():
                if not f.is_file():
                    continue
                if f.name in loader_names:
                    self.add_finding(
                        "critical",
                        f"Malware loader dropped in {d}/ ({f.name}) - agent/IDE persistence",
                        str(f),
                        {"campaign": "Mini Shai-Hulud"}
                    )
                    self.analyze_file(f)
                elif f.name in ambiguous_names:
                    # The Miasma droppers are single-line obfuscated blobs of
                    # several megabytes; a hand-written helper is not.
                    try:
                        size_mb = f.stat().st_size / (1024 * 1024)
                    except OSError:
                        size_mb = 0
                    if size_mb > 1:
                        self.add_finding(
                            "critical",
                            f"Large obfuscated script in {d}/ ({f.name}, {size_mb:.1f}MB) "
                            "- Miasma agent/IDE persistence",
                            str(f),
                            {"campaign": "Miasma", "size_mb": round(size_mb, 1)}
                        )
                    self.analyze_file(f)

    def check_pypi_dependencies(self):
        """Cross-ecosystem coverage: scan Python manifests for Hades-wave
        compromised PyPI packages, malicious *.pth startup hooks, and _index.js
        payloads."""
        print(" Checking PyPI dependencies (Hades wave)...")

        if self.pypi_compromised:
            manifests = ["requirements.txt", "requirements-dev.txt", "pyproject.toml",
                         "setup.py", "setup.cfg", "Pipfile"]
            seen = set()
            for name in manifests:
                for path in self.project_path.rglob(name):
                    if "node_modules" in str(path):
                        continue
                    try:
                        text = path.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue
                    for pkg, versions in self.pypi_compromised.items():
                        for m in re.finditer(
                            rf'(?im)(?<![\w.\-]){re.escape(pkg)}\s*[=~!<>]=\s*["\']?([0-9][\w.\-]*)',
                            text
                        ):
                            ver = m.group(1)
                            if ver in versions and (str(path), pkg, ver) not in seen:
                                seen.add((str(path), pkg, ver))
                                self.add_finding(
                                    "critical",
                                    f"KNOWN COMPROMISED PyPI PACKAGE: {pkg}=={ver}",
                                    str(path),
                                    {"package": pkg, "version": ver, "attack": "Shai-Hulud Hades (PyPI)"}
                                )

        # Malicious Python startup hook: a *.pth that executes a Bun loader.
        for pth in self.project_path.rglob("*.pth"):
            if "node_modules" in str(pth):
                continue
            try:
                text = pth.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if re.search(r'^\s*import\s', text, re.MULTILINE) and \
               re.search(r'_index\.js|\.bun_ran|bun-v1\.3\.13|urlretrieve|subprocess', text):
                self.add_finding(
                    "critical",
                    "Malicious Python .pth startup hook executing a Bun loader (Hades wave)",
                    str(pth)
                )

        # _index.js payloads anywhere (hash-verified)
        for idx in self.project_path.rglob("_index.js"):
            if "node_modules" in str(idx):
                continue
            try:
                h = self.calculate_file_hash(idx)
            except Exception:
                continue
            if h in self.malicious_hashes:
                self.add_finding(
                    "critical",
                    f"KNOWN MALICIOUS FILE: {self.malicious_hashes[h]}",
                    str(idx),
                    {"sha256": h}
                )

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
            (r"bun\s+(run\s+)?(index|execution|setup|router_init|tanstack_runner)",
             "Bun loader invoked in install hook (Mini Shai-Hulud)"),
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
            "child_process", "exec", "spawn", "npm publish",
            "bun run", "setup.mjs", "execution.js", "_index.js"
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
        finding = {
            "severity": severity,
            "message": message,
            "location": location,
            "timestamp": datetime.now().isoformat()
        }
        
        if details:
            finding["details"] = details
            
        self.findings.append(finding)
        
        emoji = {"critical": "🚨", "high": "❗", "warning": "⚠️", "info": "ℹ️", "error": "❌"}.get(severity, "•")
        print(f"{emoji} [{severity.upper()}] {message}")
        if self.verbose and location:
            print(f"   Location: {location}")

    def generate_statistics(self) -> Dict:
        """Scan stats"""
        stats = {
            "total_findings": len(self.findings),
            "critical": sum(1 for f in self.findings if f["severity"] == "critical"),
            "high": sum(1 for f in self.findings if f["severity"] == "high"),
            "warning": sum(1 for f in self.findings if f["severity"] == "warning"),
            "info": sum(1 for f in self.findings if f["severity"] == "info"),
            "error": sum(1 for f in self.findings if f["severity"] == "error"),
            "high_risk_packages": list(self.high_risk_packages)
        }
        
        return stats

    def generate_report(self, results: Dict, output_format: str = "json") -> str:
        """Report"""
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
            report.append(f"  High: {stats.get('high', 0)}")
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
            report.append(f"| High | {stats.get('high', 0)} |")
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
