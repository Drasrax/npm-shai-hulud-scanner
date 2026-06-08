#!/usr/bin/env python3
"""
Incrementally update Shai-Hulud IOCs with newly reported compromised libraries.

The script keeps existing data intact (malicious patterns, hashes, timelines),
and only amends the `known_compromised_packages` plus the running total.
"""

import json
import re
from pathlib import Path
from typing import Dict, List

IOC_PATH = Path(__file__).with_name("shai-hulud-iocs.json")

# Newly reported Shai-Hulud-compromised packages (September/November 2025 follow-up).
NEW_SHAI_PACKAGES: Dict[str, List[str]] = {
    "@crowdstrike/node-exporter": ["0.2.2"],
    "@crowdstrike/threat-center": ["1.205.2"],
    "tailwind-toucan-base": ["5.0.2"],
}

# CVE-2025-54313 packages (Scavenger malware) kept in a dedicated section,
# but we also surface them in the main known list to catch them during scans.
CVE_2025_54313_PACKAGES: Dict[str, List[str]] = {
    "eslint-config-prettier": ["8.10.1", "9.1.1", "10.1.6", "10.1.7"],
    "eslint-plugin-prettier": ["4.2.2", "4.2.3"],
    "synckit": ["0.11.9"],
    "@pkgr/core": ["0.2.8"],
    "napi-postinstall": ["0.3.1"],
    "got-fetch": ["5.1.11", "5.1.12"],
    "is": ["3.3.1", "5.0.0"],
}

# Shai-Hulud 2.0 payload hashes (Unit42, Nov 25 2025)
NEW_PAYLOAD_HASHES = {
    # bun_environment.js variants (Unit42 Nov 2025)
    "version_8_bun_environment": "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0",
    "version_9_bun_environment": "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068",
    "version_10_bun_environment": "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd",
    # setup_bun.js
    "version_11_setup_bun": "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a",
}

# Shai-Hulud 2.0 patterns (preinstall payloads, destructive fallback, GitHub exfil)
NEW_MALICIOUS_PATTERNS = [
    (r"setup_bun\\.js|bun_environment\\.js", "Shai-Hulud 2.0 Bun installer payload", "critical"),
    (r"Sha1-Hulud: The Second Coming", "Shai-Hulud 2.0 GitHub exfil description", "critical"),
    (r"rm -rf\\s+(~|\\$HOME)", "Shai-Hulud 2.0 destructive fallback wiping home directory", "critical"),
    (r"preinstall.*bun_environment\\.js", "Shai-Hulud 2.0 preinstall hook pulling Bun payload", "warning"),
]

# ===========================================================================
# Mini Shai-Hulud / TeamPCP family (April-June 2026)
# Source-verified IOCs (StepSecurity, JFrog, Snyk, Socket, Wiz, Microsoft).
# All hashes cross-checked against primary IOC tables on 2026-06-08.
# ===========================================================================

# New npm packages/versions across the 2026 waves -> known_compromised_packages
NEW_2026_NPM_PACKAGES = {
    # --- SAP CAP wave (2026-04-29, StepSecurity/Onapsis/Wiz) ---
    "mbt": ["1.2.48"],
    "@cap-js/sqlite": ["2.2.2"],
    "@cap-js/postgres": ["2.2.2"],
    "@cap-js/db-service": ["2.10.1"],
    # --- Bitwarden CLI wave (2026-04-22, JFrog/Bitwarden; "The Third Coming") ---
    "@bitwarden/cli": ["2026.4.0"],
    # --- TanStack wave (2026-05-11, CVE-2026-45321, Snyk/GHSA-g7cv-rxg3-hmpx) ---
    "@tanstack/react-router": ["1.169.5", "1.169.8"],
    "@tanstack/vue-router": ["1.169.5", "1.169.8"],
    "@tanstack/solid-router": ["1.169.5", "1.169.8"],
    "@tanstack/router-core": ["1.169.5", "1.169.8"],
    "@tanstack/react-start": ["1.167.68", "1.167.71"],
    "@tanstack/router-plugin": ["1.167.38", "1.167.41"],
    "@tanstack/history": ["1.161.9", "1.161.12"],
    # --- TanStack secondary self-propagation victims ---
    "@mistralai/mistralai": ["2.2.2", "2.2.3", "2.2.4"],
    "@uipath/cli": ["1.0.1"],
    "@squawk/mcp": ["0.9.1", "0.9.2", "0.9.3", "0.9.4"],
    # --- AntV wave (2026-05-19, Socket/StepSecurity/Microsoft; "Here We Go Again") ---
    "@antv/g2": ["5.5.8", "5.6.8"],
    "@antv/g6": ["5.2.1", "5.3.1"],
    "@antv/l7": ["2.26.10", "2.27.10"],
    "@antv/s2": ["2.8.1", "2.9.1"],
    "timeago.js": ["4.1.2", "4.2.2"],
    "echarts-for-react": ["3.0.7", "3.1.7", "3.2.7"],
    "jest-canvas-mock": ["2.5.3", "2.6.3", "2.7.3"],
    "size-sensor": ["1.0.4", "1.1.4", "1.2.4"],
    "canvas-nest.js": ["2.1.4", "2.2.4"],
    # --- Miasma wave (2026-06-01, JFrog/Wiz/Aikido; @redhat-cloud-services) ---
    "@redhat-cloud-services/chrome": ["2.3.1", "2.3.2", "2.3.4"],
    "@redhat-cloud-services/compliance-client": ["4.0.3", "4.0.4", "4.0.6"],
    "@redhat-cloud-services/config-manager-client": ["5.0.4", "5.0.5", "5.0.7"],
    "@redhat-cloud-services/entitlements-client": ["4.0.11", "4.0.12", "4.0.14"],
    "@redhat-cloud-services/eslint-config-redhat-cloud-services": ["3.2.1", "3.2.2", "3.2.4"],
    "@redhat-cloud-services/frontend-components": ["7.7.2", "7.7.3", "7.7.5"],
    "@redhat-cloud-services/frontend-components-advisor-components": ["3.8.2", "3.8.4", "3.8.6"],
    "@redhat-cloud-services/frontend-components-config": ["6.11.3", "6.11.4", "6.11.6"],
    "@redhat-cloud-services/frontend-components-config-utilities": ["4.11.2", "4.11.3", "4.11.5"],
    "@redhat-cloud-services/frontend-components-notifications": ["6.9.2", "6.9.3", "6.9.5"],
    "@redhat-cloud-services/frontend-components-remediations": ["4.9.2", "4.9.3", "4.9.5"],
    "@redhat-cloud-services/frontend-components-testing": ["1.2.1", "1.2.2", "1.2.4"],
    "@redhat-cloud-services/frontend-components-translations": ["4.4.1", "4.4.2", "4.4.4"],
    "@redhat-cloud-services/frontend-components-utilities": ["7.4.1", "7.4.2", "7.4.4"],
    "@redhat-cloud-services/hcc-feo-mcp": ["0.3.1", "0.3.2", "0.3.4"],
    "@redhat-cloud-services/hcc-kessel-mcp": ["0.3.1", "0.3.2", "0.3.4"],
    "@redhat-cloud-services/hcc-pf-mcp": ["0.6.1", "0.6.2", "0.6.4"],
    "@redhat-cloud-services/host-inventory-client": ["5.0.3", "5.0.4", "5.0.6"],
    "@redhat-cloud-services/insights-client": ["4.0.4", "4.0.5", "4.0.7"],
    "@redhat-cloud-services/integrations-client": ["6.0.4", "6.0.5", "6.0.7"],
    "@redhat-cloud-services/javascript-clients-shared": ["2.0.8", "2.0.9", "2.0.11"],
    "@redhat-cloud-services/notifications-client": ["6.1.4", "6.1.5", "6.1.7"],
    "@redhat-cloud-services/patch-client": ["4.0.4", "4.0.5", "4.0.7"],
    "@redhat-cloud-services/quickstarts-client": ["4.0.11", "4.0.12", "4.0.14"],
    "@redhat-cloud-services/rbac-client": ["9.0.3", "9.0.4", "9.0.6"],
    "@redhat-cloud-services/remediations-client": ["4.0.4", "4.0.5", "4.0.7"],
    "@redhat-cloud-services/rule-components": ["4.7.2", "4.7.3", "4.7.5"],
    "@redhat-cloud-services/sources-client": ["3.0.10", "3.0.11", "3.0.13"],
    "@redhat-cloud-services/topological-inventory-client": ["3.0.10", "3.0.11", "3.0.13"],
    "@redhat-cloud-services/tsc-transform-imports": ["1.2.2", "1.2.4", "1.2.6"],
    "@redhat-cloud-services/types": ["3.6.1", "3.6.2", "3.6.4"],
    "@redhat-cloud-services/vulnerabilities-client": ["2.1.8", "2.1.9", "2.1.11"],
    "@vapi-ai/server-sdk": ["0.11.1", "0.11.2", "1.2.1", "1.2.2"],
}

# Confirmed SHA-256 hashes for the 2026 family (hash -> human label).
# Hashes are exact-match IOCs: a wrong entry can only ever fail to match,
# never produce a false positive, so all attributed hashes are safe to ship.
MINI_SHAI_HULUD_HASHES = {
    "4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34": "Mini Shai-Hulud SAP CAP setup.mjs loader",
    "80a3d2877813968ef847ae73b5eeeb70b9435254e74d7f07d8cf4057f0a710ac": "Mini Shai-Hulud SAP CAP execution.js (mbt)",
    "6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95": "Mini Shai-Hulud SAP CAP execution.js (@cap-js/sqlite)",
    "18f784b3bc9a0bcdcb1a8d7f51bc5f54323fc40cbd874119354ab609bef6e4cb": "Mini Shai-Hulud Bitwarden CLI bw_setup.js loader",
    "8605e365edf11160aad517c7d79a3b26b62290e5072ef97b102a01ddbb343f14": "Mini Shai-Hulud Bitwarden CLI bw1.js payload",
    "167ce57ef59a32a6a0ef4137785828077879092d7f83ddbc1755d6e69116e0ad": "Mini Shai-Hulud Bitwarden CLI tampered root metadata",
    "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c": "Mini Shai-Hulud TanStack router_init.js",
    "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96": "Mini Shai-Hulud TanStack tanstack_runner.js",
    "a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c": "Mini Shai-Hulud AntV index.js payload (Microsoft)",
    "fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142": "Mini Shai-Hulud AntV cat.py backdoor (Microsoft)",
    "7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655": "Shai-Hulud Miasma @redhat-cloud-services/types metadata",
    "b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966": "Shai-Hulud Miasma install-time loader",
    "c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c": "Shai-Hulud Hades PyPI *-setup.pth startup hook",
    "dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe": "Shai-Hulud Hades PyPI _index.js payload v1",
    "e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d": "Shai-Hulud Hades PyPI _index.js payload v2",
}

# PyPI packages compromised in the Hades wave (2026-06-07, Socket).
PYPI_HADES_PACKAGES = {
    "bramin": ["0.0.2", "0.0.3", "0.0.4"],
    "cmd2func": ["0.2.2", "0.2.3"],
    "coolbox": ["0.4.1", "0.4.2"],
    "dynamo-release": ["1.5.4"],
    "executor-engine": ["0.3.4", "0.3.5"],
    "executor-http": ["0.1.3", "0.1.4"],
    "funcdesc": ["0.2.2", "0.2.3"],
    "magique": ["0.6.8", "0.6.9"],
    "magique-ai": ["0.4.4", "0.4.5"],
    "mrbios": ["0.1.1", "0.1.2"],
    "napari-ufish": ["0.0.2", "0.0.3"],
    "nucbox": ["0.1.2", "0.1.3"],
    "okite": ["0.0.7", "0.0.8"],
    "pantheon-agents": ["0.6.1", "0.6.2"],
    "pantheon-toolsets": ["0.5.5", "0.5.6"],
    "spateo-release": ["1.1.2"],
    "synago": ["0.1.1", "0.1.2"],
    "ufish": ["0.1.2", "0.1.3"],
    "uprobe": ["0.1.3", "0.1.4"],
}

# New C2 / exfiltration / phishing domains for 2026 waves.
# NOTE: api.anthropic.com is NOT listed here on purpose - it is a legitimate
# host abused only via the bogus /v1/api path; matched as a path pattern below.
NEW_2026_C2_DOMAINS = [
    "t.m-kosche.com",
    "filev2.getsession.org",
    "api.masscan.cloud",
    "git-tanstack.com",
    "audit.checkmarx.cx",
]

# Exfil repo descriptions / campaign marker strings (GitHub dead-drops).
NEW_2026_REPO_MARKERS = [
    "A Mini Shai-Hulud has Appeared",
    "Sha1-Hulud: The Second Coming.",
    "niagA oG eW ereH :duluH-iahS",
    "Shai-Hulud: Here We Go Again",
    "Miasma: The Spreading Blight",
    "Hades - The End for the Damned",
    "Shai-Hulud: The Third Coming",
]

# Agent/IDE config persistence artefacts abused by the malware to survive
# `npm uninstall` (the malware writes these; detecting them is real coverage).
AGENT_PERSISTENCE_FILES = [
    ".claude/settings.json",
    ".claude/setup.mjs",
    ".claude/execution.js",
    ".claude/router_runtime.js",
    ".vscode/tasks.json",
    ".vscode/setup.mjs",
    ".cursor/setup.mjs",
]

# Curated regex patterns (correct single-backslash escaping). Kept precise to
# avoid false positives: most are unique campaign strings or constants.
NEW_2026_PATTERNS = [
    # --- runner / infrastructure ---
    (r"SHA1HULUD", "Shai-Hulud self-hosted GitHub Actions runner / C2 marker", "critical"),
    (r"actions-runner-linux-x64-2\.330\.0\.tar\.gz", "Shai-Hulud 2.0 self-hosted runner download", "critical"),
    (r"oven-sh/bun/releases/download/bun-v1\.3\.13", "Pinned Bun v1.3.13 download (Mini Shai-Hulud EDR evasion)", "warning"),
    # --- malware persistence via agent/IDE config (survives npm uninstall) ---
    (r"\"(SessionStart|folderOpen)\"[\s\S]{0,200}(setup\.mjs|execution\.js|router_runtime\.js)", "Malware persistence hook in agent/IDE config (setup.mjs/execution.js)", "critical"),
    (r"\"runOn\"\s*:\s*\"folderOpen\"[\s\S]{0,200}(setup\.mjs|execution\.js)", "Editor task auto-running a Bun loader on folder open (Mini Shai-Hulud)", "critical"),
    (r"\"preinstall\"\s*:\s*\"[^\"]*bun\s+(run\s+)?(index|execution|setup|router_init|tanstack_runner)", "preinstall hook invoking Bun loader (Mini Shai-Hulud)", "critical"),
    (r"github:(tanstack/router|antvis/[Gg]2)#[0-9a-f]{7,40}", "Injected GitHub-tarball dependency pinned to attacker commit", "critical"),
    # --- exfil repo descriptions / campaign markers ---
    (r"A Mini Shai-Hulud has Appeared", "Mini Shai-Hulud SAP CAP exfil repo description", "critical"),
    (r"Sha1-Hulud: The Second Coming\.", "Shai-Hulud 2.0 exfil repo description (exact, trailing dot)", "high"),
    (r"niagA oG eW ereH :duluH-iahS", "Mini Shai-Hulud AntV reversed exfil repo description", "critical"),
    (r"Shai-Hulud: Here We Go Again", "Mini Shai-Hulud AntV exfil repo description", "critical"),
    (r"Miasma: The Spreading Blight", "Shai-Hulud Miasma (Red Hat) exfil repo description", "critical"),
    (r"Hades - The End for the Damned", "Shai-Hulud Hades (PyPI) exfil repo description", "critical"),
    (r"Shai-Hulud: The Third Coming", "Mini Shai-Hulud Bitwarden CLI marker", "critical"),
    # --- destructive / threat markers ---
    (r"IfYou(Invalidate|Yank|Revoke)This\w*Token\w*", "Mini Shai-Hulud destructive token-wipe threat marker", "critical"),
    (r"find\s+\"?\$HOME\"?[^\n]*-writable[^\n]*shred\s+-u", "Mini Shai-Hulud destructive wipe (shred on $HOME)", "critical"),
    (r"cipher\s+/[Ww]:%USERPROFILE%", "Mini Shai-Hulud destructive wipe (Windows cipher /W of %USERPROFILE%)", "critical"),
    (r"LongLiveTheResistanceAgainstMachines", "TeamPCP PAT-staging marker (Bitwarden wave)", "high"),
    (r"Exiting as russian language detected", "Mini Shai-Hulud CIS/RU locale-exemption check", "warning"),
    # --- tooling / staging ---
    (r"\.truffler-cache", "TruffleHog cache directory used by Shai-Hulud 2.0/Mini", "warning"),
    (r"results/results-\d+-\d+\.json", "Encrypted-credential staging path before GitHub exfil", "warning"),
    (r"\.bun_ran", "Shai-Hulud Hades PyPI Bun-execution sentinel file", "warning"),
    # --- crypto constants (unique, near-zero FP) ---
    (r"5012caa5847ae9261dfa16f91417042f367d6bed149c3b8af7a50b203a093007", "TeamPCP PBKDF2 static key constant", "high"),
    (r"fd4b0f07b27e8f41bc70b8e2b79d168fb3fe80d7e0b37f43c506136a3418b44d", "TeamPCP derived master-key constant", "high"),
    (r"svksjrhjkcejg", "Mini Shai-Hulud TanStack PBKDF2 salt constant", "high"),
    (r"ctf-scramble-v2", "Mini Shai-Hulud SAP CAP cipher salt constant", "high"),
    # --- living-off-trusted-host exfil (path/behaviour, host kept allow-listed) ---
    (r"api\.anthropic\.com/v1/api\b", "Exfil via legit Anthropic host abused with bogus /v1/api path (Miasma/Hades)", "high"),
    (r"api\.github\.com/search/commits\?q=firedalazer", "Miasma kitty-monitor GitHub commit-search dead-drop", "high"),
    (r"litter\.catbox\.moe/[\w]+\.(js|mjs)", "Mini Shai-Hulud TanStack second-stage payload host", "high"),
    (r"filev2\.getsession\.org", "Mini Shai-Hulud exfil via Session P2P network", "critical"),
    # --- persistence daemons ---
    (r"gh-token-monitor\.(sh|service|plist)", "Mini Shai-Hulud gh-token-monitor persistence daemon", "high"),
    (r"kitty-monitor\.(service|plist)", "Shai-Hulud Miasma kitty-monitor persistence daemon", "high"),
]

# Timeline additions for the 2026 family.
NEW_2026_TIMELINE = {
    "2026-04-22": "Mini Shai-Hulud: @bitwarden/cli@2026.4.0 trojanised via Checkmarx breach ('The Third Coming')",
    "2026-04-29": "Mini Shai-Hulud: SAP CAP packages (mbt, @cap-js/*) hit with Bun-loaded credential stealer + agent/IDE config persistence",
    "2026-05-11": "Mini Shai-Hulud: TanStack (42 pkgs) compromised via OIDC/trusted-publishing hijack (CVE-2026-45321), 170+ npm/PyPI pkgs total",
    "2026-05-19": "Mini Shai-Hulud: AntV ecosystem - 639 versions / 323 pkgs in ~22 min via compromised 'atool' maintainer ('Here We Go Again')",
    "2026-06-01": "Shai-Hulud Miasma: @redhat-cloud-services packages compromised via GitHub Actions OIDC ('The Spreading Blight')",
    "2026-06-07": "Shai-Hulud Hades: PyPI wave - 37 wheels / 19 projects via *-setup.pth -> Bun -> _index.js",
}


def dedupe_preserve_order(items):
    """Return a list with unique items while keeping the first-seen order."""
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def merge_packages(target: Dict[str, List[str]], additions: Dict[str, List[str]]) -> int:
    """Merge version lists into the target dict, returning how many versions were added."""
    added = 0
    for name, versions in additions.items():
        existing = target.get(name, [])
        merged = dedupe_preserve_order(existing + versions)
        added += len(merged) - len(existing)
        target[name] = merged
    return added


def load_iocs() -> Dict:
    if not IOC_PATH.exists():
        return {
            "known_compromised_packages": {},
            "malicious_code_patterns": [],
            "bundle_js_hashes": {},
            "indicators_of_compromise": {},
            "attack_timeline": {},
        }
    with IOC_PATH.open() as f:
        return json.load(f)


def fetch_wiz_shai_hulud_20_packages() -> Dict[str, List[str]]:
    """
    Fetch package list from Wiz Shai-Hulud 2.0 blog (Nov 2025).
    Returns {package: [versions]}.
    """
    try:
        import requests
    except ImportError:
        return {}

    url = "https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack"
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
    except Exception:
        return {}

    packages: Dict[str, List[str]] = {}

    try:
        from bs4 import BeautifulSoup  # type: ignore

        soup = BeautifulSoup(resp.text, "html.parser")
        for row in soup.find_all("tr"):
            spans = row.find_all("span")
            if len(spans) < 2:
                continue
            pkg = spans[0].get_text(strip=True)
            ver_text = spans[1].get_text(strip=True)
            if not pkg.startswith("@") or "=" not in ver_text:
                continue
            vers_raw = ver_text.replace("=", " ")
            parts = [v.strip() for v in re.split(r"\|\|", vers_raw)]
            parts = [p for p in parts if p]
            packages.setdefault(pkg, [])
            for v in parts:
                if v not in packages[pkg]:
                    packages[pkg].append(v)
    except Exception:
        pass

    if not packages:
        text = re.sub(r"<[^>]+>", "\n", resp.text)
        fallback_pattern = re.compile(r"(@[\\w.-]+/[\\w.-]+)\\s*=\\s*([^\\n<]+)")
        for match in fallback_pattern.finditer(text):
            pkg = match.group(1).strip()
            vers_raw = match.group(2).strip().split("\n")[0]
            parts = [v.strip().lstrip("=") for v in re.split(r"\|\|", vers_raw)]
            parts = [p for p in parts if p]
            if not parts:
                continue
            packages.setdefault(pkg, [])
            for v in parts:
                if v not in packages[pkg]:
                    packages[pkg].append(v)

    return packages


def main() -> None:
    data = load_iocs()
    known = data.setdefault("known_compromised_packages", {})

    # Pull CVE packages from the dedicated section as well as the local fallback.
    cve_section = data.get("cve_2025_54313_scavenger", {}).get("compromised_packages", {})
    added_versions = 0
    added_versions += merge_packages(known, cve_section)
    added_versions += merge_packages(known, CVE_2025_54313_PACKAGES)
    added_versions += merge_packages(known, NEW_SHAI_PACKAGES)

    # Fetch and merge Wiz November 2025 Shai-Hulud 2.0 package list (if reachable)
    wiz_pkgs = fetch_wiz_shai_hulud_20_packages()
    added_versions += merge_packages(known, wiz_pkgs)

    # --- 2026 Mini Shai-Hulud / TeamPCP family (npm packages) ---
    added_versions += merge_packages(known, NEW_2026_NPM_PACKAGES)

    # Dedicated section documenting the 2026 waves + exact, source-verified hashes.
    mini = data.setdefault("mini_shai_hulud_2026", {})
    mini["description"] = (
        "Mini Shai-Hulud / TeamPCP family (Apr-Jun 2026): SAP CAP, Bitwarden CLI, "
        "TanStack (CVE-2026-45321), AntV, Miasma (Red Hat), Hades (PyPI). "
        "Bun-runtime credential stealer, OIDC/trusted-publishing abuse, cross-ecosystem propagation."
    )
    mini["actor"] = "TeamPCP (aka UNC6780); Miasma/Hades likely copycats reusing the open-sourced code"
    mini["file_hashes_sha256"] = dict(MINI_SHAI_HULUD_HASHES)
    mini["c2_domains"] = list(NEW_2026_C2_DOMAINS)
    mini["repo_descriptions"] = list(NEW_2026_REPO_MARKERS)
    mini["agent_persistence_files"] = list(AGENT_PERSISTENCE_FILES)
    mini["notes"] = {
        "living_off_trusted_host": "api.anthropic.com abused only via the bogus /v1/api path - do NOT block the host",
        "cross_ecosystem_spillover": "org.mvnpm:posthog-node:4.18.1 (Maven Central mirror of a compromised npm release)",
    }

    # PyPI Hades wave (kept separate from the npm known-compromised list).
    pypi = data.setdefault("pypi_hades_2026", {})
    pypi["description"] = "Shai-Hulud Hades PyPI wave (2026-06-07): *-setup.pth startup hook -> Bun -> _index.js stealer"
    pypi["compromised_packages"] = {k: list(v) for k, v in PYPI_HADES_PACKAGES.items()}
    pypi["malicious_files"] = ["*-setup.pth", "_index.js", ".bun_ran"]
    pypi["file_hashes_sha256"] = {
        h: lbl for h, lbl in MINI_SHAI_HULUD_HASHES.items() if "Hades" in lbl
    }

    # Merge new payload hashes (Shai-Hulud 2.0)
    bundle_hashes = data.setdefault("bundle_js_hashes", {})
    for key, value in NEW_PAYLOAD_HASHES.items():
        bundle_hashes[key] = value
    # Deduplicate bundle hashes by value while keeping the first key encountered
    deduped_hashes = {}
    seen_vals = set()
    for k, v in bundle_hashes.items():
        if v not in seen_vals:
            deduped_hashes[k] = v
            seen_vals.add(v)
    deduped_hashes.pop("version_9_setup_bun", None)
    deduped_hashes["version_11_setup_bun"] = NEW_PAYLOAD_HASHES["version_11_setup_bun"]
    data["bundle_js_hashes"] = deduped_hashes

    patterns = data.setdefault("malicious_code_patterns", [])
    seen_patterns = {p[0] for p in patterns if isinstance(p, (list, tuple)) and len(p) >= 1}
    for pat in list(NEW_MALICIOUS_PATTERNS) + list(NEW_2026_PATTERNS):
        if pat[0] not in seen_patterns:
            patterns.append(list(pat))
            seen_patterns.add(pat[0])

    attack_timeline = data.setdefault("attack_timeline", {})
    attack_timeline.setdefault("2025-11-25", "Shai-Hulud 2.0: Unit42 reports Bun-based preinstall payloads (setup_bun.js, bun_environment.js)")
    attack_timeline.setdefault("2025-11-27", "Shai-Hulud 2.0: Wiz publishes extended package list and CI/CD impact analysis")
    for date, desc in NEW_2026_TIMELINE.items():
        attack_timeline.setdefault(date, desc)

    # Update IOC metadata for 2.0 campaign
    iocs = data.setdefault("indicators_of_compromise", {})
    iocs.setdefault("shai_hulud_2_payloads", ["setup_bun.js", "bun_environment.js"])
    iocs.setdefault("shai_hulud_2_exfil_description", "Sha1-Hulud: The Second Coming")

    # 2026 family metadata
    for name in ["TeamPCP", "UNC6780", "Mini Shai-Hulud", "Miasma", "Hades"]:
        if name not in iocs.setdefault("campaign_names", []):
            iocs["campaign_names"].append(name)
    for cve in ["CVE-2026-45321", "GHSA-g7cv-rxg3-hmpx"]:
        if cve not in iocs.setdefault("cve_references", []):
            iocs["cve_references"].append(cve)
    iocs["exfil_repo_descriptions_2026"] = list(NEW_2026_REPO_MARKERS)
    iocs["c2_domains_2026"] = list(NEW_2026_C2_DOMAINS)

    total_versions = sum(len(v) for v in known.values())
    data["total_compromised_count"] = total_versions

    with IOC_PATH.open("w") as f:
        json.dump(data, f, indent=2)

    print(f"Updated {IOC_PATH.name}: +{added_versions} versions added/merged")
    print(f"Total compromised package versions: {total_versions}")


if __name__ == "__main__":
    main()
