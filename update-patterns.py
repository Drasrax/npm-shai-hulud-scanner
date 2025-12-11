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
    for pat in NEW_MALICIOUS_PATTERNS:
        if pat[0] not in seen_patterns:
            patterns.append(list(pat))

    attack_timeline = data.setdefault("attack_timeline", {})
    attack_timeline.setdefault("2025-11-25", "Shai-Hulud 2.0: Unit42 reports Bun-based preinstall payloads (setup_bun.js, bun_environment.js)")
    attack_timeline.setdefault("2025-11-27", "Shai-Hulud 2.0: Wiz publishes extended package list and CI/CD impact analysis")

    # Update IOC metadata for 2.0 campaign
    iocs = data.setdefault("indicators_of_compromise", {})
    iocs.setdefault("shai_hulud_2_payloads", ["setup_bun.js", "bun_environment.js"])
    iocs.setdefault("shai_hulud_2_exfil_description", "Sha1-Hulud: The Second Coming")

    total_versions = sum(len(v) for v in known.values())
    data["total_compromised_count"] = total_versions

    with IOC_PATH.open("w") as f:
        json.dump(data, f, indent=2)

    print(f"Updated {IOC_PATH.name}: +{added_versions} versions added/merged")
    print(f"Total compromised package versions: {total_versions}")


if __name__ == "__main__":
    main()
