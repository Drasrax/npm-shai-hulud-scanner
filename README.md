# NPM Supply Chain Security Scanner

Security toolkit for detecting supply chain vulnerabilities in NPM projects, designed to detect patterns from **two major 2025 npm supply chain attacks**:

- **CVE-2025-54313** (Scavenger malware - July 2025)
- **Shai-Hulud worm** (September 2025)

## Purpose

Detect and notify security vulnerabilities in NPM dependencies, including:

- **1193+ compromised package versions** (Shai-Hulud + CVE-2025-54313, incl. Wiz Shai-Hulud 2.0 list)
- Shai-Hulud 2.0 Bun payloads (`setup_bun.js`, `bun_environment.js`)
- Typosquatting attempts
- Injected malicious code (DLL/SO files, obfuscated scripts)
- Suspicious installation scripts
- Worm-like/propagation behaviors
- C2 domain communication
- Cloud metadata endpoint (IMDS) access

## Files

- `npm-supply-chain-detector.py` - Main Python detection script
- `scan-npm-security.sh` - Bash automation and monitoring script
- `malicious-patterns.json` - Malicious patterns database (production)
- `shai-hulud-iocs.json` - Extended IOCs database (692 packages / 1193 versions, 14 hashes, C2 domains)
- `update-patterns.py` - Pattern database generator/updater

## Installation

```bash
# Clone or download scripts
chmod +x npm-supply-chain-detector.py scan-npm-security.sh

# Check prerequisites
./scan-npm-security.sh --help
```

### Prerequisites
- Python 3.6+
- npm/node installed
- NPM project with package.json

## Usage

### Simple scan

```bash
# Scan current directory
python3 npm-supply-chain-detector.py

# Scan specific project
python3 npm-supply-chain-detector.py /path/to/project

# With detailed report
python3 npm-supply-chain-detector.py -v -o markdown -f report.md
```

### Automation script

```bash
# Basic scan
./scan-npm-security.sh

# Continuous monitoring (scan every 5 minutes)
./scan-npm-security.sh -c -i 300

# Deep scan with save
./scan-npm-security.sh -d -f security-report.md -o markdown /project

# With webhook notifications (Slack, Discord, etc.)
./scan-npm-security.sh -w https://hooks.slack.com/services/XXX

# Quarantine suspicious packages (moves to .npm-quarantine/)
./scan-npm-security.sh --quarantine

# Restore quarantined packages if false positive
./.npm-quarantine/restore.sh
```

### Available options

#### Python Script (`npm-supply-chain-detector.py`)
- `-o, --output`: Output format (json, text, markdown)
- `-f, --file`: Save report to file
- `-v, --verbose`: Verbose mode
- `--webhook`: Webhook URL for notifications

#### Bash Script (`scan-npm-security.sh`)
- `-c, --continuous`: Continuous monitoring mode
- `-i, --interval`: Interval between scans (seconds)
- `-d, --deep`: Deep scan (includes npm audit, outdated packages)
- `--quarantine`: **Move suspicious packages to quarantine folder**
- `--update-patterns`: Update patterns from file

## Quarantine Feature

The `--quarantine` option automatically isolates compromised packages:

**How it works:**

1. Scans for critical vulnerabilities
2. Identifies compromised packages from scan results
3. Moves packages from `node_modules/` to `.npm-quarantine/packages/`
4. Creates JSON manifest with metadata (versions, paths, timestamps)
5. Generates automatic `restore.sh` script

**Directory structure created:**
```
.npm-quarantine/
├── packages/              # Isolated packages
│   ├── package-name/
│   └── @scope_package-name/
├── logs/                  # Scan logs
├── quarantine-manifest-*.json  # Metadata
└── restore.sh            # Restoration script
```

**To restore (if false positive):**
```bash
cd .npm-quarantine
./restore.sh              # Interactive confirmation required
```

## Detections

### 1. Known compromised packages (1193 versions)

**CVE-2025-54313 (Scavenger - July 2025):**

- eslint-config-prettier (8.10.1, 9.1.1, 10.1.6, 10.1.7)
- eslint-plugin-prettier (4.2.2, 4.2.3)
- synckit (0.11.9)
- @pkgr/core (0.2.8)
- napi-postinstall (0.3.1)
- got-fetch (5.1.11, 5.1.12)
- is (3.3.1, 5.0.0)
- npm-registry-fetch (*)
- @crowdstrike/node-exporter (0.2.2)
- @crowdstrike/threat-center (1.205.2)
- tailwind-toucan-base (5.0.2)
- **Shai-Hulud 2.0 (Wiz, 27 nov 2025)** : ~470 packages / versions (e.g. `@asyncapi/*`, `@actbase/*`, `@accordproject/*`, `@antstackio/*`, etc.) – voir `shai-hulud-iocs.json` pour la liste complète

**Shai-Hulud worm (September 2025):**

- CrowdStrike packages (@crowdstrike/*)
- @ctrl/tinycolor (4.1.1, 4.1.2)
- @nativescript-community/* packages
- @operato/* packages
- @things-factory/* packages
- Many others (see shai-hulud-iocs.json)

**Shai-Hulud 2.0 (novembre 2025, Unit42 & Wiz)**

- Nouveaux payloads : `setup_bun.js`, `bun_environment.js`
- Hashes bun_environment.js : `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0`, `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068`, `cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd`
- Hash setup_bun.js : `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a`
- Exfil GitHub : description « Sha1-Hulud: The Second Coming »
- Fallback destructif possible (`rm -rf ~` / `$HOME`)

### 2. Typosquatting detection

- Levenshtein distance analysis
- Common substitutions (0→o, 1→i, etc.)
- Dash/underscore variations

### 3. Malicious code patterns

- Credential exfiltration (AWS, npm, SSH, GitHub tokens)
- Remote code execution (curl|sh, eval)
- Obfuscation (base64, atob, XOR encryption)
- Suspicious network communication to C2 domains
- Self-propagation (worm patterns, npm publishing)
- Cloud metadata endpoint (IMDS) access
- **CVE-2025-54313 specific:** DLL/SO loading, logDiskSpace function

### 4. Suspicious installation scripts
- Malicious preinstall/postinstall hooks
- Script download and execution
- npm token manipulation
- **Windows DLL execution** (rundll32, regsvr32)
- Malicious files: node-gyp.dll, loader.dll, version.dll

### 5. Hash-based detection (14 variants)
- **Shai-Hulud bundle.js** (7 SHA-256 hashes)
- **Shai-Hulud 2.0 Bun payloads**: `bun_environment.js` (3 hashes), `setup_bun.js` (1 hash)
- **CVE-2025-54313 Scavenger** (3 SHA-256 hashes)
  - node-gyp.dll: c68e42f416f482d43653f36cd14384270b54b68d6496a8e34ce887687de5b441
  - Scavenger stage 2: 5bed39728e404838ecd679df65048abcb443f8c7a9484702a2ded60104b8c4a9
  - install.js: 32d0dbdfef0e5520ba96a2673244267e204b94a49716ea13bf635fa9af6f66bf

### 6. C2 domain detection
- firebase.su (CVE-2025-54313)
- dieorsuffer.com (CVE-2025-54313)
- smartscreen-api.com (CVE-2025-54313)
- npnjs.com (typosquatting)
- webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7 (Shai-Hulud)

### 7. Integrity analysis
- Verification via `npm audit`
- Large JS file detection (>3MB)
- npm domain validation

## Report formats

### JSON
```json
{
  "scan_date": "2025-01-22T10:30:00",
  "project_path": "/path/to/project",
  "findings": [
    {
      "severity": "critical",
      "message": "KNOWN COMPROMISED PACKAGE",
      "location": "package.json",
      "details": {...}
    }
  ],
  "statistics": {
    "total_findings": 5,
    "critical": 2,
    "warning": 3
  }
}
```

### Markdown
Formatted report with tables and structured sections.

### Text
Plain text report for CI/CD integration.

## Notifications

### Webhook Configuration
Critical findings can be sent to a webhook:

```bash
./scan-npm-security.sh -w https://your-webhook-url
```

Payload format:
```json
{
  "text": "NPM Security Alert: X critical vulnerabilities",
  "findings": [...]
}
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: NPM Security Scan
  run: |
    python3 npm-supply-chain-detector.py . -o json -f scan-results.json
    if [ $? -ne 0 ]; then
      echo "Critical vulnerabilities found!"
      exit 1
    fi
```

### GitLab CI
```yaml
npm-security-scan:
  script:
    - python3 npm-supply-chain-detector.py
  artifacts:
    reports:
      paths:
        - security-reports/
```

### Jenkins
```groovy
stage('Security Scan') {
    sh './scan-npm-security.sh -o json -f report.json'
}
```

## Custom configuration

Modify `malicious-patterns.json` to:

- Add new compromised packages
- Define custom patterns
- Adjust notification thresholds
- Exclude false positives

## Continuous monitoring

For 24/7 monitoring:

```bash
# With systemd
sudo tee /etc/systemd/system/npm-security-monitor.service << EOF
[Unit]
Description=NPM Security Monitor
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/path/to/project
ExecStart=/path/to/scan-npm-security.sh -c -i 600 -w https://webhook.url
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable npm-security-monitor
sudo systemctl start npm-security-monitor
```

## What to do when detection occurs?

1. **Critical findings**:
   - **Use quarantine mode**: `./scan-npm-security.sh --quarantine`
   - Immediately isolate compromised packages
   - Regenerate all exposed tokens/secrets (npm, GitHub, AWS, SSH keys)
   - Audit affected systems for credential exposure
   - Check for unauthorized GitHub repositories named "Shai-Hulud"
   - Review cloud metadata endpoint (IMDS) access logs

2. **CVE-2025-54313 specific**:
   - Check for malicious DLL/SO files (node-gyp.dll, loader.dll, etc.)
   - Scan for connections to C2 domains (firebase.su, dieorsuffer.com, smartscreen-api.com)
   - Windows systems: Review rundll32/regsvr32 execution logs

3. **Warnings**:
   - Investigate suspicious patterns
   - Verify package legitimacy before restoration
   - Update to safe versions
   - Review package maintainer changes

4. **Post-incident**:
   - Replace with safe package versions: `npm install <package>@<safe-version>`
   - `npm audit fix` for automatic fixes
   - Dependency review and lockfile verification
   - Set up continuous monitoring (`-c -i 300`)
   - Consider restoring from quarantine only after verification

## References

- [CrowdStrike NPM Attack 2025](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
- [CVE-2025-54313](https://nvd.nist.gov/vuln/detail/CVE-2025-54313)
- [npm audit documentation](https://docs.npmjs.com/cli/v8/commands/npm-audit)

## Notes

- **549 compromised package versions** tracked (updated 2025-10-27)
- **10 malware file hashes** detected (7 Shai-Hulud + 3 Scavenger)
- **2 separate attack campaigns** covered (CVE-2025-54313 + Shai-Hulud)
- Scanner designed to minimize false positives
- Patterns based on real observed attacks (July-September 2025)
- Regular update of malicious patterns recommended
- Compatible with all standard NPM projects
- Quarantine feature allows safe isolation with restoration option

## Limitations

- Does not replace thorough manual analysis
- May not detect zero-day attacks
- Performance dependent on project size
- Requires read permissions on node_modules

## Contributing

To add new patterns or compromised packages:

1. **Update pattern files:**
   - Edit `update-patterns.py` to add new packages/patterns
   - Run `python3 update-patterns.py` to regenerate `shai-hulud-iocs.json`
   - Or manually edit `malicious-patterns.json` for quick updates

2. **Test changes:**
   ```bash
   python3 npm-supply-chain-detector.py -v test-project/
   ```

3. **Update documentation:**
   - Update statistics in `README.md`
