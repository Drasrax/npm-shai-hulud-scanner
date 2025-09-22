# NPM Supply Chain Security Scanner

Security toolkit for detecting supply chain vulnerabilities in NPM projects, based on the analysis of the 2025 CrowdStrike/Shai-Hulud attack.

## Purpose

Detect and notify security vulnerabilities in NPM dependencies, including:
- Known compromised packages
- Typosquatting attempts
- Injected malicious code
- Suspicious installation scripts
- Worm-like/propagation behaviors

## Files

- `npm-supply-chain-detector.py` - Main Python detection script
- `scan-npm-security.sh` - Bash automation and monitoring script
- `malicious-patterns.json` - Malicious patterns database

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
- `-d, --deep`: Deep scan
- `--quarantine`: Move suspicious packages
- `--update-patterns`: Update patterns

## Detections

### 1. Known compromised packages
The scanner checks a list of known compromised packages, including:
- Affected CrowdStrike packages
- eslint-config-prettier (CVE-2025-54313)
- @ctrl/tinycolor
- Others from the Shai-Hulud attack

### 2. Typosquatting detection
- Levenshtein distance analysis
- Common substitutions (0→o, 1→i, etc.)
- Dash/underscore variations

### 3. Malicious code patterns
- Credential exfiltration (AWS, npm, SSH)
- Remote code execution (curl|sh, eval)
- Obfuscation (base64, atob)
- Suspicious network communication
- Self-propagation (worm patterns)

### 4. Suspicious installation scripts
- Malicious preinstall/postinstall hooks
- Script download and execution
- npm token manipulation

### 5. Integrity analysis
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
   - Immediately remove compromised packages
   - Regenerate all exposed tokens/secrets
   - Audit affected systems

2. **Warnings**:
   - Investigate suspicious patterns
   - Verify package legitimacy
   - Update to safe versions

3. **Post-incident**:
   - `npm audit fix` for automatic fixes
   - Dependency review
   - Set up continuous monitoring

## References

- [CrowdStrike NPM Attack 2025](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
- [CVE-2025-54313](https://nvd.nist.gov/vuln/detail/CVE-2025-54313)
- [npm audit documentation](https://docs.npmjs.com/cli/v8/commands/npm-audit)

## Notes

- Scanner designed to minimize false positives
- Patterns based on real observed attacks
- Regular update of malicious patterns recommended
- Compatible with all standard NPM projects

## Limitations

- Does not replace thorough manual analysis
- May not detect zero-day attacks
- Performance dependent on project size
- Requires read permissions on node_modules

## Contributing

To add new patterns or compromised packages, modify `malicious-patterns.json` and test with:

```bash
python3 npm-supply-chain-detector.py -v test-project/
```