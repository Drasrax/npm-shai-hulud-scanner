#!/bin/bash

# NPM Supply Chain Security Scanner
# Automated scanning script for detecting supply chain attacks in NPM projects

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_SCRIPT="$SCRIPT_DIR/npm-supply-chain-detector.py"
PATTERNS_FILE="$SCRIPT_DIR/malicious-patterns.json"
REPORT_DIR="$SCRIPT_DIR/security-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Default values
PROJECT_PATH="."
OUTPUT_FORMAT="text"
VERBOSE=false
WEBHOOK_URL=""
CONTINUOUS_MODE=false
SCAN_INTERVAL=300  # 5 minutes

usage() {
    cat << EOF
Usage: $0 [OPTIONS] [PROJECT_PATH]

NPM Supply Chain Security Scanner - Detect and report vulnerabilities

OPTIONS:
    -h, --help              Show this help message
    -o, --output FORMAT     Output format: json, text, markdown (default: text)
    -f, --file FILE        Save report to file
    -v, --verbose          Enable verbose output
    -w, --webhook URL      Send critical findings to webhook
    -c, --continuous       Run in continuous monitoring mode
    -i, --interval SECONDS  Scan interval for continuous mode (default: 300)
    -d, --deep             Perform deep scan (slower but more thorough)
    --update-patterns      Update malicious patterns from online source
    --quarantine          Move suspicious packages to quarantine folder

EXAMPLES:
    # Basic scan of current directory
    $0

    # Scan specific project with JSON output
    $0 -o json /path/to/project

    # Continuous monitoring with webhook notifications
    $0 -c -w https://hooks.slack.com/services/XXX -i 600

    # Deep scan with report saved to file
    $0 -d -f report.md -o markdown /path/to/project

EOF
    exit 0
}

check_requirements() {
    echo -e "${BLUE}[*] Checking requirements...${NC}"
    
    # Check Python 3
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}[!] Python 3 is required but not installed${NC}"
        exit 1
    fi
    
    # Check npm
    if ! command -v npm &> /dev/null; then
        echo -e "${RED}[!] npm is required but not installed${NC}"
        exit 1
    fi
    
    # Check scanner script
    if [ ! -f "$SCANNER_SCRIPT" ]; then
        echo -e "${RED}[!] Scanner script not found: $SCANNER_SCRIPT${NC}"
        exit 1
    fi
    
    # Check patterns file
    if [ ! -f "$PATTERNS_FILE" ]; then
        echo -e "${YELLOW}[!] Patterns file not found, using defaults${NC}"
    fi
    
    echo -e "${GREEN}[✓] All requirements satisfied${NC}"
}

update_patterns() {
    echo -e "${BLUE}[*] Updating malicious patterns...${NC}"
    
    if [ -f "$PATTERNS_FILE" ]; then
        python3 -m json.tool "$PATTERNS_FILE" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓] Patterns file is valid${NC}"
        else
            echo -e "${RED}[!] Patterns file is invalid JSON${NC}"
            exit 1
        fi
    fi
}

run_scan() {
    local project_path="$1"
    local report_file="$2"
    
    echo -e "${BLUE}[*] Scanning project: $project_path${NC}"
    echo -e "${BLUE}[*] Timestamp: $(date)${NC}"
    
    cmd="python3 '$SCANNER_SCRIPT' '$project_path' -o '$OUTPUT_FORMAT'"
    
    if [ "$VERBOSE" = true ]; then
        cmd="$cmd -v"
    fi
    
    if [ -n "$WEBHOOK_URL" ]; then
        cmd="$cmd --webhook '$WEBHOOK_URL'"
    fi
    
    if [ -n "$report_file" ]; then
        cmd="$cmd -f '$report_file'"
        echo -e "${BLUE}[*] Report will be saved to: $report_file${NC}"
    fi
    
    eval $cmd
    scan_result=$?
    
    if [ $scan_result -eq 0 ]; then
        echo -e "${GREEN}[✓] Scan completed successfully${NC}"
    else
        echo -e "${RED}[!] Critical vulnerabilities detected!${NC}"
        
        # If in continuous mode, don't exit
        if [ "$CONTINUOUS_MODE" = false ]; then
            exit $scan_result
        fi
    fi
    
    return $scan_result
}

# continuous monitoring
continuous_monitoring() {
    echo -e "${BLUE}[*] Starting continuous monitoring mode${NC}"
    echo -e "${BLUE}[*] Scan interval: $SCAN_INTERVAL seconds${NC}"
    echo -e "${YELLOW}[*] Press Ctrl+C to stop${NC}"
    
    # Create report directory if it doesn't exist
    mkdir -p "$REPORT_DIR"
    
    # Trap Ctrl+C
    trap 'echo -e "\n${YELLOW}[*] Stopping continuous monitoring...${NC}"; exit 0' INT
    
    scan_count=0
    critical_count=0
    
    while true; do
        scan_count=$((scan_count + 1))
        echo -e "\n${BLUE}═══════════════════════════════════════════${NC}"
        echo -e "${BLUE}[*] Scan #$scan_count${NC}"
        echo -e "${BLUE}═══════════════════════════════════════════${NC}"
        
        # Generate unique report filename
        report_file="$REPORT_DIR/scan_${TIMESTAMP}_${scan_count}.${OUTPUT_FORMAT}"
        if [ "$OUTPUT_FORMAT" = "text" ]; then
            report_file="$REPORT_DIR/scan_${TIMESTAMP}_${scan_count}.txt"
        elif [ "$OUTPUT_FORMAT" = "markdown" ]; then
            report_file="$REPORT_DIR/scan_${TIMESTAMP}_${scan_count}.md"
        fi
        
        # Run scan
        run_scan "$PROJECT_PATH" "$report_file"
        result=$?
        
        if [ $result -ne 0 ]; then
            critical_count=$((critical_count + 1))
            echo -e "${RED}[!] Critical issues found in scan #$scan_count${NC}"
            
            if [ $((critical_count % 3)) -eq 0 ] && [ -n "$WEBHOOK_URL" ]; then
                send_escalation_alert
            fi
        fi
        
        echo -e "${BLUE}[*] Next scan in $SCAN_INTERVAL seconds...${NC}"
        sleep $SCAN_INTERVAL
    done
}

send_escalation_alert() {
    if [ -n "$WEBHOOK_URL" ]; then
        local message="{\"text\":\"ESCALATION: Multiple critical vulnerabilities detected in $critical_count scans!\"}"
        curl -X POST -H 'Content-Type: application/json' -d "$message" "$WEBHOOK_URL" 2>/dev/null
    fi
}

# Function for deep scan
deep_scan() {
    echo -e "${BLUE}[*] Performing deep scan...${NC}"
    
    # Additional checks for deep scan
    echo -e "${BLUE}[*] Checking npm audit...${NC}"
    npm audit --json > "$REPORT_DIR/npm_audit_${TIMESTAMP}.json" 2>/dev/null || true
    
    echo -e "${BLUE}[*] Checking for outdated packages...${NC}"
    npm outdated --json > "$REPORT_DIR/npm_outdated_${TIMESTAMP}.json" 2>/dev/null || true
    
    echo -e "${BLUE}[*] Analyzing package-lock.json integrity...${NC}"
    if [ -f "package-lock.json" ]; then
        npm ls --json > "$REPORT_DIR/npm_tree_${TIMESTAMP}.json" 2>/dev/null || true
    fi
    
    # Run main scan
    run_scan "$PROJECT_PATH" "$REPORT_DIR/main_scan_${TIMESTAMP}.${OUTPUT_FORMAT}"
}

quarantine_packages() {
    local quarantine_dir="$PROJECT_PATH/.npm-quarantine"
    local node_modules="$PROJECT_PATH/node_modules"
    local manifest_file="$quarantine_dir/quarantine-manifest-${TIMESTAMP}.json"

    echo -e "${YELLOW}[*] Quarantine mode enabled${NC}"
    echo -e "${YELLOW}[*] Suspicious packages will be moved to: $quarantine_dir${NC}"

    # Create quarantine directory structure
    mkdir -p "$quarantine_dir/packages"
    mkdir -p "$quarantine_dir/logs"

    # Check if node_modules exists
    if [ ! -d "$node_modules" ]; then
        echo -e "${RED}[!] node_modules directory not found${NC}"
        return 1
    fi

    # Run scanner to get suspicious packages
    echo -e "${BLUE}[*] Scanning for suspicious packages...${NC}"
    local scan_output="$quarantine_dir/logs/pre-quarantine-scan-${TIMESTAMP}.json"
    python3 "$SCANNER_SCRIPT" "$PROJECT_PATH" -o json -f "$scan_output" 2>/dev/null

    if [ ! -f "$scan_output" ]; then
        echo -e "${RED}[!] Failed to generate scan results${NC}"
        return 1
    fi

    # Extract compromised package names from scan results
    local compromised_packages=$(python3 -c "
import json
import sys
try:
    with open('$scan_output') as f:
        data = json.load(f)
    packages = set()
    for finding in data.get('findings', []):
        if finding.get('severity') == 'critical':
            location = finding.get('location', '')
            # Extract package name from node_modules path
            if 'node_modules/' in location:
                parts = location.split('node_modules/')[1].split('/')
                # Handle scoped packages
                if parts[0].startswith('@'):
                    pkg_name = parts[0] + '/' + parts[1] if len(parts) > 1 else parts[0]
                else:
                    pkg_name = parts[0]
                packages.add(pkg_name)
    for pkg in sorted(packages):
        print(pkg)
except Exception as e:
    sys.stderr.write(f'Error: {e}\n')
" 2>&1)

    if [ -z "$compromised_packages" ]; then
        echo -e "${GREEN}[✓] No suspicious packages found to quarantine${NC}"
        return 0
    fi

    # Initialize manifest
    echo "{" > "$manifest_file"
    echo "  \"quarantine_date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "$manifest_file"
    echo "  \"project_path\": \"$PROJECT_PATH\"," >> "$manifest_file"
    echo "  \"packages\": [" >> "$manifest_file"

    local quarantined_count=0
    local first=true

    # Quarantine each suspicious package
    while IFS= read -r package_name; do
        [ -z "$package_name" ] && continue

        local package_path="$node_modules/$package_name"

        if [ -d "$package_path" ]; then
            echo -e "${YELLOW}[*] Quarantining package: $package_name${NC}"

            # Get package version
            local version="unknown"
            if [ -f "$package_path/package.json" ]; then
                version=$(python3 -c "import json; print(json.load(open('$package_path/package.json')).get('version', 'unknown'))" 2>/dev/null || echo "unknown")
            fi

            # Create quarantine subdirectory for this package
            local quarantine_pkg_dir="$quarantine_dir/packages/${package_name//\//_}"
            mkdir -p "$quarantine_pkg_dir"

            # Move package to quarantine (with backup)
            if mv "$package_path" "$quarantine_pkg_dir/"; then
                # Add to manifest
                if [ "$first" = false ]; then
                    echo "," >> "$manifest_file"
                fi
                first=false

                cat >> "$manifest_file" << EOF
    {
      "name": "$package_name",
      "version": "$version",
      "original_path": "$package_path",
      "quarantine_path": "$quarantine_pkg_dir/$(basename $package_path)",
      "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    }
EOF

                quarantined_count=$((quarantined_count + 1))
                echo -e "${GREEN}[✓] Quarantined: $package_name@$version${NC}"
            else
                echo -e "${RED}[!] Failed to quarantine: $package_name${NC}"
            fi
        else
            echo -e "${YELLOW}[!] Package not found in node_modules: $package_name${NC}"
        fi
    done <<< "$compromised_packages"

    # Close manifest JSON
    echo "" >> "$manifest_file"
    echo "  ]," >> "$manifest_file"
    echo "  \"total_quarantined\": $quarantined_count" >> "$manifest_file"
    echo "}" >> "$manifest_file"

    # Create restore script
    create_restore_script "$quarantine_dir" "$manifest_file"

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${YELLOW}[*] Quarantine Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Total packages quarantined: $quarantined_count${NC}"
    echo -e "${YELLOW}Manifest: $manifest_file${NC}"
    echo -e "${YELLOW}Restore script: $quarantine_dir/restore.sh${NC}"

    if [ $quarantined_count -gt 0 ]; then
        echo -e "\n${RED}[!] WARNING: Quarantined packages have been removed from node_modules${NC}"
        echo -e "${YELLOW}[*] Your project may not function correctly until you:${NC}"
        echo -e "${YELLOW}    1. Review the quarantined packages${NC}"
        echo -e "${YELLOW}    2. Replace with safe versions: npm install <package>@<safe-version>${NC}"
        echo -e "${YELLOW}    3. Or restore if false positive: $quarantine_dir/restore.sh${NC}"
    fi

    return 0
}

create_restore_script() {
    local quarantine_dir="$1"
    local manifest_file="$2"
    local restore_script="$quarantine_dir/restore.sh"

    cat > "$restore_script" << 'RESTORE_SCRIPT_EOF'
#!/bin/bash

# NPM Package Quarantine Restore Script
# CAUTION: Only run this if you are certain the quarantined packages are safe

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_FILE="$1"

if [ -z "$MANIFEST_FILE" ]; then
    # Find most recent manifest
    MANIFEST_FILE=$(ls -t "$SCRIPT_DIR"/quarantine-manifest-*.json 2>/dev/null | head -1)
fi

if [ ! -f "$MANIFEST_FILE" ]; then
    echo -e "${RED}[!] No manifest file found${NC}"
    echo "Usage: $0 <manifest-file>"
    exit 1
fi

echo -e "${YELLOW}[!] WARNING: This will restore quarantined packages${NC}"
echo -e "${YELLOW}[!] Only proceed if you are certain they are safe${NC}"
echo -e "${YELLOW}Manifest: $MANIFEST_FILE${NC}"
echo ""
read -p "Are you sure you want to restore? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo -e "${YELLOW}[*] Restore cancelled${NC}"
    exit 0
fi

# Parse manifest and restore packages
python3 << 'PYTHON_EOF'
import json
import shutil
import os
import sys

manifest_file = sys.argv[1]

try:
    with open(manifest_file) as f:
        data = json.load(f)

    restored = 0
    failed = 0

    for pkg in data.get('packages', []):
        name = pkg.get('name')
        original = pkg.get('original_path')
        quarantine = pkg.get('quarantine_path')

        if os.path.exists(quarantine):
            # Ensure parent directory exists
            os.makedirs(os.path.dirname(original), exist_ok=True)

            try:
                shutil.move(quarantine, original)
                print(f"✓ Restored: {name}")
                restored += 1
            except Exception as e:
                print(f"✗ Failed to restore {name}: {e}")
                failed += 1
        else:
            print(f"✗ Quarantine path not found: {name}")
            failed += 1

    print(f"\nRestored: {restored}, Failed: {failed}")
    sys.exit(0 if failed == 0 else 1)

except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
PYTHON_EOF
python3 - "$MANIFEST_FILE"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓] Packages restored successfully${NC}"
else
    echo -e "${RED}[!] Some packages failed to restore${NC}"
fi
RESTORE_SCRIPT_EOF

    chmod +x "$restore_script"
}

DEEP_SCAN=false
QUARANTINE=false
REPORT_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -o|--output)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        -f|--file)
            REPORT_FILE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -w|--webhook)
            WEBHOOK_URL="$2"
            shift 2
            ;;
        -c|--continuous)
            CONTINUOUS_MODE=true
            shift
            ;;
        -i|--interval)
            SCAN_INTERVAL="$2"
            shift 2
            ;;
        -d|--deep)
            DEEP_SCAN=true
            shift
            ;;
        --update-patterns)
            update_patterns
            exit 0
            ;;
        --quarantine)
            QUARANTINE=true
            shift
            ;;
        *)
            PROJECT_PATH="$1"
            shift
            ;;
    esac
done

# Main execution
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo -e "${BLUE}    NPM Supply Chain Security Scanner      ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════${NC}"

check_requirements

mkdir -p "$REPORT_DIR"

if [ "$QUARANTINE" = true ]; then
    quarantine_packages
fi

if [ "$CONTINUOUS_MODE" = true ]; then
    continuous_monitoring
elif [ "$DEEP_SCAN" = true ]; then
    deep_scan
else
    if [ -n "$REPORT_FILE" ]; then
        run_scan "$PROJECT_PATH" "$REPORT_FILE"
    else
        run_scan "$PROJECT_PATH" "$REPORT_DIR/scan_${TIMESTAMP}.${OUTPUT_FORMAT}"
    fi
fi

echo -e "\n${GREEN}[✓] Security scan completed${NC}"
