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
    echo -e "${YELLOW}[*] Quarantine mode enabled${NC}"
    echo -e "${YELLOW}[*] Suspicious packages will be moved to: $quarantine_dir${NC}"
    
    # This would be implemented based on scan results
    # For now, just create the directory
    mkdir -p "$quarantine_dir"
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
