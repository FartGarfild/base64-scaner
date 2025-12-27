#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SCAN_DIR="${1:-.}"
RESULTS_FILE="scan_results.txt"
BASE64_DECODE_FILE="base64_decoded.txt"
VIRUS_PATTERNS_FILE="virus_patterns.txt"
AIBOLIT_PATTERNS_FILE="aibolit_patterns.txt"

echo -e "${GREEN}=== ADVANCED MALWARE SCAN WITH AI-BOLIT PATTERNS ===${NC}"
echo "Scanning directory: $SCAN_DIR"
echo "Results will be saved to multiple files"
echo ""

# Clear previous results
> "$RESULTS_FILE"
> "$BASE64_DECODE_FILE"
> "$VIRUS_PATTERNS_FILE"
> "$AIBOLIT_PATTERNS_FILE"

# ==========================================
# AI-BOLIT PATTERNS (from real AI-Bolit)
# ==========================================

# Critical patterns (100% malware)
CRITICAL_PATTERNS=(
  'eval\s*\(\s*base64_decode'
  'eval\s*\(\s*gzinflate'
  'eval\s*\(\s*gzuncompress'
  'eval\s*\(\s*str_rot13'
  'assert\s*\(\s*base64_decode'
  'preg_replace\s*\(.*\/e.*base64'
  'preg_replace.*\\x2f\\x65'
  '\$\{["\x27]?\$\{["\x27]?'
  'eval\s*\(\s*stripslashes\s*\('
  'array_map\s*\(\s*["\x27]assert["\x27]'
  'call_user_func\s*\(\s*["\x27]\$'
  'ReflectionFunction.*invoke'
  '\$\$[a-zA-Z_].*\('
  'create_function.*\$_(?:GET|POST|REQUEST|COOKIE)'
  'ob_start\s*\(\s*["\x27]ob_gzhandler["\x27]'
)

# Suspicious patterns (high risk)
SUSPICIOUS_PATTERNS=(
  'base64_decode.*eval'
  'gzinflate.*base64_decode'
  'str_rot13.*eval'
  'system\s*\(\s*\$'
  'shell_exec\s*\(\s*\$'
  'exec\s*\(\s*\$'
  'passthru\s*\(\s*\$'
  'proc_open\s*\('
  'popen\s*\('
  'pcntl_exec\s*\('
  'mail\s*\(.*\$_(GET|POST|REQUEST)'
  'fsockopen\s*\(\s*\$'
  'file_get_contents\s*\(.*http'
  'curl_exec\s*\('
  'move_uploaded_file.*\$_FILES'
  '@include\s*\(\s*\$'
  '@require\s*\(\s*\$'
  'file_put_contents.*\$_(GET|POST|REQUEST)'
  'fwrite.*\$_(GET|POST|REQUEST)'
  'chmod\s*\(.*0777'
  '\$_(?:GET|POST|REQUEST|COOKIE)\s*\[.*\]\s*\('
  'extract\s*\(\s*\$_(?:GET|POST|REQUEST)'
)

# Dangerous functions
DANGEROUS_FUNCTIONS=(
  'eval'
  'assert'
  'system'
  'shell_exec'
  'exec'
  'passthru'
  'proc_open'
  'popen'
  'pcntl_exec'
  'base64_decode'
  'gzinflate'
  'gzuncompress'
  'str_rot13'
  'create_function'
  'preg_replace.*\/e'
  'call_user_func'
  'ob_start'
  'array_map'
  'array_filter'
  'uasort'
  'usort'
  'preg_replace_callback'
  'register_shutdown_function'
  'register_tick_function'
  'mb_ereg_replace'
  'extract'
)

# Suspicious domains and URLs (AI-Bolit signatures)
SUSPICIOUS_DOMAINS=(
  '\.click'
  '\.top'
  '\.work'
  '\.xyz'
  '\.pw'
  '\.cc'
  'rakuten.*\.click'
  'bit\.ly'
  'tinyurl\.com'
  'goo\.gl'
  't\.co'
  'ow\.ly'
  'is\.gd'
  '\.ru/[a-z0-9]{5,}'
)

# Backdoor signatures
BACKDOOR_SIGNATURES=(
  'c99shell'
  'r57shell'
  'wso\s*shell'
  'b374k'
  'FilesMan'
  'Fx29Sh'
  'WSO\s*[0-9]'
  'Shell\s*Bot'
  'Safe0ver'
  'Angel\s*Shell'
  'Backdoor\.PHP'
  'phpspy'
  'PHPRemoteView'
  'WebShell'
  'Simple\s*Shell'
  'GFS\s*web-shell'
  'RemExp'
  'NetworkFileManagerPHP'
  'Cyber\s*Shell'
  'Worse\s*Linux'
)

# Obfuscation signatures
OBFUSCATION_PATTERNS=(
  '\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}'
  'chr\s*\(\s*[0-9]+\s*\)\.chr'
  '\$[a-zA-Z_]+\s*=\s*["\x27]{2}.*chr\s*\('
  'pack\s*\(\s*["\x27]H\*["\x27]'
  'convert_uudecode'
  'gzuncompress.*base64'
  'rawurldecode.*%[0-9a-fA-F]{2}'
)

# ==========================================
# FUNCTIONS
# ==========================================

check_pattern() {
  local file="$1"
  local pattern="$2"
  local severity="$3"
  
  if grep -qP "$pattern" "$file" 2>/dev/null; then
    echo -e "${RED}[!] $severity DETECTED${NC}"
    echo "[!] FILE: $file" >> "$AIBOLIT_PATTERNS_FILE"
    echo "[!] SEVERITY: $severity" >> "$AIBOLIT_PATTERNS_FILE"
    echo "[!] PATTERN: $pattern" >> "$AIBOLIT_PATTERNS_FILE"
    echo "[!] MATCHED LINES:" >> "$AIBOLIT_PATTERNS_FILE"
    grep -nP "$pattern" "$file" 2>/dev/null | head -5 >> "$AIBOLIT_PATTERNS_FILE"
    echo "" >> "$AIBOLIT_PATTERNS_FILE"
    echo "---" >> "$AIBOLIT_PATTERNS_FILE"
    echo "" >> "$AIBOLIT_PATTERNS_FILE"
    return 0
  fi
  return 1
}

# ==========================================
# 1. Base64 in non-certificate files
# ==========================================
echo -e "${BLUE}[1/9] Scanning for Base64 in non-certificate files...${NC}"
echo "=== BASE64 IN NON-CERTIFICATE FILES ===" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

find "$SCAN_DIR" -type f \
  ! -name "*.crt" ! -name "*.pem" ! -name "*.cer" ! -name "*.key" \
  ! -name "*.p12" ! -name "*.pfx" ! -name "*.p7b" ! -name "*.p7c" \
  ! -name "*.der" ! -name "*.csr" ! -name "*.jks" ! -name "*.keystore" \
  ! -name "*.jpg" ! -name "*.jpeg" ! -name "*.png" ! -name "*.gif" \
  ! -name "*.bmp" ! -name "*.ico" ! -name "*.svg" ! -name "*.webp" \
  ! -name "*.woff" ! -name "*.woff2" ! -name "*.ttf" ! -name "*.eot" ! -name "*.otf" \
  ! -name "*.pdf" ! -name "*.zip" ! -name "*.tar" ! -name "*.gz" \
  ! -name "*.mp4" ! -name "*.mp3" ! -name "*.avi" ! -name "*.mov" \
  ! -name "*.doc" ! -name "*.docx" ! -name "*.xls" ! -name "*.xlsx" \
  -exec grep -l -E '[A-Za-z0-9+/]{60,}={0,2}' {} \; 2>/dev/null | sort -u >> "$RESULTS_FILE"

echo "" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# ==========================================
# 2. PHP with base64_decode + dangerous functions
# ==========================================
echo -e "${BLUE}[2/9] Scanning for base64_decode + dangerous functions...${NC}"
echo "=== BASE64_DECODE + DANGEROUS FUNCTIONS ===" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

find "$SCAN_DIR" -type f -name "*.php" -exec grep -l "base64_decode" {} \; 2>/dev/null | \
  xargs grep -l -E "(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|gzinflate|gzuncompress|str_rot13|create_function|preg_replace.*\/e)" 2>/dev/null | \
  sort -u >> "$RESULTS_FILE"

echo "" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# ==========================================
# 3. External connections
# ==========================================
echo -e "${BLUE}[3/9] Scanning for external connections...${NC}"
echo "=== EXTERNAL CONNECTIONS ===" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

find "$SCAN_DIR" -type f -name "*.php" \
  -exec grep -l -E "(curl_init|file_get_contents|fsockopen|fopen|stream_socket_client).*(http://|https://)" {} \; 2>/dev/null | \
  sort -u >> "$RESULTS_FILE"

echo "" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# ==========================================
# 4. Suspicious filenames
# ==========================================
echo -e "${BLUE}[4/9] Scanning for suspicious filenames...${NC}"
echo "=== SUSPICIOUS FILENAMES ===" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

find "$SCAN_DIR" -type f \( \
  -name "*.php.*" -o \
  -name "*wp-l0gin*" -o \
  -name "*admin-ajax*" -o \
  -name "*mah.php" -o \
  -name "*radio.php" -o \
  -name "*content.php" -o \
  -name "*lock*.php" -o \
  -name "*ext.php" -o \
  -name "*.suspected" -o \
  -name "*.ico.php" -o \
  -name ".*.php" -o \
  -name "*backup*.php" -o \
  -name "*shell*.php" -o \
  -name "*c99*.php" -o \
  -name "*r57*.php" -o \
  -name "*wso*.php" -o \
  -name "*b374k*.php" \
\) 2>/dev/null | sort -u >> "$RESULTS_FILE"

echo "" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# ==========================================
# 5. All .htaccess files
# ==========================================
echo -e "${BLUE}[5/9] Checking all .htaccess files...${NC}"
echo "=== .HTACCESS FILES ===" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

find "$SCAN_DIR" -name ".htaccess" 2>/dev/null | while read -r file; do
  echo "=== $file ===" >> "$RESULTS_FILE"
  echo "" >> "$RESULTS_FILE"
  cat "$file" >> "$RESULTS_FILE" 2>/dev/null
  echo "" >> "$RESULTS_FILE"
  echo "" >> "$RESULTS_FILE"
  echo "---" >> "$RESULTS_FILE"
  echo "" >> "$RESULTS_FILE"
done

echo "" >> "$RESULTS_FILE"

# ==========================================
# 6. Long Base64 strings in PHP
# ==========================================
echo -e "${BLUE}[6/9] Scanning for long Base64 strings in PHP files...${NC}"
echo "=== LONG BASE64 STRINGS IN PHP (100+ CHARS) ===" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

find "$SCAN_DIR" -type f -name "*.php" \
  -exec grep -H -n -E '[A-Za-z0-9+/]{100,}={0,2}' {} \; 2>/dev/null | \
  head -100 >> "$RESULTS_FILE"

echo "" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# ==========================================
# 7. AI-BOLIT: Critical patterns
# ==========================================
echo -e "${BLUE}[7/9] Checking AI-Bolit CRITICAL patterns...${NC}"
echo "=== AI-BOLIT CRITICAL PATTERNS ===" >> "$AIBOLIT_PATTERNS_FILE"
echo "" >> "$AIBOLIT_PATTERNS_FILE"

critical_count=0
find "$SCAN_DIR" -type f -name "*.php" 2>/dev/null | while read -r phpfile; do
  for pattern in "${CRITICAL_PATTERNS[@]}"; do
    if check_pattern "$phpfile" "$pattern" "CRITICAL"; then
      ((critical_count++))
    fi
  done
done

echo "" >> "$AIBOLIT_PATTERNS_FILE"
echo "" >> "$AIBOLIT_PATTERNS_FILE"

# ==========================================
# 8. AI-BOLIT: Suspicious patterns
# ==========================================
echo -e "${BLUE}[8/9] Checking AI-Bolit SUSPICIOUS patterns...${NC}"
echo "=== AI-BOLIT SUSPICIOUS PATTERNS ===" >> "$AIBOLIT_PATTERNS_FILE"
echo "" >> "$AIBOLIT_PATTERNS_FILE"

suspicious_count=0
find "$SCAN_DIR" -type f -name "*.php" 2>/dev/null | while read -r phpfile; do
  for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
    if check_pattern "$phpfile" "$pattern" "SUSPICIOUS"; then
      ((suspicious_count++))
    fi
  done
done

echo "" >> "$AIBOLIT_PATTERNS_FILE"
echo "" >> "$AIBOLIT_PATTERNS_FILE"

# ==========================================
# AI-BOLIT: Backdoor signatures
# ==========================================
echo "=== AI-BOLIT BACKDOOR SIGNATURES ===" >> "$AIBOLIT_PATTERNS_FILE"
echo "" >> "$AIBOLIT_PATTERNS_FILE"

backdoor_count=0
find "$SCAN_DIR" -type f -name "*.php" 2>/dev/null | while read -r phpfile; do
  for pattern in "${BACKDOOR_SIGNATURES[@]}"; do
    if check_pattern "$phpfile" "$pattern" "BACKDOOR"; then
      ((backdoor_count++))
    fi
  done
done

echo "" >> "$AIBOLIT_PATTERNS_FILE"
echo "" >> "$AIBOLIT_PATTERNS_FILE"

# ==========================================
# AI-BOLIT: Obfuscation
# ==========================================
echo "=== AI-BOLIT OBFUSCATION PATTERNS ===" >> "$AIBOLIT_PATTERNS_FILE"
echo "" >> "$AIBOLIT_PATTERNS_FILE"

obfuscation_count=0
find "$SCAN_DIR" -type f -name "*.php" 2>/dev/null | while read -r phpfile; do
  for pattern in "${OBFUSCATION_PATTERNS[@]}"; do
    if check_pattern "$phpfile" "$pattern" "OBFUSCATION"; then
      ((obfuscation_count++))
    fi
  done
done

echo "" >> "$AIBOLIT_PATTERNS_FILE"
echo "" >> "$AIBOLIT_PATTERNS_FILE"

# ==========================================
# 9. Decode Base64 and check for virus patterns
# ==========================================
echo -e "${BLUE}[9/9] Decoding Base64 and checking for virus patterns...${NC}"
echo "=== DECODED BASE64 CONTENT ===" >> "$BASE64_DECODE_FILE"
echo "" >> "$BASE64_DECODE_FILE"

echo "=== VIRUS PATTERN MATCHES ===" >> "$VIRUS_PATTERNS_FILE"
echo "" >> "$VIRUS_PATTERNS_FILE"

# Find PHP files with base64_decode
find "$SCAN_DIR" -type f -name "*.php" -exec grep -l "base64_decode" {} \; 2>/dev/null | while read -r phpfile; do
  echo "=== FILE: $phpfile ===" >> "$BASE64_DECODE_FILE"
  echo "" >> "$BASE64_DECODE_FILE"
  
  # Extract Base64 strings
  grep -oP "base64_decode\s*\(\s*['\"]([A-Za-z0-9+/=]{50,})['\"]" "$phpfile" 2>/dev/null | \
  sed -E "s/base64_decode\s*\(\s*['\"]([A-Za-z0-9+/=]+)['\"]/\1/" | while read -r b64string; do
    
    decoded=$(echo "$b64string" | base64 -d 2>/dev/null)
    
    if [ ! -z "$decoded" ]; then
      echo "--- ENCODED STRING (first 100 chars): ${b64string:0:100}..." >> "$BASE64_DECODE_FILE"
      echo "--- DECODED CONTENT:" >> "$BASE64_DECODE_FILE"
      echo "$decoded" | head -20 >> "$BASE64_DECODE_FILE"
      echo "" >> "$BASE64_DECODE_FILE"
      
      # Check for critical AI-Bolit patterns
      for pattern in "${CRITICAL_PATTERNS[@]}"; do
        if echo "$decoded" | grep -qP "$pattern" 2>/dev/null; then
          echo -e "${RED}[!] CRITICAL AI-BOLIT PATTERN FOUND: $pattern${NC}"
          echo "[!] FILE: $phpfile" >> "$VIRUS_PATTERNS_FILE"
          echo "[!] SEVERITY: CRITICAL" >> "$VIRUS_PATTERNS_FILE"
          echo "[!] PATTERN: $pattern" >> "$VIRUS_PATTERNS_FILE"
          echo "[!] DECODED CONTENT:" >> "$VIRUS_PATTERNS_FILE"
          echo "$decoded" | head -10 >> "$VIRUS_PATTERNS_FILE"
          echo "" >> "$VIRUS_PATTERNS_FILE"
          echo "---" >> "$VIRUS_PATTERNS_FILE"
          echo "" >> "$VIRUS_PATTERNS_FILE"
        fi
      done
      
      # Check for suspicious patterns
      for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
        if echo "$decoded" | grep -qP "$pattern" 2>/dev/null; then
          echo -e "${YELLOW}[!] SUSPICIOUS PATTERN FOUND: $pattern${NC}"
          echo "[!] FILE: $phpfile" >> "$VIRUS_PATTERNS_FILE"
          echo "[!] SEVERITY: SUSPICIOUS" >> "$VIRUS_PATTERNS_FILE"
          echo "[!] PATTERN: $pattern" >> "$VIRUS_PATTERNS_FILE"
          echo "[!] DECODED CONTENT:" >> "$VIRUS_PATTERNS_FILE"
          echo "$decoded" | head -10 >> "$VIRUS_PATTERNS_FILE"
          echo "" >> "$VIRUS_PATTERNS_FILE"
          echo "---" >> "$VIRUS_PATTERNS_FILE"
          echo "" >> "$VIRUS_PATTERNS_FILE"
        fi
      done
    fi
    
    echo "========================================" >> "$BASE64_DECODE_FILE"
    echo "" >> "$BASE64_DECODE_FILE"
  done
  
  echo "" >> "$BASE64_DECODE_FILE"
  echo "" >> "$BASE64_DECODE_FILE"
done

# ==========================================
# Summary
# ==========================================
echo "" | tee -a "$RESULTS_FILE"
echo -e "${GREEN}=== SCAN COMPLETED ===${NC}" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Statistics
echo "=== STATISTICS ===" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

critical_total=$(grep -c "SEVERITY: CRITICAL" "$AIBOLIT_PATTERNS_FILE" 2>/dev/null || echo "0")
suspicious_total=$(grep -c "SEVERITY: SUSPICIOUS" "$AIBOLIT_PATTERNS_FILE" 2>/dev/null || echo "0")
backdoor_total=$(grep -c "SEVERITY: BACKDOOR" "$AIBOLIT_PATTERNS_FILE" 2>/dev/null || echo "0")
obfuscation_total=$(grep -c "SEVERITY: OBFUSCATION" "$AIBOLIT_PATTERNS_FILE" 2>/dev/null || echo "0")
virus_total=$(grep -c "VIRUS PATTERN FOUND" "$VIRUS_PATTERNS_FILE" 2>/dev/null || echo "0")

echo -e "${RED}Critical threats: $critical_total${NC}" | tee -a "$RESULTS_FILE"
echo -e "${YELLOW}Suspicious patterns: $suspicious_total${NC}" | tee -a "$RESULTS_FILE"
echo -e "${MAGENTA}Backdoors detected: $backdoor_total${NC}" | tee -a "$RESULTS_FILE"
echo -e "${CYAN}Obfuscated code: $obfuscation_total${NC}" | tee -a "$RESULTS_FILE"
echo -e "${RED}Virus patterns in decoded Base64: $virus_total${NC}" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

total_threats=$((critical_total + suspicious_total + backdoor_total + obfuscation_total + virus_total))

echo "Results saved to:" | tee -a "$RESULTS_FILE"
echo "  - Main report: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "  - AI-Bolit patterns: $AIBOLIT_PATTERNS_FILE" | tee -a "$RESULTS_FILE"
echo "  - Decoded Base64: $BASE64_DECODE_FILE" | tee -a "$RESULTS_FILE"
echo "  - Virus patterns: $VIRUS_PATTERNS_FILE" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

if [ "$total_threats" -gt 0 ]; then
  echo -e "${RED}========================================${NC}"
  echo -e "${RED}WARNING: $total_threats THREAT(S) DETECTED!${NC}"
  echo -e "${RED}========================================${NC}"
  echo ""
  echo "Priority actions:"
  echo "1. Check $AIBOLIT_PATTERNS_FILE for AI-Bolit detections"
  echo "2. Check $VIRUS_PATTERNS_FILE for decoded malware"
  echo "3. Review files in $RESULTS_FILE"
else
  echo -e "${GREEN}========================================${NC}"
  echo -e "${GREEN}No obvious threats detected${NC}"
  echo -e "${GREEN}========================================${NC}"
fi
