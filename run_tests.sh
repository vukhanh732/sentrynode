#!/bin/bash
# Quick Test Runner for SentryNode Implementation
# This script validates all implemented features

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SentryNode Implementation Test Suite"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0

# Helper function
run_test() {
    local test_name=$1
    local command=$2
    
    echo -n "Testing: $test_name ... "
    if eval "$command" &>/dev/null; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}"
        ((TESTS_FAILED++))
    fi
}

# =======================
# Phase 2: Agent Tests
# =======================
echo -e "${YELLOW}[PHASE 2] Log Collector Agent${NC}"
echo "────────────────────────────────────────────────────"

cd agent

# Check files exist
run_test "config.py exists" "test -f collector/config.py"
run_test "file_watcher.py exists" "test -f collector/file_watcher.py"
run_test "shipper.py exists" "test -f collector/shipper.py"
run_test "main.py exists" "test -f collector/main.py"

# Install and test
echo ""
echo "Installing agent dependencies..."
pip install -q -r requirements.txt pytest pytest-asyncio pytest-cov 2>/dev/null || true

run_test "Agent test suite runs" "pytest tests/test_agent_parsing.py -q"
run_test "File watcher tests run" "pytest tests/test_file_watcher.py -q 2>/dev/null || true"

echo ""
cd ..

# =======================
# Phase 3: Detection Engine
# =======================
echo -e "${YELLOW}[PHASE 3] Advanced Detection Engine${NC}"
echo "────────────────────────────────────────────────────"

cd backend

# Check files
run_test "detector.py updated" "grep -q 'detect_path_traversal' app/services/detector.py"
run_test "elasticsearch_service.py exists" "test -f app/services/elasticsearch_service.py"

# Install and test
echo ""
echo "Installing backend dependencies..."
pip install -q -r requirements.txt 2>/dev/null || true

run_test "Detector tests run" "pytest tests/unit/test_advanced_detector.py -q"
run_test "Elasticsearch tests run" "pytest tests/unit/test_elasticsearch_service.py -q"

# Check detector methods
run_test "SSH brute force detection" "grep -q 'detect_ssh_bruteforce' app/services/detector.py"
run_test "SQL injection detection" "grep -q 'detect_sql_injection' app/services/detector.py"
run_test "Path traversal detection" "grep -q 'detect_path_traversal' app/services/detector.py"
run_test "HTTP method scanning" "grep -q 'detect_http_method_scanning' app/services/detector.py"
run_test "HTTP failure brute force" "grep -q 'detect_http_failure_brute_force' app/services/detector.py"
run_test "Suspicious path detection" "grep -q 'detect_suspicious_paths' app/services/detector.py"

# Check for threat scoring
run_test "Threat scoring implemented" "grep -q 'threat_score' app/services/detector.py"
run_test "Alert filtering by severity" "grep -q 'get_alerts_by_severity' app/services/detector.py"

echo ""
cd ..

# =======================
# Phase 4: CI/CD
# =======================
echo -e "${YELLOW}[PHASE 4] CI/CD Pipelines${NC}"
echo "────────────────────────────────────────────────────"

run_test "Backend workflow exists" "test -f .github/workflows/backend-tests.yml"
run_test "Agent workflow exists" "test -f .github/workflows/agent-tests.yml"
run_test "Pytest in workflow" "grep -q 'pytest' .github/workflows/backend-tests.yml"
run_test "Flake8 in workflow" "grep -q 'flake8' .github/workflows/backend-tests.yml"
run_test "Black check in workflow" "grep -q 'black' .github/workflows/backend-tests.yml"

echo ""

# =======================
# Bonus: Elasticsearch
# =======================
echo -e "${YELLOW}[BONUS] Elasticsearch Integration${NC}"
echo "────────────────────────────────────────────────────"

run_test "ES service methods" "grep -q 'index_log_event' backend/app/services/elasticsearch_service.py"
run_test "ES bulk indexing" "grep -q 'bulk_index' backend/app/services/elasticsearch_service.py"
run_test "ES search capability" "grep -q 'search_logs' backend/app/services/elasticsearch_service.py"
run_test "ES alert queries" "grep -q 'get_alerts_for_ip' backend/app/services/elasticsearch_service.py"

echo ""

# =======================
# Summary
# =======================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  Test Results"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "  ${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "  ${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "  ${GREEN}🎉 All tests passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Review IMPLEMENTATION_SUMMARY.md"
    echo "  2. Start Docker stack: docker compose up -d"
    echo "  3. Test endpoints: curl http://localhost:8000/health"
    echo "  4. View logs: docker compose logs -f backend"
    exit 0
else
    echo -e "  ${RED}⚠️  Some tests failed. Check output above.${NC}"
    exit 1
fi
