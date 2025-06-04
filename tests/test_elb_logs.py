import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from elb_logs import parse_log_line, categorize_status

def test_parse_real_elb_log_line():
    line = (
        'https 2025-05-26T23:55:12.664047Z app/erank-app/88dfa9dc536560af '
        '34.217.80.200:44256 172.31.37.43:80 0.003 0.035 0.000 200 200 157 4408 '
        '"GET https://members.erank.com:443/ HTTP/1.1" "Datadog Agent/7.54.0" '
        'TLS_AES_128_GCM_SHA256 TLSv1.3 '
        'arn:aws:elasticloadbalancing:us-west-2:848357551741:targetgroup/erank-app-v3-production/902b52047b6f4e28 '
        '"Root=1-6834ff60-6082aea9622eb93162ebf591" "members.erank.com" '
        '"arn:aws:acm:us-west-2:848357551741:certificate/c5395ea3-7277-455d-bd7f-9369ac9eed6c" '
        '1 2025-05-26T23:55:12.625000Z "waf,forward" "-" "-" "172.31.37.43:80" '
        '"200" "-" "-" TID_62b60b871f1a3146acf08aec25fc1aed'
    )

    result = parse_log_line(line, "test-real.gz")
    
    assert result is not None
    assert result["elb_status_code"] == 200
    assert result["http_method"] == "GET"
    assert result["hostname"] == "members.erank.com"
    assert result["ua_browser_family"] == "Other"
    assert result["is_bot"] is True  # Detected from "Datadog Agent"

def test_categorize_status():
    assert categorize_status(100) == "1xx_Informational"
    assert categorize_status(200) == "2xx_Success"
    assert categorize_status(300) == "3xx_Redirection"
    assert categorize_status(404) == "4xx_ClientError"
    assert categorize_status(500) == "5xx_ServerError"
    assert categorize_status(999) == "Other"
    
def test_parse_invalid_log_line():
    line = 'invalid log line without expected fields'
    result = parse_log_line(line, "test-invalid.gz")
    
    assert result is None  # Expecting None for invalid log lines
    
def test_parse_empty_log_line():
    line = ''
    result = parse_log_line(line, "test-empty.gz")
    
    assert result is None  # Expecting None for empty log lines
    
def test_parse_log_line_with_missing_fields():
    line = (
        'https 2025-05-26T23:55:12.664047Z app/erank-app/88dfa9dc536560af '
    )
    result = parse_log_line(line, "test-missing-fields.gz")
    assert result is None  # Expecting None for log lines with missing fields
