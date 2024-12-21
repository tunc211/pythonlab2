import re
import json
from collections import Counter

def parse_log(log_data):
    url_status_pattern = re.compile(r'\"[A-Z]+ (?P<url>https?://[^\s]+) HTTP/[^\"]+\" (?P<status>\d{3})')
    url_status_list = []

    for line in log_data:
        match = url_status_pattern.search(line)
        if match:
            url_status_list.append((match.group('url'), match.group('status')))
    return url_status_list

def filter_404(url_status_list):
    filtered = [url for url, status in url_status_list if status == '404']
    return Counter(filtered)

def print_url_status_report(url_status_list):
    print("URL Status Report:")
    for url, status in url_status_list:
        print(f"URL: {url}, Status Code: {status}")

def print_malware_candidates(counter_404):
    print("\nMalware Candidates (404 URLs):")
    for url, count in counter_404.items():
        print(f"URL: {url}, 404 Count: {count}")

def parse_blacklist_domains(html_content):
    domains = re.findall(r'<domain>(.*?)</domain>', html_content)
    return [domain.strip() for domain in domains]

def match_blacklist(url_status_list, blacklist):
    matched = [(url, status) for url, status in url_status_list if any(domain in url for domain in blacklist)]
    return matched

def print_alert_json(matched_list):
    alerts = [
        {"url": url, "status": status, "count": matched_list.count((url, status))}
        for url, status in set(matched_list)
    ]
    print("\nAlert JSON:")
    print(json.dumps(alerts, indent=4))

def print_summary_json(total_urls, total_404, total_matched):
    summary = {
        "total_urls": total_urls,
        "total_404_urls": total_404,
        "total_blacklist_matched": total_matched
    }
    print("\nSummary JSON:")
    print(json.dumps(summary, indent=4))

def main():
    log_data = [
        '192.168.1.100 - - [05/Dec/2024:09:15:10 +0000] "GET http://malicious-site.com/page1 HTTP/1.1" 404 4321',
        '192.168.1.100 - - [05/Dec/2024:09:16:10 +0000] "GET http://example.com/page1 HTTP/1.1" 200 2123',
        '192.168.1.101 - - [05/Dec/2024:09:17:15 +0000] "GET http://malicious-site.com/page2 HTTP/1.1" 404 1234',
        '192.168.1.102 - - [05/Dec/2024:09:18:20 +0000] "GET http://example.com/page3 HTTP/1.1" 200 3421',
        '192.168.1.100 - - [05/Dec/2024:09:19:30 +0000] "GET http://example.com/page2 HTTP/1.1" 404 3123'
    ]

    html_content = """
    <domain>malicious-site.com</domain>
    <domain>example.com</domain>
    """
    
    url_status_list = parse_log(log_data)

    counter_404 = filter_404(url_status_list)

    print_url_status_report(url_status_list)

    print_malware_candidates(counter_404)

    blacklist = parse_blacklist_domains(html_content)

    matched_list = match_blacklist(url_status_list, blacklist)

    print_alert_json(matched_list)

    print_summary_json(len(url_status_list), len(counter_404), len(matched_list))

if __name__ == "__main__":
    main()