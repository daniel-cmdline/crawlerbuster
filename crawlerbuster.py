import time
import subprocess
from collections import defaultdict, deque
from datetime import datetime
import configparser

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    requests = None
    REQUESTS_AVAILABLE = False
    print('Warning: The "requests" library is not installed. IP reporting functionality is Disabled.', flush=True)

config = configparser.ConfigParser()
config.read('./config.ini')

# Feeds from config.ini file
LOG_PATH = str(config['params']['log_path'])
THRESHOLD = int(config['params']['threshold'])
WINDOW = int(config['params']['window'])
BAN_DURATION = int(config['params']['ban_duration'])
SAFE_IP_LIST = str(config['params']['safe_ip_list'])
KEY_WORDS = str(config['params']['keywords'])
ABUSEIPDB_API_KEY = str(config['params']['abuseipdb_api_key'])

# Checks and informs API key and the rquests library availability
if REQUESTS_AVAILABLE and ABUSEIPDB_API_KEY:
    print("Ip reporting functionality is Enabled, reporting directly to https://docs.abuseipdb.com/", flush=True)
elif REQUESTS_AVAILABLE and not ABUSEIPDB_API_KEY:
    print("Warning: 'requests' library is installed, but AbuseIPDB API key is missing. IP reporting functionality is Disabled.", flush=True)
elif not REQUESTS_AVAILABLE:
    print("Info: Skipping AbuseIPDB check as 'requests' library is not available.", flush=True)


# defaultdict for storing ip's and timestemps in the deque
request_log = defaultdict(lambda: deque())
# set to stored banned ips
banned_ips = set()
# parses the safe list
safe_list = SAFE_IP_LIST.split()
# parses the keywords
key_words = KEY_WORDS.split()


def report_ip(api_key, ip, comment, categories):
    url = f'https://api.abuseipdb.com/api/v2/report'
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    params = {
        'ip': ip,
        'comment': comment,
        'categories': categories
    }
    try:
        response = requests.post(url, headers=headers, data=params)
        response.raise_for_status()
        print(f'Status Code: {response.status_code}', flush=True)
        print('Response JSON:', flush=True)
        print(response.json(), flush=True)
        return response.json()
    except requests.exceptions.HTTPError as errh:
        print(f'Http Error: {errh}', flush=True)
    except requests.exceptions.ConnectionError as errc:
        print(f'Error Connecting: {errc}', flush=True)
    except requests.exceptions.Timeout as errt:
        print(f'Timeout Error: {errt}', flush=True)
    except requests.exceptions.RequestException as err:
        print(f'An error occurred: {err}', flush=True)
    return None

def parse_log_line(line):
    try:
        parts = line.split()
        ip = parts[0]
        timestamp_str = line.split('[')[1].split(']')[0]
        timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z").timestamp()
        is_get_request = 'GET' in line
        
        # Check if any keyword from KEY_WORDS is found in the line
        # Returns True if found, False otherwise.
        found_any_keyword = False
        for key in key_words:
            if key and key in line:
                found_any_keyword = True
                break
        
        return ip, timestamp, is_get_request, found_any_keyword
            
    except Exception:
        print(f"Error parsing log line: {line.strip()}", flush=True)
        return None, None, False, False

def block_ip(ip):
    if ip in banned_ips:
        return
    print(f'Blocking IP: {ip}', flush=True)
    try:
        subprocess.run(['sudo','/sbin/iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        banned_ips.add(ip)
    except subprocess.CalledProcessError as e:
        print(f'Failed to block IP {ip}: {e}', flush=True)

def tail_log(path):
    with open(path, 'r') as f:
        f.seek(0,2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line
            
def main():
    print('Crawler Buster is online. #Monitoring apache2 logs...', flush=True)
    for line in tail_log(LOG_PATH):
        ip, timestamp, is_get_request, found_any_keyword = parse_log_line(line)
        
        if not ip:
            continue

        if ip in safe_list:
            continue

        # First Ban Mechanism: Immediate Ban if Keyword is Found
        if found_any_keyword:
            print(f'Immediate ban: Keyword detected for IP: {ip} in line: {line.strip()}', flush=True)
            block_ip(ip)
            if ABUSEIPDB_API_KEY and requests is not None:
                # Reports IP if feature is enabled
                report_ip(ABUSEIPDB_API_KEY, ip, 'IP tried to access critical web dir (keyword match) detected by crawlerbuster =>(github.com/daniel-cmdline/crawlerbuster)', '19,21')
            continue

        # Second Ban Mechanism: Rate-Limit Ban if NO Keyword is Found
        if is_get_request:
            dq = request_log[ip]
            dq.append(timestamp)

            # Clean up old timestamps
            while dq and (timestamp - dq[0]) > WINDOW:
                dq.popleft()

            # Check if threshold is met for GET requests
            if len(dq) >= THRESHOLD and ip not in banned_ips:
                print(f'Burst scan detected from {ip}: {len(dq)} GET requests in {WINDOW} seconds. No keyword match, but threshold met.', flush=True)
                block_ip(ip)
                if ABUSEIPDB_API_KEY and requests is not None:
                    report_ip(ABUSEIPDB_API_KEY, ip, f'High volume GET request activity detected by crawlerbuster (Threshold: {THRESHOLD} requests in {WINDOW}s) =>(github.com/daniel-cmdline/crawlerbuster)', '19')

if __name__ == "__main__":
    main()
