#!/usr/bin/env python3

import argparse
import concurrent.futures
import os
import sys
import time
import re
import random
from urllib.parse import urljoin, urlparse, parse_qs
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

WP_COMMON_DIRS = [
    "wp-admin",
    "wp-content",
    "wp-includes",
    "wp-content/uploads",
    "wp-content/plugins",
    "wp-content/themes",
    "wp-content/cache",
    "wp-json",
    "wp-login.php",
    "xmlrpc.php",
]

WP_ADDITIONAL_PATHS = [
    "license.txt",
    "readme.html",
    "wp-config.php",
    "wp-config-sample.php",
    "wp-cron.php",
    "wp-links-opml.php",
    "wp-load.php",
    "wp-mail.php",
    "wp-settings.php",
    "wp-signup.php",
    "wp-trackback.php",
    ".git",
    ".env",
    "backup",
    "wp-content/backup-db",
    "wp-content/uploads/wp-backup",
    "wp-content/debug.log",
    "wp-content/upgrade",
    "wp-snapshots",
    "wp-admin/maint",
    "error_log",
    "wp-content/mysql.sql",
    "wp-content/uploads/db-backup"
]

VULNERABILITY_PATTERNS = [
    r'(sql\s*injection|xss|csrf)',
    r'(CVE-\d{4}-\d{4,7})',
    r'(error|exception|warning|deprecated)',
    r'(password|user|username|pass|pwd)\s*=',
    r'(database|mysqli|pdo)',
    r'(admin|root|administrator)',
    r'(config|configuration|setup)',
    r'(debug|test|dev)',
    r'(key|secret|token|api)',
]

KNOWN_PLUGINS = [
    "contact-form-7",
    "woocommerce",
    "elementor",
    "jetpack",
    "akismet",
    "wordfence",
    "yoast-seo",
    "duplicate-post",
    "wp-super-cache",
    "classic-editor",
    "gutenberg",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
]

MAX_THREADS = 20
TIMEOUT = 10
DELAY = 0.2


class WPScanner:
    def __init__(self, target_url, output_file=None, verbose=False, aggressive=False, detect_plugins=True, detect_themes=True, detect_vulns=True, cookie=None, proxy=None):
        self.target_url = target_url if target_url.endswith("/") else target_url + "/"
        self.output_file = output_file
        self.verbose = verbose
        self.aggressive = aggressive
        self.detect_plugins = detect_plugins
        self.detect_themes = detect_themes
        self.detect_vulns = detect_vulns
        self.visited_urls = set()
        self.found_dirs = set()
        self.found_files = set()
        self.found_paths = []
        self.accessible_paths = set()
        self.inaccessible_paths = set()
        self.potential_vulns = []
        self.wordpress_version = None
        self.detected_plugins = set()
        self.detected_themes = set()
        self.forms = []
        self.interesting_files = []
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.cookie = cookie
        self.custom_headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        
        if cookie:
            self.custom_headers["Cookie"] = cookie

    def is_valid_wp_site(self):
        try:
            response = requests.get(
                self.target_url, headers=self.custom_headers, timeout=TIMEOUT, proxies=self.proxies
            )
            if response.status_code != 200:
                return False

            soup = BeautifulSoup(response.text, "html.parser")
            
            for tag in soup.find_all(["script", "link"]):
                if tag.get("src") and "wp-content" in tag.get("src"):
                    return True
                if tag.get("href") and "wp-content" in tag.get("href"):
                    return True
            
            meta = soup.find("meta", attrs={"name": "generator"})
            if meta and "WordPress" in meta.get("content", ""):
                content = meta.get("content", "")
                version_match = re.search(r'WordPress (\d+\.\d+(?:\.\d+)?)', content)
                if version_match:
                    self.wordpress_version = version_match.group(1)
                    print(f"{Fore.BLUE}[+] WordPress version: {self.wordpress_version}")
                return True
                    
            for script in soup.find_all("script"):
                if script.string and "admin-ajax.php" in script.string:
                    return True
                    
            return False
        except Exception as e:
            print(f"{Fore.RED}Error checking site: {e}")
            return False

    def check_path(self, path):
        full_url = urljoin(self.target_url, path)
        if full_url in self.visited_urls:
            return None
            
        self.visited_urls.add(full_url)
        time.sleep(DELAY)
        
        try:
            response = requests.get(
                full_url, 
                headers=self.custom_headers, 
                timeout=TIMEOUT, 
                allow_redirects=False, 
                proxies=self.proxies
            )
            status_code = response.status_code
            
            result = {
                "url": full_url,
                "path": path,
                "status_code": status_code,
                "accessible": 200 <= status_code < 400,
                "is_dir": path.endswith("/") or path == "",
                "content_length": len(response.content),
                "content_type": response.headers.get("Content-Type", ""),
                "server": response.headers.get("Server", ""),
                "headers": dict(response.headers),
            }
            
            if result["accessible"]:
                self.accessible_paths.add(path)
                if result["is_dir"]:
                    self.found_dirs.add(path)
                else:
                    self.found_files.add(path)
                    
                if "text/html" in result["content_type"]:
                    soup = BeautifulSoup(response.text, "html.parser")
                    
                    self.extract_links(soup, full_url)
                    
                    if self.detect_vulns:
                        self.check_for_vulnerabilities(full_url, response.text)
                    
                    if self.detect_plugins:
                        self.detect_wp_plugins(soup, response.text)
                    
                    if self.detect_themes:
                        self.detect_wp_themes(soup, response.text)
                        
                    self.extract_forms(soup, full_url)
                    
                if "application/json" in result["content_type"]:
                    self.check_json_content(full_url, response.text)
                    
                if path.endswith(('.txt', '.log', '.sql', '.bak', '.old', '.backup', '.env', '.yml', '.xml')):
                    self.interesting_files.append({"url": full_url, "size": result["content_length"]})
                    
                if "wp-content/plugins/" in path:
                    plugin_match = re.search(r'wp-content/plugins/([^/]+)', path)
                    if plugin_match:
                        self.detected_plugins.add(plugin_match.group(1))
                        
                if "wp-content/themes/" in path:
                    theme_match = re.search(r'wp-content/themes/([^/]+)', path)
                    if theme_match:
                        self.detected_themes.add(theme_match.group(1))
            else:
                self.inaccessible_paths.add(path)
                
            return result
            
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"{Fore.YELLOW}Error accessing {full_url}: {e}")
            self.inaccessible_paths.add(path)
            return {
                "url": full_url,
                "path": path,
                "status_code": 0,
                "accessible": False,
                "is_dir": path.endswith("/"),
                "error": str(e),
            }

    def extract_links(self, soup, base_url):
        for link in soup.find_all("a", href=True):
            href = link["href"]
            parsed_href = urlparse(href)
            
            if not parsed_href.netloc or parsed_href.netloc == urlparse(self.target_url).netloc:
                new_path = parsed_href.path
                if new_path and urljoin(self.target_url, new_path) not in self.visited_urls:
                    self.found_paths.append(new_path)

    def check_for_vulnerabilities(self, url, content):
        for pattern in VULNERABILITY_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches:
                    self.potential_vulns.append({
                        "url": url,
                        "pattern": pattern,
                        "match": match
                    })
                    if self.verbose:
                        print(f"{Fore.MAGENTA}[!] Potential vulnerability indicator in {url}: {match}")

    def detect_wp_plugins(self, soup, content):
        plugin_patterns = [
            r'wp-content/plugins/([^/]+)',
            r'plugins:[\'"]*([^\'"]+)',
        ]
        
        for pattern in plugin_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if match and match not in ['plugins', 'content']:
                    self.detected_plugins.add(match)
                    
        for plugin in KNOWN_PLUGINS:
            if f"wp-content/plugins/{plugin}" in content:
                self.detected_plugins.add(plugin)
                
            plugin_dir = f"wp-content/plugins/{plugin}/"
            if plugin not in self.detected_plugins:
                self.found_paths.append(plugin_dir)

    def detect_wp_themes(self, soup, content):
        theme_patterns = [
            r'wp-content/themes/([^/]+)',
            r'themes:[\'"]*([^\'"]+)',
        ]
        
        for pattern in theme_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if match and match not in ['themes', 'content']:
                    self.detected_themes.add(match)

    def extract_forms(self, soup, url):
        forms = soup.find_all('form')
        for form in forms:
            form_data = {
                'url': url,
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            inputs = form.find_all(['input', 'textarea', 'select'])
            for input_field in inputs:
                input_data = {
                    'name': input_field.get('name', ''),
                    'type': input_field.get('type', 'text'),
                    'value': input_field.get('value', '')
                }
                if input_data['name']:
                    form_data['inputs'].append(input_data)
            
            self.forms.append(form_data)

    def check_json_content(self, url, content):
        try:
            data = content
            if any(term in data.lower() for term in ['password', 'user', 'key', 'token', 'secret', 'admin']):
                self.potential_vulns.append({
                    'url': url,
                    'pattern': 'Sensitive information in JSON response',
                    'match': 'Possibly sensitive data in API response'
                })
        except:
            pass

    def scan_common_wp_dirs(self):
        print(f"{Fore.CYAN}[*] Scanning common WordPress paths...")
        paths_to_check = WP_COMMON_DIRS + WP_ADDITIONAL_PATHS
        
        if self.aggressive:
            print(f"{Fore.YELLOW}[*] Aggressive mode enabled - adding more paths to check")
            with open(os.path.join(os.path.dirname(__file__), 'wp_paths.txt'), 'r') if os.path.exists(os.path.join(os.path.dirname(__file__), 'wp_paths.txt')) else [] as f:
                extra_paths = [line.strip() for line in f]
                paths_to_check.extend(extra_paths)
        
        self.found_paths = paths_to_check.copy()
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(self.check_path, path): path for path in paths_to_check}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    self.print_result(result)
        
        self.process_found_paths()
        
        return results

    def process_found_paths(self):
        while self.found_paths:
            new_paths = list(set(self.found_paths.copy()))  # Deduplicate
            self.found_paths = []
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                futures = {executor.submit(self.check_path, path): path for path in new_paths if urljoin(self.target_url, path) not in self.visited_urls}
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        self.print_result(result)

    def print_result(self, result):
        if result["accessible"]:
            status_color = Fore.GREEN
        else:
            status_color = Fore.RED
        
        print(f"{status_color}[{result['status_code']}] {result['url']}")
        
        if self.verbose and result["accessible"]:
            print(f"  {Fore.CYAN}Size: {result['content_length']} bytes, Type: {result['content_type']}")
            if result["server"]:
                print(f"  {Fore.CYAN}Server: {result['server']}")
        
        if self.output_file:
            with open(self.output_file, "a") as f:
                f.write(f"{result['status_code']},{result['url']},{result['accessible']},{result.get('content_length', 0)}\n")

    def check_plugin_vulnerabilities(self):
        print(f"{Fore.CYAN}[*] Checking detected plugins for potential vulnerabilities...")
        for plugin in self.detected_plugins:
            print(f"{Fore.BLUE}[+] Checking plugin: {plugin}")
            self.check_path(f"wp-content/plugins/{plugin}/readme.txt")
            self.check_path(f"wp-content/plugins/{plugin}/changelog.txt")
            self.check_path(f"wp-content/plugins/{plugin}/README.md")
            self.check_path(f"wp-content/plugins/{plugin}/LICENSE")

    def check_theme_vulnerabilities(self):
        print(f"{Fore.CYAN}[*] Checking detected themes for potential vulnerabilities...")
        for theme in self.detected_themes:
            print(f"{Fore.BLUE}[+] Checking theme: {theme}")
            self.check_path(f"wp-content/themes/{theme}/readme.txt")
            self.check_path(f"wp-content/themes/{theme}/style.css")
            self.check_path(f"wp-content/themes/{theme}/LICENSE")
            self.check_path(f"wp-content/themes/{theme}/screenshot.png")

    def print_summary(self):
        print("\n" + "=" * 70)
        print(f"{Fore.CYAN}Scan Summary for {self.target_url}")
        print("=" * 70)
        print(f"{Fore.GREEN}Accessible Paths: {len(self.accessible_paths)}")
        print(f"{Fore.RED}Inaccessible Paths: {len(self.inaccessible_paths)}")
        print(f"Total URLs Checked: {len(self.visited_urls)}")
        print(f"Directories Found: {len(self.found_dirs)}")
        print(f"Files Found: {len(self.found_files)}")
        
        if self.wordpress_version:
            print(f"\n{Fore.CYAN}WordPress Version: {self.wordpress_version}")
        
        if self.detected_plugins:
            print(f"\n{Fore.CYAN}Detected Plugins ({len(self.detected_plugins)}):")
            for plugin in sorted(self.detected_plugins):
                print(f"  {Fore.GREEN}[+] {plugin}")
                
        if self.detected_themes:
            print(f"\n{Fore.CYAN}Detected Themes ({len(self.detected_themes)}):")
            for theme in sorted(self.detected_themes):
                print(f"  {Fore.GREEN}[+] {theme}")
        
        if self.potential_vulns:
            print(f"\n{Fore.MAGENTA}Potential Vulnerabilities ({len(self.potential_vulns)}):")
            for i, vuln in enumerate(self.potential_vulns[:10], 1):  # Show top 10
                print(f"  {Fore.RED}[!] {i}. {vuln['url']}")
                print(f"     {Fore.YELLOW}Pattern: {vuln['pattern']}")
                print(f"     {Fore.YELLOW}Match: {vuln['match']}")
            
            if len(self.potential_vulns) > 10:
                print(f"  {Fore.YELLOW}... and {len(self.potential_vulns) - 10} more potential issues")
        
        if self.forms:
            print(f"\n{Fore.CYAN}Discovered Forms ({len(self.forms)}):")
            for i, form in enumerate(self.forms[:5], 1):  # Show top 5
                print(f"  {Fore.BLUE}[+] Form {i} at {form['url']}")
                print(f"     {Fore.GREEN}Action: {form['action'] or 'Same page'}")
                print(f"     {Fore.GREEN}Method: {form['method']}")
                print(f"     {Fore.GREEN}Inputs: {', '.join([i['name'] for i in form['inputs'] if i['name']])}")
            
            if len(self.forms) > 5:
                print(f"  {Fore.YELLOW}... and {len(self.forms) - 5} more forms")
                
        if self.interesting_files:
            print(f"\n{Fore.CYAN}Interesting Files ({len(self.interesting_files)}):")
            for i, file in enumerate(sorted(self.interesting_files, key=lambda x: x['size'], reverse=True)[:10], 1):
                print(f"  {Fore.BLUE}[+] {file['url']} ({file['size']} bytes)")
            
            if len(self.interesting_files) > 10:
                print(f"  {Fore.YELLOW}... and {len(self.interesting_files) - 10} more files")
        
        if self.output_file:
            print(f"\n{Fore.CYAN}Results saved to: {self.output_file}")
            
        print("\n" + "=" * 70)
        print(f"{Fore.CYAN}Next Steps:")
        print(f"  {Fore.YELLOW}1. Check potential vulnerabilities")
        print(f"  {Fore.YELLOW}2. Enumerate user accounts: try /wp-json/wp/v2/users")
        print(f"  {Fore.YELLOW}3. Test forms for XSS and CSRF")
        print(f"  {Fore.YELLOW}4. Check plugin versions against known CVEs")
        print("=" * 70)

    def exploit_xmlrpc(self):
        if self.aggressive:
            print(f"{Fore.CYAN}[*] Testing XML-RPC for vulnerabilities...")
            xml_methods = """
            <?xml version="1.0" encoding="utf-8"?>
            <methodCall>
            <methodName>system.listMethods</methodName>
            <params></params>
            </methodCall>
            """
            
            try:
                response = requests.post(
                    urljoin(self.target_url, "xmlrpc.php"), 
                    data=xml_methods, 
                    headers={"Content-Type": "text/xml"}, 
                    timeout=TIMEOUT,
                    proxies=self.proxies
                )
                
                if response.status_code == 200 and "methodResponse" in response.text:
                    print(f"{Fore.RED}[!] XML-RPC is enabled and responding to system.listMethods")
                    methods = re.findall(r'<value><string>(.+?)</string></value>', response.text)
                    print(f"{Fore.YELLOW}[+] Available methods: {', '.join(methods[:10])}...")
                    
                    self.potential_vulns.append({
                        "url": urljoin(self.target_url, "xmlrpc.php"),
                        "pattern": "XML-RPC enabled",
                        "match": "system.listMethods accessible"
                    })
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.YELLOW}Error testing XML-RPC: {e}")

    def check_api_exposure(self):
        print(f"{Fore.CYAN}[*] Checking for exposed WP REST API endpoints...")
        api_endpoints = [
            "wp-json/",
            "wp-json/wp/v2/users",
            "wp-json/wp/v2/posts",
            "wp-json/wp/v2/pages",
            "wp-json/wp/v2/media",
            "wp-json/wp/v2/types",
            "wp-json/wp/v2/statuses",
            "wp-json/wp/v2/taxonomies",
            "wp-json/wp/v2/categories",
            "wp-json/wp/v2/tags",
            "wp-json/wp/v2/comments",
            "wp-json/wp/v2/settings",
            "wp-json/wp/v2/themes"
        ]
        
        for endpoint in api_endpoints:
            self.check_path(endpoint)

    def run(self):
        print(f"{Fore.CYAN}[*] Starting Advanced WordPress Scanner")
        print(f"{Fore.CYAN}[*] Target: {self.target_url}")
        
        if not self.is_valid_wp_site():
            print(f"{Fore.RED}[!] This does not appear to be a WordPress site or is not accessible")
            choice = input("Do you want to continue anyway? (y/n): ")
            if choice.lower() != "y":
                sys.exit(1)
        
        print(f"{Fore.CYAN}[*] Checking site accessibility...")
        root_check = self.check_path("")
        if root_check and not root_check["accessible"]:
            print(f"{Fore.RED}[!] Target site is not accessible")
            sys.exit(1)
            
        if self.output_file:
            with open(self.output_file, "w") as f:
                f.write("status_code,url,accessible,content_length\n")
        
        self.scan_common_wp_dirs()
        
        if self.detect_plugins and self.detected_plugins:
            self.check_plugin_vulnerabilities()
            
        if self.detect_themes and self.detected_themes:
            self.check_theme_vulnerabilities()
            
        self.exploit_xmlrpc()
        self.check_api_exposure()
        
        self.print_summary()


def main():
    parser = argparse.ArgumentParser(description="Advanced WordPress Scanner for CTF/Bug Bounty")
    parser.add_argument("url", help="Target WordPress URL")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Enable aggressive scanning")
    parser.add_argument("-p", "--plugins", action="store_false", help="Disable plugin detection")
    parser.add_argument("-t", "--themes", action="store_false", help="Disable theme detection")
    parser.add_argument("-n", "--no-vulns", action="store_false", help="Disable vulnerability detection")
    parser.add_argument("-c", "--cookie", help="Custom cookie value")
    parser.add_argument("-x", "--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("-r", "--random-agent", action="store_true", help="Use random User-Agent")
    parser.add_argument("-d", "--delay", type=float, help="Delay between requests (default: 0.2s)")
    parser.add_argument("-l", "--wordlist", help="Additional paths wordlist")
    
    args = parser.parse_args()
    
    if args.delay:
        global DELAY
        DELAY = args.delay
    
    if args.wordlist and os.path.exists(args.wordlist):
        print(f"{Fore.CYAN}[*] Loading additional paths from {args.wordlist}")
        try:
            with open(args.wordlist, 'r') as f:
                WP_ADDITIONAL_PATHS.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading wordlist: {e}")
    
    scanner = WPScanner(
        args.url, 
        args.output, 
        args.verbose, 
        args.aggressive, 
        args.plugins, 
        args.themes, 
        args.no_vulns,
        args.cookie,
        args.proxy
    )
    scanner.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user")
        sys.exit(0)
