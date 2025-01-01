import socket
import dns.resolver
import argparse
import whois
import re
import os
import tempfile
import subprocess
import requests
import time
import enum
import bs4

class Colors(enum.Enum):
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    BLUE = "\033[0;34m"
    MAGENTA = "\033[0;35m"
    CYAN = "\033[0;36m"
    WHITE = "\033[0;37m"
    RESET = "\033[0m"
    BLACK = "\033[0;30m"
    HI_BLACK = "\033[0;90m"
    HI_RED = "\033[0;91m"
    HI_GREEN = "\033[0;92m"
    HI_YELLOW = "\033[0;93m"
    HI_BLUE = "\033[0;94m"
    HI_MAGENTA = "\033[0;95m"
    HI_CYAN = "\033[0;96m"
    HI_WHITE = "\033[0;97m"
    HI_BG_BLACK = "\033[0;100m"
    HI_BG_RED = "\033[0;101m"
    HI_BG_GREEN = "\033[0;102m"
    HI_BG_YELLOW = "\033[0;103m"
    HI_BG_BLUE = "\033[0;104m"
    HI_BG_PURPLE = "\033[0;105m"
    HI_BG_CYAN = "\033[0;106m"
    HI_BG_WHITE = "\033[0;107m"

class Styles(enum.Enum):
    NORMAL=""
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    REVERSED = "\033[7m"
    RESET = "\033[0m"
    
class RecordType(enum.Enum):
    SOA=enum.auto(), 
    NS=enum.auto(),
    A=enum.auto(),
    AAAA=enum.auto(), 
    MX=enum.auto(),
    TXT=enum.auto(),

    def from_str(str):
        match(str):
            case "A": return RecordType.A
            case "AAAA": return RecordType.AAAA
            case "NS": return RecordType.NS
            case "SOA": return RecordType.SOA
            case "MX": return RecordType.MX
            case "TXT": return RecordType.TXT

class Config:
    class HEADER:
        CHAR="."
        LENGTH=50
    
    class COLORS:
        PRIMARY_COLOR = Colors.HI_CYAN
        SECONDARY_COLOR = Colors.WHITE
        WHOIS_PRIMARY_COLOR = PRIMARY_COLOR
        WHOIS_SECONDARY_COLOR = SECONDARY_COLOR
        ASIC_PRIMARY_COLOR = PRIMARY_COLOR
        ASIC_SECONDARY_COLOR = SECONDARY_COLOR
        WHM_PRIMARY_COLOR = PRIMARY_COLOR
        WHM_SECONDARY_COLOR = SECONDARY_COLOR
        SPF_PRIMARY_COLOR = PRIMARY_COLOR
        SPF_SECONDARY_COLOR = SECONDARY_COLOR
        RECORD_HIGHLIGHT_COLOR = Colors.GREEN
        
    class STYLES:
        PRIMARY_STYLE=Styles.NORMAL
        SECONDARY_STYLE=Styles.NORMAL
        WHOIS_STYLE=PRIMARY_STYLE
        ASIC_STYLE=PRIMARY_STYLE
        WHM_STYLE=PRIMARY_STYLE
        SPF_STYLE=PRIMARY_STYLE
        
    class URLS:    
        ABN_URL="https://abr.business.gov.au/ABN/View?id="
        ACN_URL="https://connectonline.asic.gov.au/RegistrySearch/faces/landing/panelSearch.jspx?searchTab=search&searchType=OrgAndBusNm&searchText="

    GENERIC_SUBDOMAINS = [
        "www",
        "mail",
        "webmail",
        "ftp",
        "localhost",
        "admin",
        "administrator",
    ]
    
    SMART_SUBDOMAINS = {   
        (RecordType.MX, r"mx\d+\.email-hosting\.net\.au\.") : "axigen._domainkey",
        (RecordType.TXT, r"spf\.email-hosting\.net\.au"): "axigen._domainkey",
        (RecordType.TXT, r"spf\.hostingplatform\.net\.au"): "default._domainkey"
    }
    RECORD_SEPARATOR = " -> "
    
    RECORD_HIGHLIGHTS = {
        r"^.*v=spf1.*$" : lambda record: Config.COLORS.RECORD_HIGHLIGHT_COLOR,
        r"mx\d+\.email-hosting\.net\.au\.": lambda record: Config.COLORS.RECORD_HIGHLIGHT_COLOR,
        r"^ns\d+\.[a-zA-Z0-9]+\.hostingplatform\.net\.au": lambda record: Config.COLORS.RECORD_HIGHLIGHT_COLOR,
        r"ns\d+\.nameserver\.net\.au": lambda record: Config.COLORS.RECORD_HIGHLIGHT_COLOR,
    }

class StringBuilder:
    def __init__(self, default_color=Colors.RESET, default_base_color=Colors.RESET, default_style=Styles.NORMAL):
        self._string = ""
        self.default_color = default_color
        self.default_base_color = default_base_color
        self.default_style = default_style

    def append(self, text):
        self._string += text
        return self

    def write(self, string, color=None, style=None, end="\n"):
        color = color or self.default_color
        style = style or self.default_style
        formatted_string = f"{color.value}{style.value}{string}{Styles.RESET.value}{end}"
        self._string += formatted_string
        return self

    def highlight(self, string, regex_pattern, highlight_color=None, base_color=None, style=None):
        highlight_color = highlight_color or self.default_color
        base_color = base_color or self.default_base_color
        style = style or self.default_style
        
        def apply_highlighting(match):
            return f"{highlight_color.value}{style.value}{match.group(0)}{base_color.value}{Styles.RESET.value}"
        
        highlighted_string = re.sub(regex_pattern, apply_highlighting, string)
        return highlighted_string

    def get_string(self):
        return self._string

    def reset(self):
        self._string = ""
        return self
        
    def display(self):
        print(self._string)
        
class Utils:
    @staticmethod
    def as_list(value):
        return value if isinstance(value, list) else [value]

class StringUtils:
    @staticmethod
    def digitialise(string):
        return ''.join(char for char in string if char.isdigit())

    @staticmethod
    def hyperlink(url, text):
        return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"

class WhoisDisplay:
    def __init__(self, whois_lookup):
        self.whois_lookup = whois_lookup
    
    def __str__(self):
        builder = StringBuilder()
        builder.write(f"{self.whois_lookup.registrar}", Config.COLORS.WHOIS_SECONDARY_COLOR, Config.STYLES.WHOIS_STYLE)
        
        for date in Utils.as_list(self.whois_lookup.updated_date):
            builder.write(f"Updated: {date}", Config.COLORS.WHOIS_SECONDARY_COLOR, Config.STYLES.WHOIS_STYLE)
        
        for status in Utils.as_list(self.whois_lookup.status):
            builder.write(f"Status: {status}", Config.COLORS.WHOIS_SECONDARY_COLOR, Config.STYLES.WHOIS_STYLE)

        for i, nameserver in enumerate(Utils.as_list(self.whois_lookup.name_servers)):
            builder.write(f"Nameserver {i+1}: {nameserver}", Config.COLORS.WHOIS_SECONDARY_COLOR, Config.STYLES.WHOIS_STYLE)
        
        return builder.get_string()

class ACN:
    def __init__(self, url, id):
        self.id = id
        self.url = f"{url}{id}"
    
    def __str__(self):
        builder = StringBuilder()
        builder.write(self.url, Config.COLORS.ACN_SECONDARY_COLOR, Config.STYLES.ACN_STYLE)
        builder.write(f"ACN: {self.id}", Config.COLORS.ACN_SECONDARY_COLOR, Config.STYLES.ACN_STYLE)
        return builder.get_string()

class ABN:
    def __init__(self, url, id):
        abn_data = self.fetch_abn(url, id)
        if abn_data:
            self.id = id
            self.url = f"{url}{id}"
            self.name = abn_data.get("name")
            self.type = abn_data.get("type")
            self.status = abn_data.get("status")

    def fetch_abn(self, url, id):
        abn_search_uri = f"{url}{id}"
        html = requests.get(abn_search_uri).text
        soup = bs4.BeautifulSoup(html, "html.parser").find("div", {'itemscope': True, 'itemtype': 'http://schema.org/LocalBusiness'})    
        
        abn_data = {}
        try:
            entity_type_row = soup.find("th", string="Entity type:")
            if entity_type_row:
                abn_data["type"] = entity_type_row.find_next("a").text.strip()
            abn_data["name"] = soup.find("span", itemprop="legalName").text.strip()
            abn_data["status"] = soup.find("td", string=lambda text: text and ('Active' in text or 'Cancelled' in text)).text.strip()
            return abn_data
        except AttributeError:
            # TODO: Log errors
            return None
        
    def __str__(self):
        builder = StringBuilder()
        builder.write(self.url, Config.COLORS.ASIC_SECONDARY_COLOR, Config.STYLES.ASIC_STYLE)
        builder.write(f"ABN: {self.id}", Config.COLORS.ASIC_SECONDARY_COLOR, Config.STYLES.ASIC_STYLE)
        builder.write(f"Name: {self.name}", Config.COLORS.ASIC_SECONDARY_COLOR, Config.STYLES.ASIC_STYLE)
        builder.write(f"Type: {self.type}", Config.COLORS.ASIC_SECONDARY_COLOR, Config.STYLES.ASIC_STYLE)
        builder.append(builder.highlight(self.status, "Active", Colors.GREEN, Config.COLORS.ASIC_SECONDARY_COLOR, Config.STYLES.ASIC_STYLE) 
                       if "Active" in self.status 
                       else builder.highlight(self.status, "Cancelled", Colors.RED, Config.STYLES.ASIC_STYLE))
        
        return builder.get_string()
    

class Nano:
    def get_text():
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file_path = temp_file.name
        try:
            subprocess.run(['nano', temp_file_path], check=True)
            with open(temp_file_path, 'r') as temp_file:
                content = temp_file.read()
        finally:
            os.unlink(temp_file_path)
        return content


class Logger:
    @staticmethod
    def write(string, color: Colors = Colors.RESET, style: Styles = Styles.NORMAL, end="\n"):
        formatted_string = f"{color.value}{style.value}{string}{Styles.RESET.value}"
        print(formatted_string, end=end)
        
    @staticmethod
    def write_header(string, color: Colors = Colors.RESET, style: Styles = Styles.NORMAL, center_char=".", center_length=50):
        message = f"{string}"
        offset = center_length - len(message)
        left_padding = offset // 2
        right_padding = offset - left_padding
        Logger.write(center_char * left_padding, color, style, end="")
        Logger.write(f"\x1b[7m {message} \x1b[0m", color, style, end="")
        Logger.write(center_char * right_padding, color, style, end="\n")

    
    @staticmethod
    def highlight(string, regex_pattern, color: Colors = Colors.RESET, base_color: Colors=Colors.RESET, style: Styles = Styles.NORMAL):
        def apply_highlighting(match):
            return f"{color.value}{style.value}{match.group(0)}{Styles.RESET.value}{base_color.value}"
        
        highlighted_string = re.sub(regex_pattern, apply_highlighting, string)  
        return f"{highlighted_string}"
                


class Record:
    def __init__(self, host, value, type):
        self.host = host
        self.type = type
        self.value = value

    def __str__(self):
        return f"{self.host} {self.value}"


class MXRecord(Record):
    def __init__(self, host, value, priority):
        super().__init__(host, value, RecordType.MX)
        self.priority = priority

    def __str__(self):
        return f"{self.host} {self.priority} {self.value}"


class SOARecord(Record):
    def __init__(self, host, value, mname, rname, serial, refresh, retry, expire, minimum):
        super().__init__(host, value, RecordType.SOA)
        self.mname = mname
        self.rname = rname
        self.serial = serial
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.minimum = minimum

    def __str__(self):
        return f"{self.host} {self.mname} {self.rname} {self.serial} {self.refresh} {self.retry} {self.expire} {self.minimum}"

class Domain:
    @staticmethod
    def is_fqdn(domain):
        pattern = r'^(([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}|localhost)\.?$'
        return re.match(pattern, f"{domain}") is not None
    
    @staticmethod
    def extract_tld(domain):
        return domain.lower().split(".")[-1]
    
    @staticmethod
    def extract_subdomain(domain, base_domain):
        if domain == base_domain:
            return ""
        return domain.replace(f".{base_domain}", "")
        
class SPFResolver:
    def __init__(self, dns_resolver):
        self.errors = []
        self.lookup_count = 0
        self.dns_resolver = dns_resolver
        self.limit = 10

    def resolve_domain(self, domain):
        try:
            answers = self.dns_resolver.resolve(domain, RecordType.TXT)
            for txt_record in answers:
                txt_data = txt_record.value
                if txt_data.startswith('"') and txt_data.endswith('"'):
                    txt_data = txt_data[1:-1]
                if "v=spf1" in txt_data: 
                    spf_record = txt_data
                    if domain in spf_record:
                        self.errors.append(f"Recursive SPF record detected! Contains the domain: {domain}")
                    return self.parse_spf(spf_record)
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoNameservers:
            return

    def resolve_spf(self, spf):
        try:
            # DNS Resolver includes quotation marks in the TXT record, so we need to remove them
            if spf.startswith('"') and spf.endswith('"'):
                    spf = spf[1:-1]
            return self.parse_spf(spf)
        except Exception as e:
            print(e)
            
    def parse_spf(self, spf_record):
        if spf_record.startswith('"') or spf_record.endswith('"'):
            self.errors.append(f"SPF record has unnecessary quotation marks: {spf_record}")
        
        if "\\" in spf_record:
            self.errors.append(f"SPF record contains backslashes: {spf_record}")
        
        if spf_record.count("~all") > 1:
            self.errors.append(f"Redundant '~all' mechanism detected in SPF record: {spf_record}")
        
        if not spf_record.startswith('v=spf1'):
            self.errors.append(f"Missing 'v=spf1' at the start of the SPF record: {spf_record}")

        if re.search(r'\binclude:[^\w.-]', spf_record):
            self.errors.append(f"Malformed 'include' mechanism in SPF record: {spf_record}")

        if re.search(r'\bredirect=[^\s]+', spf_record):
            self.errors.append(f"SPF record contains a 'redirect' modifier, which should be used alone: {spf_record}")

        if len(re.findall(r'\ba\b', spf_record)) > 1:
            self.errors.append(f"Duplicate 'a' mechanism detected in SPF record: {spf_record}")
        
        if len(re.findall(r'\bmx\b', spf_record)) > 1:
            self.errors.append(f"Duplicate 'mx' mechanism detected in SPF record: {spf_record}")
        
        includes = re.findall(r'include:([\w.-]+)', spf_record)
        seen_includes = set()
        for include in includes:
            if include in seen_includes:
                self.errors.append(f"Duplicate 'include' mechanism for domain {include} detected: {spf_record}")
            seen_includes.add(include)

        if len(spf_record) > 255:
            self.errors.append(f"SPF record exceeds 255 characters: {spf_record}")

        if re.search(r'\b\d{1,3}(\.\d{1,3}){3}\b', spf_record) and not re.search(r'\bip[46]:', spf_record):
            self.errors.append(f"IP address used without 'ip4' or 'ip6' prefix in SPF record: {spf_record}")
        
        if not spf_record.strip():
            self.errors.append("SPF record is empty.")
        
        if re.search(r'\bredirect\b', spf_record) and re.search(r'\b(include|a|mx|ip4|ip6)\b', spf_record):
            self.errors.append(f"SPF record contains both 'redirect' and other mechanisms: {spf_record}")

        if self.lookup_count > self.limit:
            self.errors.append(f"Too many lookups: {spf_record} {self.lookup_count}/{self.limit}")
            return

        if bool(re.search(r'\ba\b', spf_record)):
            self.lookup_count += 1
        if bool(re.search(r'\bmx\b', spf_record)):
            self.lookup_count += 1

        include_results = {}
        includes = re.findall(r'include:([\w.-]+)', spf_record)
        for include_domain in includes:
            if include_domain not in include_results:
                self.lookup_count += 1
                include_results[include_domain] = self.resolve_domain(include_domain)

        redirects = re.findall(r'redirect=([\w.-]+)', spf_record)
        if redirects:
            self.lookup_count += 1
            self.resolve_domain(redirects[0])

        if self.lookup_count > self.limit:
            self.errors.append(f"Too many lookups: {self.lookup_count}/{self.limit} for SPF record: {spf_record}")
        
        result = {
            "count": self.lookup_count,
            "spf": spf_record,
            "include": include_results,
            "errors": self.errors
        }
        return result

class SPFDisplay:
    def __init__(self, spf_lookup):
        self.spf_lookup = spf_lookup
    
    def display(self):
        self.display_lookup(self.spf_lookup)
        self.display_errors(self.spf_lookup)
    
    def display_lookup(self, spf_lookup, depth=0):
        if spf_lookup is None:
            return 
        
        indent = "\t" * depth  # Indentation to show recursion depth
        if not spf_lookup:
            Logger.write(f"{indent}No lookup results to display.", Colors.RED)
            return

        # Display the current SPF record and lookup count with colors
        Logger.write(f"{indent}SPF Lookup Results", Colors.CYAN, Styles.BOLD)
        Logger.write(f"{indent}SPF Record: {spf_lookup.get('spf', 'No SPF record found')}", Colors.WHITE)
        
        if depth == 0:
            Logger.write(f"{indent}Total Lookups: {spf_lookup.get('count', 0)}", Colors.YELLOW)
        
        # Recursively display includes with color
        include_results = spf_lookup.get("include", {})
        if include_results:
            Logger.write(f"{indent}\nIncluded Domains:", Colors.BLUE, Styles.BOLD)
            for domain, result in include_results.items():
                Logger.write(f"{indent}  - {domain}:", Colors.HI_BLUE)
                # If the result is a dictionary (indicating it has been recursively resolved), call display_lookup again
                if isinstance(result, dict):
                    self.display_lookup(result, depth + 1)
                else:
                    Logger.write(f"{indent}    {result}", Colors.HI_GREEN)

        # Display redirects if any
        redirects = spf_lookup.get("redirect", [])
        if redirects:
            Logger.write(f"{indent}\nRedirects:", Colors.MAGENTA, Styles.BOLD)
            for redirect_domain in redirects:
                Logger.write(f"{indent}  - {redirect_domain}", Colors.HI_CYAN)

                
    def display_errors(self, spf_lookup):
        if spf_lookup is None:
            return
        errors = spf_lookup.get("errors", [])
        if errors:
            for error in errors:
                Logger.write(f"- {error}", Colors.HI_RED)

class DNSResolver:
    def __init__(self, nameserver=None):
        self.resolver = dns.resolver.Resolver()

    def resolve(self, domain, type):
        try:
            answers = self.resolver.resolve(domain, type.name)
            match type:
                case RecordType.MX:
                    return [MXRecord(domain, answer.exchange.to_text(), answer.preference) for answer in answers]
                case RecordType.SOA:
                    answer = answers[0]
                    return [SOARecord(domain, answer.to_text(), answer.mname.to_text(), answer.rname.to_text(), answer.serial, answer.refresh, answer.retry, answer.expire, answer.minimum)]
                case _: return [Record(domain, answer.to_text(), type) for answer in answers]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoNameservers:
            return []
        
    def exists(self, domain):
        try:
            self.resolve(domain, RecordType.A)
            return True
        except dns.resolver.NoAnswer:
            return False
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoNameservers:
            return False
        

    
    @staticmethod
    def is_valid_ipv4(ipv4):
        ipv4_pattern = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ipv4_pattern, ipv4):
            return True
        return False

    @staticmethod
    def is_valid_ipv6(ipv6):
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$|^::([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,6}:([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$'
        if re.match(ipv6_pattern, ipv6):
            return True
        return False
    
    @staticmethod
    def is_valid_ip(ip):
        if len(ip) <= 15:
            if DNSResolver.is_valid_ipv4(ip):
                return True
        if DNSResolver.is_valid_ipv6(ip):
            return True
        return False

class WHMResolver:
    def fetch_whm(self, domain):
        try:
            command = ["bash", "-i", "-c", f"whm {domain}"]
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return result.stdout.decode('utf-8')
        except:
            return None
            pass

    def extract_details(self, data):
        match = re.search(r"ID (\d+) - username (\w+) - server ([\w\d.]+)", data)
        if match:
            return {
                "ID": match.group(1),
                "username": match.group(2),
                "server": match.group(3)
            }
        return None

    def extract_title(self, data):
        match = re.search(r"===== (.*?)[: ]", data)
        if match:
            return match.group(1)
        return None

    def parse_name_link(self, data):
        parts = data.split(" - ", 1)
        if len(parts) == 2:
            return {"name": parts[0].strip(), "link": parts[1].strip()}
        return None

    def parse_output(self, output):
        whm_object = {}
        title = ""
        for line in output.split('\n'):
            if "=====" in line:
                if "No service found for domain" in line:
                    continue
                title = self.extract_title(line)
                whm_object[title] = {"details": {}, "links": {}}
            elif "Found service" in line and title:
                details = self.extract_details(line)
                whm_object[title]["details"] = details
            elif "Link" in line and title:
                link = self.parse_name_link(line)
                whm_object[title]["links"][link["name"]] = link["link"]
        return whm_object if title else None
    
    def resolve(self, domain):
        output = self.fetch_whm(domain)    
        if output:
            return self.parse_output(output)
        return None

class RecordDisplay:
    def display_target(target, resolver, separator, depth=0, is_multiple=False):
        def print_target(target, highlight, color, highlight_color, is_multiple, end=""):
            indent = "\t" * depth if is_multiple else ""
            Logger.write((f"{indent}{Logger.highlight(f"{target}", highlight, highlight_color, color)}"), color, end=end)

        color = Config.COLORS.SECONDARY_COLOR
        
        highlight_color = Config.COLORS.RECORD_HIGHLIGHT_COLOR
        highlight_pattern = ""
        
        for pattern in Config.RECORD_HIGHLIGHTS:
            if re.search(pattern, target.value):
                highlight_color = Config.RECORD_HIGHLIGHTS[pattern](target)
                highlight_pattern = pattern
                break

        if Domain.is_fqdn(target.value):
            try:
                results = resolver.resolve(target.value, RecordType.A)
                is_multiple = len(results) > 1

                print_target(target, highlight_pattern, color, highlight_color, is_multiple)
                print(f"{separator}", end="")

                if is_multiple:
                    print()

                for record in results:
                    RecordDisplay.display_target(record, resolver,
                                separator, depth+1, is_multiple)

            except Exception as e:
                Logger.write(f"Error resolving {target}: {e}", Colors.RED, Styles.REVERSED)
        elif DNSResolver.is_valid_ip(target.value):
            try:
                hostname = socket.gethostbyaddr(f"{target.value}")[0]
                print_target(target.value, highlight_pattern, color, highlight_color, is_multiple)
                print(f"{separator}", end="")
                Logger.write(hostname, color)
            
            except socket.herror as e:
                print(f"{separator}", end="")
                Logger.write(f"Unknown Host", Colors.RED, Styles.REVERSED)
        else:
            print_target(target, highlight_pattern, color, highlight_color, is_multiple)
            print()


def main():
    parser = argparse.ArgumentParser(description='Domain Information')
    parser.add_argument('domain', type=str, help='Domain name')
    parser.add_argument("-ns", "--nameserver", help="Set nameserver")
    parser.add_argument("-sd", "--subdomains", help="Multiple subdomains", action="store_true")

    args = parser.parse_args()
    base_domain = args.domain

    dns_resolver = DNSResolver(args.nameserver)
    subdomains = Config.GENERIC_SUBDOMAINS
    
    if args.subdomains:
        subdomains.extend([line for line in Nano.get_text().split("\n") if line != ""])
        for subdomain in subdomains[:]:
            if not dns_resolver.exists(f"{subdomain}.{base_domain}"):
                subdomains.remove(subdomain)                
                
    start_time = time.time()
                
    whm_resolver = WHMResolver()
    whm = whm_resolver.resolve(base_domain)
    if whm is not None:
        Logger.write_header("Web Hosting Manager (WHM)", Config.COLORS.WHM_PRIMARY_COLOR, Config.STYLES.PRIMARY_STYLE)
        for title, data in whm.items():
            if "links" not in data:
                continue
            Logger.write(f"{title}", Config.COLORS.WHM_SECONDARY_COLOR, Config.STYLES.WHM_STYLE)
            for name, link in data["links"].items():
                Logger.write(f"\t{StringUtils.hyperlink(link, name)}", Config.COLORS.WHM_SECONDARY_COLOR, Config.STYLES.WHM_STYLE)


    whois_lookup = whois.whois(base_domain)    
    if whois_lookup.registrant_id != None:
        Logger.write_header("ASIC Lookup", Config.COLORS.ASIC_PRIMARY_COLOR, Config.STYLES.PRIMARY_STYLE)
        id = StringUtils.digitialise(whois_lookup.registrant_id)
        id_length = len(id)
        if id_length == 11:
            abn = ABN(Config.URLS.ABN_URL,id)
            Logger.write(abn)
        elif id_length == 9:
            acn = ACN(Config.URLS.ACN_URL,id)
            Logger.write(acn)
    
    Logger.write_header("Domain Information", Config.COLORS.WHOIS_PRIMARY_COLOR, Config.STYLES.PRIMARY_STYLE)
    Logger.write(WhoisDisplay(whois_lookup), end=" ")
    
    # get all records on the domain
    records = []
    for record_type in RecordType:
        records.extend(dns_resolver.resolve(base_domain, record_type))
    
    # get all the records on the subdomains
    subdomain_records = {}
    for subdomain in subdomains:
        subdomain_records[subdomain] = []
        for record_type in RecordType:
            subdomain_records[subdomain].extend(dns_resolver.resolve(f"{subdomain}.{base_domain}", record_type))
    
    # combine into a single list keyed by the domain
    all_records = {base_domain: records}
    all_records.update(subdomain_records)
    
    # Using Config.SMART_SUBDOMAINS, check if any records trigger a special case and add them to a local smart_subdomains list.
    smart_subdomains = {}
    for record_list in all_records.values():
        for record in record_list:
            for (record_type, regex), subdomain in Config.SMART_SUBDOMAINS.items():
                if record.type == record_type and re.search(regex, record.value):
                    if subdomain not in smart_subdomains:
                        smart_subdomains[subdomain] = []
                    smart_subdomains[subdomain].append(record)
                    
    # Resolve the smart subdomains into all_records
    for subdomain in smart_subdomains:
        subdomain_records[subdomain] = []
        for record_type in RecordType:
            subdomain_records[subdomain].extend(dns_resolver.resolve(f"{subdomain}.{base_domain}", record_type))
        all_records.update(subdomain_records)
        
    
    transformed_records = {}
    for domain, record_list in all_records.items():
        for record in record_list:
            if record.type not in transformed_records:
                transformed_records[record.type] = {}
            if domain not in transformed_records[record.type]:
                transformed_records[record.type][domain] = []
            transformed_records[record.type][domain].append(record)
    
    # Display all records
    for record_type, domains in transformed_records.items():
        Logger.write_header(f"{record_type.name} RECORDS", Config.COLORS.PRIMARY_COLOR, Config.STYLES.PRIMARY_STYLE)
        for domain, records in domains.items():
            for record in records:
                RecordDisplay.display_target(record, dns_resolver, Config.RECORD_SEPARATOR) 
    
    
    spf_resolver = SPFResolver(dns_resolver)
    spf_lookup = spf_resolver.resolve_domain(base_domain)
    
    if (len(spf_lookup["errors"]) > 0):
        Logger.write_header("SPF Lookup", Config.COLORS.SPF_PRIMARY_COLOR, Config.STYLES.SPF_STYLE)
        spf_display = SPFDisplay(spf_lookup)
        spf_display.display()

    Logger.write_header("Statistics", Config.COLORS.PRIMARY_COLOR, Config.STYLES.PRIMARY_STYLE)
    Logger.write(f"Execution time: {time.time() - start_time:.2f} seconds", Config.COLORS.SECONDARY_COLOR)
    Logger.write(f"{requests.get('http://api.quotable.io/random').json()['content']}", Config.COLORS.SECONDARY_COLOR)
    Logger.write_header("The End", Config.COLORS.PRIMARY_COLOR, Config.STYLES.PRIMARY_STYLE)
    
    
if __name__ == "__main__":
    main()
