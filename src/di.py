import socket
import dns.resolver
import argparse
import whois
import asic
import common
import re
import os
import whm
import tempfile
import subprocess
import spf
import requests
import time

START_TIME=time.time()

CENTER_LENGTH = 50
CENTER_CHAR = "-"


COLOR_LIST = ["GREEN", "YELLOW", "RED",
              "BLUE", "PURPLE", "CYAN"]

PRIMARY_COLOR = "RED"
RECORD_COLOR = "GREEN"
RECORD_SEPARATOR = " -> "

# DNS record types to resolve and their specific attributes
RECORDS = [
    "SOA",
    "NS",
    "A",
    "AAAA",
    "MX",
    "TXT"
]

RECORDS_EXTRACT = {
    "SOA": lambda record: f"{record.mname}",
    "NS": lambda record: f"{record}",
    "A": lambda record: f"{record}",
    "AAAA": lambda record: f"{record}",
    "MX": lambda record: f"{record.exchange}",
    "TXT": lambda record: f"{record}",
}

RECORDS_DISPLAY = {
    "SOA": lambda record: f"{record.mname} {record.rname} {record.serial} {record.refresh} {record.retry} {record.expire} {record.minimum}",
    "NS": lambda record: f"{record}",
    "A": lambda record: f"{record}",
    "AAAA": lambda record: f"{record}",
    "MX": lambda record: f"{record}",
    "TXT": lambda record: f"{record}",
}

SUBDOMAIN_LOOKUPS = [
    "www",
    "shop",
    "_dmarc",
    "_fuckoff"
]

SPECIAL_RECORD_VALUES = {
    (r"MX", r"mx\d+\.email-hosting\.net\.au\."): lambda: "axigen._domainkey",
    (r"TXT", r"spf\.email-hosting\.net\.au"): lambda: "axigen._domainkey",
    (r"TXT", r"spf\.hostingplatform\.net\.au"): lambda: "default._domainkey"
}

RECORD_HIGHLIGHTS = {
    (r"TXT", r"v=spf1"): lambda record: process_spf_highlight(record)
}


def process_spf_highlight(record):
    resolver = spf.SPFResolver()
    lookup = resolver.resolve_spf(record)
    return "WHITE" if len(lookup["errors"]) <= 0 else "HI_BG_RED"


def process_highlight(record_type, record):
    for (rtype, pattern), highlight in RECORD_HIGHLIGHTS.items():
        if rtype == record_type and re.search(pattern, record):
            return highlight
    return None


def process_record(record_type, record):
    for (rtype, pattern), action in SPECIAL_RECORD_VALUES.items():
        if rtype == record_type and re.search(pattern, record):
            return action()


def print_header(message):
    message = f" {message} "
    offset = CENTER_LENGTH - len(message)
    left_padding = offset // 2
    right_padding = offset - left_padding
    common.print_color(CENTER_CHAR * left_padding, PRIMARY_COLOR, end="")
    common.print_color(f"\x1b[7m{message}\x1b[0m", PRIMARY_COLOR, "BOLD", end="")
    common.print_color(CENTER_CHAR * right_padding, PRIMARY_COLOR, end="\n")


def display_records(domain, record_type, records, resolver):
    for record in records:
        record_extract = RECORDS_EXTRACT[record_type](record)

        if domain != None and domain != "":
            common.print_color(
                f"{domain}. ", "CYAN", "BOLD", end="")

        record_display = RECORDS_DISPLAY[record_type](record)
        record_color = RECORD_COLOR

        highlight = process_highlight(record_type, record_display)
        if highlight is not None:
            record_color = highlight(record_display)

        common.print_color(record_display, record_color, end="")

        display_target(record_extract, resolver, show_first=False)


def display_target(target, resolver, separator=RECORD_SEPARATOR, depth=0, is_multiple=False, show_first=True):
    def print_target(target, color,  is_multiple, end=""):
        if not show_first and depth <= 0:
            return
        indent = "\t" * depth if is_multiple else ""
        common.print_color(f"{indent}{target}", color=color, end=end)

    color = "WHITE"

    if common.is_fqdn(target):
        try:
            results = resolver.resolve(f"{target}", "A")
            is_multiple = len(results) > 1

            print_target(target, color, is_multiple)
            print(f"{separator}", end="")

            if is_multiple:
                print()

            for record in results:
                display_target(record.to_text(), resolver,
                               separator, depth+1, is_multiple)

        except Exception as e:
            common.print_color(f"Error resolving {target}: {e}", "RED", "FLASH")
    elif common.is_valid_ip(target):
        try:
            hostname = socket.gethostbyaddr(f"{target}")[0]
            print_target(target, color, is_multiple)
            print(f"{separator}", end="")
            common.print_color(hostname, "CYAN")
        
        except socket.herror as e:
            print(f"{separator}", end="")
            common.print_color(f"Unknown Host", "RED", "FLASH")    
    else:
        print_target(target, color, is_multiple)
        print()


def as_list(obj):
    if isinstance(obj, list):
        return obj
    else:
        return [obj]


def check_subdomain_exists(subdomain, domain, resolver):
    try:
        # Try resolving the subdomain's A record
        resolver.resolve(f"{subdomain}.{domain}", 'A')
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return False


def shallow_dns_lookup(domain, nameserver=None, record_types=[], resolver=dns.resolver.Resolver()):
    records = {}
    subdomains = []

    for record_type in record_types:
        try:
            result = resolver.resolve(domain, record_type)
            if domain not in records:
                records[domain] = {}

            records[domain][record_type] = result

            for record in result:
                record_extract = RECORDS_EXTRACT[record_type](record)
                subdomain = process_record(record_type, record_extract)
                if subdomain is not None:
                    subdomains.append(subdomain)
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            common.print_color(
                f"Hostname {domain} does not exist.", "RED", "FLASH")
            return (records, subdomains)
        except dns.resolver.NoNameservers:
            common.print_color(
                f"Hostname {domain} does not exist.", "RED", "FLASH")
            break
    return (records, subdomains)


def deep_dns_lookup(domain, nameserver, record_types, resolver):
    records, subdomains = shallow_dns_lookup(domain, nameserver, record_types,resolver)
    for subdomain in subdomains:
        sub_records, _ = shallow_dns_lookup(
            f"{subdomain}.{domain}", nameserver, record_types,resolver)
        records.update(sub_records)
    for subdomain in SUBDOMAIN_LOOKUPS:
        sub_records, _ = shallow_dns_lookup(
            f"{subdomain}.{domain}", nameserver, record_types,resolver)
        records.update(sub_records)
    return records


def transform_records(records):
    transformed_records = {}

    for domain, record_types in records.items():
        for record_type, record in record_types.items():
            if record_type not in transformed_records:
                transformed_records[record_type] = {}
            transformed_records[record_type][domain] = record

    return transformed_records

def extract_subdomain(domain, base_domain):
    if domain == base_domain:
        return ""
    return domain.replace(f".{base_domain}", "")

def display_all_records(root_domain, records, nameserver):
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [socket.gethostbyname(nameserver)]

    transformed_records = transform_records(records)
    for record_type, domains in transformed_records.items():
        print_header(f"{record_type} RECORDS")
        for domain, records in domains.items():
            subdomain = extract_subdomain(domain, root_domain)
            display_records(subdomain, record_type, records, resolver)


def display_asic(registrant_id):
    print_header("Registrant ID")
    asic.search_asic(registrant_id)


def display_whois(whois_information):
    print_header("WHOIS Information")
    common.print_color(
        f"Registrar: {whois_information.registrar}", "YELLOW")
    for updated_date in as_list(whois_information.updated_date):
        common.print_color(f"Updated: {updated_date}", "YELLOW")
    for status in as_list(whois_information.status):
        common.print_color(f"Status: {status}", "YELLOW")
    for i, nameserver in enumerate(as_list(whois_information.name_servers)):
        common.print_color(f"Nameserver {i+1}: {nameserver}", "YELLOW")


def display_whm(domain):
    output = whm.fetch_whm(domain)
    if output is None:
        return
    parsed_output = whm.parse_output(output)
    if parsed_output is None:
        return
    print_header("MANAGEMENT")
    whm.display_output(parsed_output)


def error_check_spf(domain):
    resolver = spf.SPFResolver()
    spf_lookup = resolver.resolve_domain(domain)

    if spf_lookup is None:
        return

    if (len(spf_lookup["errors"]) > 0):
        print_header(f"SPF TRACE: {domain}")
        resolver.display_lookup(spf_lookup)
        print_header(f"ERRORS: {domain}")
        resolver.display_errors(spf_lookup)
        
def display_footer():
    print_header("Le' Info")
    end_time = time.time()
    elapsed_time = end_time - START_TIME
    common.print_color(f"Executed in: {elapsed_time}s.", "WHITE", "BOLD")
    quote = requests.get("http://api.quotable.io/random")
    quote_data = quote.json()
    quote_content = quote_data["content"]
    common.print_color(quote_content, "WHITE", "BOLD")
    print_header("THE END")

def main():
    parser = argparse.ArgumentParser(
        prog="DI",
        description="Domain Information"
    )
    parser.add_argument("domain", help="Domain to resolve")
    parser.add_argument("-ns", "--nameserver",
                        help="Specify a custom nameserver")
    parser.add_argument("-sd", "--subdomains", action="store_true")

    args = parser.parse_args()

    if args.subdomains:
        subdomains = common.get_text_from_nano().split("\n")
        for subdomain in subdomains:
            if subdomain == "":
                continue
            SUBDOMAIN_LOOKUPS.append(subdomain)

    resolver = dns.resolver.Resolver()
    if args.nameserver:
        resolver.nameservers=[args.nameserver]

    for subdomain in SUBDOMAIN_LOOKUPS[:]:
        if not check_subdomain_exists(subdomain, args.domain, resolver):
            SUBDOMAIN_LOOKUPS.remove(subdomain)     

    display_whm(args.domain)
    whois_information = whois.whois(args.domain)
    if whois_information.registrant_id is not None:
        display_asic(whois_information.registrant_id)

    display_whois(whois_information)

    records = deep_dns_lookup(args.domain, args.nameserver, RECORDS, resolver)
    display_all_records(args.domain, records, args.nameserver)

    error_check_spf(args.domain)
    for subdomain in SUBDOMAIN_LOOKUPS:
        error_check_spf(f"{subdomain}.{args.domain}")

    display_footer()

if __name__ == "__main__":
    main()
