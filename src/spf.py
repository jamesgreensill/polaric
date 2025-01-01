import dns.resolver
import re
import argparse
import common

CENTER_LENGTH = 50
CENTER_CHAR = "-"


class SPFResolver:
    def __init__(self):
        self.errors = []
        self.lookup_count = 0
        self.resolver = dns.resolver.Resolver()
        self.limit = 10

    def resolve_domain(self, domain):
        try:
            answers = self.resolver.query(domain, 'TXT')
            for txt_record in answers:
                txt_data = txt_record.to_text()
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
            common.print_color(f"Hostname {domain} does not exist.", "RED", "FLASH")
        except dns.resolver.NoNameservers:
            common.print_color(f"Hostname {domain} does not exist.", "RED", "FLASH")
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


    def display_lookup(self, spf_lookup, depth=0):
        if spf_lookup is None:
            return 
        
        indent = "\t" * depth  # Indentation to show recursion depth
        if not spf_lookup:
            common.print_color(f"{indent}No lookup results to display.", "RED")
            return

        # Display the current SPF record and lookup count with colors
        common.print_color(f"{indent}SPF Lookup Results", "CYAN", "BOLD")
        common.print_color(f"{indent}SPF Record: {spf_lookup.get('spf', 'No SPF record found')}", "WHITE")
        
        if (depth == 0):
            common.print_color(f"{indent}Total Lookups: {spf_lookup.get('count', 0)}", "YELLOW")
        
        # Recursively display includes with color
        include_results = spf_lookup.get("include", {})
        if include_results:
            common.print_color(f"{indent}\nIncluded Domains:", "BLUE", "BOLD")
            for domain, result in include_results.items():
                common.print_color(f"{indent}  - {domain}:", "HI_BLUE")
                # If the result is a dictionary (indicating it has been recursively resolved), call display_lookup again
                if isinstance(result, dict):
                    self.display_lookup(result, depth + 1)
                else:
                    common.print_color(f"{indent}    {result}", "HI_GREEN")

        # Display redirects if any
        redirects = spf_lookup.get("redirect", [])
        if redirects:
            common.print_color(f"{indent}\nRedirects:", "MAGENTA", "BOLD")
            for redirect_domain in redirects:
                common.print_color(f"{indent}  - {redirect_domain}", "HI_CYAN")

                
    def display_errors(self, spf_lookup):
        errors = spf_lookup.get("errors", [])
        if errors:
            for error in errors:
                common.print_color(f"- {error}", "HI_RED")

def main():
    parser = argparse.ArgumentParser(
        prog="SPF Resolver",
        description="Counts SPF Lookups")

    parser.add_argument("domain", help="Domain to be resolved.")
    args = parser.parse_args()

    resolver = SPFResolver()
    spf_lookup = resolver.resolve_domain(args.domain)
    resolver.display_lookup(spf_lookup)
    pass


if __name__ == "__main__":
    main()
