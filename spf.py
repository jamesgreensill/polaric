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
                txt_data = txt_record.to_text().strip('"')
                if txt_data.startswith('v=spf1'):
                    spf_record = txt_data
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
            return self.parse_spf(spf)
        except Exception as e:
            print(e)

    def parse_spf(self, spf_record):
        if (self.lookup_count > self.limit):
            self.errors.append(f"{spf_record} {self.lookup_count}/{self.limit} Lookups Exceeded.")         
            return
        
        if bool(re.search(r'\ba\b', spf_record)):
            self.lookup_count += 1
        if bool(re.search(r'\bmx\b', spf_record)):
            self.lookup_count += 1

        include_results = {}
        includes = re.findall(r'include:([\w.-]+)', spf_record)
        for include_domain in includes:
            self.lookup_count += 1
            include_results[include_domain] = self.resolve_domain(include_domain)

        redirects = re.findall(r'redirect=([\w.-]+)', spf_record)
        if redirects:
            self.lookup_count += 1
            self.resolve_domain(redirects[0])

        result = {
            "count": self.lookup_count,
            "spf": spf_record,
            "include": include_results,
            "errors" : self.errors
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
