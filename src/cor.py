import argparse
import common
import whois
import asic

def resolve_id(input):
    if not common.is_fqdn(input):
            common.print_error(f"{input} is not a fully qualified domain name. Skipping.")
            return None
    if not common.validate_tld(input, "au"):
        common.print_error(f"{input} is not australian...? Skipping.")
        return None
    whois_information = whois.whois(input)
    if whois_information.registrant_id is None:
        return None
    id = common.digitialise(whois_information.registrant_id).replace(" ", "")
    return id

def resolve_ids(data):
    # data-type: [("qualifier", "id"]
    ids = []
    for qualifier in data:
        id = resolve_id(qualifier)
        if id != None:
            ids.append((qualifier, id))
    return ids

def main():
    parser = argparse.ArgumentParser(
        prog="COR",
        description="Change of Registrant"
    )
    parser.add_argument("destination", help="What entity is owning the domain?")
    parser.add_argument("-d", "--domain", help="What domain is changing registrant?")
    parser.add_argument("-m", "--multiple", help="What domains are changing registrnat? (separate by new line)", action="store_true")

    args = parser.parse_args()

    domains = []

    if args.domain:
        domains.append(args.domain)
    
    if args.multiple:
        domains_data = common.get_text_from_nano().split("\n")
        for domain in domains_data:
            if domain == "":
                continue
            domains.append(domain)
            
    destination_id = common.digitialise(args.destination).replace(" ", "")
    if destination_id is None:
        return
    
    ids = resolve_ids(domains)
    for (qualifier, id) in ids:
        print(f" {qualifier} ".center(25, "="))
        asic.search_asic(id)
    print("".center(25, "="))
    print(f"Destination {args.destination}")
    asic.search_asic(destination_id)
    print("".center(25, "="))
    pass

if __name__ == "__main__":
    
    main()