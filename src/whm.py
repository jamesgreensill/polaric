import re
import common
import subprocess
import argparse
import os


COLORS = common.COLORS
STYLES = common.STYLES


def fetch_whm(domain):
    try:
        command = ["bash", "-i", "-c", f"whm {domain}"]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return result.stdout.decode('utf-8')
    except:
        return None
        pass


def extract_details(string):
    match = re.search(r"ID (\d+) - username (\w+) - server ([\w\d.]+)", string)
    if match:
        return {
            "ID": match.group(1),
            "username": match.group(2),
            "server": match.group(3)
        }
    return None


def extract_title(string):
    match = re.search(r"===== (.*?)[: ]", string)
    if match:
        return match.group(1)
    return None


def parse_name_link(string):
    parts = string.split(" - ", 1)
    if len(parts) == 2:
        return {"name": parts[0].strip(), "link": parts[1].strip()}
    return None


def parse_output(output):
    whm_object = {}
    title = ""
    for line in output.split('\n'):
        if "=====" in line:
            if "No service found for domain" in line:
                continue

            title = extract_title(line)
            whm_object[title] = {}
        if "Found service" in line and title != "":
            details = extract_details(line)
            whm_object[title]["details"] = {}
            whm_object[title]["details"]["id"] = details["ID"]
            whm_object[title]["details"]["username"] = details["username"]
            whm_object[title]["details"]["server"] = details["server"]

        if "Link" in line and title != "":
            link = parse_name_link(line)
            if not "links" in whm_object[title]:
                whm_object[title]["links"] = {}
            whm_object[title]["links"][link["name"]] = link["link"]

    if title == "":
        return None

    return whm_object


def display_output(whm_object):
    for title, data in whm_object.items():
        if "links" in data:
            common.print_color(f"{title}", "CYAN", "NORMAL")
            for name, link in data["links"].items():
                common.print_color(
                    f"\t{common.hyperlink(link, name)}", "WHITE")
    return


def display_whm(domain):
    output = fetch_whm(domain)
    parsed_output = parse_output(output)
    display_output(parsed_output)


def main():
    parser = argparse.ArgumentParser(
        prog="DI",
        description="Domain Information"
    )
    parser.add_argument("domain", help="Domain to query")
    parser.add_argument("-ns", "--nameserver",
                        help="Specify a custom nameserver")

    args = parser.parse_args()

    display_whm(args.domain)
    pass


if __name__ == "__main__":
    main()
