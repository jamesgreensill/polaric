import re
import socket
import tempfile
import subprocess
import os

RESET = "\033[0m"
COLORS = {
    # Standard Colors
    "BLACK": "\033[0;30m",
    "RED": "\033[0;31m",
    "GREEN": "\033[0;32m",
    "YELLOW": "\033[0;33m",
    "BLUE": "\033[0;34m",
    "PURPLE": "\033[0;35m",
    "CYAN": "\033[0;36m",
    "WHITE": "\033[0;37m",
    "RESET": "\033[0m",
    
    # High-Intensity Colors
    "HI_BLACK": "\033[0;90m",
    "HI_RED": "\033[0;91m",
    "HI_GREEN": "\033[0;92m",
    "HI_YELLOW": "\033[0;93m",
    "HI_BLUE": "\033[0;94m",
    "HI_PURPLE": "\033[0;95m",
    "HI_CYAN": "\033[0;96m",
    "HI_WHITE": "\033[0;97m",

    # High-Intensity Backgrounds
    "HI_BG_BLACK": "\033[0;100m",
    "HI_BG_RED": "\033[0;101m",
    "HI_BG_GREEN": "\033[0;102m",
    "HI_BG_YELLOW": "\033[0;103m",
    "HI_BG_BLUE": "\033[0;104m",
    "HI_BG_PURPLE": "\033[0;105m",
    "HI_BG_CYAN": "\033[0;106m",
    "HI_BG_WHITE": "\033[0;107m",
}

STYLES = {
    "NORMAL": 0,
    "BOLD": 1,
    "UNDERLINE": 4,
    "FLASH": 5
}


def get_text_from_nano():
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file_path = temp_file.name
    try:
        subprocess.run(['nano', temp_file_path], check=True)
        with open(temp_file_path, 'r') as temp_file:
            content = temp_file.read()
    finally:
        # Clean up the temporary file
        os.unlink(temp_file_path)

    return content


def styleise(color, style):
    parts = color.split(';')
    parts[0] = f"{style}"
    return '\033[' + ';'.join(parts)

def digitialise(text):
    return ''.join(char for char in text if char.isdigit())


def gen_color_str(message, color, style):
    return f"{styleise(COLORS[color], STYLES[style])}{message}{RESET}"


def hyperlink(link, display):
    return f'\033]8;;{link}\033\\{display}\033]8;;\033\\'


def print_color(message, color, style="NORMAL", end="\n"):
    """Prints a message with the specified color."""
    print(gen_color_str(message, color, style), end=end)


def print_error(message):
    print_color(message, COLORS["RED"], STYLES["BOLD"])


def validate_tld(domain, tld):
    return domain.lower().split(".")[-1] == tld.lower()


def is_fqdn(value):
    pattern = r'^(([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}|localhost)\.?$'
    return re.match(pattern, f"{value}") is not None


def is_valid_ipv4(ipv4):
    # mathc ipv4 pattern with 1 byte range check (0-255)
    ipv4_pattern = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if re.match(ipv4_pattern, ipv4):
        return True
    return False


def is_valid_ipv6(ipv6):
    # match ipv6 pattern with shorthand notation included
    ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$|^::([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,6}:([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$'
    if re.match(ipv6_pattern, ipv6):
        return True
    return False


def is_valid_ip(ip):
    if len(ip) <= 15:
        if is_valid_ipv4(ip):
            return True
    if is_valid_ipv6(ip):
        return Tru
    return False
