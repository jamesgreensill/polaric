import argparse
import bs4
import requests
import common

ABN_URI="https://abr.business.gov.au/ABN/View?abn="
ACN_URI="https://connectonline.asic.gov.au/RegistrySearch/faces/landing/panelSearch.jspx?searchTab=search&searchType=OrgAndBusNm&searchText="

def fetch_abn(id):
    abn_search_uri = f"{ABN_URI}{id}"
    abn = {
        "id":f"{id}",
    }
    html = requests.get(abn_search_uri).text
    soup = bs4.BeautifulSoup(html, "html.parser").find("div", {'itemscope': True, 'itemtype': 'http://schema.org/LocalBusiness'})    
    
    try:
        entity_type_row = soup.find("th", string="Entity type:")
        if entity_type_row:
            abn["type"] = entity_type_row.find_next("a").text.strip()
        abn["name"] = soup.find("span", itemprop="legalName").text.strip()
        abn["status"] = soup.find("td", string=lambda text: text and ('Active' in text or 'Cancelled' in text)).text.strip()
        return abn
    except:
        common.print_error(f"Could not find ABN at: {abn_search_uri}")
        return None

def display_abn(abn):
    common.print_color(f"{ABN_URI}{abn['id']}", "YELLOW")
    common.print_color(f"ABN: {abn['id']}", "YELLOW")
    common.print_color(f"Name: {abn['name']}", "YELLOW")
    common.print_color(f"Type: {abn['type']}", "YELLOW")
    status = abn["status"].lower()
    status_color = "GREEN" if "active" in status else "RED" if "cancelled" in status else "YELLOW"
    common.print_color(f"Status: {abn['status']}", status_color)

def display_acn(id):
    common.print_color(f"{ACN_URI}{id}", "BLUE", end="\n")
    common.print_color(f"ACN: {id}", "CYAN", end="\n")
    common.print_color(f"ACN: {id}", "RED", end="\n")

def format_id(id):
    # 213 123 123 12 -> 21312312312
    # ABN: 123 123 123 12 -> 12312312312
    # ABN: 12312312312 -> 12312312312
    # ACN: 123 123 123 -> 123123123
    # ACN: 123 123 123 -> 123123123
    return common.digitialise(id).replace(" ", "")    

def search_asic(input):
    try:
        id = format_id(input)
        id_length = len(id)
        if (id_length == 11):
            # abn
            abn = fetch_abn(id)
            if abn != None:
                display_abn(abn)
            return
        if (id_length == 9):
            # acn
            display_acn(id)
            return
    except:
        common.print_error(f"Cannot find: {input}")    

def main():
    parser = argparse.ArgumentParser(
        prog="ASIC",
        description="ASIC Search"
    )
    parser.add_argument("id", help="ABN/ACN")
    args = parser.parse_args()
    search_asic(args.id)        
    pass

if __name__ == "__main__":
    main()