# main.py
import datetime
from data_retrieval import get_patch_tuesday_data_soup
from data_parsing import collect_products
from cli_parser import parse_arguments
from logging_display import info, err, dbg
import argparse
import os

DEBUG = True

API_URL = "https://api.msrc.microsoft.com/cvrf/v2.0/document"
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"


API_URL: str = "https://api.msrc.microsoft.com/cvrf/v2.0/document"
DEFAULT_PRODUCT: str = "Windows 11 Version 22H2 for x64-based Systems"
# # DEFAULT_PRODUCT : str = "Windows 10 Version 21H2 for 32-bit Systems"
# # DEFAULT_PRODUCT : str = "Windows 10 Version 21H2 for ARM64-based Systems"
# # DEFAULT_PRODUCT : str = "Windows 10 Version 1909 for x64-based Systems"
# # DEFAULT_PRODUCT : str = "Windows 10 Version 1809 for x64-based Systems"
# KB_SEARCH_URL: str = "https://catalog.update.microsoft.com/v7/site/Search.aspx"
# DEFAULT_UA: str = """Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"""
# CVE_URL: str = "https://msrc.microsoft.com/update-guide/vulnerability"



def main():
    args = parse_arguments()
    today = datetime.date.today()
    parser = argparse.ArgumentParser(description="Get the Patch Tuesday info")
    parser.add_argument(
        "-V",
        "--vulns",
        help="Specifiy the vuln(s) to detail (can be repeated)",
        default=[],
        action="append",
        type=str,
    )
    parser.add_argument(
        "-p",
        "--products",
        help="Specifiy Product name(s) (can be repeated)",
        default=[],
        action="append",
        type=str,
    )
    parser.add_argument(
        "-m",
        "--months",
        help="Specify the Patch Tuesday month(s) (can be repeated)",
        default=[],
        action="append",
        type=lambda x: datetime.datetime.strptime(x, "%Y-%b"),
        metavar="YYYY-ABBREVMONTH",
    )
    parser.add_argument(
        "-y",
        "--years",
        help="Specify a year - will be expended in months (can be repeated)",
        default=[],
        action="append",
        type=int,
    )
    parser.add_argument(
        "--list-products", help="List all products", action="store_true"
    )
    parser.add_argument("--brief", help="Display a summary", action="store_true")
    parser.add_argument(
        "-v", "--verbose", action="count", dest="verbose", help="Increments verbosity"
    )

    args = parser.parse_args()
    vulnerabilities: list[Vulnerability] = []
    today = datetime.date.today()

    if args.list_products:
        soup = get_patch_tuesday_data_soup(today)
        products = collect_products(soup)
        info(os.linesep.join([f"- {x}" for x in products]))
        exit(0)

    if not len(args.products):
        info(f"Using default product as '{DEFAULT_PRODUCT}'")
        args.products = (DEFAULT_PRODUCT,)

    if args.years:
        args.months.extend(
            [
                args.months.append(datetime.date(year, month, 1))
                for year in args.years
                for month in range(1, 13)
            ]
        )

    if not len(args.months):
        info(f"Using default month as '{today.strftime('%B %Y')}'")
        args.months = (today,)

    summary = not (args.brief or args.vulns)

    for month in args.months:
        info(f"For {month.strftime('%B %Y')}")
        soup = get_patch_tuesday_data_soup(month, API_URL, DEFAULT_UA)
        products = collect_products(soup)
        info(f"Discovered {len(products)} products")

        for product_name in args.products:
            assert any(map(lambda p: p.name == product_name, products))
            product = list(filter(lambda p: p.name == product_name, products))[0]

            if args.brief:
                print(f"{product.name:-^95s}")
                print(f"* {len(product.vulnerabilities)} CVE{'s' if len(product.vulnerabilities)>1 else ''} including:")
                print(f"  - {len(list(filter(lambda x: x.severity == 'Critical', product.vulnerabilities)))} critical")
                print(f"  - {len(list(filter(lambda x: x.severity == 'Important', product.vulnerabilities)))} important")
                print("* with:")
                print(f"  - {len(list(filter(lambda x: x.impact == 'Remote Code Execution', product.vulnerabilities)))} are RCE")
                print(f"  - {len(list(filter(lambda x: x.impact == 'Elevation of Privilege', product.vulnerabilities)))} are EoP")
                print(f"  - {len(list(filter(lambda x: x.impact == 'Information Disclosure', product.vulnerabilities)))} are EoP")

            if args.vulns:
                for vuln_id in args.vulns:
                    for vuln in Vulnerability.find(soup, vuln_id):
                        print(f"- Title: {vuln.title}")
                        print(f"- Description: {vuln.description}")
                        print(f"- Impact: {vuln.impact}")
                        print(f"- Severity: {vuln.severity}")
                        print(f"- KB: {vuln.kb}")
                        print(f"- CVE: {vuln.cve}")
                        print(f"- Link: {CVE_URL}/{vuln.cve}")
                        print(f"{'':-^95}")

            if summary:
                print(f"{product.name:-^95s}")
                print(os.linesep.join([f"- {x}" for x in product.vulnerabilities]))
    # ... (rest of the script logic using modularized functions)

if __name__ == "__main__":
    main()