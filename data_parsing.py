# data_parsing.py
from typing import List, Union
import bs4

def get_root(node: bs4.Tag) -> bs4.Tag:
    curnode = node
    valid_parent = None
    while curnode != None:
        valid_parent = curnode
        curnode = curnode.parent
    assert valid_parent is not None
    return valid_parent


class Product:
    def __init__(self, soup: bs4.Tag):
        self.node: bs4.Tag = soup
        self.root = get_root(soup)
        assert isinstance(self.root, bs4.Tag)
        __id = self.node.get("ProductID")
        assert isinstance(__id, str)
        self.id: str = __id
        self.name: str = self.node.text.strip()
        self.family = self.node.parent.get("Name", "")
        self._vulnerabilities = []

    def add_vulnerability(self, vulnerability):
        self._vulnerabilities.append(vulnerability)

    @property
    def vulnerabilities(self):
        return self._vulnerabilities
    
class Vulnerability:
    product: Product
    cve: str
    title: str
    severity: str
    impact: str
    description: str
    itw: bool
    kb: str
    __characteristics: dict[str, str]

    def __init__(self, product: Product, node: bs4.BeautifulSoup):
        self.product = product
        self.__node = node
        self.cve = self.__node.find("vuln:CVE").text.strip()
        self.title = self.__node.find("vuln:Title").text.strip()
        self.__characteristics = {}
        self.severity = self.__get_severity()
        self.impact = self.__get_impact()
        self.description = node.find(
            "vuln:Note", Title="Description", Type="Description"
        ).text.strip()
        self.kb = self.__get_remediation_info("Description")
        self.superseeded_kb = self.__get_remediation_info("Supercedence")
        self.itw = (
            "Exploited:Yes"
            in self.__node.find("vuln:Threat", Type="Exploit Status").text.strip()
        )
        self.product.vulnerabilities.append(self)
        return

    def url(self) -> str:
        return f"{KB_SEARCH_URL}?q={self.kb}"

    def __get_impact_or_severity(self, node, what: str) -> str:
        threads = node.find("vuln:Threats")
        if threads:
            for t in threads.find_all("vuln:Threat", Type=what):
                _value = t.find("vuln:ProductID").text.strip()
                _product_ids = list(map(int, _value.split("-", 1)))
                if self.product in _product_ids:
                    return t.find("vuln:Description").text.strip()
        return f"<UNKNOWN_{what.upper()}>"

    def __get_impact(self) -> str:
        if not "Impact" in self.__characteristics:
            self.__characteristics["Impact"] = self.__get_impact_or_severity(
                self.__node, "Impact"
            )
        return self.__characteristics["Impact"]

    def __get_severity(self) -> str:
        if not "Severity" in self.__characteristics:
            self.__characteristics["Severity"] = self.__get_impact_or_severity(
                self.__node, "Severity"
            )
        return self.__characteristics["Severity"]

    def __get_remediation_info(self, what: str) -> str:
        if not what in self.__characteristics:
            self.__characteristics[what] = ""
            for r in self.__node.find_all("vuln:Remediation", Type="Vendor Fix"):
                field = r.find("vuln:ProductID")
                if not field:
                    continue
                current_product_ids = list(map(int, field.text.strip().split("-", 1)))
                if self.product.id in current_product_ids:
                    info = r.find(f"vuln:{what}")
                    self.__characteristics[what] = info.text.strip() if info else ""
        return self.__characteristics[what]

    def __str__(self):
        return f"{self.cve} // KB{self.kb} // {self.title} // {self.severity} // {self.impact}"

    def __format__(self, format_spec) -> str:
        match format_spec:
            case "s":
                return format(str(self), format_spec)
            case "c":
                return format(self.cve, format_spec)
        return ""

    @staticmethod
    def find(
        soup: bs4.BeautifulSoup, cve_or_kb: Union[str, int]
    ) -> List["Vulnerability"]:
        """Search a vuln"""
        if isinstance(cve_or_kb, str):
            if cve_or_kb.lower().startswith("cve-"):
                return Vulnerability.get_vuln_info_by_cve(soup, cve_or_kb)
            if cve_or_kb.lower().startswith("kb"):
                kb: int = int(cve_or_kb[2:])
                return Vulnerability.get_vuln_info_by_kb(soup, kb)
        if isinstance(cve_or_kb, int):
            return Vulnerability.get_vuln_info_by_kb(soup, cve_or_kb)
        raise ValueError

    @staticmethod
    def get_vuln_info_by_cve(
        soup: bs4.BeautifulSoup, cve: str
    ) -> List["Vulnerability"]:
        """Search a vuln"""
        vulnerabilities: list[Vulnerability] = []
        for vuln in soup.find_all("vuln:Vulnerability"):
            cve_node = vuln.find("vuln:CVE")
            if not cve_node or not cve_node.text:
                continue
            if cve_node.text.lower() == cve.lower():
                for product_id in cve_node.find("vuln:ProductID"):
                    vulnerabilities.append(Vulnerability(product_id, vuln))
        return vulnerabilities

    @staticmethod
    def get_vuln_info_by_kb(soup: bs4.BeautifulSoup, kb: int) -> list["Vulnerability"]:
        """Search a vuln"""
        vulnerabilities: list[Vulnerability] = []
        for vuln in soup.find_all("vuln:Vulnerability"):
            cve_nodes = vuln.find_all("vuln:Remediation")
            if not cve_nodes:
                continue
            for cve_node in cve_nodes:
                kb_node = cve_node.find("vuln:Description")
                if not kb_node or not kb_node.text:
                    continue
                if kb_node.text.isdigit() and kb == int(kb_node.text):
                    for product_id in cve_node.find("vuln:ProductID"):
                        vulnerabilities.append(Vulnerability(product_id, vuln))
        return vulnerabilities


def collect_products(root: bs4.BeautifulSoup) -> list[Product]:
    soup = root.find("prod:ProductTree")
    assert isinstance(soup, bs4.Tag)
    products = [Product(product) for product in soup.find_all("prod:FullProductName")]
    return products
