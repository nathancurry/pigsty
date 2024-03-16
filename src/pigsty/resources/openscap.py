"""
Interface to OpenSCAP XCCDF results in STIG Viewer format
"""

import re
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

NS: dict = {
    "XMLSchema": "http://oval.mitre.org/XMLSchema/oval-results-5",
    "xccdf": "http://checklists.nist.gov/xccdf/1.2",
    "arf": "http://scap.nist.gov/schema/asset-reporting-format/1.1",
    "oval-definitions": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
    "scap": "http://scap.nist.gov/schema/scap/source/1.2",
    "oval-characteristics": "http://oval.mitre.org/XMLSchema/oval-system-characteristics-5",
    "oval-object": "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent",
    "cpe-dict": "http://cpe.mitre.org/dictionary/2.0",
    "ds": "http://scap.nist.gov/schema/scap/source/1.2",
    "cpe-lang": "http://cpe.mitre.org/language/2.0",
    "cdf": "http://checklists.nist.gov/xccdf/1.2",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "dc": "http://purl.org/dc/elements/1.1/",
}

INVALID_IPV4: set = {
    "127.0.0.1",
    "192.168.122.1",
}

INVALID_MAC: set = {
    "00:00:00:00:00:00",
}

INVALID_HOSTNAME: set = {
    "localhost",
}

INVALID_IPV6: set = {
    "::1",
}


class OpenSCAPRuleResult:
    """
    Interface to parse and retrieve results from an OpenSCAP XCCDF result file in STIG Viewer format.

    Args:
        result_node (ET.Element): Root element

    Parameters:
        rule_id (str): Full rule ID
        vid (str): V-ID in format 'V-[0-9]+'
        time (datetime): Scan time
        result (str): Result of check
        severity (str): Severity rating
        weight (str): Numeric weight of check
        as_dict (dict): Dictionary representation of the OpenSCAPRuleResult object
    """

    def __init__(self, result_node: ET.Element):
        super().__init__()
        self.rule_id: str
        self.vid: str
        self.time: datetime
        self.result: str
        self.__datetime_format: str = "%Y-%m-%dT%H:%M:%S%z"
        self.node = result_node

    @property
    def rule_id(self) -> str:
        return self.node.get("idref")

    @property
    def vid(self) -> str:
        return re.search(r"V-[0-9]+", self.rule_id).group(0)

    @property
    def time(self) -> datetime:
        return datetime.strptime(self.node.get("time"), self.__datetime_format)

    @property
    def severity(self) -> str:
        return self.node.get("severity")

    @property
    def weight(self) -> str:
        return self.node.get("weight")

    @property
    def result(self) -> str:
        return self.node.get("result")

    def as_dict(self) -> dict:
        """
        Returns a dictionary representation of the OpenSCAPRuleResult object
        """
        ident = self.node.find("xccdf:ident", NS)
        check = self.node.find("xccdf:check", NS)
        if check:
            check_export: list = self.node.findall("xccdf:check-export")
            check_content_ref = self.node.find("xccdf:check-content-ref", NS)
            check_data: dict = (
                {
                    "system": check.get("system"),
                    "check_content_ref": {
                        "name": check_content_ref.get("name"),
                        "href": check_content_ref.get("href"),
                    }
                    if check_content_ref
                    else None,
                    "check_export": [
                        {
                            "export_name": x.get("export_name"),
                            "href": x.get("href"),
                        }
                        for x in check_export
                    ],
                }
                if check
                else None,
            )

        return {
            "rule_id": self.rule_id,
            "vid": self.vid,
            "time": self.time,
            "severity": self.severity,
            "weight": self.weight,
            "result": self.result,
            "ident": {"system": ident.get("system"), "text": ident.text},
            "check": check_data if check else None,
        }


class OpenSCAPSTIGViewerResult:
    """
    Interface to parse and retrieve results from an OpenSCAP XCCDF result file in STIG Viewer format.

    Args:
        file (str): Path to XCCDF file
        autoload (bool): Whether to load the data immediately

    Attributes:
        file (Path): Path to XCCDF file
        tree (ET.ElementTree): ElementTree object
        root (ET.Element): Root element
        rule_results (Dict[str, OpenSCAPRuleResult]): Dictionary of OpenSCAPRuleResult objects

    Properties:
        target (str): Target name
        identity (str): Identity of scan operator
        target_addresses (Set[str]): Values of target-address fields
        fqdn (Set[str]): Values FQDN target-facts
    """

    def __init__(self, file: str, autoload: bool = True):
        self.tree: ET.ElementTree = None
        self.root: ET.Element = None
        self.rule_results: dict[str, OpenSCAPRuleResult] = {}
        self.file: Path = Path(file)
        if autoload:
            self.load()

    def load(self):
        """
        Load checklist XML data from file.
        """
        self._parse()
        self._load_rule_results()

    def _parse(self):
        """
        Parse XML.
        """
        self.tree = ET.parse(self.file)
        self.root = self.tree.getroot()

    def _load_rule_results(self):
        """
        Load the rule results as OpenSCAPRuleResult objects in the rule_results dictionary.
        """
        vid_regex = r"V-[0-9]+"
        rule_results = self.root.findall(".//xccdf:rule-result", NS)
        for result in rule_results:
            rule_id = result.get("idref")
            vid = re.search(vid_regex, rule_id).group(0)
            self.rule_results.update({vid: OpenSCAPRuleResult(result)})

    @property
    def target(self) -> str:
        return self.root.find(".//xccdf:target", NS).text

    @property
    def identity(self) -> str:
        return self.root.find(".//xccdf:identity", NS).text

    @property
    def target_addresses(self) -> set[str]:
        super = INVALID_IPV4.union(INVALID_IPV6, INVALID_HOSTNAME, INVALID_MAC)
        return {
            x.text
            for x in self.root.findall(".//xccdf:target-address", NS)
            if x.text not in super
        }

    @property
    def ipv4(self) -> set[str]:
        query = './/xccdf:target-facts/xccdf:fact[@name="urn:xccdf:fact:asset:identifier:ipv4"]'
        return {
            x.text for x in self.root.findall(query, NS) if x.text not in INVALID_IPV4
        }

    @property
    def ipv6(self) -> set[str]:
        query = './/xccdf:target-facts/xccdffact[@name="urn:xccdf:fact:asset:identifier:ipv6"]'
        return {
            x.text for x in self.root.findall(query, NS) if x.text not in INVALID_IPV6
        }

    @property
    def mac(self) -> set[str]:
        query = './/xccdf:target-facts/xccdf:fact[@name="urn:xccdf:fact:asset:identifier:mac"]'
        return {
            x.text for x in self.root.findall(query, NS) if x.text not in INVALID_MAC
        }

    @property
    def hostname(self) -> set[str]:
        query = './/xccdf:target-facts/xccdf:fact[@name="urn:xccdf:fact:asset:identifier:host_name"]'
        return {
            x.text
            for x in self.root.findall(query, NS)
            if x.text not in INVALID_HOSTNAME
        }

    @property
    def fqdn(self) -> set[str]:
        query = './/xccdf:target-facts/xccdf:fact[@name="urn:xccdf:fact:asset:identifier:fqdn"]'
        return {x.text for x in self.root.findall(query, NS)}

    @property
    def platform(self) -> set[str]:
        return {x.get("idref") for x in self.root.findall(".//xccdf:platform", NS)}

    @property
    def cpe(self) -> set[str]:
        return {x for x in self.platform if x.startswith("cpe:/o:")}
