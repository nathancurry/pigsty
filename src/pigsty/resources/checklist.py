"""
Interface to DISA checklist files produced by STIG Viewer 2.
"""

from pathlib import Path
from xml.etree import ElementTree as ET


class DictNode():
    """
    Interface for dictionary node.
    """

    def __init__(self, node: ET.Element, prefix: str, suffix: str, immutable: bool):
        self.node: ET.Element = node
        self._prefix: str = prefix
        self._suffix: str = suffix
        self.immutable: bool = immutable

    def get(self, key: str) -> str:
        """
        Get value for key.

        Args:
            key (str): Key

        Returns:
            str: Value

        Raises:
            KeyError: If key not found
        """
        try:
            return self.node.find(f"{self._prefix}{key}{self._suffix}").text
        except AttributeError as exc:
            raise KeyError(f"{key} not found in {self.node.tag}") from exc

    def set(self, key: str, value: str):
        """
        Set value for key.

        Args:
            key (str): Key
            value (str): Value

        Raises:
            PermissionError: If node is write protected
            KeyError: If key not found
        """
        if self.immutable:
            raise PermissionError(f"Node is write protected. Cannot set {key} to {value}")
        try:
            self.node.find(f"{self._prefix}{key}{self._suffix}").text = value
        except AttributeError as exc:
            raise KeyError(f"{key} not found in {self.node.tag}") from exc

    def items(self):
        """
        Returns list of (key, value) tuples
        """
        return [(x.tag, x.text) for x in self.node]

    def keys(self):
        """
        Returns list of keys
        """
        return [x[0] for x in self.items()]

    def values(self):
        """
        Returns list of values
        """
        return [x[1] for x in self.items()]

    def as_dict(self):
        """
        Returns a dictionary representation of the asset node.
        """
        return {x[0]: x[1] for x in self.items()}



class AssetNode(DictNode):
    """
    Interface for target asset node.
    """

    def __init__(self, node: ET.Element):
        prefix: str = ".//"
        suffix: str = ""
        immutable: bool = False
        super().__init__(node, prefix, suffix, immutable)

class StigInfoNode(DictNode):
    """
    Stig Info node providing a dict-like interface.

    Args:
        node (ET.Element): STIG_INFO node
    Attributes:
        immutable (bool): Whether dict interface is immutable
        prefix (str): Element lookup prefix
        suffix (str): Element lookup suffix
    """

    def __init__(self, node: ET.Element):
        # self.node: ET.Element = node
        immutable: bool = True
        prefix: str = './/SI_DATA/SID_NAME[.="'
        suffix: str = '"]/../SID_DATA'
        super().__init__(node, prefix, suffix, immutable)

    def items(self) -> list[str]:
        key = ".//SID_NAME"
        value = ".//SID_DATA"
        result = []
        for sid in self.node:
            x = sid.find(key).text
            try:
                y = sid.find(value).text
            except AttributeError:
                sid.makeelement(value, {}).text = ""
                y = ""
            result.append((x, y))
        return result


class VulnNode(DictNode):
    """
    Vulnerability node providing properties for mutable elements, and a
    dict-like interface to the STIG data.

    Args:
        node (ET.Element): VULN node

    Attributes:
        immutable (bool): Whether dict interface is immutable
        prefix (str): Element lookup prefix
        suffix (str): Element lookup suffix

    Properties:
        vuln_num (str): V-ID (immutable)
        status (str): Status [Not_Reviewed, NotAFinding, Not_Applicable, Open]
        finding_details (str): Finding details field
        comments (str): Comments field
        severity_override (str): Severity override
        severity_justification (str): Severity justification
    """

    def __init__(self, node: ET.Element):
        # self.node: ET.Element = node
        immutable: bool = True
        prefix: str = './/STIG_DATA/VULN_ATTRIBUTE[.="'
        suffix: str = '"]/../ATTRIBUTE_DATA'
        super().__init__(node, prefix, suffix, immutable)

    @property
    def vuln_num(self) -> str:
        return self.node.find(f"{self._prefix}Vuln_Num{self._suffix}").text

    @property
    def status(self) -> str:
        return self.node.find("STATUS").text

    @status.setter
    def status(self, value: str):
        self.node.find("STATUS").text = value

    @property
    def finding_details(self) -> str:
        return self.node.find("FINDING_DETAILS").text

    @finding_details.setter
    def finding_details(self, value: str):
        self.node.find("FINDING_DETAILS").text = value

    @property
    def comments(self) -> str:
        return self.node.find("COMMENTS").text

    @comments.setter
    def comments(self, value: str):
        self.node.find("COMMENTS").text = value

    @property
    def severity_override(self) -> str:
        return self.node.find("SEVERITY_OVERRIDE").text

    @severity_override.setter
    def severity_override(self, value: str):
        self.node.find("SEVERITY_OVERRIDE").text = value

    @property
    def severity_justification(self) -> str:
        return self.node.find("SEVERITY_JUSTIFICATION").text

    @severity_justification.setter
    def severity_justification(self, value: str):
        self.node.find("SEVERITY_JUSTIFICATION").text = value

    def items(self) -> list[str]:
        key = ".//VULN_ATTRIBUTE"
        value = ".//ATTRIBUTE_DATA"
        return [
            (x.find(key).text, x.find(value).text) for x in self.node.iter("STIG_DATA")
        ]


class StigNode:
    """
    Node containing STIG data.

    Args:
        stig (ET.Element): STIG node

    Attributes:
        info (StigInfoNode): STIG_INFO node
        vuln_nodes (dict[str, VulnNode]): VULN nodes
    """

    def __init__(self, stig: ET.Element):
        self.node: ET.Element = stig
        self.info: StigInfoNode = StigInfoNode(self.node.find(".//STIG_INFO"))
        self.vuln_nodes: dict[str, VulnNode] = {
            x.find(
                './/STIG_DATA/VULN_ATTRIBUTE[.="Vuln_Num"]/../ATTRIBUTE_DATA'
            ).text: VulnNode(x)
            for x in self.node.findall("VULN")
        }

    @property
    def stigid(self) -> str:
        return self.info.get("stigid")

    @property
    def version(self) -> str:
        return self.info.get("version")

    @property
    def releaseinfo(self) -> str:
        return self.info.get("releaseinfo")


class Checklist:
    """
    Interface to parse and build DISA checklist files.

    Attributes:
        file (Path): Path to checklist file
        tree (ET.ElementTree): ElementTree object
        root (ET.Element): Root element
        asset (AssetNode): Asset element
        stigs (list[StigNode]): List of STIG elements in file

    Methods:
        load(self): Load checklist XML data from file
        as_dict(self) -> dict: Return a summary of checklist data as a dictionary
    """

    def __init__(self, file: str, autoload: bool = True):
        self.tree: ET.ElementTree = None
        self.root: ET.Element = None
        self.asset: AssetNode = None
        self.stigs: list[StigNode] = []
        self.file: Path = Path(file)
        if autoload:
            self.load()

    def as_dict(self) -> dict:
        """
        Return a summary of checklist data as a dictionary.

        Returns:
            dict: Checklist data
        """
        return {
            "asset": self.asset.as_dict(),
            "stigs": [
                {
                    "info": stig.info.as_dict(),
                    "vulnerabilities": {
                        v: stig.vuln_nodes[v].status for v in stig.vuln_nodes
                    },
                }
                for stig in self.stigs
                ],
        }

    def load(self):
        """
        Load checklist XML data from file.
        """
        self._parse()
        self._load_asset()
        self._load_stigs()

    def _parse(self):
        """
        Parse XML.
        """
        try:
            self.tree = ET.parse(self.file)
            self.root = self.tree.getroot()
        except ET.ParseError as exc:
            raise exc

    def _load_asset(self):
        """
        Load asset data.
        """
        self.asset = AssetNode(self.root.find(".//ASSET"))

    def _load_stigs(self):
        """
        Load stig data.
        """
        self.stigs = [StigNode(x) for x in self.root.findall(".//STIGS/iSTIG")]

    def save(self, output_file: Path, force: bool = False):
        """
        Save checklist XML to specified file.

        Args:
            output_file (Path): Path to output file
        """
        if not output_file.parent.is_dir():
            output_file.parent.mkdir(parents=True)
        if output_file.exists():
            if not force:
                raise FileExistsError(f"{output_file} already exists. Pass 'force=True' to overwrite.")
            else:
                output_file.unlink()
        self.tree.write(output_file)
