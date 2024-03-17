from pathlib import Path
from xml.etree import ElementTree as ET

import pytest
from pigsty.resources.checklist import AssetNode, Checklist, StigNode


class TestChecklist:
    rhel9_file = Path(
        "./tests/files/checklists/U_RHEL_9_V1R1_STIG_SCAP_1-3_Benchmark.ckl"
    )
    bad_file = Path("./tests/files/checklists/bad.ckl")
    rhel9_ckl = Checklist(rhel9_file, autoload=False)
    bad_ckl = Checklist(bad_file, autoload=False)

    @pytest.mark.parametrize(
        "element", [rhel9_ckl.tree, rhel9_ckl.root, rhel9_ckl.asset]
    )
    def test_checklist_no_load(self, element):
        assert element is None

    def test_checklist_bad_load(self):
        with pytest.raises(ET.ParseError):
            self.bad_ckl.load()

    def test_checklist_load(self):
        self.rhel9_ckl.load()
        assert isinstance(self.rhel9_ckl.tree, ET.ElementTree)
        assert isinstance(self.rhel9_ckl.root, ET.Element)
        assert isinstance(self.rhel9_ckl.asset, AssetNode)
        assert isinstance(self.rhel9_ckl.stigs, list)
        for stig in self.rhel9_ckl.stigs:
            assert isinstance(stig, StigNode)

    def test_checklist_as_dict(self):
        self.rhel9_ckl.load()
        assert self.rhel9_ckl.as_dict()

    @pytest.mark.parametrize(
        "key,value",
        [
            ("ROLE", "None"),
            ("ASSET_TYPE", "Computing"),
            ("MARKING", "CUI"),
            ("HOST_NAME", None),
            ("HOST_IP", None),
            ("HOST_MAC", None),
            ("HOST_FQDN", None),
            ("TARGET_COMMENT", None),
            ("TECH_AREA", None),
            ("TARGET_KEY", "5551"),
            ("WEB_OR_DATABASE", "false"),
            ("WEB_DB_SITE", None),
            ("WEB_DB_INSTANCE", None),
        ],
    )
    def test_asset(self, key, value):
        self.rhel9_ckl.load()
        asset = self.rhel9_ckl.asset
        assert asset.get(key) == value

    def test_stig_node(self):
        self.rhel9_ckl.load()
        stig = self.rhel9_ckl.stigs[0]
        assert stig.stigid == "xccdf_mil.disa.stig_benchmark_RHEL_9_STIG"
        assert stig.version == "001.001"
        assert stig.releaseinfo == "Release: 1.1 Benchmark Date: 12 Mar 2024"

    @pytest.mark.parametrize(
        "key,value",
        [
            ("version", "001.001"),
            ("classification", "UNCLASSIFIED"),
            ("customname", None),
            ("stigid", "xccdf_mil.disa.stig_benchmark_RHEL_9_STIG"),
            (
                "description",
                "This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DOD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.",
            ),
            ("filename", "U_RHEL_9_V1R1_STIG_SCAP_1-3_Benchmark.xml"),
            ("releaseinfo", "Release: 1.1 Benchmark Date: 12 Mar 2024"),
            ("title", "Red Hat Enterprise Linux 9 STIG SCAP Benchmark"),
            ("uuid", "90659ce2-3487-4ef3-b96b-8a7a67ad9c90"),
            ("notice", "terms-of-use"),
            ("source", "STIG.DOD.MIL"),
        ],
    )
    def test_stig_info_node(self, key, value):
        self.rhel9_ckl.load()
        info = self.rhel9_ckl.stigs[0].info
        assert len(info.items()) > 0
        assert info.get(key) == value

    def test_vuln_nodes(self):
        self.rhel9_ckl.load()
        vulns = self.rhel9_ckl.stigs[0].vuln_nodes
        assert len(vulns) > 0
        assert isinstance(vulns, dict)
        for k, v in vulns.items():
            assert k == v.vuln_num
            assert v.status in ["NotAFinding", "Open", "Not_Reviewed", "Not_Applied"]
            assert v.finding_details is None
            assert v.comments is None
            assert v.severity_override is None
            assert v.severity_justification is None

    @pytest.mark.parametrize(
        "key",
        [
            "Vuln_Num",
            "Severity",
            "Group_Title",
            "Rule_ID",
            "Rule_Ver",
            "Rule_Title",
            "Vuln_Discuss",
            "IA_Controls",
            "Check_Content",
            "Fix_Text",
            "False_Positives",
            "False_Negatives",
            "Documentable",
            "Mitigations",
            "Potential_Impact",
            "Third_Party_Tools",
            "Mitigation_Control",
            "Responsibility",
            "Security_Override_Guidance",
            "Check_Content_Ref",
            "Weight",
            "Class",
            "STIGRef",
            "TargetKey",
            "STIG_UUID",
            "LEGACY_ID",
            "CCI_REF",
        ],
    )
    def test_vuln_node_keys(self, key):
        self.rhel9_ckl.load()
        vulns = self.rhel9_ckl.stigs[0].vuln_nodes
        assert len(vulns) > 0
        for v in vulns.values():
            assert any((v.get(key) is None, isinstance(v.get(key), (str))))
