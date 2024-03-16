from pigsty.resources.checklist import Checklist, AssetNode, StigNode, StigInfoNode
from xml.etree import ElementTree as ET
from pathlib import Path
import pytest

class TestChecklist:
    rhel9_file = Path("./tests/files/checklists/rhel9.ckl")
    bad_file = Path("./tests/files/checklists/bad.ckl")
    rhel9_ckl = Checklist(rhel9_file, autoload=False)
    bad_ckl = Checklist(bad_file, autoload=False)

    @pytest.mark.parametrize("element", [rhel9_ckl.tree, rhel9_ckl.root, rhel9_ckl.asset])
    def test_checklist_no_load(self, element):
        assert element is None

    def test_checklist_load(self):
        self.rhel9_ckl.load()
        assert isinstance(self.rhel9_ckl.tree, ET.ElementTree)
        assert isinstance(self.rhel9_ckl.root, ET.Element)
        assert isinstance(self.rhel9_ckl.asset, AssetNode)
        assert isinstance(self.rhel9_ckl.stigs, list)
        for stig in self.rhel9_ckl.stigs:
            assert isinstance(stig, StigNode)

    def test_checklist_bad_load(self):
        with pytest.raises(ET.ParseError):
            self.bad_ckl.load()

    @pytest.mark.parametrize("key,value", [("ROLE","None"),("HOST_IP",None),("ASSET_TYPE","Computing")])
    def test_asset(self, key, value):
        self.rhel9_ckl.load()
        asset = self.rhel9_ckl.asset
        assert asset.get(key) == value


    def test_stig_node(self):
        self.rhel9_ckl.load()
        stig = self.rhel9_ckl.stigs[0]
        assert stig.stigid == 'xccdf_mil.disa.stig_benchmark_RHEL_9_STIG'
        assert stig.version == '001.001'
        assert stig.releaseinfo == 'Release: 1.1 Benchmark Date: 12 Mar 2024'

    def test_checklist_as_dict(self):
        self.rhel9_ckl.load()
        assert self.rhel9_ckl.as_dict()

    def test_vulnerabilities(self):
        self.rhel9_ckl.load()
        assert self.rhel9_ckl.stigs[0].vuln_nodes