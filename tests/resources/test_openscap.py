import ipaddress
import re
from pathlib import Path

from pigsty.resources.openscap import OpenSCAPSTIGViewerResult, OpenSCAPRuleResult


class TestOpenSCAP:
    stigviewer = Path("./tests/files/openscap/stigviewer-xccdf.xml")
    mac_regex = r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$"

    def _is_ip(self, ip) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_mac(self, mac) -> bool:
        if re.match(self.mac_regex, mac):
            return True
        return False

    def test_load(self):
        r = OpenSCAPSTIGViewerResult(self.stigviewer)
        assert r
        assert r.identity
        assert all(self._is_ip(ip) for ip in r.ipv4)
        assert all(self._is_ip(ip) for ip in r.ipv6)
        assert all(self._is_mac(mac) for mac in r.mac)
        assert "localhost" not in r.hostname
        assert isinstance(r.target_addresses, set)
        assert isinstance(r.cpe, set)
        assert isinstance(r.platform, set)

    def test_set_value(self):
        r = OpenSCAPSTIGViewerResult(self.stigviewer)
        assert (
            "xccdf_org.ssgproject.content_value_var_aide_scan_notification_email"
            in r.set_value
        )
        assert (
            r.set_value[
                "xccdf_org.ssgproject.content_value_var_aide_scan_notification_email"
            ]
            == "root@localhost"
        )

    def test_rule_results(self):
        r = OpenSCAPSTIGViewerResult(self.stigviewer)
        assert r
        assert all(isinstance(r, OpenSCAPRuleResult) for r in r.rule_results.values())
        for k, v in r.rule_results.items():
            assert k in v.rule_id
