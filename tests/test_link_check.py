"""Link checks against the last firmware build's map file (build/mestio_gw.map).

The SNMP agent (snmp_lwip) is only linked once snmp_gw references it; until stream E lands
components/snmp_gw/usm.c these checks are skipped. Afterwards the agent, the PSA SNMPv3 backend and
the transport must be in the image (DECISIONS.md FIXER, finding "snmp_lwip not linked")."""
import pytest

from conftest import COMPONENTS, ROOT

MAP = ROOT / 'build' / 'mestio_gw.map'


def test_snmp_agent_linked_once_usm_exists():
    if not (COMPONENTS / 'snmp_gw' / 'usm.c').is_file():
        pytest.skip('stream E has not landed snmp_gw/usm.c yet')
    if not MAP.is_file():
        pytest.skip('no firmware build yet (build/mestio_gw.map)')
    text = MAP.read_text(errors='replace')
    for sym in ('snmp_transport_start', 'snmp_receive', 'snmpv3_auth', 'snmpv3_crypt', 'snmpv3_get_user'):
        assert sym in text, f'{sym} is not linked into the firmware image'
