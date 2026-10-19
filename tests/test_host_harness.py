"""The host harness itself: third-party cJSON is available to pure sources, and per-component
libraries build independently of the union library."""
import pytest

from conftest import LISTS, ROOT, compile_and_run


def test_cjson_available_to_host_sources(tmp_path):
    srcs = [ROOT / p for p in LISTS['GW_HOST_THIRD_PARTY_SOURCES']]
    if not all(s.is_file() for s in srcs):
        pytest.skip('managed_components/ not fetched yet (run tools/idf.py reconfigure)')
    prog = r'''
#include <stdio.h>
#include "cJSON.h"
int main(void) {
    cJSON *j = cJSON_Parse("{\"sev_override\":{\"high_hum\":2}}");
    cJSON *o = cJSON_GetObjectItemCaseSensitive(j, "sev_override");
    printf("%d\n", cJSON_GetObjectItemCaseSensitive(o, "high_hum")->valueint);
    cJSON_Delete(j);
    return 0;
}
'''
    flags = ['-DCJSON_NESTING_LIMIT=32', '-DCJSON_CIRCULAR_LIMIT=10000', '-Wno-error']
    assert compile_and_run(tmp_path, prog, extra_sources=srcs, flags=flags).strip() == '2'


def test_per_component_library_builds(host_lib):
    lib = host_lib()  # GW_CORE + host-only backends only
    assert lib.gw_hash_len(2) == 32
