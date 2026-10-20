"""Compile the production static-file server with host HTTP/mount stubs and stream real files."""
import gzip
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from conftest import ROOT, cc, INCLUDE_FLAGS, CFLAGS

sys.path.insert(0, str(ROOT / 'tools'))
import gen_web_assets as assets

SHIM = r'''
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NOT_FOUND 1
#define ESP_ERR_INVALID_CRC 2
#define ESP_PARTITION_SUBTYPE_APP_OTA_0 16
#define ESP_PARTITION_SUBTYPE_APP_OTA_1 17
#define GW_HB_HTTPD 0
#define WEB_E_NOT_FOUND "not_found"
#define WEB_E_UNAVAILABLE "unavailable"
#define MEX_REGMAP_VERSION 1
#define ESP_LOGE(tag, ...) ((void)(tag))
#define ESP_LOGI(tag, ...) ((void)(tag))
#define ESP_LOGD(tag, ...) ((void)(tag))
typedef struct { int subtype; } esp_partition_t;
typedef struct { const char *base_path, *partition_label; bool format_if_mount_failed, read_only; } esp_vfs_littlefs_conf_t;
typedef struct { bool api, cache_set; } web_rstate_t;
typedef struct { int unused; } httpd_req_t;
const esp_partition_t *esp_ota_get_running_partition(void);
esp_err_t esp_vfs_littlefs_register(const esp_vfs_littlefs_conf_t *c);
esp_err_t esp_vfs_littlefs_unregister(const char *label);
web_rstate_t *web_rs(httpd_req_t *req);
esp_err_t web_send_error_raw(httpd_req_t *req, int status, const char *code);
void web_security_headers(httpd_req_t *req);
const char *web_status_line(int status);
bool web_etag_match(const char *a, const char *b);
void gw_hb_beat(int id);
const char *esp_err_to_name(int e);
void esp_app_get_elf_sha256(char *s, size_t n);
esp_err_t httpd_resp_set_hdr(httpd_req_t *r, const char *name, const char *value);
size_t httpd_req_get_hdr_value_len(httpd_req_t *r, const char *name);
esp_err_t httpd_req_get_hdr_value_str(httpd_req_t *r, const char *name, char *out, size_t size);
esp_err_t httpd_resp_set_status(httpd_req_t *r, const char *s);
esp_err_t httpd_resp_set_type(httpd_req_t *r, const char *s);
esp_err_t httpd_resp_send(httpd_req_t *r, const char *data, size_t len);
esp_err_t httpd_resp_send_chunk(httpd_req_t *r, const char *data, size_t len);
'''

HARNESS = r'''
#include <stdio.h>
#include <string.h>
#include "shim.h"
#include "web/web_assets.h"
static int status = 200, chunks, finished, max_chunk, security, immutable, gzip_hdr, etag_hdr;
static bool revalidate, fail_send, mount_fail;
static web_rstate_t state;
static esp_partition_t run = {16};
const esp_partition_t *esp_ota_get_running_partition(void) { return &run; }
esp_err_t esp_vfs_littlefs_register(const esp_vfs_littlefs_conf_t *c) {
    if (c->format_if_mount_failed || !c->read_only) return ESP_FAIL;
    if (strcmp(c->partition_label, run.subtype == 16 ? "web_0" : "web_1")) return ESP_FAIL;
    return mount_fail ? ESP_FAIL : ESP_OK;
}
esp_err_t esp_vfs_littlefs_unregister(const char *s) { (void)s; return ESP_OK; }
web_rstate_t *web_rs(httpd_req_t *r) { (void)r; return &state; }
esp_err_t web_send_error_raw(httpd_req_t *r, int s, const char *c) { (void)r; (void)c; status=s; return ESP_OK; }
void web_security_headers(httpd_req_t *r) { (void)r; security++; }
const char *web_status_line(int s) { return s == 304 ? "304 Not Modified" : "200 OK"; }
bool web_etag_match(const char *a, const char *b) { return !strcmp(a,b); }
void gw_hb_beat(int id) { (void)id; }
const char *esp_err_to_name(int e) { (void)e; return "error"; }
void esp_app_get_elf_sha256(char *s, size_t n) { snprintf(s,n,"1234567890abcdef"); }
esp_err_t httpd_resp_set_hdr(httpd_req_t *r, const char *n, const char *v) {
    (void)r;
    if (!strcmp(n,"Cache-Control") && strstr(v,"immutable")) immutable++;
    if (!strcmp(n,"Content-Encoding") && !strcmp(v,"gzip")) gzip_hdr++;
    if (!strcmp(n,"ETag")) etag_hdr++;
    return ESP_OK;
}
size_t httpd_req_get_hdr_value_len(httpd_req_t *r, const char *n) { (void)r; (void)n; return revalidate ? 7 : 0; }
esp_err_t httpd_req_get_hdr_value_str(httpd_req_t *r, const char *n, char *s, size_t cap) {
    (void)r; (void)n; snprintf(s,cap,"\"index\""); return ESP_OK;
}
esp_err_t httpd_resp_set_status(httpd_req_t *r, const char *s) { (void)r; status = !strncmp(s,"304",3) ? 304 : 200; return ESP_OK; }
esp_err_t httpd_resp_set_type(httpd_req_t *r, const char *s) { (void)r; (void)s; return ESP_OK; }
esp_err_t httpd_resp_send(httpd_req_t *r, const char *s, size_t n) { (void)r; (void)s; (void)n; return ESP_OK; }
esp_err_t httpd_resp_send_chunk(httpd_req_t *r, const char *s, size_t n) {
    (void)r;
    if (!n) { finished++; return ESP_OK; }
    chunks++; if ((int)n > max_chunk) max_chunk=(int)n;
    if (fail_send && chunks == 2) return ESP_FAIL;
    for (size_t i=0;i<n;i++) printf("%02x",(unsigned char)s[i]);
    return ESP_OK;
}
#include "static.c"
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "normal";
    revalidate = !strcmp(mode,"cached"); fail_send = !strcmp(mode,"sendfail"); mount_fail = !strcmp(mode,"mountfail");
    if (!strcmp(mode,"slot1")) run.subtype=17;
    (void)web_assets_mount();
    const char *path = !strcmp(mode,"unknown") ? "/../secret" : !strcmp(mode,"immutable") ? "/assets/app.12345678.js" : "/";
    httpd_req_t req = {0};
    int err = web_static_serve(&req,path,strlen(path));
    printf("\n%d %d %d %d %d %d %d %d %d\n",status,err,chunks,finished,max_chunk,security,immutable,gzip_hdr,etag_hdr);
    return 0;
}
'''


@pytest.fixture
def server(tmp_path):
    body = os.urandom(70 * 1024)
    entries = [assets.Asset('/', 'text/html', '"index"', gzip.compress(body), False),
               assets.Asset('/assets/app.12345678.js', 'text/javascript', '"js"', gzip.compress(b'js'), True)]
    stage = tmp_path / 'webfs'
    assets.write_filesystem(entries, stage)
    (tmp_path / 'metadata.c').write_text(assets.render_c(entries, 'host test', 262144))
    (tmp_path / 'shim.h').write_text(SHIM)
    for header in ('esp_app_desc.h', 'esp_littlefs.h', 'esp_log.h', 'esp_ota_ops.h',
                   'gw_core/gw_health.h', 'mex150/regmap.h', 'web_priv.h'):
        p = tmp_path / header
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('#include "shim.h"\n')
    shutil.copy(ROOT / 'components/web/static.c', tmp_path / 'static.c')
    (tmp_path / 'main.c').write_text(HARNESS)
    exe = tmp_path / 'server'
    cc([*CFLAGS, '-D_POSIX_C_SOURCE=200809L', f'-DWEB_FS_BASE="{stage}"',
        f'-I{tmp_path}', *INCLUDE_FLAGS, str(tmp_path / 'main.c'), str(tmp_path / 'metadata.c'), '-o', str(exe)])

    def run(mode='normal'):
        result = subprocess.run([str(exe), mode], capture_output=True, text=True, check=True)
        hex_body, report = result.stdout.splitlines()
        return bytes.fromhex(hex_body), list(map(int, report.split()))
    return run, stage, body


@pytest.mark.parametrize('mode', ['normal', 'slot1'])
def test_streams_byte_exact_gzip_in_bounded_chunks(server, mode):
    run, _, plain = server
    body, report = run(mode)
    assert gzip.decompress(body) == plain
    status, err, chunks, finished, maximum, security, immutable, encoded, etag = report
    assert (status, err, finished, maximum, security, immutable, encoded, etag) == (200, 0, 1, 1024, 1, 0, 1, 1)
    assert chunks > 64


def test_304_sends_no_body_and_retains_security_headers(server):
    run, _, _ = server
    body, report = run('cached')
    assert body == b'' and report[:4] == [304, 0, 0, 0] and report[5] == 1


def test_immutable_cache_and_midstream_send_failure(server):
    run, _, _ = server
    _, report = run('immutable')
    assert report[0] == 200 and report[6:] == [1, 1, 1]
    body, report = run('sendfail')
    assert len(body) == 1024 and report[:4] == [200, -1, 2, 0]


@pytest.mark.parametrize('fault', ['identity', 'missing', 'truncated', 'mountfail'])
def test_corrupt_or_unavailable_filesystem_returns_503_without_body(server, fault):
    run, stage, _ = server
    if fault == 'identity': (stage / '.asset-id').write_text('wrong identity')
    elif fault == 'missing': (stage / 'index.html.gz').unlink()
    elif fault == 'truncated': (stage / 'index.html.gz').write_bytes(b'truncated')
    body, report = run(fault)
    assert body == b'' and report[0] == 503


def test_only_manifest_paths_are_served(server):
    run, _, _ = server
    body, report = run('unknown')
    assert not body and report[0] == 404
