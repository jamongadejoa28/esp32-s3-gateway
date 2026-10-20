"""Exercise the actual C package uploader with fragmented HTTP reads and simulated flash faults.

sysmgr's existing app validation is stubbed here; these tests cover the new web/package layer.
LittleFS image content and the packager are separately read back by test_web_littlefs.py.
"""
import gzip
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from conftest import ROOT, CFLAGS, INCLUDE_FLAGS, cc

sys.path.insert(0, str(ROOT / 'tools'))
import gen_web_assets as assets
import build_web_fs
import package_ota

SHIM = r'''
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/evp.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NOT_FOUND 1
#define ESP_ERR_INVALID_CRC 2
#define ESP_ERR_INVALID_STATE 3
#define ESP_ERR_INVALID_SIZE 4
#define ESP_ERR_NO_MEM 5
#define ESP_ERR_OTA_VALIDATE_FAILED 6
#define ESP_ERR_INVALID_VERSION 7
#define ESP_PARTITION_SUBTYPE_APP_OTA_0 16
#define ESP_PARTITION_SUBTYPE_APP_OTA_1 17
#define ESP_PARTITION_TYPE_DATA 1
#define ESP_PARTITION_SUBTYPE_DATA_LITTLEFS 0x83
#define ESP_OTA_IMG_PENDING_VERIFY 1
#define GW_HB_HTTPD 0
#define GW_CRYPTO_OK 0
#define GW_HASH_SHA256 0
#define GW_VERSION_SZ 32
#define SYS_OTA_REBOOT_DELAY_MS 2000
#define MALLOC_CAP_INTERNAL 1
#define MALLOC_CAP_8BIT 2
#define WEB_E_BAD_REQUEST "bad_request"
#define WEB_E_IMAGE_INVALID "image_invalid"
#define WEB_E_UNAVAILABLE "unavailable"
#define WEB_E_LOCKED "locked"
#define WEB_E_TOO_LARGE "too_large"
#define WEB_E_INTERNAL "internal"
#define WEB_E_HASH_MISMATCH "hash_mismatch"
#define ESP_LOGE(tag, ...) ((void)(tag))
#define ESP_LOGI(tag, ...) ((void)(tag))
#define ESP_LOGW(tag, ...) ((void)(tag))
typedef struct { int subtype; size_t size; const char *label; } esp_partition_t;
typedef int esp_ota_img_states_t;
typedef struct { const char *base_path, *partition_label; bool format_if_mount_failed, read_only; } esp_vfs_littlefs_conf_t;
typedef struct { size_t content_len; } httpd_req_t;
typedef struct { httpd_req_t *req; } web_ctx_t;
typedef struct { int unused; } gw_jw_t;
typedef struct { size_t len, done; unsigned char expected[32]; } sys_ota_t;
typedef EVP_MD_CTX gw_hash_ctx_t;
const esp_partition_t *esp_ota_get_running_partition(void);
const esp_partition_t *esp_ota_get_next_update_partition(const void *p);
const esp_partition_t *esp_partition_find_first(int type, int subtype, const char *label);
esp_err_t esp_ota_get_state_partition(const esp_partition_t *p, esp_ota_img_states_t *s);
esp_err_t esp_partition_erase_range(const esp_partition_t *p, size_t off, size_t n);
esp_err_t esp_partition_write(const esp_partition_t *p, size_t off, const void *src, size_t n);
esp_err_t esp_partition_read(const esp_partition_t *p, size_t off, void *dst, size_t n);
esp_err_t esp_vfs_littlefs_register(const esp_vfs_littlefs_conf_t *c);
esp_err_t esp_vfs_littlefs_unregister(const char *label);
void *heap_caps_malloc(size_t n, int caps);
void gw_hb_beat(int id);
gw_hash_ctx_t *gw_hash_begin(int kind);
int gw_hash_update(gw_hash_ctx_t *h, const void *data, size_t n);
int gw_hash_finish(gw_hash_ctx_t *h, unsigned char *digest);
void gw_hash_abort(gw_hash_ctx_t *h);
bool gw_ct_equal(const void *a, const void *b, size_t n);
int gw_hex_decode(const char *hex, size_t n, unsigned char *dst, size_t cap);
bool web_header(web_ctx_t *c, const char *name, char *out, size_t n);
bool web_ct_is_octet(const char *s);
#define WEB_Q_INVALID -1
int web_query_bool(web_ctx_t *c, const char *key, bool *out);
const char *web_user(web_ctx_t *c);
int web_body_read(web_ctx_t *c, void *buf, size_t n);
esp_err_t web_send_error(web_ctx_t *c, int status, const char *code, const char *message, const void *extra);
esp_err_t web_send_esp_err(web_ctx_t *c, int err);
esp_err_t sys_ota_begin(size_t n, const uint8_t sha[32], bool allow, const char *by, sys_ota_t **out);
esp_err_t sys_ota_write(sys_ota_t *s, const void *buf, size_t n);
void sys_ota_abort(sys_ota_t *s);
esp_err_t sys_ota_end(sys_ota_t *s, char version[32]);
void gw_jw_init_fixed(gw_jw_t *w, void *buf, size_t n);
void gw_jw_obj_open(gw_jw_t *w);
void gw_jw_kstr(gw_jw_t *w, const char *key, const char *value);
void gw_jw_kuint(gw_jw_t *w, const char *key, unsigned value);
void gw_jw_obj_close(gw_jw_t *w);
esp_err_t web_send_jw(web_ctx_t *c, int status, gw_jw_t *w);
'''

HARNESS = r'''
#include <stdio.h>
#include <string.h>
#include "shim.h"
static esp_partition_t app = {17,0x280000,"ota_1"}, web = {0x83,0x80000,"web_1"};
static unsigned char app_bytes[0x280000], web_bytes[0x80000], running_web[0x80000];
static unsigned char *packet;
static size_t packet_len, received, fragment, truncate_at;
static int status, commits, aborts, erased, touched, mount_fail, write_fail, corrupt_read, reject_app;
static const char *error = "none";
static char hex[65];
const esp_partition_t *esp_ota_get_running_partition(void) { static esp_partition_t p = {16,0x280000,"ota_0"}; return &p; }
const esp_partition_t *esp_ota_get_next_update_partition(const void *p) { (void)p; return &app; }
const esp_partition_t *esp_partition_find_first(int t, int s, const char *label) {
    (void)t; (void)s; return !strcmp(label,"web_1") ? &web : NULL;
}
esp_err_t esp_ota_get_state_partition(const esp_partition_t *p, esp_ota_img_states_t *s) { (void)p; *s=0; return ESP_OK; }
esp_err_t esp_partition_erase_range(const esp_partition_t *p, size_t off, size_t n) {
    if (p != &web || off+n>p->size || off%4096 || n!=4096) return ESP_FAIL;
    memset(web_bytes+off,255,n); erased++; return ESP_OK;
}
esp_err_t esp_partition_write(const esp_partition_t *p, size_t off, const void *src, size_t n) {
    if (p != &web || off+n>p->size || (write_fail && off>=4096)) return ESP_FAIL;
    memcpy(web_bytes+off,src,n); touched++; return ESP_OK;
}
esp_err_t esp_partition_read(const esp_partition_t *p, size_t off, void *dst, size_t n) {
    if (off+n>p->size) return ESP_FAIL;
    memcpy(dst,(p==&web ? web_bytes : app_bytes)+off,n);
    if (p==&web && corrupt_read && off==0) ((unsigned char *)dst)[0]^=1;
    return ESP_OK;
}
esp_err_t esp_vfs_littlefs_register(const esp_vfs_littlefs_conf_t *c) {
    return !c->format_if_mount_failed && c->read_only && !strcmp(c->partition_label,"web_1") && !mount_fail ? ESP_OK : ESP_FAIL;
}
esp_err_t esp_vfs_littlefs_unregister(const char *s) { (void)s; return ESP_OK; }
void *heap_caps_malloc(size_t n, int c) { (void)c; return malloc(n); }
void gw_hb_beat(int id) { (void)id; }
gw_hash_ctx_t *gw_hash_begin(int kind) { (void)kind; EVP_MD_CTX *h=EVP_MD_CTX_new(); EVP_DigestInit_ex(h,EVP_sha256(),NULL); return h; }
int gw_hash_update(gw_hash_ctx_t *h, const void *d, size_t n) { return EVP_DigestUpdate(h,d,n)==1 ? 0 : -1; }
int gw_hash_finish(gw_hash_ctx_t *h, unsigned char *d) { int r=EVP_DigestFinal_ex(h,d,NULL); EVP_MD_CTX_free(h); return r==1 ? 0 : -1; }
void gw_hash_abort(gw_hash_ctx_t *h) { EVP_MD_CTX_free(h); }
bool gw_ct_equal(const void *a, const void *b, size_t n) { return !memcmp(a,b,n); }
int gw_hex_decode(const char *s, size_t n, unsigned char *d, size_t cap) {
    if (n!=64 || cap<32) return -1;
    for (size_t i=0;i<32;i++) { unsigned value; if(sscanf(s+i*2,"%2x",&value)!=1) return -1; d[i]=(unsigned char)value; } return 32;
}
bool web_header(web_ctx_t *c, const char *name, char *out, size_t n) { (void)c; snprintf(out,n,"%s",!strcmp(name,"Content-Type") ? "application/octet-stream" : hex); return true; }
bool web_ct_is_octet(const char *s) { return !strcmp(s,"application/octet-stream"); }
int web_query_bool(web_ctx_t *c, const char *k, bool *v) { (void)c; (void)k; *v=false; return 0; }
const char *web_user(web_ctx_t *c) { (void)c; return "admin"; }
int web_body_read(web_ctx_t *c, void *out, size_t n) {
    (void)c;
    if (received>=truncate_at) return -1;
    if(n>fragment) n=fragment;
    if(n>truncate_at-received) n=truncate_at-received;
    memcpy(out,packet+received,n); received+=n; return (int)n;
}
esp_err_t web_send_error(web_ctx_t *c, int s, const char *code, const char *m, const void *x) { (void)c; (void)m; (void)x; status=s; error=code; return ESP_OK; }
esp_err_t web_send_esp_err(web_ctx_t *c, int e) { (void)e; return web_send_error(c,500,"internal",NULL,NULL); }
esp_err_t sys_ota_begin(size_t n, const uint8_t sha[32], bool a, const char *by, sys_ota_t **out) {
    (void)a; (void)by; *out=calloc(1,sizeof(sys_ota_t)); (*out)->len=n; memcpy((*out)->expected,sha,32); return ESP_OK;
}
esp_err_t sys_ota_write(sys_ota_t *s, const void *buf, size_t n) {
    if(reject_app) { free(s); aborts++; return ESP_ERR_INVALID_VERSION; }
    memcpy(app_bytes+s->done,buf,n); s->done+=n; return ESP_OK;
}
void sys_ota_abort(sys_ota_t *s) { free(s); aborts++; app_bytes[0]=0; }
esp_err_t sys_ota_end(sys_ota_t *s, char version[32]) {
    unsigned char digest[32]; EVP_Digest(app_bytes,s->done,digest,NULL,EVP_sha256(),NULL);
    bool valid=s->len==s->done && !memcmp(digest,s->expected,32); free(s);
    if(!valid) { aborts++; return ESP_ERR_INVALID_CRC; }
    strcpy(version,"9.9.9"); commits++; return ESP_OK;
}
void gw_jw_init_fixed(gw_jw_t *w, void *b, size_t n) { (void)w; (void)b; (void)n; }
void gw_jw_obj_open(gw_jw_t *w) { (void)w; }
void gw_jw_kstr(gw_jw_t *w, const char *k, const char *v) { (void)w; (void)k; (void)v; }
void gw_jw_kuint(gw_jw_t *w, const char *k, unsigned v) { (void)w; (void)k; (void)v; }
void gw_jw_obj_close(gw_jw_t *w) { (void)w; }
esp_err_t web_send_jw(web_ctx_t *c, int s, gw_jw_t *w) { (void)c; (void)w; status=s; return ESP_OK; }
#include "ota_upload.c"
int main(int argc, char **argv) {
    if(argc<4) return 2;
    FILE *f=fopen(argv[1],"rb"); if(!f) return 2;
    fseek(f,0,SEEK_END); packet_len=(size_t)ftell(f); rewind(f);
    packet=malloc(packet_len); if(fread(packet,1,packet_len,f)!=packet_len) return 2; fclose(f);
    fragment=(size_t)strtoul(argv[2],NULL,10); truncate_at=packet_len;
    const char *mode=argv[3];
    unsigned char digest[32]; EVP_Digest(packet,packet_len,digest,NULL,EVP_sha256(),NULL);
    for(size_t i=0;i<32;i++) snprintf(hex+i*2,3,"%02x",digest[i]);
    if(!strcmp(mode,"hashfail")) memset(hex,'0',64);
    if(!strcmp(mode,"truncate")) truncate_at=80+8192+513;
    mount_fail=!strcmp(mode,"mountfail"); write_fail=!strcmp(mode,"writefail");
    corrupt_read=!strcmp(mode,"readfail"); reject_app=!strcmp(mode,"rejectapp");
    memset(running_web,0xaa,sizeof(running_web));
    httpd_req_t req={packet_len}; web_ctx_t ctx={&req};
    (void)h_firmware_upload(&ctx);
    bool intact=true; for(size_t i=0;i<sizeof(running_web);i++) if(running_web[i]!=0xaa) intact=false;
    printf("%d %d %d %d %d %d %s\n",status,commits,aborts,erased,touched,intact,error);
    free(packet); return 0;
}
'''


@pytest.fixture(scope='module')
def uploader(tmp_path_factory):
    root = tmp_path_factory.mktemp('web-ota')
    bodies = [assets.Asset('/', 'text/html', '"index"', gzip.compress(b'<html>hello</html>'), False)]
    stage = root / 'webfs'
    assets.write_filesystem(bodies, stage)
    image = build_web_fs.build(stage, 0x80000)
    app = bytearray(8192)
    app[0] = 0xe9
    app[4070:4145] = f'GW_WEB_ID:{assets.asset_id(bodies)}\0'.encode()
    packet = package_ota.package(bytes(app), image)
    (root / 'package.gwota').write_bytes(packet)
    mismatched_app = bytes(app).replace(b'GW_WEB_ID:', b'GW_BAD_ID:')
    mismatch = package_ota.HEADER.pack(package_ota.MAGIC, len(app), len(image),
                    hashlib.sha256(mismatched_app).digest(), hashlib.sha256(image).digest())
    (root / 'mismatch.gwota').write_bytes(mismatch + mismatched_app + image)
    (root / 'legacy.bin').write_bytes(app)
    (root / 'shim.h').write_text(SHIM)
    for header in ('esp_heap_caps.h', 'esp_littlefs.h', 'esp_log.h', 'esp_ota_ops.h',
                   'gw_core/gw_b64.h', 'gw_core/gw_health.h', 'gw_core/gw_crypto.h',
                   'sysmgr/sysmgr.h', 'web_priv.h'):
        p = root / header
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('#include "shim.h"\n')
    shutil.copy(ROOT / 'components/web/ota_upload.c', root / 'ota_upload.c')
    (root / 'main.c').write_text(HARNESS)
    exe = root / 'uploader'
    cc([*CFLAGS, f'-DWEB_CHECK_BASE="{stage}"', f'-I{root}', *INCLUDE_FLAGS,
        str(root / 'main.c'), '-lcrypto', '-o', str(exe)])

    def run(mode='normal', fragment=4096, filename='package.gwota'):
        result = subprocess.run([str(exe), str(root / filename), str(fragment), mode],
                                capture_output=True, text=True, check=True, timeout=20)
        values = result.stdout.split()
        return [int(v) for v in values[:6]], values[6]
    return run


@pytest.mark.parametrize('fragment', [7, 1023, 4096])
def test_fragmented_package_commits_only_after_web_validation(uploader, fragment):
    report, error = uploader(fragment=fragment)
    assert report[:4] == [200, 1, 0, 128] and report[4] > 0 and report[5] == 1
    assert error == 'none'


@pytest.mark.parametrize('mode, status, code', [
    ('hashfail', 422, 'hash_mismatch'), ('readfail', 422, 'hash_mismatch'),
    ('mountfail', 422, 'image_invalid'), ('writefail', 500, 'internal'),
    ('rejectapp', 422, 'image_invalid'), ('truncate', 0, 'none'),
])
def test_failed_upload_never_commits_and_preserves_running_pair(uploader, mode, status, code):
    report, error = uploader(mode)
    assert report[:3] == [status, 0, 1] and report[5] == 1 and error == code


def test_legacy_bin_is_rejected_before_any_flash_writes(uploader):
    report, error = uploader(filename='legacy.bin')
    assert report == [422, 0, 0, 0, 0, 1] and error == 'image_invalid'


def test_mismatched_app_and_web_are_rejected_even_with_valid_component_hashes(uploader):
    report, error = uploader(filename='mismatch.gwota')
    assert report[:3] == [422, 0, 1] and report[5] == 1 and error == 'image_invalid'
