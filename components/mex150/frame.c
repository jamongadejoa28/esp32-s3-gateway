/*
 * frame.c - Modbus RTU framing for MEX150 (pure C, host-safe; contract: mex150/frame.h).
 *
 * Ported from esp32-s3-monitor src/domain/model.c (mex_crc / mex_request / mex_response). Return codes
 * and acceptance rules are identical, with two hardening changes that do not alter any result for
 * inputs the monitor handled: NULL/oversized arguments are rejected instead of dereferenced, and the
 * byte count is checked against the received length before any value is unpacked.
 */
#include "mex150/frame.h"

#include <string.h>

uint16_t mex_crc(const uint8_t *p, size_t n) {
    uint16_t c = 0xFFFFu;
    if (!p)
        return c;
    while (n--) {
        c ^= *p++;
        for (int i = 0; i < 8; i++)
            c = (uint16_t)((c >> 1) ^ ((c & 1u) ? 0xA001u : 0u));
    }
    return c;
}

bool mex_frame_crc_ok(const uint8_t *p, size_t n) {
    if (!p || n < 3)
        return false;
    return mex_crc(p, n - 2) == (uint16_t)(p[n - 2] | (p[n - 1] << 8));
}

size_t mex_request(uint8_t unit, uint8_t fc, uint16_t addr, uint16_t value, uint8_t out[MEX_REQ_LEN]) {
    out[0] = unit;
    out[1] = fc;
    out[2] = (uint8_t)(addr >> 8);
    out[3] = (uint8_t)addr;
    out[4] = (uint8_t)(value >> 8);
    out[5] = (uint8_t)value;
    const uint16_t c = mex_crc(out, 6);
    out[6] = (uint8_t)c;
    out[7] = (uint8_t)(c >> 8);
    return MEX_REQ_LEN;
}

int mex_response(const uint8_t req[MEX_REQ_LEN], const uint8_t *p, size_t n, uint16_t *values, size_t cap) {
    if (!req || !p || n < 5 || n > MEX_FRAME_MAX || p[0] != req[0] || !mex_frame_crc_ok(p, n))
        return MEX_RESP_E_FRAME;
    if (p[1] == (uint8_t)(req[1] | 0x80u))
        return (n == 5 && p[2]) ? p[2] : MEX_RESP_E_FRAME;
    if (p[1] != req[1])
        return MEX_RESP_E_FC;
    if (req[1] == 5 || req[1] == MEX_FC_WRITE_SINGLE)
        return (n == 8 && !memcmp(p, req, 6)) ? MEX_RESP_OK : MEX_RESP_E_ECHO;
    const unsigned count = (unsigned)req[4] * 256u + req[5];
    const unsigned bytes = req[1] == MEX_FC_READ_COILS ? (count + 7u) / 8u : count * 2u;
    if ((req[1] != MEX_FC_READ_COILS && req[1] != MEX_FC_READ_HOLDING) || n != bytes + 5u || p[2] != bytes ||
        count > cap || !values)
        return MEX_RESP_E_LEN;
    for (unsigned i = 0; i < count; i++) {
        values[i] = req[1] == MEX_FC_READ_COILS ? (uint16_t)((p[3 + i / 8] >> (i % 8)) & 1u)
                                                 : (uint16_t)(p[3 + 2 * i] * 256u + p[4 + 2 * i]);
    }
    return MEX_RESP_OK;
}

size_t mex_response_expected(const uint8_t *p, size_t n, uint8_t fc) {
    if (!p || n < 3)
        return 0;
    if (p[1] & 0x80u)
        return 5;
    if (fc == 5 || fc == MEX_FC_WRITE_SINGLE)
        return 8;
    return (size_t)p[2] + 5u;
}
