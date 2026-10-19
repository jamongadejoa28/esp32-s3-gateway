/*
 * frame.h - Modbus RTU framing for MEX150 (pure C, host-safe).
 * Ported from esp32-s3-monitor src/domain/model.c (mex_crc/mex_request/mex_response): semantics,
 * including return codes, are kept bit-for-bit so the monitor tests port as equivalence tests.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEX_FC_READ_COILS 1
#define MEX_FC_READ_HOLDING 3
#define MEX_FC_WRITE_SINGLE 6
#define MEX_REQ_LEN 8     /* every request we send is 8 bytes */
#define MEX_FRAME_MAX 256 /* RTU ADU maximum */
#define MEX_MAX_READ 16   /* largest block in the poll plan (coils 8, holding 12) rounded up */

/* mex_response() results (monitor-compatible) */
#define MEX_RESP_OK 0
#define MEX_RESP_E_FRAME (-1) /* < 5 bytes, unit mismatch, CRC mismatch, or malformed exception */
#define MEX_RESP_E_FC (-2)    /* function code mismatch */
#define MEX_RESP_E_ECHO (-3)  /* FC05/06 echo differs from request */
#define MEX_RESP_E_LEN (-4)   /* byte count/length/capacity mismatch */

/* Transaction-level errors added by the service (never returned by mex_response) */
#define MEX_TXN_E_TIMEOUT (-10) /* no byte received before the timeout */
#define MEX_TXN_E_UART (-11)    /* UART driver error */

/** CRC-16/MODBUS (poly 0xA001 reflected, init 0xFFFF). Appended little-endian. */
uint16_t mex_crc(const uint8_t *p, size_t n);

/** True iff n >= 3 and the trailing 2 bytes are the CRC of p[0..n-2). */
bool mex_frame_crc_ok(const uint8_t *p, size_t n);

/**
 * Build an 8-byte request: unit, fc, addr (PDU, BE), value/count (BE), CRC (LE).
 * For FC01/FC03 `value` is the quantity; for FC06 the register value. Returns 8.
 */
size_t mex_request(uint8_t unit, uint8_t fc, uint16_t addr, uint16_t value, uint8_t out[MEX_REQ_LEN]);

/**
 * Validate response p[0..n) against request req and unpack values.
 * FC01: values[i] = coil bit i (0/1); FC03: values[i] = register i (BE); FC05/06: echo check only.
 * @return MEX_RESP_OK, a positive Modbus exception code (1..255), or MEX_RESP_E_* (< 0).
 */
int mex_response(const uint8_t req[MEX_REQ_LEN], const uint8_t *p, size_t n, uint16_t *values, size_t cap);

/**
 * Expected total response length given the first n received bytes and the request fc:
 * 0 if n < 3 (unknown yet); 5 for an exception (fc|0x80); 8 for FC05/06; p[2] + 5 otherwise.
 * Used by the receive loop to stop reading early (monitor exchange()).
 */
size_t mex_response_expected(const uint8_t *p, size_t n, uint8_t fc);

#ifdef __cplusplus
}
#endif
