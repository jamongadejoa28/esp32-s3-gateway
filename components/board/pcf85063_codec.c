/* PCF85063 time register codec (pure C). Contract: pcf85063_codec.h. Ported from the monitor's
 * monitor_clock_decode_rtc(), but the RTC holds UTC here (monitor: KST civil time). */
#include "pcf85063_codec.h"

#include "gw_core/gw_time.h"

#define PCF_EPOCH_2000 946684800LL /* 2000-01-01T00:00:00Z */
#define PCF_EPOCH_2100 4102444800LL /* 2100-01-01T00:00:00Z */

int pcf_bcd_decode(uint8_t b) {
    const unsigned hi = b >> 4, lo = b & 0x0F;
    if (hi > 9 || lo > 9) {
        return -1;
    }
    return (int)(hi * 10 + lo);
}

uint8_t pcf_bcd_encode(uint8_t v) {
    v %= 100;
    return (uint8_t)(((v / 10) << 4) | (v % 10));
}

int pcf85063_decode(const uint8_t r[PCF85063_TIME_LEN], int64_t *epoch_s) {
    if (r[0] & PCF85063_OS_FLAG) {
        return PCF_E_OSF;
    }
    const int sec = pcf_bcd_decode(r[0] & 0x7F);
    const int min = pcf_bcd_decode(r[1] & 0x7F);
    const int hour = pcf_bcd_decode(r[2] & 0x3F);
    const int day = pcf_bcd_decode(r[3] & 0x3F);
    const int mon = pcf_bcd_decode(r[5] & 0x1F);
    const int year = pcf_bcd_decode(r[6]);
    if (sec < 0 || min < 0 || hour < 0 || day < 0 || mon < 0 || year < 0) {
        return PCF_E_BCD;
    }
    const gw_civil_t c = {
        .year = (uint16_t)(2000 + year),
        .mon = (uint8_t)mon,
        .day = (uint8_t)day,
        .hour = (uint8_t)hour,
        .min = (uint8_t)min,
        .sec = (uint8_t)sec,
    };
    const int64_t t = gw_time_from_civil(&c); /* validates every field incl. days per month */
    if (t < GW_TIME_VALID_MIN_S) {
        return PCF_E_RANGE;
    }
    *epoch_s = t;
    return PCF_OK;
}

bool pcf85063_encode(int64_t epoch_s, uint8_t r[PCF85063_TIME_LEN]) {
    if (epoch_s < PCF_EPOCH_2000 || epoch_s >= PCF_EPOCH_2100) {
        return false;
    }
    gw_civil_t c;
    gw_time_to_civil(epoch_s, &c);
    r[0] = pcf_bcd_encode(c.sec); /* OS flag cleared */
    r[1] = pcf_bcd_encode(c.min);
    r[2] = pcf_bcd_encode(c.hour);
    r[3] = pcf_bcd_encode(c.day);
    r[4] = c.wday;
    r[5] = pcf_bcd_encode(c.mon);
    r[6] = pcf_bcd_encode((uint8_t)(c.year - 2000));
    return true;
}
