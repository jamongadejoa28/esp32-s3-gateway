/* Pure calendar helpers of gw_core/gw_time.h (UTC, proleptic Gregorian). Host-tested. */
#include <stdio.h>

#include "gw_core/gw_time.h"

/* Days since 1970-01-01 <-> civil date (H. Hinnant's algorithms, valid for the whole int range). */
static int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static void civil_from_days(int64_t z, int64_t *y, unsigned *m, unsigned *d) {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = (unsigned)(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = mp < 10 ? mp + 3 : mp - 9;
    *y = (int64_t)yoe + era * 400 + (*m <= 2);
}

static unsigned days_in_month(unsigned y, unsigned m) {
    static const uint8_t dim[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const int leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    return dim[m - 1] + (m == 2 && leap);
}

void gw_time_to_civil(int64_t epoch_s, gw_civil_t *out) {
    if (epoch_s < 0) {
        epoch_s = 0;
    }
    const int64_t days = epoch_s / 86400;
    const unsigned secs = (unsigned)(epoch_s % 86400);
    int64_t y;
    unsigned m, d;
    civil_from_days(days, &y, &m, &d);
    out->year = (uint16_t)y;
    out->mon = (uint8_t)m;
    out->day = (uint8_t)d;
    out->hour = (uint8_t)(secs / 3600);
    out->min = (uint8_t)(secs / 60 % 60);
    out->sec = (uint8_t)(secs % 60);
    out->wday = (uint8_t)((days + 4) % 7); /* 1970-01-01 was a Thursday */
}

int64_t gw_time_from_civil(const gw_civil_t *c) {
    if (!c || c->year < 1970 || c->year > 2105 || c->mon < 1 || c->mon > 12 || c->day < 1 ||
        c->day > days_in_month(c->year, c->mon) || c->hour > 23 || c->min > 59 || c->sec > 59) {
        return -1;
    }
    return days_from_civil(c->year, c->mon, c->day) * 86400 + c->hour * 3600 + c->min * 60 + c->sec;
}

uint32_t gw_time_yyyymmdd(int64_t epoch_s) {
    gw_civil_t c;
    gw_time_to_civil(epoch_s, &c);
    return (uint32_t)c.year * 10000u + c.mon * 100u + c.day;
}

size_t gw_time_snmp_date(int64_t wall_ms, uint8_t out[11]) {
    if (wall_ms < 0) {
        wall_ms = 0;
    }
    gw_civil_t c;
    gw_time_to_civil(wall_ms / 1000, &c);
    out[0] = (uint8_t)(c.year >> 8);
    out[1] = (uint8_t)c.year;
    out[2] = c.mon;
    out[3] = c.day;
    out[4] = c.hour;
    out[5] = c.min;
    out[6] = c.sec;
    out[7] = (uint8_t)(wall_ms % 1000 / 100);
    out[8] = '+';
    out[9] = 0;
    out[10] = 0;
    return 11;
}

size_t gw_time_iso8601(int64_t wall_ms, char *out, size_t cap) {
    if (!out || cap < 25) {
        return 0;
    }
    if (wall_ms < 0) {
        wall_ms = 0;
    }
    gw_civil_t c;
    gw_time_to_civil(wall_ms / 1000, &c);
    int n = snprintf(out, cap, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", (unsigned)c.year, (unsigned)c.mon,
                     (unsigned)c.day, (unsigned)c.hour, (unsigned)c.min, (unsigned)c.sec,
                     (unsigned)(wall_ms % 1000));
    return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}
