/* Router decision core and small HTTP helpers (web_core.h). Pure C, host-tested. */
#include <string.h>

#include "web_core.h"

static bool is_mutating(int m) {
    return m == WEB_CORE_M_POST || m == WEB_CORE_M_PUT || m == WEB_CORE_M_DELETE;
}

web_verdict_t web_policy_decide(const web_rpolicy_t *r, const web_facts_t *f) {
    web_verdict_t v = {0, NULL};
    if (!r || !f) {
        v.status = 500;
        v.code = "internal";
        return v;
    }
    if (r->min_role > GW_ROLE_NONE) {
        if (!f->authed) {
            v.status = 401;
            v.code = "unauthorized";
            return v;
        }
        if (f->role < r->min_role) {
            v.status = 403;
            v.code = "forbidden";
            return v;
        }
        if (f->must_change && !(r->flags & WEB_CORE_RF_ALLOW_MUST_CHANGE)) {
            v.status = 403;
            v.code = "password_change_required";
            return v;
        }
    }
    if (is_mutating(f->method)) {
        if (f->origin_present && !f->origin_ok) {
            v.status = 403;
            v.code = "origin";
            return v;
        }
        if ((r->flags & WEB_CORE_RF_CSRF) && (!f->authed || !f->csrf_ok)) {
            v.status = 403;
            v.code = "csrf";
            return v;
        }
    }
    if (f->content_len > r->max_body) {
        v.status = 413;
        v.code = "payload_too_large";
        return v;
    }
    if (f->content_len > 0 && !(r->flags & WEB_CORE_RF_RAW_BODY) && !f->content_type_json) {
        v.status = 400;
        v.code = "bad_request";
        return v;
    }
    return v;
}

/* Media type check: `ct` equals `type` (case-insensitive) optionally followed by OWS and ';'. */
static bool ct_is(const char *ct, const char *type) {
    if (!ct) {
        return false;
    }
    while (*ct == ' ' || *ct == '\t') {
        ct++;
    }
    size_t n = strlen(type);
    for (size_t i = 0; i < n; i++) {
        char c = ct[i];
        if (c >= 'A' && c <= 'Z') {
            c = (char)(c - 'A' + 'a');
        }
        if (c != type[i]) {
            return false;
        }
    }
    const char *p = ct + n;
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    return *p == '\0' || *p == ';';
}

bool web_ct_is_json(const char *content_type) {
    return ct_is(content_type, "application/json");
}

bool web_ct_is_octet(const char *content_type) {
    return ct_is(content_type, "application/octet-stream");
}

bool web_etag_match(const char *inm, const char *etag) {
    if (!inm || !etag || !etag[0]) {
        return false;
    }
    const size_t el = strlen(etag);
    const char *p = inm;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        if (!*p) {
            break;
        }
        const char *e = p;
        if (*e == '*') {
            return true;
        }
        if (e[0] == 'W' && e[1] == '/') {
            e += 2;
        }
        const char *end = e;
        if (*end == '"') {
            end++;
            while (*end && *end != '"') {
                end++;
            }
            if (*end == '"') {
                end++;
            }
        } else {
            while (*end && *end != ',' && *end != ' ' && *end != '\t') {
                end++;
            }
        }
        if ((size_t)(end - e) == el && memcmp(e, etag, el) == 0) {
            return true;
        }
        p = end;
        while (*p && *p != ',') {
            p++;
        }
    }
    return false;
}

const char *web_status_line(int status) {
    switch (status) {
    case 101:
        return "101 Switching Protocols";
    case 200:
        return "200 OK";
    case 201:
        return "201 Created";
    case 202:
        return "202 Accepted";
    case 204:
        return "204 No Content";
    case 304:
        return "304 Not Modified";
    case 400:
        return "400 Bad Request";
    case 401:
        return "401 Unauthorized";
    case 403:
        return "403 Forbidden";
    case 404:
        return "404 Not Found";
    case 405:
        return "405 Method Not Allowed";
    case 408:
        return "408 Request Timeout";
    case 409:
        return "409 Conflict";
    case 411:
        return "411 Length Required";
    case 413:
        return "413 Content Too Large";
    case 414:
        return "414 URI Too Long";
    case 421:
        return "421 Misdirected Request";
    case 422:
        return "422 Unprocessable Content";
    case 423:
        return "423 Locked";
    case 429:
        return "429 Too Many Requests";
    case 431:
        return "431 Request Header Fields Too Large";
    case 501:
        return "501 Not Implemented";
    case 503:
        return "503 Service Unavailable";
    case 505:
        return "505 HTTP Version Not Supported";
    case 500:
    default:
        return "500 Internal Server Error";
    }
}
