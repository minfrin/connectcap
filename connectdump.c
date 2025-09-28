/**
 *    Copyright (C) 2025 Graham Leggett <minfrin@sharp.fm>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "config.h"

#include <assert.h>
#include <stdlib.h>

#include <apr.h>
#include <apr_base64.h>
#include <apr_buckets.h>
#include <apr_encode.h>
#include <apr_file_io.h>
#include <apr_getopt.h>
#include <apr_network_io.h>
#include <apr_poll.h>
#include <apr_pools.h>
#include <apr_portable.h>
#include <apr_tables.h>
#include <apr_strings.h>

#include <pcap/pcap.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define DEFAULT_BUFFER_SIZE 1 * 1024 * 1024
#define DEFAULT_LISTENBACKLOG 511
#define DEFAULT_POLLSOCKETS 10240
#define DEFAULT_REQUEST_TIMEOUT 5
#define DEFAULT_PUMP_TIMEOUT 30
#define DEFAULT_CAPTURE_TIMEOUT 2
#define DEFAULT_PCAP_DEVICE "any"
#define DEFAULT_PCAP_SNAPLEN 65536

#define HUGE_STRING_LEN 8192

#define CRLF "\015\012"

#define NONCE_TIME_LEN  (((sizeof(apr_time_t)+2)/3)*4)
#define NONCE_HASH_LEN  (2*SHA256_DIGEST_LENGTH)
#define NONCE_LEN       (int )(NONCE_TIME_LEN + NONCE_HASH_LEN)

typedef enum prefer_e {
    NO_PREFERENCE,
    PREFER_IPV4,
    PREFER_IPV6,
} prefer_e;

typedef struct connectdump_t {
    apr_pool_t *pool;
    apr_pool_t *tpool;
    apr_file_t *err;
    apr_file_t *in;
    apr_file_t *out;
    const char *laddr4;
    const char *laddr6;
    const char *interface;
    const char *realm;
    EVP_MD *sha256;
    apr_array_header_t *events;
    apr_pollset_t *pollset;
    apr_bucket_alloc_t *alloc;
    int numbers;
    prefer_e prefer;
    apr_int32_t family;
    apr_int32_t flags;
    int shutdown;
} connectdump_t;

struct event_t;

typedef struct listen_t {
    /**
     * Local apr_sockaddr_t to listen to
     */
    apr_sockaddr_t *sa;

    /**
     * The listening socket
     */
    apr_socket_t *sd;

} listen_t;

typedef struct request_t {
    /**
     * Remote apr_sockaddr_t to connect to
     */
    apr_sockaddr_t *sa;

    /**
     * The accepted frontend socket
     */
    apr_socket_t *sd;

    /**
     * Incoming bucket brigade
     */
    apr_bucket_brigade *ibb;

    /**
     * Outgoing bucket brigade
     */
    apr_bucket_brigade *obb;

    /**
     * Bucket brigade for lines
     */
    apr_bucket_brigade *bb;

    /**
     * Address we are to connect to
     */
    char *address;

    /**
     * Host we are to connect to
     */
    char *host;

    /**
     * Scope ID of host we are to connect to
     */
    char *scope_id;

    /**
     * Port of host we are to connect to
     */
    apr_port_t port;

    /**
     * The pump associated with the request
     */
    struct event_t *pump;

    /**
     * Proxy-Authenticate header to be sent to browser
     */
    const char *authenticate;

    /**
     * Message to be included with 407 response.
     */
    const char *not_authenticated;

    /**
     * Is the username hashed by the client?
     */
    unsigned int userhash:1;
} request_t;

typedef struct pump_t {
    /**
     * The local apr_sockaddr_t to bind to
     */
    apr_sockaddr_t *lsa;

    /**
     * The peer apr_sockaddr_t to connect to
     */
    apr_sockaddr_t *psa;

    /**
     * The actual socket
     */
    apr_socket_t *sd;

    /**
     * Incoming bucket brigade
     */
    apr_bucket_brigade *ibb;

    /**
     * Outgoing bucket brigade
     */
    apr_bucket_brigade *obb;

    /**
     * Empty space
     */
    void *bb;

    /**
     * Address we are to connect to
     */
    char *address;

    /**
     * Host we are to connect to
     */
    char *host;

    /**
     * Scope ID of host we are to connect to
     */
    char *scope_id;

    /**
     * Port of host we are to connect to
     */
    apr_port_t port;

    /**
     * The request that spawned this pump
     */
    struct event_t *request;

    /**
     * The capture that was spawned by this pump
     */
    struct event_t *capture;
} pump_t;

typedef struct capture_t {
    /**
     * The local apr_sockaddr_t to bind to
     */
    apr_sockaddr_t *lsa;

    /**
     * The peer apr_sockaddr_t to connect to
     */
    apr_sockaddr_t *psa;

    /**
     * The actual socket
     */
    apr_socket_t *sd;

    /**
     * Empty space
     */
    void *ibb;

    /**
     * Empty space
     */
    void *obb;

    /**
     * Empty space
     */
    void *bb;

    /**
     * Address we are to connect to
     */
    char *address;

    /**
     * Host we are to connect to
     */
    char *host;

    /**
     * Scope ID of host we are to connect to
     */
    char *scope_id;

    /**
     * Port of host we are to connect to
     */
    apr_port_t port;

    /**
     * The pump we are capturing
     */
    struct event_t *pump;

    /**
     * The pcap session
     */
    pcap_t *pcap;

    /**
     * The pcap save session
     */
    pcap_dumper_t *dumper;

    /**
     * The eml save session
     */
    apr_file_t *eml;
} capture_t;

typedef enum event_e {
    EVENT_NONE,
    EVENT_LISTEN,
    EVENT_REQUEST,
    EVENT_PUMP,
    EVENT_CAPTURE,
} event_e;

typedef struct event_t {
    connectdump_t *cd;
    apr_pool_t *pool;
    apr_time_t timestamp;
    apr_time_t when;
    apr_pollfd_t pfd;
    int number;
    event_e type;
    union {
        listen_t listen;
        request_t request;
        pump_t pump;
        capture_t capture;
    };
} event_t;

typedef union time_union {
    apr_time_t    time;
    unsigned char arr[sizeof(apr_time_t)];
} time_rec;

static const apr_getopt_option_t
    cmdline_opts[] =
{
    /* commands */
    { "help", 'h', 0, "  -h, --help\t\t\tDisplay this help message." },
    { "version", 'v', 0,
        "  -v, --version\t\t\tDisplay the version number." },
    { "source-ipv4", '4', 1, "  -4, --source-ipv4 ip4\t\t\tSource address for IPv4 connections. If specified before the -6 option, attempt IPv4 first." },
    { "source-ipv6", '6', 1, "  -6, --source-ipv6 ip6\t\t\tSource address for IPv6 connections. If specified before the -4 option, attempt IPv6 first." },
    { "interface", 'i', 1, "  -i, --interface dev\t\t\tInterface containing the source addresses. This interface will be used to capture traffic." },
    { NULL }
};

static int help(apr_file_t *out, const char *name, const char *msg, int code,
        const apr_getopt_option_t opts[])
{
    const char *n;
    int i = 0;

    n = strrchr(name, '/');
    if (!n) {
        n = name;
    }
    else {
        n++;
    }

    apr_file_printf(out,
            "%s\n"
            "\n"
            "NAME\n"
            "  %s - https CONNECT proxy that records network traffic for diagnostics.\n"
            "\n"
            "SYNOPSIS\n"
            "  %s [-4] [-6] [-v] [-h] address:port [address:port ...]\n"
            "\n"
            "DESCRIPTION\n"
            "\n"
            "  The connectdump daemon implements an https CONNECT proxy that records\n"
            "  all outgoing traffic as pcap for later analysis in Wireshark.\n"
            "\n"
            "  No attempts are made to compensate for badly configured servers, the\n"
            " idea being to provide predictable diagnostics for each connection.\n"
            "\n"
            "  The daemon will listen on all the addresses and ports specified.\n"
            "\n"
            "OPTIONS\n", msg ? msg : "", n, n);

    while (opts[i].name) {
        apr_file_printf(out, "%s\n\n", opts[i].description);
        i++;
    }

    apr_file_printf(out,
            "RETURN VALUE\n"
            "  The connectdump daemon returns a non zero exit code on error.\n"
            "\n"
            "AUTHOR\n"
            "  Graham Leggett <minfrin@sharp.fm>\n");

    return code;
}

static int version(apr_file_t *out)
{
    apr_file_printf(out, PACKAGE_STRING "\n");

    return 0;
}

static int abortfunc(int retcode)
{
    fprintf(stderr, "Out of memory.\n");

    return retcode;
}

static char *connectcap_strqtok(char *str, const char *sep, char **last)
{
    char *token;
    apr_size_t rewind = 0;
    char c, q = 0, s = 0;

    if (!str) {         /* subsequent call */
        str = *last;    /* start where we left off */
    }

    /* skip characters in sep (will terminate at '\0') */
    while (*str && strchr(sep, *str)) {
        ++str;
    }

    if (!*str) {        /* no more tokens */
        return NULL;
    }

    token = str;

    /* skip quoted sections */
    while ((c = *str)) {

        if (!q) {
            if ('\'' == c) {
                q = '\'';
                rewind++;
            }
            else if ('\"' == c) {
                q = '\"';
                rewind++;
            }
            else if (strchr(sep, c)) {
                break;
            }
            else if (rewind) {
                str[-rewind] = c;
            }
        }
        else {
            if (!s) {
                if ('\\' == c) {
                    s = c;
                    rewind++;
                }
                else if (!s && q == c) {
                    rewind++;
                    q = 0;
                }
                else if (rewind) {
                    str[-rewind] = c;
                }
            }
            else {
                s = 0;
                if (rewind) {
                    str[-rewind] = c;
                }
            }
        }

        str++;
    }

    if (rewind) {
        str[-rewind] = '\0';
    }

    /* prepare for the next call (will terminate at '\0)
     */
    *last = str;

    if (**last) {
        **last = '\0';
        ++*last;
    }

    return token;
}

static void event_verify(apr_array_header_t *events)
{
    int i;

    for (i = 0; i < events->nelts; i++) {
        event_t *e = APR_ARRAY_IDX(events, i, event_t *);

        switch(e->type) {
        case EVENT_LISTEN:
        case EVENT_REQUEST:
        case EVENT_PUMP:
        case EVENT_CAPTURE:
            break;
        default:
            /* bogus elements */
            assert(0);
        }

    }
}

static int event_remove(apr_array_header_t *events, event_t *event)
{
    event_t **es = (event_t **)events->elts;

    int i, found = 0;

    event_verify(events);

    for (i = 0; i < events->nelts; i++) {
        event_t *e = APR_ARRAY_IDX(events, i, event_t *);
        if (e == event) {
            apr_size_t len = (events->nelts - i - 1) * sizeof(event_t **);
            if (len) {
                memmove(&es[i], &es[i+1], len);
            }
            apr_array_pop(events);
            found = 1;
            break;
        }
    }

    event_verify(events);

    return found;
}

static int event_cmp(const void *a, const void *b)
{
    const event_t *ea = a;
    const event_t *eb = b;

    apr_time_t t1 = (apr_time_t) ea->when;
    apr_time_t t2 = (apr_time_t) eb->when;

    return ((t1 > t2) ? -1 : 1);
}

static void event_reindex(apr_array_header_t *events)
{
    event_verify(events);

    qsort(events->elts, events->nelts, sizeof(event_t *),
          event_cmp);

    event_verify(events);
}

static void event_add(apr_array_header_t *events, event_t *event)
{
    event_t **e = apr_array_push(events);

    *e = event;

    event_reindex(events);

    event_verify(events);
}

static event_t *event_peek(apr_array_header_t *events)
{
    event_verify(events);

    if (events->nelts) {
        return APR_ARRAY_IDX(events, events->nelts - 1, event_t *);
    }
    return NULL;
}

static apr_status_t cleanup_event(void *dummy)
{
    event_t *event = dummy;
    connectdump_t *cd = event->cd;

    if (event->when) {
        assert(event_remove(event->cd->events, event));
    }
    if (event->cd->pollset) {
        apr_pollset_remove(event->cd->pollset, &event->pfd);
    }

    /* break links to other events */
    switch(event->type) {
    case EVENT_NONE: {
        /* we should never cleanup twice */
        assert(0);
        break;
    }
    case EVENT_LISTEN:
        break;
    case EVENT_REQUEST: {
        event_t *pump = event->request.pump;
        if (pump) {
            apr_bucket *b;

            /* request a pump shutdown */
            b = apr_bucket_eos_create(cd->alloc);
            APR_BRIGADE_INSERT_TAIL(pump->pump.obb, b);

            /* swap events from not write to write */
            apr_pollset_remove(pump->cd->pollset, &pump->pfd);
            pump->pfd.reqevents |= APR_POLLOUT;
            apr_pollset_add(pump->cd->pollset, &pump->pfd);

            pump->pump.request = NULL;
        }
        break;
    }
    case EVENT_PUMP: {
        event_t *request = event->pump.request;
        event_t *capture = event->pump.capture;
        if (request) {
            apr_bucket *b;

            b = apr_bucket_eos_create(cd->alloc);
            APR_BRIGADE_INSERT_TAIL(request->request.obb, b);

            /* swap events from not write to write */
            apr_pollset_remove(request->cd->pollset, &request->pfd);
            request->pfd.reqevents |= APR_POLLOUT;
            apr_pollset_add(request->cd->pollset, &request->pfd);

            request->request.pump = NULL;
        }
        if (capture) {

            apr_time_t now;

            if (!capture->cd->shutdown) {

                now = apr_time_now();

                /*
                 * Captures do not have timeouts until we reach this point, at
                 * which we want a single timeout to give the capture enough
                 * time to catch the last details of the pump.
                 */

                /* refresh the timeout */
                capture->when = now + apr_time_from_sec(DEFAULT_CAPTURE_TIMEOUT);
                event_add(capture->cd->events, capture);
            }

            capture->capture.pump = NULL;
        }
        break;
    }
    case EVENT_CAPTURE: {
        event_t *pump = event->capture.pump;
        pcap_t *pcap = event->capture.pcap;
        apr_file_t *eml = event->capture.eml;

        if (eml) {
            apr_time_t now = apr_time_now();

#if 0
            char datebuf[APR_RFC822_DATA_LEN];
#endif
            char datebuf[128];

            apr_rfc822_date(datebuf, now);

            apr_file_printf(event->capture.eml, "End:\t\t\t\t\t%s\n",
                            datebuf);

            if (pcap) {
                struct pcap_stat ps;
                if (!pcap_stats(pcap, &ps)) {

                    apr_file_printf(event->capture.eml, "Packets received:\t\t%d\n",
                            ps.ps_recv);
                    apr_file_printf(event->capture.eml, "Packets dropped:\t\t%d\n",
                            ps.ps_drop);
                    apr_file_printf(event->capture.eml, "Packets dropped by kernel:\t%d\n",
                            ps.ps_ifdrop);

                }

            }

            apr_file_flush(eml);
        }

        if (pump) {
            pump->pump.capture = NULL;
        }
        break;
    }
    }

    memset(event, 0, sizeof(event_t));

    return APR_SUCCESS;
}

static apr_status_t cleanup_pcap(void *dummy)
{
    pcap_t *pcap = dummy;

    pcap_close(pcap);

    return APR_SUCCESS;
}

static apr_status_t cleanup_dumper(void *dummy)
{
    pcap_dumper_t *dumper = dummy;

    pcap_dump_close(dumper);

    return APR_SUCCESS;
}

/**
 * Send an HTTP response.
 *
 * The response consists of a status line, followed by a plain text
 * status message that will be returned to the client.
 */
apr_status_t send_response(event_t *request, const char *line, const char *fmt, ...)
{
    va_list ap;
    apr_status_t status = APR_SUCCESS;

    /* write the response line */
    apr_brigade_puts(request->request.obb, NULL, NULL, "HTTP/1.1 ");
    apr_brigade_puts(request->request.obb, NULL, NULL, line);
    apr_brigade_puts(request->request.obb, NULL, NULL, CRLF);
    if (request->request.authenticate) {
        apr_brigade_puts(request->request.obb, NULL, NULL, "Proxy-Authenticate: ");
        apr_brigade_puts(request->request.obb, NULL, NULL, request->request.authenticate);
        apr_brigade_puts(request->request.obb, NULL, NULL, CRLF);
    }
    apr_brigade_puts(request->request.obb, NULL, NULL, "Connection: close");
    apr_brigade_puts(request->request.obb, NULL, NULL, CRLF CRLF);

    /* write the response if any and end the stream */
    if (fmt) {
        apr_bucket *b;

//        va_start(ap, fmt);
//        status = apr_brigade_vprintf(request->request.obb, NULL, NULL, fmt, ap);
//        va_end(ap);

        b = apr_bucket_eos_create(request->cd->alloc);
        APR_BRIGADE_INSERT_TAIL(request->request.obb, b);
    }

    /* swap events from read to write */
    apr_pollset_remove(request->cd->pollset, &request->pfd);
    request->pfd.reqevents |= APR_POLLOUT;
    apr_pollset_add(request->cd->pollset, &request->pfd);

    return status;
}

apr_status_t do_accept(connectdump_t* cd, event_t *event)
{
    apr_pool_t *pool;
    apr_sockaddr_t *sa;
    apr_socket_t *sd;
    event_t *request;
    apr_bucket_brigade *ibb, *obb, *bb;
    apr_bucket *b;

    apr_time_t now = apr_time_now();
    apr_status_t status;

    apr_pool_create(&pool, event->pool);

    status = apr_socket_accept(&sd, event->listen.sd, pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err, "connectdump[%d]: accept failed, ignoring: %pm\n",
                event->number, &status);
        apr_pool_destroy(pool);
        return status;
    }

    status = apr_socket_addr_get(&sa, APR_REMOTE, sd);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err, "connectdump[%d]: apr_socket_addr_get failed, ignoring: %pm\n",
                event->number, &status);
        apr_pool_destroy(pool);
        return status;
    }

    ibb = apr_brigade_create(pool, cd->alloc);
    obb = apr_brigade_create(pool, cd->alloc);
    bb = apr_brigade_create(pool, cd->alloc);

    request = apr_pcalloc(pool, sizeof(event_t));
    request->cd = cd;
    request->pool = pool;
    request->pfd.p = pool;
    request->pfd.desc_type = APR_POLL_SOCKET;
    request->pfd.desc.s = sd;
    request->pfd.reqevents = APR_POLLIN;
    request->pfd.client_data = request;
    request->number = cd->numbers++;
    request->type = EVENT_REQUEST;
    request->request.sa = sa;
    request->request.sd = sd;
    request->request.ibb = ibb;
    request->request.obb = obb;
    request->request.bb = bb;

    /* until further notice */
    request->request.not_authenticated = "Authorization is required\n";

    apr_pool_cleanup_register(pool, request, cleanup_event,
            apr_pool_cleanup_null);

    b = apr_bucket_socket_create(sd, cd->alloc);

    APR_BRIGADE_INSERT_HEAD(ibb, b);

    request->timestamp = now;
    request->when = now + apr_time_from_sec(DEFAULT_REQUEST_TIMEOUT);
    event_add(cd->events, request);

    apr_pollset_add(cd->pollset, &request->pfd);

    apr_file_printf(cd->err, "connectdump[%d]: accepted connection from %pI\n",
            request->number, sa);

    return APR_SUCCESS;
}

apr_status_t do_capture(connectdump_t* cd, event_t *request, event_t *pump)
{
    apr_pool_t *pool;
    event_t *capture;
    pcap_if_t *devs, *dev;
    const char *name = cd->interface;
    pcap_t *pcap;
    const char *buf;
    struct bpf_program bp;
    char *src, *dst;
    apr_socket_t *sd;
    const char *ename;
    const char *wname;
    pcap_dumper_t *dumper;
    apr_file_t *eml;
    apr_time_t now;

#if 0
    char datebuf[APR_RFC822_DATA_LEN];
#endif
    char datebuf[128];
    char errbuf[PCAP_ERRBUF_SIZE];

    int rc;
    apr_os_sock_t fd;

    apr_status_t status;

    now = apr_time_now();

    apr_pool_create(&pool, cd->pool);

    rc = pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);
    if (rc == -1) {
        apr_file_printf(cd->err,
                "connectdump[%d]: pcap_init failed for '%s:%hu': %s\n",
                request->number,
                request->request.host,
                request->request.port, errbuf);

        send_response(request, "500 Internal Server Error",
                "pcap_init failed for '%s', rejecting request: %s\n",
                request->request.host, errbuf);

        apr_pool_destroy(pool);

        return APR_EGENERAL;
    }

    if (!name) {
        if (pcap_findalldevs(&devs, errbuf)) {
            apr_file_printf(cd->err,
                    "connectdump[%d]: pcap_findalldevs failed for '%s:%hu': %s\n",
                    request->number,
                    request->request.host,
                    request->request.port, errbuf);

            send_response(request, "500 Internal Server Error",
                    "pcap_findalldevs failed for '%s', rejecting request: %s\n",
                    request->request.host, errbuf);

            apr_pool_destroy(pool);

            return APR_EGENERAL;
        }

        for (dev = devs; dev; dev = dev->next) {

            struct pcap_addr *address = dev->addresses;

            apr_file_printf(cd->err,
                    "connectdump[%d]: pcap_findalldevs returned for '%s:%hu': %s\n",
                    request->number,
                    request->request.host,
                    request->request.port, dev->name);

            for (address = dev->addresses; address; address = address->next) {

                struct sockaddr *sa = address->addr;

                if (sa->sa_family == pump->pump.lsa->family) {
                    if (APR_INET == sa->sa_family ) {
                        struct sockaddr_in *in = (struct sockaddr_in *)sa;

                        if (!memcmp(&in->sin_addr, &pump->pump.lsa->sa.sin.sin_addr, sizeof(struct in_addr))) {
                            name = apr_pstrdup(pool, dev->name);
                            break;
                        }

                    }
                    else if (APR_INET6 == sa->sa_family) {
                        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;

                        if (!memcmp(&in6->sin6_addr, &pump->pump.lsa->sa.sin6.sin6_addr, sizeof(struct in6_addr))) {
                            name = apr_pstrdup(pool, dev->name);
                            break;
                        }

                    }
                }

            }

            if (name) {
                break;
            }
        }

        if (name) {
            apr_file_printf(cd->err,
                    "connectdump[%d]: pcap_findalldevs found interface %s for '%s:%hu'\n",
                    request->number,
                    name,
                    request->request.host,
                    request->request.port);
        }
        else {
            apr_file_printf(cd->err,
                    "connectdump[%d]: pcap_findalldevs found no interface matching %pI for '%s:%hu'\n",
                    request->number,
                    pump->pump.lsa,
                    request->request.host,
                    request->request.port);

            send_response(request, "500 Internal Server Error",
                    "pcap_findalldevs found no interface matching %pI for '%s:%hu'\n",
                    pump->pump.lsa,
                    request->request.host,
                    request->request.port);

            apr_pool_destroy(pool);

            return APR_EGENERAL;
        }

        pcap_freealldevs(devs);
    }

    pcap = pcap_create(name, errbuf);
    if (!pcap) {
        apr_file_printf(cd->err,
                "connectdump[%d]: pcap_create failed for '%s:%hu': %s\n",
                request->number,
                request->request.host,
                request->request.port, errbuf);

        send_response(request, "500 Internal Server Error",
                "pcap_create failed for '%s', rejecting request: %s\n",
                request->request.host, errbuf);

        apr_pool_destroy(pool);

        return APR_EGENERAL;
    }

    apr_pool_cleanup_register(pool, pcap, cleanup_pcap,
            apr_pool_cleanup_null);

    pcap_set_snaplen(pcap, DEFAULT_PCAP_SNAPLEN);
    pcap_set_immediate_mode(pcap, 1);

    rc = pcap_activate(pcap);
    if (rc < 0) {
        /* errors */
        apr_file_printf(cd->err,
                "connectdump[%d]: pcap_activate failed for '%s:%hu': %s\n",
                request->number,
                request->request.host,
                request->request.port, pcap_statustostr(rc));

        send_response(request, "500 Internal Server Error",
                "pcap_activate failed for '%s', rejecting request: %s\n",
                request->request.host, pcap_statustostr(rc));

        apr_pool_destroy(pool);

        return APR_EGENERAL;
    }
    else if (rc > 0) {
        /* warnings */
        apr_file_printf(cd->err,
                "connectdump[%d]: pcap_activate warning for '%s:%hu': %s\n",
                request->number,
                request->request.host,
                request->request.port, pcap_statustostr(rc));
    }

    rc = pcap_setnonblock(pcap, 1, errbuf);
    if (rc) {
        apr_file_printf(cd->err,
                "connectdump[%d]: pcap_setnonblock failed for '%s:%hu': %s\n",
                request->number,
                request->request.host,
                request->request.port, errbuf);

        send_response(request, "500 Internal Server Error",
                "pcap_setnonblock failed for '%s', rejecting request: %s\n",
                request->request.host, errbuf);

        apr_pool_destroy(pool);

        return APR_EGENERAL;
    }

    /*
     * Create the filter from our source and destination address.
     */
    apr_sockaddr_ip_get(&src, pump->pump.lsa);
    apr_sockaddr_ip_get(&dst, pump->pump.psa);

    buf = apr_psprintf(pool, "(src %s and src port %d and dst %s and dst port %d) or (dst %s and dst port %d and src %s and src port %d)",
            src, pump->pump.lsa->port, dst, pump->pump.psa->port,
            src, pump->pump.lsa->port, dst, pump->pump.psa->port);

    rc = pcap_compile(pcap, &bp, buf, 0, 0);
    if (rc) {
        apr_file_printf(cd->err,
                "connectdump[%d]: pcap_compile of '%s' failed for '%s:%hu': %s\n",
                request->number,
                buf,
                request->request.host,
                request->request.port, pcap_geterr(pcap));

        send_response(request, "500 Internal Server Error",
                "pcap_compile of '%s' failed for '%s', rejecting request: %s\n",
                buf,
                request->request.host, pcap_geterr(pcap));

        apr_pool_destroy(pool);

        return APR_EGENERAL;
    }

    rc = pcap_setfilter(pcap, &bp);
    pcap_freecode(&bp);
    if (rc) {
        apr_file_printf(cd->err,
                "connectdump[%d]: pcap_setfilter failed for '%s:%hu': %s\n",
                request->number,
                request->request.host,
                request->request.port, pcap_geterr(pcap));

        send_response(request, "500 Internal Server Error",
                "pcap_setfilter failed for '%s', rejecting request: %s\n",
                request->request.host, pcap_geterr(pcap));

        apr_pool_destroy(pool);

        return APR_EGENERAL;
    }

    fd = pcap_get_selectable_fd(pcap);
    if (fd == -1) {
        apr_file_printf(cd->err,
                "connectdump[%d]: pcap_get_selectable_fd failed while capturing '%s' for '%s:%hu'\n",
                request->number,
                name,
                request->request.host,
                request->request.port);

        send_response(request, "500 Internal Server Error",
                "pcap_get_selectable_fd failed while capturing '%s' for '%s', rejecting request\n",
                name,
                request->request.host);

        apr_pool_destroy(pool);

        return APR_EGENERAL;
    }
    sd = NULL;
    apr_os_sock_put(&sd, &fd, pool);

    /*
     * Create the filename for the pcap file.
     *
     * For now, it's the number, the host, port, and pcap.
     */
    wname = apr_psprintf(pool, "%d-%s-%d.pcap",
                request->number, request->request.host,
                request->request.port);

    dumper = pcap_dump_open(pcap, wname);
    if (!dumper) {
        apr_file_printf(cd->err,
                "connectdump[%d]: pcap_dump_open failed opening '%s' for '%s:%hu': %s\n",
                request->number,
                wname,
                request->request.host,
                request->request.port, pcap_geterr(pcap));

        send_response(request, "500 Internal Server Error",
                "pcap_dump_open failed for '%s', rejecting request: %s\n",
                request->request.host, pcap_geterr(pcap));

        apr_pool_destroy(pool);

        return APR_EGENERAL;
    }

    apr_pool_cleanup_register(pool, dumper, cleanup_dumper,
            apr_pool_cleanup_null);

    /*
     * Create the filename for the email file.
     *
     * For now, it's the number, the host, port, and eml.
     */
    ename = apr_psprintf(pool, "%d-%s-%d.eml",
                request->number, request->request.host,
                request->request.port);

    status = apr_file_open(&eml, ename,
            APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE,
            APR_FPROT_OS_DEFAULT, pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err,
                "connectdump[%d]: file create of '%s' failed for '%s:%hu': %pm\n",
                request->number,
                ename,
                request->request.host,
                request->request.port, &status);

        send_response(request, "500 Internal Server Error",
                "file create of '%s' failed for '%s', rejecting request: %pm\n",
                ename,
                request->request.host, &status);

        apr_pool_destroy(pool);

        return status;
    }

    apr_rfc822_date(datebuf, now);

    apr_file_printf(eml, "Start:\t\t\t\t%s\n"
                         "Origin:\t\t\t\t%s:%d\n"
                         "Source:\t\t\t\t%pI\n"
                         "Destination:\t\t\t%pI\n",
                    datebuf, pump->pump.host, pump->pump.port,
                    pump->pump.lsa, pump->pump.psa);


    capture = apr_pcalloc(pool, sizeof(event_t));
    capture->cd = cd;
    capture->pool = pool;
    capture->timestamp = apr_time_now();
    capture->when = 0;
    capture->pfd.p = pool;
    capture->pfd.desc_type = APR_POLL_SOCKET;
    capture->pfd.desc.s = sd;
    /* wait for capture to be ready to read */
    capture->pfd.reqevents = APR_POLLIN;
    capture->pfd.client_data = capture;
    capture->number = request->number;
    capture->type = EVENT_CAPTURE;
//    capture->capture.lsa = lsa;
//    capture->capture.psa = psa;
    capture->capture.sd = sd;
    capture->capture.host = apr_pstrdup(pool, pump->pump.host);
    capture->capture.scope_id = apr_pstrdup(pool, pump->pump.scope_id);
    capture->capture.port = pump->pump.port;
    capture->capture.pcap = pcap;
    capture->capture.dumper = dumper;
    capture->capture.eml = eml;

    capture->capture.pump = pump;
    pump->pump.capture = capture;

    apr_pollset_add(cd->pollset, &capture->pfd);

    apr_pool_cleanup_register(pool, capture, cleanup_event,
            apr_pool_cleanup_null);

    apr_file_printf(cd->err, "connectdump[%d]: capture '%s' started with filter: %s\n",
            pump->number, request->request.host, buf);

    return APR_SUCCESS;
}

apr_status_t do_connect(connectdump_t* cd, event_t *request)
{
    apr_pool_t *pool;
    apr_sockaddr_t *psa, *lsa;
    apr_socket_t *sd;
    apr_bucket_brigade *ibb, *obb;
    apr_bucket *b;
    event_t *pump;

    apr_time_t now = apr_time_now();
    apr_int32_t family;

    apr_status_t status;

    apr_pool_create(&pool, cd->pool);

    /* look up the socket to the other side */

    status = apr_sockaddr_info_get(&psa, request->request.host, cd->family,
            request->request.port, cd->flags, pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err,
                "connectdump[%d]: sockaddr setup failed for '%s:%hu': %pm\n",
                request->number,
                request->request.host,
                request->request.port, &status);

        send_response(request, "502 Bad Gateway",
                "sockaddr failed for '%s', rejecting request: %pm\n",
                request->request.host, &status);

        apr_pool_destroy(pool);

        return status;
    }

    /* we should know now if we want IPv4 or IPv6 - use this to decide the
     * source IP to bind to.
     */

    /* handle ipv4 mapped ipv6 addresses */
    if (psa->family == AF_INET6 &&
        IN6_IS_ADDR_V4MAPPED(&psa->sa.sin6.sin6_addr)) {
        family = APR_INET;
    }
    else {
        family = psa->family;
    }

    switch (family) {
    case APR_INET: {

        status = apr_sockaddr_info_get(&lsa, cd->laddr4, APR_UNSPEC,
                0, 0, pool);
        if (APR_SUCCESS != status) {
            apr_file_printf(cd->err,
                    "connectdump[%d]: source IPv4 '%s' setup failed for '%s:%hu': %pm\n",
                    request->number,
                    cd->laddr4,
                    request->request.host,
                    request->request.port, &status);

            send_response(request, "502 Bad Gateway",
                    "source IPv4 '%s' setup failed for '%s:%hu': %pm\n",
                    cd->laddr4,
                    request->request.host,
                    request->request.port, &status);

            apr_pool_destroy(pool);

            return status;
        }

        break;
    }
    case APR_INET6: {

        status = apr_sockaddr_info_get(&lsa, cd->laddr6, APR_UNSPEC,
                0, 0, pool);
        if (APR_SUCCESS != status) {
            apr_file_printf(cd->err,
                    "connectdump[%d]: source IPv6 '%s' setup failed for '%s:%hu': %pm\n",
                    request->number,
                    cd->laddr6,
                    request->request.host,
                    request->request.port, &status);

            send_response(request, "502 Bad Gateway",
                    "source IPv6 '%s' setup failed for '%s:%hu': %pm\n",
                    cd->laddr6,
                    request->request.host,
                    request->request.port, &status);

            apr_pool_destroy(pool);

            return status;
        }

        break;
    }
    default: {

        apr_file_printf(cd->err,
                "connectdump[%d]: sockaddr family not IPv4 or IPv6 for '%s:%hu'\n",
                request->number, request->request.host,
                request->request.port);

        send_response(request, "502 Bad Gateway",
                "sockaddr family not IPv4 or IPv6 for '%s', rejecting request\n",
                request->request.host);

        apr_pool_destroy(pool);

        return APR_EINVAL;
    }
    }

    status = apr_socket_create(&sd, psa->family,
                                SOCK_STREAM, 0, pool);
    if (status != APR_SUCCESS) {
        apr_file_printf(cd->err,
                "connectdump[%d]: socket create failed for '%s:%hu' (%pI): %pm\n",
                request->number, request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "socket create failed for '%s:%hu' (%pI): %pm\n",
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }

    status = apr_socket_opt_set(sd, APR_SO_SNDBUF, DEFAULT_BUFFER_SIZE);
    if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
        apr_file_printf(cd->err,
                "connectdump[%d]: send buffer size cannot be set for '%s:%hu' (%pI): %pm\n",
                request->number,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "socket create failed for '%s:%hu' (%pI): %pm\n",
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }

    status = apr_socket_opt_set(sd, APR_SO_RCVBUF, DEFAULT_BUFFER_SIZE);
    if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
        apr_file_printf(cd->err,
                "connectdump[%d]: receive buffer size cannot be set for '%s:%hu' (%pI): %pm\n",
                request->number,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "socket create failed for '%s:%hu' (%pI): %pm\n",
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }

    status = apr_socket_opt_set(sd, APR_TCP_NODELAY, 1);
    if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
        apr_file_printf(cd->err,
                "connectdump[%d]: nagle cannot be disabled for '%s:%hu' (%pI): %pm\n",
                request->number,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "socket create failed for '%s:%hu' (%pI): %pm\n",
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }

    status = apr_socket_opt_set(sd, APR_SO_NONBLOCK, 1);
    if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
        apr_file_printf(cd->err,
                "connectdump[%d]: non block cannot be set for '%s:%hu' (%pI): %pm\n",
                request->number,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "non block cannot be set for '%s:%hu' (%pI): %pm\n",
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }

#if 0
    status = apr_socket_opt_set(sd, APR_IPV6_V6ONLY, 1);
    if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
        apr_file_printf(cd->err,
                "connectdump[%d]: ipv6only cannot be set for '%s:%hu' (%pI): %pm\n",
                request->number,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "ipv6only cannot be set for '%s:%hu' (%pI): %pm\n",
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }
#endif

    status = apr_socket_bind(sd, lsa);
    if (status != APR_SUCCESS) {
        apr_file_printf(cd->err,
                "connectdump[%d]: socket bind to %pI failed for '%s:%hu' (%pI): %pm\n",
                request->number,
                lsa,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "connectdump: socket bind to %pI failed for '%s:%hu' (%pI): %pm\n",
                lsa,
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }

    /* repeat the lsa lookup, this gives us the chosen outgoing port */

    status = apr_socket_addr_get(&lsa, APR_LOCAL, sd);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err,
                "connectdump[%d]: get sockaddr failed for '%s:%hu' (%pI): %pm\n",
                request->number,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "connectdump: get sockaddr failed for '%s:%hu' (%pI): %pm\n",
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }

    ibb = apr_brigade_create(pool, cd->alloc);
    obb = apr_brigade_create(pool, cd->alloc);

    pump = apr_pcalloc(pool, sizeof(event_t));
    pump->cd = cd;
    pump->pool = pool;
    pump->pfd.p = pool;
    pump->pfd.desc_type = APR_POLL_SOCKET;
    pump->pfd.desc.s = sd;
    /* wait for pump to be ready to write */
    pump->pfd.reqevents = APR_POLLOUT;
    pump->pfd.client_data = pump;
    pump->number = request->number;
    pump->type = EVENT_PUMP;
    pump->pump.lsa = lsa;
    pump->pump.psa = psa;
    pump->pump.sd = sd;
    pump->pump.host = apr_pstrdup(pool, request->request.host);
    pump->pump.scope_id = apr_pstrdup(pool, request->request.scope_id);
    pump->pump.port = request->request.port;
    pump->pump.ibb = ibb;
    pump->pump.obb = obb;

    pump->pump.request = request;
    request->request.pump = pump;

    b = apr_bucket_socket_create(sd, cd->alloc);

    APR_BRIGADE_INSERT_HEAD(ibb, b);

    pump->timestamp = now;
    pump->when = now + apr_time_from_sec(DEFAULT_PUMP_TIMEOUT);
    event_add(cd->events, pump);

//    apr_file_printf(cd->err, "connectdump[%d]: skiplist size: %" APR_SIZE_T_FMT " event %pp (before add)\n",
//            pump->number, apr_skiplist_size(cd->events), pump);
//    assert(apr_skiplist_add(cd->events, pump));
//    apr_file_printf(cd->err, "connectdump[%d]: skiplist size: %" APR_SIZE_T_FMT " event %pp (after add)\n",
//            pump->number, apr_skiplist_size(cd->events), pump);

    apr_pollset_add(cd->pollset, &pump->pfd);

    apr_pool_cleanup_register(pool, pump, cleanup_event,
            apr_pool_cleanup_null);

    /* To bootstrap the pump/request pair, we set to start
     * by waiting for both sides to be ready to write.
     *
     * As soon as a side is ready to write, the write
     * events are triggered, at which point both sides are
     * marked ready to read.
     *
     * As soon as we read something, we then mark the other
     * side ready to write, and so on.
     */

    /* wait for request to be ready to write */
    apr_pollset_remove(request->cd->pollset, &request->pfd);
    request->pfd.reqevents = APR_POLLOUT;
    apr_pollset_add(request->cd->pollset, &request->pfd);

    /*
     * At this point we know the source IP and port, and the
     * destination IP and port, start capturing traffic before
     * the connect generates the first traffic.
     */
#if 1
    status = do_capture(cd, request, pump);
    if (status != APR_SUCCESS) {
        /* error is already handled */

        apr_pool_destroy(pool);

        return status;
    }
#endif
    status = apr_socket_connect(sd, psa);
    if (status != APR_EINPROGRESS) {
        apr_file_printf(cd->err,
                "connectdump[%d]: socket connect failed for '%s:%hu' (%pI): %pm\n",
                request->number,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "connectdump: socket bind to %pI failed for '%s:%hu' (%pI): %pm\n",
                lsa,
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }

    /* phew, so many steps, time to shift some data */

    apr_file_printf(cd->err, "connectdump[%d]: '%s' connecting to %pI from %pI\n",
            pump->number, request->request.host, psa, lsa);

    send_response(request, "200 Let's Gooooooo", NULL);

    return APR_SUCCESS;
}

apr_status_t do_authenticate(connectdump_t* cd, event_t *request)
{
    char *nonce = apr_palloc(request->pool, NONCE_LEN+1);
    time_rec t;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx;

    t.time = request->timestamp;

    apr_base64_encode_binary(nonce, t.arr, sizeof(t.arr));

    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, cd->sha256, NULL);
    EVP_DigestUpdate(mdctx, cd->realm, strlen(cd->realm));
    EVP_DigestUpdate(mdctx, t.arr, sizeof(t.arr));
//    EVP_DigestUpdate(mdctx, opaque, strlen(opaque));
    EVP_DigestFinal_ex(mdctx, digest, NULL);

    apr_encode_base16_binary(nonce+NONCE_TIME_LEN, digest, sizeof(digest), APR_ENCODE_NONE, NULL);

    request->request.authenticate = apr_psprintf(request->pool, "Digest "
            "realm=\"%s\","
            "qop=\"auth\","
            "algorithm=SHA-256,"
            "nonce=\"%s\","
            "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\","
            "userhash=true", cd->realm, nonce);

    apr_file_printf(cd->err,
            "connectdump[%d]: authenticate: %s\n",
            request->number, request->request.authenticate);

    return APR_SUCCESS;
}

apr_status_t do_request_header(connectdump_t* cd, event_t *request, char *buf)
{
    char *tok_state;

    char *header, *scheme, *kv;

    const char *username = NULL;
    const char *realm = NULL;
    const char *uri = NULL;
    const char *algorithm = NULL;
    const char *nonce = NULL;
    const char *nc = NULL;
    const char *cnonce = NULL;
    const char *qop = NULL;
    const char *response = NULL;
    const char *opaque = NULL;
    const char *userhash = NULL;

    /* look for Proxy-Authorization, ignore everything else */
    header = apr_strtok(buf, " ", &tok_state);
    if (strcasecmp(header, "Proxy-Authorization:")) {
        /* ignore everything else */
        return APR_SUCCESS;
    }

    /* look for DIGEST, ignore everything else */
    scheme = apr_strtok(NULL, " ", &tok_state);
    if (strcasecmp(scheme, "DIGEST")) {
        /* ignore everything else */
        return APR_SUCCESS;
    }

    while ((kv = connectcap_strqtok(NULL, ", ", &tok_state))) {
        char *kv_state;

        char *key, *value;

        key = apr_strtok(kv, "=", &kv_state);
        value = connectcap_strqtok(NULL, "=", &kv_state);

        if (!key || !value) {
            break;
        }

        if (!strcmp(key, "username")) {
            username = value;
        }
        else if (!strcmp(key, "realm")) {
            realm = value;
        }
        else if (!strcmp(key, "uri")) {
            uri = value;
        }
        else if (!strcmp(key, "algorithm")) {
            algorithm = value;
        }
        else if (!strcmp(key, "nonce")) {
            nonce = value;
        }
        else if (!strcmp(key, "nc")) {
            nc = value;
        }
        else if (!strcmp(key, "cnonce")) {
            cnonce = value;
        }
        else if (!strcmp(key, "qop")) {
            qop = value;
        }
        else if (!strcmp(key, "response")) {
            response = value;
        }
        else if (!strcmp(key, "opaque")) {
            opaque = value;
        }
        else if (!strcmp(key, "userhash")) {
            userhash = value;
        }
    }

    if (!username) {
        apr_file_printf(cd->err,
                "connectdump[%d]: browser %pI: username is missing, auth denied\n",
                request->number, request->request.sa);

        request->request.not_authenticated = "Username is missing\n";
        return APR_SUCCESS;
    }

    /* realm must match */
    if (!realm || strcmp(cd->realm, realm)) {
        apr_file_printf(cd->err,
                "connectdump[%d]: browser %pI: realm '%s' does not match '%s', auth denied\n",
                request->number, request->request.sa, realm, cd->realm);

        request->request.not_authenticated = "Realm does not match\n";
        return APR_SUCCESS;
    }

    /* uri must match address */
    if (!uri || strcmp(request->request.address, uri)) {
        apr_file_printf(cd->err,
                "connectdump[%d]: browser %pI: uri '%s' does not match '%s', auth denied\n",
                request->number, request->request.sa, uri, request->request.address);

        request->request.not_authenticated = "URI does not match\n";
        return APR_SUCCESS;
    }

    /* algorithm must be SHA-256 */
    if (!algorithm || strcmp("SHA-256", algorithm)) {
        apr_file_printf(cd->err,
                "connectdump[%d]: browser %pI: algorithm '%s' does not match 'SHA-256', auth denied\n",
                request->number, request->request.sa, algorithm);

        request->request.not_authenticated = "Algorithm is not 'SHA-256'\n";
        return APR_SUCCESS;
    }

    /* nonce must be present */
    if (!nonce) {
        apr_file_printf(cd->err,
                "connectdump[%d]: browser %pI: nonce is missing, auth denied\n",
                request->number, request->request.sa);

        request->request.not_authenticated = "Nonce is missing\n";
        return APR_SUCCESS;
    }

    // fixme check nonce

    /* nonce count must be present */
    if (!nc) {
        apr_file_printf(cd->err,
                "connectdump[%d]: browser %pI: nc is missing, auth denied\n",
                request->number, request->request.sa);

        request->request.not_authenticated = "Nonce count is missing\n";
        return APR_SUCCESS;
    }

    // fixme: implement nonce count

    /* cnonce must be present */
    if (!cnonce) {
        apr_file_printf(cd->err,
                "connectdump[%d]: browser %pI: cnonce is missing, auth denied\n",
                request->number, request->request.sa);

        request->request.not_authenticated = "Client nonce is missing\n";
        return APR_SUCCESS;
    }

    /* qop must be auth */
    if (!qop || strcmp("auth", qop)) {
        apr_file_printf(cd->err,
                "connectdump[%d]: browser %pI: qop '%s' does not match 'auth', auth denied\n",
                request->number, request->request.sa, qop);

        request->request.not_authenticated = "QOP is not 'auth'\n";
        return APR_SUCCESS;
    }

    /* response must be present */
    if (!response) {
        apr_file_printf(cd->err,
                "connectdump[%d]: browser %pI: response is missing, auth denied\n",
                request->number, request->request.sa);

        request->request.not_authenticated = "Response is missing\n";
        return APR_SUCCESS;
    }

    // fixme opaque is optional

    /* userhash is optional, but must be well formed */
    if (!userhash) {
        /* optional value */
        request->request.userhash = 0;
    }
    else if (!strcmp(userhash, "false")) {
        request->request.userhash = 0;
    }
    else if (!strcmp(userhash, "true")) {
        request->request.userhash = 1;
    }
    else {
        apr_file_printf(cd->err,
                "connectdump[%d]: browser %pI: userhash '%s' not recognised, auth denied\n",
                request->number, request->request.sa, userhash);

        request->request.not_authenticated = "Userhash not recognised\n";
        return APR_SUCCESS;
    }

    // fixme check username

    // fixme hard wired to accept auth
    request->request.not_authenticated = NULL;

    return APR_SUCCESS;
}

apr_status_t do_request_write(connectdump_t* cd, event_t *request)
{
    apr_bucket_brigade *obb;
    apr_bucket *b;

    event_t *pump = request->request.pump;

    const char *data;
    apr_size_t length;

    apr_status_t status = APR_SUCCESS;

    obb = request->request.obb;

    while (((b = APR_BRIGADE_FIRST(obb)) != APR_BRIGADE_SENTINEL(obb))) {

        if (APR_BUCKET_IS_EOS(b)) {

            /* once we reach here, we have finished writing to the client
             * and can close up this connection.
             */
            apr_file_printf(cd->err,
                    "connectdump[%d]: sending shutdown to browser %pI\n",
                    request->number, request->request.sa);

            /* swap events from write to not write */
            apr_pollset_remove(request->cd->pollset, &request->pfd);
            request->pfd.reqevents &= ~APR_POLLOUT;
            apr_pollset_add(request->cd->pollset, &request->pfd);

            /* lingering close, we will wait for other side to close */
            apr_socket_shutdown(request->request.sd, APR_SHUTDOWN_WRITE);

            apr_bucket_delete(b);

            /* our request is finally done, destroy the request */
            apr_pool_destroy(request->pool);

            return APR_SUCCESS;
        }

        /* we are reading heap buckets here, by definition we will never block */
        status = apr_bucket_read(b, &data, &length, APR_BLOCK_READ);

        /* heap buckets should always succeed */
        assert(APR_SUCCESS == status);

        if (length) {

            apr_size_t requested = length;

            status = apr_socket_send(request->request.sd, data, &length);

            if (APR_STATUS_IS_EAGAIN(status)) {
                /* poll again */
                return status;
            }
            else if (APR_SUCCESS != status) {
                /* write attempt failed, give up */
                apr_file_printf(cd->err,
                        "connectdump[%d]: write failed to %pI, closing: %pm\n",
                        request->number, request->request.sa, &status);

                apr_pool_destroy(request->pool);
                return status;
            }

            if (requested > length) {
                apr_bucket_split(b, length);
            }

        }

        apr_bucket_delete(b);
    }

    /* If we reach here, we have nothing more to write. Switch
     * write off and read on, let's go fetch some more data.
     */

    if (pump) {

        /* swap events from write to not write */
        apr_pollset_remove(request->cd->pollset, &request->pfd);
        request->pfd.reqevents &= ~APR_POLLOUT;
        apr_pollset_add(request->cd->pollset, &request->pfd);

        /* swap events from not read to read */
        apr_pollset_remove(pump->cd->pollset, &pump->pfd);
        pump->pfd.reqevents |= APR_POLLIN;
        apr_pollset_add(pump->cd->pollset, &pump->pfd);

    }

    return APR_SUCCESS;
}

apr_status_t do_request_read(connectdump_t* cd, event_t *request)
{
    apr_bucket_brigade *ibb, *bb;

    event_t *pump = request->request.pump;

    apr_status_t status = APR_SUCCESS;

    ibb = request->request.ibb;
    bb = request->request.bb;

    /* are we pumping data? */
    if (pump) {

        apr_bucket *b;
        const char *data;
        apr_size_t length;

        b = APR_BRIGADE_FIRST(ibb);

        if (APR_BRIGADE_SENTINEL(ibb) == b) {
            /* client hung up early, tear everything down */
            apr_file_printf(cd->err,
                    "connectdump[%d]: no more to read from %pI\n",
                    request->number, request->request.sa);

            apr_pool_destroy(request->pool);
            return status;
        }

        /* read exactly once */
        status = apr_bucket_read(b, &data, &length, APR_NONBLOCK_READ);

        if (APR_SUCCESS == status) {
            /* pass across to the pump */
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(pump->pump.obb, b);

            apr_file_printf(cd->err, "connectdump[%d]: '%s' read %" APR_SIZE_T_FMT " bytes from %pI\n",
                    pump->number, request->request.host, length, request->request.sa);

            /* swap events from read to not read */
            apr_pollset_remove(request->cd->pollset, &request->pfd);
            request->pfd.reqevents &= ~APR_POLLIN;
            apr_pollset_add(request->cd->pollset, &request->pfd);

            /* swap events from not write to write */
            apr_pollset_remove(pump->cd->pollset, &pump->pfd);
            pump->pfd.reqevents |= APR_POLLOUT;
            apr_pollset_add(pump->cd->pollset, &pump->pfd);

            return status;
        }
        else if (APR_STATUS_IS_EAGAIN(status)) {
            /* we need to poll for more data */
            return status;
        }
        else if (APR_STATUS_IS_EOF(status)) {

            /* client hung up early, tear everything down */
            apr_file_printf(cd->err,
                    "connectdump[%d]: connection closed unexpectedly from %pI\n",
                    request->number, request->request.sa);

            apr_pool_destroy(request->pool);
            return status;
        }
        else {

            /* read failed, tear everything down */
            apr_file_printf(cd->err,
                    "connectdump[%d]: error reading from %pI: %pm\n",
                    request->number, request->request.sa, &status);

            apr_pool_destroy(request->pool);
            return status;
        }

    }

    /* are we handling a connect request? */
    while (!pump && APR_SUCCESS == status) {

        status = apr_brigade_split_line(bb, ibb, APR_NONBLOCK_READ,
                        HUGE_STRING_LEN);

        if (APR_SUCCESS == status) {

            char buf[HUGE_STRING_LEN];
            apr_size_t size = HUGE_STRING_LEN;

            apr_brigade_flatten(bb, buf, &size);

            /* strip trailing APR_ASCII_LF */
            if (size && buf[size - 1] == APR_ASCII_LF) {
                size--;
            }
            if (size && buf[size - 1] == APR_ASCII_CR) {
                size--;
            }
            buf[size] = 0;

            apr_brigade_cleanup(bb);

            /* empty line and no host yet */
            if (!size && !request->request.host) {

                /* client hung up early, tear everything down */
                apr_file_printf(cd->err,
                        "connectdump[%d]: connection closed unexpectedly from %pI\n",
                        request->number, request->request.sa);

                apr_pool_destroy(request->pool);

                break;
            }

            /* empty line and not yet authenticated */
            else if (!size && request->request.not_authenticated) {
                apr_file_printf(cd->err,
                        "connectdump[%d]: unauthenticated request from %pI\n",
                        request->number, request->request.sa);

                do_authenticate(cd, request);

                send_response(request, "407 Proxy Authentication Required", request->request.not_authenticated);

                break;
            }

            /* empty line, are our headers done? */
            else if (!size) {

                apr_file_printf(cd->err,
                        "connectdump[%d]: end of headers from %pI, starting pump\n",
                        request->number, request->request.sa);

#if 1
                do_connect(cd, request);
#endif

                break;
            }

            /* line is too long - reject the request */
            else if (size >= HUGE_STRING_LEN) {

                apr_file_printf(cd->err,
                        "connectdump[%d]: line too long from %pI\n",
                        request->number, request->request.sa);

                send_response(request, "414 URI Too Long", "Request line is too long, rejecting request.\n");

                break;
            }

            /* not too long, not too short, just right */
            else if (!request->request.host) {

                char *tok_state;

                const char *method = apr_strtok(buf, " ", &tok_state);
                const char *address = apr_strtok(NULL, " ", &tok_state);
                const char *version = apr_strtok(NULL, " ", &tok_state);

                if (!version) {
                    apr_file_printf(cd->err,
                            "connectdump[%d]: version not specified from %pI\n",
                            request->number, request->request.sa);

                    send_response(request, "400 Bad Request", "Request line did not carry a version, rejecting request.\n");

                    break;
                }

                else if (!address) {
                    apr_file_printf(cd->err,
                            "connectdump[%d]: address not specified from %pI\n",
                            request->number, request->request.sa);

                    send_response(request, "400 Bad Request", "Request line did not carry an address, rejecting request.\n");

                    break;
                }

                else if (strcmp(method, "CONNECT")) {
                    apr_file_printf(cd->err,
                            "connectdump[%d]: method %s not allowed from %pI\n",
                            request->number, method, request->request.sa);

                    send_response(request, "405 Method Not Allowed", "This proxy supports the CONNECT method only, rejecting request.\n");

                    break;
                }

                request->request.address = apr_pstrdup(request->pool, address);

                /* request line */
                status = apr_parse_addr_port(&request->request.host,
                        &request->request.scope_id, &request->request.port,
                        address, request->pool);
                if (status != APR_SUCCESS) {
                    apr_file_printf(cd->err,
                            "connectdump[%d]: cannot parse '%s' from %pI: %pm\n",
                            request->number, address, request->request.sa, &status);

                    send_response(request, "400 Bad Request", "Address '%s' could not be parsed, rejecting request.\n", address);

                    break;
                }

                if (!request->request.port) {
                    apr_file_printf(cd->err,
                            "connectdump[%d]: port not specified from %pI\n",
                            request->number, request->request.sa);

                    send_response(request, "400 Bad Request", "Address '%s' requires a port be specified explicitly, rejecting request.\n", address);

                    break;
                }

                apr_file_printf(cd->err,
                        "connectdump[%d]: '%s' to '%s' received from %pI\n",
                        request->number, method, address, request->request.sa);

            }
            else {
                /* header line */

                apr_file_printf(cd->err,
                        "connectdump[%d]: header line '%s' received from %pI\n",
                        request->number, buf, request->request.sa);

                status = do_request_header(cd, request, buf);
                if (APR_SUCCESS != status) {

                    /* error is already handled */
                    break;
                }
            }

        }
        else if (APR_STATUS_IS_EAGAIN(status)) {
            /* we need to poll for more data */
            break;
        }
        else if (APR_STATUS_IS_EOF(status)) {

            /* client hung up early, tear everything down */
            apr_file_printf(cd->err,
                    "connectdump[%d]: connection closed unexpectedly from %pI\n",
                    request->number, request->request.sa);

            apr_pool_destroy(request->pool);
            break;
        }
        else {

            /* read failed, tear everything down */
            apr_file_printf(cd->err,
                    "connectdump[%d]: error reading from %pI: %pm\n",
                    request->number, request->request.sa, &status);

            apr_pool_destroy(request->pool);
            break;
        }

    }

    return status;
}

apr_status_t do_request_hangup(connectdump_t* cd, event_t *request)
{
    event_t *pump = request->request.pump;

    apr_bucket *b;

    apr_socket_shutdown(request->request.sd, APR_SHUTDOWN_READ);

    /* are we pumping data? */
    if (pump) {

        b = apr_bucket_eos_create(cd->alloc);
        APR_BRIGADE_INSERT_TAIL(pump->pump.obb, b);

        /* swap events from not write to write */
        apr_pollset_remove(pump->cd->pollset, &pump->pfd);
        pump->pfd.reqevents |= APR_POLLOUT;
        apr_pollset_add(pump->cd->pollset, &pump->pfd);

    }

    /* client hung up early, tear everything down */
    apr_file_printf(cd->err,
            "connectdump[%d]: browser %pI closed connection\n",
            request->number, request->request.sa);

    apr_pool_destroy(request->pool);

    return APR_SUCCESS;
}

apr_status_t do_pump_write(connectdump_t* cd, event_t *pump)
{
    apr_bucket_brigade *obb;
    apr_bucket *b;

    event_t *request = pump->pump.request;

    const char *data;
    apr_size_t length;

    apr_status_t status = APR_SUCCESS;

    obb = pump->pump.obb;

    while (((b = APR_BRIGADE_FIRST(obb)) != APR_BRIGADE_SENTINEL(obb))) {

        if (APR_BUCKET_IS_EOS(b)) {

            /* once we reach here, we have finished writing to the client
             * and can close up this connection.
             */
            apr_file_printf(cd->err,
                    "connectdump[%d]: sending shutdown to origin %pI\n",
                    pump->number, pump->pump.psa);

            /* swap events from write to not write */
            apr_pollset_remove(pump->cd->pollset, &pump->pfd);
            pump->pfd.reqevents &= ~APR_POLLOUT;
            apr_pollset_add(pump->cd->pollset, &pump->pfd);

            /* lingering close, we will wait for other side to close */
            apr_socket_shutdown(pump->pump.sd, APR_SHUTDOWN_WRITE);

            apr_bucket_delete(b);

            return APR_SUCCESS;
        }

        status = apr_bucket_read(b, &data, &length, APR_BLOCK_READ);

        /* heap buckets should always succeed */
        assert(APR_SUCCESS == status);

        if (length) {

            apr_size_t requested = length;

            status = apr_socket_send(pump->pump.sd, data, &length);

            if (APR_STATUS_IS_EAGAIN(status)) {
                /* poll again */
                return status;
            }
            else if (APR_SUCCESS != status) {

                /* write attempt failed, give up */
                apr_file_printf(cd->err,
                        "connectdump[%d]: origin %pI write %" APR_SIZE_T_FMT " bytes failed: %pm\n",
                        pump->number, pump->pump.psa, length, &status);

                b = apr_bucket_eos_create(cd->alloc);
                APR_BRIGADE_INSERT_TAIL(request->request.obb, b);

                /* swap events from not write to write */
                apr_pollset_remove(request->cd->pollset, &request->pfd);
                request->pfd.reqevents |= APR_POLLOUT;
                apr_pollset_add(request->cd->pollset, &request->pfd);

                apr_bucket_delete(b);

                apr_pool_destroy(pump->pool);

                return status;
            }
            else {

                apr_file_printf(cd->err, "connectdump[%d]: '%s' write %" APR_SIZE_T_FMT " bytes to origin %pI\n",
                        pump->number, pump->pump.host, length, pump->pump.psa);

            }

            if (requested > length) {
                apr_bucket_split(b, length);
            }

        }

        apr_bucket_delete(b);
    }

    /* If we reach here, we have nothing more to write. Switch
     * write off and read on, let's go fetch some more data.
     */

    if (request) {

        /* swap events from write to not write */
        apr_pollset_remove(pump->cd->pollset, &pump->pfd);
        pump->pfd.reqevents &= ~APR_POLLOUT;
        apr_pollset_add(pump->cd->pollset, &pump->pfd);

        /* swap events from not read to read */
        apr_pollset_remove(request->cd->pollset, &request->pfd);
        request->pfd.reqevents |= APR_POLLIN;
        apr_pollset_add(request->cd->pollset, &request->pfd);

    }

    return APR_SUCCESS;
}

apr_status_t do_pump_read(connectdump_t* cd, event_t *pump)
{
    apr_bucket_brigade *ibb;

    event_t *request = pump->pump.request;

    apr_status_t status = APR_SUCCESS;

    ibb = pump->pump.ibb;

    /* are we pumping data? */
    if (request) {

        apr_bucket *b;
        const char *data;
        apr_size_t length;

        b = APR_BRIGADE_FIRST(ibb);

        if (APR_BRIGADE_SENTINEL(ibb) == b) {
            /* origin hung up early, tear everything down */
            apr_file_printf(cd->err,
                    "connectdump[%d]: no more to read from %pI\n",
                    pump->number, pump->pump.psa);

            b = apr_bucket_eos_create(cd->alloc);
            APR_BRIGADE_INSERT_TAIL(request->request.obb, b);

            /* swap events from not write to write */
            apr_pollset_remove(request->cd->pollset, &request->pfd);
            request->pfd.reqevents |= APR_POLLOUT;
            apr_pollset_add(request->cd->pollset, &request->pfd);

            apr_pool_destroy(pump->pool);

            return status;
        }

        /* read exactly once */
        status = apr_bucket_read(b, &data, &length, APR_NONBLOCK_READ);

        if (APR_SUCCESS == status) {
            /* pass across to the pump */
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(request->request.obb, b);

            /* swap events from read to not read */
            apr_pollset_remove(pump->cd->pollset, &pump->pfd);
            pump->pfd.reqevents &= ~APR_POLLIN;
            apr_pollset_add(pump->cd->pollset, &pump->pfd);

            /* swap events from not write to write */
            apr_pollset_remove(request->cd->pollset, &request->pfd);
            request->pfd.reqevents |= APR_POLLOUT;
            apr_pollset_add(request->cd->pollset, &request->pfd);

            apr_file_printf(cd->err, "connectdump[%d]: '%s' read %" APR_SIZE_T_FMT " bytes from origin %pI\n",
                    pump->number, pump->pump.host, length, pump->pump.psa);

            return status;
        }
        else if (APR_STATUS_IS_EAGAIN(status)) {
            /* we need to poll for more data */
            return status;
        }
        else if (APR_STATUS_IS_EOF(status)) {

            /* origin hung up early, tear everything down */
            apr_file_printf(cd->err,
                    "connectdump[%d]: origin %pI received eof\n",
                    pump->number, pump->pump.psa);

            b = apr_bucket_eos_create(cd->alloc);
            APR_BRIGADE_INSERT_TAIL(request->request.obb, b);

            /* swap events from not write to write */
            apr_pollset_remove(request->cd->pollset, &request->pfd);
            request->pfd.reqevents |= APR_POLLOUT;
            apr_pollset_add(request->cd->pollset, &request->pfd);

            apr_pool_destroy(pump->pool);

            return status;
        }
        else {

            /* read failed, tear everything down */
            apr_file_printf(cd->err,
                    "connectdump[%d]: origin %pI read error: %pm\n",
                    pump->number, pump->pump.psa, &status);

            b = apr_bucket_eos_create(cd->alloc);
            APR_BRIGADE_INSERT_TAIL(request->request.obb, b);

            /* swap events from not write to write */
            apr_pollset_remove(request->cd->pollset, &request->pfd);
            request->pfd.reqevents |= APR_POLLOUT;
            apr_pollset_add(request->cd->pollset, &request->pfd);

            apr_pool_destroy(pump->pool);

            return status;
        }

    }

    return APR_SUCCESS;
}

apr_status_t do_pump_hangup(connectdump_t* cd, event_t *pump)
{
    event_t *request = pump->pump.request;

    apr_bucket *b;

    apr_socket_shutdown(pump->pump.sd, APR_SHUTDOWN_READ);

    /* is our request still alive? */
    if (request) {

        b = apr_bucket_eos_create(cd->alloc);
        APR_BRIGADE_INSERT_TAIL(request->request.obb, b);

        /* swap events from not write to write */
        apr_pollset_remove(request->cd->pollset, &request->pfd);
        request->pfd.reqevents |= APR_POLLOUT;
        apr_pollset_add(request->cd->pollset, &request->pfd);

    }

    /* client hung up early, tear everything down */
    apr_file_printf(cd->err,
            "connectdump[%d]: origin %pI closed connection\n",
            pump->number, pump->pump.psa);

    apr_pool_destroy(pump->pool);

    return APR_SUCCESS;
}

apr_status_t do_capture_read(connectdump_t* cd, event_t *capture)
{
    struct pcap_pkthdr *pkt_header = NULL;
    const u_char *pkt_data = NULL;

    int rc;

    rc = pcap_next_ex(capture->capture.pcap,
            &pkt_header, &pkt_data);
    if (PCAP_ERROR == rc) {
        apr_file_printf(cd->err,
                "connectdump[%d]: capture error: %s\n",
                capture->number, pcap_geterr(capture->capture.pcap));

        apr_pool_destroy(capture->pool);

        return APR_EGENERAL;
    }

    pcap_dump((u_char *)capture->capture.dumper, pkt_header, pkt_data);
    rc = pcap_dump_flush(capture->capture.dumper);
    if (PCAP_ERROR == rc) {
        apr_file_printf(cd->err,
                "connectdump[%d]: capture save error, giving up capture\n",
                capture->number);

        apr_pool_destroy(capture->pool);

        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

apr_status_t do_capture_hangup(connectdump_t* cd, event_t *capture)
{
    apr_file_printf(cd->err,
            "connectdump[%d]: capture error: %s\n",
            capture->number, pcap_geterr(capture->capture.pcap));

    apr_pool_destroy(capture->pool);

    return APR_EGENERAL;
}

int do_poll(connectdump_t* cd)
{
    apr_status_t status;
    int i;

    while (!cd->shutdown) {

        event_t *event;
        const apr_pollfd_t *out_pfd;
        apr_time_t now;
        apr_interval_time_t timeout = -1;
        apr_int32_t num = 0;

//        apr_skiplistnode *n;

        event_verify(cd->events);

#if 0
        /* how to iterate a skiplist */
        apr_file_printf(cd->err, "*********** skiplist %d entries: ", cd->events->nelts);
//        for (n = apr_skiplist_getlist(cd->events); n; apr_skiplist_next(cd->events, &n)) {
//            event_t *event = apr_skiplist_element(n);

        for (i = 0; i < cd->events->nelts; i++) {
            event_t *event = APR_ARRAY_IDX(cd->events, i, event_t *);

        // fixme

            switch (event->type) {
            case EVENT_NONE: {
                apr_file_printf(cd->err, "***%d(%pp) ",
                        event->number, event);
                assert(0);

                break;
            }
            case EVENT_LISTEN: {
                apr_file_printf(cd->err, "L%d(%pp) ",
                        event->number, event);

                break;
            }
            case EVENT_REQUEST: {

                apr_file_printf(cd->err, "R%d(%pp) ",
                        event->number, event);

                break;
            }
            case EVENT_PUMP: {

                apr_file_printf(cd->err, "P%d(%pp) ",
                        event->number, event);

                break;
            }
            case EVENT_CAPTURE: {

                apr_file_printf(cd->err, "C%d(%pp) ",
                        event->number, event);

                break;
            }
            }

        }
        apr_file_printf(cd->err, "\n");
#endif

        now = apr_time_now();

        /* calculate the timeout, if any */
        while ((event = event_peek(cd->events))) {
            if (event->when < now) {

                /* timed out, let's clean up */
                switch (event->type) {
                case EVENT_NONE: {
                    /* we should never poll on a cleaned up event */
                    assert(0);

                    break;
                }
                case EVENT_LISTEN: {
                    /* listen should never have a timeout */
                    assert(0);

                    break;
                }
                case EVENT_REQUEST: {

                    apr_file_printf(cd->err,
                            "connectdump[%d]: browser %pI timed out\n",
                            event->number, event->request.sa);

                    apr_pool_destroy(event->pool);

                    break;
                }
                case EVENT_PUMP: {

                    apr_file_printf(cd->err,
                            "connectdump[%d]: origin %pI timed out\n",
                            event->number, event->pump.psa);

                    apr_pool_destroy(event->pool);

                    break;
                }
                case EVENT_CAPTURE: {

                    apr_file_printf(cd->err,
                            "connectdump[%d]: capture %s:%d finialised after pump shutdown\n",
                            event->number, event->capture.host, event->capture.port);

                    apr_pool_destroy(event->pool);

                    break;
                }
                }

            }
            else {
                timeout = event->when - now;
                break;
            }
        }

        /* let's poll for that data */
        status = apr_pollset_poll(cd->pollset, timeout, &num, &out_pfd);

        /* were we interrupted? */
        if (APR_STATUS_IS_EINTR(status)) {
            continue;
        }

        /* did we time out? */
        else if (APR_STATUS_IS_TIMEUP(status)) {
            continue;
        }

        /* did we get signalled for data? */
        else if (APR_SUCCESS == status) {

            const apr_pollfd_t *pollfd;

            for (i = 0, pollfd = out_pfd; i < num; i++, pollfd++) {

                event = pollfd->client_data;

                switch (event->type) {
                case EVENT_NONE: {
                    /* we should never poll on a cleaned up event */
                    assert(0);

                    break;
                }
                case EVENT_LISTEN: {

                    do_accept(cd, event);

                    break;
                }
                case EVENT_REQUEST: {

                    /* refresh the timeout */
                    event->when = now + apr_time_from_sec(DEFAULT_REQUEST_TIMEOUT);

                    event_reindex(cd->events);

                    if (pollfd->rtnevents & (APR_POLLHUP)) {
                        do_request_hangup(cd, event);
                        continue;
                    }

                    if (pollfd->rtnevents & (APR_POLLOUT)) {
                        do_request_write(cd, event);
                        continue;
                    }

                    if (pollfd->rtnevents & (APR_POLLIN)) {
                        do_request_read(cd, event);
                        continue;
                    }

                    break;
                }
                case EVENT_PUMP: {

                    /* refresh the timeout */
                    event->when = now + apr_time_from_sec(DEFAULT_PUMP_TIMEOUT);

                    event_reindex(cd->events);

                    if (pollfd->rtnevents & (APR_POLLHUP)) {
                        do_pump_hangup(cd, event);
                        continue;
                    }

                    if (pollfd->rtnevents & (APR_POLLOUT)) {
                        do_pump_write(cd, event);
                        continue;
                    }

                    if (pollfd->rtnevents & (APR_POLLIN)) {
                        do_pump_read(cd, event);
                        continue;
                    }

                    break;
                }
                case EVENT_CAPTURE: {

                    /* do not refresh the capture timeout, we want it to end */

                    if (pollfd->rtnevents & (APR_POLLHUP)) {
                        do_capture_hangup(cd, event);
                        continue;
                    }

                    if (pollfd->rtnevents & (APR_POLLIN)) {
                        do_capture_read(cd, event);
                        continue;
                    }

                    break;
                }
                }
            }

        }

        /* */
        else {
            apr_file_printf(cd->err,
                    "connectdump[%d]: apr_pollset_poll: %pm\n",
                    event->number, &status);
            return EXIT_FAILURE;
        }

    }

    return EXIT_SUCCESS;
}

int do_listen(connectdump_t* cd, const char **args)
{
    apr_status_t status;

    cd->events = apr_array_make(cd->pool, 64, sizeof(event_t *));
//    apr_skiplist_init(&cd->events, cd->pool);
//    apr_skiplist_set_compare(cd->events, timer_comp, timer_compk);

    status = apr_pollset_create(&cd->pollset, DEFAULT_POLLSOCKETS, cd->pool,
                                APR_POLLSET_NOCOPY | APR_POLLSET_WAKEABLE );
    if (status != APR_SUCCESS) {
        apr_file_printf(cd->err, "connectdump: cannot create pollset: %pm\n",
                &status);
        return EXIT_FAILURE;
    }

    while (args && *args) {

        apr_sockaddr_t *sa;
        char *host, *scope_id;
        apr_port_t port;

        int first = 1;

        const char *arg = *(args++);

        status = apr_parse_addr_port(&host, &scope_id, &port, arg, cd->pool);
        if (status != APR_SUCCESS) {
            apr_file_printf(cd->err, "connectdump: cannot parse '%s': %pm\n", arg,
                    &status);
            return EXIT_FAILURE;
        }

        if (!port) {
            apr_file_printf(cd->err, "connectdump: port must be specified with '%s': %pm\n", arg,
                    &status);
            return EXIT_FAILURE;
        }

        if ((status = apr_sockaddr_info_get(&sa, host, APR_UNSPEC, port, 0,
                                            cd->pool))
            != APR_SUCCESS) {
            apr_file_printf(cd->err, "connectdump: sockaddr setup failed for '%s': %pm\n", arg,
                    &status);
            return EXIT_FAILURE;
        }

        while (sa) {

            apr_pool_t *pool;
            event_t *event;
            apr_socket_t *sd;

            apr_pool_create(&pool, cd->pool);

            status = apr_socket_create(&sd, sa->family,
                                        SOCK_STREAM, 0, pool);
            if (status != APR_SUCCESS) {
                apr_file_printf(cd->err, "connectdump: socket create failed for '%s' (%pI): %pm\n", arg,
                        sa, &status);
                apr_pool_destroy(pool);
                return EXIT_FAILURE;
            }

            status = apr_socket_opt_set(sd, APR_SO_SNDBUF, DEFAULT_BUFFER_SIZE);
            if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
                apr_file_printf(cd->err, "connectdump: send buffer size cannot be set for '%s' (%pI): %pm\n", arg,
                        sa, &status);
                apr_pool_destroy(pool);
                return EXIT_FAILURE;
            }

            status = apr_socket_opt_set(sd, APR_SO_RCVBUF, DEFAULT_BUFFER_SIZE);
            if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
                apr_file_printf(cd->err, "connectdump: receive buffer size cannot be set for '%s' (%pI): %pm\n", arg,
                        sa, &status);
                apr_pool_destroy(pool);
                return EXIT_FAILURE;
            }

            status = apr_socket_opt_set(sd, APR_TCP_NODELAY, 1);
            if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
                apr_file_printf(cd->err, "connectdump: nagle cannot be disabled for '%s' (%pI): %pm\n", arg,
                        sa, &status);
                apr_pool_destroy(pool);
                return EXIT_FAILURE;
            }

            status = apr_socket_opt_set(sd, APR_SO_REUSEADDR, 1);
            if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
                apr_file_printf(cd->err, "connectdump: reuse address cannot be enabled for '%s' (%pI): %pm\n", arg,
                        sa, &status);
                apr_pool_destroy(pool);
                return EXIT_FAILURE;
            }

            status = apr_socket_opt_set(sd, APR_SO_NONBLOCK,  1);
            if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
                apr_file_printf(cd->err, "connectdump: non blocking cannot be set for '%s' (%pI): %pm\n", arg,
                        sa, &status);
                apr_pool_destroy(pool);
                return EXIT_FAILURE;
            }

            status = apr_socket_bind(sd, sa);
            /* EADDRINUSE is not defined in APR */
            if (!first && status == EADDRINUSE) {

                /* Dual stack sockets will fail on the second attempt to
                 * bind with an address already in use, as the first bind
                 * covered IPv6 and IPv4 together.
                 *
                 * Ignore the error and keep going.
                 */

            }
            else if (status != APR_SUCCESS) {
                apr_file_printf(cd->err, "connectdump: socket bind failed for '%s' (%pI): %pm\n", arg,
                        sa, &status);
                apr_pool_destroy(pool);
                return EXIT_FAILURE;
            }
            else {

                status = apr_socket_listen(sd, DEFAULT_LISTENBACKLOG);
                if ((status) != APR_SUCCESS) {
                    apr_file_printf(cd->err, "connectdump: socket listen failed for '%s' (%pI): %pm\n", arg,
                            sa, &status);
                    apr_pool_destroy(pool);
                    return EXIT_FAILURE;
                }

                event = apr_pcalloc(pool, sizeof(event_t));
                event->cd = cd;
                event->pool = pool;
                event->timestamp = apr_time_now();
                event->when = 0;
                event->pfd.p = pool;
                event->pfd.desc_type = APR_POLL_SOCKET;
                event->pfd.desc.s = sd;
                event->pfd.reqevents = APR_POLLIN;
                event->pfd.client_data = event;
                event->number = cd->numbers++;
                event->type = EVENT_LISTEN;
                event->listen.sa = sa;
                event->listen.sd = sd;

#if 0
                apr_file_printf(cd->err, "connectdump[%d]: skiplist size: %" APR_SIZE_T_FMT " event %pp\n",
                        event->number, apr_skiplist_size(cd->events), event);
                apr_skiplist_insert(cd->events, event);
                apr_file_printf(cd->err, "connectdump[%d]: skiplist size: %" APR_SIZE_T_FMT " event %pp\n",
                        event->number, apr_skiplist_size(cd->events), event);
#endif
                apr_pollset_add(cd->pollset, &event->pfd);

                apr_pool_cleanup_register(pool, event, cleanup_event,
                        apr_pool_cleanup_null);

                apr_file_printf(cd->err, "connectdump[%d]: '%s' listening to %pI\n",
                        event->number, arg, sa);

            }

            first = 0;

            sa = sa->next;
        }

    }

    return do_poll(cd);
}

connectdump_t cd = { 0 };

void terminate()
{
    if (cd.pool) {
        apr_pool_destroy(cd.pool);
    }
    apr_terminate();
}

void sigterm(int signum)
{
    cd.shutdown = 1;
    if (cd.pollset) {
        apr_pollset_wakeup(cd.pollset);
    }
}

int main(int argc, const char * const argv[])
{
    apr_getopt_t *opt;
    const char *optarg;
    struct sigaction sa = { 0 };

//    connectdump_t cd = { 0 };

    int optch;
    apr_status_t status = 0;

    /* lets get APR off the ground, and make sure it terminates cleanly */
    if (APR_SUCCESS != (status = apr_app_initialize(&argc, &argv, NULL))) {
        return 1;
    }
    atexit(terminate);

    if (APR_SUCCESS != (status = apr_pool_create_ex(&cd.pool, NULL, abortfunc, NULL))) {
        return 1;
    }

    sa.sa_handler = sigterm;
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        return 1;
    }

    sa.sa_handler = sigterm;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        return 1;
    }

    apr_file_open_stderr(&cd.err, cd.pool);
    apr_file_open_stdin(&cd.in, cd.pool);
    apr_file_open_stdout(&cd.out, cd.pool);

    cd.alloc = apr_bucket_alloc_create(cd.pool);

    cd.realm = "http-auth@example.org";

    apr_getopt_init(&opt, cd.pool, argc, argv);
    while ((status = apr_getopt_long(opt, cmdline_opts, &optch, &optarg))
            == APR_SUCCESS) {

        switch (optch) {
        case '4': {
            if (!cd.prefer) {
                cd.prefer = PREFER_IPV4;
            }
            cd.laddr4 = optarg;
            break;
        }
        case '6': {
            if (!cd.prefer) {
                cd.prefer = PREFER_IPV6;
            }
            cd.laddr6 = optarg;
            break;
        }
        case 'i': {
            cd.interface = optarg;
            break;
        }
        case 'v': {
            version(cd.out);
            return 0;
        }
        case 'h': {
            help(cd.out, argv[0], NULL, 0, cmdline_opts);
            return 0;
        }
        }
    }

    if (APR_SUCCESS != status && APR_EOF != status) {
        return help(cd.err, argv[0], NULL, EXIT_FAILURE, cmdline_opts);
    }

    if (NO_PREFERENCE == cd.prefer) {
        return help(cd.err, argv[0], "One of -4 or -6 must be specified.\n", EXIT_FAILURE, cmdline_opts);
    }

    /* ipv4 only */
    if (!cd.laddr6) {
        cd.family = APR_INET;
    }

    /* ipv6 only */
    else if (!cd.laddr4) {
        cd.family = APR_INET6;
    }

    /* dual ipv4 and ipv6 */
    else {
        cd.family = APR_UNSPEC;

        if (PREFER_IPV6 == cd.prefer) {
            cd.flags = APR_IPV6_ADDR_OK;
        }
        else if (PREFER_IPV4 == cd.prefer) {
            cd.flags = APR_IPV4_ADDR_OK;
        }
    }

    cd.sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (!cd.sha256) {
        apr_file_printf(cd.err, "SHA256 not supported by OpenSSL\n");
        return EXIT_FAILURE;
    }

    return do_listen(&cd, opt->argv + opt->ind);
}
