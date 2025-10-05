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

#include "connectcap.h"

#include <assert.h>
#include <stdlib.h>

#include <apr_uuid.h>

static const apr_getopt_option_t
    cmdline_opts[] =
{
    /* commands */
    { "help", 'h', 0, "  -h, --help\t\t\tDisplay this help message." },
    { "version", 'v', 0,
        "  -v, --version\t\t\tDisplay the version number." },
    { "source-ipv4", '4', 1, "  -4, --source-ipv4 ip4\t\t\tSource address for IPv4 connections. If specified before the -6 option, attempt IPv4 first." },
    { "source-ipv6", '6', 1, "  -6, --source-ipv6 ip6\t\t\tSource address for IPv6 connections. If specified before the -4 option, attempt IPv6 first." },
    { "directory", 'd', 1, "  -d, --directory path\t\t\tPath to the directory where capture files are saved. Defaults to the current directory." },
    { "interface", 'i', 1, "  -i, --interface dev\t\t\tInterface containing the source addresses. This interface will be used to capture traffic." },
    { "listen", 'l', 1, "  -l, --listen [addr:]port\t\t\tListen to this IP address and port for proxy requests. If IP address is unspecified, binds to all IPs on the port specified." },
    { "passwd", 'p', 1, "  -p, --passwd path\t\t\tFile containing usernames and passwords." },
    { "realm", 'r', 1, "  -r, --realm name\t\t\tName of the realm. Defaults to " DEFAULT_REALM "." },
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
            "  %s [-4] [-6] [-v] [-h] -l address:port [/usr/bin/sendmail -t]\n"
            "\n"
            "DESCRIPTION\n"
            "\n"
            "  The connectcap daemon implements an https CONNECT proxy that records\n"
            "  all outgoing traffic as pcap for later analysis in Wireshark.\n"
            "\n"
            "  No attempts are made to compensate for badly configured servers, the\n"
            " idea being to provide predictable diagnostics for each connection.\n"
            "\n"
            "  The daemon will listen on all the addresses and ports specified.\n"
            "\n"
    		"  If a command is specified, it will be interpreted as a tool to\n"
    		"  send email. The summary and pcap file will be sent to the email\n"
    		"  address corresponding to the logged in user.\n"
            "\n"
            "OPTIONS\n", msg ? msg : "", n, n);

    while (opts[i].name) {
        apr_file_printf(out, "%s\n\n", opts[i].description);
        i++;
    }

    apr_file_printf(out,
            "RETURN VALUE\n"
            "  The connectcap daemon returns a non zero exit code on error.\n"
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

static apr_status_t cleanup_event(void *dummy)
{
    event_t *event = dummy;
    connectcap_t *cd = event->cd;

    if (event->when) {
        assert(event_remove(event->cd->events, event));
    }
    if (event->cd->pollset && event->pfd.p) {
        /* if pollset exists and if descriptor has a pool */
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
    case EVENT_CONN: {
        event_t *request = event->conn.request;
        event_t *pump = event->conn.pump;
        if (request) {
            request->request.conn = NULL;
        }
        if (pump) {
            apr_bucket *b;

            /* request a pump shutdown */
            b = apr_bucket_eos_create(cd->alloc);
            APR_BRIGADE_INSERT_TAIL(pump->pump.obb, b);

            /* swap events from not write to write */
            apr_pollset_remove(pump->cd->pollset, &pump->pfd);
            pump->pfd.reqevents |= APR_POLLOUT;
            apr_pollset_add(pump->cd->pollset, &pump->pfd);

            pump->pump.conn = NULL;
        }
        break;
    }
    case EVENT_REQUEST: {
        event_t *conn = event->request.conn;
        if (conn) {
            conn->conn.request = NULL;
        }
        break;
    }
    case EVENT_PUMP: {
        event_t *conn = event->pump.conn;
        event_t *capture = event->pump.capture;
        if (conn) {
            apr_bucket *b;

            b = apr_bucket_eos_create(cd->alloc);
            APR_BRIGADE_INSERT_TAIL(conn->conn.obb, b);

            /* swap events from not write to write */
            apr_pollset_remove(conn->cd->pollset, &conn->pfd);
            conn->pfd.reqevents |= APR_POLLOUT;
            apr_pollset_add(conn->cd->pollset, &conn->pfd);

            conn->conn.pump = NULL;
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

            apr_file_printf(event->capture.eml, "End:\t\t\t\t%s\n",
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

        if (!cd->shutdown) {
            do_sendmail(cd, event);
        }

        break;
    }
    case EVENT_SENDMAIL: {
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
    event_t *conn = request->request.conn;
    apr_status_t status = APR_SUCCESS;
    int i;

    /* safety first */
    assert(request->type == EVENT_REQUEST);

    /* write the response line */
    apr_brigade_puts(conn->conn.obb, NULL, NULL, "HTTP/1.1 ");
    apr_brigade_puts(conn->conn.obb, NULL, NULL, line);
    apr_brigade_puts(conn->conn.obb, NULL, NULL, CRLF);

    for (i = 0; i < request->request.authenticate->nelts; i++) {
        const char *a = APR_ARRAY_IDX(request->request.authenticate, i, const char *);

        apr_brigade_puts(conn->conn.obb, NULL, NULL, "Proxy-Authenticate: ");
        apr_brigade_puts(conn->conn.obb, NULL, NULL, a);
        apr_brigade_puts(conn->conn.obb, NULL, NULL, CRLF);
    }

    /* write the connection if any and end the stream */
    if (fmt) {
        apr_brigade_puts(conn->conn.obb, NULL, NULL, "X-Proxy-Status: ");
        va_start(ap, fmt);
        status = apr_brigade_vprintf(conn->conn.obb, NULL, NULL, fmt, ap);
        va_end(ap);
        apr_brigade_puts(conn->conn.obb, NULL, NULL, CRLF);
    }

    apr_brigade_puts(conn->conn.obb, NULL, NULL, CRLF);

    /* swap events from read to write */
    apr_pollset_remove(conn->cd->pollset, &conn->pfd);
    conn->pfd.reqevents |= APR_POLLOUT;
    apr_pollset_add(conn->cd->pollset, &conn->pfd);

    return status;
}

apr_status_t do_sendmail(connectcap_t* cd, event_t *capture)
{
    apr_pool_t *pool;
    apr_bucket_brigade *obb;
    apr_bucket *b;
    apr_file_t *efd;
    apr_file_t *wfd;

    event_t *sendmail;

    apr_procattr_t *proc_attrs = NULL;
    apr_proc_t proc;
    apr_file_t *pipe_in_read = NULL, *pipe_in_write = NULL;

    apr_uuid_t uuid;
    char boundary[APR_UUID_FORMATTED_LENGTH + 1];

    apr_time_t now = apr_time_now();

    apr_off_t offset = 0, zero = 0, len = 0;

    apr_status_t status;

    assert(EVENT_CAPTURE == capture->type);

    if (!cd->args || !cd->args[0]) {
        return APR_SUCCESS;
    }

    apr_uuid_get(&uuid);
    apr_uuid_format(boundary, &uuid);

    apr_pool_create(&pool, cd->pool);

    obb = apr_brigade_create(pool, cd->alloc);

    /*
     * Create the email to be sent.
     *
     * We need to base64 encode the pcap file when we send it,
     * so to do that we detect the file buckets and base64 them
     * before we send them.
     *
     * Ideally apr needs an encode bucket.
     */

    /* start of the email */
    apr_brigade_printf(obb, NULL, NULL,
            "MIME-Version: 1.0" CRLF
            "Content-Type: multipart/mixed;" CRLF
            "\tboundary=\"connectcap_%s\"" CRLF
            "To: %s" CRLF
            "Subject: [ConnectCap][%d] %s" CRLF
            CRLF
            "--connectcap_%s" CRLF
            "Content-Transfer-Encoding: base64" CRLF
            "Content-Type: text/plain; charset=\"UTF-8\"" CRLF
            CRLF,
            boundary,
            capture->capture.mail,
            capture->number,
            capture->capture.address,
            boundary);

    status = apr_file_dup(&efd, capture->capture.eml, pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err,
                "connectcap[%d]: file dup failed for '%s': %pm\n",
                capture->number,
                capture->capture.ename,
                &status);

        apr_pool_destroy(pool);

        return status;
    }

    if ((status = apr_file_seek(efd, APR_CUR, &offset)) != APR_SUCCESS) {
        apr_file_printf(cd->err,
                "connectcap[%d]: file seek failed for '%s': %pm\n",
                capture->number,
                capture->capture.ename,
                &status);

        apr_pool_destroy(pool);

        return status;
    }

    if ((status = apr_file_seek(efd, APR_END, &len)) != APR_SUCCESS) {
        apr_file_printf(cd->err,
                "connectcap[%d]: file seek failed for '%s': %pm\n",
                capture->number,
                capture->capture.ename,
                &status);

        apr_pool_destroy(pool);

        return status;
    }

    if ((status = apr_file_seek(efd, APR_SET, &zero)) != APR_SUCCESS) {
        apr_file_printf(cd->err,
                "connectcap[%d]: file seek failed for '%s': %pm\n",
                capture->number,
                capture->capture.ename,
                &status);

        apr_pool_destroy(pool);

        return status;
    }

    b = apr_bucket_file_create(efd, 0, len, pool, cd->alloc);
    APR_BRIGADE_INSERT_TAIL(obb, b);

    /* in between the text and the attachment */
    apr_brigade_printf(obb, NULL, NULL,
            "--connectcap_%s" CRLF
            "Content-Transfer-Encoding: base64" CRLF
            "Content-Disposition: attachment;" CRLF
            "\tfilename=%s" CRLF
            "Content-Type: application/octet-stream;" CRLF
            "\tx-unix-mode=0644;" CRLF
            "\tname=\"%s\"" CRLF
            CRLF,
            boundary,
            capture->capture.ename,
            capture->capture.ename);

    status = apr_file_open(&wfd, capture->capture.wname,
            APR_FOPEN_READ,
            APR_FPROT_OS_DEFAULT, pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err,
                "connectcap[%d]: file open failed for '%s': %pm\n",
                capture->number,
                capture->capture.wname,
                &status);

        apr_pool_destroy(pool);

        return status;
    }

    if ((status = apr_file_seek(wfd, APR_CUR, &offset)) != APR_SUCCESS) {
        apr_file_printf(cd->err,
                "connectcap[%d]: file seek failed for '%s': %pm\n",
                capture->number,
                capture->capture.ename,
                &status);

        apr_pool_destroy(pool);

        return status;
    }

    if ((status = apr_file_seek(wfd, APR_END, &len)) != APR_SUCCESS) {
        apr_file_printf(cd->err,
                "connectcap[%d]: file seek failed for '%s': %pm\n",
                capture->number,
                capture->capture.ename,
                &status);

        apr_pool_destroy(pool);

        return status;
    }

    if ((status = apr_file_seek(wfd, APR_SET, &zero)) != APR_SUCCESS) {
        apr_file_printf(cd->err,
                "connectcap[%d]: file seek failed for '%s': %pm\n",
                capture->number,
                capture->capture.ename,
                &status);

        apr_pool_destroy(pool);

        return status;
    }

    b = apr_bucket_file_create(wfd, 0, len, pool, cd->alloc);
    APR_BRIGADE_INSERT_TAIL(obb, b);

    /* end of the email */
    apr_brigade_printf(obb, NULL, NULL,
            "--connectcap_%s--" CRLF,
            boundary);

    b = apr_bucket_eos_create(cd->alloc);
    APR_BRIGADE_INSERT_TAIL(obb, b);

    /* clean up the files */
    apr_file_remove(capture->capture.ename, pool);
    apr_file_remove(capture->capture.wname, pool);
    apr_dir_remove(capture->capture.mail, pool);

    status = apr_file_pipe_create(&pipe_in_read, &pipe_in_write, pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err,
                "connectcap[%d]: pipe create failed for '%s:%hu': %pm\n",
                capture->number,
                capture->capture.host,
                capture->capture.port, &status);

        apr_pool_destroy(pool);

        return status;
    }

    status = apr_procattr_create(&proc_attrs, pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err,
                "connectcap[%d]: procattr create failed for '%s:%hu': %pm\n",
                capture->number,
                capture->capture.host,
                capture->capture.port, &status);

        apr_pool_destroy(pool);

        return status;
    }
    apr_procattr_child_in_set(proc_attrs, pipe_in_read, NULL);
    apr_procattr_error_check_set(proc_attrs, 1);
    apr_procattr_cmdtype_set(proc_attrs, APR_PROGRAM_ENV);

    status = apr_proc_create(&proc, cd->args[0], cd->args, NULL, proc_attrs, pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err,
                "connectcap[%d]: proc create '%s' failed for '%s:%hu': %pm\n",
                capture->number,
                cd->args[0],
                capture->capture.host,
                capture->capture.port, &status);

        apr_pool_destroy(pool);

        return status;
    }

    /* sanity must prevail */
    apr_file_close(pipe_in_read);

    sendmail = apr_pcalloc(pool, sizeof(event_t));
    sendmail->cd = cd;
    sendmail->pool = pool;
    sendmail->pfd.p = pool;
    sendmail->pfd.desc_type = APR_POLL_FILE;
    sendmail->pfd.desc.f = pipe_in_write;
    /* wait for sendmail to be ready to write */
    sendmail->pfd.reqevents = APR_POLLOUT;
    sendmail->pfd.client_data = sendmail;
    sendmail->number = capture->number;
    sendmail->type = EVENT_SENDMAIL;
    sendmail->sendmail.fd = pipe_in_write;
    sendmail->sendmail.host = apr_pstrdup(pool, capture->capture.host);
    sendmail->sendmail.scope_id = apr_pstrdup(pool, capture->capture.scope_id);
    sendmail->sendmail.port = capture->capture.port;
    sendmail->sendmail.username = capture->capture.username;
    sendmail->sendmail.mail = capture->capture.mail;
    sendmail->sendmail.obb = obb;

    sendmail->timestamp = now;
    sendmail->when = 0;

    apr_pollset_add(cd->pollset, &sendmail->pfd);

    apr_pool_cleanup_register(pool, sendmail, cleanup_event,
            apr_pool_cleanup_null);

    /* time to send some email */

    apr_file_printf(cd->err, "connectcap[%d]: sending '%s:%d' capture to '%s'\n",
            sendmail->number, sendmail->sendmail.host, sendmail->sendmail.port, sendmail->sendmail.mail);

    return APR_SUCCESS;
}

apr_status_t do_accept(connectcap_t* cd, event_t *event)
{
    apr_pool_t *pool;
    apr_sockaddr_t *sa;
    apr_socket_t *sd;
    event_t *conn;
    apr_bucket_brigade *ibb, *obb, *bb;
    apr_bucket *b;

    apr_time_t now = apr_time_now();
    apr_status_t status;

    assert(EVENT_LISTEN == event->type);

    apr_pool_create(&pool, event->pool);

    status = apr_socket_accept(&sd, event->listen.sd, pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err, "connectcap[%d]: accept failed, ignoring: %pm\n",
                event->number, &status);
        apr_pool_destroy(pool);
        return status;
    }

    status = apr_socket_addr_get(&sa, APR_REMOTE, sd);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err, "connectcap[%d]: apr_socket_addr_get failed, ignoring: %pm\n",
                event->number, &status);
        apr_pool_destroy(pool);
        return status;
    }

    ibb = apr_brigade_create(pool, cd->alloc);
    obb = apr_brigade_create(pool, cd->alloc);
    bb = apr_brigade_create(pool, cd->alloc);

    conn = apr_pcalloc(pool, sizeof(event_t));
    conn->cd = cd;
    conn->pool = pool;
    conn->pfd.p = pool;
    conn->pfd.desc_type = APR_POLL_SOCKET;
    conn->pfd.desc.s = sd;
    conn->pfd.reqevents = APR_POLLIN;
    conn->pfd.client_data = conn;
    conn->number = cd->numbers++;
    conn->type = EVENT_CONN;
    conn->conn.sa = sa;
    conn->conn.sd = sd;
    conn->conn.ibb = ibb;
    conn->conn.obb = obb;
    conn->conn.bb = bb;

    apr_pool_cleanup_register(pool, conn, cleanup_event,
            apr_pool_cleanup_null);

    b = apr_bucket_socket_create(sd, cd->alloc);

    APR_BRIGADE_INSERT_HEAD(ibb, b);

    conn->timestamp = now;
    conn->when = now + apr_time_from_sec(DEFAULT_CONN_TIMEOUT);
    event_add(cd->events, conn);

    apr_pollset_add(cd->pollset, &conn->pfd);

    apr_file_printf(cd->err, "connectcap[%d]: accepted connection from %pI\n",
            conn->number, sa);

    return APR_SUCCESS;
}

apr_status_t do_capture(connectcap_t* cd, event_t *request, event_t *pump)
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

    assert(EVENT_PUMP == pump->type);
    assert(EVENT_REQUEST == request->type);

    now = apr_time_now();

    apr_pool_create(&pool, cd->pool);

    rc = pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);
    if (rc == -1) {
        apr_file_printf(cd->err,
                "connectcap[%d]: pcap_init failed for '%s:%hu': %s\n",
                request->number,
                request->request.host,
                request->request.port, errbuf);

        send_response(request, "500 Internal Server Error",
                "pcap_init failed for '%s', rejecting request: %s",
                request->request.host, errbuf);

        apr_pool_destroy(pool);

        return APR_EGENERAL;
    }

    if (!name) {
        if (pcap_findalldevs(&devs, errbuf)) {
            apr_file_printf(cd->err,
                    "connectcap[%d]: pcap_findalldevs failed for '%s:%hu': %s\n",
                    request->number,
                    request->request.host,
                    request->request.port, errbuf);

            send_response(request, "500 Internal Server Error",
                    "pcap_findalldevs failed for '%s', rejecting request: %s",
                    request->request.host, errbuf);

            apr_pool_destroy(pool);

            return APR_EGENERAL;
        }

        for (dev = devs; dev; dev = dev->next) {

            struct pcap_addr *address = dev->addresses;

            apr_file_printf(cd->err,
                    "connectcap[%d]: pcap_findalldevs returned for '%s:%hu': %s\n",
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
                    "connectcap[%d]: pcap_findalldevs found interface %s for '%s:%hu'\n",
                    request->number,
                    name,
                    request->request.host,
                    request->request.port);
        }
        else {
            apr_file_printf(cd->err,
                    "connectcap[%d]: pcap_findalldevs found no interface matching %pI for '%s:%hu'\n",
                    request->number,
                    pump->pump.lsa,
                    request->request.host,
                    request->request.port);

            send_response(request, "500 Internal Server Error",
                    "pcap_findalldevs found no interface matching %pI for '%s:%hu'",
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
                "connectcap[%d]: pcap_create failed for '%s:%hu': %s\n",
                request->number,
                request->request.host,
                request->request.port, errbuf);

        send_response(request, "500 Internal Server Error",
                "pcap_create failed for '%s', rejecting request: %s",
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
                "connectcap[%d]: pcap_activate failed for '%s:%hu': %s\n",
                request->number,
                request->request.host,
                request->request.port, pcap_statustostr(rc));

        send_response(request, "500 Internal Server Error",
                "pcap_activate failed for '%s', rejecting request: %s",
                request->request.host, pcap_statustostr(rc));

        apr_pool_destroy(pool);

        return APR_EGENERAL;
    }
    else if (rc > 0) {
        /* warnings */
        apr_file_printf(cd->err,
                "connectcap[%d]: pcap_activate warning for '%s:%hu': %s\n",
                request->number,
                request->request.host,
                request->request.port, pcap_statustostr(rc));
    }

    rc = pcap_setnonblock(pcap, 1, errbuf);
    if (rc) {
        apr_file_printf(cd->err,
                "connectcap[%d]: pcap_setnonblock failed for '%s:%hu': %s\n",
                request->number,
                request->request.host,
                request->request.port, errbuf);

        send_response(request, "500 Internal Server Error",
                "pcap_setnonblock failed for '%s', rejecting request: %s",
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
                "connectcap[%d]: pcap_compile of '%s' failed for '%s:%hu': %s\n",
                request->number,
                buf,
                request->request.host,
                request->request.port, pcap_geterr(pcap));

        send_response(request, "500 Internal Server Error",
                "pcap_compile of '%s' failed for '%s', rejecting request: %s",
                buf,
                request->request.host, pcap_geterr(pcap));

        apr_pool_destroy(pool);

        return APR_EGENERAL;
    }

    rc = pcap_setfilter(pcap, &bp);
    pcap_freecode(&bp);
    if (rc) {
        apr_file_printf(cd->err,
                "connectcap[%d]: pcap_setfilter failed for '%s:%hu': %s\n",
                request->number,
                request->request.host,
                request->request.port, pcap_geterr(pcap));

        send_response(request, "500 Internal Server Error",
                "pcap_setfilter failed for '%s', rejecting request: %s",
                request->request.host, pcap_geterr(pcap));

        apr_pool_destroy(pool);

        return APR_EGENERAL;
    }

    fd = pcap_get_selectable_fd(pcap);
    if (fd == -1) {
        apr_file_printf(cd->err,
                "connectcap[%d]: pcap_get_selectable_fd failed while capturing '%s' for '%s:%hu'\n",
                request->number,
                name,
                request->request.host,
                request->request.port);

        send_response(request, "500 Internal Server Error",
                "pcap_get_selectable_fd failed while capturing '%s' for '%s', rejecting conn",
                name,
                request->request.host);

        apr_pool_destroy(pool);

        return APR_EGENERAL;
    }
    sd = NULL;
    apr_os_sock_put(&sd, &fd, pool);

    /*
     * Create the directory for the pcap file.
     */
    status = apr_dir_make_recursive(request->request.mail, APR_FPROT_OS_DEFAULT, pool);

    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err,
                "connectcap[%d]: directory create of '%s' failed for '%s:%hu': %pm\n",
                request->number,
                request->request.mail,
                request->request.host,
                request->request.port, &status);

        send_response(request, "500 Internal Server Error",
                "directory create of '%s' failed for '%s', rejecting request: %pm",
                request->request.username,
                request->request.host, &status);

        apr_pool_destroy(pool);

        return status;
    }

    /*
     * Create the filename for the pcap file.
     *
     * For now, it's the number, the host, port, and pcap.
     */
    wname = apr_psprintf(pool, "%s/%d-%s-%d.pcap",
            request->request.mail,
            request->number, request->request.host,
            request->request.port);

    dumper = pcap_dump_open(pcap, wname);
    if (!dumper) {
        apr_file_printf(cd->err,
                "connectcap[%d]: pcap_dump_open failed opening '%s' for '%s:%hu': %s\n",
                request->number,
                wname,
                request->request.host,
                request->request.port, pcap_geterr(pcap));

        send_response(request, "500 Internal Server Error",
                "pcap_dump_open failed for '%s', rejecting request: %s",
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
    ename = apr_psprintf(pool, "%s/%d-%s-%d.eml",
            request->request.mail,
            request->number, request->request.host,
            request->request.port);

    status = apr_file_open(&eml, ename,
    		APR_FOPEN_READ | APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE,
            APR_FPROT_OS_DEFAULT, pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err,
                "connectcap[%d]: file create of '%s' failed for '%s:%hu': %pm\n",
                request->number,
                ename,
                request->request.host,
                request->request.port, &status);

        send_response(request, "500 Internal Server Error",
                "file create of '%s' failed for '%s', rejecting request: %pm",
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
    capture->number = pump->number;
    capture->type = EVENT_CAPTURE;
    capture->capture.sd = sd;
    capture->capture.host = apr_pstrdup(pool, pump->pump.host);
    capture->capture.scope_id = apr_pstrdup(pool, pump->pump.scope_id);
    capture->capture.port = pump->pump.port;
    capture->capture.username = apr_pstrdup(pool, request->request.username);
    capture->capture.mail = apr_pstrdup(pool, request->request.mail);
    capture->capture.pcap = pcap;
    capture->capture.dumper = dumper;
    capture->capture.eml = eml;
    capture->capture.wname = wname;
    capture->capture.ename = ename;

    capture->capture.pump = pump;
    pump->pump.capture = capture;

    apr_pollset_add(cd->pollset, &capture->pfd);

    apr_pool_cleanup_register(pool, capture, cleanup_event,
            apr_pool_cleanup_null);

    apr_file_printf(cd->err, "connectcap[%d]: capture '%s' started with filter: %s\n",
            capture->number, capture->capture.host, buf);

    return APR_SUCCESS;
}

apr_status_t do_connect(connectcap_t* cd, event_t *request)
{
    apr_pool_t *pool;
    apr_sockaddr_t *psa, *lsa;
    apr_socket_t *sd;
    apr_bucket_brigade *ibb, *obb;
    apr_bucket *b;
    event_t *pump, *conn;

    apr_time_t now = apr_time_now();
    apr_int32_t family;

    apr_status_t status;

    assert(EVENT_REQUEST == request->type);

    apr_pool_create(&pool, cd->pool);

    /* look up the socket to the other side */

    status = apr_sockaddr_info_get(&psa, request->request.host, cd->family,
            request->request.port, cd->flags, pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd->err,
                "connectcap[%d]: sockaddr setup failed for '%s:%hu': %pm\n",
                request->number,
                request->request.host,
                request->request.port, &status);

        send_response(request, "502 Bad Gateway",
                "sockaddr failed for '%s', rejecting request: %pm",
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
                    "connectcap[%d]: source IPv4 '%s' setup failed for '%s:%hu': %pm\n",
                    request->number,
                    cd->laddr4,
                    request->request.host,
                    request->request.port, &status);

            send_response(request, "502 Bad Gateway",
                    "source IPv4 '%s' setup failed for '%s:%hu': %pm",
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
                    "connectcap[%d]: source IPv6 '%s' setup failed for '%s:%hu': %pm\n",
                    request->number,
                    cd->laddr6,
                    request->request.host,
                    request->request.port, &status);

            send_response(request, "502 Bad Gateway",
                    "source IPv6 '%s' setup failed for '%s:%hu': %pm",
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
                "connectcap[%d]: sockaddr family not IPv4 or IPv6 for '%s:%hu'\n",
                request->number, request->request.host,
                request->request.port);

        send_response(request, "502 Bad Gateway",
                "sockaddr family not IPv4 or IPv6 for '%s', rejecting conn",
                request->request.host);

        apr_pool_destroy(pool);

        return APR_EINVAL;
    }
    }

    status = apr_socket_create(&sd, psa->family,
                                SOCK_STREAM, 0, pool);
    if (status != APR_SUCCESS) {
        apr_file_printf(cd->err,
                "connectcap[%d]: socket create failed for '%s:%hu' (%pI): %pm\n",
                request->number, request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "socket create failed for '%s:%hu' (%pI): %pm",
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }

    status = apr_socket_opt_set(sd, APR_SO_SNDBUF, DEFAULT_BUFFER_SIZE);
    if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
        apr_file_printf(cd->err,
                "connectcap[%d]: send buffer size cannot be set for '%s:%hu' (%pI): %pm\n",
                request->number,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "socket create failed for '%s:%hu' (%pI): %pm",
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }

    status = apr_socket_opt_set(sd, APR_SO_RCVBUF, DEFAULT_BUFFER_SIZE);
    if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
        apr_file_printf(cd->err,
                "connectcap[%d]: receive buffer size cannot be set for '%s:%hu' (%pI): %pm\n",
                request->number,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "socket create failed for '%s:%hu' (%pI): %pm",
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }

    status = apr_socket_opt_set(sd, APR_TCP_NODELAY, 1);
    if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
        apr_file_printf(cd->err,
                "connectcap[%d]: nagle cannot be disabled for '%s:%hu' (%pI): %pm\n",
                request->number,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "socket create failed for '%s:%hu' (%pI): %pm",
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }

    status = apr_socket_opt_set(sd, APR_SO_NONBLOCK, 1);
    if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
        apr_file_printf(cd->err,
                "connectcap[%d]: non block cannot be set for '%s:%hu' (%pI): %pm\n",
                request->number,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "non block cannot be set for '%s:%hu' (%pI): %pm",
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }

#if 0
    status = apr_socket_opt_set(sd, APR_IPV6_V6ONLY, 1);
    if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
        apr_file_printf(cd->err,
                "connectcap[%d]: ipv6only cannot be set for '%s:%hu' (%pI): %pm\n",
                request->number,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "ipv6only cannot be set for '%s:%hu' (%pI): %pm",
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }
#endif

    status = apr_socket_bind(sd, lsa);
    if (status != APR_SUCCESS) {
        apr_file_printf(cd->err,
                "connectcap[%d]: socket bind to %pI failed for '%s:%hu' (%pI): %pm\n",
                request->number,
                lsa,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "connectcap: socket bind to %pI failed for '%s:%hu' (%pI): %pm",
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
                "connectcap[%d]: get sockaddr failed for '%s:%hu' (%pI): %pm\n",
                request->number,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "connectcap: get sockaddr failed for '%s:%hu' (%pI): %pm",
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

    conn = request->request.conn;

    pump->pump.conn = conn;
    conn->conn.pump = pump;

    b = apr_bucket_socket_create(sd, cd->alloc);

    APR_BRIGADE_INSERT_HEAD(ibb, b);

    pump->timestamp = now;
    pump->when = now + apr_time_from_sec(DEFAULT_PUMP_TIMEOUT);
    event_add(cd->events, pump);

    apr_pollset_add(cd->pollset, &pump->pfd);

    apr_pool_cleanup_register(pool, pump, cleanup_event,
            apr_pool_cleanup_null);

    /* To bootstrap the pump/conn pair, we set to start
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
    apr_pollset_remove(conn->cd->pollset, &conn->pfd);
    conn->pfd.reqevents = APR_POLLOUT;
    apr_pollset_add(conn->cd->pollset, &conn->pfd);

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
                "connectcap[%d]: socket connect failed for '%s:%hu' (%pI): %pm\n",
                request->number,
                request->request.host,
                request->request.port, psa, &status);

        send_response(request, "502 Bad Gateway",
                "connectcap: socket bind to %pI failed for '%s:%hu' (%pI): %pm",
                lsa,
                request->request.host,
                request->request.port, psa, &status);

        apr_pool_destroy(pool);

        return status;
    }

    /* phew, so many steps, time to shift some data */

    apr_file_printf(cd->err, "connectcap[%d]: '%s' connecting to %pI from %pI\n",
            pump->number, request->request.host, psa, lsa);

    send_response(request, "200 Let's Gooooooo", NULL);

    return APR_SUCCESS;
}

apr_status_t do_request(connectcap_t* cd, event_t *conn)
{
    apr_pool_t *pool;
    apr_sockaddr_t *sa = conn->conn.sa;
    event_t *request;

    apr_time_t now = apr_time_now();

    assert(EVENT_CONN == conn->type);

    apr_pool_create(&pool, conn->pool);

    request = apr_pcalloc(pool, sizeof(event_t));
    request->cd = cd;
    request->pool = pool;
    request->number = conn->number;
    request->type = EVENT_REQUEST;
    request->request.sa = sa;
    request->request.number = conn->conn.requests++;
    request->request.authenticate = apr_array_make(request->pool, 3, sizeof(const char *));

    apr_pool_cleanup_register(pool, request, cleanup_event,
            apr_pool_cleanup_null);

    request->timestamp = now;

    conn->conn.request = request;
    request->request.conn = conn;

    apr_file_printf(cd->err, "connectcap[%d]: browser %pI request %d ready\n",
            conn->number, sa, request->request.number);

    /* until further notice */
    request->request.not_authenticated = "Authorization is required\n";

    return APR_SUCCESS;
}

apr_status_t do_conn_write(connectcap_t* cd, event_t *conn)
{
    apr_bucket_brigade *obb;
    apr_bucket *b;

    event_t *pump = conn->conn.pump;
    event_t *request = conn->conn.request;

    const char *data;
    apr_size_t length;

    apr_status_t status = APR_SUCCESS;

    assert(EVENT_CONN == conn->type);

    obb = conn->conn.obb;

    while (((b = APR_BRIGADE_FIRST(obb)) != APR_BRIGADE_SENTINEL(obb))) {

        if (APR_BUCKET_IS_EOS(b)) {

            /* once we reach here, we have finished writing to the client
             * and can close up this connection.
             */
            apr_file_printf(cd->err,
                    "connectcap[%d]: sending shutdown to browser %pI\n",
                    conn->number, conn->conn.sa);

            /* swap events from write to not write */
            apr_pollset_remove(conn->cd->pollset, &conn->pfd);
            conn->pfd.reqevents &= ~APR_POLLOUT;
            apr_pollset_add(conn->cd->pollset, &conn->pfd);

            /* lingering close, we will wait for other side to close */
            apr_socket_shutdown(conn->conn.sd, APR_SHUTDOWN_WRITE);

            apr_bucket_delete(b);

            /* our request is finally done, destroy the conn */
            apr_pool_destroy(conn->pool);

            return APR_SUCCESS;
        }

        /* we are reading heap buckets here, by definition we will never block */
        status = apr_bucket_read(b, &data, &length, APR_BLOCK_READ);

        /* heap buckets should always succeed */
        assert(APR_SUCCESS == status);

        if (length) {

            apr_size_t requested = length;

            status = apr_socket_send(conn->conn.sd, data, &length);

            if (APR_STATUS_IS_EAGAIN(status)) {
                /* poll again */
                return status;
            }
            else if (APR_SUCCESS != status) {
                /* write attempt failed, give up */
                apr_file_printf(cd->err,
                        "connectcap[%d]: write failed to %pI, closing: %pm\n",
                        conn->number, conn->conn.sa, &status);

                apr_pool_destroy(conn->pool);
                return status;
            }

            if (requested > length) {
                apr_bucket_split(b, length);
            }

            if (cd->verbose) {
                apr_file_printf(cd->err, "connectcap[%d]: browser %pI write %" APR_SIZE_T_FMT " bytes\n",
                        conn->number, conn->conn.sa, length);
            }

            conn->conn.bytes_written += length;
            conn->conn.writes++;

        }

        apr_bucket_delete(b);
    }

    /* If we reach here, we have nothing more to write.
     *
     * Do we have a pump? If so, tunnel mode, switch
     * conn write off and pump read on, let's go fetch
     * some more data.
     *
     * Do we not have a pump? If so, HTTP mode with
     * keepalive, switch conn write off and conn read
     * on to get the next pipelined request.
     */

    if (pump) {

        /* swap events from write to not write */
        apr_pollset_remove(conn->cd->pollset, &conn->pfd);
        conn->pfd.reqevents &= ~APR_POLLOUT;
        apr_pollset_add(conn->cd->pollset, &conn->pfd);

        /* swap events from not read to read */
        apr_pollset_remove(pump->cd->pollset, &pump->pfd);
        pump->pfd.reqevents |= APR_POLLIN;
        apr_pollset_add(pump->cd->pollset, &pump->pfd);

    }

    else if (request) {

        /* swap events from write to read */
        apr_pollset_remove(conn->cd->pollset, &conn->pfd);
        conn->pfd.reqevents &= ~APR_POLLOUT;
        conn->pfd.reqevents |= APR_POLLIN;
        apr_pollset_add(conn->cd->pollset, &conn->pfd);

        /* reset and be ready to parse the next request */
        apr_pool_destroy(request->pool);
    }

    return APR_SUCCESS;
}

apr_status_t do_conn_read(connectcap_t* cd, event_t *conn)
{
    apr_bucket_brigade *ibb, *bb;

    event_t *request = conn->conn.request;
    event_t *pump = conn->conn.pump;

    apr_status_t status = APR_SUCCESS;

    assert(EVENT_CONN == conn->type);

    ibb = conn->conn.ibb;
    bb = conn->conn.bb;

    /* are we pumping data? */
    if (pump) {

        apr_bucket *b;
        const char *data;
        apr_size_t length;

        b = APR_BRIGADE_FIRST(ibb);

        if (APR_BRIGADE_SENTINEL(ibb) == b) {
            /* client hung up early, tear everything down */
            apr_file_printf(cd->err,
                    "connectcap[%d]: no more to read from %pI\n",
                    conn->number, conn->conn.sa);

            apr_pool_destroy(conn->pool);
            return status;
        }

        /* read exactly once */
        status = apr_bucket_read(b, &data, &length, APR_NONBLOCK_READ);

        if (APR_SUCCESS == status) {
            /* pass across to the pump */
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(pump->pump.obb, b);

            if (cd->verbose) {
                apr_file_printf(cd->err, "connectcap[%d]: browser %pI read %" APR_SIZE_T_FMT " bytes\n",
                        conn->number, conn->conn.sa, length);
            }

            conn->conn.bytes_read += length;
            conn->conn.reads++;

            /* swap events from read to not read */
            apr_pollset_remove(conn->cd->pollset, &conn->pfd);
            conn->pfd.reqevents &= ~APR_POLLIN;
            apr_pollset_add(conn->cd->pollset, &conn->pfd);

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
                    "connectcap[%d]: connection closed unexpectedly from %pI\n",
                    conn->number, conn->conn.sa);

            apr_pool_destroy(conn->pool);
            return status;
        }
        else {

            /* read failed, tear everything down */
            apr_file_printf(cd->err,
                    "connectcap[%d]: error reading from %pI: %pm\n",
                    conn->number, conn->conn.sa, &status);

            apr_pool_destroy(conn->pool);
            return status;
        }

        return status;
    }

    /* must we set up a request? */
    if (!request) {

        status = do_request(cd, conn);
        if (APR_SUCCESS != status) {
            /* errors already handled */
            return status;
        }

        /* set up above */
        request = conn->conn.request;
    }

    /* are we handling a connect conn? */
    while (APR_SUCCESS == status) {

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
                        "connectcap[%d]: connection closed unexpectedly from %pI\n",
                        conn->number, conn->conn.sa);

                apr_pool_destroy(conn->pool);

                break;
            }

            /* empty line and not yet authenticated */
            else if (!size && request->request.not_authenticated) {
                apr_file_printf(cd->err,
                        "connectcap[%d]: unauthenticated request from %pI\n",
                        conn->number, conn->conn.sa);

                make_proxy_authenticate(cd, request);

                send_response(request, "407 Proxy Authentication Required", request->request.not_authenticated);

                break;
            }

            /* empty line, are our headers done? */
            else if (!size) {

                apr_file_printf(cd->err,
                        "connectcap[%d]: browser %pI: user '%s' authenticated successfuly, starting pump\n",
                        conn->number, conn->conn.sa, request->request.username);

                do_connect(cd, request);

                break;
            }

            /* line is too long - reject the conn */
            else if (size >= HUGE_STRING_LEN) {

                apr_file_printf(cd->err,
                        "connectcap[%d]: line too long from %pI\n",
                        conn->number, conn->conn.sa);

                send_response(request, "414 URI Too Long", "Request line is too long, rejecting conn.");

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
                            "connectcap[%d]: version not specified from %pI\n",
                            conn->number, conn->conn.sa);

                    send_response(request, "400 Bad Request", "Request line did not carry a version, rejecting conn.\n");

                    break;
                }

                else if (!address) {
                    apr_file_printf(cd->err,
                            "connectcap[%d]: address not specified from %pI\n",
                            conn->number, conn->conn.sa);

                    send_response(request, "400 Bad Request", "Request line did not carry an address, rejecting conn.");

                    break;
                }

                else if (strcmp(method, "CONNECT")) {
                    apr_file_printf(cd->err,
                            "connectcap[%d]: method %s not allowed from %pI\n",
                            conn->number, method, conn->conn.sa);

                    send_response(request, "405 Method Not Allowed", "This proxy supports the CONNECT method only, rejecting conn.");

                    break;
                }

                request->request.method = apr_pstrdup(request->pool, method);
                request->request.address = apr_pstrdup(request->pool, address);

                /* request line */
                status = apr_parse_addr_port(&request->request.host,
                        &request->request.scope_id, &request->request.port,
                        address, conn->pool);
                if (status != APR_SUCCESS) {
                    apr_file_printf(cd->err,
                            "connectcap[%d]: cannot parse '%s' from %pI: %pm\n",
                            conn->number, address, conn->conn.sa, &status);

                    send_response(request, "400 Bad Request", "Address '%s' could not be parsed, rejecting conn.\n", address);

                    break;
                }

                if (!request->request.port) {
                    apr_file_printf(cd->err,
                            "connectcap[%d]: port not specified from %pI\n",
                            conn->number, conn->conn.sa);

                    send_response(request, "400 Bad Request", "Address '%s' requires a port be specified explicitly, rejecting conn.", address);

                    break;
                }

                apr_file_printf(cd->err,
                        "connectcap[%d]: '%s' to '%s' received from %pI\n",
                        conn->number, method, address, conn->conn.sa);

            }
            else {
                /* header line */

                if (cd->verbose) {
                    apr_file_printf(cd->err,
                            "connectcap[%d]: header line '%s' received from %pI\n",
                            conn->number, buf, conn->conn.sa);
                }

                status = parse_proxy_authorization(cd, request, buf);
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
                    "connectcap[%d]: connection closed unexpectedly from %pI\n",
                    conn->number, conn->conn.sa);

            apr_pool_destroy(conn->pool);
            break;
        }
        else {

            /* read failed, tear everything down */
            apr_file_printf(cd->err,
                    "connectcap[%d]: error reading from %pI: %pm\n",
                    conn->number, conn->conn.sa, &status);

            apr_pool_destroy(conn->pool);
            break;
        }

    }

    return status;
}

apr_status_t do_conn_hangup(connectcap_t* cd, event_t *conn)
{
    event_t *pump = conn->conn.pump;

    apr_bucket *b;

    assert(EVENT_CONN == conn->type);

    apr_socket_shutdown(conn->conn.sd, APR_SHUTDOWN_READ);

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
            "connectcap[%d]: browser %pI closed connection (%d reads %" APR_SIZE_T_FMT " bytes, %d writes %" APR_SIZE_T_FMT " bytes)\n",
            conn->number, conn->conn.sa,
            conn->conn.reads, conn->conn.bytes_read,
            conn->conn.writes, conn->conn.bytes_written);

    apr_pool_destroy(conn->pool);

    return APR_SUCCESS;
}

apr_status_t do_pump_write(connectcap_t* cd, event_t *pump)
{
    apr_bucket_brigade *obb;
    apr_bucket *b;

    event_t *conn = pump->pump.conn;

    const char *data;
    apr_size_t length;

    apr_status_t status = APR_SUCCESS;

    assert(EVENT_PUMP == pump->type);

    obb = pump->pump.obb;

    while (((b = APR_BRIGADE_FIRST(obb)) != APR_BRIGADE_SENTINEL(obb))) {

        if (APR_BUCKET_IS_EOS(b)) {

            /* once we reach here, we have finished writing to the client
             * and can close up this connection.
             */
            apr_file_printf(cd->err,
                    "connectcap[%d]: sending shutdown to origin %pI\n",
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
                        "connectcap[%d]: origin %pI write %" APR_SIZE_T_FMT " bytes failed: %pm\n",
                        pump->number, pump->pump.psa, length, &status);

                b = apr_bucket_eos_create(cd->alloc);
                APR_BRIGADE_INSERT_TAIL(conn->conn.obb, b);

                /* swap events from not write to write */
                apr_pollset_remove(conn->cd->pollset, &conn->pfd);
                conn->pfd.reqevents |= APR_POLLOUT;
                apr_pollset_add(conn->cd->pollset, &conn->pfd);

                apr_bucket_delete(b);

                apr_pool_destroy(pump->pool);

                return status;
            }
            else {

                if (cd->verbose) {
                    apr_file_printf(cd->err,
                            "connectcap[%d]: '%s' write %" APR_SIZE_T_FMT " bytes to origin %pI\n",
                            pump->number, pump->pump.host, length, pump->pump.psa);
                }

                pump->pump.bytes_written += length;
                pump->pump.writes++;
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

    if (conn) {

        /* swap events from write to not write */
        apr_pollset_remove(pump->cd->pollset, &pump->pfd);
        pump->pfd.reqevents &= ~APR_POLLOUT;
        apr_pollset_add(pump->cd->pollset, &pump->pfd);

        /* swap events from not read to read */
        apr_pollset_remove(conn->cd->pollset, &conn->pfd);
        conn->pfd.reqevents |= APR_POLLIN;
        apr_pollset_add(conn->cd->pollset, &conn->pfd);

    }

    return APR_SUCCESS;
}

apr_status_t do_pump_read(connectcap_t* cd, event_t *pump)
{
    apr_bucket_brigade *ibb;

    event_t *conn = pump->pump.conn;

    apr_status_t status = APR_SUCCESS;

    assert(EVENT_PUMP == pump->type);

    ibb = pump->pump.ibb;

    /* are we pumping data? */
    if (conn) {

        apr_bucket *b;
        const char *data;
        apr_size_t length;

        b = APR_BRIGADE_FIRST(ibb);

        if (APR_BRIGADE_SENTINEL(ibb) == b) {
            /* origin hung up early, tear everything down */
            apr_file_printf(cd->err,
                    "connectcap[%d]: no more to read from %pI\n",
                    pump->number, pump->pump.psa);

            b = apr_bucket_eos_create(cd->alloc);
            APR_BRIGADE_INSERT_TAIL(conn->conn.obb, b);

            /* swap events from not write to write */
            apr_pollset_remove(conn->cd->pollset, &conn->pfd);
            conn->pfd.reqevents |= APR_POLLOUT;
            apr_pollset_add(conn->cd->pollset, &conn->pfd);

            apr_pool_destroy(pump->pool);

            return status;
        }

        /* read exactly once */
        status = apr_bucket_read(b, &data, &length, APR_NONBLOCK_READ);

        if (APR_SUCCESS == status) {
            /* pass across to the pump */
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(conn->conn.obb, b);

            /* swap events from read to not read */
            apr_pollset_remove(pump->cd->pollset, &pump->pfd);
            pump->pfd.reqevents &= ~APR_POLLIN;
            apr_pollset_add(pump->cd->pollset, &pump->pfd);

            /* swap events from not write to write */
            apr_pollset_remove(conn->cd->pollset, &conn->pfd);
            conn->pfd.reqevents |= APR_POLLOUT;
            apr_pollset_add(conn->cd->pollset, &conn->pfd);

            if (cd->verbose) {
                apr_file_printf(cd->err,
                        "connectcap[%d]: '%s' read %" APR_SIZE_T_FMT " bytes from origin %pI\n",
                        pump->number, pump->pump.host, length, pump->pump.psa);
            }

            pump->pump.bytes_read += length;
            pump->pump.reads++;

            return status;
        }
        else if (APR_STATUS_IS_EAGAIN(status)) {
            /* we need to poll for more data */
            return status;
        }
        else if (APR_STATUS_IS_EOF(status)) {

            /* origin hung up early, tear everything down */
            apr_file_printf(cd->err,
                    "connectcap[%d]: origin %pI received eof\n",
                    pump->number, pump->pump.psa);

            b = apr_bucket_eos_create(cd->alloc);
            APR_BRIGADE_INSERT_TAIL(conn->conn.obb, b);

            /* swap events from not write to write */
            apr_pollset_remove(conn->cd->pollset, &conn->pfd);
            conn->pfd.reqevents |= APR_POLLOUT;
            apr_pollset_add(conn->cd->pollset, &conn->pfd);

            apr_pool_destroy(pump->pool);

            return status;
        }
        else {

            /* read failed, tear everything down */
            apr_file_printf(cd->err,
                    "connectcap[%d]: origin %pI read error: %pm\n",
                    pump->number, pump->pump.psa, &status);

            b = apr_bucket_eos_create(cd->alloc);
            APR_BRIGADE_INSERT_TAIL(conn->conn.obb, b);

            /* swap events from not write to write */
            apr_pollset_remove(conn->cd->pollset, &conn->pfd);
            conn->pfd.reqevents |= APR_POLLOUT;
            apr_pollset_add(conn->cd->pollset, &conn->pfd);

            apr_pool_destroy(pump->pool);

            return status;
        }

    }

    return APR_SUCCESS;
}

apr_status_t do_pump_hangup(connectcap_t* cd, event_t *pump)
{
    event_t *conn = pump->pump.conn;

    apr_bucket *b;

    assert(EVENT_PUMP == pump->type);

    apr_socket_shutdown(pump->pump.sd, APR_SHUTDOWN_READ);

    /* is our request still alive? */
    if (conn) {

        b = apr_bucket_eos_create(cd->alloc);
        APR_BRIGADE_INSERT_TAIL(conn->conn.obb, b);

        /* swap events from not write to write */
        apr_pollset_remove(conn->cd->pollset, &conn->pfd);
        conn->pfd.reqevents |= APR_POLLOUT;
        apr_pollset_add(conn->cd->pollset, &conn->pfd);

    }

    /* client hung up early, tear everything down */
    apr_file_printf(cd->err,
            "connectcap[%d]: origin %pI closed connection (%d reads %" APR_SIZE_T_FMT " bytes, %d writes %" APR_SIZE_T_FMT " bytes)\n",
            pump->number, pump->pump.psa,
            pump->pump.reads, pump->pump.bytes_read,
            pump->conn.writes, pump->conn.bytes_written);

    apr_pool_destroy(pump->pool);

    return APR_SUCCESS;
}

apr_status_t do_capture_read(connectcap_t* cd, event_t *capture)
{
    struct pcap_pkthdr *pkt_header = NULL;
    const u_char *pkt_data = NULL;

    int rc;

    assert(EVENT_CAPTURE == capture->type);

    rc = pcap_next_ex(capture->capture.pcap,
            &pkt_header, &pkt_data);
    if (PCAP_ERROR == rc) {
        apr_file_printf(cd->err,
                "connectcap[%d]: capture error: %s\n",
                capture->number, pcap_geterr(capture->capture.pcap));

        apr_pool_destroy(capture->pool);

        return APR_EGENERAL;
    }

    pcap_dump((u_char *)capture->capture.dumper, pkt_header, pkt_data);
    rc = pcap_dump_flush(capture->capture.dumper);
    if (PCAP_ERROR == rc) {
        apr_file_printf(cd->err,
                "connectcap[%d]: capture save error, giving up capture\n",
                capture->number);

        apr_pool_destroy(capture->pool);

        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

apr_status_t do_capture_hangup(connectcap_t* cd, event_t *capture)
{
    assert(EVENT_CAPTURE == capture->type);

    apr_file_printf(cd->err,
            "connectcap[%d]: capture error: %s\n",
            capture->number, pcap_geterr(capture->capture.pcap));

    apr_pool_destroy(capture->pool);

    return APR_EGENERAL;
}

apr_status_t do_sendmail_write(connectcap_t* cd, event_t *sendmail)
{
    apr_bucket_brigade *obb;
    apr_bucket *b;

    const char *data;
    apr_size_t length;

    apr_status_t status = APR_SUCCESS;

    assert(EVENT_SENDMAIL == sendmail->type);

    obb = sendmail->sendmail.obb;

    while (((b = APR_BRIGADE_FIRST(obb)) != APR_BRIGADE_SENTINEL(obb))) {

        int must_encode = 0;

        if (APR_BUCKET_IS_FILE(b)) {

            /* we cheat a bit, file buckets are converted to base64
             * encoding before we send them, ideally this is something
             * APR does on its own.
             */
        	if (b->length > 57) {
        		apr_bucket_split(b, 57);
        	}

            must_encode = 1;
        }

        if (APR_BUCKET_IS_EOS(b)) {

            /* once we reach here, we have finished writing to the client
             * and can close up this connection.
             */
            apr_file_printf(cd->err,
                    "connectcap[%d]: sending close to sendmail: %s\n",
                    sendmail->number, sendmail->sendmail.mail);

            /* swap events from write to not write */
            apr_pollset_remove(sendmail->cd->pollset, &sendmail->pfd);
            sendmail->pfd.reqevents &= ~APR_POLLOUT;
            apr_pollset_add(sendmail->cd->pollset, &sendmail->pfd);

            /* tell sendmail we are done */
            apr_file_close(sendmail->sendmail.fd);

            apr_bucket_delete(b);

            return APR_SUCCESS;
        }

        status = apr_bucket_read(b, &data, &length, APR_BLOCK_READ);

        if (APR_SUCCESS != status) {
            /* read attempt failed, give up */
            apr_file_printf(cd->err,
                    "connectcap[%d]: sendmail %s read %" APR_SIZE_T_FMT " bytes failed: %pm\n",
                    sendmail->number, sendmail->sendmail.mail, length, &status);

            apr_bucket_delete(b);

            apr_pool_destroy(sendmail->pool);

            return status;
        }

        if (length) {

            apr_size_t requested = length;

            if (must_encode) {
                char buf[76 + strlen(CRLF) + 1];

                apr_encode_base64(buf, data, length, APR_ENCODE_NONE, &length);
                strcpy(buf + length, CRLF);
                length += strlen(CRLF);

                status = apr_file_write(sendmail->sendmail.fd, buf, &length);
            }
            else {
                status = apr_file_write(sendmail->sendmail.fd, data, &length);
            }

            if (APR_STATUS_IS_EAGAIN(status)) {
                /* poll again */
                return status;
            }
            else if (APR_SUCCESS != status) {

                /* write attempt failed, give up */
                apr_file_printf(cd->err,
                        "connectcap[%d]: sendmail %s write %" APR_SIZE_T_FMT " bytes failed: %pm\n",
                        sendmail->number, sendmail->sendmail.mail, length, &status);

                apr_bucket_delete(b);

                apr_pool_destroy(sendmail->pool);

                return status;
            }
            else {

                if (cd->verbose) {
                    apr_file_printf(cd->err,
                            "connectcap[%d]: sendmail '%s' write %" APR_SIZE_T_FMT " bytes\n",
                            sendmail->number, sendmail->sendmail.mail, length);
                }

                sendmail->sendmail.bytes_written += length;
                sendmail->sendmail.writes++;
            }

            if (must_encode) {
                /* do nothing, we are already split */
            }
            else if (requested > length) {
                apr_bucket_split(b, length);
            }

        }

        apr_bucket_delete(b);
    }

    return APR_SUCCESS;
}

apr_status_t do_sendmail_hangup(connectcap_t* cd, event_t *sendmail)
{
    assert(EVENT_SENDMAIL == sendmail->type);

    apr_file_printf(cd->err,
            "connectcap[%d]: sendmail hung up\n",
            sendmail->number);

    apr_pool_destroy(sendmail->pool);

    return APR_EGENERAL;
}

int do_poll(connectcap_t* cd)
{
    apr_status_t status;
    int i;

    while (!cd->shutdown) {

        event_t *event;
        const apr_pollfd_t *out_pfd;
        apr_time_t now;
        apr_interval_time_t timeout = -1;
        apr_int32_t num = 0;

        event_verify(cd->events);

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
                    /* requests are not handled by the event loop */
                    assert(0);

                    break;
                }
                case EVENT_CONN: {

                    apr_file_printf(cd->err,
                            "connectcap[%d]: browser %pI timed out\n",
                            event->number, event->conn.sa);

                    apr_pool_destroy(event->pool);

                    break;
                }
                case EVENT_PUMP: {

                    apr_file_printf(cd->err,
                            "connectcap[%d]: origin %pI timed out\n",
                            event->number, event->pump.psa);

                    apr_pool_destroy(event->pool);

                    break;
                }
                case EVENT_CAPTURE: {

                    apr_file_printf(cd->err,
                            "connectcap[%d]: capture %s:%d finialised after pump shutdown\n",
                            event->number, event->capture.host, event->capture.port);

                    apr_pool_destroy(event->pool);

                    break;
                }
                case EVENT_SENDMAIL: {
                    /* sendmail should never have a timeout */
                    assert(0);

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
                    /* requests are not handled by the event loop */
                    assert(0);

                    break;
                }
                case EVENT_CONN: {

                    /* refresh the timeout */
                    event->when = now + apr_time_from_sec(DEFAULT_CONN_TIMEOUT);

                    event_reindex(cd->events);

                    if (pollfd->rtnevents & (APR_POLLHUP)) {
                        do_conn_hangup(cd, event);
                        continue;
                    }

                    if (pollfd->rtnevents & (APR_POLLOUT)) {
                        do_conn_write(cd, event);
                        continue;
                    }

                    if (pollfd->rtnevents & (APR_POLLIN)) {
                        do_conn_read(cd, event);
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
                case EVENT_SENDMAIL: {

                    if (pollfd->rtnevents & (APR_POLLHUP)) {
                        do_sendmail_hangup(cd, event);
                        continue;
                    }

                    if (pollfd->rtnevents & (APR_POLLOUT)) {
                        do_sendmail_write(cd, event);
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
                    "connectcap[%d]: apr_pollset_poll: %pm\n",
                    event->number, &status);
            return EXIT_FAILURE;
        }

    }

    return EXIT_SUCCESS;
}

int do_listen(connectcap_t* cd)
{
    apr_status_t status;
    int i;

    cd->events = apr_array_make(cd->pool, 64, sizeof(event_t *));

    status = apr_pollset_create(&cd->pollset, DEFAULT_POLLSOCKETS, cd->pool,
                                APR_POLLSET_NOCOPY | APR_POLLSET_WAKEABLE );
    if (status != APR_SUCCESS) {
        apr_file_printf(cd->err, "connectcap: cannot create pollset: %pm\n",
                &status);
        return EXIT_FAILURE;
    }

    for (i = 0; i < cd->listen->nelts; i++) {

        const char *arg = APR_ARRAY_IDX(cd->listen, i, const char *);

        apr_sockaddr_t *sa;
        char *host, *scope_id;
        apr_port_t port;

        int first = 1;

        status = apr_parse_addr_port(&host, &scope_id, &port, arg, cd->pool);
        if (status != APR_SUCCESS) {
            apr_file_printf(cd->err, "connectcap: cannot parse '%s': %pm\n", arg,
                    &status);
            return EXIT_FAILURE;
        }

        if (!port) {
            apr_file_printf(cd->err, "connectcap: port must be specified with '%s': %pm\n", arg,
                    &status);
            return EXIT_FAILURE;
        }

        if ((status = apr_sockaddr_info_get(&sa, host, APR_UNSPEC, port, 0,
                                            cd->pool))
            != APR_SUCCESS) {
            apr_file_printf(cd->err, "connectcap: sockaddr setup failed for '%s': %pm\n", arg,
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
                apr_file_printf(cd->err, "connectcap: socket create failed for '%s' (%pI): %pm\n", arg,
                        sa, &status);
                apr_pool_destroy(pool);
                return EXIT_FAILURE;
            }

            status = apr_socket_opt_set(sd, APR_SO_SNDBUF, DEFAULT_BUFFER_SIZE);
            if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
                apr_file_printf(cd->err, "connectcap: send buffer size cannot be set for '%s' (%pI): %pm\n", arg,
                        sa, &status);
                apr_pool_destroy(pool);
                return EXIT_FAILURE;
            }

            status = apr_socket_opt_set(sd, APR_SO_RCVBUF, DEFAULT_BUFFER_SIZE);
            if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
                apr_file_printf(cd->err, "connectcap: receive buffer size cannot be set for '%s' (%pI): %pm\n", arg,
                        sa, &status);
                apr_pool_destroy(pool);
                return EXIT_FAILURE;
            }

            status = apr_socket_opt_set(sd, APR_TCP_NODELAY, 1);
            if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
                apr_file_printf(cd->err, "connectcap: nagle cannot be disabled for '%s' (%pI): %pm\n", arg,
                        sa, &status);
                apr_pool_destroy(pool);
                return EXIT_FAILURE;
            }

            status = apr_socket_opt_set(sd, APR_SO_REUSEADDR, 1);
            if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
                apr_file_printf(cd->err, "connectcap: reuse address cannot be enabled for '%s' (%pI): %pm\n", arg,
                        sa, &status);
                apr_pool_destroy(pool);
                return EXIT_FAILURE;
            }

            status = apr_socket_opt_set(sd, APR_SO_NONBLOCK,  1);
            if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
                apr_file_printf(cd->err, "connectcap: non blocking cannot be set for '%s' (%pI): %pm\n", arg,
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
                apr_file_printf(cd->err, "connectcap: socket bind failed for '%s' (%pI): %pm\n", arg,
                        sa, &status);
                apr_pool_destroy(pool);
                return EXIT_FAILURE;
            }
            else {

                status = apr_socket_listen(sd, DEFAULT_LISTENBACKLOG);
                if ((status) != APR_SUCCESS) {
                    apr_file_printf(cd->err, "connectcap: socket listen failed for '%s' (%pI): %pm\n", arg,
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
                apr_file_printf(cd->err, "connectcap[%d]: skiplist size: %" APR_SIZE_T_FMT " event %pp\n",
                        event->number, apr_skiplist_size(cd->events), event);
                apr_skiplist_insert(cd->events, event);
                apr_file_printf(cd->err, "connectcap[%d]: skiplist size: %" APR_SIZE_T_FMT " event %pp\n",
                        event->number, apr_skiplist_size(cd->events), event);
#endif
                apr_pollset_add(cd->pollset, &event->pfd);

                apr_pool_cleanup_register(pool, event, cleanup_event,
                        apr_pool_cleanup_null);

                apr_file_printf(cd->err, "connectcap[%d]: '%s' listening to %pI\n",
                        event->number, arg, sa);

            }

            first = 0;

            sa = sa->next;
        }

    }

    return do_poll(cd);
}

connectcap_t cd = { 0 };

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

    signal(SIGPIPE, SIG_IGN);

    apr_file_open_stderr(&cd.err, cd.pool);
    apr_file_open_stdin(&cd.in, cd.pool);
    apr_file_open_stdout(&cd.out, cd.pool);

    cd.alloc = apr_bucket_alloc_create(cd.pool);

    cd.directory = DEFAULT_DIRECTORY;
    cd.passwd = DEFAULT_PASSWD_FILE;
    cd.realm = DEFAULT_REALM;

    cd.listen = apr_array_make(cd.pool, 2, sizeof(const char *));

    cd.clients = apr_pcalloc(cd.pool, DEFAULT_CLIENTS_SIZE * sizeof(client_t));

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
        case 'd': {
            cd.directory = optarg;
            break;
        }
        case 'i': {
            cd.interface = optarg;
            break;
        }
        case 'l': {
            const char **listen = apr_array_push(cd.listen);
            *listen = optarg;
            break;
        }
        case 'p': {
            cd.passwd = optarg;
            break;
        }
        case 'r': {
            cd.realm = optarg;
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

    if (!cd.listen->nelts) {
        return help(cd.err, argv[0], "At least one listen address/port must be specified.\n", EXIT_FAILURE, cmdline_opts);
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

    status = read_passwd(&cd);
    if (APR_EGENERAL == status) {
        /* already handled */
        return EXIT_FAILURE;
    }
    if (APR_SUCCESS != status) {
        apr_file_printf(cd.err, "connectcap: could not read users from '%s': %pm\n",
                cd.passwd, &status);
        return EXIT_FAILURE;
    }

    status = apr_filepath_set(cd.directory, cd.pool);
    if (APR_SUCCESS != status) {
        apr_file_printf(cd.err, "connectcap: could not change directory to '%s': %pm\n",
                cd.directory, &status);
        return EXIT_FAILURE;
    }

    cd.args = opt->argv + opt->ind;

    return do_listen(&cd);
}
