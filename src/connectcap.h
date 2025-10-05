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

/*
 * connectcap.h
 *
 *  Created on: 05 Oct 2025
 *      Author: minfrin
 */

#ifndef SRC_CONNECTCAP_H_
#define SRC_CONNECTCAP_H_

#include "config.h"

#include <apr.h>
#include <apr_buckets.h>
#include <apr_encode.h>
#include <apr_file_io.h>
#include <apr_file_info.h>
#include <apr_getopt.h>
#include <apr_hash.h>
#include <apr_md5.h>
#include <apr_network_io.h>
#include <apr_poll.h>
#include <apr_pools.h>
#include <apr_portable.h>
#include <apr_tables.h>
#include <apr_strings.h>

#include <pcap/pcap.h>

#define DEFAULT_BUFFER_SIZE 1 * 1024 * 1024
#define DEFAULT_LISTENBACKLOG 511
#define DEFAULT_POLLSOCKETS 10240
#define DEFAULT_CONN_TIMEOUT 60
#define DEFAULT_PUMP_TIMEOUT 60
#define DEFAULT_CAPTURE_TIMEOUT 2
#define DEFAULT_PCAP_DEVICE "any"
#define DEFAULT_PCAP_SNAPLEN 65536
#define DEFAULT_DIRECTORY "."
#define DEFAULT_PASSWD_FILE "ccpasswd"
#define DEFAULT_REALM "connectcap"
#define DEFAULT_CLIENTS_SIZE 16384

#define PASSWORD_MIN 16

#define HUGE_STRING_LEN 8192

#define CRLF "\015\012"

#define NONCE_TIME_LEN  (((sizeof(apr_time_t)+2)/3)*4)
#define NONCE_HASH_LEN  (2*SHA512_DIGEST_LENGTH)
#define NONCE_LEN       (int )(NONCE_TIME_LEN + NONCE_HASH_LEN)

typedef enum prefer_e {
    NO_PREFERENCE,
    PREFER_IPV4,
    PREFER_IPV6,
} prefer_e;

typedef enum digest_e {
    NO_DIGEST,
    DIGEST_SHA512,
    DIGEST_SHA512_256,
    DIGEST_SHA256,
    DIGEST_MD5, /* yuck, MacOS/iOS still forces this */
} digest_e;

#define DIGEST_LEN 5

struct connectcap_t;

typedef struct users_t {
    apr_pool_t *pool;
    struct connectcap_t *cd;
    apr_time_t mtime;
    apr_hash_t *users;
} users_t;

typedef struct user_t {
    apr_time_t mtime;
    const char *username;
    const char *hu[DIGEST_LEN];
    const char *ha1[DIGEST_LEN];
    const char *mail;
} user_t;

typedef struct client_t {
    apr_uint64_t opaque_counter;
    apr_uint64_t minimum_nc;
} client_t;

typedef struct connectcap_t {
    apr_pool_t *pool;
    apr_pool_t *tpool;
    apr_file_t *err;
    apr_file_t *in;
    apr_file_t *out;
    const char *laddr4;
    const char *laddr6;
    const char *interface;
    const char *realm;
    const char *directory;
    const char *passwd;
    const char **args;
    users_t *users;
    apr_array_header_t *listen;
    apr_array_header_t *events;
    apr_pollset_t *pollset;
    apr_bucket_alloc_t *alloc;
    client_t *clients;
    apr_uint64_t opaque_counter;
    int numbers;
    prefer_e prefer;
    apr_int32_t family;
    apr_int32_t flags;
    int verbose;
    int shutdown;
} connectcap_t;

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
     * Method we used, should always be CONNECT
     */
    char *method;

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
     * Proxy-Authenticate header(s) to be sent to browser
     */
    apr_array_header_t *authenticate;

    /**
     * Message to be included with 407 response
     */
    const char *not_authenticated;

    /**
     * Username of the successfully logged in user
     */
    const char *username;

    /**
     * Mail address of the successfully logged in user
     */
    const char *mail;

    /**
     * Is the username hashed by the client?
     */
    unsigned int userhash:1;

    /**
     * Is the nonce stale?
     */
    unsigned int stale:1;

    /**
     * The connection associated with the request
     */
    struct event_t *conn;

    /**
     * The request number
     */
    int number;
} request_t;

typedef struct conn_t {
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
     * The request associated with the connection
     */
    struct event_t *request;

    /**
     * The pump associated with the connection
     */
    struct event_t *pump;

    /**
     * The number of requests so far on this connection
     */
    int requests;

    /**
     * The number of bytes written to browser
     */
    apr_size_t bytes_written;

    /**
     * The number of bytes read from browser
     */
    apr_size_t bytes_read;

    /**
     * Number of successful writes to browser
     */
    int writes;

    /**
     * Number of successful reads from browser
     */
    int reads;
} conn_t;

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
     * The connection that spawned this pump
     */
    struct event_t *conn;

    /**
     * The capture that was spawned by this pump
     */
    struct event_t *capture;

    /**
     * The number of bytes written to origin
     */
    apr_size_t bytes_written;

    /**
     * The number of bytes read from origin
     */
    apr_size_t bytes_read;

    /**
     * Number of successful writes to origin
     */
    int writes;

    /**
     * Number of successful reads from origin
     */
    int reads;
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
    EVENT_CONN,
    EVENT_REQUEST,
    EVENT_PUMP,
    EVENT_CAPTURE,
} event_e;

typedef struct event_t {
    connectcap_t *cd;
    apr_pool_t *pool;
    apr_time_t timestamp;
    apr_time_t when;
    apr_pollfd_t pfd;
    int number;
    event_e type;
    union {
        listen_t listen;
        conn_t conn;
        request_t request;
        pump_t pump;
        capture_t capture;
    };
} event_t;

typedef union time_union {
    apr_time_t    time;
    unsigned char arr[sizeof(apr_time_t)];
} time_rec;

apr_status_t make_proxy_authenticate(connectcap_t* cd, event_t *request);
apr_status_t parse_proxy_authorization(connectcap_t* cd, event_t *request, char *buf);

apr_status_t read_passwd(connectcap_t* cd);

#endif /* SRC_CONNECTCAP_H_ */
