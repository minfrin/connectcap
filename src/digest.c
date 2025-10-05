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
 * digest.c
 *
 *  Created on: 05 Oct 2025
 *      Author: minfrin
 */

#include "connectcap.h"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <assert.h>

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

const char *calc_digest_binary(apr_pool_t *pool, digest_e digest, const unsigned char *data, apr_size_t len)
{

    switch (digest) {
    case DIGEST_SHA512: {
        unsigned char digest[SHA512_DIGEST_LENGTH];
        EVP_MD_CTX *mdctx;

        EVP_MD *md = EVP_MD_fetch(NULL, "SHA512", NULL);
        if (!md) {
            return NULL;
        }

        mdctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, data, len);
        EVP_DigestFinal_ex(mdctx, digest, NULL);

        return apr_pencode_base16_binary(pool, digest, SHA512_DIGEST_LENGTH, APR_ENCODE_LOWER, NULL);
    }
    case DIGEST_SHA512_256: {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        EVP_MD_CTX *mdctx;

        EVP_MD *md = EVP_MD_fetch(NULL, "SHA512-256", NULL);
        if (!md) {
            return NULL;
        }

        mdctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, data, len);
        EVP_DigestFinal_ex(mdctx, digest, NULL);

        return apr_pencode_base16_binary(pool, digest, SHA256_DIGEST_LENGTH, APR_ENCODE_LOWER, NULL);
    }
    case DIGEST_SHA256: {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        EVP_MD_CTX *mdctx;

        EVP_MD *md = EVP_MD_fetch(NULL, "SHA256", NULL);
        if (!md) {
            return NULL;
        }

        mdctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, data, len);
        EVP_DigestFinal_ex(mdctx, digest, NULL);

        return apr_pencode_base16_binary(pool, digest, SHA256_DIGEST_LENGTH, APR_ENCODE_LOWER, NULL);
    }
    case DIGEST_MD5: {
        unsigned char digest[APR_MD5_DIGESTSIZE];
        apr_md5_ctx_t mdctx;

        apr_md5_init(&mdctx);
        apr_md5_update(&mdctx, data, len);
        apr_md5_final(digest, &mdctx);

        return apr_pencode_base16_binary(pool, digest, APR_MD5_DIGESTSIZE, APR_ENCODE_LOWER, NULL);
    }
    case NO_DIGEST: {
        return NULL;
    }
    }

    return NULL;
}

const char *calc_digest(apr_pool_t *pool, digest_e digest, const char *data)
{
    return calc_digest_binary(pool, digest, (const unsigned char *)data, strlen(data));
}

static apr_status_t cleanup_users(void *dummy)
{
    users_t *users = dummy;

    users->cd->users = NULL;

    return APR_SUCCESS;
}

apr_status_t read_passwd(connectcap_t* cd)
{
    apr_pool_t *pool;
    apr_finfo_t finfo = { 0 };
    users_t *users = cd->users;
    apr_file_t *in;
    char *buf, *tok_state, *line;

    apr_off_t end = 0, start = 0;
    apr_size_t size;

    apr_status_t status;
    int count = 0;

    apr_pool_create(&pool, cd->pool);

    status = apr_stat(&finfo, cd->passwd, APR_FINFO_MTIME | APR_FINFO_GPROT | APR_FINFO_WPROT, pool);

    if (APR_SUCCESS != status) {
        apr_pool_destroy(pool);
        return status;
    }

    if (finfo.protection & (0xFF)) {
        apr_file_printf(cd->err, "connectcap: '%s' is group/world readable, ignoring\n",
                cd->passwd);

        return APR_EGENERAL;
    }

    if (users) {

        /* no change in file? */
        if (finfo.mtime == users->mtime) {
            return APR_SUCCESS;
        }

        apr_pool_destroy(users->pool);
    }

    users = apr_pcalloc(pool, sizeof(users_t));
    users->cd = cd;
    users->pool = pool;
    users->mtime = finfo.mtime;
    users->users = apr_hash_make(pool);

    apr_pool_cleanup_register(pool, users, cleanup_users,
            apr_pool_cleanup_null);

    cd->users = users;

    /* open the file */
    if (APR_SUCCESS
            != (status = apr_file_open(&in, cd->passwd, APR_FOPEN_READ,
                    APR_FPROT_OS_DEFAULT, pool))) {
        apr_pool_destroy(pool);
        return status;
    }

    /* how long is the file? */
    else if (APR_SUCCESS
            != (status = apr_file_seek(in, APR_END, &end))) {
        apr_pool_destroy(pool);
        return status;
    }

    /* back to the beginning */
    else if (APR_SUCCESS
            != (status = apr_file_seek(in, APR_SET, &start))) {
        apr_pool_destroy(pool);
        return status;
    }

    buf = apr_palloc(pool, end + 1);
    buf[end] = 0;

    if (APR_SUCCESS
            != (status = apr_file_read_full(in, buf, end, &size))) {
        memset(buf, 0, end);
        apr_pool_destroy(pool);
        return status;
    }

    /*
     * The passwd file has the following format:
     *
     * user:password:email address
     */

    for (line = apr_strtok(buf, CRLF, &tok_state);
         line;
         line = apr_strtok(NULL, CRLF, &tok_state)) {

        char *username, *password = NULL, *mail = NULL;
        char *a1, *u;
        user_t *user;

        apr_size_t plen;

        if (line[0] == '#') {
            continue;
        }

        username = line;
        password = strchr(username, ':');
        if (password) {
            *password = 0;
            password++;
            mail = strrchr(password, ':');
        }
        if (mail) {
            *mail = 0;
            mail++;
        }

        if (!username || !password || !mail) {
            continue;
        }

        plen = strlen(password);
        if (plen < PASSWORD_MIN) {
            apr_file_printf(cd->err,
                    "connectcap: user '%s' password too short (%" APR_SIZE_T_FMT "<%" APR_SIZE_T_FMT "), ignoring\n",
                    username, plen, (apr_size_t)PASSWORD_MIN);

            continue;
        }

        user = apr_pcalloc(pool, sizeof(user_t));
        user->username = apr_pstrdup(pool, username);
        user->mail = apr_pstrdup(pool, mail);

        a1 = apr_pstrcat(pool, username, ":", cd->realm, ":", password, NULL);
        u = apr_pstrcat(pool, username, ":", cd->realm, NULL);

        user->ha1[DIGEST_SHA512_256] = calc_digest(pool, DIGEST_SHA512_256, a1);
           user->ha1[DIGEST_SHA256] = calc_digest(pool, DIGEST_SHA256, a1);
           user->ha1[DIGEST_MD5] = calc_digest(pool, DIGEST_MD5, a1);

        user->hu[DIGEST_SHA512_256] = calc_digest(pool, DIGEST_SHA512_256, u);
           user->hu[DIGEST_SHA256] = calc_digest(pool, DIGEST_SHA256, u);
           user->hu[DIGEST_MD5] = calc_digest(pool, DIGEST_MD5, u);

           memset(a1, 0, strlen(a1));

        apr_hash_set(users->users, user->username, APR_HASH_KEY_STRING, user);
        apr_hash_set(users->users, user->hu[DIGEST_SHA512_256], APR_HASH_KEY_STRING, user);
        apr_hash_set(users->users, user->hu[DIGEST_SHA256], APR_HASH_KEY_STRING, user);
        apr_hash_set(users->users, user->hu[DIGEST_MD5], APR_HASH_KEY_STRING, user);

        count++;
    }

    /* zero out the buffer */
    memset(buf, 0, end);

    apr_file_printf(cd->err, "connectcap: read %d users from: %s\n",
            count, cd->passwd);

    return APR_SUCCESS;
}

apr_status_t make_proxy_authenticate(connectcap_t* cd, event_t *request)
{
    const char **authenticate;
    const char *opaque;
    char nonce[NONCE_LEN + 1];
    client_t *client;
    time_rec t;
    int index;

    unsigned char digest[SHA512_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx;

    const char *stale = request->request.stale ? "true" : "false";

    EVP_MD *md = EVP_MD_fetch(NULL, "SHA512", NULL);

    assert(md);
    assert(EVENT_REQUEST == request->type);

    t.time = request->timestamp;

    apr_encode_base64_binary(nonce, t.arr, sizeof(t.arr), APR_ENCODE_NONE, NULL);

    /*
     * Opaque is a counter, generate the next count
     */
    opaque = apr_ltoa(request->pool, (long)cd->opaque_counter);
    index = cd->opaque_counter % DEFAULT_CLIENTS_SIZE;
    client = &cd->clients[index];
    client->opaque_counter = cd->opaque_counter;
    client->minimum_nc = 0;

    cd->opaque_counter++;

    /*
     * The nonce has meaning to us only, not the client, so we
     * can use the highest digest we support.
     */

    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, cd->realm, strlen(cd->realm));
    EVP_DigestUpdate(mdctx, t.arr, sizeof(t.arr));
    EVP_DigestUpdate(mdctx, opaque, strlen(opaque));
    EVP_DigestFinal_ex(mdctx, digest, NULL);

    apr_encode_base16_binary(nonce + NONCE_TIME_LEN, digest, sizeof(digest), APR_ENCODE_LOWER, NULL);

    nonce[NONCE_LEN] = 0;

    /* we support all three digest types, starting with SHA-512-256 */
    authenticate = apr_array_push(request->request.authenticate);
    *authenticate = apr_psprintf(request->pool, "Digest "
            "realm=\"%s\","
            "qop=\"auth\","
            "algorithm=SHA-512-256,"
            "nonce=\"%s\","
            "stale=%s,"
            "opaque=\"%s\","
            "userhash=false", cd->realm, nonce, stale, opaque);

    apr_file_printf(cd->err,
            "connectcap[%d]: request authenticate: %s\n",
            request->number, *authenticate);

    /* followed bv SHA-256 */
    authenticate = apr_array_push(request->request.authenticate);
    *authenticate = apr_psprintf(request->pool, "Digest "
            "realm=\"%s\","
            "qop=\"auth\","
            "algorithm=SHA-256,"
            "nonce=\"%s\","
            "stale=%s,"
            "opaque=\"%s\","
            "userhash=false", cd->realm, nonce, stale, opaque);

    apr_file_printf(cd->err,
            "connectcap[%d]: request authenticate: %s\n",
            request->number, *authenticate);

    /* lastly the venerable MD5 */
    authenticate = apr_array_push(request->request.authenticate);
    *authenticate = apr_psprintf(request->pool, "Digest "
            "realm=\"%s\","
            "qop=\"auth\","
            "algorithm=MD5,"
            "nonce=\"%s\","
            "stale=%s,"
            "opaque=\"%s\","
            "userhash=false", cd->realm, nonce, stale, opaque);

    apr_file_printf(cd->err,
            "connectcap[%d]: request authenticate: %s\n",
            request->number, *authenticate);

    return APR_SUCCESS;
}

apr_status_t parse_proxy_authorization(connectcap_t* cd, event_t *request, char *buf)
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

    user_t *user;
    client_t *client;

    apr_uint64_t opaque_counter;
    apr_uint64_t actual_nc;
    int index;
    digest_e digest = NO_DIGEST;

    int len;

    assert(EVENT_REQUEST == request->type);

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

    if (*tok_state) {
        apr_file_printf(cd->err,
                "connectcap[%d]: parse authenticate: %s\n",
                request->number, tok_state);
    }

    while ((kv = connectcap_strqtok(NULL, ", ", &tok_state))) {
        char *kv_state;

        char *key, *value;

        key = apr_strtok(kv, "=", &kv_state);
        value = apr_strtok(NULL, "", &kv_state);

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
                "connectcap[%d]: browser %pI: username is missing, auth denied\n",
                request->number, request->request.sa);

        request->request.not_authenticated = "Username is missing\n";
        return APR_SUCCESS;
    }

    /* realm must match */
    if (!realm || strcmp(cd->realm, realm)) {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: realm '%s' does not match '%s' for username '%s', auth denied\n",
                request->number, request->request.sa, realm, cd->realm, username);

        request->request.not_authenticated = "Realm does not match\n";
        return APR_SUCCESS;
    }

    /* uri must match address */
    if (!uri || strcmp(request->request.address, uri)) {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: uri '%s' does not match '%s' for username '%s', auth denied\n",
                request->number, request->request.sa, uri, request->request.address, username);

        request->request.not_authenticated = "URI does not match\n";
        return APR_SUCCESS;
    }

    /* algorithm must be present */
    if (!algorithm) {
        digest = DIGEST_MD5;
    }
    else if (!strcmp("SHA-512-256", algorithm)) {
        digest = DIGEST_SHA512_256;
    }
    else if (!strcmp("SHA-256", algorithm)) {
        digest = DIGEST_SHA256;
    }
    else if (!strcmp("MD5", algorithm)) {
        digest = DIGEST_MD5;
    }
    else {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: algorithm '%s' does not match 'SHA-512-256', 'SHA-256', 'MD5' for username '%s', auth denied\n",
                request->number, request->request.sa, algorithm, username);

        request->request.not_authenticated = "Algorithm is not one of 'SHA-512-256', 'SHA-256', 'MD5'\n";
        return APR_SUCCESS;
    }

    /* opaque must be present */
    if (!opaque) {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: opaque is missing for username '%s', auth denied\n",
                request->number, request->request.sa, username);

        request->request.not_authenticated = "Opaque is missing\n";
        return APR_SUCCESS;
    }

    /* opaque must be numeric and base 10 */
    opaque_counter = apr_strtoi64(opaque, NULL, 10);
    if (APR_SUCCESS != errno) {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: opaque '%s' not numeric for username '%s', auth denied\n",
                request->number, request->request.sa, opaque, username);

        request->request.not_authenticated = "Opaque is not numeric\n";
        return APR_SUCCESS;
    }

    /* nonce must be present */
    if (!nonce) {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: nonce is missing for username '%s', auth denied\n",
                request->number, request->request.sa, username);

        request->request.not_authenticated = "Nonce is missing\n";
        return APR_SUCCESS;
    }
    /* nonce must be correct length */
    else if (NONCE_LEN != (len = strlen(nonce))) {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: nonce is wrong length (%d != %d) for username '%s', auth denied\n",
                request->number, request->request.sa, NONCE_LEN, len, username);

        request->request.not_authenticated = "Nonce is wrong length\n";
        return APR_SUCCESS;
    }
    /* nonce must decode correctly */
    else {
        unsigned char digest1[SHA512_DIGEST_LENGTH];
        unsigned char digest2[SHA512_DIGEST_LENGTH];
        EVP_MD_CTX *mdctx;
        EVP_MD *md = EVP_MD_fetch(NULL, "SHA512", NULL);

        time_rec t;

        assert(md);

        apr_decode_base64_binary(t.arr, nonce, NONCE_TIME_LEN, APR_ENCODE_NONE, NULL);

        mdctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, cd->realm, strlen(cd->realm));
        EVP_DigestUpdate(mdctx, t.arr, sizeof(t.arr));
        EVP_DigestUpdate(mdctx, opaque, strlen(opaque));
        EVP_DigestFinal_ex(mdctx, digest1, NULL);

        apr_decode_base16_binary(digest2, nonce + NONCE_TIME_LEN, NONCE_HASH_LEN, APR_ENCODE_LOWER, NULL);

        /* nonce digest must match computed digest */
        if (memcmp(digest1, digest2, sizeof(digest1))) {
            apr_file_printf(cd->err,
                    "connectcap[%d]: browser %pI: nonce digest mismatch (stale) for username '%s', auth denied\n",
                    request->number, request->request.sa, username);

            request->request.not_authenticated = "Nonce digest mismatch\n";
            request->request.stale = 1;
            return APR_SUCCESS;
        }

    }

    /* nonce count must be present */
    if (!nc) {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: nc is missing for username '%s', auth denied\n",
                request->number, request->request.sa, username);

        request->request.not_authenticated = "Nonce count is missing\n";
        return APR_SUCCESS;
    }

    /* nc must be numeric and base 16 */
    actual_nc = apr_strtoi64(nc, NULL, 16);
    if (APR_SUCCESS != errno) {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: nc '%s' not numeric for username '%s', auth denied\n",
                request->number, request->request.sa, nc, username);

        request->request.not_authenticated = "NC is not numeric\n";
        return APR_SUCCESS;
    }

    /* cnonce must be present */
    if (!cnonce) {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: cnonce is missing for username '%s', auth denied\n",
                request->number, request->request.sa, username);

        request->request.not_authenticated = "Client nonce is missing\n";
        return APR_SUCCESS;
    }

    /* qop must be auth */
    if (!qop || strcmp("auth", qop)) {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: qop '%s' does not match 'auth' for username '%s', auth denied\n",
                request->number, request->request.sa, qop, username);

        request->request.not_authenticated = "QOP is not 'auth'\n";
        return APR_SUCCESS;
    }

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
                "connectcap[%d]: browser %pI: userhash '%s' not recognised for username '%s', auth denied\n",
                request->number, request->request.sa, userhash, username);

        request->request.not_authenticated = "Userhash not recognised\n";
        return APR_SUCCESS;
    }

    /* username must exist */
    user = apr_hash_get(cd->users->users, username, APR_HASH_KEY_STRING);
    if (!user) {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: user '%s' not found (password incorrect), auth denied\n",
                request->number, request->request.sa, username);

        request->request.not_authenticated = "Password incorrect\n";
        return APR_SUCCESS;
    }

    /* response must be present */
    if (!response) {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: response is missing for username '%s', auth denied\n",
                request->number, request->request.sa, username);

        request->request.not_authenticated = "Response is missing\n";
        return APR_SUCCESS;
    }
    else if ((len = strlen(response)) &&
            !((DIGEST_SHA512_256 == digest && SHA256_DIGEST_LENGTH*2 == len) ||
            (DIGEST_SHA256 == digest && SHA256_DIGEST_LENGTH*2 == len) ||
            (DIGEST_MD5 == digest && APR_MD5_DIGESTSIZE*2 == len))) {

        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: response has wrong length (%d) for username '%s', auth denied\n",
                request->number, request->request.sa, len, username);

        request->request.not_authenticated = "Response is wrong length\n";
        return APR_SUCCESS;
    }

    /* check response */
    else {
        const char *ha1, *ha2, *a2, *r;

        ha1 = user->ha1[digest];

        a2 = apr_pstrcat(request->pool, request->request.method,
                ":",
                request->request.address,
                NULL);

        ha2 = calc_digest(request->pool, digest, a2);

        r = calc_digest(request->pool, digest,
                      apr_pstrcat(request->pool, ha1, ":", nonce,
                                  ":", nc, ":",
                                  cnonce, ":",
                                  qop, ":", ha2,
                                  NULL));

        /* response digest must match computed digest */
        if (strcmp(r, response)) {
            apr_file_printf(cd->err,
                    "connectcap[%d]: browser %pI: response mismatch for username '%s' (password incorrect), auth denied\n",
                    request->number, request->request.sa, username);

            request->request.not_authenticated = "Password incorrect\n";
            return APR_SUCCESS;
        }

    }

    /* check the nc value, but after we checked the password */

    index = opaque_counter % DEFAULT_CLIENTS_SIZE;
    client = &cd->clients[index];
    if (opaque_counter != client->opaque_counter) {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: nonce stale (%" APR_UINT64_T_FMT "!=%" APR_UINT64_T_FMT ") for username '%s', auth denied\n",
                request->number, request->request.sa, opaque_counter, client->opaque_counter, username);

        request->request.not_authenticated = "Nonce is stale\n";
        request->request.stale = 1;
        return APR_SUCCESS;
    }

    if (actual_nc <= client->minimum_nc) {
        apr_file_printf(cd->err,
                "connectcap[%d]: browser %pI: nc mismatch (%" APR_UINT64_T_FMT "<=%" APR_UINT64_T_FMT ") for username '%s', auth denied\n",
                request->number, request->request.sa, actual_nc, client->minimum_nc, username);

        request->request.not_authenticated = "Nonce is stale\n";
        request->request.stale = 1;
        return APR_SUCCESS;
    }

    client->minimum_nc = actual_nc;

    /* if we got this far, we're in! */
    request->request.username = apr_pstrdup(request->pool, user->username);
    request->request.mail = apr_pstrdup(request->pool, user->mail);
    request->request.not_authenticated = NULL;

    return APR_SUCCESS;
}

