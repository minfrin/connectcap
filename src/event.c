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
 * event.c
 *
 *  Created on: 05 Oct 2025
 *      Author: minfrin
 */

#include "connectcap.h"

#include <assert.h>

void event_verify(apr_array_header_t *events)
{
    int i;

    for (i = 0; i < events->nelts; i++) {
        event_t *e = APR_ARRAY_IDX(events, i, event_t *);

        switch(e->type) {
        case EVENT_LISTEN:
        case EVENT_CONN:
        case EVENT_PUMP:
        case EVENT_CAPTURE:
            break;
        default:
            /* bogus elements */
            assert(0);
        }

    }
}

int event_remove(apr_array_header_t *events, event_t *event)
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

int event_cmp(const void *a, const void *b)
{
    const event_t *ea = a;
    const event_t *eb = b;

    apr_time_t t1 = (apr_time_t) ea->when;
    apr_time_t t2 = (apr_time_t) eb->when;

    return ((t1 > t2) ? -1 : 1);
}

void event_reindex(apr_array_header_t *events)
{
    event_verify(events);

    qsort(events->elts, events->nelts, sizeof(event_t *),
          event_cmp);

    event_verify(events);
}

void event_add(apr_array_header_t *events, event_t *event)
{
    event_t **e = apr_array_push(events);

    *e = event;

    event_reindex(events);

    event_verify(events);
}

event_t *event_peek(apr_array_header_t *events)
{
    event_verify(events);

    if (events->nelts) {
        return APR_ARRAY_IDX(events, events->nelts - 1, event_t *);
    }
    return NULL;
}

