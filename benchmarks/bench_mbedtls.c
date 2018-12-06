//  Copyright (C) 2015-2018 Virgil Security Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

#include <mbedtls/ecp.h>
#include "benchmark/include/benchmark.h"

typedef struct params {
    mbedtls_ecp_group *group;
    mbedtls_ecp_point *P;
    mbedtls_mpi *m;
    mbedtls_ecp_point *R;

} params_t;

void benchmark_mbedtls_ecp_mul(void *data, size_t len) {
    params_t *params = data;

    mbedtls_ecp_mul(params->group, params->R, params->m, params->P, NULL, NULL);
}

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------

int main (void) {
    params_t params;

    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);

    mbedtls_mpi m;
    mbedtls_mpi_init(&m);

    mbedtls_mpi_read_string(&m, 10, "43706665579225183909865134322239684236977397686025563957189888324317762848330");

    mbedtls_ecp_point P;
    mbedtls_ecp_point_init(&P);

    mbedtls_ecp_point_read_string(&P, 10,
            "49166285642990312777312778351013119878896537776050488997315166935690363463787",
            "66983832439067043864623691503721372978034854603698954939248898067109763920732");


    mbedtls_ecp_point R;
    mbedtls_ecp_point_init(&R);

    params.P = &P;
    params.m = &m;
    params.group = &group;
    params.R = &R;

    benchmark(benchmark_mbedtls_ecp_mul, &params, 0, 1000);

    mbedtls_ecp_point_free(&P);
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&m);
}
