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

#include <PHEModels.pb.h>
#include <virgil/crypto/foundation/vscf_random.h>
#include "benchmark/include/benchmark.h"

#include "virgil/crypto/foundation/private/vscf_ctr_drbg_impl.h"
#include "vsce_phe_server.h"
#include "vsce_phe_server_defs.h"
#include "vsc_buffer_defs.h"

#define TEST_DEPENDENCIES_AVAILABLE VSCE_PHE_SERVER
#if TEST_DEPENDENCIES_AVAILABLE

typedef struct params {
    vsce_phe_server_t *server;
    vsc_buffer_t *server_private_key;
    vsc_buffer_t *server_public_key;
} params_t;

static void init(params_t *params) {
    params->server = vsce_phe_server_new();

    params->server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    params->server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    vsce_phe_server_generate_server_key_pair(params->server, params->server_private_key, params->server_public_key);
}

void benchmark__phe_server__gen_enrollment(void *v_params, size_t data_size) {
    params_t *params = v_params;

    byte buffer[1000];

    vsc_buffer_t enrollment_response;
    vsc_buffer_init(&enrollment_response);
    vsc_buffer_use(&enrollment_response, buffer, sizeof(buffer));

//    = vsc_buffer_new_with_capacity(vsce_phe_server_enrollment_response_len(params->server));
    vsce_phe_server_get_enrollment(params->server, vsc_buffer_data(params->server_private_key),
                                            vsc_buffer_data(params->server_public_key), &enrollment_response);

    vsc_buffer_delete(&enrollment_response);
}

void benchmark__phe_server__generate_keys(void *v_params, size_t data_size) {
    params_t *params = v_params;

    byte pub[vsce_phe_common_PHE_PUBLIC_KEY_LENGTH];
    byte priv[vsce_phe_common_PHE_PRIVATE_KEY_LENGTH];

    vsc_buffer_t pub_buff, priv_buff;
    vsc_buffer_init(&pub_buff);
    vsc_buffer_init(&priv_buff);
    vsc_buffer_use(&pub_buff, pub, sizeof(pub));
    vsc_buffer_use(&priv_buff, priv, sizeof(priv));

    vsce_phe_server_generate_server_key_pair(params->server, &priv_buff, &pub_buff);

    vsc_buffer_delete(&priv_buff);
    vsc_buffer_delete(&pub_buff);
}

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------

int main (void) {
    params_t params;

    init(&params);

    benchmark(benchmark__phe_server__gen_enrollment, &params, 0, 100);

//    benchmark(benchmark__phe_server__generate_keys, &params, 0, 100);

    vsce_phe_server_destroy(&params.server);

    vsc_buffer_destroy(&params.server_private_key);
    vsc_buffer_destroy(&params.server_public_key);
}

#endif