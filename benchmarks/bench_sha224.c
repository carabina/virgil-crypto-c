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

#include "vscf_hash_info.h"
#include "vscf_hash.h"
#include "vscf_hash_stream.h"
#include "vscf_sha224.h"
#include "vscf_assert.h"
#include "vscf_hash_api.h"
#include "vscf_hash_stream.h"

#include "data/include/bench_data_sha224.h"
#include "benchmark/include/benchmark.h"

// --------------------------------------------------------------------------
// Test implementation helpers & lifecycle functions.
// --------------------------------------------------------------------------

void benchmark_sha224_native(void *data, size_t data_size)
{
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha224_DIGEST_LEN);

    vscf_sha224_hash(*(vsc_data_t *)data, digest);

    vsc_buffer_destroy(&digest);
}

void benchmark_sha224_interface(void * data, size_t data_size)
{
    vscf_impl_t *impl = vscf_sha224_impl (vscf_sha224_new ());
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha224_DIGEST_LEN);

    vscf_hash_stream_start (impl);
    vscf_hash_stream_update (impl, *(vsc_data_t *)data);
    vscf_hash_stream_finish (impl, digest);

    vsc_buffer_destroy(&digest);
    vscf_impl_destroy (&impl);
}

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------

int main (void) {
    benchmark2(benchmark_sha224_native,"SHA224 (native)",benchmark_sha224_interface,"(interface)",(void*)&test_sha224_VECTOR_1_DIGEST, 0, 1000000);
}
