//  Copyright (C) 2015-2019 Virgil Security, Inc.
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

#include "test_data_ratchet_session.h"

const byte test_ratchet_session_alice_identity_private_key_BYTES[] = {
        0x0f, 0xc4, 0x6d, 0x9e, 0x04, 0x49, 0xd7, 0x90,
        0xcb, 0x64, 0xd6, 0xe4, 0xb3, 0x83, 0x24, 0xe9,
        0x5a, 0x70, 0x88, 0xb0, 0x36, 0xea, 0x5b, 0x37,
        0xac, 0x7a, 0x8b, 0x50, 0x3f, 0x8a, 0xec, 0xb9,
};

const byte test_ratchet_session_bob_identity_private_key_BYTES[] = {
        0x1f, 0xf1, 0x32, 0x35, 0xb0, 0xbe, 0x13, 0xa9,
        0x91, 0xcd, 0xa7, 0xd4, 0x0f, 0x8b, 0x56, 0xb5,
        0xf8, 0x27, 0xaf, 0x54, 0x1a, 0x05, 0x06, 0xe9,
        0x05, 0x6f, 0x45, 0x54, 0x1a, 0x95, 0xd8, 0x28,
};

const byte test_ratchet_session_bob_longterm_private_key_BYTES[] = {
        0xee, 0x8a, 0xc3, 0x6c, 0xa3, 0x2a, 0xd1, 0xbf,
        0xed, 0x76, 0xca, 0x49, 0x4d, 0xda, 0x95, 0xbe,
        0x18, 0x24, 0x79, 0x43, 0x6e, 0x2f, 0xf9, 0x19,
        0x2a, 0x54, 0xb2, 0xad, 0x64, 0x9d, 0x2d, 0x68,
};

const byte test_ratchet_session_bob_onetime_private_key_BYTES[] = {
        0xf3, 0xd9, 0x47, 0x7c, 0x91, 0x27, 0x2c, 0xa0,
        0x0f, 0x9f, 0x9a, 0x5c, 0x07, 0x02, 0x05, 0xc1,
        0x39, 0x2b, 0x1c, 0xf6, 0x24, 0x11, 0xb1, 0x9e,
        0x6e, 0x07, 0x24, 0x3f, 0xf6, 0xdf, 0x58, 0xe2,
};

const vsc_data_t test_ratchet_session_alice_identity_private_key = {
        test_ratchet_session_alice_identity_private_key_BYTES, sizeof(test_ratchet_session_alice_identity_private_key_BYTES)
};

const vsc_data_t test_ratchet_session_bob_identity_private_key = {
        test_ratchet_session_bob_identity_private_key_BYTES, sizeof(test_ratchet_session_bob_identity_private_key_BYTES)
};

const vsc_data_t test_ratchet_session_bob_longterm_private_key = {
        test_ratchet_session_bob_longterm_private_key_BYTES, sizeof(test_ratchet_session_bob_longterm_private_key_BYTES)
};

const vsc_data_t test_ratchet_session_bob_onetime_private_key = {
        test_ratchet_session_bob_onetime_private_key_BYTES, sizeof(test_ratchet_session_bob_onetime_private_key_BYTES)
};
