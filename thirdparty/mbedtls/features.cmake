#   @license
#   -------------------------------------------------------------------------
#   Copyright (C) 2015-2018 Virgil Security Inc.
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#       (1) Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#       (2) Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#       (3) Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
#   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
#   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.
#
#   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#   -------------------------------------------------------------------------

#   @warning
#   -------------------------------------------------------------------------
#   This file is fully generated by script 'cmake_files_codegen.gsl'.
#   It can be changed temporary for debug purposes only.
#   -------------------------------------------------------------------------
#   @end


include_guard()

option(MBEDTLS_SHA256_C "" ON)
option(MBEDTLS_SHA512_C "" ON)
option(MBEDTLS_CIPHER_C "" ON)
option(MBEDTLS_AES_C "" ON)
option(MBEDTLS_GCM_C "" ON)
option(MBEDTLS_MD_C "" ON)
option(MBEDTLS_BIGNUM_C "" ON)
option(MBEDTLS_RSA_C "" ON)
option(MBEDTLS_CTR_DRBG_C "" ON)
option(MBEDTLS_ENTROPY_C "" ON)
option(MBEDTLS_SHA256_ALT "" OFF)
option(MBEDTLS_SHA512_ALT "" OFF)
option(MBEDTLS_AES_ALT "" OFF)
option(MBEDTLS_GCM_ALT "" OFF)
mark_as_advanced(
        MBEDTLS_SHA256_C
        MBEDTLS_SHA512_C
        MBEDTLS_CIPHER_C
        MBEDTLS_AES_C
        MBEDTLS_GCM_C
        MBEDTLS_MD_C
        MBEDTLS_BIGNUM_C
        MBEDTLS_RSA_C
        MBEDTLS_CTR_DRBG_C
        MBEDTLS_ENTROPY_C
        MBEDTLS_SHA256_ALT
        MBEDTLS_SHA512_ALT
        MBEDTLS_AES_ALT
        MBEDTLS_GCM_ALT
        )

if(MBEDTLS_RSA_C AND NOT MBEDTLS_BIGNUM_C)
    message("-- error --")
    message("--")
    message("Feature MBEDTLS_RSA_C depends on the feature:")
    message("     MBEDTLS_BIGNUM_C - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(MBEDTLS_CTR_DRBG_C AND NOT MBEDTLS_ENTROPY_C)
    message("-- error --")
    message("--")
    message("Feature MBEDTLS_CTR_DRBG_C depends on the feature:")
    message("     MBEDTLS_ENTROPY_C - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(MBEDTLS_ENTROPY_C AND NOT MBEDTLS_SHA256_C AND NOT MBEDTLS_SHA512_C)
    message("-- error --")
    message("--")
    message("Feature MBEDTLS_ENTROPY_C depends on one of the features:")
    message("     MBEDTLS_SHA256_C, MBEDTLS_SHA512_C - which are disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(MBEDTLS_SHA256_ALT AND NOT MBEDTLS_SHA256_C)
    message("-- error --")
    message("--")
    message("Feature MBEDTLS_SHA256_ALT depends on the feature:")
    message("     MBEDTLS_SHA256_C - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(MBEDTLS_SHA512_ALT AND NOT MBEDTLS_SHA512_C)
    message("-- error --")
    message("--")
    message("Feature MBEDTLS_SHA512_ALT depends on the feature:")
    message("     MBEDTLS_SHA512_C - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(MBEDTLS_AES_ALT AND NOT MBEDTLS_AES_C)
    message("-- error --")
    message("--")
    message("Feature MBEDTLS_AES_ALT depends on the feature:")
    message("     MBEDTLS_AES_C - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(MBEDTLS_GCM_ALT AND NOT MBEDTLS_GCM_C)
    message("-- error --")
    message("--")
    message("Feature MBEDTLS_GCM_ALT depends on the feature:")
    message("     MBEDTLS_GCM_C - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()
