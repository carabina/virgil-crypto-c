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

if(NOT TARGET foundation)
    message(FATAL_ERROR "Expected target 'foundation' to be defined first.")
endif()

target_compile_definitions(foundation
        PUBLIC
            $<BUILD_INTERFACE:VSCF_BUILD_INTERFACE>
            "VSCF_LIBRARY=$<BOOL:${VSCF_LIBRARY}>"
            "VSCF_CIPHER=$<BOOL:${VSCF_CIPHER}>"
            "VSCF_AUTH_ENCRYPT=$<BOOL:${VSCF_AUTH_ENCRYPT}>"
            "VSCF_AUTH_DECRYPT=$<BOOL:${VSCF_AUTH_DECRYPT}>"
            "VSCF_CIPHER_AUTH=$<BOOL:${VSCF_CIPHER_AUTH}>"
            "VSCF_CIPHER_AUTH_INFO=$<BOOL:${VSCF_CIPHER_AUTH_INFO}>"
            "VSCF_CIPHER_INFO=$<BOOL:${VSCF_CIPHER_INFO}>"
            "VSCF_DECRYPT=$<BOOL:${VSCF_DECRYPT}>"
            "VSCF_ENCRYPT=$<BOOL:${VSCF_ENCRYPT}>"
            "VSCF_EX_KDF=$<BOOL:${VSCF_EX_KDF}>"
            "VSCF_HASH=$<BOOL:${VSCF_HASH}>"
            "VSCF_HASH_INFO=$<BOOL:${VSCF_HASH_INFO}>"
            "VSCF_HASH_STREAM=$<BOOL:${VSCF_HASH_STREAM}>"
            "VSCF_MAC=$<BOOL:${VSCF_MAC}>"
            "VSCF_MAC_INFO=$<BOOL:${VSCF_MAC_INFO}>"
            "VSCF_MAC_STREAM=$<BOOL:${VSCF_MAC_STREAM}>"
            "VSCF_KDF=$<BOOL:${VSCF_KDF}>"
            "VSCF_RANDOM=$<BOOL:${VSCF_RANDOM}>"
            "VSCF_ENTROPY_SOURCE=$<BOOL:${VSCF_ENTROPY_SOURCE}>"
            "VSCF_KEY=$<BOOL:${VSCF_KEY}>"
            "VSCF_PUBLIC_KEY=$<BOOL:${VSCF_PUBLIC_KEY}>"
            "VSCF_PRIVATE_KEY=$<BOOL:${VSCF_PRIVATE_KEY}>"
            "VSCF_SIGN=$<BOOL:${VSCF_SIGN}>"
            "VSCF_VERIFY=$<BOOL:${VSCF_VERIFY}>"
            "VSCF_GENERATE_KEY=$<BOOL:${VSCF_GENERATE_KEY}>"
            "VSCF_COMPUTE_SHARED_KEY=$<BOOL:${VSCF_COMPUTE_SHARED_KEY}>"
            "VSCF_EXPORT_PUBLIC_KEY=$<BOOL:${VSCF_EXPORT_PUBLIC_KEY}>"
            "VSCF_EXPORT_PRIVATE_KEY=$<BOOL:${VSCF_EXPORT_PRIVATE_KEY}>"
            "VSCF_IMPORT_PUBLIC_KEY=$<BOOL:${VSCF_IMPORT_PUBLIC_KEY}>"
            "VSCF_IMPORT_PRIVATE_KEY=$<BOOL:${VSCF_IMPORT_PRIVATE_KEY}>"
            "VSCF_ASN1_READER=$<BOOL:${VSCF_ASN1_READER}>"
            "VSCF_ASN1_WRITER=$<BOOL:${VSCF_ASN1_WRITER}>"
            "VSCF_SHA224=$<BOOL:${VSCF_SHA224}>"
            "VSCF_SHA256=$<BOOL:${VSCF_SHA256}>"
            "VSCF_SHA384=$<BOOL:${VSCF_SHA384}>"
            "VSCF_SHA512=$<BOOL:${VSCF_SHA512}>"
            "VSCF_AES256_GCM=$<BOOL:${VSCF_AES256_GCM}>"
            "VSCF_ASN1RD=$<BOOL:${VSCF_ASN1RD}>"
            "VSCF_ASN1WR=$<BOOL:${VSCF_ASN1WR}>"
            "VSCF_RSA_PUBLIC_KEY=$<BOOL:${VSCF_RSA_PUBLIC_KEY}>"
            "VSCF_RSA_PRIVATE_KEY=$<BOOL:${VSCF_RSA_PRIVATE_KEY}>"
            "VSCF_PLATFORM_ENTROPY=$<BOOL:${VSCF_PLATFORM_ENTROPY}>"
            "VSCF_ENTROPY_ACCUMULATOR=$<BOOL:${VSCF_ENTROPY_ACCUMULATOR}>"
            "VSCF_CTR_DRBG=$<BOOL:${VSCF_CTR_DRBG}>"
            "VSCF_HMAC=$<BOOL:${VSCF_HMAC}>"
            "VSCF_HKDF=$<BOOL:${VSCF_HKDF}>"
            "VSCF_KDF1=$<BOOL:${VSCF_KDF1}>"
            "VSCF_KDF2=$<BOOL:${VSCF_KDF2}>"
            "VSCF_FAKE_RANDOM=$<BOOL:${VSCF_FAKE_RANDOM}>"
            "VSCF_ERROR_CTX=$<BOOL:${VSCF_ERROR_CTX}>"
            "VSCF_MBEDTLS_BIGNUM_ASN1_WRITER=$<BOOL:${VSCF_MBEDTLS_BIGNUM_ASN1_WRITER}>"
            "VSCF_MBEDTLS_BIGNUM_ASN1_READER=$<BOOL:${VSCF_MBEDTLS_BIGNUM_ASN1_READER}>"
            "VSCF_MBEDTLS_MD=$<BOOL:${VSCF_MBEDTLS_MD}>"
        )
