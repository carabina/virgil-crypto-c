/*
* Copyright (C) 2015-2019 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* (1) Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* (2) Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
*
* (3) Neither the name of the copyright holder nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
* IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

package virgil.crypto.foundation;

import virgil.crypto.common.*;

/*
* Defines library error codes.
 */
public enum FoundationError {

    /*
    * No errors was occurred.
     */
    SUCCESS(0),
    /*
    * This error should not be returned if assertions is enabled.
     */
    BAD_ARGUMENTS(-1),
    /*
    * Can be used to define that not all context prerequisites are satisfied.
    * Note, this error should not be returned if assertions is enabled.
     */
    UNINITIALIZED(-2),
    /*
    * Define that error code from one of third-party module was not handled.
    * Note, this error should not be returned if assertions is enabled.
     */
    UNHANDLED_THIRDPARTY_ERROR(-3),
    /*
    * Buffer capacity is not enaugh to hold result.
     */
    SMALL_BUFFER(-101),
    /*
    * Authentication failed during decryption.
     */
    AUTH_FAILED(-201),
    /*
    * Attempt to read data out of buffer bounds.
     */
    OUT_OF_DATA(-202),
    /*
    * ASN.1 encoded data is corrupted.
     */
    BAD_ASN1(-203),
    /*
    * Attempt to read ASN.1 type that is bigger then requested C type.
     */
    ASN1_LOSSY_TYPE_NARROWING(-204),
    /*
    * ASN.1 representation of PKCS#1 public key is corrupted.
     */
    BAD_PKCS1_PUBLIC_KEY(-205),
    /*
    * ASN.1 representation of PKCS#1 private key is corrupted.
     */
    BAD_PKCS1_PRIVATE_KEY(-206),
    /*
    * ASN.1 representation of PKCS#8 public key is corrupted.
     */
    BAD_PKCS8_PUBLIC_KEY(-207),
    /*
    * ASN.1 representation of PKCS#8 private key is corrupted.
     */
    BAD_PKCS8_PRIVATE_KEY(-208),
    /*
    * Encrypted data is corrupted.
     */
    BAD_ENCRYPTED_DATA(-209),
    /*
    * Underlying random operation returns error.
     */
    RANDOM_FAILED(-210),
    /*
    * Generation of the private or secret key failed.
     */
    KEY_GENERATION_FAILED(-211),
    /*
    * One of the entropy sources failed.
     */
    ENTROPY_SOURCE_FAILED(-212),
    /*
    * Requested data to be generated is too big.
     */
    RNG_REQUESTED_DATA_TOO_BIG(-213),
    /*
    * Base64 encoded string contains invalid characters.
     */
    BAD_BASE64(-214),
    /*
    * PEM data is corrupted.
     */
    BAD_PEM(-215),
    /*
    * Exchange key return zero.
     */
    SHARED_KEY_EXCHANGE_FAILED(-216);

    private final int code;

    private FoundationError(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}

