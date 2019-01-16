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
public class FoundationException extends RuntimeException {

    public static final int SUCCESS = 0;

    public static final int BAD_ARGUMENTS = -1;

    public static final int UNINITIALIZED = -2;

    public static final int UNHANDLED_THIRDPARTY_ERROR = -3;

    public static final int SMALL_BUFFER = -101;

    public static final int AUTH_FAILED = -201;

    public static final int OUT_OF_DATA = -202;

    public static final int BAD_ASN1 = -203;

    public static final int ASN1_LOSSY_TYPE_NARROWING = -204;

    public static final int BAD_PKCS1_PUBLIC_KEY = -205;

    public static final int BAD_PKCS1_PRIVATE_KEY = -206;

    public static final int BAD_PKCS8_PUBLIC_KEY = -207;

    public static final int BAD_PKCS8_PRIVATE_KEY = -208;

    public static final int BAD_ENCRYPTED_DATA = -209;

    public static final int RANDOM_FAILED = -210;

    public static final int KEY_GENERATION_FAILED = -211;

    public static final int ENTROPY_SOURCE_FAILED = -212;

    public static final int RNG_REQUESTED_DATA_TOO_BIG = -213;

    public static final int BAD_BASE64 = -214;

    public static final int BAD_PEM = -215;

    public static final int SHARED_KEY_EXCHANGE_FAILED = -216;

    private int errorCode;

    /* Create new instance. */
    public FoundationException(int errorCode) {
        super();
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return this.errorCode;
    }
}

