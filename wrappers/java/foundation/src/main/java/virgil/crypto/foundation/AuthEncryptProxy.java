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
* Provide interface for authenticated data encryption.
 */
class AuthEncryptProxy implements AuthEncrypt {

    public long cCtx;

    /* Take C context that implements this interface */
    public AuthEncryptProxy(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /*
    * Defines authentication tag length in bytes.
     */
    public int getAuthTagLen() {
        return FoundationJNI.INSTANCE.cipherAuthInfo_getAuthTagLen(this.cCtx);
    }

    /*
    * Encrypt given data.
    * If 'tag' is not give, then it will written to the 'enc'.
     */
    public AuthEncryptAuthEncryptResult authEncrypt(byte[] data, byte[] authData) {
        return FoundationJNI.INSTANCE.authEncrypt_authEncrypt(this.cCtx, data, authData);
    }

    /*
    * Calculate required buffer length to hold the authenticated encrypted data.
     */
    public int authEncryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.authEncrypt_authEncryptedLen(this.cCtx, dataLen);
    }
}

