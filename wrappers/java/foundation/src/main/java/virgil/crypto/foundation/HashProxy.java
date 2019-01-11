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
* Provides interface to the stateless hashing (messege digest) algorithms.
 */
class HashProxy implements Hash {

    public long cCtx;

    /* Take C context that implements this interface */
    public HashProxy(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /*
    * Length of the digest (hashing output) in bytes.
     */
    public int getDigestLen() {
        return FoundationJNI.INSTANCE.hashInfo_getDigestLen(this.cCtx);
    }

    /*
    * Block length of the digest function in bytes.
     */
    public int getBlockLen() {
        return FoundationJNI.INSTANCE.hashInfo_getBlockLen(this.cCtx);
    }

    /*
    * Return implemented hash algorithm type.
     */
    public HashAlg alg() {
        return FoundationJNI.INSTANCE.hashInfo_alg(this.cCtx);
    }

    /*
    * Calculate hash over given data.
     */
    public byte[] hash(byte[] data) {
        return FoundationJNI.INSTANCE.hash_hash(this.cCtx, data);
    }
}

