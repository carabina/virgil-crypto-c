/*
* Copyright (C) 2015-2018 Virgil Security Inc.
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
* Random number generator that is used for test purposes only.
 */
public class FakeRandom implements Random, EntropySource {

    public long cCtx;

    /* Create underlying C context. */
    public FakeRandom() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.fakeRandom_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public FakeRandom(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /*
    * Configure random number generator to generate sequence filled with given byte.
     */
    public void setupSourceByte(Byte byteSource) {
        FoundationJNI.INSTANCE.fakeRandom_setupSourceByte(this.cCtx, byteSource);
    }

    /*
    * Configure random number generator to generate random sequence from given data.
    * Note, that given data is used as circular source.
     */
    public void setupSourceData(byte[] dataSource) {
        FoundationJNI.INSTANCE.fakeRandom_setupSourceData(this.cCtx, dataSource);
    }

    /*
    * Generate random bytes.
     */
    public byte[] random(Integer dataLen) {
        return FoundationJNI.INSTANCE.fakeRandom_random(this.cCtx, dataLen);
    }

    /*
    * Retreive new seed data from the entropy sources.
     */
    public void reseed() {
        FoundationJNI.INSTANCE.fakeRandom_reseed(this.cCtx);
    }

    /*
    * Defines that implemented source is strong.
     */
    public Boolean isStrong() {
        return FoundationJNI.INSTANCE.fakeRandom_isStrong(this.cCtx);
    }

    /*
    * Gather entropy of the requested length.
     */
    public byte[] gather(Integer len) {
        return FoundationJNI.INSTANCE.fakeRandom_gather(this.cCtx, len);
    }
}

