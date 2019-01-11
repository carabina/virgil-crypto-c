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
* Provide interface for symmetric ciphers.
 */
class CipherProxy implements Cipher {

    public long cCtx;

    /* Take C context that implements this interface */
    public CipherProxy(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /*
    * Encrypt given data.
     */
    public byte[] encrypt(byte[] data) {
        return FoundationJNI.INSTANCE.encrypt_encrypt(this.cCtx, data);
    }

    /*
    * Calculate required buffer length to hold the encrypted data.
     */
    public int encryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.encrypt_encryptedLen(this.cCtx, dataLen);
    }

    /*
    * Decrypt given data.
     */
    public byte[] decrypt(byte[] data) {
        return FoundationJNI.INSTANCE.decrypt_decrypt(this.cCtx, data);
    }

    /*
    * Calculate required buffer length to hold the decrypted data.
     */
    public int decryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.decrypt_decryptedLen(this.cCtx, dataLen);
    }

    /*
    * Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
     */
    public int getNonceLen() {
        return FoundationJNI.INSTANCE.cipherInfo_getNonceLen(this.cCtx);
    }

    /*
    * Cipher key length in bytes.
     */
    public int getKeyLen() {
        return FoundationJNI.INSTANCE.cipherInfo_getKeyLen(this.cCtx);
    }

    /*
    * Cipher key length in bits.
     */
    public int getKeyBitlen() {
        return FoundationJNI.INSTANCE.cipherInfo_getKeyBitlen(this.cCtx);
    }

    /*
    * Cipher block length in bytes.
     */
    public int getBlockLen() {
        return FoundationJNI.INSTANCE.cipherInfo_getBlockLen(this.cCtx);
    }

    /*
    * Setup IV or nonce.
     */
    public void setNonce(byte[] nonce) {
        FoundationJNI.INSTANCE.cipher_setNonce(this.cCtx, nonce);
    }

    /*
    * Set cipher encryption / decryption key.
     */
    public void setKey(byte[] key) {
        FoundationJNI.INSTANCE.cipher_setKey(this.cCtx, key);
    }
}

