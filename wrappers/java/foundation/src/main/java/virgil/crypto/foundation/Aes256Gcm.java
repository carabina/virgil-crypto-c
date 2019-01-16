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
* Implementation of the symmetric cipher AES-256 bit in a GCM mode.
* Note, this implementation contains dynamic memory allocations,
* this should be improved in the future releases.
 */
public class Aes256Gcm implements Encrypt, Decrypt, CipherInfo, Cipher, CipherAuthInfo, AuthEncrypt, AuthDecrypt, CipherAuth {

    public long cCtx;

    /* Create underlying C context. */
    public Aes256Gcm() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.aes256Gcm_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public Aes256Gcm(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /*
    * Encrypt given data.
     */
    public byte[] encrypt(byte[] data) {
        return FoundationJNI.INSTANCE.aes256Gcm_encrypt(this.cCtx, data);
    }

    /*
    * Calculate required buffer length to hold the encrypted data.
     */
    public int encryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_encryptedLen(this.cCtx, dataLen);
    }

    /*
    * Decrypt given data.
     */
    public byte[] decrypt(byte[] data) {
        return FoundationJNI.INSTANCE.aes256Gcm_decrypt(this.cCtx, data);
    }

    /*
    * Calculate required buffer length to hold the decrypted data.
     */
    public int decryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_decryptedLen(this.cCtx, dataLen);
    }

    /*
    * Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
     */
    public int getNonceLen() {
        return 12;
    }

    /*
    * Cipher key length in bytes.
     */
    public int getKeyLen() {
        return 32;
    }

    /*
    * Cipher key length in bits.
     */
    public int getKeyBitlen() {
        return 256;
    }

    /*
    * Cipher block length in bytes.
     */
    public int getBlockLen() {
        return 16;
    }

    /*
    * Setup IV or nonce.
     */
    public void setNonce(byte[] nonce) {
        FoundationJNI.INSTANCE.aes256Gcm_setNonce(this.cCtx, nonce);
    }

    /*
    * Set cipher encryption / decryption key.
     */
    public void setKey(byte[] key) {
        FoundationJNI.INSTANCE.aes256Gcm_setKey(this.cCtx, key);
    }

    /*
    * Start sequential encryption.
     */
    public void startEncryption() {
        FoundationJNI.INSTANCE.aes256Gcm_startEncryption(this.cCtx);
    }

    /*
    * Start sequential decryption.
     */
    public void startDecryption() {
        FoundationJNI.INSTANCE.aes256Gcm_startDecryption(this.cCtx);
    }

    /*
    * Process encryption or decryption of the given data chunk.
     */
    public byte[] update(byte[] data) {
        return FoundationJNI.INSTANCE.aes256Gcm_update(this.cCtx, data);
    }

    /*
    * Return buffer length required to hold an output of the methods
    * "update" or "finish".
    * Pass zero length to define buffer length of the method "finish".
     */
    public int outLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_outLen(this.cCtx, dataLen);
    }

    /*
    * Accomplish encryption or decryption process.
     */
    public byte[] finish() {
        return FoundationJNI.INSTANCE.aes256Gcm_finish(this.cCtx);
    }

    /*
    * Defines authentication tag length in bytes.
     */
    public int getAuthTagLen() {
        return 16;
    }

    /*
    * Encrypt given data.
    * If 'tag' is not give, then it will written to the 'enc'.
     */
    public AuthEncryptAuthEncryptResult authEncrypt(byte[] data, byte[] authData) {
        return FoundationJNI.INSTANCE.aes256Gcm_authEncrypt(this.cCtx, data, authData);
    }

    /*
    * Calculate required buffer length to hold the authenticated encrypted data.
     */
    public int authEncryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_authEncryptedLen(this.cCtx, dataLen);
    }

    /*
    * Decrypt given data.
    * If 'tag' is not give, then it will be taken from the 'enc'.
     */
    public byte[] authDecrypt(byte[] data, byte[] authData, byte[] tag) {
        return FoundationJNI.INSTANCE.aes256Gcm_authDecrypt(this.cCtx, data, authData, tag);
    }

    /*
    * Calculate required buffer length to hold the authenticated decrypted data.
     */
    public int authDecryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.aes256Gcm_authDecryptedLen(this.cCtx, dataLen);
    }
}

