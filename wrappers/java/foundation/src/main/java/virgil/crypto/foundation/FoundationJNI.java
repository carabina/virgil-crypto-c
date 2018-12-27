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

import virgil.crypto.common.utils.NativeUtils;

public class FoundationJNI {

    public static final FoundationJNI INSTANCE;

    static {
        NativeUtils.load();
        INSTANCE = new FoundationJNI();
    }

    private FoundationJNI() {
    }

    public native long errorCtx_new() ;

    public native void errorCtx_reset(long cCtx) ;

    public native void errorCtx_error(long cCtx) ;

    public native long rawKey_new() ;

    public native KeyAlg rawKey_alg(long cCtx) ;

    public native byte[] rawKey_data(long cCtx) ;

    public native byte[] oid_fromKeyAlg(KeyAlg keyAlg) ;

    public native KeyAlg oid_toKeyAlg(byte[] oid) ;

    public native Boolean oid_equal(byte[] lhs, byte[] rhs) ;

    public native Integer base64_encodedLen(Integer dataLen) ;

    public native byte[] base64_encode(byte[] data) ;

    public native Integer base64_decodedLen(Integer strLen) ;

    public native byte[] base64_decode(byte[] str) ;

    public native Integer pem_wrappedLen(String title, Integer dataLen) ;

    public native byte[] pem_wrap(String title, byte[] data) ;

    public native Integer pem_unwrappedLen(Integer pemLen) ;

    public native byte[] pem_unwrap(byte[] pem) ;

    public native byte[] pem_title(byte[] pem) ;

    public native void defaults_setupDefaults(long cCtx) ;

    public native byte[] encrypt_encrypt(long cCtx, byte[] data) ;

    public native Integer encrypt_encryptedLen(long cCtx, Integer dataLen) ;

    public native byte[] decrypt_decrypt(long cCtx, byte[] data) ;

    public native Integer decrypt_decryptedLen(long cCtx, Integer dataLen) ;

    /*
    * Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
     */
    public native Integer cipherInfo_getNonceLen(long cCtx) ;

    /*
    * Cipher key length in bytes.
     */
    public native Integer cipherInfo_getKeyLen(long cCtx) ;

    /*
    * Cipher key length in bits.
     */
    public native Integer cipherInfo_getKeyBitlen(long cCtx) ;

    /*
    * Cipher block length in bytes.
     */
    public native Integer cipherInfo_getBlockLen(long cCtx) ;

    public native void cipher_setNonce(long cCtx, byte[] nonce) ;

    public native void cipher_setKey(long cCtx, byte[] key) ;

    /*
    * Defines authentication tag length in bytes.
     */
    public native Integer cipherAuthInfo_getAuthTagLen(long cCtx) ;

    public native AuthEncryptAuthEncryptResult authEncrypt_authEncrypt(long cCtx, byte[] data, byte[] authData) ;

    public native Integer authEncrypt_authEncryptedLen(long cCtx, Integer dataLen) ;

    public native byte[] authDecrypt_authDecrypt(long cCtx, byte[] data, byte[] authData, byte[] tag) ;

    public native Integer authDecrypt_authDecryptedLen(long cCtx, Integer dataLen) ;

    public native byte[] saltedKdf_derive(long cCtx, byte[] data, byte[] salt, byte[] info, Integer keyLen) ;

    /*
    * Length of the digest (hashing output) in bytes.
     */
    public native Integer hashInfo_getDigestLen(long cCtx) ;

    /*
    * Block length of the digest function in bytes.
     */
    public native Integer hashInfo_getBlockLen(long cCtx) ;

    public native HashAlg hashInfo_alg(long cCtx) ;

    public native byte[] hash_hash(long cCtx, byte[] data) ;

    public native void hashStream_start(long cCtx) ;

    public native void hashStream_update(long cCtx, byte[] data) ;

    public native byte[] hashStream_finish(long cCtx) ;

    public native Integer macInfo_digestLen(long cCtx) ;

    public native byte[] mac_mac(long cCtx, byte[] key, byte[] data) ;

    public native void macStream_start(long cCtx, byte[] key) ;

    public native void macStream_update(long cCtx, byte[] data) ;

    public native byte[] macStream_finish(long cCtx) ;

    public native void macStream_reset(long cCtx) ;

    public native byte[] kdf_derive(long cCtx, byte[] data, Integer keyLen) ;

    public native byte[] random_random(long cCtx, Integer dataLen) ;

    public native void random_reseed(long cCtx) ;

    public native Boolean entropySource_isStrong(long cCtx) ;

    public native byte[] entropySource_gather(long cCtx, Integer len) ;

    public native KeyAlg key_alg(long cCtx) ;

    public native Integer key_keyLen(long cCtx) ;

    public native Integer key_keyBitlen(long cCtx) ;

    /*
    * Define whether a public key can be exported or not.
     */
    public native Boolean publicKey_getCanExportPublicKey(long cCtx) ;

    /*
    * Defines whether a public key can be imported or not.
     */
    public native Boolean publicKey_getCanImportPublicKey(long cCtx) ;

    public native byte[] publicKey_exportPublicKey(long cCtx) ;

    public native Integer publicKey_exportedPublicKeyLen(long cCtx) ;

    public native void publicKey_importPublicKey(long cCtx, byte[] data) ;

    /*
    * Define whether a private key can be exported or not.
     */
    public native Boolean privateKey_getCanExportPrivateKey(long cCtx) ;

    /*
    * Define whether a private key can be imported or not.
     */
    public native Boolean privateKey_getCanImportPrivateKey(long cCtx) ;

    public native PublicKey privateKey_extractPublicKey(long cCtx) ;

    public native byte[] privateKey_exportPrivateKey(long cCtx) ;

    public native Integer privateKey_exportedPrivateKeyLen(long cCtx) ;

    public native void privateKey_importPrivateKey(long cCtx, byte[] data) ;

    public native byte[] sign_sign(long cCtx, byte[] data) ;

    public native Integer sign_signatureLen(long cCtx) ;

    public native Boolean verify_verify(long cCtx, byte[] data, byte[] signature) ;

    public native void generateKey_generateKey(long cCtx) ;

    public native byte[] computeSharedKey_computeSharedKey(long cCtx, PublicKey publicKey) ;

    public native Integer computeSharedKey_sharedKeyLen(long cCtx) ;

    public native Integer keySerializer_serializedPublicKeyLen(long cCtx, PublicKey publicKey) ;

    public native byte[] keySerializer_serializePublicKey(long cCtx, PublicKey publicKey) ;

    public native Integer keySerializer_serializedPrivateKeyLen(long cCtx, PrivateKey privateKey) ;

    public native byte[] keySerializer_serializePrivateKey(long cCtx, PrivateKey privateKey) ;

    public native RawKey keyDeserializer_deserializePublicKey(long cCtx, byte[] publicKeyData, ErrorCtx error) ;

    public native RawKey keyDeserializer_deserializePrivateKey(long cCtx, byte[] privateKeyData, ErrorCtx error) ;

    public native void asn1Reader_reset(long cCtx, byte[] data) ;

    public native void asn1Reader_error(long cCtx) ;

    public native Integer asn1Reader_getTag(long cCtx) ;

    public native Integer asn1Reader_getLen(long cCtx) ;

    public native Integer asn1Reader_readTag(long cCtx, Integer tag) ;

    public native Integer asn1Reader_readInt(long cCtx) ;

    public native Byte asn1Reader_readInt8(long cCtx) ;

    public native Short asn1Reader_readInt16(long cCtx) ;

    public native Integer asn1Reader_readInt32(long cCtx) ;

    public native Long asn1Reader_readInt64(long cCtx) ;

    public native Long asn1Reader_readUint(long cCtx) ;

    public native Short asn1Reader_readUint8(long cCtx) ;

    public native Integer asn1Reader_readUint16(long cCtx) ;

    public native Long asn1Reader_readUint32(long cCtx) ;

    public native Long asn1Reader_readUint64(long cCtx) ;

    public native Boolean asn1Reader_readBool(long cCtx) ;

    public native void asn1Reader_readNull(long cCtx) ;

    public native byte[] asn1Reader_readOctetStr(long cCtx) ;

    public native byte[] asn1Reader_readBitstringAsOctetStr(long cCtx) ;

    public native byte[] asn1Reader_readUtf8Str(long cCtx) ;

    public native byte[] asn1Reader_readOid(long cCtx) ;

    public native byte[] asn1Reader_readData(long cCtx, Integer len) ;

    public native Integer asn1Reader_readSequence(long cCtx) ;

    public native Integer asn1Reader_readSet(long cCtx) ;

    public native void asn1Writer_reset(long cCtx, Byte out, Integer outLen) ;

    public native Integer asn1Writer_finish(long cCtx) ;

    public native void asn1Writer_error(long cCtx) ;

    public native Byte asn1Writer_reserve(long cCtx, Integer len) ;

    public native Integer asn1Writer_writeTag(long cCtx, Integer tag) ;

    public native Integer asn1Writer_writeLen(long cCtx, Integer len) ;

    public native Integer asn1Writer_writeInt(long cCtx, Integer value) ;

    public native Integer asn1Writer_writeInt8(long cCtx, Byte value) ;

    public native Integer asn1Writer_writeInt16(long cCtx, Short value) ;

    public native Integer asn1Writer_writeInt32(long cCtx, Integer value) ;

    public native Integer asn1Writer_writeInt64(long cCtx, Long value) ;

    public native Integer asn1Writer_writeUint(long cCtx, Long value) ;

    public native Integer asn1Writer_writeUint8(long cCtx, Short value) ;

    public native Integer asn1Writer_writeUint16(long cCtx, Integer value) ;

    public native Integer asn1Writer_writeUint32(long cCtx, Long value) ;

    public native Integer asn1Writer_writeUint64(long cCtx, Long value) ;

    public native Integer asn1Writer_writeBool(long cCtx, Boolean value) ;

    public native Integer asn1Writer_writeNull(long cCtx) ;

    public native Integer asn1Writer_writeOctetStr(long cCtx, byte[] value) ;

    public native Integer asn1Writer_writeOctetStrAsBitstring(long cCtx, byte[] value) ;

    public native Integer asn1Writer_writeData(long cCtx, byte[] data) ;

    public native Integer asn1Writer_writeUtf8Str(long cCtx, byte[] value) ;

    public native Integer asn1Writer_writeOid(long cCtx, byte[] value) ;

    public native Integer asn1Writer_writeSequence(long cCtx, Integer len) ;

    public native Integer asn1Writer_writeSet(long cCtx, Integer len) ;

    public native long sha224_new() ;

    public native HashAlg sha224_alg(long cCtx) ;

    public native byte[] sha224_hash(long cCtx, byte[] data) ;

    public native void sha224_start(long cCtx) ;

    public native void sha224_update(long cCtx, byte[] data) ;

    public native byte[] sha224_finish(long cCtx) ;

    public native long sha256_new() ;

    public native HashAlg sha256_alg(long cCtx) ;

    public native byte[] sha256_hash(long cCtx, byte[] data) ;

    public native void sha256_start(long cCtx) ;

    public native void sha256_update(long cCtx, byte[] data) ;

    public native byte[] sha256_finish(long cCtx) ;

    public native long sha384_new() ;

    public native HashAlg sha384_alg(long cCtx) ;

    public native byte[] sha384_hash(long cCtx, byte[] data) ;

    public native void sha384_start(long cCtx) ;

    public native void sha384_update(long cCtx, byte[] data) ;

    public native byte[] sha384_finish(long cCtx) ;

    public native long sha512_new() ;

    public native HashAlg sha512_alg(long cCtx) ;

    public native byte[] sha512_hash(long cCtx, byte[] data) ;

    public native void sha512_start(long cCtx) ;

    public native void sha512_update(long cCtx, byte[] data) ;

    public native byte[] sha512_finish(long cCtx) ;

    public native long aes256Gcm_new() ;

    public native byte[] aes256Gcm_encrypt(long cCtx, byte[] data) ;

    public native Integer aes256Gcm_encryptedLen(long cCtx, Integer dataLen) ;

    public native byte[] aes256Gcm_decrypt(long cCtx, byte[] data) ;

    public native Integer aes256Gcm_decryptedLen(long cCtx, Integer dataLen) ;

    public native void aes256Gcm_setNonce(long cCtx, byte[] nonce) ;

    public native void aes256Gcm_setKey(long cCtx, byte[] key) ;

    public native AuthEncryptAuthEncryptResult aes256Gcm_authEncrypt(long cCtx, byte[] data, byte[] authData) ;

    public native Integer aes256Gcm_authEncryptedLen(long cCtx, Integer dataLen) ;

    public native byte[] aes256Gcm_authDecrypt(long cCtx, byte[] data, byte[] authData, byte[] tag) ;

    public native Integer aes256Gcm_authDecryptedLen(long cCtx, Integer dataLen) ;

    public native long asn1rd_new() ;

    public native void asn1rd_reset(long cCtx, byte[] data) ;

    public native void asn1rd_error(long cCtx) ;

    public native Integer asn1rd_getTag(long cCtx) ;

    public native Integer asn1rd_getLen(long cCtx) ;

    public native Integer asn1rd_readTag(long cCtx, Integer tag) ;

    public native Integer asn1rd_readInt(long cCtx) ;

    public native Byte asn1rd_readInt8(long cCtx) ;

    public native Short asn1rd_readInt16(long cCtx) ;

    public native Integer asn1rd_readInt32(long cCtx) ;

    public native Long asn1rd_readInt64(long cCtx) ;

    public native Long asn1rd_readUint(long cCtx) ;

    public native Short asn1rd_readUint8(long cCtx) ;

    public native Integer asn1rd_readUint16(long cCtx) ;

    public native Long asn1rd_readUint32(long cCtx) ;

    public native Long asn1rd_readUint64(long cCtx) ;

    public native Boolean asn1rd_readBool(long cCtx) ;

    public native void asn1rd_readNull(long cCtx) ;

    public native byte[] asn1rd_readOctetStr(long cCtx) ;

    public native byte[] asn1rd_readBitstringAsOctetStr(long cCtx) ;

    public native byte[] asn1rd_readUtf8Str(long cCtx) ;

    public native byte[] asn1rd_readOid(long cCtx) ;

    public native byte[] asn1rd_readData(long cCtx, Integer len) ;

    public native Integer asn1rd_readSequence(long cCtx) ;

    public native Integer asn1rd_readSet(long cCtx) ;

    public native long asn1wr_new() ;

    public native void asn1wr_reset(long cCtx, Byte out, Integer outLen) ;

    public native Integer asn1wr_finish(long cCtx) ;

    public native void asn1wr_error(long cCtx) ;

    public native Byte asn1wr_reserve(long cCtx, Integer len) ;

    public native Integer asn1wr_writeTag(long cCtx, Integer tag) ;

    public native Integer asn1wr_writeLen(long cCtx, Integer len) ;

    public native Integer asn1wr_writeInt(long cCtx, Integer value) ;

    public native Integer asn1wr_writeInt8(long cCtx, Byte value) ;

    public native Integer asn1wr_writeInt16(long cCtx, Short value) ;

    public native Integer asn1wr_writeInt32(long cCtx, Integer value) ;

    public native Integer asn1wr_writeInt64(long cCtx, Long value) ;

    public native Integer asn1wr_writeUint(long cCtx, Long value) ;

    public native Integer asn1wr_writeUint8(long cCtx, Short value) ;

    public native Integer asn1wr_writeUint16(long cCtx, Integer value) ;

    public native Integer asn1wr_writeUint32(long cCtx, Long value) ;

    public native Integer asn1wr_writeUint64(long cCtx, Long value) ;

    public native Integer asn1wr_writeBool(long cCtx, Boolean value) ;

    public native Integer asn1wr_writeNull(long cCtx) ;

    public native Integer asn1wr_writeOctetStr(long cCtx, byte[] value) ;

    public native Integer asn1wr_writeOctetStrAsBitstring(long cCtx, byte[] value) ;

    public native Integer asn1wr_writeData(long cCtx, byte[] data) ;

    public native Integer asn1wr_writeUtf8Str(long cCtx, byte[] value) ;

    public native Integer asn1wr_writeOid(long cCtx, byte[] value) ;

    public native Integer asn1wr_writeSequence(long cCtx, Integer len) ;

    public native Integer asn1wr_writeSet(long cCtx, Integer len) ;

    public native long rsaPublicKey_new() ;

    public native KeyAlg rsaPublicKey_alg(long cCtx) ;

    public native Integer rsaPublicKey_keyLen(long cCtx) ;

    public native Integer rsaPublicKey_keyBitlen(long cCtx) ;

    public native byte[] rsaPublicKey_encrypt(long cCtx, byte[] data) ;

    public native Integer rsaPublicKey_encryptedLen(long cCtx, Integer dataLen) ;

    public native Boolean rsaPublicKey_verify(long cCtx, byte[] data, byte[] signature) ;

    public native byte[] rsaPublicKey_exportPublicKey(long cCtx) ;

    public native Integer rsaPublicKey_exportedPublicKeyLen(long cCtx) ;

    public native void rsaPublicKey_importPublicKey(long cCtx, byte[] data) ;

    public native void rsaPrivateKey_setKeygenParams(long cCtx, Integer bitlen, Integer exponent) ;

    public native long rsaPrivateKey_new() ;

    public native KeyAlg rsaPrivateKey_alg(long cCtx) ;

    public native Integer rsaPrivateKey_keyLen(long cCtx) ;

    public native Integer rsaPrivateKey_keyBitlen(long cCtx) ;

    public native void rsaPrivateKey_generateKey(long cCtx) ;

    public native byte[] rsaPrivateKey_decrypt(long cCtx, byte[] data) ;

    public native Integer rsaPrivateKey_decryptedLen(long cCtx, Integer dataLen) ;

    public native byte[] rsaPrivateKey_sign(long cCtx, byte[] data) ;

    public native Integer rsaPrivateKey_signatureLen(long cCtx) ;

    public native PublicKey rsaPrivateKey_extractPublicKey(long cCtx) ;

    public native byte[] rsaPrivateKey_exportPrivateKey(long cCtx) ;

    public native Integer rsaPrivateKey_exportedPrivateKeyLen(long cCtx) ;

    public native void rsaPrivateKey_importPrivateKey(long cCtx, byte[] data) ;

    public native void entropyAccumulator_addSource(long cCtx, EntropySource source, Integer threshold) ;

    public native long entropyAccumulator_new() ;

    public native void entropyAccumulator_setupDefaults(long cCtx) ;

    public native Boolean entropyAccumulator_isStrong(long cCtx) ;

    public native byte[] entropyAccumulator_gather(long cCtx, Integer len) ;

    public native void ctrDrbg_enablePredictionResistance(long cCtx) ;

    public native void ctrDrbg_setReseedInterval(long cCtx, Integer interval) ;

    public native void ctrDrbg_setEntropyLen(long cCtx, Integer len) ;

    public native long ctrDrbg_new() ;

    public native void ctrDrbg_setupDefaults(long cCtx) ;

    public native byte[] ctrDrbg_random(long cCtx, Integer dataLen) ;

    public native void ctrDrbg_reseed(long cCtx) ;

    public native long hmac_new() ;

    public native Integer hmac_digestLen(long cCtx) ;

    public native byte[] hmac_mac(long cCtx, byte[] key, byte[] data) ;

    public native void hmac_start(long cCtx, byte[] key) ;

    public native void hmac_update(long cCtx, byte[] data) ;

    public native byte[] hmac_finish(long cCtx) ;

    public native void hmac_reset(long cCtx) ;

    public native long hkdf_new() ;

    public native byte[] hkdf_derive(long cCtx, byte[] data, byte[] salt, byte[] info, Integer keyLen) ;

    public native long kdf1_new() ;

    public native byte[] kdf1_derive(long cCtx, byte[] data, Integer keyLen) ;

    public native long kdf2_new() ;

    public native byte[] kdf2_derive(long cCtx, byte[] data, Integer keyLen) ;

    public native void fakeRandom_setupSourceByte(long cCtx, Byte byteSource) ;

    public native void fakeRandom_setupSourceData(long cCtx, byte[] dataSource) ;

    public native long fakeRandom_new() ;

    public native byte[] fakeRandom_random(long cCtx, Integer dataLen) ;

    public native void fakeRandom_reseed(long cCtx) ;

    public native Boolean fakeRandom_isStrong(long cCtx) ;

    public native byte[] fakeRandom_gather(long cCtx, Integer len) ;

    public native long pkcs8DerSerializer_new() ;

    public native void pkcs8DerSerializer_setupDefaults(long cCtx) ;

    public native Integer pkcs8DerSerializer_serializedPublicKeyLen(long cCtx, PublicKey publicKey) ;

    public native byte[] pkcs8DerSerializer_serializePublicKey(long cCtx, PublicKey publicKey) ;

    public native Integer pkcs8DerSerializer_serializedPrivateKeyLen(long cCtx, PrivateKey privateKey) ;

    public native byte[] pkcs8DerSerializer_serializePrivateKey(long cCtx, PrivateKey privateKey) ;

    public native long pkcs8DerDeserializer_new() ;

    public native void pkcs8DerDeserializer_setupDefaults(long cCtx) ;

    public native RawKey pkcs8DerDeserializer_deserializePublicKey(long cCtx, byte[] publicKeyData, ErrorCtx error) ;

    public native RawKey pkcs8DerDeserializer_deserializePrivateKey(long cCtx, byte[] privateKeyData, ErrorCtx error) ;

    public native long pkcs8Serializer_new() ;

    public native void pkcs8Serializer_setupDefaults(long cCtx) ;

    public native Integer pkcs8Serializer_serializedPublicKeyLen(long cCtx, PublicKey publicKey) ;

    public native byte[] pkcs8Serializer_serializePublicKey(long cCtx, PublicKey publicKey) ;

    public native Integer pkcs8Serializer_serializedPrivateKeyLen(long cCtx, PrivateKey privateKey) ;

    public native byte[] pkcs8Serializer_serializePrivateKey(long cCtx, PrivateKey privateKey) ;

    public native long pkcs8Deserializer_new() ;

    public native void pkcs8Deserializer_setupDefaults(long cCtx) ;

    public native RawKey pkcs8Deserializer_deserializePublicKey(long cCtx, byte[] publicKeyData, ErrorCtx error) ;

    public native RawKey pkcs8Deserializer_deserializePrivateKey(long cCtx, byte[] privateKeyData, ErrorCtx error) ;

    public native long ed25519PublicKey_new() ;

    public native KeyAlg ed25519PublicKey_alg(long cCtx) ;

    public native Integer ed25519PublicKey_keyLen(long cCtx) ;

    public native Integer ed25519PublicKey_keyBitlen(long cCtx) ;

    public native Boolean ed25519PublicKey_verify(long cCtx, byte[] data, byte[] signature) ;

    public native byte[] ed25519PublicKey_exportPublicKey(long cCtx) ;

    public native Integer ed25519PublicKey_exportedPublicKeyLen(long cCtx) ;

    public native void ed25519PublicKey_importPublicKey(long cCtx, byte[] data) ;

    public native long ed25519PrivateKey_new() ;

    public native KeyAlg ed25519PrivateKey_alg(long cCtx) ;

    public native Integer ed25519PrivateKey_keyLen(long cCtx) ;

    public native Integer ed25519PrivateKey_keyBitlen(long cCtx) ;

    public native void ed25519PrivateKey_generateKey(long cCtx) ;

    public native byte[] ed25519PrivateKey_sign(long cCtx, byte[] data) ;

    public native Integer ed25519PrivateKey_signatureLen(long cCtx) ;

    public native PublicKey ed25519PrivateKey_extractPublicKey(long cCtx) ;

    public native byte[] ed25519PrivateKey_exportPrivateKey(long cCtx) ;

    public native Integer ed25519PrivateKey_exportedPrivateKeyLen(long cCtx) ;

    public native void ed25519PrivateKey_importPrivateKey(long cCtx, byte[] data) ;

    public native byte[] ed25519PrivateKey_computeSharedKey(long cCtx, PublicKey publicKey) ;

    public native Integer ed25519PrivateKey_sharedKeyLen(long cCtx) ;
}
