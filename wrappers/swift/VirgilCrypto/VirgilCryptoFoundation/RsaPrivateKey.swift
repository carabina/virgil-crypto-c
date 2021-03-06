/// Copyright (C) 2015-2019 Virgil Security, Inc.
///
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are
/// met:
///
///     (1) Redistributions of source code must retain the above copyright
///     notice, this list of conditions and the following disclaimer.
///
///     (2) Redistributions in binary form must reproduce the above copyright
///     notice, this list of conditions and the following disclaimer in
///     the documentation and/or other materials provided with the
///     distribution.
///
///     (3) Neither the name of the copyright holder nor the names of its
///     contributors may be used to endorse or promote products derived from
///     this software without specific prior written permission.
///
/// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
/// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
/// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
/// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
/// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
/// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
/// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
/// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
/// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
/// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
/// POSSIBILITY OF SUCH DAMAGE.
///
/// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


import Foundation
import VSCFoundation
import VirgilCryptoCommon

@objc(VSCFRsaPrivateKey) public class RsaPrivateKey: NSObject, Key, GenerateKey, Decrypt, Sign, PrivateKey {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Define whether a private key can be imported or not.
    @objc public let canImportPrivateKey: Bool = true

    /// Define whether a private key can be exported or not.
    @objc public let canExportPrivateKey: Bool = true

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_rsa_private_key_new()
        super.init()
    }

    /// Acquire C context.
    /// Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    public init(take c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    /// Acquire retained C context.
    /// Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    public init(use c_ctx: OpaquePointer) {
        self.c_ctx = vscf_rsa_private_key_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_rsa_private_key_delete(self.c_ctx)
    }

    @objc public func setHash(hash: Hash) {
        vscf_rsa_private_key_release_hash(self.c_ctx)
        vscf_rsa_private_key_use_hash(self.c_ctx, hash.c_ctx)
    }

    @objc public func setRandom(random: Random) {
        vscf_rsa_private_key_release_random(self.c_ctx)
        vscf_rsa_private_key_use_random(self.c_ctx, random.c_ctx)
    }

    @objc public func setAsn1rd(asn1rd: Asn1Reader) {
        vscf_rsa_private_key_release_asn1rd(self.c_ctx)
        vscf_rsa_private_key_use_asn1rd(self.c_ctx, asn1rd.c_ctx)
    }

    @objc public func setAsn1wr(asn1wr: Asn1Writer) {
        vscf_rsa_private_key_release_asn1wr(self.c_ctx)
        vscf_rsa_private_key_use_asn1wr(self.c_ctx, asn1wr.c_ctx)
    }

    /// Setup parameters that is used during key generation.
    @objc public func setKeygenParams(bitlen: Int, exponent: Int) {
        vscf_rsa_private_key_set_keygen_params(self.c_ctx, bitlen, exponent)
    }

    /// Return implemented asymmetric key algorithm type.
    @objc public func alg() -> KeyAlg {
        let proxyResult = vscf_rsa_private_key_alg(self.c_ctx)

        return KeyAlg.init(fromC: proxyResult)
    }

    /// Length of the key in bytes.
    @objc public func keyLen() -> Int {
        let proxyResult = vscf_rsa_private_key_key_len(self.c_ctx)

        return proxyResult
    }

    /// Length of the key in bits.
    @objc public func keyBitlen() -> Int {
        let proxyResult = vscf_rsa_private_key_key_bitlen(self.c_ctx)

        return proxyResult
    }

    /// Generate new private or secret key.
    /// Note, this operation can be slow.
    @objc public func generateKey() throws {
        let proxyResult = vscf_rsa_private_key_generate_key(self.c_ctx)

        try FoundationError.handleError(fromC: proxyResult)
    }

    /// Decrypt given data.
    @objc public func decrypt(data: Data) throws -> Data {
        let outCount = self.decryptedLen(dataLen: data.count)
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> vscf_error_t in
            out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
                vsc_buffer_init(outBuf)
                vsc_buffer_use(outBuf, outPointer, outCount)
                return vscf_rsa_private_key_decrypt(self.c_ctx, vsc_data(dataPointer, data.count), outBuf)
            })
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return out
    }

    /// Calculate required buffer length to hold the decrypted data.
    @objc public func decryptedLen(dataLen: Int) -> Int {
        let proxyResult = vscf_rsa_private_key_decrypted_len(self.c_ctx, dataLen)

        return proxyResult
    }

    /// Sign data given private key.
    @objc public func sign(data: Data) throws -> Data {
        let signatureCount = self.signatureLen()
        var signature = Data(count: signatureCount)
        var signatureBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(signatureBuf)
        }

        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> vscf_error_t in
            signature.withUnsafeMutableBytes({ (signaturePointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
                vsc_buffer_init(signatureBuf)
                vsc_buffer_use(signatureBuf, signaturePointer, signatureCount)
                return vscf_rsa_private_key_sign(self.c_ctx, vsc_data(dataPointer, data.count), signatureBuf)
            })
        })
        signature.count = vsc_buffer_len(signatureBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return signature
    }

    /// Return length in bytes required to hold signature.
    @objc public func signatureLen() -> Int {
        let proxyResult = vscf_rsa_private_key_signature_len(self.c_ctx)

        return proxyResult
    }

    /// Extract public part of the key.
    @objc public func extractPublicKey() -> PublicKey {
        let proxyResult = vscf_rsa_private_key_extract_public_key(self.c_ctx)

        return PublicKeyProxy.init(c_ctx: proxyResult!)
    }

    /// Export private key in the binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA private key must be exported in format defined in
    /// RFC 3447 Appendix A.1.2.
    @objc public func exportPrivateKey() throws -> Data {
        let outCount = self.exportedPrivateKeyLen()
        var out = Data(count: outCount)
        var outBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outBuf)
        }

        let proxyResult = out.withUnsafeMutableBytes({ (outPointer: UnsafeMutablePointer<byte>) -> vscf_error_t in
            vsc_buffer_init(outBuf)
            vsc_buffer_use(outBuf, outPointer, outCount)
            return vscf_rsa_private_key_export_private_key(self.c_ctx, outBuf)
        })
        out.count = vsc_buffer_len(outBuf)

        try FoundationError.handleError(fromC: proxyResult)

        return out
    }

    /// Return length in bytes required to hold exported private key.
    @objc public func exportedPrivateKeyLen() -> Int {
        let proxyResult = vscf_rsa_private_key_exported_private_key_len(self.c_ctx)

        return proxyResult
    }

    /// Import private key from the binary format.
    ///
    /// Binary format must be defined in the key specification.
    /// For instance, RSA private key must be imported from the format defined in
    /// RFC 3447 Appendix A.1.2.
    @objc public func importPrivateKey(data: Data) throws {
        let proxyResult = data.withUnsafeBytes({ (dataPointer: UnsafePointer<byte>) -> vscf_error_t in
            return vscf_rsa_private_key_import_private_key(self.c_ctx, vsc_data(dataPointer, data.count))
        })

        try FoundationError.handleError(fromC: proxyResult)
    }
}
