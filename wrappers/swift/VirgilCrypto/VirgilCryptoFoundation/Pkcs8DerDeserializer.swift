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

/// Implements PKCS#8 key deserialization from DER format.
@objc(VSCFPkcs8DerDeserializer) public class Pkcs8DerDeserializer: NSObject, Defaults, KeyDeserializer {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscf_pkcs8_der_deserializer_new()
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
        self.c_ctx = vscf_pkcs8_der_deserializer_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscf_pkcs8_der_deserializer_delete(self.c_ctx)
    }

    @objc public func setAsn1Reader(asn1Reader: Asn1Reader) {
        vscf_pkcs8_der_deserializer_release_asn1_reader(self.c_ctx)
        vscf_pkcs8_der_deserializer_use_asn1_reader(self.c_ctx, asn1Reader.c_ctx)
    }

    /// Setup predefined values to the uninitialized class dependencies.
    @objc public func setupDefaults() throws {
        let proxyResult = vscf_pkcs8_der_deserializer_setup_defaults(self.c_ctx)

        try FoundationError.handleError(fromC: proxyResult)
    }

    /// Deserialize given public key as an interchangeable format to the object.
    @objc public func deserializePublicKey(publicKeyData: Data, error: ErrorCtx) -> RawKey {
        let proxyResult = publicKeyData.withUnsafeBytes({ (publicKeyDataPointer: UnsafePointer<byte>) in
            return vscf_pkcs8_der_deserializer_deserialize_public_key(self.c_ctx, vsc_data(publicKeyDataPointer, publicKeyData.count), error.c_ctx)
        })

        return RawKey.init(take: proxyResult!)
    }

    /// Deserialize given private key as an interchangeable format to the object.
    @objc public func deserializePrivateKey(privateKeyData: Data, error: ErrorCtx) -> RawKey {
        let proxyResult = privateKeyData.withUnsafeBytes({ (privateKeyDataPointer: UnsafePointer<byte>) in
            return vscf_pkcs8_der_deserializer_deserialize_private_key(self.c_ctx, vsc_data(privateKeyDataPointer, privateKeyData.count), error.c_ctx)
        })

        return RawKey.init(take: proxyResult!)
    }
}
