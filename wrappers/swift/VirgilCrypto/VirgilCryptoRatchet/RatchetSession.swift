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
import VSCRatchet
import VirgilCryptoCommon
import VirgilCryptoFoundation

@objc(VSCRRatchetSession) public class RatchetSession: NSObject {

    /// FIXME
    static let maxRatchetLength = 1024 * 1024;

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscr_ratchet_session_new()
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
        self.c_ctx = vscr_ratchet_session_shallow_copy(c_ctx)
        super.init()
    }

    public init(receivedFirstResponse: Bool, senderIdentityPublicKey: Data, senderEphemeralPublicKey: Data, receiverLongtermPublicKey: Data, receiverOnetimePublicKey: Data, ratchet: Ratchet) {
        let proxyResult = senderIdentityPublicKey.withUnsafeBytes({ (senderIdentityPublicKeyPointer: UnsafePointer<byte>) -> OpaquePointer in
            senderEphemeralPublicKey.withUnsafeBytes({ (senderEphemeralPublicKeyPointer: UnsafePointer<byte>) -> OpaquePointer in
                receiverLongtermPublicKey.withUnsafeBytes({ (receiverLongtermPublicKeyPointer: UnsafePointer<byte>) -> OpaquePointer in
                    receiverOnetimePublicKey.withUnsafeBytes({ (receiverOnetimePublicKeyPointer: UnsafePointer<byte>) -> OpaquePointer in
                        var senderIdentityPublicKeyBuf = vsc_buffer_new_with_data(vsc_data(senderIdentityPublicKeyPointer, senderIdentityPublicKey.count))
                        defer {
                            vsc_buffer_delete(senderIdentityPublicKeyBuf)
                        }

                        var senderEphemeralPublicKeyBuf = vsc_buffer_new_with_data(vsc_data(senderEphemeralPublicKeyPointer, senderEphemeralPublicKey.count))
                        defer {
                            vsc_buffer_delete(senderEphemeralPublicKeyBuf)
                        }

                        var receiverLongtermPublicKeyBuf = vsc_buffer_new_with_data(vsc_data(receiverLongtermPublicKeyPointer, receiverLongtermPublicKey.count))
                        defer {
                            vsc_buffer_delete(receiverLongtermPublicKeyBuf)
                        }

                        var receiverOnetimePublicKeyBuf = vsc_buffer_new_with_data(vsc_data(receiverOnetimePublicKeyPointer, receiverOnetimePublicKey.count))
                        defer {
                            vsc_buffer_delete(receiverOnetimePublicKeyBuf)
                        }
                        return vscr_ratchet_session_new_with_members(receivedFirstResponse, senderIdentityPublicKeyBuf, senderEphemeralPublicKeyBuf, receiverLongtermPublicKeyBuf, receiverOnetimePublicKeyBuf, &ratchet.c_ctx)
                    })
                })
            })
        })

        self.c_ctx = proxyResult
    }

    /// Release underlying C context.
    deinit {
        vscr_ratchet_session_delete(self.c_ctx)
    }

    @objc public func setRng(rng: RatchetRng) {
        vscr_ratchet_session_release_rng(self.c_ctx)
        vscr_ratchet_session_use_rng(self.c_ctx, rng.c_ctx)
    }

    @objc public func setRatchet(ratchet: Ratchet) {
        vscr_ratchet_session_release_ratchet(self.c_ctx)
        vscr_ratchet_session_use_ratchet(self.c_ctx, ratchet.c_ctx)
    }

    @objc public func initiate(senderIdentityPrivateKey: Data, receiverIdentityPublicKey: Data, receiverLongTermPublicKey: Data, receiverOneTimePublicKey: Data) throws {
        let proxyResult = senderIdentityPrivateKey.withUnsafeBytes({ (senderIdentityPrivateKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
            receiverIdentityPublicKey.withUnsafeBytes({ (receiverIdentityPublicKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                receiverLongTermPublicKey.withUnsafeBytes({ (receiverLongTermPublicKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                    receiverOneTimePublicKey.withUnsafeBytes({ (receiverOneTimePublicKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                        var receiverLongTermPublicKeyBuf = vsc_buffer_new_with_data(vsc_data(receiverLongTermPublicKeyPointer, receiverLongTermPublicKey.count))
                        defer {
                            vsc_buffer_delete(receiverLongTermPublicKeyBuf)
                        }

                        var receiverOneTimePublicKeyBuf = vsc_buffer_new_with_data(vsc_data(receiverOneTimePublicKeyPointer, receiverOneTimePublicKey.count))
                        defer {
                            vsc_buffer_delete(receiverOneTimePublicKeyBuf)
                        }
                        return vscr_ratchet_session_initiate(self.c_ctx, vsc_data(senderIdentityPrivateKeyPointer, senderIdentityPrivateKey.count), vsc_data(receiverIdentityPublicKeyPointer, receiverIdentityPublicKey.count), receiverLongTermPublicKeyBuf, receiverOneTimePublicKeyBuf)
                    })
                })
            })
        })

        try RatchetError.handleError(fromC: proxyResult)
    }

    @objc public func respond(senderIdentityPublicKey: Data, senderEphemeralPublicKey: Data, ratchetPublicKey: Data, receiverIdentityPrivateKey: Data, receiverLongTermPrivateKey: Data, receiverOneTimePrivateKey: Data, message: RegularMessage) throws {
        let proxyResult = senderIdentityPublicKey.withUnsafeBytes({ (senderIdentityPublicKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
            senderEphemeralPublicKey.withUnsafeBytes({ (senderEphemeralPublicKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                ratchetPublicKey.withUnsafeBytes({ (ratchetPublicKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                    receiverIdentityPrivateKey.withUnsafeBytes({ (receiverIdentityPrivateKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                        receiverLongTermPrivateKey.withUnsafeBytes({ (receiverLongTermPrivateKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                            receiverOneTimePrivateKey.withUnsafeBytes({ (receiverOneTimePrivateKeyPointer: UnsafePointer<byte>) -> vscr_error_t in
                                var senderIdentityPublicKeyBuf = vsc_buffer_new_with_data(vsc_data(senderIdentityPublicKeyPointer, senderIdentityPublicKey.count))
                                defer {
                                    vsc_buffer_delete(senderIdentityPublicKeyBuf)
                                }

                                var senderEphemeralPublicKeyBuf = vsc_buffer_new_with_data(vsc_data(senderEphemeralPublicKeyPointer, senderEphemeralPublicKey.count))
                                defer {
                                    vsc_buffer_delete(senderEphemeralPublicKeyBuf)
                                }

                                var ratchetPublicKeyBuf = vsc_buffer_new_with_data(vsc_data(ratchetPublicKeyPointer, ratchetPublicKey.count))
                                defer {
                                    vsc_buffer_delete(ratchetPublicKeyBuf)
                                }

                                var receiverIdentityPrivateKeyBuf = vsc_buffer_new_with_data(vsc_data(receiverIdentityPrivateKeyPointer, receiverIdentityPrivateKey.count))
                                defer {
                                    vsc_buffer_delete(receiverIdentityPrivateKeyBuf)
                                }

                                var receiverLongTermPrivateKeyBuf = vsc_buffer_new_with_data(vsc_data(receiverLongTermPrivateKeyPointer, receiverLongTermPrivateKey.count))
                                defer {
                                    vsc_buffer_delete(receiverLongTermPrivateKeyBuf)
                                }

                                var receiverOneTimePrivateKeyBuf = vsc_buffer_new_with_data(vsc_data(receiverOneTimePrivateKeyPointer, receiverOneTimePrivateKey.count))
                                defer {
                                    vsc_buffer_delete(receiverOneTimePrivateKeyBuf)
                                }
                                return vscr_ratchet_session_respond(self.c_ctx, senderIdentityPublicKeyBuf, senderEphemeralPublicKeyBuf, ratchetPublicKeyBuf, receiverIdentityPrivateKeyBuf, receiverLongTermPrivateKeyBuf, receiverOneTimePrivateKeyBuf, message.c_ctx)
                            })
                        })
                    })
                })
            })
        })

        try RatchetError.handleError(fromC: proxyResult)
    }

    @objc public func encryptLen(plainTextLen: Int) -> Int {
        let proxyResult = vscr_ratchet_session_encrypt_len(self.c_ctx, plainTextLen)

        return proxyResult
    }

    @objc public func encrypt(plainText: Data) throws -> Data {
        let cipherTextCount = self.encryptLen(plainTextLen: plainText.count)
        var cipherText = Data(count: cipherTextCount)
        var cipherTextBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(cipherTextBuf)
        }

        let proxyResult = plainText.withUnsafeBytes({ (plainTextPointer: UnsafePointer<byte>) -> vscr_error_t in
            cipherText.withUnsafeMutableBytes({ (cipherTextPointer: UnsafeMutablePointer<byte>) -> vscr_error_t in
                vsc_buffer_init(cipherTextBuf)
                vsc_buffer_use(cipherTextBuf, cipherTextPointer, cipherTextCount)
                return vscr_ratchet_session_encrypt(self.c_ctx, vsc_data(plainTextPointer, plainText.count), cipherTextBuf)
            })
        })
        cipherText.count = vsc_buffer_len(cipherTextBuf)

        try RatchetError.handleError(fromC: proxyResult)

        return cipherText
    }

    @objc public func decryptLen(message: Message) -> Int {
        let proxyResult = vscr_ratchet_session_decrypt_len(self.c_ctx, message.c_ctx)

        return proxyResult
    }

    @objc public func decrypt(message: Message) throws -> Data {
        let plainTextCount = self.decryptLen(message: message)
        var plainText = Data(count: plainTextCount)
        var plainTextBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(plainTextBuf)
        }

        let proxyResult = plainText.withUnsafeMutableBytes({ (plainTextPointer: UnsafeMutablePointer<byte>) -> vscr_error_t in
            vsc_buffer_init(plainTextBuf)
            vsc_buffer_use(plainTextBuf, plainTextPointer, plainTextCount)
            return vscr_ratchet_session_decrypt(self.c_ctx, message.c_ctx, plainTextBuf)
        })
        plainText.count = vsc_buffer_len(plainTextBuf)

        try RatchetError.handleError(fromC: proxyResult)

        return plainText
    }

    @objc public func serializeLen() -> Int {
        let proxyResult = vscr_ratchet_session_serialize_len(self.c_ctx)

        return proxyResult
    }

    @objc public func serialize() throws -> Data {
        let outputCount = self.serializeLen()
        var output = Data(count: outputCount)
        var outputBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(outputBuf)
        }

        let proxyResult = output.withUnsafeMutableBytes({ (outputPointer: UnsafeMutablePointer<byte>) -> vscr_error_t in
            vsc_buffer_init(outputBuf)
            vsc_buffer_use(outputBuf, outputPointer, outputCount)
            return vscr_ratchet_session_serialize(self.c_ctx, outputBuf)
        })
        output.count = vsc_buffer_len(outputBuf)

        try RatchetError.handleError(fromC: proxyResult)

        return output
    }

    @objc public static func deserialize(input: Data, errCtx: ErrorCtx) -> RatchetSession {
        let proxyResult = input.withUnsafeBytes({ (inputPointer: UnsafePointer<byte>) in
            return vscr_ratchet_session_deserialize(vsc_data(inputPointer, input.count), errCtx.c_ctx)
        })

        return RatchetSession.init(take: proxyResult!)
    }
}
