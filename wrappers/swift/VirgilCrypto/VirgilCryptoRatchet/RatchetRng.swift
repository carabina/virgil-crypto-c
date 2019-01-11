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

/// Interface for ratchet rng
@objc(VSCRRatchetRng) public protocol RatchetRng : CContext {

    /// Interface for ratchet rng
    @objc func generateRandomData(size: Int) -> Data
}

/// Implement interface methods
@objc(VSCRRatchetRngProxy) internal class RatchetRngProxy: NSObject, RatchetRng {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Take C context that implements this interface
    public init(c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscr_impl_delete(self.c_ctx)
    }

    /// Interface for ratchet rng
    @objc public func generateRandomData(size: Int) -> Data {
        let randomCount = size
        var random = Data(count: randomCount)
        var randomBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(randomBuf)
        }

        random.withUnsafeMutableBytes({ (randomPointer: UnsafeMutablePointer<byte>) -> Void in
            vsc_buffer_init(randomBuf)
            vsc_buffer_use(randomBuf, randomPointer, randomCount)
            vscr_ratchet_rng_generate_random_data(self.c_ctx, size, randomBuf)
        })
        random.count = vsc_buffer_len(randomBuf)

        return random
    }
}
