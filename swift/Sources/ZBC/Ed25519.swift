// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

import Crypto

/// Deterministic Ed25519 signing (RFC 8032) in pure Swift. CryptoKit's `Curve25519.Signing` randomises
/// its signatures on Apple platforms, so a signature made there would never equal the one every
/// other implementation (and the reference C++ tools) produce for the same bytes; the vectors need
/// byte-equal signatures. Verification stays with CryptoKit / swift-crypto.
public enum Ed25519 {
    // ---- a small unsigned big integer on 32-bit limbs, little-endian ----------------------------
    struct Big: Comparable {
        var limbs: [UInt32]   // little-endian, no leading zero limbs required
        init(_ limbs: [UInt32]) { self.limbs = limbs; trim() }
        init(le bytes: [UInt8]) {
            var l: [UInt32] = []
            var i = 0
            while i < bytes.count {
                var w: UInt32 = 0
                for j in 0..<4 where i + j < bytes.count { w |= UInt32(bytes[i + j]) << UInt32(8 * j) }
                l.append(w); i += 4
            }
            limbs = l; trim()
        }
        init(_ v: UInt64) { limbs = [UInt32(v & 0xffffffff), UInt32(v >> 32)]; trim() }
        mutating func trim() { while let last = limbs.last, last == 0 { limbs.removeLast() } }
        var isZero: Bool { limbs.isEmpty }
        var isOdd: Bool { (limbs.first ?? 0) & 1 == 1 }
        var bitLength: Int { limbs.isEmpty ? 0 : 32 * (limbs.count - 1) + (32 - limbs.last!.leadingZeroBitCount) }
        func bit(_ i: Int) -> Bool { let w = i / 32; return w < limbs.count && (limbs[w] >> UInt32(i % 32)) & 1 == 1 }
        func leBytes(_ n: Int) -> [UInt8] {
            var out = [UInt8](repeating: 0, count: n)
            for i in 0..<n { let w = i / 4; if w < limbs.count { out[i] = UInt8((limbs[w] >> UInt32(8 * (i % 4))) & 0xff) } }
            return out
        }
        static func < (a: Big, b: Big) -> Bool {
            if a.limbs.count != b.limbs.count { return a.limbs.count < b.limbs.count }
            for i in stride(from: a.limbs.count - 1, through: 0, by: -1) where a.limbs[i] != b.limbs[i] { return a.limbs[i] < b.limbs[i] }
            return false
        }
        static func == (a: Big, b: Big) -> Bool { a.limbs == b.limbs }
        static func + (a: Big, b: Big) -> Big {
            var out = [UInt32](repeating: 0, count: max(a.limbs.count, b.limbs.count) + 1)
            var carry: UInt64 = 0
            for i in 0..<out.count - 1 {
                let s = UInt64(i < a.limbs.count ? a.limbs[i] : 0) + UInt64(i < b.limbs.count ? b.limbs[i] : 0) + carry
                out[i] = UInt32(s & 0xffffffff); carry = s >> 32
            }
            out[out.count - 1] = UInt32(carry)
            return Big(out)
        }
        /// a - b, requires a >= b.
        static func - (a: Big, b: Big) -> Big {
            var out = [UInt32](repeating: 0, count: a.limbs.count)
            var borrow: Int64 = 0
            for i in 0..<a.limbs.count {
                var d = Int64(a.limbs[i]) - Int64(i < b.limbs.count ? b.limbs[i] : 0) - borrow
                if d < 0 { d += 1 << 32; borrow = 1 } else { borrow = 0 }
                out[i] = UInt32(d)
            }
            return Big(out)
        }
        static func * (a: Big, b: Big) -> Big {
            if a.isZero || b.isZero { return Big([]) }
            var out = [UInt32](repeating: 0, count: a.limbs.count + b.limbs.count)
            for i in 0..<a.limbs.count {
                var carry: UInt64 = 0
                for j in 0..<b.limbs.count {
                    let p = UInt64(a.limbs[i]) * UInt64(b.limbs[j]) + UInt64(out[i + j]) + carry
                    out[i + j] = UInt32(p & 0xffffffff); carry = p >> 32
                }
                out[i + b.limbs.count] = UInt32(carry)
            }
            return Big(out)
        }
        func shiftedLeft(_ n: Int) -> Big {
            let words = n / 32, bits = n % 32
            var out = [UInt32](repeating: 0, count: limbs.count + words + 1)
            for i in 0..<limbs.count {
                out[i + words] |= limbs[i] << UInt32(bits)
                if bits > 0 { out[i + words + 1] |= limbs[i] >> UInt32(32 - bits) }
            }
            return Big(out)
        }
        func shiftedRight(_ n: Int) -> Big {
            let words = n / 32, bits = n % 32
            if words >= limbs.count { return Big([]) }
            var out = [UInt32](repeating: 0, count: limbs.count - words)
            for i in 0..<out.count {
                out[i] = limbs[i + words] >> UInt32(bits)
                if bits > 0 && i + words + 1 < limbs.count { out[i] |= limbs[i + words + 1] << UInt32(32 - bits) }
            }
            return Big(out)
        }
        /// Remainder by binary long division (used only for the scalar reductions mod L).
        func mod(_ m: Big) -> Big {
            if self < m { return self }
            var r = self
            var shift = r.bitLength - m.bitLength
            var d = m.shiftedLeft(shift)
            while shift >= 0 {
                if !(r < d) { r = r - d }
                d = d.shiftedRight(1); shift -= 1
            }
            return r
        }
    }

    // ---- the field GF(2^255 - 19), reduction using 2^256 = 38 (mod p) --------------------------
    static let p = Big(le: [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f])
    static let L = Big(le: [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10])
    static let thirtyEight = Big(38)

    static func reduceP(_ x: Big) -> Big {
        var r = x
        while r.bitLength > 256 {
            let hi = r.shiftedRight(256), lo = Big(Array(r.limbs.prefix(8)))
            r = lo + hi * thirtyEight
        }
        while !(r < p) { r = r - p }
        return r
    }
    static func fadd(_ a: Big, _ b: Big) -> Big { reduceP(a + b) }
    static func fsub(_ a: Big, _ b: Big) -> Big { a < b ? reduceP(a + p - b) : a - b }
    static func fmul(_ a: Big, _ b: Big) -> Big { reduceP(a * b) }
    static func fpow(_ b: Big, _ e: Big) -> Big {
        var r = Big(1), base = b
        for i in 0..<e.bitLength { if e.bit(i) { r = fmul(r, base) }; base = fmul(base, base) }
        return r
    }
    static func finv(_ a: Big) -> Big { fpow(a, p - Big(2)) }

    static let d: Big = fmul(fsub(Big([]), Big(121665)), finv(Big(121666)))
    static let sqrtM1: Big = fpow(Big(2), (p - Big(1)).shiftedRight(2))
    static let gy: Big = fmul(Big(4), finv(Big(5)))
    static let gx: Big = recoverX(gy, sign: false)!

    static func recoverX(_ y: Big, sign: Bool) -> Big? {
        let y2 = fmul(y, y)
        let u = fsub(y2, Big(1)), v = fadd(fmul(d, y2), Big(1))
        var x = fpow(fmul(u, finv(v)), (p + Big(3)).shiftedRight(3))
        if fsub(fmul(v, fmul(x, x)), u) != Big([]) { x = fmul(x, sqrtM1) }
        if fsub(fmul(v, fmul(x, x)), u) != Big([]) { return nil }
        if x.isOdd != sign { x = fsub(p, x) }
        return x
    }

    // ---- points in extended coordinates -------------------------------------------------------
    struct Pt { var x: Big, y: Big, z: Big, t: Big }
    static let zero = Pt(x: Big([]), y: Big(1), z: Big(1), t: Big([]))
    static let base = Pt(x: gx, y: gy, z: Big(1), t: fmul(gx, gy))

    static func add(_ p1: Pt, _ p2: Pt) -> Pt {
        let a = fmul(fsub(p1.y, p1.x), fsub(p2.y, p2.x))
        let b = fmul(fadd(p1.y, p1.x), fadd(p2.y, p2.x))
        let c = fmul(fmul(Big(2), fmul(p1.t, p2.t)), d)
        let dd = fmul(Big(2), fmul(p1.z, p2.z))
        let e = fsub(b, a), f = fsub(dd, c), g = fadd(dd, c), h = fadd(b, a)
        return Pt(x: fmul(e, f), y: fmul(g, h), z: fmul(f, g), t: fmul(e, h))
    }
    static func mul(_ pt: Pt, _ s: Big) -> Pt {
        var r = zero, q = pt
        for i in 0..<256 {
            let sum = add(r, q)
            r = s.bit(i) ? sum : r
            q = add(q, q)
        }
        return r
    }
    static func encode(_ pt: Pt) -> [UInt8] {
        let zi = finv(pt.z)
        let x = fmul(pt.x, zi), y = fmul(pt.y, zi)
        var out = y.leBytes(32)
        if x.isOdd { out[31] |= 0x80 }
        return out
    }
    static func clamp(_ h: [UInt8]) -> Big {
        var k = Array(h[0..<32])
        k[0] &= 248; k[31] &= 127; k[31] |= 64
        return Big(le: k)
    }
    static func sha512(_ parts: [UInt8]...) -> [UInt8] {
        var h = SHA512()
        for p in parts { h.update(data: p) }
        return Array(h.finalize())
    }

    /// The 32-byte public key of a 32-byte seed.
    public static func publicKey(seed: [UInt8]) -> [UInt8] {
        encode(mul(base, clamp(sha512(seed))))
    }

    /// Detached 64-byte signature of `message` with the 32-byte seed, deterministic per RFC 8032.
    public static func sign(_ message: [UInt8], seed: [UInt8]) -> [UInt8] {
        let h = sha512(seed)
        let a = clamp(h)
        let prefix = Array(h[32..<64])
        let pub = encode(mul(base, a))
        let r = Big(le: sha512(prefix, message)).mod(L)
        let bigR = encode(mul(base, r))
        let k = Big(le: sha512(bigR, pub, message)).mod(L)
        let s = (r + k * a).mod(L)
        return bigR + s.leBytes(32)
    }

    /// True when `signature` is a valid signature of `message` by `publicKey`. Never throws.
    public static func verify(_ message: [UInt8], _ signature: [UInt8], _ publicKey: [UInt8]) -> Bool {
        guard signature.count == 64, let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return pk.isValidSignature(signature, for: message)
    }
}
