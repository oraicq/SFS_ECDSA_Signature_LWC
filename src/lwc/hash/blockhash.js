/**
 * Created by pliuzzi on 19/03/24.
 */
import {
    assert,
    join32,
    rotl32, rotr64_hi, rotr64_lo, shr64_hi, shr64_lo,
    split32,
    sum32,
    sum32_4,
    sum32_5, sum64,
    sum64_4_hi,
    sum64_4_lo, sum64_5_hi, sum64_5_lo, sum64_hi, sum64_lo,
    toArray,
    toHex32
} from "./utils";
import {ch32, ft_1, g0_256, g1_256, maj32, s0_256, s1_256} from "./shaCommon";

class BlockHash {
    pending;
    pendingTotal;
    blockSize;
    outSize;
    hmacStrength;
    padLength;
    endian;

    _delta8;
    _delta32;

    constructor(blockSize, outSize, hmacStrength, padLength) {
        this.pending = null;
        this.pendingTotal = 0;
        this.blockSize = blockSize;
        this.outSize = outSize;
        this.hmacStrength = hmacStrength;
        this.padLength = padLength / 8;
        this.endian = 'big';

        this._delta8 = this.blockSize / 8;
        this._delta32 = this.blockSize / 32;
    }

    update(msg, enc) {
        // Convert message to array, pad it, and join into 32bit blocks
        msg = toArray(msg, enc);
        if (!this.pending)
            this.pending = msg;
        else
            this.pending = this.pending.concat(msg);
        this.pendingTotal += msg.length;

        // Enough data, try updating
        if (this.pending.length >= this._delta8) {
            msg = this.pending;

            // Process pending data in blocks
            const r = msg.length % this._delta8;
            this.pending = msg.slice(msg.length - r, msg.length);
            if (this.pending.length === 0)
                this.pending = null;

            msg = join32(msg, 0, msg.length - r, this.endian);
            for (let i = 0; i < msg.length; i += this._delta32)
                this._update(msg, i, i + this._delta32);
        }

        return this;
    }

    _update() {
        throw new Error('Not implemented');
    }

    digest(enc) {
        this.update(this.pad());
        assert(this.pending === null);

        return this._digest(enc);
    }

    _digest() {
        throw new Error('Not implemented');
    }

    pad() {
        let t;
        let i;
        let len = this.pendingTotal;
        const bytes = this._delta8;
        const k = bytes - ((len + this.padLength) % bytes);
        const res = new Array(k + this.padLength);
        res[0] = 0x80;
        for (i = 1; i < k; i++)
            res[i] = 0;

        // Append length
        len <<= 3;
        if (this.endian === 'big') {
            for (t = 8; t < this.padLength; t++)
                res[i++] = 0;

            res[i++] = 0;
            res[i++] = 0;
            res[i++] = 0;
            res[i++] = 0;
            res[i++] = (len >>> 24) & 0xff;
            res[i++] = (len >>> 16) & 0xff;
            res[i++] = (len >>> 8) & 0xff;
            res[i++] = len & 0xff;
        } else {
            res[i++] = len & 0xff;
            res[i++] = (len >>> 8) & 0xff;
            res[i++] = (len >>> 16) & 0xff;
            res[i++] = (len >>> 24) & 0xff;
            res[i++] = 0;
            res[i++] = 0;
            res[i++] = 0;
            res[i++] = 0;

            for (t = 8; t < this.padLength; t++)
                res[i++] = 0;
        }

        return res;
    }

}

const sha1_K = [
    0x5A827999, 0x6ED9EBA1,
    0x8F1BBCDC, 0xCA62C1D6
];

class SHA1 extends BlockHash {
    constructor() {
        super(512, 160, 80, 64);
        this.h = [
            0x67452301, 0xefcdab89, 0x98badcfe,
            0x10325476, 0xc3d2e1f0];
        this.W = new Array(80);
    }

    _update(msg, start) {
        const W = this.W;

        for (let i = 0; i < 16; i++)
            W[i] = msg[start + i];

        for (let i = 0; i < W.length; i++)
            W[i] = rotl32(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);

        let a = this.h[0];
        let b = this.h[1];
        let c = this.h[2];
        let d = this.h[3];
        let e = this.h[4];

        for (let i = 0; i < W.length; i++) {
            const s = ~~(i / 20);
            const t = sum32_5(rotl32(a, 5), ft_1(s, b, c, d), e, W[i], sha1_K[s]);
            e = d;
            d = c;
            c = rotl32(b, 30);
            b = a;
            a = t;
        }

        this.h[0] = sum32(this.h[0], a);
        this.h[1] = sum32(this.h[1], b);
        this.h[2] = sum32(this.h[2], c);
        this.h[3] = sum32(this.h[3], d);
        this.h[4] = sum32(this.h[4], e);
    }

    _digest(enc) {
        if (enc === 'hex')
            return toHex32(this.h, 'big');
        else
            return split32(this.h, 'big');
    }

}

const sha256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

class SHA256 extends BlockHash {
    constructor() {
        super(512, 256, 192, 64);
        this.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ];
        this.k = sha256_K;
        this.W = new Array(64);
    }

    _update(msg, start) {
        const W = this.W;

        for (let i = 0; i < 16; i++)
            W[i] = msg[start + i];
        for (let i = 0; i < W.length; i++)
            W[i] = sum32_4(g1_256(W[i - 2]), W[i - 7], g0_256(W[i - 15]), W[i - 16]);

        let a = this.h[0];
        let b = this.h[1];
        let c = this.h[2];
        let d = this.h[3];
        let e = this.h[4];
        let f = this.h[5];
        let g = this.h[6];
        let h = this.h[7];

        assert(this.k.length === W.length);
        for (let i = 0; i < W.length; i++) {
            const T1 = sum32_5(h, s1_256(e), ch32(e, f, g), this.k[i], W[i]);
            const T2 = sum32(s0_256(a), maj32(a, b, c));
            h = g;
            g = f;
            f = e;
            e = sum32(d, T1);
            d = c;
            c = b;
            b = a;
            a = sum32(T1, T2);
        }

        this.h[0] = sum32(this.h[0], a);
        this.h[1] = sum32(this.h[1], b);
        this.h[2] = sum32(this.h[2], c);
        this.h[3] = sum32(this.h[3], d);
        this.h[4] = sum32(this.h[4], e);
        this.h[5] = sum32(this.h[5], f);
        this.h[6] = sum32(this.h[6], g);
        this.h[7] = sum32(this.h[7], h);
    }

    _digest(enc) {
        if (enc === 'hex')
            return toHex32(this.h, 'big');
        else
            return split32(this.h, 'big');
    }
}

class SHA224 extends SHA256 {
    constructor() {
        super();
        super.blockSize = 512;
        super.outSize = 224;
        super.hmacStrength = 192;
        super.padLength = 64;
        this.h = [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    }

    _digest(enc) {
        // Just truncate output
        if (enc === 'hex')
            return toHex32(this.h.slice(0, 7), 'big');
        else
            return split32(this.h.slice(0, 7), 'big');
    };
}

const sha512_K = [
    0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd,
    0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
    0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
    0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
    0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
    0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
    0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
    0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
    0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
    0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
    0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
    0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
    0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
    0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
    0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
    0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
    0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
    0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
    0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
    0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
    0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
    0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
    0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
    0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
    0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
    0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
    0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
    0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
    0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
    0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
    0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
    0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
    0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
    0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
    0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
    0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
    0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
    0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
    0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
    0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
];

class SHA512 extends BlockHash {
    constructor() {
        super(1024, 512, 192, 128);
        this.k = sha512_K;
        this.W = new Array(160);
    }

    _prepareBlock(msg, start) {
        const W = this.W;

        // 32 x 32bit words
        for (let i = 0; i < 32; i++)
            W[i] = msg[start + i];
        for (let i = 0; i < W.length; i += 2) {
            const c0_hi = g1_512_hi(W[i - 4], W[i - 3]);  // i - 2
            const c0_lo = g1_512_lo(W[i - 4], W[i - 3]);
            const c1_hi = W[i - 14];  // i - 7
            const c1_lo = W[i - 13];
            const c2_hi = g0_512_hi(W[i - 30], W[i - 29]);  // i - 15
            const c2_lo = g0_512_lo(W[i - 30], W[i - 29]);
            const c3_hi = W[i - 32];  // i - 16
            const c3_lo = W[i - 31];

            W[i] = sum64_4_hi(
                c0_hi, c0_lo,
                c1_hi, c1_lo,
                c2_hi, c2_lo,
                c3_hi, c3_lo);
            W[i + 1] = sum64_4_lo(
                c0_hi, c0_lo,
                c1_hi, c1_lo,
                c2_hi, c2_lo,
                c3_hi, c3_lo);
        }
    }

    _update(msg, start) {
        this._prepareBlock(msg, start);

        const W = this.W;

        let ah = this.h[0];
        let al = this.h[1];
        let bh = this.h[2];
        let bl = this.h[3];
        let ch = this.h[4];
        let cl = this.h[5];
        let dh = this.h[6];
        let dl = this.h[7];
        let eh = this.h[8];
        let el = this.h[9];
        let fh = this.h[10];
        let fl = this.h[11];
        let gh = this.h[12];
        let gl = this.h[13];
        let hh = this.h[14];
        let hl = this.h[15];

        assert(this.k.length === W.length);
        for (let i = 0; i < W.length; i += 2) {
            let c0_hi = hh;
            let c0_lo = hl;
            let c1_hi = s1_512_hi(eh, el);
            let c1_lo = s1_512_lo(eh, el);
            const c2_hi = ch64_hi(eh, el, fh, fl, gh, gl);
            const c2_lo = ch64_lo(eh, el, fh, fl, gh, gl);
            const c3_hi = this.k[i];
            const c3_lo = this.k[i + 1];
            const c4_hi = W[i];
            const c4_lo = W[i + 1];

            const T1_hi = sum64_5_hi(
                c0_hi, c0_lo,
                c1_hi, c1_lo,
                c2_hi, c2_lo,
                c3_hi, c3_lo,
                c4_hi, c4_lo);
            const T1_lo = sum64_5_lo(
                c0_hi, c0_lo,
                c1_hi, c1_lo,
                c2_hi, c2_lo,
                c3_hi, c3_lo,
                c4_hi, c4_lo);

            c0_hi = s0_512_hi(ah, al);
            c0_lo = s0_512_lo(ah, al);
            c1_hi = maj64_hi(ah, al, bh, bl, ch, cl);
            c1_lo = maj64_lo(ah, al, bh, bl, ch, cl);

            const T2_hi = sum64_hi(c0_hi, c0_lo, c1_hi, c1_lo);
            const T2_lo = sum64_lo(c0_hi, c0_lo, c1_hi, c1_lo);

            hh = gh;
            hl = gl;

            gh = fh;
            gl = fl;

            fh = eh;
            fl = el;

            eh = sum64_hi(dh, dl, T1_hi, T1_lo);
            el = sum64_lo(dl, dl, T1_hi, T1_lo);

            dh = ch;
            dl = cl;

            ch = bh;
            cl = bl;

            bh = ah;
            bl = al;

            ah = sum64_hi(T1_hi, T1_lo, T2_hi, T2_lo);
            al = sum64_lo(T1_hi, T1_lo, T2_hi, T2_lo);
        }

        sum64(this.h, 0, ah, al);
        sum64(this.h, 2, bh, bl);
        sum64(this.h, 4, ch, cl);
        sum64(this.h, 6, dh, dl);
        sum64(this.h, 8, eh, el);
        sum64(this.h, 10, fh, fl);
        sum64(this.h, 12, gh, gl);
        sum64(this.h, 14, hh, hl);
    }

    _digest(enc) {
        if (enc === 'hex')
            return toHex32(this.h, 'big');
        else
            return split32(this.h, 'big');
    }
}

function ch64_hi(xh, xl, yh, yl, zh) {
    let r = (xh & yh) ^ ((~xh) & zh);
    if (r < 0)
        r += 0x100000000;
    return r;
}

function ch64_lo(xh, xl, yh, yl, zh, zl) {
    let r = (xl & yl) ^ ((~xl) & zl);
    if (r < 0)
        r += 0x100000000;
    return r;
}

function maj64_hi(xh, xl, yh, yl, zh) {
    let r = (xh & yh) ^ (xh & zh) ^ (yh & zh);
    if (r < 0)
        r += 0x100000000;
    return r;
}

function maj64_lo(xh, xl, yh, yl, zh, zl) {
    let r = (xl & yl) ^ (xl & zl) ^ (yl & zl);
    if (r < 0)
        r += 0x100000000;
    return r;
}

function s0_512_hi(xh, xl) {
    const c0_hi = rotr64_hi(xh, xl, 28);
    const c1_hi = rotr64_hi(xl, xh, 2);  // 34
    const c2_hi = rotr64_hi(xl, xh, 7);  // 39

    let r = c0_hi ^ c1_hi ^ c2_hi;
    if (r < 0)
        r += 0x100000000;
    return r;
}

function s0_512_lo(xh, xl) {
    const c0_lo = rotr64_lo(xh, xl, 28);
    const c1_lo = rotr64_lo(xl, xh, 2);  // 34
    const c2_lo = rotr64_lo(xl, xh, 7);  // 39

    let r = c0_lo ^ c1_lo ^ c2_lo;
    if (r < 0)
        r += 0x100000000;
    return r;
}

function s1_512_hi(xh, xl) {
    const c0_hi = rotr64_hi(xh, xl, 14);
    const c1_hi = rotr64_hi(xh, xl, 18);
    const c2_hi = rotr64_hi(xl, xh, 9);  // 41

    let r = c0_hi ^ c1_hi ^ c2_hi;
    if (r < 0)
        r += 0x100000000;
    return r;
}

function s1_512_lo(xh, xl) {
    const c0_lo = rotr64_lo(xh, xl, 14);
    const c1_lo = rotr64_lo(xh, xl, 18);
    const c2_lo = rotr64_lo(xl, xh, 9);  // 41

    let r = c0_lo ^ c1_lo ^ c2_lo;
    if (r < 0)
        r += 0x100000000;
    return r;
}

function g0_512_hi(xh, xl) {
    const c0_hi = rotr64_hi(xh, xl, 1);
    const c1_hi = rotr64_hi(xh, xl, 8);
    const c2_hi = shr64_hi(xh, xl, 7);

    let r = c0_hi ^ c1_hi ^ c2_hi;
    if (r < 0)
        r += 0x100000000;
    return r;
}

function g0_512_lo(xh, xl) {
    const c0_lo = rotr64_lo(xh, xl, 1);
    const c1_lo = rotr64_lo(xh, xl, 8);
    const c2_lo = shr64_lo(xh, xl, 7);

    let r = c0_lo ^ c1_lo ^ c2_lo;
    if (r < 0)
        r += 0x100000000;
    return r;
}

function g1_512_hi(xh, xl) {
    const c0_hi = rotr64_hi(xh, xl, 19);
    const c1_hi = rotr64_hi(xl, xh, 29);  // 61
    const c2_hi = shr64_hi(xh, xl, 6);

    let r = c0_hi ^ c1_hi ^ c2_hi;
    if (r < 0)
        r += 0x100000000;
    return r;
}

function g1_512_lo(xh, xl) {
    const c0_lo = rotr64_lo(xh, xl, 19);
    const c1_lo = rotr64_lo(xl, xh, 29);  // 61
    const c2_lo = shr64_lo(xh, xl, 6);

    let r = c0_lo ^ c1_lo ^ c2_lo;
    if (r < 0)
        r += 0x100000000;
    return r;
}

class SHA384 extends SHA512 {
    constructor() {
        super();
        this.blockSize = 1024;
        this.outSize = 384;
        this.hmacStrength = 192;
        this.padLength = 128;
        this.h = [
            0xcbbb9d5d, 0xc1059ed8,
            0x629a292a, 0x367cd507,
            0x9159015a, 0x3070dd17,
            0x152fecd8, 0xf70e5939,
            0x67332667, 0xffc00b31,
            0x8eb44a87, 0x68581511,
            0xdb0c2e0d, 0x64f98fa7,
            0x47b5481d, 0xbefa4fa4];
    }

    _digest(enc) {
        if (enc === 'hex')
            return toHex32(this.h.slice(0, 12), 'big');
        else
            return split32(this.h.slice(0, 12), 'big');
    }
}

export {
    SHA1, SHA224, SHA256, SHA512, SHA384
}
