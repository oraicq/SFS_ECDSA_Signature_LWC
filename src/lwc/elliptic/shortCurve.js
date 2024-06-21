/**
 * Created by pliuzzi on 18/03/24.
 */


import {BN} from "./bigNumber";
import {BaseCurve, BasePoint} from "./baseCurve";
import {assert, toArray} from "./utils";


export class ShortCurve extends BaseCurve{
    constructor(conf) {
        super( 'short', conf);
        this.g = conf.g && ShortPoint.fromJSON(this, conf.g, conf.gRed);
        this.a = new BN(conf.a, 16).toRed(this.red);
        this.b = new BN(conf.b, 16).toRed(this.red);
        this.tinv = this.two.redInvm();

        this.zeroA = this.a.fromRed().cmpn(0) === 0;
        this.threeA = this.a.fromRed().sub(this.p).cmpn(-3) === 0;

        // If the curve is endomorphic, precalculate beta and lambda
        this.endo = this._getEndomorphism(conf);
        this._endoWnafT1 = new Array(4);
        this._endoWnafT2 = new Array(4);
    }
    _getEndomorphism(conf) {
        // No efficient endomorphism
        if (!this.zeroA || !this.g || !this.n || this.p.modn(3) !== 1)
            return;

        // Compute beta and lambda, that lambda * P = (beta * Px; Py)
        let beta;
        let lambda;
        if (conf.beta) {
            beta = new BN(conf.beta, 16).toRed(this.red);
        } else {
            const betas = this._getEndoRoots(this.p);
            // Choose the smallest beta
            beta = betas[0].cmp(betas[1]) < 0 ? betas[0] : betas[1];
            beta = beta.toRed(this.red);
        }
        if (conf.lambda) {
            lambda = new BN(conf.lambda, 16);
        } else {
            // Choose the lambda that is matching selected beta
            const lambdas = this._getEndoRoots(this.n);
            if (this.g.mul(lambdas[0]).x.cmp(this.g.x.redMul(beta)) === 0) {
                lambda = lambdas[0];
            } else {
                lambda = lambdas[1];
                assert(this.g.mul(lambda).x.cmp(this.g.x.redMul(beta)) === 0);
            }
        }

        // Get basis vectors, used for balanced length-two representation
        let basis;
        if (conf.basis) {
            basis = conf.basis.map(function (vec) {
                return {
                    a: new BN(vec.a, 16),
                    b: new BN(vec.b, 16),
                };
            });
        } else {
            basis = this._getEndoBasis(lambda);
        }

        return {
            beta: beta,
            lambda: lambda,
            basis: basis,
        };
    }
    _getEndoRoots(num) {
        // Find roots of for x^2 + x + 1 in F
        // Root = (-1 +- Sqrt(-3)) / 2
        //
        const red = num === this.p ? this.red : BN.mont(num);
        const tinv = new BN(2).toRed(red).redInvm();
        const ntinv = tinv.redNeg();

        const s = new BN(3).toRed(red).redNeg().redSqrt().redMul(tinv);

        const l1 = ntinv.redAdd(s).fromRed();
        const l2 = ntinv.redSub(s).fromRed();
        return [l1, l2];
    }
    _getEndoBasis(lambda) {
        // aprxSqrt >= sqrt(this.n)
        const aprxSqrt = this.n.ushrn(Math.floor(this.n.bitLength() / 2));

        // 3.74
        // Run EGCD, until r(L + 1) < aprxSqrt
        let u = lambda;
        let v = this.n.clone();
        let x1 = new BN(1);
        let y1 = new BN(0);
        let x2 = new BN(0);
        let y2 = new BN(1);

        // NOTE: all vectors are roots of: a + b * lambda = 0 (mod n)
        let a0;
        let b0;
        // First vector
        let a1;
        let b1;
        // Second vector
        let a2;
        let b2;

        let prevR;
        let i = 0;
        let r;
        let x;
        while (u.cmpn(0) !== 0) {
            const q = v.div(u);
            r = v.sub(q.mul(u));
            x = x2.sub(q.mul(x1));
            const y = y2.sub(q.mul(y1));

            if (!a1 && r.cmp(aprxSqrt) < 0) {
                a0 = prevR.neg();
                b0 = x1;
                a1 = r.neg();
                b1 = x;
            } else if (a1 && ++i === 2) {
                break;
            }
            prevR = r;

            v = u;
            u = r;
            x2 = x1;
            x1 = x;
            y2 = y1;
            y1 = y;
        }
        a2 = r.neg();
        b2 = x;

        const len1 = a1.sqr().add(b1.sqr());
        const len2 = a2.sqr().add(b2.sqr());
        if (len2.cmp(len1) >= 0) {
            a2 = a0;
            b2 = b0;
        }

        // Normalize signs
        if (a1.negative) {
            a1 = a1.neg();
            b1 = b1.neg();
        }
        if (a2.negative) {
            a2 = a2.neg();
            b2 = b2.neg();
        }

        return [
            {a: a1, b: b1},
            {a: a2, b: b2},
        ];
    }
    _endoSplit(k) {
        const basis = this.endo.basis;
        const v1 = basis[0];
        const v2 = basis[1];

        const c1 = v2.b.mul(k).divRound(this.n);
        const c2 = v1.b.neg().mul(k).divRound(this.n);

        const p1 = c1.mul(v1.a);
        const p2 = c2.mul(v2.a);
        const q1 = c1.mul(v1.b);
        const q2 = c2.mul(v2.b);

        // Calculate answer
        const k1 = k.sub(p1).sub(p2);
        const k2 = q1.add(q2).neg();
        return {k1: k1, k2: k2};
    }
    decodePoint(bytes, enc) {
        bytes = toArray(bytes, enc);

        const len = this.p.byteLength();

        // uncompressed, hybrid-odd, hybrid-even
        if ((bytes[0] === 0x04 || bytes[0] === 0x06 || bytes[0] === 0x07) &&
            bytes.length - 1 === 2 * len) {
            if (bytes[0] === 0x06)
                assert(bytes[bytes.length - 1] % 2 === 0);
            else if (bytes[0] === 0x07)
                assert(bytes[bytes.length - 1] % 2 === 1);

            return this.point(bytes.slice(1, 1 + len),
                bytes.slice(1 + len, 1 + 2 * len));
        } else if ((bytes[0] === 0x02 || bytes[0] === 0x03) &&
            bytes.length - 1 === len) {
            return this.pointFromX(bytes.slice(1, 1 + len), bytes[0] === 0x03);
        }
        throw new Error('Unknown point format');
    }
    pointFromX(x, odd) {
        x = new BN(x, 16);
        if (!x.red)
            x = x.toRed(this.red);

        const y2 = x.redSqr().redMul(x).redIAdd(x.redMul(this.a)).redIAdd(this.b);
        let y = y2.redSqrt();
        if (y.redSqr().redSub(y2).cmp(this.zero) !== 0)
            throw new Error('invalid point');

        // XXX Is there any way to tell if the number is odd without converting it
        // to non-red form?
        const isOdd = y.fromRed().isOdd();
        if (odd && !isOdd || !odd && isOdd)
            y = y.redNeg();

        return this.point(x, y);
    }
    validate(point) {
        if (point.inf)
            return true;

        const x = point.x;
        const y = point.y;

        const ax = this.a.redMul(x);
        const rhs = x.redSqr().redMul(x).redIAdd(ax).redIAdd(this.b);
        return y.redSqr().redISub(rhs).cmpn(0) === 0;
    }
    _endoWnafMulAdd(points, coeffs, jacobianResult) {
        const npoints = this._endoWnafT1;
        const ncoeffs = this._endoWnafT2;
        let i = 0;
        for (i = 0; i < points.length; i++) {
            const split = this._endoSplit(coeffs[i]);
            let p = points[i];
            let beta = p._getBeta();

            if (split.k1.negative) {
                split.k1.ineg();
                p = p.neg(true);
            }
            if (split.k2.negative) {
                split.k2.ineg();
                beta = beta.neg(true);
            }

            npoints[i * 2] = p;
            npoints[i * 2 + 1] = beta;
            ncoeffs[i * 2] = split.k1;
            ncoeffs[i * 2 + 1] = split.k2;
        }
        const res = this._wnafMulAdd(1, npoints, ncoeffs, i * 2, jacobianResult);

        // Clean-up references to points and coefficients
        for (let j = 0; j < i * 2; j++) {
            npoints[j] = null;
            ncoeffs[j] = null;
        }
        return res;
    }
    jpoint(x, y, z) {
        return new JPoint(this, x, y, z);
    }
    point(x, y, isRed) {
        return new ShortPoint(this, x, y, isRed);
    }
}

class ShortPoint extends BasePoint{
    constructor(curve, x, y, isRed) {
        super(curve, 'affine');
        if (x === null && y === null) {
            this.x = null;
            this.y = null;
            this.inf = true;
        } else {
            this.x = new BN(x, 16);
            this.y = new BN(y, 16);
            // Force redgomery representation when loading from JSON
            if (isRed) {
                this.x.forceRed(this.curve.red);
                this.y.forceRed(this.curve.red);
            }
            if (!this.x.red)
                this.x = this.x.toRed(this.curve.red);
            if (!this.y.red)
                this.y = this.y.toRed(this.curve.red);
            this.inf = false;
        }
    }

    _getBeta() {
        if (!this.curve.endo)
            return;

        const pre = this.precomputed;
        if (pre && pre.beta)
            return pre.beta;

        const beta = this.curve.point(this.x.redMul(this.curve.endo.beta), this.y);
        if (pre) {
            const curve = this.curve;
            const endoMul = function (p) {
                return curve.point(p.x.redMul(curve.endo.beta), p.y);
            };
            pre.beta = beta;
            beta.precomputed = {
                beta: null,
                naf: pre.naf && {
                    wnd: pre.naf.wnd,
                    points: pre.naf.points.map(endoMul),
                },
                doubles: pre.doubles && {
                    step: pre.doubles.step,
                    points: pre.doubles.points.map(endoMul),
                },
            };
        }
        return beta;
    }
    toJSON() {
        if (!this.precomputed)
            return [this.x, this.y];

        return [this.x, this.y, this.precomputed && {
            doubles: this.precomputed.doubles && {
                step: this.precomputed.doubles.step,
                points: this.precomputed.doubles.points.slice(1),
            },
            naf: this.precomputed.naf && {
                wnd: this.precomputed.naf.wnd,
                points: this.precomputed.naf.points.slice(1),
            },
        }];
    }
    static fromJSON(curve, obj, red) {
        if (typeof obj === 'string')
            obj = JSON.parse(obj);
        const res = curve.point(obj[0], obj[1], red);
        if (!obj[2])
            return res;

        function obj2point(obj) {
            return curve.point(obj[0], obj[1], red);
        }

        const pre = obj[2];
        res.precomputed = {
            beta: null,
            doubles: pre.doubles && {
                step: pre.doubles.step,
                points: [res].concat(pre.doubles.points.map(obj2point)),
            },
            naf: pre.naf && {
                wnd: pre.naf.wnd,
                points: [res].concat(pre.naf.points.map(obj2point)),
            },
        };
        return res;
    }
    inspect() {
        if (this.isInfinity())
            return '<EC Point Infinity>';
        return '<EC Point x: ' + this.x.fromRed().toString(16, 2) +
            ' y: ' + this.y.fromRed().toString(16, 2) + '>';
    }
    isInfinity() {
        return this.inf;
    }
    add(p) {
        // O + P = P
        if (this.inf)
            return p;

        // P + O = P
        if (p.inf)
            return this;

        // P + P = 2P
        if (this.eq(p))
            return this.dbl();

        // P + (-P) = O
        if (this.neg().eq(p))
            return this.curve.point(null, null);

        // P + Q = O
        if (this.x.cmp(p.x) === 0)
            return this.curve.point(null, null);

        let c = this.y.redSub(p.y);
        if (c.cmpn(0) !== 0)
            c = c.redMul(this.x.redSub(p.x).redInvm());
        const nx = c.redSqr().redISub(this.x).redISub(p.x);
        const ny = c.redMul(this.x.redSub(nx)).redISub(this.y);
        return this.curve.point(nx, ny);
    }
    dbl() {
        if (this.inf)
            return this;

        // 2P = O
        const ys1 = this.y.redAdd(this.y);
        if (ys1.cmpn(0) === 0)
            return this.curve.point(null, null);

        const a = this.curve.a;

        const x2 = this.x.redSqr();
        const dyinv = ys1.redInvm();
        const c = x2.redAdd(x2).redIAdd(x2).redIAdd(a).redMul(dyinv);

        const nx = c.redSqr().redISub(this.x.redAdd(this.x));
        const ny = c.redMul(this.x.redSub(nx)).redISub(this.y);
        return this.curve.point(nx, ny);
    }
    getX() {
        return this.x.fromRed();
    }
    getY() {
        return this.y.fromRed();
    }
    mul(k) {
        k = new BN(k, 16);
        if (this.isInfinity())
            return this;
        else if (this._hasDoubles(k))
            return this.curve._fixedNafMul(this, k);
        else if (this.curve.endo)
            return this.curve._endoWnafMulAdd([this], [k]);
        else
            return this.curve._wnafMul(this, k);
    }
    mulAdd(k1, p2, k2) {
        const points = [this, p2];
        const coeffs = [k1, k2];
        if (this.curve.endo)
            return this.curve._endoWnafMulAdd(points, coeffs);
        else
            return this.curve._wnafMulAdd(1, points, coeffs, 2);
    }
    jmulAdd(k1, p2, k2) {
        const points = [this, p2];
        const coeffs = [k1, k2];
        if (this.curve.endo)
            return this.curve._endoWnafMulAdd(points, coeffs, true);
        else
            return this.curve._wnafMulAdd(1, points, coeffs, 2, true);
    }
    eq(p) {
        return this === p ||
            this.inf === p.inf &&
            (this.inf || this.x.cmp(p.x) === 0 && this.y.cmp(p.y) === 0);
    }
    neg(_precompute) {
        if (this.inf)
            return this;

        const res = this.curve.point(this.x, this.y.redNeg());
        if (_precompute && this.precomputed) {
            const pre = this.precomputed;
            const negate = function (p) {
                return p.neg();
            };
            res.precomputed = {
                naf: pre.naf && {
                    wnd: pre.naf.wnd,
                    points: pre.naf.points.map(negate),
                },
                doubles: pre.doubles && {
                    step: pre.doubles.step,
                    points: pre.doubles.points.map(negate),
                },
            };
        }
        return res;
    }
    toJ() {
        if (this.inf)
            return this.curve.jpoint(null, null, null);

        const res = this.curve.jpoint(this.x, this.y, this.curve.one);
        return res;
    }
}

class JPoint extends BasePoint{
    constructor(curve, x, y, z) {
        super(curve, 'jacobian');
        if (x === null && y === null && z === null) {
            this.x = this.curve.one;
            this.y = this.curve.one;
            this.z = new BN(0);
        } else {
            this.x = new BN(x, 16);
            this.y = new BN(y, 16);
            this.z = new BN(z, 16);
        }
        if (!this.x.red)
            this.x = this.x.toRed(this.curve.red);
        if (!this.y.red)
            this.y = this.y.toRed(this.curve.red);
        if (!this.z.red)
            this.z = this.z.toRed(this.curve.red);

        this.zOne = this.z === this.curve.one;
    }
    toP = function toP() {
        if (this.isInfinity())
            return this.curve.point(null, null);

        const zinv = this.z.redInvm();
        const zinv2 = zinv.redSqr();
        const ax = this.x.redMul(zinv2);
        const ay = this.y.redMul(zinv2).redMul(zinv);

        return this.curve.point(ax, ay);
    }
    neg() {
        return this.curve.jpoint(this.x, this.y.redNeg(), this.z);
    }
    add(p) {
        // O + P = P
        if (this.isInfinity())
            return p;

        // P + O = P
        if (p.isInfinity())
            return this;

        // 12M + 4S + 7A
        const pz2 = p.z.redSqr();
        const z2 = this.z.redSqr();
        const u1 = this.x.redMul(pz2);
        const u2 = p.x.redMul(z2);
        const s1 = this.y.redMul(pz2.redMul(p.z));
        const s2 = p.y.redMul(z2.redMul(this.z));

        const h = u1.redSub(u2);
        const r = s1.redSub(s2);
        if (h.cmpn(0) === 0) {
            if (r.cmpn(0) !== 0)
                return this.curve.jpoint(null, null, null);
            else
                return this.dbl();
        }

        const h2 = h.redSqr();
        const h3 = h2.redMul(h);
        const v = u1.redMul(h2);

        const nx = r.redSqr().redIAdd(h3).redISub(v).redISub(v);
        const ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(h3));
        const nz = this.z.redMul(p.z).redMul(h);

        return this.curve.jpoint(nx, ny, nz);
    }
    mixedAdd(p) {
        // O + P = P
        if (this.isInfinity())
            return p.toJ();

        // P + O = P
        if (p.isInfinity())
            return this;

        // 8M + 3S + 7A
        const z2 = this.z.redSqr();
        const u1 = this.x;
        const u2 = p.x.redMul(z2);
        const s1 = this.y;
        const s2 = p.y.redMul(z2).redMul(this.z);

        const h = u1.redSub(u2);
        const r = s1.redSub(s2);
        if (h.cmpn(0) === 0) {
            if (r.cmpn(0) !== 0)
                return this.curve.jpoint(null, null, null);
            else
                return this.dbl();
        }

        const h2 = h.redSqr();
        const h3 = h2.redMul(h);
        const v = u1.redMul(h2);

        const nx = r.redSqr().redIAdd(h3).redISub(v).redISub(v);
        const ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(h3));
        const nz = this.z.redMul(h);

        return this.curve.jpoint(nx, ny, nz);
    }
    dblp(pow) {
        if (pow === 0)
            return this;
        if (this.isInfinity())
            return this;
        if (!pow)
            return this.dbl();

        let i;
        if (this.curve.zeroA || this.curve.threeA) {
            let r = this;
            for (i = 0; i < pow; i++)
                r = r.dbl();
            return r;
        }

        // 1M + 2S + 1A + N * (4S + 5M + 8A)
        // N = 1 => 6M + 6S + 9A
        const a = this.curve.a;
        const tinv = this.curve.tinv;

        let jx = this.x;
        const jy = this.y;
        let jz = this.z;
        let jz4 = jz.redSqr().redSqr();

        // Reuse results
        let jyd = jy.redAdd(jy);
        for (i = 0; i < pow; i++) {
            const jx2 = jx.redSqr();
            const jyd2 = jyd.redSqr();
            const jyd4 = jyd2.redSqr();
            const c = jx2.redAdd(jx2).redIAdd(jx2).redIAdd(a.redMul(jz4));

            const t1 = jx.redMul(jyd2);
            const nx = c.redSqr().redISub(t1.redAdd(t1));
            const t2 = t1.redISub(nx);
            let dny = c.redMul(t2);
            dny = dny.redIAdd(dny).redISub(jyd4);
            const nz = jyd.redMul(jz);
            if (i + 1 < pow)
                jz4 = jz4.redMul(jyd4);

            jx = nx;
            jz = nz;
            jyd = dny;
        }

        return this.curve.jpoint(jx, jyd.redMul(tinv), jz);
    }
    dbl() {
        if (this.isInfinity())
            return this;

        if (this.curve.zeroA)
            return this._zeroDbl();
        else if (this.curve.threeA)
            return this._threeDbl();
        else
            return this._dbl();
    }
    _zeroDbl() {
        let nx;
        let ny;
        let nz;
        // Z = 1
        if (this.zOne) {
            // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
            //     #doubling-mdbl-2007-bl
            // 1M + 5S + 14A

            // XX = X1^2
            const xx = this.x.redSqr();
            // YY = Y1^2
            const yy = this.y.redSqr();
            // YYYY = YY^2
            const yyyy = yy.redSqr();
            // S = 2 * ((X1 + YY)^2 - XX - YYYY)
            let s = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
            s = s.redIAdd(s);
            // M = 3 * XX + a; a = 0
            const m = xx.redAdd(xx).redIAdd(xx);
            // T = M ^ 2 - 2*S
            const t = m.redSqr().redISub(s).redISub(s);

            // 8 * YYYY
            let yyyy8 = yyyy.redIAdd(yyyy);
            yyyy8 = yyyy8.redIAdd(yyyy8);
            yyyy8 = yyyy8.redIAdd(yyyy8);

            // X3 = T
            nx = t;
            // Y3 = M * (S - T) - 8 * YYYY
            ny = m.redMul(s.redISub(t)).redISub(yyyy8);
            // Z3 = 2*Y1
            nz = this.y.redAdd(this.y);
        } else {
            // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
            //     #doubling-dbl-2009-l
            // 2M + 5S + 13A

            // A = X1^2
            const a = this.x.redSqr();
            // B = Y1^2
            const b = this.y.redSqr();
            // C = B^2
            const c = b.redSqr();
            // D = 2 * ((X1 + B)^2 - A - C)
            let d = this.x.redAdd(b).redSqr().redISub(a).redISub(c);
            d = d.redIAdd(d);
            // E = 3 * A
            const e = a.redAdd(a).redIAdd(a);
            // F = E^2
            const f = e.redSqr();

            // 8 * C
            let c8 = c.redIAdd(c);
            c8 = c8.redIAdd(c8);
            c8 = c8.redIAdd(c8);

            // X3 = F - 2 * D
            nx = f.redISub(d).redISub(d);
            // Y3 = E * (D - X3) - 8 * C
            ny = e.redMul(d.redISub(nx)).redISub(c8);
            // Z3 = 2 * Y1 * Z1
            nz = this.y.redMul(this.z);
            nz = nz.redIAdd(nz);
        }

        return this.curve.jpoint(nx, ny, nz);
    }
    _threeDbl() {
        let nx;
        let ny;
        let nz;
        // Z = 1
        if (this.zOne) {
            // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
            //     #doubling-mdbl-2007-bl
            // 1M + 5S + 15A

            // XX = X1^2
            const xx = this.x.redSqr();
            // YY = Y1^2
            const yy = this.y.redSqr();
            // YYYY = YY^2
            const yyyy = yy.redSqr();
            // S = 2 * ((X1 + YY)^2 - XX - YYYY)
            let s = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
            s = s.redIAdd(s);
            // M = 3 * XX + a
            const m = xx.redAdd(xx).redIAdd(xx).redIAdd(this.curve.a);
            // T = M^2 - 2 * S
            const t = m.redSqr().redISub(s).redISub(s);
            // X3 = T
            nx = t;
            // Y3 = M * (S - T) - 8 * YYYY
            let yyyy8 = yyyy.redIAdd(yyyy);
            yyyy8 = yyyy8.redIAdd(yyyy8);
            yyyy8 = yyyy8.redIAdd(yyyy8);
            ny = m.redMul(s.redISub(t)).redISub(yyyy8);
            // Z3 = 2 * Y1
            nz = this.y.redAdd(this.y);
        } else {
            // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
            // 3M + 5S

            // delta = Z1^2
            const delta = this.z.redSqr();
            // gamma = Y1^2
            const gamma = this.y.redSqr();
            // beta = X1 * gamma
            const beta = this.x.redMul(gamma);
            // alpha = 3 * (X1 - delta) * (X1 + delta)
            let alpha = this.x.redSub(delta).redMul(this.x.redAdd(delta));
            alpha = alpha.redAdd(alpha).redIAdd(alpha);
            // X3 = alpha^2 - 8 * beta
            let beta4 = beta.redIAdd(beta);
            beta4 = beta4.redIAdd(beta4);
            const beta8 = beta4.redAdd(beta4);
            nx = alpha.redSqr().redISub(beta8);
            // Z3 = (Y1 + Z1)^2 - gamma - delta
            nz = this.y.redAdd(this.z).redSqr().redISub(gamma).redISub(delta);
            // Y3 = alpha * (4 * beta - X3) - 8 * gamma^2
            let ggamma8 = gamma.redSqr();
            ggamma8 = ggamma8.redIAdd(ggamma8);
            ggamma8 = ggamma8.redIAdd(ggamma8);
            ggamma8 = ggamma8.redIAdd(ggamma8);
            ny = alpha.redMul(beta4.redISub(nx)).redISub(ggamma8);
        }

        return this.curve.jpoint(nx, ny, nz);
    }
    _dbl() {
        const a = this.curve.a;

        // 4M + 6S + 10A
        const jx = this.x;
        const jy = this.y;
        const jz = this.z;
        const jz4 = jz.redSqr().redSqr();

        const jx2 = jx.redSqr();
        const jy2 = jy.redSqr();

        const c = jx2.redAdd(jx2).redIAdd(jx2).redIAdd(a.redMul(jz4));

        let jxd4 = jx.redAdd(jx);
        jxd4 = jxd4.redIAdd(jxd4);
        const t1 = jxd4.redMul(jy2);
        const nx = c.redSqr().redISub(t1.redAdd(t1));
        const t2 = t1.redISub(nx);

        let jyd8 = jy2.redSqr();
        jyd8 = jyd8.redIAdd(jyd8);
        jyd8 = jyd8.redIAdd(jyd8);
        jyd8 = jyd8.redIAdd(jyd8);
        const ny = c.redMul(t2).redISub(jyd8);
        const nz = jy.redAdd(jy).redMul(jz);

        return this.curve.jpoint(nx, ny, nz);
    }
    trpl() {
        if (!this.curve.zeroA)
            return this.dbl().add(this);

        // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#tripling-tpl-2007-bl
        // 5M + 10S + ...

        // XX = X1^2
        const xx = this.x.redSqr();
        // YY = Y1^2
        const yy = this.y.redSqr();
        // ZZ = Z1^2
        const zz = this.z.redSqr();
        // YYYY = YY^2
        const yyyy = yy.redSqr();
        // M = 3 * XX + a * ZZ2; a = 0
        const m = xx.redAdd(xx).redIAdd(xx);
        // MM = M^2
        const mm = m.redSqr();
        // E = 6 * ((X1 + YY)^2 - XX - YYYY) - MM
        let e = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
        e = e.redIAdd(e);
        e = e.redAdd(e).redIAdd(e);
        e = e.redISub(mm);
        // EE = E^2
        const ee = e.redSqr();
        // T = 16*YYYY
        let t = yyyy.redIAdd(yyyy);
        t = t.redIAdd(t);
        t = t.redIAdd(t);
        t = t.redIAdd(t);
        // U = (M + E)^2 - MM - EE - T
        const u = m.redIAdd(e).redSqr().redISub(mm).redISub(ee).redISub(t);
        // X3 = 4 * (X1 * EE - 4 * YY * U)
        let yyu4 = yy.redMul(u);
        yyu4 = yyu4.redIAdd(yyu4);
        yyu4 = yyu4.redIAdd(yyu4);
        let nx = this.x.redMul(ee).redISub(yyu4);
        nx = nx.redIAdd(nx);
        nx = nx.redIAdd(nx);
        // Y3 = 8 * Y1 * (U * (T - U) - E * EE)
        let ny = this.y.redMul(u.redMul(t.redISub(u)).redISub(e.redMul(ee)));
        ny = ny.redIAdd(ny);
        ny = ny.redIAdd(ny);
        ny = ny.redIAdd(ny);
        // Z3 = (Z1 + E)^2 - ZZ - EE
        const nz = this.z.redAdd(e).redSqr().redISub(zz).redISub(ee);

        return this.curve.jpoint(nx, ny, nz);
    }
    mul(k, kbase) {
        k = new BN(k, kbase);

        return this.curve._wnafMul(this, k);
    }
    eq(p) {
        if (p.type === 'affine')
            return this.eq(p.toJ());

        if (this === p)
            return true;

        // x1 * z2^2 == x2 * z1^2
        const z2 = this.z.redSqr();
        const pz2 = p.z.redSqr();
        if (this.x.redMul(pz2).redISub(p.x.redMul(z2)).cmpn(0) !== 0)
            return false;

        // y1 * z2^3 == y2 * z1^3
        const z3 = z2.redMul(this.z);
        const pz3 = pz2.redMul(p.z);
        return this.y.redMul(pz3).redISub(p.y.redMul(z3)).cmpn(0) === 0;
    }
    eqXToP(x) {
        const zs = this.z.redSqr();
        const rx = x.toRed(this.curve.red).redMul(zs);
        if (this.x.cmp(rx) === 0)
            return true;

        const xc = x.clone();
        const t = this.curve.redN.redMul(zs);
        for (; ;) {
            xc.iadd(this.curve.n);
            if (xc.cmp(this.curve.p) >= 0)
                return false;

            rx.redIAdd(t);
            if (this.x.cmp(rx) === 0)
                return true;
        }
    }
    inspect() {
        if (this.isInfinity())
            return '<EC JPoint Infinity>';
        return '<EC JPoint x: ' + this.x.toString(16, 2) +
            ' y: ' + this.y.toString(16, 2) +
            ' z: ' + this.z.toString(16, 2) + '>';
    }
    isInfinity() {
        // XXX This code assumes that zero is always zero in red
        return this.z.cmpn(0) === 0;
    }
}
