/**
 * Created by pliuzzi on 18/03/24.
 */
import {BN} from './bigNumber';
import {BasePoint} from "./baseCurve";

import {BaseCurve} from "./baseCurve";
import {toArray} from "./utils";

export class MontCurve extends BaseCurve{
    constructor(conf){
        super('mont', conf);
        this.g = conf.g && this.pointFromJSON(conf.g, conf.gRed);
        this.a = new BN(conf.a, 16).toRed(this.red);
        this.b = new BN(conf.b, 16).toRed(this.red);
        this.i4 = new BN(4).toRed(this.red).redInvm();
        this.two = new BN(2).toRed(this.red);
        this.a24 = this.i4.redMul(this.a.redAdd(this.two));
    }
    validate(point) {
        var x = point.normalize().x;
        var x2 = x.redSqr();
        var rhs = x2.redMul(x).redAdd(x2.redMul(this.a)).redAdd(x);
        var y = rhs.redSqrt();

        return y.redSqr().cmp(rhs) === 0;
    }
    decodePoint(bytes, enc) {
        return this.point(toArray(bytes, enc), 1);
    }
    point(x, z) {
        return new MontPoint(this, x, z);
    }
    pointFromJSON(obj) {
        return MontPoint.fromJSON(this, obj);
    }
}

class MontPoint extends BasePoint{
    constructor(curve, x, z) {
        super(curve, 'projective');
        if (x === null && z === null) {
            this.x = this.curve.one;
            this.z = this.curve.zero;
        } else {
            this.x = new BN(x, 16);
            this.z = new BN(z, 16);
            if (!this.x.red)
                this.x = this.x.toRed(this.curve.red);
            if (!this.z.red)
                this.z = this.z.toRed(this.curve.red);
        }
    }
    precompute() {
        // No-op
    }
    _encode() {
        return this.getX().toArray('be', this.curve.p.byteLength());
    }
    static fromJSON(curve, obj) {
        return new MontPoint(curve, obj[0], obj[1] || curve.one);
    }
    inspect() {
        if (this.isInfinity())
            return '<EC Point Infinity>';
        return '<EC Point x: ' + this.x.fromRed().toString(16, 2) +
            ' z: ' + this.z.fromRed().toString(16, 2) + '>';
    }
    isInfinity() {
        // XXX This code assumes that zero is always zero in red
        return this.z.cmpn(0) === 0;
    }
    dbl() {
        // http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#doubling-dbl-1987-m-3
        // 2M + 2S + 4A

        // A = X1 + Z1
        var a = this.x.redAdd(this.z);
        // AA = A^2
        var aa = a.redSqr();
        // B = X1 - Z1
        var b = this.x.redSub(this.z);
        // BB = B^2
        var bb = b.redSqr();
        // C = AA - BB
        var c = aa.redSub(bb);
        // X3 = AA * BB
        var nx = aa.redMul(bb);
        // Z3 = C * (BB + A24 * C)
        var nz = c.redMul(bb.redAdd(this.curve.a24.redMul(c)));
        return this.curve.point(nx, nz);
    }
    add() {
        throw new Error('Not supported on Montgomery curve');
    }
    diffAdd(p, diff) {
        // http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#diffadd-dadd-1987-m-3
        // 4M + 2S + 6A

        // A = X2 + Z2
        var a = this.x.redAdd(this.z);
        // B = X2 - Z2
        var b = this.x.redSub(this.z);
        // C = X3 + Z3
        var c = p.x.redAdd(p.z);
        // D = X3 - Z3
        var d = p.x.redSub(p.z);
        // DA = D * A
        var da = d.redMul(a);
        // CB = C * B
        var cb = c.redMul(b);
        // X5 = Z1 * (DA + CB)^2
        var nx = diff.z.redMul(da.redAdd(cb).redSqr());
        // Z5 = X1 * (DA - CB)^2
        var nz = diff.x.redMul(da.redISub(cb).redSqr());
        return this.curve.point(nx, nz);
    }
    mul(k) {
        var t = k.clone();
        var a = this; // (N / 2) * Q + Q
        var b = this.curve.point(null, null); // (N / 2) * Q
        var c = this; // Q

        for (var bits = []; t.cmpn(0) !== 0; t.iushrn(1))
            bits.push(t.andln(1));

        for (var i = bits.length - 1; i >= 0; i--) {
            if (bits[i] === 0) {
                // N * Q + Q = ((N / 2) * Q + Q)) + (N / 2) * Q
                a = a.diffAdd(b, c);
                // N * Q = 2 * ((N / 2) * Q + Q))
                b = b.dbl();
            } else {
                // N * Q = ((N / 2) * Q + Q) + ((N / 2) * Q)
                b = a.diffAdd(b, c);
                // N * Q + Q = 2 * ((N / 2) * Q + Q)
                a = a.dbl();
            }
        }
        return b;
    }
    mulAdd() {
        throw new Error('Not supported on Montgomery curve');
    }
    jumlAdd() {
        throw new Error('Not supported on Montgomery curve');
    }
    eq(other) {
        return this.getX().cmp(other.getX()) === 0;
    }
    normalize() {
        this.x = this.x.redMul(this.z.redInvm());
        this.z = this.curve.one;
        return this;
    }
    getX() {
        // Normalize coordinates
        this.normalize();

        return this.x.fromRed();
    }
}

