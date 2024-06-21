/**
 * Created by pliuzzi on 18/03/24.
 */

import {assert, encode, toArray} from './utils';
import {Hmac} from "c/hash";



export class HmacDRBG {
    constructor(options) {
        if (!(this instanceof HmacDRBG))
            return new HmacDRBG(options);
        this.hash = options.hash;
        this.predResist = !!options.predResist;

        this.outLen = this.hash.outSize;
        this.minEntropy = options.minEntropy || this.hash.hmacStrength;

        this._reseed = null;
        this.reseedInterval = null;
        this.K = null;
        this.V = null;

        const entropy = toArray(options.entropy, options.entropyEnc || 'hex');
        const nonce = toArray(options.nonce, options.nonceEnc || 'hex');
        const pers = toArray(options.pers, options.persEnc || 'hex');
        assert(entropy.length >= (this.minEntropy / 8),
            'Not enough entropy. Minimum is: ' + this.minEntropy + ' bits');
        this.init(entropy, nonce, pers);
    }
    init(entropy, nonce, pers) {
        const seed = entropy.concat(nonce).concat(pers);

        this.K = new Array(this.outLen / 8);
        this.V = new Array(this.outLen / 8);
        for (let i = 0; i < this.V.length; i++) {
            this.K[i] = 0x00;
            this.V[i] = 0x01;
        }

        this.update(seed);
        this._reseed = 1;
        this.reseedInterval = 0x1000000000000;  // 2^48
    }
    hmac() {
        return new Hmac(this.hash, this.K);
    }
    update(seed) {
        let kmac = this.hmac()
            .update(this.V)
            .update([0x00]);
        if (seed)
            kmac = kmac.update(seed);
        this.K = kmac.digest();
        this.V = this.hmac().update(this.V).digest();
        if (!seed)
            return;

        this.K = this.hmac()
            .update(this.V)
            .update([ 0x01 ])
            .update(seed)
            .digest();
        this.V = this.hmac().update(this.V).digest();
    }
    reseed(entropy, entropyEnc, add, addEnc) {
        // Optional entropy enc
        if (typeof entropyEnc !== 'string') {
            addEnc = add;
            add = entropyEnc;
            entropyEnc = null;
        }

        entropy = toArray(entropy, entropyEnc);
        add = toArray(add, addEnc);

        assert(entropy.length >= (this.minEntropy / 8),
            'Not enough entropy. Minimum is: ' + this.minEntropy + ' bits');

        this.update(entropy.concat(add || []));
        this._reseed = 1;
    }
    generate(len, enc, add, addEnc) {
        if (this._reseed > this.reseedInterval)
            throw new Error('Reseed is required');

        // Optional encoding
        if (typeof enc !== 'string') {
            addEnc = add;
            add = enc;
            enc = null;
        }

        // Optional additional data
        if (add) {
            add = toArray(add, addEnc || 'hex');
            this.update(add);
        }

        let temp = [];
        while (temp.length < len) {
            this.V = this.hmac().update(this.V).digest();
            temp = temp.concat(this.V);
        }

        const res = temp.slice(0, len);
        this.update(add);
        this._reseed++;
        return encode(res, enc);
    }
}



