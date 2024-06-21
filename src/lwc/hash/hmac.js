/**
 * Created by pliuzzi on 19/03/24.
 */
import {assert, toArray} from "./utils";

export class Hmac {
    constructor(hash, key, enc){
        if (!(this instanceof Hmac))
            return new Hmac(hash, key, enc);
        this.Hash = hash;
        this.blockSize = hash.blockSize / 8;
        this.outSize = hash.outSize / 8;
        this.inner = null;
        this.outer = null;

        this._init(toArray(key, enc));
    }
    _init(key) {
        // Shorten key, if needed
        if (key.length > this.blockSize)
            key = this.Hash.update(key).digest();
        assert(key.length <= this.blockSize);

        // Add padding to key
        for (let i = key.length; i < this.blockSize; i++)
            key.push(0);

        for (let i = 0; i < key.length; i++)
            key[i] ^= 0x36;
        this.inner = this.Hash.update(key);

        // 0x36 ^ 0x5c = 0x6a
        for (let i = 0; i < key.length; i++)
            key[i] ^= 0x6a;
        this.outer = this.Hash.update(key);
    }
    update(msg, enc) {
        this.inner.update(msg, enc);
        return this;
    }
    digest(enc) {
        this.outer.update(this.inner.digest());
        return this.outer.digest(enc);
    }
}
