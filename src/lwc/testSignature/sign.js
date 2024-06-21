/**
 * Created by pliuzzi on 16/03/24.
 */

import {Signature} from "./signature";
import {ECDSA} from "c/elliptic";
import {SHA256} from "c/hash";

const privateKeyPEM = 'MHcCAQEEILjW6aWeUyhQiKmnUeRaO7DealAHLnBy6m2KYqne2aVXoAoGCCqGSM49AwEHoUQDQgAE2PzYUjHNnkhuSWvpbHl8lYx+qtMZV7K/UnnbiOyin/yuQ096FK9j/eq10+iAXrGH/F9vclg1DffKGQh0yNO+Ug==';
const privateKeyPKCS8 = 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguNbppZ5TKFCIqadR5Fo7sN5qUAcucHLqbYpiqd7ZpVehRANCAATY/NhSMc2eSG5Ja+lseXyVjH6q0xlXsr9SeduI7KKf/K5DT3oUr2P96rXT6IBesYf8X29yWDUN98oZCHTI075S';
const publicKeyPEM = 'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEZvxpKtXmeLry0eggYxfMUP6f0YzKTvTcUnB213Sj/GOBfhgrk4Z+dFW64g2mrlLkWhyHQvItU/OwkQHkuW0h0g==';
const publicKeyXY = {
    x: 'd8fcd85231cd9e486e496be96c797c958c7eaad31957b2bf5279db88eca29ffc',
    y: 'ae434f7a14af63fdeab5d3e8805eb187fc5f6f7258350df7ca190874c8d3be52'
};
const privateKeyFormat = 'pkcs8';
const privateKeyAlgorithm = {
    name: 'ECDSA',
    namedCurve: 'P-256',
    hash: {name: 'SHA-256'}
};
const privateKeyExtractable = true;
const privateKeyUsages = ['sign'];

const algo = {
    name: "ECDSA",
    namedCurve: "P-256", // secp256r1
};
const hash = {name: "SHA-256"};
const signAlgo = {...algo, hash};

function base64ToArrayBuffer(b64) {
    const byteString = window.atob(b64);
    const byteArray = new Uint8Array(byteString.length);
    for (let i = 0; i < byteString.length; i++) {
        byteArray[i] = byteString.charCodeAt(i);
    }
    return byteArray.buffer;
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return binary;
}

function base64urlencode(str) {
    return window.btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}
function buf2hex(buffer) { // buffer is an ArrayBuffer
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}
function u8(a) { return new Uint8Array(a); }
function bin2int(bin) {
    var i = 0;
    var len = bin.length;
    var num = 0;
    while (i < len) {
        num <<= 8;
        num += bin.charCodeAt(i);
        i++;
    }
    return num;
}
function toBytes(number) {
    if (!Number.isSafeInteger(number)) {
        throw new Error("Number is out of range");
    }

    const size = number === 0 ? 0 : byteLength(number);
    const bytes = new Uint8ClampedArray(size);
    let x = number;
    for (let i = (size - 1); i >= 0; i--) {
        const rightByte = x & 0xff;
        bytes[i] = rightByte;
        x = Math.floor(x / 0x100);
    }

    return bytes.buffer;
}
function toDER(r,s){
    let b0 = [0x30];
    let b1 = 0;
    let b2 = 0x02;


}
// Hex to Base64
/*function hexToBase64(str) {
    return btoa(String.fromCharCode.apply(null,
        str.replace(/\r|\n/g, "").replace(/([\da-fA-F]{2}) ?/g, "0x$1 ").replace(/ +$/, "").split(" "))
    );
}*/
function hexToBase64(hexstring) {
    return btoa(hexstring.match(/\w{2}/g).map(function(a) {
        return String.fromCharCode(parseInt(a, 16));
    }).join(""));
}

// Base64 to Hex
function base64ToHex(str) {
    for (var i = 0, bin = atob(str.replace(/[ \r\n]+$/, "")), hex = []; i < bin.length; ++i) {
        let tmp = bin.charCodeAt(i).toString(16);
        if (tmp.length === 1) tmp = "0" + tmp;
        hex[hex.length] = tmp;
    }
    return hex.join(" ");
}
function strToHex(str) {
    try {
        const raw = str;
        let hex = '';

        for (let i = 0; i < raw.length; i++) {
            const hexChar = raw.charCodeAt(i).toString(16);
            hex += (hexChar.length === 2 ? hexChar : '0' + hexChar);
        }

        return hex;
    } catch (err) {
        return '';
    }
}

export async function sign2(text) {

    try {
        console.log('sign()', text)
        const privateKey = await window.crypto.subtle.importKey(privateKeyFormat, base64ToArrayBuffer(privateKeyPKCS8), privateKeyAlgorithm, privateKeyExtractable, privateKeyUsages);
        const encoded = new TextEncoder().encode(text);
        const result = await window.crypto.subtle.sign(privateKeyAlgorithm, privateKey, encoded);
        const r = buf2hex(result.slice(0, 32));
        const s = buf2hex(result.slice(32));
        const signature = new Signature({r, s}, 'hex');
        console.log('sign() asn1Signature', signature);
        const derSignature = signature.toDER('hex');
        console.log('sign() derSignature', hexToBase64(signature));

        return derSignature;


    } catch (e) {
        console.error('sign()', e.toString());
    }
}
export function zero2(word) {
    if (word.length === 1)
        return '0' + word;
    else
        return word;
}


export function toHex(msg) {
    let res = '';
    for (let i = 0; i < msg.length; i++)
        res += zero2(msg.charCodeAt(i).toString(16));
    return res;
}
async function hashSHA256(string) {
    const utf8 = new TextEncoder().encode(string);
    const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray
        .map((bytes) => bytes.toString(16).padStart(2, '0'))
        .join('');
    return hashHex;
}
export async function sign(text) {

    try {
        const sha256 = new SHA256();
        console.log('sign()', text)
        const privateKey = privateKeyPKCS8;
        const ecdsa = new ECDSA('p256');
        const textEncoded = await hashSHA256(text);
        console.log('sign() textTo16', textEncoded);
        const signature = ecdsa.sign(textEncoded, '00B8D6E9A59E53285088A9A751E45A3BB0DE6A50072E7072EA6D8A62A9DED9A557');
        console.log('sign() signature', signature);
        const derSignature = signature.toDER('hex');
        console.log('sign() hexSignature', derSignature);
        console.log('sign() derSignature', hexToBase64(derSignature));

        const verification = ecdsa.verify(textEncoded,derSignature,publicKeyXY);
        console.log('sign() verification', verification);


        return hexToBase64(derSignature);


    } catch (e) {
        console.error('sign()', e.toString());
    }
}

export default {sign};