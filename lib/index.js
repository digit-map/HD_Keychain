"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var tslib_1 = require("tslib");
var crypto_1 = tslib_1.__importDefault(require("crypto"));
var elliptic_1 = require("elliptic");
var bn_js_1 = tslib_1.__importDefault(require("bn.js"));
var EMPTY_BUFFER = Buffer.from([]);
var HARDENED_INDEX_BASE = 0x80000000;
var ec = new elliptic_1.ec('secp256k1');
var privKeyToPubKey = function (privKey) {
    if (privKey.length !== 32) {
        throw new Error('Invalid private key');
    }
    return Buffer.from(ec.keyFromPrivate(privKey).getPublic('hex'), 'hex');
};
var hash160 = function (data) {
    var sha256 = crypto_1.default
        .createHash('sha256')
        .update(data)
        .digest();
    var res = crypto_1.default
        .createHash('ripemd160')
        .update(sha256)
        .digest();
    return res;
};
var derivePrivKey = function (privKey, il) {
    var result = new bn_js_1.default(il);
    result.iadd(new bn_js_1.default(privKey));
    if (result.cmp(ec.curve.n) > 0) {
        result.isub(ec.curve.n);
    }
    return result.toArrayLike(Buffer, 'be', 32);
};
var derivePubKey = function (pubKey, il) {
    var x = new bn_js_1.default(pubKey.slice(1)).toRed(ec.curve.red);
    var y = x
        .redSqr()
        .redIMul(x)
        .redIAdd(ec.curve.b)
        .redSqrt();
    if ((pubKey[0] === 0x03) !== y.isOdd()) {
        y = y.redNeg();
    }
    var point = ec.curve.g.mul(new bn_js_1.default(il)).add({ x: x, y: y });
    return Buffer.from(point.encode(true, true));
};
var HDKeychain = (function () {
    function HDKeychain(privKey, chainCode) {
        var _this = this;
        this.privKey = EMPTY_BUFFER;
        this.pubKey = EMPTY_BUFFER;
        this.chainCode = EMPTY_BUFFER;
        this.index = 0;
        this.depth = 0;
        this.identifier = EMPTY_BUFFER;
        this.fingerprint = 0;
        this.parentFingerprint = 0;
        this.isNeutered = function () {
            return _this.privKey === EMPTY_BUFFER;
        };
        this.calculateFingerprint = function () {
            _this.fingerprint = hash160(_this.pubKey)
                .slice(4)
                .readUInt32BE(0);
        };
        this.deriveChild = function (index, hardened) {
            if (index === void 0) { index = 0; }
            if (hardened === void 0) { hardened = false; }
            var data = EMPTY_BUFFER;
            var indexBuffer = Buffer.allocUnsafe(4);
            if (hardened) {
                var privKey = Buffer.concat([Buffer.alloc(1, 0), _this.privKey]);
                indexBuffer.writeUInt32BE(index + HARDENED_INDEX_BASE, 0);
                data = Buffer.concat([privKey, indexBuffer]);
            }
            else {
                indexBuffer.writeUInt32BE(index, 0);
                data = Buffer.concat([_this.pubKey, indexBuffer]);
            }
            var i = crypto_1.default
                .createHmac('sha512', _this.chainCode)
                .update(data)
                .digest();
            var il = i.slice(0, 32);
            var ir = i.slice(32);
            var child;
            if (_this.isNeutered()) {
                child = new HDKeychain(EMPTY_BUFFER, ir);
                child.pubKey = derivePubKey(_this.pubKey, il);
                child.calculateFingerprint();
            }
            else {
                var privKey = derivePrivKey(_this.privKey, il);
                child = new HDKeychain(privKey, ir);
                child.calculateFingerprint();
            }
            child.index = index;
            child.depth = _this.depth + 1;
            child.parentFingerprint = _this.fingerprint;
            return child;
        };
        this.deriveFromPath = function (path) {
            var master = ["m", "/", ""];
            if (master.includes(path)) {
                return _this;
            }
            var derived = _this;
            var entries = path.split('/');
            if (entries[0] === "m") {
                entries = entries.slice(1);
            }
            entries.forEach(function (c) {
                var childIndex = parseInt(c, 10);
                var hardened = c.length > 1 && c.endsWith("'");
                derived = derived.deriveChild(childIndex, hardened);
            });
            return derived;
        };
        this.privKey = privKey;
        this.chainCode = chainCode;
        if (!this.isNeutered()) {
            this.pubKey = privKeyToPubKey(this.privKey);
        }
    }
    return HDKeychain;
}());
exports.HDKeychain = HDKeychain;
exports.default = HDKeychain;
//# sourceMappingURL=index.js.map