/// <reference types="node" />
export declare class HDKeychain {
    privKey: Buffer;
    pubKey: Buffer;
    chainCode: Buffer;
    index: number;
    depth: number;
    identifier: Buffer;
    fingerprint: number;
    parentFingerprint: number;
    constructor(privKey: Buffer, chainCode: Buffer);
    isNeutered: () => boolean;
    calculateFingerprint: () => void;
    deriveChild: (index?: number, hardened?: boolean) => HDKeychain;
    deriveFromPath: (path: string) => HDKeychain;
}
export default HDKeychain;
//# sourceMappingURL=index.d.ts.map