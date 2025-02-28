// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import * as asn1js from 'asn1js';

// Converts a RSA-PSS key into a RSA Encryption key.
// Required because WebCrypto do not support importing keys with `RSASSA-PSS` OID,
//
// Chromium: https://www.chromium.org/blink/webcrypto/#supported-key-formats
// Firefox: https://github.com/mozilla/pkipolicy/blob/master/rootstore/policy.md#511-rsa
// WebCrypto: https://github.com/w3c/webcrypto/pull/325
//
// Documentation: https://www.rfc-editor.org/rfc/rfc4055#section-6
export function convertRSASSAPSSToEnc(keyRSAPSSEncSpki: Uint8Array): Uint8Array {
    const RSAEncryptionAlgID = '1.2.840.113549.1.1.1';
    const schema = new asn1js.Sequence({
        value: [
            new asn1js.Sequence({ name: 'algorithm' }),
            new asn1js.BitString({ name: 'subjectPublicKey' }),
        ],
    });
    const cmp = asn1js.verifySchema(keyRSAPSSEncSpki, schema);
    if (!cmp.verified) {
        throw new Error('bad parsing RSA-PSS key');
    }

    const keyASN = new asn1js.Sequence({
        value: [
            new asn1js.Sequence({
                value: [
                    new asn1js.ObjectIdentifier({ value: RSAEncryptionAlgID }),
                    new asn1js.Null(),
                ],
            }),
            cmp.result.subjectPublicKey,
        ],
    });

    return new Uint8Array(keyASN.toBER());
}

function algorithm_RSASSA_PSS() {
    const RSAPSSAlgID = '1.2.840.113549.1.1.10';
    const publicKeyParams = new asn1js.Sequence({
        value: [
            new asn1js.Constructed({
                idBlock: {
                    tagClass: 3, // CONTEXT-SPECIFIC
                    tagNumber: 0, // [0]
                },
                value: [
                    new asn1js.Sequence({
                        value: [
                            new asn1js.ObjectIdentifier({ value: '2.16.840.1.101.3.4.2.2' }), // sha-384
                        ],
                    }),
                ],
            }),
            new asn1js.Constructed({
                idBlock: {
                    tagClass: 3, // CONTEXT-SPECIFIC
                    tagNumber: 1, // [1]
                },
                value: [
                    new asn1js.Sequence({
                        value: [
                            new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.1.8' }), // pkcs1-MGF
                            new asn1js.Sequence({
                                value: [
                                    new asn1js.ObjectIdentifier({
                                        value: '2.16.840.1.101.3.4.2.2',
                                    }), // sha-384
                                ],
                            }),
                        ],
                    }),
                ],
            }),
            new asn1js.Constructed({
                idBlock: {
                    tagClass: 3, // CONTEXT-SPECIFIC
                    tagNumber: 2, // [2]
                },
                value: [
                    new asn1js.Integer({ value: 48 }), // sLen = 48
                ],
            }),
        ],
    });

    return new asn1js.Sequence({
        value: [new asn1js.ObjectIdentifier({ value: RSAPSSAlgID }), publicKeyParams],
    });
}

// Exports a RSA-PSS key as RSASSA-PSS.
// This is required because browsers do not support exporting RSA-PSS keys.
//
// Chromium: https://www.chromium.org/blink/webcrypto/#supported-key-formats
// Firefox: https://github.com/mozilla/pkipolicy/blob/master/rootstore/policy.md#511-rsa
//
// Documentation: https://www.rfc-editor.org/rfc/rfc4055#section-6
export function convertEncToRSASSAPSS(keyEncRSAPSSSpki: Uint8Array): Uint8Array {
    const schema = new asn1js.Sequence({
        value: [
            new asn1js.Sequence({ name: 'algorithm' }),
            new asn1js.BitString({ name: 'subjectPublicKey' }),
        ],
    });

    const cmp = asn1js.verifySchema(keyEncRSAPSSSpki, schema);
    if (!cmp.verified) {
        throw new Error('bad parsing EncRSA key');
    }

    const algorithmID = algorithm_RSASSA_PSS();
    const asn = new asn1js.Sequence({
        value: [algorithmID, cmp.result.subjectPublicKey],
    });

    return new Uint8Array(asn.toBER());
}

export function joinAll(a: ArrayBuffer[]): ArrayBuffer {
    let size = 0;
    for (const ai of a) {
        size += ai.byteLength;
    }

    const buffer = new ArrayBuffer(size);
    const view = new Uint8Array(buffer);
    let offset = 0;
    for (const ai of a) {
        view.set(new Uint8Array(ai), offset);
        offset += ai.byteLength;
    }

    return buffer;
}

export interface CanSerialize {
    serialize(): Uint8Array;
}

export interface CanDeserialize<T extends CanSerialize> {
    deserialize(_b: Uint8Array): T;
}

// implemented using https://www.rfc-editor.org/rfc/rfc9000.html#name-sample-variable-length-inte
export const readVarint = (
    input: DataView<ArrayBufferLike>,
    offset: number,
): { value: number; usize: number } => {
    let b = input.getUint8(offset);
    offset += 1;

    const prefix = b >> 6;
    if (prefix > 3) {
        // technically, not true. there is space between 2^62 and 2^64-1 which would not require a bigint
        // here, it's to big anyway, we won't reach these values
        throw new Error('unsupported size');
    }

    const length = 1 << prefix;

    let int = b & 0b00111111;

    while (offset < length) {
        b = input.getUint8(offset);
        offset += 1;

        int = int << (8 + b);
    }
    return { value: int, usize: prefix };
};

export const serialiseVarint = (n: number): Uint8Array => {
    if (n < 0) {
        throw new Error('Cannot encode negative numbers');
    }

    let length = 1;
    let prefix = 0b00;
    if (n > 0x3f) {
        length = 2;
        prefix = 0b01;
    }
    if (n > 0x3fff) {
        length = 4;
        prefix = 0b10;
    }
    // technically, not true. there is space between 2^62 and 2^64-1 which would not require a bigint
    // here, it's to big anyway, we won't reach these values
    if (n > 0x3fffff) {
        throw new Error('n too large to encode');
    }

    // First byte contains the prefix in the 2-MSB and part of n
    const bytes = new Uint8Array(length);
    bytes[0] = (prefix << 6) | ((n >> ((length - 1) * 8)) & 0b00111111);

    for (let i = 1; i < length; i++) {
        bytes[i] = (n >> ((length - 1 - i) * 8)) & 0xff;
    }

    return bytes;
};
