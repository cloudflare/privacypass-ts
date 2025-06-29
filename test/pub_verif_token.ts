// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { base64 } from 'rfc4648';

import { util } from '../src/index.js';

import { hexToUint8 } from './util.js';

// https://www.rfc-editor.org/rfc/rfc9578.html#name-issuance-protocol-2-blind-r
import vectorsGo from './test_data/pub_verif_rfc9578.go.json';
// https://raw.githubusercontent.com/raphaelrobert/privacypass/refs/heads/main/tests/kat_vectors/public_rs.json
import vectorsRust from './test_data/pub_verif_rfc9578.rust.json';

export const vectors = [...vectorsGo, ...vectorsRust];

export type Vectors = (typeof vectors)[number];

export async function keysFromVector(
    v: Pick<Vectors, 'pkS' | 'skS'>,
): Promise<[CryptoKeyPair, Uint8Array]> {
    const hexEncoded = hexToUint8(v.skS);
    const pem = new TextDecoder().decode(hexEncoded);
    const pemHeader = '-----BEGIN PRIVATE KEY-----';
    const pemFooter = '-----END PRIVATE KEY-----';
    const pemContents = pem.replace(pemHeader, '').replace(pemFooter, '');
    const trimPemContents = pemContents.replace(/\s+/g, '');
    const payload = base64.parse(trimPemContents);

    const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        payload,
        { name: 'RSA-PSS', hash: 'SHA-384' },
        true,
        ['sign'],
    );

    const spkiEncoded = util.convertRSASSAPSSToEnc(hexToUint8(v.pkS));
    const publicKey = await crypto.subtle.importKey(
        'spki',
        spkiEncoded,
        { name: 'RSA-PSS', hash: 'SHA-384' },
        true,
        ['verify'],
    );
    const publicKeyEnc = hexToUint8(v.pkS);

    return [{ privateKey, publicKey }, publicKeyEnc];
}
