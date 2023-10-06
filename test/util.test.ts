// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { convertEncToRSASSAPSS, convertRSASSAPSSToEnc } from '../src/util.js';

describe('RSA-PSS', () => {
    it('should export a key', async () => {
        // generates a keyPair
        const keyPair = (await crypto.subtle.generateKey(
            {
                name: 'RSA-PSS',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: { name: 'SHA-384' },
            },
            true,
            ['sign', 'verify'],
        )) as CryptoKeyPair;

        // export the public key as RFC-5756 RSASSA-PSS, and import it again
        const publicKey = new Uint8Array(
            (await crypto.subtle.exportKey('spki', keyPair.publicKey)) as ArrayBuffer,
        );
        const publicKeyEnc = convertEncToRSASSAPSS(publicKey);
        const spkiEncoded = convertRSASSAPSSToEnc(publicKeyEnc);
        const publicKeyIssuerPromise = crypto.subtle.importKey(
            'spki',
            spkiEncoded,
            { name: 'RSA-PSS', hash: 'SHA-384' },
            true,
            ['verify'],
        );

        // export succeeds
        expect(await publicKeyIssuerPromise).toBeTruthy();

        // verify that signature using the private key can be verified by the inferred public key
        const publicKeyIssuer = await publicKeyIssuerPromise;
        const message = 'Hello World!';
        const signature = await crypto.subtle.sign(
            { name: 'RSA-PSS', saltLength: 48 },
            keyPair.privateKey,
            new TextEncoder().encode(message),
        );
        const verified = await crypto.subtle.verify(
            { name: 'RSA-PSS', saltLength: 48 },
            publicKeyIssuer,
            signature,
            new TextEncoder().encode(message),
        );
        expect(verified).toBeTruthy();
    });
});
