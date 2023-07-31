import { jest } from '@jest/globals';
import { base64 } from 'rfc4648';

import { Client, Issuer } from '../src/pubVerifToken.js';
import { convertPSSToEnc } from '../src/util.js';
import { TokenChallenge, PrivateToken } from '../src/httpAuthScheme.js';

// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-11#name-test-vectors
import vectors from './testdata/publicverif_v11.json';

function hexToUint8(x: string): Uint8Array {
    return new Uint8Array(Buffer.from(x, 'hex'));
}

function uint8ToHex(x: Uint8Array): string {
    return Buffer.from(x).toString('hex');
}

type Vectors = (typeof vectors)[number];

async function keysFromVector(v: Vectors): Promise<[CryptoKeyPair, Uint8Array]> {
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

    const spkiEncoded = convertPSSToEnc(hexToUint8(v.pkS));
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

test.each(vectors)('PublicVerifiable-Vector-%#', async (v: Vectors) => {
    const [{ privateKey, publicKey }, publicKeyEnc] = await keysFromVector(v);
    expect(privateKey).toBeDefined();
    expect(publicKey).toBeDefined();

    const salt = hexToUint8(v.salt);
    const nonce = hexToUint8(v.nonce);
    const blind = hexToUint8(v.blind);
    const challengeSerialized = hexToUint8(v.token_challenge);
    const challenge = TokenChallenge.parse(challengeSerialized);

    const privToken: PrivateToken = {
        challenge,
        challengeSerialized,
        tokenKey: publicKeyEnc,
        maxAge: undefined,
    };

    // Mock for randomized operations.
    jest.spyOn(crypto, 'getRandomValues')
        .mockReturnValueOnce(nonce)
        .mockReturnValueOnce(salt)
        .mockReturnValueOnce(blind);

    const client = new Client();
    const tokReq = await client.createTokenRequest(privToken);
    const tokReqSer = tokReq.serialize();
    expect(uint8ToHex(tokReqSer)).toStrictEqual(v.token_request);

    const tokRes = await Issuer.issue(privateKey, tokReq);
    const tokResSer = tokRes.serialize();
    expect(tokResSer).toStrictEqual(hexToUint8(v.token_response));

    const token = await client.finalize(tokRes);
    const tokenSer = token.serialize();
    expect(tokenSer).toStrictEqual(hexToUint8(v.token));
});
