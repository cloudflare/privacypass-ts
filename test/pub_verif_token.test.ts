// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { jest } from '@jest/globals';
import { base64 } from 'rfc4648';

import {
    Client,
    Issuer,
    TokenRequest,
    TokenResponse,
    util,
    TokenChallenge,
    TOKEN_TYPES,
    Token,
    verifyToken,
    AuthorizationHeader,
} from '../src/index.js';

import { hexToUint8, testSerialize, testSerializeType, uint8ToHex } from './util.js';

// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-16#name-test-vectors
import vectors from './test_data/pub_verif_v16.json';

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

test.each(vectors)('PublicVerifiable-Vector-%#', async (v: Vectors) => {
    const [{ privateKey, publicKey }, publicKeyEnc] = await keysFromVector(v);
    expect(privateKey).toBeDefined();
    expect(publicKey).toBeDefined();

    const salt = hexToUint8(v.salt);
    const nonce = hexToUint8(v.nonce);
    const blind = hexToUint8(v.blind);
    const challengeSerialized = hexToUint8(v.token_challenge);
    const tokChl = TokenChallenge.deserialize(challengeSerialized);

    // Mock for randomized operations.
    jest.spyOn(crypto, 'getRandomValues')
        .mockReturnValueOnce(nonce)
        .mockReturnValueOnce(salt)
        .mockReturnValueOnce(blind);

    const client = new Client();
    const tokReq = await client.createTokenRequest(tokChl, publicKeyEnc);
    testSerialize(TokenRequest, tokReq);

    const tokReqSer = tokReq.serialize();
    expect(uint8ToHex(tokReqSer)).toBe(v.token_request);

    const issuer = new Issuer('issuer.example.com', privateKey, publicKey);
    const tokRes = await issuer.issue(tokReq);
    testSerialize(TokenResponse, tokRes);

    const tokResSer = tokRes.serialize();
    expect(uint8ToHex(tokResSer)).toBe(v.token_response);

    const token = await client.finalize(tokRes);
    testSerializeType(TOKEN_TYPES.BLIND_RSA, Token, token);

    const tokenSer = token.serialize();
    expect(uint8ToHex(tokenSer)).toBe(v.token);

    expect(await verifyToken(token, issuer.publicKey)).toBe(true);

    const header = new AuthorizationHeader(token).toString();
    const parsedTokens = AuthorizationHeader.parse(TOKEN_TYPES.BLIND_RSA, header);
    const parsedToken = parsedTokens[0];
    expect(parsedTokens).toHaveLength(1);
    expect(parsedToken.token.authInput.challengeDigest).toEqual(token.authInput.challengeDigest);
    expect(parsedToken.token.authInput.nonce).toEqual(token.authInput.nonce);
    expect(parsedToken.token.authInput.tokenKeyId).toEqual(token.authInput.tokenKeyId);
    expect(parsedToken.token.authInput.tokenType).toBe(token.authInput.tokenType);
    expect(parsedToken.token.authenticator).toEqual(token.authenticator);
});
