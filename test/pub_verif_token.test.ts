// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { describe, expect, test, vi } from 'vitest';

import {
    TokenChallenge,
    TOKEN_TYPES,
    Token,
    AuthorizationHeader,
    publicVerif,
    tokenRequestToTokenTypeEntry,
} from '../src/index.js';
const { BlindRSAMode, Client, Issuer, Origin, TokenRequest, TokenResponse, getPublicKeyBytes } =
    publicVerif;

import { hexToUint8, testSerialize, testSerializeType, uint8ToHex } from './util.js';

// https://www.rfc-editor.org/rfc/rfc9578.html#name-issuance-protocol-2-blind-r
import vectorsGo from './test_data/pub_verif_rfc9578.go.json';
// https://raw.githubusercontent.com/raphaelrobert/privacypass/refs/heads/main/tests/kat_vectors/public_rs.json
import vectorsRust from './test_data/pub_verif_rfc9578.rust.json';

const vectors = [...vectorsGo, ...vectorsRust];

import { keysFromVector, type Vectors } from './pub_verif_token.js';
import { convertEncToRSASSAPSS } from '../src/util.js';

describe.each(vectors)('PublicVerifiable-Vector-%#', (v: Vectors) => {
    const params = [[], [{ supportsRSARAW: true }]];

    test.each(params)('PublicVerifiable-Vector-%#-Issuer-Params-%#', async (...params) => {
        const [{ privateKey, publicKey }, publicKeyEnc] = await keysFromVector(v);
        expect(privateKey).toBeDefined();
        expect(publicKey).toBeDefined();

        const salt = hexToUint8(v.salt);
        const mode =
            salt.length == (BlindRSAMode.PSS as number) ? BlindRSAMode.PSS : BlindRSAMode.PSSZero;
        const nonce = hexToUint8(v.nonce);
        const blind = hexToUint8(v.blind);
        const challengeSerialized = hexToUint8(v.token_challenge);
        const tokChl = TokenChallenge.deserialize(challengeSerialized);

        // Mock for randomized operations.
        vi.spyOn(crypto, 'getRandomValues')
            .mockReturnValueOnce(nonce)
            .mockReturnValueOnce(salt)
            .mockReturnValueOnce(blind);

        const client = new Client(mode);
        const tokReq = await client.createTokenRequest(tokChl, publicKeyEnc);
        testSerializeType(TOKEN_TYPES.BLIND_RSA, TokenRequest, tokReq);

        const tokReqSer = tokReq.serialize();
        expect(uint8ToHex(tokReqSer)).toBe(v.token_request);
        expect(tokenRequestToTokenTypeEntry(tokReqSer)).toBe(TOKEN_TYPES.BLIND_RSA);

        const issuer = new Issuer(mode, 'issuer.example.com', privateKey, publicKey, ...params);
        const tokRes = await issuer.issue(tokReq);
        testSerialize(TokenResponse, tokRes);

        const tokResSer = tokRes.serialize();
        expect(uint8ToHex(tokResSer)).toBe(v.token_response);

        const token = await client.finalize(tokRes);
        testSerializeType(TOKEN_TYPES.BLIND_RSA, Token, token);

        const tokenSer = token.serialize();
        expect(uint8ToHex(tokenSer)).toBe(v.token);

        expect(await new Origin(mode).verify(token, issuer.publicKey)).toBe(true);

        const header = new AuthorizationHeader(token).toString();
        const parsedTokens = AuthorizationHeader.parse(TOKEN_TYPES.BLIND_RSA, header);
        const parsedToken = parsedTokens[0];
        expect(parsedTokens).toHaveLength(1);
        expect(parsedToken.token.authInput.challengeDigest).toEqual(
            token.authInput.challengeDigest,
        );
        expect(parsedToken.token.authInput.nonce).toEqual(token.authInput.nonce);
        expect(parsedToken.token.authInput.tokenKeyId).toEqual(token.authInput.tokenKeyId);
        expect(parsedToken.token.authInput.tokenType).toBe(token.authInput.tokenType);
        expect(parsedToken.token.authenticator).toEqual(token.authenticator);
    });
});

describe('getPublicKeyBytes', () => {
    const modes = [BlindRSAMode.PSS, BlindRSAMode.PSSZero];

    test.each(modes)('it should use RSAPSS and not enc', async (mode) => {
        const keys = await Issuer.generateKey(mode, {
            modulusLength: 2048,
            publicExponent: Uint8Array.from([1, 0, 1]),
        });
        const issuer = new Issuer(mode, 'issuer.com', keys.privateKey, keys.publicKey);
        const pkIssuer = await getPublicKeyBytes(issuer.publicKey);

        const publicKeyEnc = new Uint8Array(
            await crypto.subtle.exportKey('spki', issuer.publicKey),
        );

        // We don't want the public key to be enc. It should be RSAPSS
        expect(pkIssuer).not.toEqual(publicKeyEnc);

        const publicKeyRSAPSS = convertEncToRSASSAPSS(publicKeyEnc);
        expect(pkIssuer).toEqual(publicKeyRSAPSS);
    });
});
