// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

/* eslint-disable security/detect-object-injection */

import { TokenRequest } from '../src/arbitrary_batched_token.js';
import { type Token, type TokenChallenge, arbitraryBatched, publicVerif } from '../src/index.js';
type BlindRSAMode = publicVerif.BlindRSAMode;
const { Client, Issuer } = arbitraryBatched;

async function setupPublicVerif(mode: BlindRSAMode) {
    // [ Issuer ] creates a key pair.
    const keys = await publicVerif.Issuer.generateKey(mode, {
        modulusLength: 2048,
        publicExponent: Uint8Array.from([1, 0, 1]),
    });
    const issuer = new publicVerif.Issuer(mode, 'issuer.com', keys.privateKey, keys.publicKey);
    const pkIssuer = await publicVerif.getPublicKeyBytes(issuer.publicKey);

    // [ Client ] creates a state.
    const client = new publicVerif.Client(mode);

    // [ Origin ] creates a state.
    const origin = new publicVerif.Origin(mode, ['origin.example.com', 'origin2.example.com']);

    return { issuer, client, origin, pkIssuer };
}
async function setup() {
    const s1 = await setupPublicVerif(publicVerif.BlindRSAMode.PSS);
    const s2 = await setupPublicVerif(publicVerif.BlindRSAMode.PSSZero);

    return {
        issuers: [s1.issuer, s2.issuer],
        clients: [s1.client, s2.client],
        origins: [s1.origin, s2.origin],
        pkIssuers: [s1.pkIssuer, s2.pkIssuer],
    };
}

async function rsaVariant(): Promise<void> {
    // Protocol Setup
    //
    // [ Everybody ] agree to use Public Verifiable Tokens.
    const { issuers, clients, origins, pkIssuers } = await setup();
    const issuer = new Issuer(issuers[0], issuers[1]);

    // [ Client ] creates a state.
    const client = new Client();

    // Online Protocol
    //
    // +--------+            +--------+         +----------+ +--------+
    // | Origin |            | Client |         | Attester | | Issuer |
    // +---+----+            +---+----+         +----+-----+ +---+----+
    //     |                     |                   |           |
    //     |<----- Request ------+                   |           |
    const tokChls = new Array<TokenChallenge>(origins.length);
    let i = 0;
    for (const currentIssuer of issuer) {
        const redemptionContext = crypto.getRandomValues(new Uint8Array(32));
        tokChls[i] = origins[i].createTokenChallenge(currentIssuer.name, redemptionContext);
        i += 1;
    }
    //     +-- TokenChallenge -->|                   |           |
    //     |                     |<== Attestation ==>|           |
    //     |                     |                   |           |
    const tokReqs = new Array<TokenRequest>(tokChls.length);
    for (let i = 0; i < tokChls.length; i += 1) {
        const tokReq = await clients[i].createTokenRequest(tokChls[i], pkIssuers[i]);
        tokReqs[i] = new TokenRequest(tokReq);
    }
    const tokReq = client.createTokenRequest(tokReqs);
    //     |                     +--------- TokenRequest ------->|
    //     |                     |                   |           |
    const tokRes = await issuer.issue(tokReq);
    //     |                     |<-------- TokenResponse -------+
    //     |                     |                   |           |
    i = 0;
    const tokens = new Array<Token | undefined>(tokChls.length);
    for (const res of tokRes) {
        if (res.tokenResponse === null) {
            continue;
        }
        const r = publicVerif.TokenResponse.deserialize(res.tokenResponse);
        tokens[i] = await clients[i].finalize(r);

        i += 1;
    }
    //     |<-- Request+Token ---+                   |           |
    //     |                     |                   |           |
    let isValid = true;
    for (let i = 0; i < tokens.length; i += 1) {
        const token = tokens[i];
        isValid &&= token !== undefined && (await origins[i].verify(token, issuers[i].publicKey));
    }

    console.log('Arbitrary batched tokens');
    console.log(`    Valid token: ${isValid}`);
}

export async function arbitraryBatchedTokens() {
    await rsaVariant();
}
