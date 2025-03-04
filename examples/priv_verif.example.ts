// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { TOKEN_TYPES, privateVerif } from '../src/index.js';
const { Client, Issuer, Origin, keyGen } = privateVerif;

export async function privateVerifiableTokens(): Promise<void> {
    // Protocol Setup

    // [ Issuer ] creates a key pair.
    const keys = await keyGen();
    const issuer = new Issuer('issuer.com', keys.privateKey, keys.publicKey);
    const pkIssuer = issuer.publicKey;

    // [ Client ] creates a state.
    const client = new Client();

    // [ Origin ] creates a state.
    const origin = new Origin(['origin.example.com', 'origin2.example.com']);

    // Online Protocol
    //
    // +--------+            +--------+         +----------+ +--------+
    // | Origin |            | Client |         | Attester | | Issuer |
    // +---+----+            +---+----+         +----+-----+ +---+----+
    //     |                     |                   |           |
    //     |<----- Request ------+                   |           |
    const redemptionContext = crypto.getRandomValues(new Uint8Array(32));
    const tokChl = origin.createTokenChallenge(issuer.name, redemptionContext);
    //     +-- TokenChallenge -->|                   |           |
    //     |                     |<== Attestation ==>|           |
    //     |                     |                   |           |
    const tokReq = await client.createTokenRequest(tokChl, pkIssuer);
    //     |                     +--------- TokenRequest ------->|
    //     |                     |                   |           |
    const tokRes = await issuer.issue(tokReq);
    //     |                     |<-------- TokenResponse -------+
    //     |                     |                   |           |
    const token = await client.finalize(tokRes);
    //     |<-- Request+Token ---+                   |           |
    //     |                     |                   |           |
    const isValid = await origin.verify(token, keys.privateKey);

    console.log('Private-Verifiable tokens');
    console.log(`    Suite: ${TOKEN_TYPES.VOPRF.name}`);
    console.log(`    Valid token: ${isValid}`);
}
