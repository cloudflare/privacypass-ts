// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { webcrypto } from 'node:crypto';
import { publicVerifiableTokens } from './pubVerifiable.example.js';
import { privateVerifiableTokens } from './privVerifiable.example.js';

if (typeof crypto === 'undefined') {
    global.crypto = webcrypto as unknown as Crypto;
}

async function examples() {
    privateVerifiableTokens();
    publicVerifiableTokens();
}

examples().catch((e: Error) => {
    console.log(`Error: ${e.message}`);
    console.log(`Stack: ${e.stack}`);
    process.exit(1);
});
