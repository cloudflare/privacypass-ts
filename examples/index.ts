// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { webcrypto } from 'node:crypto';

import { publicVerifiableTokens } from './pub_verif.example.js';
import { privateVerifiableTokens } from './priv_verif.example.js';

if (typeof crypto === 'undefined') {
    Object.assign(global, { crypto: webcrypto });
}

async function examples() {
    await privateVerifiableTokens();
    await publicVerifiableTokens();
}

examples().catch((e: Error) => {
    console.log(`Error: ${e.message}`);
    console.log(`Stack: ${e.stack}`);
    process.exit(1);
});
