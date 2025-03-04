// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { webcrypto } from 'node:crypto';

import { arbitraryBatchedTokens } from './arbitrary_batched.example.js';
import { publicVerifiableTokens } from './pub_verif.example.js';
import { publicVerifiableWithMetadataTokens } from './pub_verif_metadata.example.js';
import { privateVerifiableTokens } from './priv_verif.example.js';

if (typeof crypto === 'undefined') {
    Object.assign(global, { crypto: webcrypto });
}

async function examples() {
    await arbitraryBatchedTokens();
    await privateVerifiableTokens();
    await publicVerifiableTokens();
    await publicVerifiableWithMetadataTokens();
}

examples().catch((e: unknown) => {
    console.log(`Error: ${(e as Error).message}`);
    console.log(`Stack: ${(e as Error).stack}`);
    process.exit(1);
});
