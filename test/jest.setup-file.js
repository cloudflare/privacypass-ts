// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0


// Mocking crypto with NodeJS WebCrypto module only for tests.
import { webcrypto } from 'node:crypto'

if (typeof crypto === 'undefined') {
    global.crypto = webcrypto
}
