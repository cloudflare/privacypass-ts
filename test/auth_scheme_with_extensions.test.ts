// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import {
    AuthenticatorInput,
    Extension,
    Extensions,
    TOKEN_TYPES,
    TokenChallenge,
} from '../src/index.js';
import {
    hexToString,
    hexToUint8,
    testSerialize,
    testSerializeWithOps,
    uint8ToHex,
} from './util.js';

// Test vectors adapted from Privacy Pass Auth Scheme Draft 14
// The draft for extensions only defines Authorization header, not WWW-Authenticate
import tokenVectors from './test_data/auth_scheme_token_with_extensions_v1.json';

type TokenVectors = (typeof tokenVectors)[number];

const MAX_UINT16 = (1 << 16) - 1;

describe('PublicVerifiableMetadata failing edge case', () => {
    test('Invalid extension number', () => {
        function invalidExtensionConstructor() {
            return new Extension(1.1, new Uint8Array(0));
        }
        expect(invalidExtensionConstructor).toThrow();
    });

    test('Invalid extension data size', () => {
        function invalidExtensionConstructor() {
            return new Extension(1, new Uint8Array(MAX_UINT16 + 1));
        }
        expect(invalidExtensionConstructor).toThrow();
    });

    test('Invalid extension type ordering', () => {
        function invalidExtensionsConstructor() {
            return new Extensions([
                new Extension(2, new Uint8Array(0)),
                new Extension(1, new Uint8Array(0)),
            ]);
        }
        expect(invalidExtensionsConstructor).toThrow();
    });

    test('Valid extension type ordering', () => {
        function extensionsConstructor() {
            return new Extensions([
                new Extension(1, new Uint8Array(0)),
                new Extension(2, new Uint8Array(0)),
            ]);
        }
        const extensions = extensionsConstructor();
        const serialized = extensions.serialize();
        expect(serialized).toStrictEqual(new Uint8Array([0, 8, 0, 1, 0, 0, 0, 2, 0, 0]));
    });

    test('Repeated extension type', () => {
        function extensionsConstructor() {
            return new Extensions([
                new Extension(1, new Uint8Array(0)),
                new Extension(1, new Uint8Array(0)),
            ]);
        }
        const extensions = extensionsConstructor();
        const serialized = extensions.serialize();
        expect(serialized).toStrictEqual(new Uint8Array([0, 8, 0, 1, 0, 0, 0, 1, 0, 0]));
    });

    test('Extensions 0 and MAX_UINT type', () => {
        function extensionsConstructor() {
            return new Extensions([
                new Extension(0, new Uint8Array(0)),
                new Extension(MAX_UINT16, new Uint8Array(0)),
            ]);
        }
        const extensions = extensionsConstructor();
        const serialized = extensions.serialize();
        expect(serialized).toStrictEqual(new Uint8Array([0, 8, 0, 0, 0, 0, 255, 255, 0, 0]));
    });
});

test.each(tokenVectors)('AuthScheme-TokenVector-%#', async (v: TokenVectors) => {
    const tokenType = parseInt(v.token_type);
    expect(tokenType).toBe(TOKEN_TYPES.PARTIALLY_BLIND_RSA.value);

    const issuerName = hexToString(v.issuer_name);
    const redemptionContext = hexToUint8(v.redemption_context);
    const originInfo = v.origin_info !== '' ? hexToString(v.origin_info).split(',') : undefined;
    const nonce = hexToUint8(v.nonce);
    const keyId = hexToUint8(v.token_key_id);

    const challenge = new TokenChallenge(tokenType, issuerName, redemptionContext, originInfo);
    const challengeSerialized = challenge.serialize();
    testSerialize(TokenChallenge, challenge);

    const context = new Uint8Array(await crypto.subtle.digest('SHA-256', challengeSerialized));
    // use PARTIALLY_BLIND_RSA because it is a has public extensions
    const authInput = new AuthenticatorInput(
        TOKEN_TYPES.PARTIALLY_BLIND_RSA,
        TOKEN_TYPES.PARTIALLY_BLIND_RSA.value,
        nonce,
        context,
        keyId,
    );
    const authInputEnc = authInput.serialize();

    expect(uint8ToHex(authInputEnc)).toBe(v.token_authenticator_input);
});

describe('extensions', () => {
    test('maxSizeExtension', () => {
        const ext = new Extension(0xaa, new Uint8Array(Extension.MAX_EXTENSION_DATA_LENGTH));
        testSerializeWithOps(Extension, ext);

        const extBytes = ext.serialize();
        expect(extBytes.length).toBe(2 + 2 + Extension.MAX_EXTENSION_DATA_LENGTH);
    });

    test('maxSizeArrayExtension', () => {
        const ext = new Extension(0xaa, new Uint8Array(Extension.MAX_EXTENSION_DATA_LENGTH));
        const arrayExt = new Extensions([ext]);

        testSerialize(Extensions, arrayExt);

        const arrayExtBytes = arrayExt.serialize();
        expect(arrayExtBytes.length).toBe(
            2 /* Length-prefix for array of extensions. */ +
                (2 + 2 + Extension.MAX_EXTENSION_DATA_LENGTH),
        );
    });

    test('serialize', () => {
        const arrayExt = new Extensions([
            new Extension(0xa1, new Uint8Array([0x11, 0x22, 0x33])),
            new Extension(0xa2, new Uint8Array([0x55, 0x66])),
            new Extension(0xa3, new Uint8Array([0x88])),
        ]);

        testSerialize(Extensions, arrayExt);

        const expectedBytes = Uint8Array.from([
            // Total length of the next bytes
            0x00, 0x12,
            // first extension
            0x00, 0xa1, 0x00, 0x03, 0x11, 0x22, 0x33,
            // second extension
            0x00, 0xa2, 0x00, 0x02, 0x55, 0x66,
            // third extension
            0x00, 0xa3, 0x00, 0x01, 0x88,
        ]);

        const bytes = arrayExt.serialize();
        expect(bytes).toStrictEqual(expectedBytes);
    });
});
