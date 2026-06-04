// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

export function joinAll(a: ArrayBuffer[]): ArrayBuffer {
    let size = 0;
    for (const ai of a) {
        size += ai.byteLength;
    }

    const buffer = new ArrayBuffer(size);
    const view = new Uint8Array(buffer);
    let offset = 0;
    for (const ai of a) {
        view.set(new Uint8Array(ai), offset);
        offset += ai.byteLength;
    }

    return buffer;
}

export interface CanSerialize {
    serialize(): Uint8Array;
}

export interface CanDeserialize<T extends CanSerialize> {
    deserialize(_b: Uint8Array): T;
}
