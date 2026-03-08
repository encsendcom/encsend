import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, test } from 'node:test';

import {
    decryptTextPayload,
    encryptTextPayload,
    packageRequiresPassword,
} from '../src/encsendAesGcm.js';
import {
    installBrowserCryptoTestGlobals,
    resetBrowserCryptoTestGlobals,
    withDeterministicRandom,
} from './support/testEnvironment.js';

const vectors = JSON.parse(
    readFileSync(new URL('../test-vectors/encsendAesGcm.json', import.meta.url), 'utf8')
);

function buildDecryptPayload(output) {
    return {
        encryption_version: output.encryptionVersion,
        encryption_algorithm: output.encryptionAlgorithm,
        encryption_iv: output.encryptionIv,
        encrypted_payload: output.encryptedPayload,
        encrypted_key: output.encryptedKey,
        encryption_meta: output.encryptionMeta,
    };
}

beforeEach(() => {
    installBrowserCryptoTestGlobals();
});

afterEach(() => {
    resetBrowserCryptoTestGlobals();
});

test('encryptTextPayload matches the fixture without password wrapping', async () => {
    const fixture = vectors.without_password;

    const actual = await withDeterministicRandom(fixture.random_bytes, () => encryptTextPayload(
        fixture.input.plaintext,
        fixture.input.key_material,
        fixture.input.password
    ));

    assert.deepEqual(actual, fixture.output);
    assert.equal(packageRequiresPassword(buildDecryptPayload(actual)), false);
});

test('encryptTextPayload matches the fixture with password wrapping', async () => {
    const fixture = vectors.with_password;

    const actual = await withDeterministicRandom(fixture.random_bytes, () => encryptTextPayload(
        fixture.input.plaintext,
        fixture.input.key_material,
        fixture.input.password
    ));

    assert.deepEqual(actual, fixture.output);
    assert.equal(packageRequiresPassword(buildDecryptPayload(actual)), true);
});

test('decryptTextPayload reproduces the fixture plaintext for both AES-GCM payload variants', async () => {
    const plainWithoutPassword = await decryptTextPayload(
        buildDecryptPayload(vectors.without_password.output),
        vectors.without_password.input.key_material
    );
    const plainWithPassword = await decryptTextPayload(
        buildDecryptPayload(vectors.with_password.output),
        vectors.with_password.input.key_material,
        vectors.with_password.input.password
    );

    assert.equal(plainWithoutPassword, vectors.without_password.decrypted);
    assert.equal(plainWithPassword, vectors.with_password.decrypted);
});

test('decryptTextPayload requires the password for password-wrapped payloads', async () => {
    await assert.rejects(
        () => decryptTextPayload(
            buildDecryptPayload(vectors.with_password.output),
            vectors.with_password.input.key_material
        ),
        /Decryption password required\./
    );
});
