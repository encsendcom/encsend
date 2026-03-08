import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, test } from 'node:test';

import {
    createEncryptedOwnerProfile,
    decryptOwnerMasterKey,
    unwrapRequestKeyForOwner,
    unwrapSecretKeyForOwner,
    wrapRequestKeyForOwner,
    wrapSecretKeyForOwner,
} from '../src/encsendOwnerProfile.js';
import {
    installBrowserCryptoTestGlobals,
    resetBrowserCryptoTestGlobals,
    withDeterministicRandom,
    withFrozenDate,
} from './support/testEnvironment.js';

const vectors = JSON.parse(
    readFileSync(new URL('../test-vectors/encsendOwnerProfile.json', import.meta.url), 'utf8')
);

beforeEach(() => {
    installBrowserCryptoTestGlobals();
});

afterEach(() => {
    resetBrowserCryptoTestGlobals();
});

test('createEncryptedOwnerProfile matches the owner profile fixture', async () => {
    const fixture = vectors.owner_profile;

    const actual = await withFrozenDate(fixture.frozen_at, () => withDeterministicRandom(
        fixture.random_bytes,
        () => createEncryptedOwnerProfile(
            fixture.input.passphrase,
            fixture.input.owner_master_key,
            fixture.input.iterations
        )
    ));

    assert.deepEqual(actual, fixture.output);
});

test('decryptOwnerMasterKey reproduces the owner master key from the fixture', async () => {
    const actual = await decryptOwnerMasterKey(
        vectors.owner_profile.output,
        vectors.owner_profile.input.passphrase
    );

    assert.equal(actual, vectors.owner_profile.decrypted);
});

test('wrapRequestKeyForOwner matches the request key fixture and unwraps correctly', async () => {
    const fixture = vectors.wrapped_request_key;

    const actual = await withDeterministicRandom(fixture.random_bytes, () => wrapRequestKeyForOwner(
        fixture.input.owner_master_key,
        fixture.input.request_key
    ));

    assert.deepEqual(actual, fixture.output);

    const unwrapped = await unwrapRequestKeyForOwner(
        fixture.input.owner_master_key,
        actual
    );

    assert.equal(unwrapped, fixture.unwrapped);
});

test('wrapSecretKeyForOwner matches the secret key fixture and unwraps correctly', async () => {
    const fixture = vectors.wrapped_secret_key;

    const actual = await withDeterministicRandom(fixture.random_bytes, () => wrapSecretKeyForOwner(
        fixture.input.owner_master_key,
        fixture.input.secret_key
    ));

    assert.deepEqual(actual, fixture.output);

    const unwrapped = await unwrapSecretKeyForOwner(
        fixture.input.owner_master_key,
        actual
    );

    assert.equal(unwrapped, fixture.unwrapped);
});

test('decryptOwnerMasterKey rejects an invalid recovery passphrase', async () => {
    await assert.rejects(
        () => decryptOwnerMasterKey(vectors.owner_profile.output, 'WrongPassphrase123'),
        /Recovery passphrase is invalid or profile data is corrupted\./
    );
});
