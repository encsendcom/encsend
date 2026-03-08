import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, test } from 'node:test';

import {
    decryptOwnerKeyVault,
    encryptOwnerKeyVault,
} from '../src/encsendKeyVault.js';
import {
    installBrowserCryptoTestGlobals,
    resetBrowserCryptoTestGlobals,
    withDeterministicRandom,
    withFrozenDate,
} from './support/testEnvironment.js';

const vectors = JSON.parse(
    readFileSync(new URL('../test-vectors/encsendKeyVault.json', import.meta.url), 'utf8')
);

beforeEach(() => {
    installBrowserCryptoTestGlobals();
});

afterEach(() => {
    resetBrowserCryptoTestGlobals();
});

test('encryptOwnerKeyVault matches the encrypted vault fixture', async () => {
    const fixture = vectors.key_vault;

    const actual = await withFrozenDate(fixture.frozen_at, () => withDeterministicRandom(
        fixture.random_bytes,
        () => encryptOwnerKeyVault(
            fixture.input.payload,
            fixture.input.passphrase,
            fixture.input.iterations
        )
    ));

    assert.deepEqual(actual, fixture.output);
});

test('decryptOwnerKeyVault reproduces the normalized vault payload from the fixture', async () => {
    const actual = await decryptOwnerKeyVault(
        vectors.key_vault.output,
        vectors.key_vault.input.passphrase
    );

    assert.deepEqual(actual, vectors.key_vault.decrypted);
});

test('decryptOwnerKeyVault rejects an invalid passphrase', async () => {
    await assert.rejects(
        () => decryptOwnerKeyVault(vectors.key_vault.output, 'WrongPassphrase123'),
        /Unable to decrypt key vault\. Passphrase or vault data is invalid\./
    );
});
