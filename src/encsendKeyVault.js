import { base64UrlToBytes, bytesToBase64Url } from './base64url.js';

export const ENCSEND_KEY_VAULT_VERSION = 'encsend-owner-key-vault-v1';
export const ENCSEND_KEY_VAULT_ALGORITHM = 'AES-GCM';
export const ENCSEND_KEY_VAULT_KDF = 'PBKDF2-SHA-256';

const DEFAULT_KDF_ITERATIONS = 240000;
const KEY_BYTE_LENGTH = 32;
const IV_BYTE_LENGTH = 12;
const SALT_BYTE_LENGTH = 16;
const AUTH_TAG_LENGTH = 128;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function randomBytes(length) {
    const bytes = new Uint8Array(length);
    window.crypto.getRandomValues(bytes);

    return bytes;
}

function normalizePassphrase(passphrase) {
    if (typeof passphrase !== 'string') {
        throw new Error('Recovery passphrase is required.');
    }

    const normalized = passphrase.trim();

    if (normalized.length < 8) {
        throw new Error('Use at least 8 characters for the recovery passphrase.');
    }

    return normalized;
}

function sanitizeKeyMap(source) {
    if (!source || typeof source !== 'object') {
        return {};
    }

    return Object.entries(source).reduce((carry, [publicId, keyMaterial]) => {
        if (typeof publicId !== 'string' || publicId.trim() === '') {
            return carry;
        }

        if (typeof keyMaterial !== 'string' || keyMaterial.trim() === '') {
            return carry;
        }

        carry[publicId] = keyMaterial.trim();
        return carry;
    }, {});
}

function normalizeVaultPayload(payload) {
    return {
        secret_keys: sanitizeKeyMap(payload?.secret_keys),
        request_keys: sanitizeKeyMap(payload?.request_keys),
    };
}

async function deriveKey(passphrase, saltBytes, iterations) {
    const baseKey = await window.crypto.subtle.importKey(
        'raw',
        textEncoder.encode(passphrase),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    return window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            hash: 'SHA-256',
            salt: saltBytes,
            iterations,
        },
        baseKey,
        {
            name: ENCSEND_KEY_VAULT_ALGORITHM,
            length: KEY_BYTE_LENGTH * 8,
        },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptAesGcm(bytes, key, ivBytes, aadText) {
    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: ENCSEND_KEY_VAULT_ALGORITHM,
            iv: ivBytes,
            tagLength: AUTH_TAG_LENGTH,
            additionalData: textEncoder.encode(aadText),
        },
        key,
        bytes
    );

    return new Uint8Array(ciphertext);
}

async function decryptAesGcm(ciphertextBytes, key, ivBytes, aadText) {
    const plaintext = await window.crypto.subtle.decrypt(
        {
            name: ENCSEND_KEY_VAULT_ALGORITHM,
            iv: ivBytes,
            tagLength: AUTH_TAG_LENGTH,
            additionalData: textEncoder.encode(aadText),
        },
        key,
        ciphertextBytes
    );

    return new Uint8Array(plaintext);
}

export async function encryptOwnerKeyVault(payload, passphrase, iterations = DEFAULT_KDF_ITERATIONS) {
    const normalizedPassphrase = normalizePassphrase(passphrase);
    const normalizedPayload = normalizeVaultPayload(payload);

    const secretKeyCount = Object.keys(normalizedPayload.secret_keys).length;
    const requestKeyCount = Object.keys(normalizedPayload.request_keys).length;

    const saltBytes = randomBytes(SALT_BYTE_LENGTH);
    const ivBytes = randomBytes(IV_BYTE_LENGTH);
    const derivedKey = await deriveKey(normalizedPassphrase, saltBytes, Number(iterations));

    const payloadBytes = textEncoder.encode(JSON.stringify({
        ...normalizedPayload,
        exported_at: new Date().toISOString(),
        format: 'encsend-key-bundle-v1',
    }));
    const encryptedBytes = await encryptAesGcm(
        payloadBytes,
        derivedKey,
        ivBytes,
        ENCSEND_KEY_VAULT_VERSION
    );

    return {
        vault_version: ENCSEND_KEY_VAULT_VERSION,
        encryption_algorithm: ENCSEND_KEY_VAULT_ALGORITHM,
        encrypted_blob: bytesToBase64Url(encryptedBytes),
        encryption_iv: bytesToBase64Url(ivBytes),
        kdf: {
            name: ENCSEND_KEY_VAULT_KDF,
            iterations: Number(iterations),
            salt: bytesToBase64Url(saltBytes),
        },
        metadata: {
            format: 'encsend-key-bundle-v1',
            secret_key_count: secretKeyCount,
            request_key_count: requestKeyCount,
            exported_at: new Date().toISOString(),
        },
    };
}

export async function decryptOwnerKeyVault(vaultPackage, passphrase) {
    if (!vaultPackage || typeof vaultPackage !== 'object') {
        throw new Error('Encrypted key vault is missing.');
    }

    if (vaultPackage.vault_version !== ENCSEND_KEY_VAULT_VERSION) {
        throw new Error('Unsupported key vault version.');
    }

    if (vaultPackage.encryption_algorithm !== ENCSEND_KEY_VAULT_ALGORITHM) {
        throw new Error('Unsupported key vault encryption algorithm.');
    }

    if (vaultPackage?.kdf?.name !== ENCSEND_KEY_VAULT_KDF) {
        throw new Error('Unsupported key vault KDF.');
    }

    const normalizedPassphrase = normalizePassphrase(passphrase);
    const iterations = Number(vaultPackage?.kdf?.iterations ?? 0);
    const saltBytes = base64UrlToBytes(vaultPackage?.kdf?.salt ?? '');
    const ivBytes = base64UrlToBytes(vaultPackage?.encryption_iv ?? '');
    const encryptedBytes = base64UrlToBytes(vaultPackage?.encrypted_blob ?? '');

    if (!Number.isFinite(iterations) || iterations < 120000 || iterations > 1000000) {
        throw new Error('Invalid key vault KDF parameters.');
    }

    try {
        const derivedKey = await deriveKey(normalizedPassphrase, saltBytes, iterations);
        const decryptedBytes = await decryptAesGcm(
            encryptedBytes,
            derivedKey,
            ivBytes,
            ENCSEND_KEY_VAULT_VERSION
        );
        const parsedPayload = JSON.parse(textDecoder.decode(decryptedBytes));

        return normalizeVaultPayload(parsedPayload);
    } catch (error) {
        throw new Error('Unable to decrypt key vault. Passphrase or vault data is invalid.');
    }
}
