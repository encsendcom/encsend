import { base64UrlToBytes, bytesToBase64Url } from './base64url.js';

export const ENCSEND_OWNER_PROFILE_VERSION = 'encsend-owner-profile-v1';
export const ENCSEND_OWNER_WRAP_KEY_VERSION = 'encsend-owner-rk-wrap-v1';
export const ENCSEND_OWNER_SECRET_WRAP_KEY_VERSION = 'encsend-owner-sk-wrap-v1';
export const ENCSEND_OWNER_CRYPTO_ALGORITHM = 'AES-GCM';
export const ENCSEND_OWNER_PROFILE_KDF = 'PBKDF2-SHA-256';

const KEY_BYTE_LENGTH = 32;
const IV_BYTE_LENGTH = 12;
const SALT_BYTE_LENGTH = 16;
const AUTH_TAG_LENGTH = 128;

const textEncoder = new TextEncoder();

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
        throw new Error('Recovery passphrase must be at least 8 characters.');
    }

    return normalized;
}

async function importAesKey(rawBytes, usages) {
    return window.crypto.subtle.importKey(
        'raw',
        rawBytes,
        { name: ENCSEND_OWNER_CRYPTO_ALGORITHM },
        false,
        usages
    );
}

async function encryptAesGcm(rawBytes, cryptoKey, ivBytes, aadText) {
    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: ENCSEND_OWNER_CRYPTO_ALGORITHM,
            iv: ivBytes,
            tagLength: AUTH_TAG_LENGTH,
            additionalData: textEncoder.encode(aadText),
        },
        cryptoKey,
        rawBytes
    );

    return new Uint8Array(encrypted);
}

async function decryptAesGcm(ciphertextBytes, cryptoKey, ivBytes, aadText) {
    const decrypted = await window.crypto.subtle.decrypt(
        {
            name: ENCSEND_OWNER_CRYPTO_ALGORITHM,
            iv: ivBytes,
            tagLength: AUTH_TAG_LENGTH,
            additionalData: textEncoder.encode(aadText),
        },
        cryptoKey,
        ciphertextBytes
    );

    return new Uint8Array(decrypted);
}

async function derivePassphraseKey(passphrase, saltBytes, iterations) {
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
            name: ENCSEND_OWNER_CRYPTO_ALGORITHM,
            length: KEY_BYTE_LENGTH * 8,
        },
        false,
        ['encrypt', 'decrypt']
    );
}

export function generateOwnerMasterKeyMaterial() {
    return bytesToBase64Url(randomBytes(KEY_BYTE_LENGTH));
}

export async function createEncryptedOwnerProfile(passphrase, ownerMasterKeyMaterial, kdfIterations = 260000) {
    const normalizedPassphrase = normalizePassphrase(passphrase);
    const masterKeyBytes = base64UrlToBytes(ownerMasterKeyMaterial);

    if (masterKeyBytes.length !== KEY_BYTE_LENGTH) {
        throw new Error('Invalid owner master key material.');
    }

    const saltBytes = randomBytes(SALT_BYTE_LENGTH);
    const ivBytes = randomBytes(IV_BYTE_LENGTH);
    const passphraseKey = await derivePassphraseKey(normalizedPassphrase, saltBytes, Number(kdfIterations));
    const encryptedMasterKeyBytes = await encryptAesGcm(
        masterKeyBytes,
        passphraseKey,
        ivBytes,
        ENCSEND_OWNER_PROFILE_VERSION
    );

    return {
        profile_version: ENCSEND_OWNER_PROFILE_VERSION,
        encryption_algorithm: ENCSEND_OWNER_CRYPTO_ALGORITHM,
        encrypted_master_key: bytesToBase64Url(encryptedMasterKeyBytes),
        encryption_iv: bytesToBase64Url(ivBytes),
        kdf: {
            name: ENCSEND_OWNER_PROFILE_KDF,
            iterations: Number(kdfIterations),
            salt: bytesToBase64Url(saltBytes),
        },
        metadata: {
            created_at: new Date().toISOString(),
            format: 'encsend-owner-master-key',
        },
    };
}

export async function decryptOwnerMasterKey(profilePackage, passphrase) {
    if (!profilePackage || typeof profilePackage !== 'object') {
        throw new Error('Recovery profile is missing.');
    }

    if (profilePackage.profile_version !== ENCSEND_OWNER_PROFILE_VERSION) {
        throw new Error('Unsupported recovery profile version.');
    }

    if (profilePackage.encryption_algorithm !== ENCSEND_OWNER_CRYPTO_ALGORITHM) {
        throw new Error('Unsupported recovery profile encryption algorithm.');
    }

    if (profilePackage?.kdf?.name !== ENCSEND_OWNER_PROFILE_KDF) {
        throw new Error('Unsupported recovery profile KDF.');
    }

    const normalizedPassphrase = normalizePassphrase(passphrase);
    const iterations = Number(profilePackage?.kdf?.iterations ?? 0);
    const saltBytes = base64UrlToBytes(profilePackage?.kdf?.salt ?? '');
    const ivBytes = base64UrlToBytes(profilePackage?.encryption_iv ?? '');
    const encryptedMasterKeyBytes = base64UrlToBytes(profilePackage?.encrypted_master_key ?? '');

    if (!Number.isFinite(iterations) || iterations < 120000 || iterations > 1000000) {
        throw new Error('Invalid recovery profile KDF parameters.');
    }

    try {
        const passphraseKey = await derivePassphraseKey(normalizedPassphrase, saltBytes, iterations);
        const masterKeyBytes = await decryptAesGcm(
            encryptedMasterKeyBytes,
            passphraseKey,
            ivBytes,
            ENCSEND_OWNER_PROFILE_VERSION
        );

        if (masterKeyBytes.length !== KEY_BYTE_LENGTH) {
            throw new Error('Invalid recovered master key length.');
        }

        return bytesToBase64Url(masterKeyBytes);
    } catch (error) {
        throw new Error('Recovery passphrase is invalid or profile data is corrupted.');
    }
}

export async function wrapRequestKeyForOwner(ownerMasterKeyMaterial, requestKeyMaterial) {
    const ownerMasterKeyBytes = base64UrlToBytes(ownerMasterKeyMaterial);
    const requestKeyBytes = base64UrlToBytes(requestKeyMaterial);

    if (ownerMasterKeyBytes.length !== KEY_BYTE_LENGTH || requestKeyBytes.length !== KEY_BYTE_LENGTH) {
        throw new Error('Invalid key material for request key wrapping.');
    }

    const wrappingIvBytes = randomBytes(IV_BYTE_LENGTH);
    const ownerMasterKey = await importAesKey(ownerMasterKeyBytes, ['encrypt', 'decrypt']);
    const wrappedRequestKeyBytes = await encryptAesGcm(
        requestKeyBytes,
        ownerMasterKey,
        wrappingIvBytes,
        ENCSEND_OWNER_WRAP_KEY_VERSION
    );

    return {
        key_version: ENCSEND_OWNER_WRAP_KEY_VERSION,
        wrapping_algorithm: ENCSEND_OWNER_CRYPTO_ALGORITHM,
        wrapped_request_key: bytesToBase64Url(wrappedRequestKeyBytes),
        wrapping_iv: bytesToBase64Url(wrappingIvBytes),
        wrapping_meta: {
            tag_length: AUTH_TAG_LENGTH,
            encoding: 'base64url',
        },
    };
}

export async function unwrapRequestKeyForOwner(ownerMasterKeyMaterial, wrappedRequestPackage) {
    if (!wrappedRequestPackage || typeof wrappedRequestPackage !== 'object') {
        throw new Error('Wrapped request key payload is missing.');
    }

    if (wrappedRequestPackage.key_version !== ENCSEND_OWNER_WRAP_KEY_VERSION) {
        throw new Error('Unsupported wrapped request key version.');
    }

    if (wrappedRequestPackage.wrapping_algorithm !== ENCSEND_OWNER_CRYPTO_ALGORITHM) {
        throw new Error('Unsupported wrapped request key algorithm.');
    }

    const ownerMasterKeyBytes = base64UrlToBytes(ownerMasterKeyMaterial);
    const wrappedRequestKeyBytes = base64UrlToBytes(wrappedRequestPackage.wrapped_request_key ?? '');
    const wrappingIvBytes = base64UrlToBytes(wrappedRequestPackage.wrapping_iv ?? '');

    if (ownerMasterKeyBytes.length !== KEY_BYTE_LENGTH) {
        throw new Error('Invalid owner master key.');
    }

    const ownerMasterKey = await importAesKey(ownerMasterKeyBytes, ['decrypt']);

    try {
        const requestKeyBytes = await decryptAesGcm(
            wrappedRequestKeyBytes,
            ownerMasterKey,
            wrappingIvBytes,
            ENCSEND_OWNER_WRAP_KEY_VERSION
        );

        if (requestKeyBytes.length !== KEY_BYTE_LENGTH) {
            throw new Error('Recovered request key has invalid length.');
        }

        return bytesToBase64Url(requestKeyBytes);
    } catch (error) {
        throw new Error('Unable to unwrap request key with the current recovery state.');
    }
}

export async function wrapSecretKeyForOwner(ownerMasterKeyMaterial, secretKeyMaterial) {
    const ownerMasterKeyBytes = base64UrlToBytes(ownerMasterKeyMaterial);
    const secretKeyBytes = base64UrlToBytes(secretKeyMaterial);

    if (ownerMasterKeyBytes.length !== KEY_BYTE_LENGTH || secretKeyBytes.length !== KEY_BYTE_LENGTH) {
        throw new Error('Invalid key material for secret key wrapping.');
    }

    const wrappingIvBytes = randomBytes(IV_BYTE_LENGTH);
    const ownerMasterKey = await importAesKey(ownerMasterKeyBytes, ['encrypt', 'decrypt']);
    const wrappedSecretKeyBytes = await encryptAesGcm(
        secretKeyBytes,
        ownerMasterKey,
        wrappingIvBytes,
        ENCSEND_OWNER_SECRET_WRAP_KEY_VERSION
    );

    return {
        key_version: ENCSEND_OWNER_SECRET_WRAP_KEY_VERSION,
        wrapping_algorithm: ENCSEND_OWNER_CRYPTO_ALGORITHM,
        wrapped_secret_key: bytesToBase64Url(wrappedSecretKeyBytes),
        wrapping_iv: bytesToBase64Url(wrappingIvBytes),
        wrapping_meta: {
            tag_length: AUTH_TAG_LENGTH,
            encoding: 'base64url',
        },
    };
}

export async function unwrapSecretKeyForOwner(ownerMasterKeyMaterial, wrappedSecretPackage) {
    if (!wrappedSecretPackage || typeof wrappedSecretPackage !== 'object') {
        throw new Error('Wrapped secret key payload is missing.');
    }

    if (wrappedSecretPackage.key_version !== ENCSEND_OWNER_SECRET_WRAP_KEY_VERSION) {
        throw new Error('Unsupported wrapped secret key version.');
    }

    if (wrappedSecretPackage.wrapping_algorithm !== ENCSEND_OWNER_CRYPTO_ALGORITHM) {
        throw new Error('Unsupported wrapped secret key algorithm.');
    }

    const ownerMasterKeyBytes = base64UrlToBytes(ownerMasterKeyMaterial);
    const wrappedSecretKeyBytes = base64UrlToBytes(wrappedSecretPackage.wrapped_secret_key ?? '');
    const wrappingIvBytes = base64UrlToBytes(wrappedSecretPackage.wrapping_iv ?? '');

    if (ownerMasterKeyBytes.length !== KEY_BYTE_LENGTH) {
        throw new Error('Invalid owner master key.');
    }

    const ownerMasterKey = await importAesKey(ownerMasterKeyBytes, ['decrypt']);

    try {
        const secretKeyBytes = await decryptAesGcm(
            wrappedSecretKeyBytes,
            ownerMasterKey,
            wrappingIvBytes,
            ENCSEND_OWNER_SECRET_WRAP_KEY_VERSION
        );

        if (secretKeyBytes.length !== KEY_BYTE_LENGTH) {
            throw new Error('Recovered secret key has invalid length.');
        }

        return bytesToBase64Url(secretKeyBytes);
    } catch (error) {
        throw new Error('Unable to unwrap secret key with the current recovery state.');
    }
}

export function serializeOwnerWrappedKeyForUi(ownerWrappedKey) {
    try {
        return JSON.stringify(ownerWrappedKey);
    } catch (error) {
        return '';
    }
}

export function parseOwnerWrappedKeyFromUi(rawValue) {
    if (typeof rawValue !== 'string' || rawValue.trim() === '') {
        return null;
    }

    try {
        const parsed = JSON.parse(rawValue);
        return (parsed && typeof parsed === 'object') ? parsed : null;
    } catch (error) {
        return null;
    }
}

export function buildRecoveryMetadataSummary(profilePayload) {
    const kdfIterations = Number(profilePayload?.kdf?.iterations ?? 0);
    const updatedAt = profilePayload?.updated_at;
    const parts = [];

    if (Number.isFinite(kdfIterations) && kdfIterations > 0) {
        parts.push(`PBKDF2 iterations: ${kdfIterations}`);
    }

    if (typeof updatedAt === 'string' && updatedAt.length > 0) {
        parts.push(`Updated: ${updatedAt}`);
    }

    return parts.join(' | ');
}
