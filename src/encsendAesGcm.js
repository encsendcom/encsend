import { base64UrlToBytes, bytesToBase64Url } from './base64url.js';

export const ENCSEND_CRYPTO_VERSION_V1 = 'encsend-aesgcm-v1';
export const ENCSEND_CRYPTO_VERSION_V2 = 'encsend-aesgcm-wrap-v2';
export const ENCSEND_CRYPTO_ALGORITHM = 'AES-GCM';

const KEY_BYTE_LENGTH = 32;
const IV_BYTE_LENGTH = 12;
const SALT_BYTE_LENGTH = 16;
const AUTH_TAG_LENGTH = 128;
const LINK_WRAP_INFO = 'encsend/link-wrap/v2';
const PASSWORD_KDF_ITERATIONS = 210000;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function hasWebCryptoSupport() {
    return typeof window !== 'undefined'
        && !!window.crypto
        && !!window.crypto.subtle
        && typeof window.crypto.getRandomValues === 'function';
}

export function generateKeyMaterial() {
    const keyBytes = new Uint8Array(KEY_BYTE_LENGTH);
    window.crypto.getRandomValues(keyBytes);

    return bytesToBase64Url(keyBytes);
}

function randomBytes(length) {
    const bytes = new Uint8Array(length);
    window.crypto.getRandomValues(bytes);

    return bytes;
}

async function importAesGcmKey(rawBytes, usages) {
    return window.crypto.subtle.importKey(
        'raw',
        rawBytes,
        { name: ENCSEND_CRYPTO_ALGORITHM },
        false,
        usages
    );
}

async function encryptWithAesGcm(rawBytes, cryptoKey, ivBytes) {
    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: ENCSEND_CRYPTO_ALGORITHM,
            iv: ivBytes,
            tagLength: AUTH_TAG_LENGTH,
        },
        cryptoKey,
        rawBytes
    );

    return new Uint8Array(encrypted);
}

async function decryptWithAesGcm(ciphertextBytes, cryptoKey, ivBytes) {
    const decrypted = await window.crypto.subtle.decrypt(
        {
            name: ENCSEND_CRYPTO_ALGORITHM,
            iv: ivBytes,
            tagLength: AUTH_TAG_LENGTH,
        },
        cryptoKey,
        ciphertextBytes
    );

    return new Uint8Array(decrypted);
}

async function deriveLinkWrapKey(linkKeyBytes, saltBytes, infoText) {
    const baseKey = await window.crypto.subtle.importKey(
        'raw',
        linkKeyBytes,
        'HKDF',
        false,
        ['deriveKey']
    );

    return window.crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: saltBytes,
            info: textEncoder.encode(infoText),
        },
        baseKey,
        {
            name: ENCSEND_CRYPTO_ALGORITHM,
            length: 256,
        },
        false,
        ['encrypt', 'decrypt']
    );
}

async function derivePasswordWrapKey(passwordText, saltBytes, iterations) {
    const baseKey = await window.crypto.subtle.importKey(
        'raw',
        textEncoder.encode(passwordText),
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
            name: ENCSEND_CRYPTO_ALGORITHM,
            length: 256,
        },
        false,
        ['encrypt', 'decrypt']
    );
}

function normalizePasswordValue(passwordValue) {
    if (typeof passwordValue !== 'string') {
        return null;
    }

    const trimmed = passwordValue.trim();

    return trimmed.length > 0 ? trimmed : null;
}

export function packageRequiresPassword(payloadPackage) {
    if (!payloadPackage || typeof payloadPackage !== 'object') {
        return false;
    }

    if (payloadPackage.encryption_version !== ENCSEND_CRYPTO_VERSION_V2) {
        return false;
    }

    return Boolean(payloadPackage?.encryption_meta?.password_wrap?.enabled);
}

export async function encryptTextPayload(plaintext, keyMaterial, passwordValue = null) {
    if (typeof plaintext !== 'string' || plaintext.length === 0) {
        throw new Error('Message is empty.');
    }

    const linkKeyBytes = base64UrlToBytes(keyMaterial);

    if (linkKeyBytes.length !== KEY_BYTE_LENGTH) {
        throw new Error('Invalid link key material length.');
    }

    const payloadKeyBytes = randomBytes(KEY_BYTE_LENGTH);
    const payloadIvBytes = randomBytes(IV_BYTE_LENGTH);

    const payloadKey = await importAesGcmKey(payloadKeyBytes, ['encrypt', 'decrypt']);
    const payloadCiphertext = await encryptWithAesGcm(
        textEncoder.encode(plaintext),
        payloadKey,
        payloadIvBytes
    );

    const linkWrapSaltBytes = randomBytes(SALT_BYTE_LENGTH);
    const linkWrapIvBytes = randomBytes(IV_BYTE_LENGTH);
    const linkWrapKey = await deriveLinkWrapKey(linkKeyBytes, linkWrapSaltBytes, LINK_WRAP_INFO);
    const linkWrappedPayloadKeyBytes = await encryptWithAesGcm(payloadKeyBytes, linkWrapKey, linkWrapIvBytes);

    const normalizedPassword = normalizePasswordValue(passwordValue);

    let encryptedKeyBytes = linkWrappedPayloadKeyBytes;
    let passwordWrapMeta = {
        enabled: false,
    };

    if (normalizedPassword) {
        const passwordSaltBytes = randomBytes(SALT_BYTE_LENGTH);
        const passwordWrapIvBytes = randomBytes(IV_BYTE_LENGTH);
        const passwordWrapKey = await derivePasswordWrapKey(
            normalizedPassword,
            passwordSaltBytes,
            PASSWORD_KDF_ITERATIONS
        );

        encryptedKeyBytes = await encryptWithAesGcm(
            linkWrappedPayloadKeyBytes,
            passwordWrapKey,
            passwordWrapIvBytes
        );

        passwordWrapMeta = {
            enabled: true,
            kdf: 'PBKDF2-SHA-256',
            iterations: PASSWORD_KDF_ITERATIONS,
            salt: bytesToBase64Url(passwordSaltBytes),
            iv: bytesToBase64Url(passwordWrapIvBytes),
            tag_length: AUTH_TAG_LENGTH,
        };
    }

    payloadKeyBytes.fill(0);

    return {
        encryptedPayload: bytesToBase64Url(payloadCiphertext),
        encryptedKey: bytesToBase64Url(encryptedKeyBytes),
        encryptionVersion: ENCSEND_CRYPTO_VERSION_V2,
        encryptionAlgorithm: ENCSEND_CRYPTO_ALGORITHM,
        encryptionIv: bytesToBase64Url(payloadIvBytes),
        encryptionMeta: {
            payload_iv_length: IV_BYTE_LENGTH,
            payload_tag_length: AUTH_TAG_LENGTH,
            encoding: 'utf-8',
            key_material_encoding: 'base64url',
            link_wrap: {
                kdf: 'HKDF-SHA-256',
                info: LINK_WRAP_INFO,
                salt: bytesToBase64Url(linkWrapSaltBytes),
                iv: bytesToBase64Url(linkWrapIvBytes),
                tag_length: AUTH_TAG_LENGTH,
            },
            password_wrap: passwordWrapMeta,
        },
    };
}

async function decryptVersionOnePayload(payloadPackage, keyMaterial) {
    if (payloadPackage.encryption_algorithm !== ENCSEND_CRYPTO_ALGORITHM) {
        throw new Error('Unsupported encryption algorithm.');
    }

    const keyBytes = base64UrlToBytes(keyMaterial);
    const ivBytes = base64UrlToBytes(payloadPackage.encryption_iv ?? '');
    const ciphertextBytes = base64UrlToBytes(payloadPackage.encrypted_payload ?? '');

    if (keyBytes.length !== KEY_BYTE_LENGTH) {
        throw new Error('Invalid key material length.');
    }

    if (ivBytes.length < IV_BYTE_LENGTH) {
        throw new Error('Invalid IV.');
    }

    const cryptoKey = await importAesGcmKey(keyBytes, ['decrypt']);

    try {
        const plaintextBytes = await decryptWithAesGcm(ciphertextBytes, cryptoKey, ivBytes);
        return textDecoder.decode(plaintextBytes);
    } catch (error) {
        throw new Error('Decryption failed. Key or payload is invalid.');
    }
}

export async function decryptTextPayload(payloadPackage, keyMaterial, passwordValue = null) {
    if (!payloadPackage || typeof payloadPackage !== 'object') {
        throw new Error('Missing payload package.');
    }

    const version = payloadPackage.encryption_version;

    if (version === ENCSEND_CRYPTO_VERSION_V1) {
        return decryptVersionOnePayload(payloadPackage, keyMaterial);
    }

    if (version !== ENCSEND_CRYPTO_VERSION_V2) {
        throw new Error('Unsupported encryption version.');
    }

    if (payloadPackage.encryption_algorithm !== ENCSEND_CRYPTO_ALGORITHM) {
        throw new Error('Unsupported encryption algorithm.');
    }

    const linkKeyBytes = base64UrlToBytes(keyMaterial);

    if (linkKeyBytes.length !== KEY_BYTE_LENGTH) {
        throw new Error('Invalid link key material length.');
    }

    const metadata = payloadPackage.encryption_meta ?? {};
    const linkWrapMeta = metadata.link_wrap ?? {};
    const passwordWrapMeta = metadata.password_wrap ?? {};

    const encryptedPayloadBytes = base64UrlToBytes(payloadPackage.encrypted_payload ?? '');
    const payloadIvBytes = base64UrlToBytes(payloadPackage.encryption_iv ?? '');
    const encryptedKeyBytes = base64UrlToBytes(payloadPackage.encrypted_key ?? '');

    const linkWrapSaltBytes = base64UrlToBytes(linkWrapMeta.salt ?? '');
    const linkWrapIvBytes = base64UrlToBytes(linkWrapMeta.iv ?? '');
    const linkWrapInfo = typeof linkWrapMeta.info === 'string' ? linkWrapMeta.info : LINK_WRAP_INFO;

    const linkWrapKey = await deriveLinkWrapKey(linkKeyBytes, linkWrapSaltBytes, linkWrapInfo);

    let linkWrappedPayloadKeyBytes = encryptedKeyBytes;

    if (passwordWrapMeta.enabled === true) {
        const normalizedPassword = normalizePasswordValue(passwordValue);

        if (!normalizedPassword) {
            throw new Error('Decryption password required.');
        }

        const iterations = Number(passwordWrapMeta.iterations ?? PASSWORD_KDF_ITERATIONS);
        const passwordSaltBytes = base64UrlToBytes(passwordWrapMeta.salt ?? '');
        const passwordIvBytes = base64UrlToBytes(passwordWrapMeta.iv ?? '');
        const passwordWrapKey = await derivePasswordWrapKey(
            normalizedPassword,
            passwordSaltBytes,
            iterations
        );

        try {
            linkWrappedPayloadKeyBytes = await decryptWithAesGcm(
                encryptedKeyBytes,
                passwordWrapKey,
                passwordIvBytes
            );
        } catch (error) {
            throw new Error('Password-based key unwrap failed.');
        }
    }

    let payloadKeyBytes;

    try {
        payloadKeyBytes = await decryptWithAesGcm(linkWrappedPayloadKeyBytes, linkWrapKey, linkWrapIvBytes);
    } catch (error) {
        throw new Error('Link key unwrap failed.');
    }

    const payloadKey = await importAesGcmKey(payloadKeyBytes, ['decrypt']);
    payloadKeyBytes.fill(0);

    try {
        const plaintextBytes = await decryptWithAesGcm(encryptedPayloadBytes, payloadKey, payloadIvBytes);
        return textDecoder.decode(plaintextBytes);
    } catch (error) {
        throw new Error('Payload decryption failed.');
    }
}
