export function bytesToBase64Url(bytes) {
    let binary = '';

    for (let i = 0; i < bytes.length; i += 1) {
        binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
}

export function base64UrlToBytes(base64UrlValue) {
    if (typeof base64UrlValue !== 'string' || base64UrlValue.trim() === '') {
        throw new Error('Missing base64url value.');
    }

    let base64Value = base64UrlValue
        .replace(/-/g, '+')
        .replace(/_/g, '/');

    const paddingLength = (4 - (base64Value.length % 4)) % 4;
    base64Value += '='.repeat(paddingLength);

    const binary = atob(base64Value);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}
