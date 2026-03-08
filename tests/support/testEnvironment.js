const originalDate = globalThis.Date;
const originalWindow = globalThis.window;
const originalBtoa = globalThis.btoa;
const originalAtob = globalThis.atob;

function cloneWindowWithCrypto(getRandomValues) {
    const nextWindow = originalWindow ? { ...originalWindow } : {};

    nextWindow.crypto = {
        subtle: globalThis.crypto.subtle,
        getRandomValues,
    };

    return nextWindow;
}

export function installBrowserCryptoTestGlobals() {
    if (typeof globalThis.btoa !== 'function') {
        globalThis.btoa = (value) => Buffer.from(value, 'binary').toString('base64');
    }

    if (typeof globalThis.atob !== 'function') {
        globalThis.atob = (value) => Buffer.from(value, 'base64').toString('binary');
    }

    globalThis.window = cloneWindowWithCrypto((target) => globalThis.crypto.getRandomValues(target));
}

export function resetBrowserCryptoTestGlobals() {
    if (typeof originalBtoa === 'function') {
        globalThis.btoa = originalBtoa;
    } else {
        delete globalThis.btoa;
    }

    if (typeof originalAtob === 'function') {
        globalThis.atob = originalAtob;
    } else {
        delete globalThis.atob;
    }

    globalThis.Date = originalDate;

    if (typeof originalWindow === 'undefined') {
        delete globalThis.window;
        return;
    }

    globalThis.window = originalWindow;
}

export async function withDeterministicRandom(randomChunks, callback) {
    const queue = randomChunks.map((chunk) => Uint8Array.from(chunk));
    const previousWindow = globalThis.window;

    globalThis.window = cloneWindowWithCrypto((target) => {
        const nextChunk = queue.shift();

        if (!nextChunk) {
            throw new Error(`Missing deterministic random chunk for length ${target.length}.`);
        }

        if (nextChunk.length !== target.length) {
            throw new Error(`Deterministic random length mismatch. Expected ${target.length}, received ${nextChunk.length}.`);
        }

        target.set(nextChunk);
        return target;
    });

    try {
        const result = await callback();

        if (queue.length !== 0) {
            throw new Error(`Unused deterministic random chunks remain: ${queue.length}.`);
        }

        return result;
    } finally {
        if (typeof previousWindow === 'undefined') {
            delete globalThis.window;
        } else {
            globalThis.window = previousWindow;
        }
    }
}

export async function withFrozenDate(isoTimestamp, callback) {
    class FixedDate extends originalDate {
        constructor(...args) {
            if (args.length === 0) {
                super(isoTimestamp);
                return;
            }

            super(...args);
        }

        static now() {
            return new originalDate(isoTimestamp).getTime();
        }

        static parse(value) {
            return originalDate.parse(value);
        }

        static UTC(...args) {
            return originalDate.UTC(...args);
        }
    }

    globalThis.Date = FixedDate;

    try {
        return await callback();
    } finally {
        globalThis.Date = originalDate;
    }
}
