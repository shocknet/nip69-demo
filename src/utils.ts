import { ClinkSDK, generateSecretKey, getPublicKey, nip19 } from '@shocknet/clink-sdk';

const KEY_STORAGE = 'clink-demo-privateKey';

export const DEFAULT_NOFFER =
    'noffer1qvqsyqjqxuurvwpcxc6rvvrxxsurqep5vfjk2wf4v33nsenrxumnyvesxfnrswfkvycrwdp3x93xydf5xg6rzce4vv6xgdfh8quxgct9x5erxvspremhxue69uhhgetnwskhyetvv9ujumrfva58gmnfdenjuur4vgqzpccxc30wpf78wf2q78wg3vq008fd8ygtl4qy06gstpye3h5unc47xmee6z';

function initializePrivateKey(): Uint8Array {
    const storedKey = localStorage.getItem(KEY_STORAGE);
    if (storedKey) {
        return new Uint8Array(storedKey.split(',').map(Number));
    }
    const newKey = generateSecretKey();
    localStorage.setItem(KEY_STORAGE, newKey.toString());
    return newKey;
}

/** Persisted so debit budgets stay tied to one identity. */
export const clientPrivateKey = initializePrivateKey();

export function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

export function requireEl<T extends HTMLElement>(id: string): T {
    const el = document.getElementById(id);
    if (!el) {
        throw new Error(`missing #${id}`);
    }
    return el as T;
}

export function displayClientIdentity(container: HTMLElement, npubSpan: HTMLElement): void {
    const npub = nip19.npubEncode(getPublicKey(clientPrivateKey));
    npubSpan.textContent = `${npub.slice(0, 10)}...${npub.slice(-5)}`;
    container.style.display = 'block';
}

export function sdkFromPointer(pubkey: string, relay: string): ClinkSDK {
    return new ClinkSDK({
        privateKey: clientPrivateKey,
        relays: [relay],
        toPubKey: pubkey,
        defaultTimeoutSeconds: 30,
    });
}
