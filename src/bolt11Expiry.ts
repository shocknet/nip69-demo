/** Bech32 charset. Data words never include the separator `1`. */
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const TIMESTAMP_WORDS = 7;
const DEFAULT_EXPIRY_SECONDS = 3600;
const TAG_EXPIRY = 6;

function dataWords(bolt11: string): number[] | null {
    const lower = bolt11.trim().toLowerCase();
    const sep = lower.lastIndexOf('1');
    if (sep < 1) {
        return null;
    }
    const payload = lower.slice(sep + 1, -6);
    const words: number[] = [];
    for (const char of payload) {
        const value = CHARSET.indexOf(char);
        if (value < 0) {
            return null;
        }
        words.push(value);
    }
    return words;
}

function wordsToInt(words: number[], start: number, count: number): number {
    let value = 0;
    for (let i = 0; i < count; i++) {
        value = value * 32 + words[start + i];
    }
    return value;
}

function taggedExpiry(words: number[]): number {
    let i = TIMESTAMP_WORDS;
    while (i + 3 <= words.length) {
        const type = words[i];
        const len = (words[i + 1] << 5) | words[i + 2];
        i += 3;
        if (i + len > words.length) {
            break;
        }
        if (type === TAG_EXPIRY) {
            return wordsToInt(words, i, len);
        }
        i += len;
    }
    return DEFAULT_EXPIRY_SECONDS;
}

/** Unix-ms when this BOLT11 stops being payable. Null if the string is not a bolt11. */
export function invoiceExpiresAtMs(bolt11: string): number | null {
    const words = dataWords(bolt11);
    if (!words || words.length < TIMESTAMP_WORDS) {
        return null;
    }
    const created = wordsToInt(words, 0, TIMESTAMP_WORDS);
    return (created + taggedExpiry(words)) * 1000;
}
