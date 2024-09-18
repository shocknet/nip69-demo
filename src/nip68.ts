import { bech32 } from 'bech32';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils';
import { decodePayload, decryptData, encodePayload, encryptData, getSharedSecret } from './nip44';
import { finishEvent, generatePrivateKey, getPublicKey, SimplePool, UnsignedEvent } from './tools';
import { encodeTLV, parseTLV, TLV } from './nip69';

export const utf8Decoder = new TextDecoder('utf-8')
export const utf8Encoder = new TextEncoder()

export type DebitPointer = {
    pubkey: string,
    relay: string,
    pointer?: string,
}
export const encodeNdebit = (debit: DebitPointer): string => {
    const o: TLV = {
        0: [hexToBytes(debit.pubkey)],
        1: [utf8Encoder.encode(debit.relay)],
    }
    if (debit.pointer) {
        o[2] = [utf8Encoder.encode(debit.pointer)]
    }
    const data = encodeTLV(o);
    const words = bech32.toWords(data)
    return bech32.encode("ndebit", words, 5000);
}

export const decodeNdebit = (noffer: string): DebitPointer => {
    const { prefix, words } = bech32.decode(noffer, 5000)
    if (prefix !== "ndebit") {
        throw new Error("Expected nprofile prefix");
    }
    const data = new Uint8Array(bech32.fromWords(words))

    const tlv = parseTLV(data);
    if (!tlv[0]?.[0]) throw new Error('missing TLV 0 for noffer')
    if (tlv[0][0].length !== 32) throw new Error('TLV 0 should be 32 bytes')
    if (!tlv[1]?.[0]) throw new Error('missing TLV 1 for noffer')
    return {
        pubkey: bytesToHex(tlv[0][0]),
        relay: utf8Decoder.decode(tlv[1][0]),
        pointer: tlv[2] ? utf8Decoder.decode(tlv[2][0]) : undefined
    }
}


(window as any).encodeNdebit = encodeNdebit

export const decodeNdebitInput = async (input: string) => {
    if (input.startsWith("lightning:")) {
        input = input.slice("lightning:".length)
    }
    const debit = decodeNdebit(input)
    if (input.startsWith("ndebit")) {
    } else {
        throw new Error("Invalid input")
    }
    return { debit, send: wrapSend(debit) }
}
(window as any).decodeNdebitInput = decodeNdebitInput

type RecurringDebitTimeUnit = 'day' | 'week' | 'month'
type RecurringDebit = { frequency: { number: number, unit: RecurringDebitTimeUnit } }
export type NdebitData = { pointer?: string, amount_sats: number } & (RecurringDebit | { bolt11: string })
export type NdebitSuccess = { res: 'ok' }
export type NdebitSuccessPayment = { res: 'ok', preimage: string }
export type NdebitFailure = { res: 'GFY', error: string, code: number }
type Nip68Response = NdebitSuccess | NdebitSuccessPayment | NdebitFailure
const nip68errs = {
    1: "Request Denied Warning",
    2: "Temporary Failure",
    3: "Expired Request",
    4: "Rate Limited",
    5: "Invalid Amount",
    6: "Invalid Request",
}
const pool = new SimplePool()
const privateKey = generatePrivateKey()
const publicKey = getPublicKey(privateKey)
const wrapSend = (debit: DebitPointer) => (rest: RecurringDebit | { bolt11: string }) => sendNip68([debit.relay], debit.pubkey, { ...debit, ...rest })


const sendNip68 = async (relays: string[], pubKey: string, data: DebitPointer): Promise<Nip68Response> => {
    const decoded = await encryptData(JSON.stringify(data), getSharedSecret(privateKey, pubKey))
    const content = encodePayload(decoded)
    const e = await sendRaw(
        relays,
        {
            content,
            created_at: Math.floor(Date.now() / 1000),
            kind: 21002,
            pubkey: publicKey,
            tags: [['p', pubKey]]
        },
        privateKey
    )
    const sub = pool.sub(relays, [{
        since: Math.floor(Date.now() / 1000) - 1,
        kinds: [21002],
        '#p': [publicKey],
        '#e': [e.id]
    }])
    return new Promise<Nip68Response>((res, rej) => {
        const timeout = setTimeout(() => {
            sub.unsub(); rej("failed to get nip69 reponse in time")
        }, 30 * 1000)
        sub.on('event', async (e) => {
            clearTimeout(timeout)
            const decoded = decodePayload(e.content)
            const content = await decryptData(decoded, getSharedSecret(privateKey, pubKey))
            res(JSON.parse(content))
        })
    })
}

const sendRaw = async (relays: string[], event: UnsignedEvent, privateKey: string) => {
    const signed = finishEvent(event, privateKey)
    pool.publish(relays, signed).forEach(p => {
        p.then(() => console.info("sent ok"))
        p.catch(() => console.error("failed to send"))
    })
    return signed
}


