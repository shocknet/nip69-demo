import { bech32 } from 'bech32';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils';
import { decodePayload, decryptData, encodePayload, encryptData, getSharedSecret } from './nip44';
import { finishEvent, generatePrivateKey, getPublicKey, SimplePool, UnsignedEvent } from './tools';

export const utf8Decoder = new TextDecoder('utf-8')
export const utf8Encoder = new TextEncoder()

export type OfferPointer = {
    pubkey: string,
    relay: string,
    offer: string
    priceType: PriceType,
    price?: number
}
export enum PriceType {
    fixed = 0,
    variable = 1,
    spontaneous = 2,
}

export type TLV = { [t: number]: Uint8Array[] }

export const encodeTLV = (tlv: TLV): Uint8Array => {
    const entries: Uint8Array[] = []

    Object.entries(tlv)
        /* 
          the original function does a reverse() here,
          but here it causes the nprofile string to be different,
          even though it would still decode to the correct original inputs
        */
        //.reverse() 
        .forEach(([t, vs]) => {
            vs.forEach(v => {
                const entry = new Uint8Array(v.length + 2)
                entry.set([parseInt(t)], 0)
                entry.set([v.length], 1)
                entry.set(v, 2)
                entries.push(entry)
            })
        })
    return concatBytes(...entries);
}

export const parseTLV = (data: Uint8Array): TLV => {
    const result: TLV = {}
    let rest = data
    while (rest.length > 0) {
        const t = rest[0]
        const l = rest[1]
        const v = rest.slice(2, 2 + l)
        rest = rest.slice(2 + l)
        if (v.length < l) throw new Error(`not enough data to read on TLV ${t}`)
        result[t] = result[t] || []
        result[t].push(v)
    }
    return result
}

export const decodeNoffer = (noffer: string): OfferPointer => {
    const { prefix, words } = bech32.decode(noffer, 5000)
    if (prefix !== "noffer") {
        throw new Error("Expected nprofile prefix");
    }
    const data = new Uint8Array(bech32.fromWords(words))

    const tlv = parseTLV(data);
    if (!tlv[0]?.[0]) throw new Error('missing TLV 0 for noffer')
    if (tlv[0][0].length !== 32) throw new Error('TLV 0 should be 32 bytes')
    if (!tlv[1]?.[0]) throw new Error('missing TLV 1 for noffer')
    if (!tlv[2]?.[0]) throw new Error('missing TLV 2 for noffer')
    if (!tlv[3]?.[0]) throw new Error('missing TLV 3 for noffer')
    return {
        pubkey: bytesToHex(tlv[0][0]),
        relay: utf8Decoder.decode(tlv[1][0]),
        offer: utf8Decoder.decode(tlv[2][0]),
        priceType: tlv[3][0][0],
        price: tlv[4] ? uint8ArrayToNumber(tlv[4][0]) : undefined
    }
}

export const encodeNoffer = (offer: OfferPointer): string => {
    let relay = offer.relay
    const o: TLV = {
        0: [hexToBytes(offer.pubkey)],
        1: [utf8Encoder.encode(relay)],
        2: [utf8Encoder.encode(offer.offer)],
        3: [new Uint8Array([Number(offer.priceType)])],
    }
    if (offer.price) {
        o[4] = [numberToUint8Array(offer.price)]
    }
    const data = encodeTLV(o);
    const words = bech32.toWords(data)
    return bech32.encode("noffer", words, 5000);
}

const uint8ArrayToNumber = (arr: Uint8Array): number => {
    const buffer = arr.buffer;
    const view = new DataView(buffer);
    return view.getUint32(0);
}
const numberToUint8Array = (num: number) => {
    const buffer = new ArrayBuffer(4); // 4 bytes for a 32-bit unsigned integer
    const view = new DataView(buffer);
    view.setUint32(0, num);
    return new Uint8Array(buffer);
}

(window as any).encodeNoffer = encodeNoffer

export const decodeInput = async (input: string) => {
    if (input.startsWith("lightning:")) {
        input = input.slice("lightning:".length)
    }
    let offer: OfferPointer
    if (input.startsWith("noffer")) {
        offer = decodeNoffer(input)
    } else if (input.includes("@")) {
        const lnParts = input.split("@")
        const payLink = "https://" + lnParts[1] + "/.well-known/lnurlp/" + lnParts[0];
        const res = await fetch(payLink)
        const json = await res.json()
        if (json.status === "ERROR") {
            throw new Error(json.reason)
        }
        if (!json.nip69) {
            throw new Error("missing nip69 from lnurl address")
        }
        offer = decodeNoffer(json.nip69)
    } else {
        throw new Error("Invalid input")
    }
    return { offer, send: wrapSend(offer) }
}
(window as any).decodeInput = decodeInput
export type NofferData = { offer: string, amount?: number }
export type Nip69Success = { bolt11: string }
export type Nip69Error = { code: number, error: string, range: { min: number, max: number } }
export type Nip69Response = Nip69Success | Nip69Error
const pool = new SimplePool()
const privateKey = generatePrivateKey()
const publicKey = getPublicKey(privateKey)
const wrapSend = (offer: OfferPointer) => (amt?: number) => sendNip69([offer.relay], offer.pubkey, { offer: offer.offer, amount: amt })
const sendNip69 = async (relays: string[], pubKey: string, data: NofferData): Promise<Nip69Response> => {
    const decoded = await encryptData(JSON.stringify(data), getSharedSecret(privateKey, pubKey))
    const content = encodePayload(decoded)
    const e = await sendRaw(
        relays,
        {
            content,
            created_at: Math.floor(Date.now() / 1000),
            kind: 21001,
            pubkey: publicKey,
            tags: [['p', pubKey]]
        },
        privateKey
    )
    const sub = pool.sub(relays, [{
        since: Math.floor(Date.now() / 1000) - 1,
        kinds: [21001],
        '#p': [publicKey],
        '#e': [e.id]
    }])
    return new Promise<Nip69Response>((res, rej) => {
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