import { Event, generateSecretKey, SimplePool, nip69, nip19, getPublicKey, finalizeEvent, nip44 } from 'nostr-tools'
import { SubCloser } from 'nostr-tools/lib/types/abstract-pool'


(window as any).encodeNoffer = nip19.nofferEncode

export const decodeInput = async (input: string) => {
    if (input.startsWith("lightning:")) {
        input = input.slice("lightning:".length)
    }
    let offer: nip19.OfferPointer
    if (input.startsWith("noffer")) {
        const decoded = nip19.decode(input)
        if (!decoded || decoded.type !== "noffer") throw new Error("Invalid input")
        offer = decoded.data
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
        const decoded = nip19.decode(json.nip69 as string)
        if (!decoded || decoded.type !== "noffer") throw new Error("Invalid input")
        offer = decoded.data
    } else {
        throw new Error("Invalid input")
    }
    return { offer, send: wrapSend(offer) }
}
(window as any).decodeInput = decodeInput
const pool = new SimplePool()
const privateKey = generateSecretKey()
const wrapSend = (offer: nip19.OfferPointer) => (amt?: number) => nip69.SendNofferRequest(pool, privateKey, [offer.relay], offer.pubkey, { offer: offer.offer, amount: amt })

const SendNofferRequest = async (pool: SimplePool, privateKey: Uint8Array, relays: string[], pubKey: string, data: nip69.NofferData): Promise<nip69.Nip69Response> => {
    const publicKey = getPublicKey(privateKey)
    const content = nip44.encrypt(JSON.stringify(data), nip44.getConversationKey(privateKey, pubKey))
    const event = nip69.newNip69Event(content, publicKey, pubKey)
    const signed = finalizeEvent(event, privateKey)
    await Promise.all(pool.publish(relays, signed))
    return new Promise<nip69.Nip69Response>((res, rej) => {
        let closer: SubCloser = { close: () => { } }
        const timeout = setTimeout(() => {
            closer.close(); rej("failed to get nip69 response in time")
        }, 30 * 1000)

        closer = pool.subscribeMany(relays, [newNip69Filter(publicKey, signed.id)], {
            receivedEvent: e => { console.log(e); },
            onevent: async (e) => {
                clearTimeout(timeout)
                const content = nip44.decrypt(e.content, nip44.getConversationKey(privateKey, pubKey))
                res(JSON.parse(content))
            }
        })
    })
}

export const newNip69Filter = (publicKey: string, eventId: string) => ({
    since: Math.floor(Date.now() / 1000) - 1,
    kinds: [21001],
    '#p': [publicKey],
    '#e': [eventId]
})