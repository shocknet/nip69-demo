import { Buffer } from 'buffer';
import { generateSecretKey, SimplePool, nip68, nip19 } from 'nostr-tools'


(window as any).encodeNdebit = nip19.ndebitEncode

export const decodeNdebitInput = async (input: string) => {
    if (input.startsWith("lightning:")) {
        input = input.slice("lightning:".length)
    }
    if (!input.startsWith("ndebit")) {
        throw new Error("Invalid input")
    }
    const res = nip19.decode(input)
    if (res.type !== "ndebit") {
        throw new Error("Invalid input")
    }
    const debit = res.data
    return { debit, send: wrapSend(debit) }
}
(window as any).decodeNdebitInput = decodeNdebitInput

const pool = new SimplePool()
let privateKey: Uint8Array
const secret = localStorage.getItem("nostr_secret")
if (secret) {
    privateKey = Uint8Array.from(Buffer.from(secret, "hex"))
} else {
    privateKey = generateSecretKey()
    localStorage.setItem("nostr_secret", Buffer.from(privateKey).toString("hex"))
}
const wrapSend = (debit: nip19.DebitPointer) => (rest: nip68.BudgetFrequency | { bolt11: string }) => nip68.SendNdebitRequest(pool, privateKey, [debit.relay], debit.pubkey, {
    ...debit,
    ...rest
})
