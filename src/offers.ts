import { ClinkSDK, decodeBech32, OfferPointer } from '@shocknet/clink-sdk';
import QRCode from 'qrcode';
import './styles.css';
import {
    DEFAULT_NOFFER,
    displayClientIdentity,
    errorMessage,
    requireEl,
    sdkFromPointer,
} from './utils';
import { invoiceExpiresAtMs } from './bolt11Expiry';

const nofferInput = requireEl<HTMLTextAreaElement>('nofferInput');
const decodeOfferButton = requireEl<HTMLButtonElement>('decodeOfferButton');
const offerActions = requireEl<HTMLDivElement>('offer-actions');
const amountInput = requireEl<HTMLInputElement>('amountInput');
const getInvoiceButton = requireEl<HTMLButtonElement>('getInvoiceButton');
const resultsSection = requireEl<HTMLDivElement>('offer-result-section');
const resultHeader = requireEl<HTMLHeadingElement>('result-header');
const resultData = requireEl<HTMLPreElement>('result-data');
const qrPlaceholder = requireEl<HTMLSpanElement>('qr-placeholder');
const qrCanvas = requireEl<HTMLCanvasElement>('qrCanvas');
const qrContainer = requireEl<HTMLDivElement>('qr-container');
const qrPayLink = requireEl<HTMLAnchorElement>('qr-pay-link');
const copyInvoiceButton = requireEl<HTMLButtonElement>('copy-invoice');
const receiptStatus = requireEl<HTMLDivElement>('receipt-status');
const receiptLabel = requireEl<HTMLSpanElement>('receipt-label');
const receiptCountdown = requireEl<HTMLSpanElement>('receipt-countdown');
const lnAddressInput = requireEl<HTMLInputElement>('lnAddressInput');
const checkAddressButton = requireEl<HTMLButtonElement>('checkAddressButton');
const addressResultSection = requireEl<HTMLDivElement>('address-result-section');
const addressResultHeader = requireEl<HTMLHeadingElement>('address-result-header');
const addressResultData = requireEl<HTMLPreElement>('address-result-data');
const clientIdentityDiv = requireEl<HTMLDivElement>('client-identity');
const clientNpubSpan = requireEl<HTMLSpanElement>('client-npub');

let decodedOffer: OfferPointer | null = null;
let offerSdk: ClinkSDK | null = null;
let isInvoiceDisplayed = false;
let expireTimer: ReturnType<typeof setInterval> | null = null;
let invoiceEndsAt = 0;

function formatCountdown(ms: number): string {
    const total = Math.max(0, Math.ceil(ms / 1000));
    const hours = Math.floor(total / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const seconds = total % 60;
    const two = (n: number) => n.toString().padStart(2, '0');
    if (hours > 0) {
        return `${hours}:${two(minutes)}:${two(seconds)}`;
    }
    return `${minutes}:${two(seconds)}`;
}

function hideCountdown(): void {
    receiptCountdown.hidden = true;
    receiptCountdown.textContent = '';
}

function clearExpireTimer(): void {
    if (expireTimer) {
        clearInterval(expireTimer);
        expireTimer = null;
    }
    hideCountdown();
}

function tickExpiry(): void {
    const remaining = invoiceEndsAt - Date.now();
    if (remaining <= 0) {
        expireInvoice();
        return;
    }
    receiptCountdown.hidden = false;
    receiptCountdown.textContent = formatCountdown(remaining);
}

function watchInvoiceExpiry(bolt11: string): void {
    clearExpireTimer();
    invoiceEndsAt = invoiceExpiresAtMs(bolt11) ?? Date.now() + 3600_000;
    tickExpiry();
    if (receiptStatus.classList.contains('error') || receiptStatus.classList.contains('paid')) {
        return;
    }
    expireTimer = setInterval(tickExpiry, 1000);
}

function stopOfferSdk(): void {
    clearExpireTimer();
    offerSdk?.Stop();
    offerSdk = null;
}

function expireInvoice(): void {
    if (receiptStatus.classList.contains('paid')) {
        return;
    }
    stopOfferSdk();
    qrPayLink.removeAttribute('href');
    qrPayLink.classList.remove('is-live');
    resultHeader.textContent = 'Expired';
    setReceipt('error', 'Invoice expired');
}

type ReceiptState = 'hidden' | 'waiting' | 'paid' | 'error';

function keepPaid(state: ReceiptState): boolean {
    return receiptStatus.classList.contains('paid') && state !== 'hidden' && state !== 'paid';
}

function setReceipt(state: ReceiptState, text = ''): void {
    if (keepPaid(state)) {
        return;
    }
    receiptStatus.className = `receipt-status ${state}`;
    receiptLabel.textContent = text;
    receiptStatus.hidden = state === 'hidden' || state === 'paid';
    if (state !== 'waiting') {
        hideCountdown();
    }
    qrContainer.classList.toggle('receipt-waiting', state === 'waiting');
    qrContainer.classList.toggle('receipt-paid', state === 'paid');
    qrContainer.classList.toggle('receipt-expired', state === 'error');
    if (state === 'paid') {
        clearExpireTimer();
        offerSdk?.Stop();
        offerSdk = null;
        resultHeader.textContent = 'Paid';
    }
}

function clearInvoice(): void {
    copyInvoiceButton.hidden = true;
    copyInvoiceButton.textContent = 'Copy invoice';
    qrPayLink.removeAttribute('href');
    qrPayLink.classList.remove('is-live');
}

function showInvoice(bolt11: string): void {
    resultData.textContent = bolt11;
    copyInvoiceButton.hidden = false;
    qrPayLink.href = `lightning:${bolt11.toLowerCase()}`;
    qrPayLink.classList.add('is-live');
    qrCanvas.style.display = 'block';
    QRCode.toCanvas(qrCanvas, bolt11.toUpperCase(), { width: 256, margin: 1 });
    watchInvoiceExpiry(bolt11);
}

async function copyInvoice(): Promise<void> {
    const invoice = resultData.textContent?.trim() ?? '';
    if (!invoice.toLowerCase().startsWith('ln')) {
        return;
    }
    await navigator.clipboard.writeText(invoice);
    copyInvoiceButton.textContent = 'Copied';
    window.setTimeout(() => {
        copyInvoiceButton.textContent = 'Copy invoice';
    }, 1500);
}

function resetUI(): void {
    stopOfferSdk();
    resultsSection.style.display = 'none';
    decodeOfferButton.style.display = 'block';
    offerActions.style.display = 'none';
    qrCanvas.style.display = 'none';
    qrPlaceholder.style.display = 'block';
    clearInvoice();
    setReceipt('hidden');
    decodedOffer = null;
    isInvoiceDisplayed = false;
    decodeOfferButton.textContent = 'Decode Offer';
    nofferInput.disabled = false;
}

function decodeOffer(): void {
    const nofferStr = nofferInput.value.trim();
    if (!nofferStr) {
        alert('Please provide an offer string.');
        return;
    }

    resultsSection.style.display = 'block';
    qrPlaceholder.style.display = 'none';
    qrCanvas.style.display = 'none';
    clearInvoice();
    setReceipt('hidden');

    try {
        const decoded = decodeBech32(nofferStr);
        if (decoded.type !== 'noffer') {
            throw new Error("Invalid string: expected a 'noffer'.");
        }
        decodedOffer = decoded.data;
        resultHeader.textContent = 'Decoded Offer';
        resultData.textContent = JSON.stringify(decodedOffer, null, 2);
        decodeOfferButton.style.display = 'none';
        offerActions.style.display = 'block';
    } catch (error) {
        resultHeader.textContent = 'Error';
        resultData.textContent = errorMessage(error);
        decodeOfferButton.style.display = 'block';
        offerActions.style.display = 'none';
        qrPlaceholder.style.display = 'block';
    }
    setTimeout(() => resultsSection.scrollIntoView({ behavior: 'smooth', block: 'center' }), 100);
}

async function handleGetInvoice(): Promise<void> {
    if (!decodedOffer) {
        alert('Offer data is missing. Please decode a new offer first.');
        return;
    }

    stopOfferSdk();
    nofferInput.disabled = true;
    offerActions.style.display = 'none';
    resultHeader.textContent = 'Invoice';
    resultData.textContent = 'Requesting invoice...';
    clearInvoice();
    setReceipt('hidden');

    try {
        const amountSats = amountInput.value ? parseInt(amountInput.value, 10) : undefined;
        offerSdk = sdkFromPointer(decodedOffer.pubkey, decodedOffer.relay);
        const response = await offerSdk.Noffer(
            { offer: decodedOffer.offer, amount_sats: amountSats },
            (receipt) => {
                if (receipt.res === 'ok') {
                    setReceipt('paid', 'Paid');
                }
            },
        );

        if ('bolt11' in response && typeof response.bolt11 === 'string') {
            setReceipt('waiting', 'Awaiting payment');
            showInvoice(response.bolt11);
        } else {
            stopOfferSdk();
            resultHeader.textContent = 'Error Response';
            resultData.textContent = JSON.stringify(response, null, 2);
        }
    } catch (error) {
        stopOfferSdk();
        resultHeader.textContent = 'Error';
        resultData.textContent = errorMessage(error);
    } finally {
        isInvoiceDisplayed = true;
        decodeOfferButton.textContent = 'Reset';
        decodeOfferButton.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}

function handleDecodeOrReset(): void {
    if (isInvoiceDisplayed) {
        nofferInput.value = DEFAULT_NOFFER;
        resetUI();
        return;
    }
    let nofferStr = nofferInput.value.trim();
    if (!nofferStr && nofferInput.placeholder) {
        nofferStr = nofferInput.placeholder.trim();
        nofferInput.value = nofferStr;
    }
    decodeOffer();
}

async function checkLightningAddress(): Promise<void> {
    let addr = lnAddressInput.value.trim();
    if (!addr && lnAddressInput.placeholder) {
        addr = lnAddressInput.placeholder.trim();
        lnAddressInput.value = addr;
    }
    if (!addr || !addr.includes('@')) {
        alert('Please enter a valid Lightning address (e.g., alice@example.com)');
        return;
    }

    const [name, domain] = addr.split('@');
    const url = `https://${domain}/.well-known/nostr.json?name=${encodeURIComponent(name)}`;
    addressResultHeader.textContent = 'Checking…';
    addressResultData.textContent = `GET ${url}`;
    addressResultSection.style.display = 'block';

    try {
        const resp = await fetch(url, { headers: { Accept: 'application/json' } });
        if (!resp.ok) {
            throw new Error(`HTTP ${resp.status}`);
        }
        const data = await resp.json();
        let offer: string | null = null;
        if (typeof data.clink_offer === 'string') {
            offer = data.clink_offer;
        } else if (data.clink_offer && typeof data.clink_offer === 'object') {
            offer = data.clink_offer[name] ?? null;
        }
        if (offer) {
            addressResultHeader.textContent = 'CLINK Enabled';
            nofferInput.value = offer;
            decodeOffer();
        } else {
            addressResultHeader.textContent = 'No CLINK Offer Found';
        }
        addressResultData.textContent = JSON.stringify(data, null, 2);
    } catch (error) {
        addressResultHeader.textContent = 'Error';
        addressResultData.textContent = errorMessage(error);
    }
    setTimeout(() => addressResultSection.scrollIntoView({ behavior: 'smooth', block: 'center' }), 100);
}

decodeOfferButton.addEventListener('click', handleDecodeOrReset);
getInvoiceButton.addEventListener('click', handleGetInvoice);
copyInvoiceButton.addEventListener('click', () => {
    void copyInvoice();
});
nofferInput.addEventListener('input', resetUI);
checkAddressButton.addEventListener('click', checkLightningAddress);

nofferInput.value = DEFAULT_NOFFER;
resetUI();
displayClientIdentity(clientIdentityDiv, clientNpubSpan);
