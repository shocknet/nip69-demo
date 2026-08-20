import { decodeBech32, newNdebitPaymentRequest, DebitPointer } from '@shocknet/clink-sdk';
import QRCode from 'qrcode';
import './styles.css';
import {
    displayClientIdentity,
    errorMessage,
    requireEl,
    sdkFromPointer,
} from './utils';

const ndebitInput = requireEl<HTMLTextAreaElement>('ndebitInput');
const debitActionButton = requireEl<HTMLButtonElement>('debitActionButton');
const decodedDebitData = requireEl<HTMLPreElement>('decodedDebitData');
const bolt11Input = requireEl<HTMLTextAreaElement>('bolt11Input');
const paymentResult = requireEl<HTMLDivElement>('payment-result');
const paymentData = requireEl<HTMLPreElement>('paymentData');
const qrContainer = requireEl<HTMLDivElement>('debit-qr-container');
const qrCanvas = requireEl<HTMLCanvasElement>('debitQrCanvas');
const decodedDataContainer = requireEl<HTMLDivElement>('decoded-data-container');
const debitActions = requireEl<HTMLDivElement>('debit-actions');
const clientIdentityDiv = requireEl<HTMLDivElement>('client-identity');
const clientNpubSpan = requireEl<HTMLSpanElement>('client-npub');

let decodedDebit: DebitPointer | null = null;
let isPaymentMade = false;

function resetUI(): void {
    decodedDataContainer.style.display = 'block';
    decodedDebitData.textContent = 'Decoded data will appear here...';
    paymentResult.style.display = 'none';
    debitActions.style.display = 'none';
    debitActionButton.textContent = 'Decode Debit';
    ndebitInput.disabled = false;
    bolt11Input.value = '';
    qrContainer.style.display = 'none';
    decodedDebit = null;
    isPaymentMade = false;
}

function handleDecodeDebit(): void {
    const ndebitStr = ndebitInput.value.trim();
    if (!ndebitStr) {
        alert('Please provide a debit string.');
        return;
    }
    try {
        const decoded = decodeBech32(ndebitStr);
        if (decoded.type !== 'ndebit') {
            throw new Error("Invalid string: expected an 'ndebit'.");
        }
        decodedDebit = decoded.data;
        decodedDebitData.textContent = JSON.stringify(decodedDebit, null, 2);
        debitActions.style.display = 'block';
        debitActionButton.textContent = 'Pay Invoice';
        ndebitInput.disabled = true;
    } catch (error) {
        decodedDebitData.textContent = `Error: ${errorMessage(error)}`;
    }
}

async function handlePayInvoice(): Promise<void> {
    const bolt11 = bolt11Input.value.trim();
    if (!decodedDebit) {
        alert('Debit data is missing. Please decode a new debit string.');
        return;
    }
    if (!bolt11) {
        alert('Please provide a bolt11 invoice to pay.');
        return;
    }

    paymentResult.style.display = 'block';
    paymentData.textContent = 'Sending payment...';
    decodedDataContainer.style.display = 'none';

    const sdk = sdkFromPointer(decodedDebit.pubkey, decodedDebit.relay);
    try {
        const paymentRequest = newNdebitPaymentRequest(
            bolt11,
            undefined,
            decodedDebit.pointer,
            decodedDebit.k1,
        );
        const response = await sdk.Ndebit(paymentRequest);
        paymentData.textContent = JSON.stringify(response, null, 2);
    } catch (error) {
        paymentData.textContent = `Error: ${errorMessage(error)}`;
    } finally {
        sdk.Stop();
        isPaymentMade = true;
        debitActionButton.textContent = 'Reset';
    }
}

function handleDebitAction(): void {
    if (isPaymentMade) {
        ndebitInput.value = '';
        resetUI();
        return;
    }
    if (decodedDebit) {
        handlePayInvoice();
        return;
    }
    handleDecodeDebit();
}

function handleInvoiceInput(): void {
    const bolt11 = bolt11Input.value.trim();
    if (bolt11) {
        qrContainer.style.display = 'block';
        QRCode.toCanvas(qrCanvas, bolt11.toUpperCase(), { width: 256, margin: 1 });
        return;
    }
    qrContainer.style.display = 'none';
}

debitActionButton.addEventListener('click', handleDebitAction);
ndebitInput.addEventListener('input', resetUI);
bolt11Input.addEventListener('input', handleInvoiceInput);

resetUI();
displayClientIdentity(clientIdentityDiv, clientNpubSpan);
