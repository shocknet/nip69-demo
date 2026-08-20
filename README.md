# CLINK Demo Client

A minimal web demo built with [`@shocknet/clink-sdk`](https://github.com/shocknet/ClinkSDK). Source is meant to be copied: it uses the `ClinkSDK` class (`Noffer`, `Ndebit`), not the low-level send helpers.

Live pages:

1. **Offers (`noffer`)** – request a BOLT-11 over Nostr; optional payment receipt callback.
2. **Debits (`ndebit`)** – ask a node to pay a BOLT-11.

Enroll, Beacon, and Manage stay in the [SDK](https://github.com/shocknet/ClinkSDK) and [`clinkctl`](https://github.com/shocknet/clinkctl) examples, plus the [specs](https://clinkme.dev/specs.html).

---

## Running locally

```bash
# in the clink-demo directory
npm install      # first time only
npm start        # opens http://localhost:8787
```

Build a static bundle:

```bash
npm run build    # output in dist/
```

---

## How to use

### Generate an invoice from an Offer

On `offers.html`, decode a `noffer` and click **Get Invoice**. `sdk.Noffer(request, onReceipt)` keeps the relay subscription open until the invoice is paid.

### Pay an invoice with a Debit

On `debit.html`, decode an `ndebit` and paste a BOLT-11. The SDK sends `sdk.Ndebit(...)` and shows the preimage or error.

---

## Project layout

```
clink-demo
│
├── src/
│   ├── offers.ts      # Offer request + payment receipt
│   ├── debit.ts       # Debit payment
│   ├── utils.ts       # persisted client key, SDK factory
│   └── styles.css
├── dist/              # Compiled output
├── webpack.config.js
└── tsconfig.json
```

---

## Contributing

PRs and issues welcome. Protocol discussions live in the main [CLINK repository](https://github.com/shocknet/clink).

---

## License

MIT

## Links

- [CLINK Specification](https://github.com/shocknet/clink)
- [CLINK SDK](https://github.com/shocknet/ClinkSDK)
- [clinkctl](https://github.com/shocknet/clinkctl)
- [CLINK Enabled Node](https://github.com/shocknet/Lightning.Pub)
- [CLINK Enabled Wallet](https://shockwallet.app)
