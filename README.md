acme-dns-01-netcup
==================

[Netcup](https://www.netcup.de/) DNS + Let's Encrypt. This module handles ACME dns-01 challenges, compatible with [ACME.js](https://www.npmjs.com/package/acme) and [Greenlock.js](https://www.npmjs.com/package/greenlock).

It passes [acme-dns-01-test](https://github.com/therootcompany/acme-dns-01-test).

## Features

- Full [Netcup CCP DNS API](https://www.netcup-wiki.de/wiki/CCP_API) integration
- **Built-in propagation verification** — `set()` polls authoritative nameservers and public resolvers (1.1.1.1 / 8.8.8.8) before returning
- Automatic zone detection (walks from most-specific to least-specific)
- Cleans up stale TXT records from previous runs on `remove()`
- Supports wildcard certificates (dns-01 is required for `*.example.com`)
- Zero external dependencies (uses Node.js built-in `fetch` and `dns`)

## Install

```bash
npm install acme-dns-01-netcup
```

Requires Node.js 18+.

## Netcup API Credentials

You need three values from the [Netcup Customer Control Panel (CCP)](https://www.customercontrolpanel.de/):

1. **Customer Number** (Kundennummer) — your Netcup account number
2. **API Key** — create one under *Master Data → API*
3. **API Password** — set one under *Master Data → API*

## Usage

```js
const acmeDnsNetcup = require('acme-dns-01-netcup');

const challenge = acmeDnsNetcup.create({
    customerNumber: '12345',
    apiKey: 'your-api-key',
    apiPassword: 'your-api-password',
    verifyPropagation: true,  // default: true (recommended)
    verbose: true             // log progress to console
});
```

### ACME.js

```js
const ACME = require('acme');
const Keypairs = require('@root/keypairs');
const CSR = require('@root/csr');
const PEM = require('@root/pem');

const acme = ACME.create({
    maintainerEmail: 'you@example.com',
    packageAgent: 'my-app/1.0.0',
    notify: (ev, msg) => console.log(ev, msg)
});

await acme.init('https://acme-v02.api.letsencrypt.org/directory');

// ... create account, generate keypair, CSR ...

const pems = await acme.certificates.create({
    account,
    accountKey,
    csr,
    domains: ['example.com', '*.example.com'],
    challenges: {
        'dns-01': challenge
    }
});
```

### Greenlock.js

```js
const Greenlock = require('greenlock');

const greenlock = Greenlock.create({
    packageAgent: 'my-app/1.0.0',
    configDir: './greenlock.d',
    maintainerEmail: 'you@example.com'
});

greenlock.manager.defaults({
    agreeToTerms: true,
    subscriberEmail: 'you@example.com',
    challenges: {
        'dns-01': challenge
    }
});

await greenlock.add({
    subject: 'example.com',
    altnames: ['example.com', '*.example.com']
});
```

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `customerNumber` | `string \| number` | *required* | Netcup customer number |
| `apiKey` | `string` | *required* | Netcup API key |
| `apiPassword` | `string` | *required* | Netcup API password |
| `verifyPropagation` | `boolean` | `true` | Wait for DNS propagation in `set()` before returning |
| `verbose` | `boolean` | `false` | Log debug information to console |
| `waitFor` | `number` | `10000` | Interval (ms) between DNS polling attempts |
| `retries` | `number` | `120` | Max retries for authoritative NS polling (~20 min) |
| `publicRetries` | `number` | `60` | Max retries for public resolver polling (~10 min) |
| `propagationDelay` | `number` | `120000` | Delay (ms) for acme.js (only when `verifyPropagation` is false) |

## Why does `set()` take so long?

Netcup uses a serialised DNS zone update queue. A single update typically takes 5–10 minutes to propagate. If a previous `remove()` and new `set()` happen close together, the queue can take 10–20 minutes.

When `verifyPropagation` is enabled (default), `set()` polls the authoritative nameservers every 10 seconds (up to 20 minutes), then verifies on public resolvers (1.1.1.1 / 8.8.8.8) for up to 10 additional minutes. This ensures Let's Encrypt validators see the record on the first attempt.

If you disable `verifyPropagation`, you must set a sufficiently large `propagationDelay` to account for Netcup's queue (at least 120 seconds, but more may be needed).

## License

MIT
