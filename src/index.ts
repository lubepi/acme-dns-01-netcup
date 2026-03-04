'use strict';

import { Resolver } from 'node:dns/promises';

// Public DNS resolvers for propagation verification.
const publicResolver = new Resolver();
publicResolver.setServers(['1.1.1.1', '8.8.8.8']);

// System resolver — uses whatever /etc/resolv.conf (or OS equivalent) provides.
// ACME clients (acme.js, greenlock.js) use require('dns').resolveTxt internally
// for their own challenge pre-flight checks, which hits this same system resolver.
// By also verifying propagation here, we ensure the record is visible to the
// ACME client's own verification before set() returns.
const systemResolver = new Resolver();

const API_ENDPOINT = 'https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface NetcupOptions {
    /** Netcup customer number (Kundennummer) */
    customerNumber: string | number;
    /** Netcup API key (from CCP → Master Data → API) */
    apiKey: string;
    /** Netcup API password (from CCP → Master Data → API) */
    apiPassword: string;
    /**
     * Verify that the TXT record has propagated before returning from set().
     * When true, propagationDelay is set to 0 as propagation is handled internally.
     * Default: true
     */
    verifyPropagation?: boolean;
    /** Log propagation delays and other debug information. Default: false */
    verbose?: boolean;
    /** Interval (ms) between DNS polling attempts. Default: 10_000 (10 s). */
    waitFor?: number;
    /**
     * Maximum number of retries for authoritative NS polling.
     * Default: 120 (= ~20 min with default waitFor).
     */
    retries?: number;
    /**
     * Maximum number of retries for public resolver polling.
     * Default: 60 (= ~10 min with default waitFor).
     */
    publicRetries?: number;
    /**
     * Propagation delay (ms) passed to acme.js.
     * Only used when verifyPropagation is false.
     * Default: 120_000 (2 min).
     */
    propagationDelay?: number;
}

interface DnsRecord {
    id?: string;
    hostname: string;
    type: string;
    destination: string;
    deleterecord?: boolean;
    [key: string]: unknown;
}

interface Challenge {
    dnsHost: string;
    dnsPrefix: string;
    dnsZone: string;
    dnsAuthorization: string;
}

interface ChallengeData {
    challenge: Challenge;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function log(verbose: boolean, ...args: unknown[]): void {
    if (verbose) {
        console.log('[acme-dns-01-netcup]', ...args);
    }
}

/**
 * Send a JSON request to the Netcup CCP API.
 */
async function apiCall(action: string, param: Record<string, unknown>, throwOnError = true): Promise<any> {
    const body = JSON.stringify({ action, param });

    const response = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
    });

    if (!response.ok) {
        throw new Error(`Netcup HTTP error: ${response.status} ${response.statusText}`);
    }

    const rawText = await response.text();
    let json: { statuscode: number; longmessage?: string; shortmessage?: string; responsedata: any };
    try {
        json = JSON.parse(rawText);
    } catch {
        throw new Error(`Netcup API returned non-JSON response: ${rawText.slice(0, 200)}`);
    }

    // Netcup uses 2xxx for success (2000 = OK, 2011 = object created/updated, etc.)
    const isSuccess = json.statuscode >= 2000 && json.statuscode < 3000;

    if (!isSuccess && throwOnError) {
        throw new Error(
            `Netcup API error [${json.statuscode}]: ${json.longmessage ?? json.shortmessage ?? 'unknown error'}`,
        );
    }

    return isSuccess ? json.responsedata : null;
}

/** Login and return the apisessionid. */
async function login(customerNumber: string | number, apiKey: string, apiPassword: string): Promise<string> {
    const data = await apiCall('login', {
        customernumber: String(customerNumber),
        apikey: apiKey,
        apipassword: apiPassword,
    });
    return data.apisessionid as string;
}

/** Logout. Errors are swallowed intentionally (session may already be expired). */
async function logout(customerNumber: string | number, apiKey: string, apisessionid: string): Promise<void> {
    try {
        await apiCall('logout', {
            customernumber: String(customerNumber),
            apikey: apiKey,
            apisessionid,
        });
    } catch {
        // Ignore logout errors
    }
}

/**
 * Find the correct DNS zone and relative hostname for a given full DNS name.
 * Uses infoDnsZone to probe from most-specific to least-specific, exactly like
 * the official froonix/acme-dns-nc PHP reference implementation.
 *
 * Example: "_acme-challenge.sub.example.de"
 *   → tries "sub.example.de" → not found
 *   → tries "example.de"     → found  ✓
 *   → rootDomain = "example.de", hostname = "_acme-challenge.sub"
 */
async function findZone(
    fullDomain: string,
    customerNumber: string | number,
    apiKey: string,
    apisessionid: string,
    verbose: boolean,
): Promise<{ rootDomain: string; hostname: string }> {
    const parts = fullDomain.split('.');

    for (let i = 1; i < parts.length - 1; i++) {
        const candidate = parts.slice(i).join('.');
        const result = await apiCall(
            'infoDnsZone',
            {
                customernumber: String(customerNumber),
                apikey: apiKey,
                apisessionid,
                domainname: candidate,
            },
            false,
        );

        if (result !== null && typeof result === 'object' && result.name) {
            const hostname = parts.slice(0, i).join('.') || '@';
            log(verbose, `findZone: "${fullDomain}" → zone="${candidate}", hostname="${hostname}"`);
            return { rootDomain: candidate, hostname };
        }
    }

    // Fall back to last-two-labels heuristic
    const rootDomain = parts.slice(-2).join('.');
    const hostname = parts.slice(0, -2).join('.') || '@';
    console.warn(
        `[acme-dns-01-netcup] findZone: no zone found via API for "${fullDomain}", using fallback zone="${rootDomain}", hostname="${hostname}"`,
    );
    return { rootDomain, hostname };
}

// ---------------------------------------------------------------------------
// DNS propagation verification
// ---------------------------------------------------------------------------

/**
 * Build a Resolver pointing at the zone's authoritative nameservers.
 * Falls back to public resolvers if NS lookup fails.
 */
async function getAuthoritativeResolver(zone: string, verbose: boolean): Promise<Resolver> {
    try {
        const nsNames = await publicResolver.resolveNs(zone);
        const nsIps: string[] = [];
        for (const ns of nsNames.slice(0, 3)) {
            try {
                const addrs = await publicResolver.resolve4(ns);
                nsIps.push(...addrs.map((ip: string) => `${ip}:53`));
            } catch {
                /* skip */
            }
        }
        if (nsIps.length > 0) {
            const resolver = new Resolver();
            resolver.setServers(nsIps);
            log(verbose, `using authoritative NS for ${zone}: ${nsIps.join(', ')}`);
            return resolver;
        }
        log(verbose, `NS lookup empty for ${zone}, falling back to public resolvers`);
    } catch {
        log(verbose, `NS lookup failed for ${zone}, falling back to public resolvers`);
    }
    return publicResolver;
}

function delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Poll a resolver until the expected TXT value is visible.
 */
async function pollTxtRecord(
    resolver: Resolver,
    dnsHost: string,
    expectedValue: string,
    maxAttempts: number,
    retryDelayMs: number,
    label: string,
    verbose: boolean,
): Promise<boolean> {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            const records = await resolver.resolveTxt(dnsHost);
            if (records.flat().includes(expectedValue)) {
                log(verbose, `${label}: TXT record verified after attempt ${attempt}/${maxAttempts}`);
                return true;
            }
            log(
                verbose,
                `${label}: attempt ${attempt}/${maxAttempts}: ${
                    records.length > 0
                        ? `found ${records.length} TXT record(s) but not the expected value`
                        : 'no TXT records yet'
                }, retrying in ${retryDelayMs / 1000}s...`,
            );
        } catch {
            log(
                verbose,
                `${label}: attempt ${attempt}/${maxAttempts}: NXDOMAIN, retrying in ${retryDelayMs / 1000}s...`,
            );
        }
        await delay(retryDelayMs);
    }
    return false;
}

/**
 * Verify that the TXT record is visible on authoritative, public, and system resolvers.
 *
 * Steps:
 *  1. Poll the zone's authoritative nameservers (required — throws on failure).
 *  2. Poll public resolvers (1.1.1.1/8.8.8.8)  — non-fatal timeout.
 *  3. Poll the OS system resolver (/etc/resolv.conf) — non-fatal timeout.
 *
 * Step 3 ensures that ACME clients (acme.js, greenlock.js) whose own DNS
 * pre-flight check uses require('dns').resolveTxt (= system resolver) will
 * also see the record by the time set() returns.
 */
async function verifyPropagationFn(
    challenge: Challenge,
    verbose: boolean,
    waitFor: number,
    retries: number,
    publicRetries: number,
): Promise<void> {
    const { dnsHost, dnsAuthorization } = challenge;
    const zone = dnsHost.split('.').slice(-2).join('.');

    // Wait one tick before first query to avoid cache pollution
    await delay(waitFor);

    // Step 1: Poll authoritative NS
    const authResolver = await getAuthoritativeResolver(zone, verbose);
    log(
        verbose,
        `polling authoritative NS for ${dnsHost} (every ${waitFor / 1000}s, max ${retries} attempts)...`,
    );

    const authOk = await pollTxtRecord(
        authResolver,
        dnsHost,
        dnsAuthorization,
        retries,
        waitFor,
        'authoritative NS',
        verbose,
    );

    if (!authOk) {
        throw new Error(
            `[acme-dns-01-netcup] TXT record not visible on authoritative NS for ${dnsHost} after ${retries} attempts`,
        );
    }

    // Step 2: Poll public resolvers (LE validators use recursive resolvers that
    // may have cached a negative NXDOMAIN response from earlier)
    log(verbose, `${dnsHost} visible on authoritative NS — verifying on public resolvers...`);

    const publicOk = await pollTxtRecord(
        publicResolver,
        dnsHost,
        dnsAuthorization,
        publicRetries,
        waitFor,
        'public resolver',
        verbose,
    );

    if (publicOk) {
        log(verbose, `TXT record verified on public resolvers for ${dnsHost}`);
    } else {
        // Not fatal — authoritative NS has it, LE might still succeed.
        console.warn(
            `[acme-dns-01-netcup] public resolver timeout for ${dnsHost} — proceeding anyway (authoritative NS has the record)`,
        );
    }

    // Step 3: Poll system resolver.
    // ACME clients (acme.js, greenlock.js) use require('dns').resolveTxt
    // internally for their own challenge pre-flight checks, which hits the
    // OS system resolver (/etc/resolv.conf).  By verifying propagation here
    // we prevent the ACME client's own DNS check from failing with ENOTFOUND
    // after set() returns.
    log(verbose, `verifying on system resolver for ${dnsHost}...`);

    const systemOk = await pollTxtRecord(
        systemResolver,
        dnsHost,
        dnsAuthorization,
        publicRetries,
        waitFor,
        'system resolver',
        verbose,
    );

    if (systemOk) {
        log(verbose, `TXT record verified on system resolver for ${dnsHost}`);
    } else {
        // Not fatal — authoritative NS has it, LE validators don't use our
        // system resolver.  But the ACME library's own pre-flight check may
        // still fail.  Log a warning so users can diagnose the issue.
        console.warn(
            `[acme-dns-01-netcup] system resolver timeout for ${dnsHost} — the ACME library's own DNS pre-flight check may fail`,
        );
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Create an acme-dns-01-netcup challenge handler.
 *
 * Compatible with ACME.js, Greenlock.js, and any ACME client that uses the
 * standard dns-01 challenge plugin interface (init, zones, set, get, remove).
 *
 * When `verifyPropagation` is true (default), `set()` blocks until the TXT
 * record is visible on authoritative nameservers, public resolvers
 * (1.1.1.1/8.8.8.8), and the OS system resolver.  This ensures compatibility
 * with ACME clients that run their own DNS pre-flight checks using the system
 * resolver (acme.js, greenlock.js).  Strongly recommended for Netcup because
 * their DNS zone update queue can take 5–20 minutes.
 *
 * Required options:
 *   - customerNumber: Netcup customer number (Kundennummer)
 *   - apiKey:         Netcup API key (from CCP → Master Data → API)
 *   - apiPassword:    Netcup API password (from CCP → Master Data → API)
 */
export function create(options: NetcupOptions) {
    const { customerNumber, apiKey, apiPassword } = options;
    const verbose = options.verbose ?? false;
    const doVerify = options.verifyPropagation ?? true;
    const waitFor = options.waitFor ?? 10_000;
    const retries = options.retries ?? 120;
    const publicRetries = options.publicRetries ?? 60;

    if (!customerNumber || !apiKey || !apiPassword) {
        throw new Error('acme-dns-01-netcup: customerNumber, apiKey, and apiPassword are all required');
    }

    log(verbose, `create() called for customerNumber="${customerNumber}"`);

    return {
        module: 'acme-dns-01-netcup',

        /**
         * Propagation delay for acme.js / greenlock.js.
         * When verifyPropagation is true (default), set() handles waiting internally
         * so this is 0. Otherwise, the configured delay is passed through.
         */
        propagationDelay: doVerify ? 0 : (options.propagationDelay ?? 120_000),

        /**
         * Signal to ACME clients (acme.js, greenlock.js) that this plugin
         * verifies DNS propagation internally in set().  The ACME library's
         * own pre-flight DNS check (which uses the OS system resolver via
         * require('dns').resolveTxt) is redundant and may fail on systems
         * with aggressive negative-response caching (e.g. local routers).
         *
         * When true the ACME client should set its own `skipChallengeTest`
         * flag so the dry-run set()/remove() cycle still runs (validating
         * API credentials) but the queryTxt verification is skipped.
         */
        skipChallengeTest: doVerify,

        init(): Promise<null> {
            return Promise.resolve(null);
        },

        /**
         * Return DNS zones for the requested domains.
         * The ACME library passes { challenge: { dnsHosts: [...] } }.
         * We log into the Netcup API and resolve each host to its zone.
         */
        async zones(args: { challenge?: { dnsHosts?: string[] } } = {}): Promise<string[]> {
            const dnsHosts = args?.challenge?.dnsHosts ?? [];
            log(verbose, `zones() called with dnsHosts: ${JSON.stringify(dnsHosts)}`);

            if (dnsHosts.length === 0) {
                log(verbose, 'zones(): no dnsHosts provided, returning []');
                return [];
            }

            let apisessionid: string;
            try {
                apisessionid = await login(customerNumber, apiKey, apiPassword);
            } catch (err) {
                console.error(`[acme-dns-01-netcup] zones(): login failed: ${err}`);
                return [];
            }

            try {
                const zoneSet = new Set<string>();
                for (const host of dnsHosts) {
                    try {
                        const { rootDomain } = await findZone(host, customerNumber, apiKey, apisessionid, verbose);
                        zoneSet.add(rootDomain);
                    } catch {
                        log(verbose, `zones(): could not resolve zone for "${host}"`);
                    }
                }
                const zones = [...zoneSet];
                log(verbose, `zones(): resolved zones: ${JSON.stringify(zones)}`);
                return zones;
            } finally {
                try {
                    await logout(customerNumber, apiKey, apisessionid);
                } catch { /* ignore */ }
            }
        },

        async set(data: ChallengeData): Promise<null> {
            const { dnsHost, dnsAuthorization } = data.challenge;
            log(verbose, `set: dnsHost="${dnsHost}"`);

            // Create the TXT record via Netcup API
            let apisessionid: string;
            try {
                apisessionid = await login(customerNumber, apiKey, apiPassword);
            } catch (err) {
                console.error(`[acme-dns-01-netcup] set: login failed: ${err}`);
                throw err;
            }
            try {
                const { rootDomain, hostname } = await findZone(dnsHost, customerNumber, apiKey, apisessionid, verbose);
                log(verbose, `set: creating TXT hostname="${hostname}" in zone="${rootDomain}"`);

                const setResult = await apiCall('updateDnsRecords', {
                    customernumber: String(customerNumber),
                    apikey: apiKey,
                    apisessionid,
                    domainname: rootDomain,
                    dnsrecordset: {
                        dnsrecords: [
                            {
                                hostname,
                                type: 'TXT',
                                destination: dnsAuthorization,
                                deleterecord: false,
                            } satisfies DnsRecord,
                        ],
                    },
                });
                const createdCount =
                    setResult?.dnsrecords?.filter((r: DnsRecord) => r.type === 'TXT' && r.hostname === hostname)
                        .length ?? 0;
                log(
                    verbose,
                    `set: updateDnsRecords OK (${createdCount} TXT record(s) for "${hostname}", ${setResult?.dnsrecords?.length ?? 0} total records in zone)`,
                );
            } finally {
                await logout(customerNumber, apiKey, apisessionid!);
            }

            // Verify propagation if enabled
            if (doVerify) {
                await verifyPropagationFn(data.challenge, verbose, waitFor, retries, publicRetries);
            }

            return null;
        },

        async get(data: ChallengeData): Promise<{ dnsAuthorization: string } | null> {
            const { dnsHost, dnsAuthorization } = data.challenge;
            log(verbose, `get: checking dnsHost="${dnsHost}"`);
            try {
                const results = await publicResolver.resolveTxt(dnsHost);
                const found = results.flat().includes(dnsAuthorization);
                log(verbose, `get: found=${found}`);
                return found ? { dnsAuthorization } : null;
            } catch (err: any) {
                log(verbose, `get: DNS lookup failed: ${err.code ?? err.message}`);
                return null;
            }
        },

        async remove(data: ChallengeData): Promise<null> {
            const { dnsHost } = data.challenge;
            log(verbose, `remove: dnsHost="${dnsHost}"`);

            const apisessionid = await login(customerNumber, apiKey, apiPassword);
            try {
                const { rootDomain, hostname } = await findZone(dnsHost, customerNumber, apiKey, apisessionid, verbose);
                const recordsData = await apiCall(
                    'infoDnsRecords',
                    {
                        customernumber: String(customerNumber),
                        apikey: apiKey,
                        apisessionid,
                        domainname: rootDomain,
                    },
                    false,
                );

                const records: DnsRecord[] = recordsData?.dnsrecords ?? [];
                // Delete ALL _acme-challenge TXT records for this hostname.
                // Records from previous failed/interrupted runs may have accumulated.
                const toDelete = records
                    .filter(r => r.type === 'TXT' && r.hostname === hostname)
                    .map(r => ({ ...r, deleterecord: true }));

                if (toDelete.length === 0) {
                    log(verbose, `remove: no TXT records found for hostname="${hostname}" in zone="${rootDomain}"`);
                    return null;
                }
                if (toDelete.length > 1) {
                    log(
                        verbose,
                        `remove: deleting ${toDelete.length} TXT records for hostname="${hostname}" (including stale records from previous runs)`,
                    );
                }

                await apiCall('updateDnsRecords', {
                    customernumber: String(customerNumber),
                    apikey: apiKey,
                    apisessionid,
                    domainname: rootDomain,
                    dnsrecordset: { dnsrecords: toDelete },
                });
            } finally {
                await logout(customerNumber, apiKey, apisessionid);
            }
            return null;
        },
    };
}
