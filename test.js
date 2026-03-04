#!/usr/bin/env node
'use strict';

/**
 * Integration test for acme-dns-01-netcup using acme-dns-01-test.
 *
 * Requires real Netcup API credentials and a domain you control.
 *
 * Usage:
 *   NETCUP_CUSTOMER_NUMBER=12345 \
 *   NETCUP_API_KEY=your-api-key \
 *   NETCUP_API_PASSWORD=your-api-password \
 *   ZONE=example.com \
 *   npm test
 *
 * Or with a .env file — just set the variables above before running.
 */

var tester = require('acme-dns-01-test');
var netcup = require('./dist/index.js');

// Read credentials from environment
var customerNumber = process.env.NETCUP_CUSTOMER_NUMBER;
var apiKey = process.env.NETCUP_API_KEY;
var apiPassword = process.env.NETCUP_API_PASSWORD;
var zone = process.env.ZONE;

if (!customerNumber || !apiKey || !apiPassword || !zone) {
    console.error('Missing required environment variables.');
    console.error('');
    console.error('Please set:');
    console.error('  NETCUP_CUSTOMER_NUMBER  - Your Netcup customer number (Kundennummer)');
    console.error('  NETCUP_API_KEY          - API key from CCP → Master Data → API');
    console.error('  NETCUP_API_PASSWORD     - API password from CCP → Master Data → API');
    console.error('  ZONE                    - A domain zone you control (e.g. example.com)');
    console.error('');
    console.error('Example:');
    console.error('  NETCUP_CUSTOMER_NUMBER=12345 NETCUP_API_KEY=abc NETCUP_API_PASSWORD=xyz ZONE=example.com npm test');
    process.exit(1);
}

console.log('');
console.log('=== acme-dns-01-netcup integration test ===');
console.log('Zone:     ' + zone);
console.log('Customer: ' + customerNumber);
console.log('');
console.log('This test will:');
console.log('  1. Call init()');
console.log('  2. Call zones() and verify your zone is listed');
console.log('  3. Create TXT records via set() for: ' + zone + ', foo.' + zone + ', *.foo.' + zone);
console.log('  4. Verify records via get()');
console.log('  5. Remove records via remove() and verify deletion');
console.log('');
console.log('This may take several minutes due to DNS propagation...');
console.log('');

// Create the challenger plugin with real credentials
var challenger;
if (netcup.default) {
    challenger = netcup.default.create({
        customerNumber: customerNumber,
        apiKey: apiKey,
        apiPassword: apiPassword,
        verifyPropagation: true,
        verbose: true
    });
} else {
    challenger = netcup.create({
        customerNumber: customerNumber,
        apiKey: apiKey,
        apiPassword: apiPassword,
        verifyPropagation: true,
        verbose: true
    });
}

// Run the official test suite
tester
    .testZone('dns-01', zone, challenger)
    .then(function () {
        console.log('');
        console.log('============================================');
        console.log('  PASS - All acme-dns-01-test checks passed');
        console.log('============================================');
        console.log('');
        process.exit(0);
    })
    .catch(function (err) {
        console.error('');
        console.error('============================================');
        console.error('  FAIL - Test did not pass');
        console.error('============================================');
        console.error('');
        console.error(err.message || err);
        console.error('');
        process.exit(1);
    });
