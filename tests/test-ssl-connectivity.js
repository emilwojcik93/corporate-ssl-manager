#!/usr/bin/env node
/**
 * SSL Connectivity Test Script for Corporate Environments
 * Tests HTTPS connectivity with proper SSL certificate validation
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

// Default test domains
const DEFAULT_DOMAINS = [
    'https://google.com',
    'https://github.com',
    'https://microsoft.com',
    'https://stackoverflow.com',
    'https://www.npmjs.com',
    'https://registry.npmjs.org'
];

// Configuration
const CONFIG = {
    timeout: 10000,
    userAgent: 'SSL-Test-Script/1.0'
};

/**
 * Test SSL connectivity to a single domain
 */
function testDomain(url, options = {}) {
    return new Promise((resolve) => {
        const startTime = Date.now();
        console.log(`Testing: ${url}`);
        
        const requestOptions = {
            timeout: options.timeout || CONFIG.timeout,
            headers: {
                'User-Agent': CONFIG.userAgent
            },
            rejectUnauthorized: options.rejectUnauthorized !== false
        };
        
        const req = https.get(url, requestOptions, (res) => {
            const duration = Date.now() - startTime;
            
            // Read response to complete the request
            res.on('data', () => {});
            res.on('end', () => {
                resolve({
                    url,
                    success: true,
                    statusCode: res.statusCode,
                    duration,
                    error: null
                });
            });
        });
        
        req.on('error', (error) => {
            const duration = Date.now() - startTime;
            resolve({
                url,
                success: false,
                statusCode: 0,
                duration,
                error: error.message
            });
        });
        
        req.on('timeout', () => {
            req.destroy();
            const duration = Date.now() - startTime;
            resolve({
                url,
                success: false,
                statusCode: 0,
                duration,
                error: 'Request timeout'
            });
        });
    });
}

/**
 * Test multiple domains
 */
async function testDomains(domains, options = {}) {
    const results = [];
    
    for (const domain of domains) {
        const result = await testDomain(domain, options);
        results.push(result);
        
        // Print immediate result
        if (result.success) {
            console.log(`  OK ${result.url} - HTTP ${result.statusCode} (${result.duration}ms)`);
        } else {
            console.log(`  FAIL ${result.url} - ${result.error} (${result.duration}ms)`);
        }
    }
    
    return results;
}

/**
 * Print environment information
 */
function printEnvironment() {
    console.log('\n=== Node.js Environment ===');
    console.log(`Node.js Version: ${process.version}`);
    console.log(`Platform: ${process.platform} ${process.arch}`);
    console.log(`NODE_EXTRA_CA_CERTS: ${process.env.NODE_EXTRA_CA_CERTS || 'Not set'}`);
    console.log(`NODE_TLS_REJECT_UNAUTHORIZED: ${process.env.NODE_TLS_REJECT_UNAUTHORIZED || 'Not set'}`);
    console.log(`NODE_NO_WARNINGS: ${process.env.NODE_NO_WARNINGS || 'Not set'}`);
    
    if (process.env.NODE_EXTRA_CA_CERTS) {
        const certPath = process.env.NODE_EXTRA_CA_CERTS;
        if (fs.existsSync(certPath)) {
            const stats = fs.statSync(certPath);
            console.log(`Certificate file exists: ${certPath} (${stats.size} bytes)`);
        } else {
            console.log(`Certificate file not found: ${certPath}`);
        }
    }
    console.log('===============================\n');
}

/**
 * Print test results summary
 */
function printSummary(results, testName = '') {
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    
    console.log(`\n=== ${testName} Results ===`);
    console.log(`Total domains tested: ${results.length}`);
    console.log(`Successful: ${successful.length}`);
    console.log(`Failed: ${failed.length}`);
    console.log(`Success rate: ${Math.round((successful.length / results.length) * 100)}%`);
    
    if (failed.length > 0) {
        console.log('\nFailed domains:');
        failed.forEach(result => {
            console.log(`  FAIL ${result.url}: ${result.error}`);
        });
    }
    
    if (successful.length > 0) {
        const avgDuration = successful.reduce((sum, r) => sum + r.duration, 0) / successful.length;
        console.log(`Average response time: ${Math.round(avgDuration)}ms`);
    }
    
    console.log('===============================\n');
}

/**
 * Test with a specific certificate file
 */
async function testWithCertificate(certPath, domains) {
    if (!fs.existsSync(certPath)) {
        console.log(`Certificate file not found: ${certPath}`);
        return [];
    }
    
    console.log(`\nTesting with certificate: ${path.basename(certPath)}`);
    
    // Temporarily set the certificate for this test
    const originalCert = process.env.NODE_EXTRA_CA_CERTS;
    process.env.NODE_EXTRA_CA_CERTS = certPath;
    
    try {
        const results = await testDomains(domains, { rejectUnauthorized: true });
        return results;
    } finally {
        // Restore original setting
        if (originalCert) {
            process.env.NODE_EXTRA_CA_CERTS = originalCert;
        } else {
            delete process.env.NODE_EXTRA_CA_CERTS;
        }
    }
}

/**
 * Main function
 */
async function main() {
    const args = process.argv.slice(2);
    
    // Parse command line arguments
    let domains = DEFAULT_DOMAINS;
    let certPath = null;
    let skipInsecure = false;
    
    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '--cert':
                certPath = args[++i];
                break;
            case '--domains':
                domains = args[++i].split(',').map(d => d.trim());
                break;
            case '--skip-insecure':
                skipInsecure = true;
                break;
            case '--help':
                console.log('Usage: node test-ssl-connectivity.js [options]');
                console.log('Options:');
                console.log('  --cert <path>        Test with specific certificate file');
                console.log('  --domains <list>     Comma-separated list of domains to test');
                console.log('  --skip-insecure      Skip insecure (reject unauthorized = false) test');
                console.log('  --help               Show this help');
                return;
        }
    }
    
    console.log('SSL Connectivity Test for Corporate Environments');
    console.log('================================================');
    
    printEnvironment();
    
    // Test 1: Current environment
    console.log('Testing with current environment...');
    const currentResults = await testDomains(domains);
    printSummary(currentResults, 'Current Environment');
    
    // Test 2: With specific certificate if provided
    if (certPath) {
        const certResults = await testWithCertificate(certPath, domains);
        printSummary(certResults, `Certificate: ${path.basename(certPath)}`);
    }
    
    // Test 3: Insecure mode (if not skipped)
    if (!skipInsecure) {
        console.log('Testing with TLS rejection disabled (insecure)...');
        const originalReject = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        
        try {
            const insecureResults = await testDomains(domains, { rejectUnauthorized: false });
            printSummary(insecureResults, 'Insecure Mode (TLS rejection disabled)');
        } finally {
            // Restore original setting
            if (originalReject) {
                process.env.NODE_TLS_REJECT_UNAUTHORIZED = originalReject;
            } else {
                delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
            }
        }
    }
    
    // Recommendations
    console.log('Recommendations:');
    const currentSuccess = currentResults.filter(r => r.success).length;
    const totalDomains = domains.length;
    
    if (currentSuccess === totalDomains) {
        console.log('All domains are working correctly with current configuration.');
    } else if (currentSuccess === 0) {
        console.log('No domains are working. Consider:');
        console.log('   - Setting NODE_EXTRA_CA_CERTS to your corporate certificate bundle');
        console.log('   - Checking network connectivity');
        console.log('   - Verifying corporate proxy/firewall settings');
    } else {
        console.log(`Partial connectivity (${currentSuccess}/${totalDomains} domains working).`);
        console.log('   - Some domains may require additional certificates');
        console.log('   - Check if specific domains are blocked by corporate policy');
    }
}

// Run the script
if (require.main === module) {
    main().catch(console.error);
}

module.exports = { testDomain, testDomains, testWithCertificate };
