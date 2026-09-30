/* =========================================================
   Detecção de SO, navegador e engine — v4
   ---------------------------------------------------------
   Mudanças desta versão:
   - getArchFromUA(): arquitetura via UA (não depende de oscpu,
     funciona em file:// e em navegadores sem UA-CH)
   - Windows version: 3 fontes testadas em sequência SEM curto-
     circuito silencioso (UA-CH > UA NT > oscpu)
   - getEnv aceita env só com userAgent, senão usa navigator
   ========================================================= */

import { NA } from "./safe.js";

const EMPTY_ENV = {
    userAgent: "",
    platform: "",
    maxTouchPoints: 0,
    userAgentData: null,
    oscpu: "",
    buildID: "",
    product: "",
    vendor: "",
    languages: [],
    language: "",
    hardwareConcurrency: undefined,
    deviceMemory: undefined
};

function getEnv(env) {
    if (env && typeof env === "object" && typeof env.userAgent === "string" && env.userAgent.length > 0) {
        return env;
    }
    if (typeof navigator !== "undefined" && typeof navigator.userAgent === "string" && navigator.userAgent.length > 0) {
        return navigator;
    }
    return EMPTY_ENV;
}

/* ------------------------------------------------------------------ */
/* Firefox helpers                                                     */
/* ------------------------------------------------------------------ */

export function isFirefoxLike(env) {
    const nav = getEnv(env);
    const ua = String(nav.userAgent || "");
    const product = String(nav.product || "");
    if (product === "Gecko") return true;
    return /Firefox\/|FxiOS\/|Focus\/|FirefoxReality\/|Waterfox\/|PaleMoon\/|Basilisk\/|LibreWolf\/|TorBrowser\//.test(
        ua
    );
}

export function detectFirefoxChannel(env) {
    const nav = getEnv(env);
    const ua = String(nav.userAgent || "");

    if (/FirefoxReality\/([\d.]+)/.test(ua))
        return { channel: "Reality (VR)", version: ua.match(/FirefoxReality\/([\d.]+)/)[1] };
    if (/Focus\/([\d.]+)/.test(ua)) return { channel: "Focus (Android/iOS)", version: ua.match(/Focus\/([\d.]+)/)[1] };
    if (/FxiOS\/([\d.]+)/.test(ua)) return { channel: "iOS (WebKit)", version: ua.match(/FxiOS\/([\d.]+)/)[1] };
    if (/TorBrowser\/([\d.]+)/.test(ua))
        return { channel: "Tor Browser", version: ua.match(/TorBrowser\/([\d.]+)/)[1] };
    if (/LibreWolf\/([\d.]+)/.test(ua))
        return { channel: "LibreWolf (fork)", version: ua.match(/LibreWolf\/([\d.]+)/)[1] };
    if (/Waterfox\/([\d.]+)/.test(ua))
        return { channel: "Waterfox (fork)", version: ua.match(/Waterfox\/([\d.]+)/)[1] };
    if (/PaleMoon\/([\d.]+)/.test(ua))
        return { channel: "Pale Moon (fork)", version: ua.match(/PaleMoon\/([\d.]+)/)[1] };
    if (/Basilisk\/([\d.]+)/.test(ua))
        return { channel: "Basilisk (fork)", version: ua.match(/Basilisk\/([\d.]+)/)[1] };

    const m = ua.match(/Firefox\/([\d.]+)([ab]\d+)?(esr)?/i);
    if (!m) return null;

    const version = m[1];
    const suffix = m[2] || "";
    const esr = m[3] || "";

    let channel = "Release";
    if (esr) channel = "ESR (Extended Support)";
    else if (suffix.startsWith("a1")) channel = "Nightly";
    else if (suffix.startsWith("a2")) channel = "Developer Edition";
    else if (suffix.startsWith("b")) channel = "Beta";

    if (/Android/i.test(ua) && /Mobile|Tablet/i.test(ua)) channel += " — Android";
    return { channel, version };
}

/* ------------------------------------------------------------------ */
/* Arquitetura — três fontes                                           */
/* ------------------------------------------------------------------ */

/**
 * Extrai arquitetura de navigator.userAgent (funciona em qualquer
 * contexto, inclusive file:// e navegadores sem UA-CH).
 */
export function getArchFromUA(ua) {
    if (!ua || typeof ua !== "string") return NA;
    if (/WOW64/i.test(ua)) return "x86_64 (via WOW64)";
    if (/Win64|x64|x86_64/i.test(ua)) return "x86_64 (64-bit)";
    if (/aarch64|arm64/i.test(ua)) return "arm64";
    if (/i686|i386|i486/i.test(ua)) return "x86 (32-bit)";
    if (/armv7l|armv7/i.test(ua)) return "ARM (32-bit)";
    if (/ppc64|PowerPC64/i.test(ua)) return "PowerPC (64-bit)";
    return NA;
}

/**
 * Extrai arquitetura de navigator.oscpu (Firefox).
 */
export function getArchFromOscpu(oscpu) {
    if (!oscpu || typeof oscpu !== "string") return NA;
    if (/aarch64|arm64/i.test(oscpu)) return "arm64";
    if (/x86_64|Win64|x64/i.test(oscpu)) return "x86_64 (64-bit)";
    if (/i686|i386/i.test(oscpu)) return "x86 (32-bit)";
    if (/armv7|armel/i.test(oscpu)) return "ARM (32-bit)";
    if (/PowerPC|ppc/i.test(oscpu)) return "PowerPC";
    if (/Intel/i.test(oscpu)) return "x86_64 (Intel)";
    return NA;
}

/** Combina UA-CH > oscpu > UA. */
export function detectArch(env, high = {}) {
    if (high.architecture) return high.architecture;
    const nav = getEnv(env);
    const fromOscpu = nav.oscpu ? getArchFromOscpu(nav.oscpu) : NA;
    if (fromOscpu !== NA) return fromOscpu;
    return getArchFromUA(nav.userAgent);
}

/** Deriva bitness a partir da string de arquitetura. */
export function deriveBitness(arch) {
    if (!arch || arch === NA) return NA;
    if (/64/.test(arch)) return "64 bits";
    if (/32/.test(arch)) return "32 bits";
    return NA;
}

/* ------------------------------------------------------------------ */
/* Parsing de oscpu                                                    */
/* ------------------------------------------------------------------ */

export function detectOSFromOscpu(oscpu) {
    if (!oscpu || typeof oscpu !== "string") return null;

    if (/Windows NT/i.test(oscpu)) {
        const nt = oscpu.match(/Windows NT ([\d.]+)/)?.[1];
        const map = {
            5.1: "XP",
            5.2: "XP x64",
            "6.0": "Vista",
            6.1: "7",
            6.2: "8",
            6.3: "8.1",
            "10.0": "10 ou 11"
        };
        return { name: "Windows", version: map[nt] || nt || NA, source: "oscpu" };
    }

    if (/Mac OS X/i.test(oscpu)) {
        const m = oscpu.match(/Mac OS X ([\d.]+)/);
        return { name: "macOS", version: m ? m[1] : NA, source: "oscpu" };
    }

    if (/^Linux/i.test(oscpu)) {
        return { name: "Linux", version: NA, arch: oscpu.split(/\s+/)[1] || NA, source: "oscpu" };
    }

    if (/FreeBSD/i.test(oscpu)) return { name: "FreeBSD", version: NA, source: "oscpu" };
    if (/SunOS/i.test(oscpu)) return { name: "Solaris", version: NA, source: "oscpu" };

    return null;
}

/* ------------------------------------------------------------------ */
/* Mapeamentos                                                         */
/* ------------------------------------------------------------------ */

const WINDOWS_MAP = {
    "0.1.0": "7",
    "0.2.0": "8",
    "0.3.0": "8.1",
    "1.0.0": "10",
    "10.0.0": "10",
    "15.0.0": "11"
};

const WINDOWS_NT_MAP = {
    5.1: "XP",
    5.2: "XP x64",
    "6.0": "Vista",
    6.1: "7",
    6.2: "8",
    6.3: "8.1",
    "10.0": "10 ou 11"
};

function mapMacPlatformVersion(pv) {
    if (!pv) return NA;
    const map = {
        "10.15.7": "10.15 (Catalina)",
        "11.0.0": "11 (Big Sur)",
        "12.0.0": "12 (Monterey)",
        "13.0.0": "13 (Ventura)",
        "14.0.0": "14 (Sonoma)",
        "15.0.0": "15 (Sequoia)"
    };
    return map[pv] || pv;
}

function mapMacVersion(v) {
    if (!v) return NA;
    if (v.startsWith("10.15")) return "10.15 (Catalina)";
    if (v.startsWith("11")) return `${v} (Big Sur)`;
    if (v.startsWith("12")) return `${v} (Monterey)`;
    if (v.startsWith("13")) return `${v} (Ventura)`;
    if (v.startsWith("14")) return `${v} (Sonoma)`;
    if (v.startsWith("15")) return `${v} (Sequoia)`;
    return v;
}

const LINUX_DISTROS = [
    ["Ubuntu", /Ubuntu/i],
    ["Fedora", /Fedora/i],
    ["Debian", /Debian/i],
    ["Arch", /Arch/i],
    ["Manjaro", /Manjaro/i],
    ["Mint", /Mint/i],
    ["Gentoo", /Gentoo/i],
    ["openSUSE", /openSUSE|SUSE/i],
    ["Kali", /Kali/i],
    ["Raspbian", /Raspbian/i],
    ["Alpine", /Alpine/i]
];

/* ------------------------------------------------------------------ */
/* detectOS                                                            */
/* ------------------------------------------------------------------ */

export function detectOS(env) {
    const nav = getEnv(env);
    const ua = String(nav.userAgent || "");
    const oscpu = String(nav.oscpu || "");
    const high = nav.userAgentData || {};
    const platform = String(high.platform || nav.platform || "");
    const p = platform.toLowerCase();
    const maxTouch = Number(nav.maxTouchPoints) || 0;

    /* Android */
    if (/android/i.test(ua)) {
        const version = ua.match(/Android\s+([\d.]+)/)?.[1] ?? NA;
        if (/Android TV/i.test(ua)) return { name: "Android TV", version };
        if (/Wear OS|Android Wear/i.test(ua)) return { name: "Wear OS", version };
        return { name: "Android", version };
    }

    /* iOS / iPadOS */
    const isIOS =
        /iPad|iPhone|iPod/.test(ua) ||
        (p.includes("mac") && maxTouch > 1) ||
        (ua.includes("Macintosh") && maxTouch > 1);
    if (isIOS) {
        const m = ua.match(/OS (\d+[_\d]*)\s+like Mac OS X/);
        const version = m ? m[1].replace(/_/g, ".") : NA;
        if (/iPad/.test(ua) || (p.includes("mac") && maxTouch > 1)) return { name: "iPadOS", version };
        return { name: "iOS", version };
    }

    /* HarmonyOS */
    if (/HarmonyOS/i.test(ua)) {
        return { name: "HarmonyOS", version: ua.match(/HarmonyOS\s*([\d.]+)?/)?.[1] || NA };
    }

    /* ChromeOS */
    if (/CrOS/i.test(ua) || p.includes("cros")) {
        const version = high.platformVersion || ua.match(/CrOS \S+ ([\d.]+)/)?.[1] || NA;
        return { name: "ChromeOS", version };
    }

    /* ============================================================
     Windows — fallback explícito em 3 fontes, sem curto-circuito
     ============================================================ */
    const isWindows = p.includes("win") || /Windows NT/.test(ua) || /^Windows NT/.test(oscpu);

    if (isWindows) {
        if (/Windows Phone/i.test(ua)) {
            return { name: "Windows Phone", version: high.platformVersion || NA };
        }

        // Fonte 1: UA-CH (Chrome/Edge) — distingue 10 vs 11
        const pv = String(high.platformVersion || "");
        if (pv && WINDOWS_MAP[pv]) {
            return { name: "Windows", version: WINDOWS_MAP[pv] };
        }

        // Fonte 2: UA — "Windows NT X.Y"
        const ntUA = ua.match(/Windows NT\s+([\d.]+)/)?.[1];
        if (ntUA) {
            return { name: "Windows", version: WINDOWS_NT_MAP[ntUA] || ntUA };
        }

        // Fonte 3: oscpu — "Windows NT X.Y"
        const ntOscpu = oscpu.match(/Windows NT\s+([\d.]+)/)?.[1];
        if (ntOscpu) {
            return { name: "Windows", version: WINDOWS_NT_MAP[ntOscpu] || ntOscpu };
        }

        // Último recurso: só sabemos que é Windows
        return { name: "Windows", version: "versão desconhecida" };
    }

    /* macOS */
    const isMac = p.includes("mac") || /Macintosh/.test(ua) || /Mac OS X/.test(oscpu);

    if (isMac) {
        const pv = String(high.platformVersion || "");
        if (pv) return { name: "macOS", version: mapMacPlatformVersion(pv) };

        const m = ua.match(/Mac OS X (\d+)[._](\d+)(?:[._](\d+))?/);
        if (m) {
            const full = [m[1], m[2], m[3]].filter(Boolean).join(".");
            return { name: "macOS", version: mapMacVersion(full) };
        }

        const fromOscpu = detectOSFromOscpu(oscpu);
        if (fromOscpu?.name === "macOS") {
            return { name: "macOS", version: mapMacVersion(fromOscpu.version) };
        }

        return { name: "macOS", version: NA };
    }

    /* Linux — mantém distro */
    const isLinux = p.includes("linux") || /Linux/.test(ua) || /^Linux/.test(oscpu);

    if (isLinux) {
        let distroName = "Linux";
        for (const [name, re] of LINUX_DISTROS) {
            if (re.test(ua)) {
                distroName = `Linux (${name})`;
                break;
            }
        }
        let version = NA;
        const vm = ua.match(/Linux[^)]*?(\d+\.\d+)/);
        if (vm) version = vm[1];
        return { name: distroName, version };
    }

    /* BSD / Solaris */
    if (/FreeBSD/i.test(ua) || /FreeBSD/i.test(oscpu)) return { name: "FreeBSD", version: NA };
    if (/OpenBSD/i.test(ua)) return { name: "OpenBSD", version: NA };
    if (/NetBSD/i.test(ua)) return { name: "NetBSD", version: NA };
    if (/SunOS|Solaris/i.test(ua) || /SunOS/i.test(oscpu)) return { name: "Solaris", version: NA };

    return { name: platform || NA, version: high.platformVersion || NA };
}

/* ------------------------------------------------------------------ */
/* Plataforma e fabricante                                             */
/* ------------------------------------------------------------------ */

export function detectPlatform(env) {
    const nav = getEnv(env);
    const platform = String(nav.platform || "");
    const oscpu = String(nav.oscpu || "");
    const ua = String(nav.userAgent || "");

    if (/win/i.test(platform)) {
        if (/Win64|x64|WOW64/i.test(ua) || /Win64|x64/i.test(oscpu)) return "Windows (x64)";
        if (/arm64|aarch64/i.test(ua)) return "Windows (ARM64)";
        return "Windows (x86)";
    }
    if (/mac/i.test(platform)) {
        if (/arm/i.test(oscpu)) return "macOS (Apple Silicon)";
        return "macOS (Intel)";
    }
    if (/linux/i.test(platform)) {
        if (/aarch64|arm64/i.test(ua) || /aarch64|arm64/i.test(oscpu)) return "Linux (arm64)";
        if (/x86_64/i.test(ua) || /x86_64/i.test(oscpu)) return "Linux (x86_64)";
        return "Linux";
    }
    return platform || NA;
}

export function detectVendor(env) {
    const nav = getEnv(env);
    const ua = String(nav.userAgent || "");
    const vendor = String(nav.vendor || "").trim();

    if (vendor) return vendor;

    // Firefox expõe navigator.vendor = "" — inferimos
    if (isFirefoxLike(nav)) {
        if (/FxiOS|Firefox\/|Focus\//.test(ua)) return "Mozilla Foundation";
        if (/TorBrowser\//.test(ua)) return "The Tor Project";
        if (/LibreWolf\//.test(ua)) return "LibreWolf Community";
        if (/Waterfox\//.test(ua)) return "Waterfox Ltd";
        if (/PaleMoon\//.test(ua)) return "Moonchild Productions";
        return "Mozilla";
    }

    if (/Safari/.test(ua) && !/Chrome/.test(ua)) return "Apple Inc.";
    if (/Edg\//.test(ua)) return "Microsoft Corporation";
    if (/Chrome\//.test(ua)) return "Google Inc.";

    return NA;
}

/* ------------------------------------------------------------------ */
/* Navegador e engine                                                  */
/* ------------------------------------------------------------------ */

const BROWSER_PATTERNS = [
    { name: "Firefox Reality (VR)", re: /FirefoxReality\/([\d.]+)/ },
    { name: "Firefox Focus", re: /Focus\/([\d.]+)/ },
    { name: "Firefox (iOS)", re: /FxiOS\/([\d.]+)/ },
    { name: "Tor Browser", re: /TorBrowser\/([\d.]+)/ },
    { name: "LibreWolf", re: /LibreWolf\/([\d.]+)/ },
    { name: "Waterfox", re: /Waterfox\/([\d.]+)/ },
    { name: "Pale Moon", re: /PaleMoon\/([\d.]+)/ },
    { name: "Basilisk", re: /Basilisk\/([\d.]+)/ },
    { name: "Arc", re: /\bArc\/([\d.]+)/ },
    { name: "Brave", re: /Brave\/([\d.]+)/ },
    { name: "Vivaldi", re: /Vivaldi\/([\d.]+)/ },
    { name: "Yandex", re: /YaBrowser\/([\d.]+)/ },
    { name: "UC Browser", re: /UCBrowser\/([\d.]+)/ },
    { name: "Whale", re: /Whale\/([\d.]+)/ },
    { name: "Opera GX", re: /OPR\/([\d.]+).*GX/ },
    { name: "Opera", re: /OPR\/([\d.]+)/ },
    { name: "Samsung Internet", re: /SamsungBrowser\/([\d.]+)/ },
    { name: "Firefox", re: /Firefox\/([\d.]+)/ },
    { name: "Microsoft Edge", re: /Edg(?:A|IOS)?\/([\d.]+)/ },
    { name: "Google Chrome", re: /Chrome\/([\d.]+)/ },
    { name: "Chromium", re: /Chromium\/([\d.]+)/ },
    { name: "Safari", re: /Version\/([\d.]+).*Safari/ },
    { name: "Internet Explorer", re: /MSIE\s([\d.]+)/ },
    { name: "Internet Explorer", re: /Trident\/.*rv:([\d.]+)/ }
];

export function detectBrowser(env) {
    const nav = getEnv(env);
    const ua = String(nav.userAgent || "");

    if (nav.brave && typeof nav.brave.isBrave === "function") {
        const v = ua.match(/Chrome\/([\d.]+)/)?.[1] || NA;
        return { name: "Brave", version: v };
    }
    if (/Electron\/([\d.]+)/.test(ua)) {
        const v = ua.match(/Chrome\/([\d.]+)/)?.[1] || NA;
        return { name: "Electron", version: v };
    }
    if (/HeadlessChrome\/([\d.]+)/.test(ua)) {
        return { name: "Chrome Headless", version: ua.match(/HeadlessChrome\/([\d.]+)/)[1] };
    }
    if (/DuckDuckGo\/([\d.]+)/.test(ua)) {
        return { name: "DuckDuckGo", version: ua.match(/DuckDuckGo\/([\d.]+)/)[1] };
    }

    for (const { name, re } of BROWSER_PATTERNS) {
        const m = ua.match(re);
        if (m) return { name, version: m[1] || NA };
    }

    if (String(nav.product || "") === "Gecko" && /rv:([\d.]+)/.test(ua)) {
        return { name: "Firefox (compat)", version: ua.match(/rv:([\d.]+)/)[1] };
    }

    return { name: NA, version: NA };
}

export function detectEngine(env) {
    const nav = getEnv(env);
    const ua = String(nav.userAgent || "");
    if (!ua) return NA;

    if (/Edg\/|OPR\/|Chrome\/|Chromium\/|HeadlessChrome\//.test(ua)) return "Blink";
    if (/Firefox\/|FirefoxReality\/|Waterfox\/|PaleMoon\/|Basilisk\/|LibreWolf\/|TorBrowser\//.test(ua)) return "Gecko";
    if (/Gecko\//.test(ua) && !/like Gecko/i.test(ua)) return "Gecko";
    if (/AppleWebKit\//.test(ua)) return "WebKit";
    if (/Trident\//.test(ua)) return "Trident";
    if (/Edge\//.test(ua)) return "EdgeHTML";

    return NA;
}

/* ------------------------------------------------------------------ */
/* Firefox info                                                        */
/* ------------------------------------------------------------------ */

export function getFirefoxInfo(env) {
    const nav = getEnv(env);
    if (!isFirefoxLike(nav)) return null;

    const channelInfo = detectFirefoxChannel(nav);
    const osFromOscpu = nav.oscpu ? detectOSFromOscpu(nav.oscpu) : null;

    const osSummary =
        osFromOscpu && osFromOscpu.name !== "Linux"
            ? `${osFromOscpu.name} ${osFromOscpu.version}`.trim()
            : osFromOscpu?.name || NA;

    return {
        channel: channelInfo?.channel || NA,
        version: channelInfo?.version || NA,
        oscpu: nav.oscpu || NA,
        buildID: nav.buildID || NA,
        osFromOscpu: osSummary,
        archFromOscpu: nav.oscpu ? getArchFromOscpu(nav.oscpu) : NA,
        archFromUA: getArchFromUA(nav.userAgent)
    };
}

/* ------------------------------------------------------------------ */
/* Diagnóstico — exponha no console                                    */
/* ------------------------------------------------------------------ */

export function diagnose(env) {
    const nav = getEnv(env);
    return {
        isSecureContext: typeof window !== "undefined" ? window.isSecureContext : null,
        protocol: typeof location !== "undefined" ? location.protocol : null,
        userAgent: nav.userAgent || NA,
        platform: nav.platform || NA,
        oscpu: nav.oscpu || NA,
        product: nav.product || NA,
        vendor: nav.vendor || NA,
        hasUserAgentData: !!nav.userAgentData,
        hasStorage: typeof navigator !== "undefined" ? !!navigator.storage : false,
        hasMediaDevices: typeof navigator !== "undefined" ? !!navigator.mediaDevices : false,
        hasServiceWorker: typeof navigator !== "undefined" ? "serviceWorker" in navigator : false,
        detected: {
            os: detectOS(nav),
            platform: detectPlatform(nav),
            vendor: detectVendor(nav),
            arch: detectArch(nav),
            browser: detectBrowser(nav)
        }
    };
}

export function detectAll(env) {
    return {
        os: detectOS(env),
        browser: detectBrowser(env),
        engine: detectEngine(env),
        platform: detectPlatform(env),
        vendor: detectVendor(env),
        firefox: getFirefoxInfo(env)
    };
}
