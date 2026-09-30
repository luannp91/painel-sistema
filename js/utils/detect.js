/* =========================================================
   Detecção aprimorada de SO, navegador e engine
   ---------------------------------------------------------
   Funções puras e testáveis — recebem `env` (navigator-like)
   como dependência injetada, com fallback para o global.
   ========================================================= */

import { NA } from "./safe.js";

/* ------------------------------------------------------------------ */
/* Entrada                                                             */
/* ------------------------------------------------------------------ */

/**
 * Normaliza a "entrada" (navigator-like).
 * Permite testar sem depender do ambiente real.
 */
function getEnv(env) {
    if (env) return env;
    if (typeof navigator !== "undefined") return navigator;
    return {
        userAgent: "",
        platform: "",
        maxTouchPoints: 0,
        userAgentData: null
    };
}

/* ------------------------------------------------------------------ */
/* Sistema Operacional                                                 */
/* ------------------------------------------------------------------ */

const WINDOWS_MAP = {
    "0.1.0": "7",
    "0.2.0": "8",
    "0.3.0": "8.1",
    "1.0.0": "10",
    "1.1.0": "10",
    "2.0.0": "10",
    "3.0.0": "10",
    "4.0.0": "10",
    "5.0.0": "10",
    "6.0.0": "10",
    "7.0.0": "10",
    "8.0.0": "10",
    "9.0.0": "10",
    "10.0.0": "10",
    "11.0.0": "10",
    "12.0.0": "10",
    "13.0.0": "11",
    "14.0.0": "11",
    "15.0.0": "11",
    "16.0.0": "11"
};

/** Extrai versão de macOS a partir do platformVersion do UA-CH. */
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

/**
 * Detecta o sistema operacional.
 * @param {object} [env] navigator-like (opcional)
 * @returns {{ name: string, version: string }}
 */
export function detectOS(env) {
    const nav = getEnv(env);
    const ua = String(nav.userAgent || "");
    const high = nav.userAgentData || {};
    const platform = String(high.platform || nav.platform || "");
    const p = platform.toLowerCase();
    const maxTouch = Number(nav.maxTouchPoints) || 0;

    // Android (inclui TV, Wear OS)
    if (/android/i.test(ua)) {
        const version = ua.match(/Android\s+([\d.]+)/)?.[1] ?? NA;

        if (/Android TV/i.test(ua)) return { name: "Android TV", version };
        if (/Wear OS|Android Wear/i.test(ua)) return { name: "Wear OS", version };

        return { name: "Android", version };
    }

    // iOS / iPadOS
    const isIOS =
        /iPad|iPhone|iPod/.test(ua) ||
        (p.includes("mac") && maxTouch > 1) ||
        (ua.includes("Macintosh") && maxTouch > 1);

    if (isIOS) {
        const m = ua.match(/OS (\d+[_\d]*)\s+like Mac OS X/);
        const version = m ? m[1].replace(/_/g, ".") : NA;

        if (/iPad/.test(ua) || (p.includes("mac") && maxTouch > 1)) {
            return { name: "iPadOS", version };
        }
        return { name: "iOS", version };
    }

    // HarmonyOS (aparece no UA como "HarmonyOS")
    if (/HarmonyOS/i.test(ua)) {
        return { name: "HarmonyOS", version: ua.match(/HarmonyOS\s*([\d.]+)?/)?.[1] || NA };
    }

    // ChromeOS / ChromeOS Flex
    if (/CrOS/i.test(ua) || p.includes("cros")) {
        const version = high.platformVersion || ua.match(/CrOS \S+ ([\d.]+)/)?.[1] || NA;
        return { name: "ChromeOS", version };
    }

    // Windows
    if (p.includes("win")) {
        const pv = String(high.platformVersion || "");

        // Windows Phone
        if (/Windows Phone/i.test(ua)) {
            return { name: "Windows Phone", version: pv || NA };
        }

        return { name: "Windows", version: WINDOWS_MAP[pv] || pv || NA };
    }

    // macOS
    if (p.includes("mac") || /Macintosh/.test(ua)) {
        const pv = String(high.platformVersion || "");
        return { name: "macOS", version: mapMacPlatformVersion(pv) };
    }

    // Linux (com detecção de distro)
    if (p.includes("linux") || /Linux/.test(ua)) {
        const distros = [
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
        for (const [name, re] of distros) {
            if (re.test(ua)) return { name: `Linux (${name})`, version: high.platformVersion || NA };
        }
        return { name: "Linux", version: high.platformVersion || NA };
    }

    // FreeBSD, OpenBSD, NetBSD, Solaris
    if (/FreeBSD/i.test(ua)) return { name: "FreeBSD", version: NA };
    if (/OpenBSD/i.test(ua)) return { name: "OpenBSD", version: NA };
    if (/NetBSD/i.test(ua)) return { name: "NetBSD", version: NA };
    if (/SunOS|Solaris/i.test(ua)) return { name: "Solaris", version: NA };

    return { name: platform || NA, version: high.platformVersion || NA };
}

/* ------------------------------------------------------------------ */
/* Navegador                                                           */
/* ------------------------------------------------------------------ */

/**
 * Ordem importa! Navegadores baseados em Chromium "mentem" no UA
 * (o Chrome aparece em vários UAs). Detectamos primeiro os derivados.
 */
const BROWSER_PATTERNS = [
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
    { name: "Firefox (ESR)", re: /Firefox\/([\d.]+)\s*ESR/ },
    { name: "Waterfox", re: /Waterfox\/([\d.]+)/ },
    { name: "Pale Moon", re: /PaleMoon\/([\d.]+)/ },
    { name: "Microsoft Edge", re: /Edg(?:A|IOS)?\/([\d.]+)/ },
    { name: "Google Chrome", re: /Chrome\/([\d.]+)/ },
    { name: "Chromium", re: /Chromium\/([\d.]+)/ },
    { name: "Safari", re: /Version\/([\d.]+).*Safari/ },
    { name: "Internet Explorer", re: /MSIE\s([\d.]+)/ },
    { name: "Internet Explorer", re: /Trident\/.*rv:([\d.]+)/ }
];

/**
 * Detecta o navegador (nome + versão).
 * @param {object} [env] navigator-like (opcional)
 * @returns {{ name: string, version: string }}
 */
export function detectBrowser(env) {
    const nav = getEnv(env);
    const ua = String(nav.userAgent || "");

    // Detecções especiais que não dependem de UA
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

    // Padrões normais
    for (const { name, re } of BROWSER_PATTERNS) {
        const m = ua.match(re);
        if (m) return { name, version: m[1] || NA };
    }

    return { name: NA, version: NA };
}

/* ------------------------------------------------------------------ */
/* Engine / Motor de renderização                                      */
/* ------------------------------------------------------------------ */

/**
 * Detecta o motor de renderização.
 * @param {object} [env] navigator-like (opcional)
 * @returns {string}
 */
export function detectEngine(env) {
    const nav = getEnv(env);
    const ua = String(nav.userAgent || "");

    if (!ua) return NA;

    // Blink: Chromium derivatives
    if (/Edg\/|OPR\/|Chrome\/|Chromium\/|HeadlessChrome\//.test(ua)) {
        return "Blink";
    }

    // Gecko (Firefox e derivados). A regex "/like Gecko/" é usada
    // em UAs de outros motores como disfarce, então filtramos.
    if (/Gecko\//.test(ua) && !/like Gecko/i.test(ua)) {
        return "Gecko";
    }

    // WebKit (Safari, iOS WebViews)
    if (/AppleWebKit\//.test(ua)) {
        return "WebKit";
    }

    // Trident (IE)
    if (/Trident\//.test(ua)) {
        return "Trident";
    }

    // EdgeHTML (Edge legacy)
    if (/Edge\//.test(ua)) {
        return "EdgeHTML";
    }

    return NA;
}

/* ------------------------------------------------------------------ */
/* Utilitário: resumo pronto para uso                                  */
/* ------------------------------------------------------------------ */

/**
 * Retorna um resumo combinado de SO, navegador e engine.
 * @param {object} [env] navigator-like (opcional)
 * @returns {{ os: object, browser: object, engine: string }}
 */
export function detectAll(env) {
    return {
        os: detectOS(env),
        browser: detectBrowser(env),
        engine: detectEngine(env)
    };
}
