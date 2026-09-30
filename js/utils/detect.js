/* =========================================================
   Detecção de SO, navegador e motor de renderização
   ========================================================= */

import { NA } from "./safe.js";

export function detectOS(high = {}) {
    const ua = navigator.userAgent;
    const platform = String(high.platform || navigator.platform || "");
    const p = platform.toLowerCase();
    const maxTouch = navigator.maxTouchPoints || 0;

    if (/android/i.test(ua)) {
        const m = ua.match(/Android\s+([\d.]+)/);
        return { name: "Android", version: m ? m[1] : NA };
    }

    const isIOS = /iPad|iPhone|iPod/.test(ua) || (p.includes("mac") && maxTouch > 1);
    if (isIOS) {
        const m = ua.match(/OS (\d+[_\d]*) like Mac/);
        return { name: "iOS / iPadOS", version: m ? m[1].replace(/_/g, ".") : NA };
    }

    if (p.includes("win")) {
        const pv = String(high.platformVersion || "");
        const map = {
            "0.1.0": "7",
            "0.2.0": "8",
            "0.3.0": "8.1",
            "1.0.0": "10",
            "10.0.0": "10",
            "15.0.0": "11"
        };
        return { name: "Windows", version: map[pv] || pv || NA };
    }

    if (p.includes("mac")) return { name: "macOS", version: high.platformVersion || NA };
    if (p.includes("cros")) return { name: "ChromeOS", version: high.platformVersion || NA };
    if (p.includes("linux")) return { name: "Linux", version: high.platformVersion || NA };

    return { name: platform || NA, version: high.platformVersion || NA };
}

export function detectBrowser() {
    const ua = navigator.userAgent;

    const patterns = [
        { name: "Microsoft Edge", re: /Edg(?:A|IOS)?\/([\d.]+)/ },
        { name: "Opera", re: /OPR\/([\d.]+)/ },
        { name: "Samsung Internet", re: /SamsungBrowser\/([\d.]+)/ },
        { name: "Firefox", re: /Firefox\/([\d.]+)/ },
        { name: "Google Chrome", re: /Chrome\/([\d.]+)/ },
        { name: "Safari", re: /Version\/([\d.]+).*Safari/ }
    ];

    for (const { name, re } of patterns) {
        const m = ua.match(re);
        if (m) return { name, version: m[1] };
    }
    return { name: NA, version: NA };
}

export function detectEngine() {
    const ua = navigator.userAgent;
    if (/Gecko\/|Firefox/.test(ua) && !/like Gecko/.test(ua)) return "Gecko";
    if (/AppleWebKit/.test(ua) && /Chrome|Chromium|Edg|OPR/.test(ua)) return "Blink";
    if (/AppleWebKit/.test(ua)) return "WebKit";
    if (/Trident/.test(ua)) return "Trident";
    return NA;
}
