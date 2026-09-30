import { describe, it, expect } from "vitest";
import { detectOS, detectOSFromOscpu, getArchFromOscpu, isFirefoxLike } from "./detect.js";

function fakeNav(opts = {}) {
    return {
        userAgent: "",
        platform: "",
        maxTouchPoints: 0,
        userAgentData: null,
        oscpu: "",
        buildID: "",
        product: "",
        vendor: "",
        ...opts
    };
}

describe("REGRESSÃO — Firefox mantém detecção rica", () => {
    it("Linux com Firefox preserva a distro (Ubuntu)", () => {
        const nav = fakeNav({
            userAgent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
            platform: "Linux x86_64",
            oscpu: "Linux x86_64",
            product: "Gecko"
        });
        expect(detectOS(nav).name).toBe("Linux (Ubuntu)");
    });

    it("Linux com Firefox preserva a distro (Fedora)", () => {
        const nav = fakeNav({
            userAgent: "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
            platform: "Linux x86_64",
            oscpu: "Linux x86_64",
            product: "Gecko"
        });
        expect(detectOS(nav).name).toBe("Linux (Fedora)");
    });

    it("macOS com Firefox mapeia para nome amigável (Catalina)", () => {
        const nav = fakeNav({
            userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
            platform: "MacIntel",
            oscpu: "Intel Mac OS X 10.15",
            product: "Gecko"
        });
        expect(detectOS(nav)).toEqual({ name: "macOS", version: "10.15 (Catalina)" });
    });

    it("macOS Sonoma com Firefox", () => {
        const nav = fakeNav({
            userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
            platform: "MacIntel",
            oscpu: "Intel Mac OS X 10.15",
            product: "Gecko"
            // sem userAgentData em Firefox, a versão vem do UA (que Firefox
            // congela em 10.15 por privacidade — então cai no 10.15 mesmo)
        });
        expect(detectOS(nav).name).toBe("macOS");
    });

    it('Windows com Firefox mostra "10 ou 11" (não pode distinguir)', () => {
        const nav = fakeNav({
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
            platform: "Win32",
            oscpu: "Windows NT 10.0; Win64; x64",
            product: "Gecko"
        });
        expect(detectOS(nav)).toEqual({ name: "Windows", version: "10 ou 11" });
    });

    it("Windows com Chrome distingue 10 vs 11 via UA-CH", () => {
        const nav = fakeNav({
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0",
            platform: "Win32",
            userAgentData: { platform: "Windows", platformVersion: "15.0.0" }
        });
        expect(detectOS(nav)).toEqual({ name: "Windows", version: "11" });
    });
});

describe("getArchFromOscpu", () => {
    it("extrai x86_64", () => {
        expect(getArchFromOscpu("Linux x86_64")).toBe("x86_64 (64-bit)");
        expect(getArchFromOscpu("Windows NT 10.0; Win64; x64")).toBe("x86_64 (64-bit)");
    });

    it("extrai arm64", () => {
        expect(getArchFromOscpu("Linux aarch64")).toBe("arm64");
    });

    it("extrai x86 32-bit", () => {
        expect(getArchFromOscpu("Linux i686")).toBe("x86 (32-bit)");
    });

    it("extrai Intel (macOS)", () => {
        expect(getArchFromOscpu("Intel Mac OS X 10.15")).toBe("x86_64 (Intel)");
    });

    it('retorna "Não disponível" para vazio', () => {
        expect(getArchFromOscpu("")).toBe("Não disponível");
        expect(getArchFromOscpu(null)).toBe("Não disponível");
    });
});

describe("detectOSFromOscpu — valores corretos", () => {
    it('Windows NT 10.0 → "10 ou 11"', () => {
        expect(detectOSFromOscpu("Windows NT 10.0").version).toBe("10 ou 11");
    });

    it('Windows NT 6.1 → "7"', () => {
        expect(detectOSFromOscpu("Windows NT 6.1").version).toBe("7");
    });

    it("Linux inclui arch em campo próprio (não em version)", () => {
        const r = detectOSFromOscpu("Linux x86_64");
        expect(r.name).toBe("Linux");
        expect(r.version).toBe("Não disponível");
        expect(r.arch).toBe("x86_64");
    });
});

describe("isFirefoxLike", () => {
    it("reconhece Firefox pelo product=Gecko", () => {
        expect(isFirefoxLike(fakeNav({ product: "Gecko" }))).toBe(true);
    });
    it("reconhece Tor Browser", () => {
        expect(isFirefoxLike(fakeNav({ userAgent: "Mozilla/5.0 TorBrowser/13.0" }))).toBe(true);
    });
    it("reconhece LibreWolf", () => {
        expect(isFirefoxLike(fakeNav({ userAgent: "Mozilla/5.0 LibreWolf/121.0" }))).toBe(true);
    });
    it("não confunde Chrome", () => {
        expect(isFirefoxLike(fakeNav({ userAgent: "Chrome/121.0" }))).toBe(false);
    });
});
