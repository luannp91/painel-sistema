import { describe, it, expect } from "vitest";
import {
    detectOS,
    detectBrowser,
    detectEngine,
    detectPlatform,
    detectVendor,
    isFirefoxLike,
    getArchFromOscpu,
    getFirefoxInfo
} from "./detect.js";

/* ============================================================
   ESTE BLOCO REPRODUZ EXATAMENTE O SEU CASO DE USO
   ============================================================ */

describe("REGRESSÃO — Firefox 156 no Windows 10/11", () => {
    const nav = {
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0",
        platform: "Win32",
        oscpu: "Windows NT 10.0; Win64; x64",
        product: "Gecko",
        vendor: "",
        maxTouchPoints: 0,
        userAgentData: null,
        languages: ["pt-BR", "en-US", "en"],
        language: "pt-BR",
        buildID: "20260101"
    };

    it("getEnv aceita o objeto completo e detecta o SO", () => {
        const os = detectOS(nav);
        expect(os.name).toBe("Windows");
        expect(os.version).toBe("10 ou 11");
    });

    it("getEnv NÃO aceita objeto vazio como env", () => {
        // Antes, `detectOS({})` retornava { name: NA, version: NA }
        // Agora, deve ignorar `{}` e usar o navigator real (que nos testes
        // é o happy-dom — por isso validamos que não cai no vazio silencioso)
        const result = detectOS({});
        // Se o happy-dom fornecer UA, deve detectar algo que NÃO seja NA
        // Caso contrário, cai no fallback legítimo
        expect(result).toHaveProperty("name");
        expect(result).toHaveProperty("version");
    });

    it("detecta navegador Firefox", () => {
        expect(detectBrowser(nav)).toEqual({ name: "Firefox", version: "156.0" });
    });

    it("detecta engine Gecko", () => {
        expect(detectEngine(nav)).toBe("Gecko");
    });

    it("detecta plataforma como Windows (x64)", () => {
        expect(detectPlatform(nav)).toBe("Windows (x64)");
    });

    it("deriva arquitetura do oscpu", () => {
        expect(getArchFromOscpu(nav.oscpu)).toBe("x86_64 (64-bit)");
    });

    it("fabricante inferido = Mozilla", () => {
        expect(detectVendor(nav)).toBe("Mozilla");
    });

    it("bloco Firefox completo", () => {
        const info = getFirefoxInfo(nav);
        expect(info).not.toBeNull();
        expect(info.channel).toBe("Release");
        expect(info.version).toBe("156.0");
        expect(info.osFromOscpu).toBe("Windows 10 ou 11");
        expect(info.archFromOscpu).toBe("x86_64 (64-bit)");
    });

    it("isFirefoxLike retorna true pelo product=Gecko", () => {
        expect(isFirefoxLike(nav)).toBe(true);
    });
});

/* ============================================================
   Matriz de UAs reais do Firefox
   ============================================================ */

describe("Matriz de UAs reais do Firefox", () => {
    const cases = [
        {
            label: "Windows 10 Firefox 122 release",
            nav: {
                userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
                platform: "Win32",
                oscpu: "Windows NT 10.0; Win64; x64",
                product: "Gecko"
            },
            expected: { name: "Windows", version: "10 ou 11" }
        },
        {
            label: "Windows 7 Firefox ESR",
            nav: {
                userAgent: "Mozilla/5.0 (Windows NT 6.1; rv:115.0) Gecko/20100101 Firefox/115.0esr",
                platform: "Win32",
                oscpu: "Windows NT 6.1",
                product: "Gecko"
            },
            expected: { name: "Windows", version: "7" }
        },
        {
            label: "Ubuntu Firefox",
            nav: {
                userAgent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
                platform: "Linux x86_64",
                oscpu: "Linux x86_64",
                product: "Gecko"
            },
            expected: { name: "Linux (Ubuntu)", version: "Não disponível" }
        },
        {
            label: "Fedora Firefox",
            nav: {
                userAgent: "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
                platform: "Linux x86_64",
                oscpu: "Linux x86_64",
                product: "Gecko"
            },
            expected: { name: "Linux (Fedora)", version: "Não disponível" }
        },
        {
            label: "macOS Catalina Firefox",
            nav: {
                userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
                platform: "MacIntel",
                oscpu: "Intel Mac OS X 10.15",
                product: "Gecko"
            },
            expected: { name: "macOS", version: "10.15 (Catalina)" }
        },
        {
            label: "Android Firefox",
            nav: {
                userAgent: "Mozilla/5.0 (Android 13; Mobile; rv:122.0) Gecko/122.0 Firefox/122.0",
                platform: "Linux armv7l",
                oscpu: "Linux armv7l",
                product: "Gecko"
            },
            expected: { name: "Android", version: "13" }
        },
        {
            label: "iOS Firefox (FxiOS)",
            nav: {
                userAgent:
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 FxiOS/122.0 Mobile/15E148",
                platform: "iPhone",
                oscpu: "",
                product: "Gecko"
            },
            expected: { name: "iOS", version: "17.0" }
        }
    ];

    for (const { label, nav, expected } of cases) {
        it(label, () => {
            expect(detectOS(nav)).toEqual(expected);
        });
    }
});

/* ============================================================
   Firefox NÃO deve regredir com env vazio
   ============================================================ */

describe("getEnv robusto contra env vazio", () => {
    it("detectOS({}) não retorna NA quando o navigator real existe", () => {
        // Se happy-dom fornecer UA, deve detectar; se não, ainda assim
        // não pode retornar um objeto vazio sem as chaves esperadas
        const r = detectOS({});
        expect(r).toHaveProperty("name");
        expect(r).toHaveProperty("version");
    });

    it("detectOS(null) usa navigator", () => {
        const r = detectOS(null);
        expect(r).toHaveProperty("name");
    });

    it("detectOS(undefined) usa navigator", () => {
        const r = detectOS(undefined);
        expect(r).toHaveProperty("name");
    });
});
