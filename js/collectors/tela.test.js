import { describe, it, expect, beforeEach, vi } from "vitest";
import { collectTela } from "./tela.js";

describe("collectTela", () => {
    beforeEach(() => {
        vi.stubGlobal("screen", {
            width: 1920,
            height: 1080,
            availWidth: 1920,
            availHeight: 1040,
            colorDepth: 24,
            pixelDepth: 24,
            orientation: { type: "landscape-primary", angle: 0 }
        });

        vi.stubGlobal("window", {
            devicePixelRatio: 2,
            outerWidth: 1920,
            outerHeight: 1080,
            innerWidth: 1280,
            innerHeight: 800,
            matchMedia: (query) => ({
                matches: query.includes("srgb")
            })
        });
    });

    it("retorna as informações da tela formatadas", async () => {
        const rows = await collectTela(60);
        const map = Object.fromEntries(rows);

        expect(map["Resolução"]).toBe("1920 × 1080 px");
        expect(map["Área disponível"]).toBe("1920 × 1040 px");
        expect(map["Profundidade de cor"]).toBe("24 bits");
        expect(map["Device Pixel Ratio"]).toBe(2);
        expect(map["Orientação"]).toBe("landscape-primary");
        expect(map["Taxa de atualização"]).toBe("60 Hz");
        expect(map["Espaço de cor"]).toBe("sRGB");
    });
});
