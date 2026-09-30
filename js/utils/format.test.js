import { describe, it, expect } from "vitest";
import { safe, isNA, NA } from "./safe.js";

describe("isNA", () => {
    it("detecta valores vazios", () => {
        expect(isNA(undefined)).toBe(true);
        expect(isNA(null)).toBe(true);
        expect(isNA("")).toBe(true);
        expect(isNA(NaN)).toBe(true);
        expect(isNA(Infinity)).toBe(true);
        expect(isNA([])).toBe(true);
    });

    it("aceita valores válidos", () => {
        expect(isNA(0)).toBe(false);
        expect(isNA("x")).toBe(false);
        expect(isNA(false)).toBe(false);
        expect(isNA([1])).toBe(false);
    });
});

describe("safe", () => {
    it("retorna o valor quando a função tem sucesso", async () => {
        expect(await safe(() => 42)).toBe(42);
        expect(await safe(() => "abc")).toBe("abc");
        expect(await safe(async () => "ok")).toBe("ok");
    });

    it("retorna fallback quando a função lança erro", async () => {
        expect(
            await safe(() => {
                throw new Error("x");
            })
        ).toBe(NA);
        expect(
            await safe(() => {
                throw new Error("x");
            }, "custom")
        ).toBe("custom");
    });

    it("retorna fallback quando o valor é vazio", async () => {
        expect(await safe(() => undefined)).toBe(NA);
        expect(await safe(() => null)).toBe(NA);
        expect(await safe(() => "")).toBe(NA);
        expect(await safe(() => NaN)).toBe(NA);
        expect(await safe(() => [], "vazio")).toBe("vazio");
    });

    it("aceita valores não-função diretamente", async () => {
        expect(await safe(42)).toBe(42);
        expect(await safe(undefined)).toBe(NA);
    });
});
