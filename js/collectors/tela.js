import { NA } from "../utils/safe.js";
import { yesNo } from "../utils/format.js";

export async function collectTela(refreshRate) {
    const s = screen;
    const o = s.orientation;

    const colorGamut = window.matchMedia("(color-gamut: p3)").matches
        ? "Display P3"
        : window.matchMedia("(color-gamut: srgb)").matches
          ? "sRGB"
          : NA;

    return [
        ["Resolução", `${s.width} × ${s.height} px`],
        ["Área disponível", `${s.availWidth} × ${s.availHeight} px`],
        ["Profundidade de cor", `${s.colorDepth} bits`],
        ["Pixel depth", `${s.pixelDepth} bits`],
        ["Device Pixel Ratio", window.devicePixelRatio ?? NA],
        ["Orientação", o?.type ?? NA],
        ["Ângulo da tela", o?.angle !== undefined ? `${o.angle}°` : NA],
        ["Janela externa", `${window.outerWidth} × ${window.outerHeight} px`],
        ["Viewport interno", `${window.innerWidth} × ${window.innerHeight} px`],
        ["Espaço de cor", colorGamut],
        ["Faixa dinâmica (HDR)", yesNo(window.matchMedia("(dynamic-range: high)").matches)],
        ["Taxa de atualização", refreshRate === NA ? NA : `${refreshRate} Hz`]
    ];
}
