import { NA } from "../utils/safe.js";

export async function collectGPU() {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");

    if (!gl) {
        return [
            ["WebGL", "Não suportado"],
            ["Aceleração", "Indisponível"]
        ];
    }

    const dbg = gl.getExtension("WEBGL_debug_renderer_info");
    const vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
    const renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);

    return [
        ["Fabricante da GPU", vendor || NA],
        ["GPU / Renderizador", renderer || NA],
        ["Versão do WebGL", gl.getParameter(gl.VERSION) || NA],
        ["GLSL", gl.getParameter(gl.SHADING_LANGUAGE_VERSION) || NA],
        ["Textura máxima", `${gl.getParameter(gl.MAX_TEXTURE_SIZE)} px`],
        ["Unidades de textura", gl.getParameter(gl.MAX_TEXTURE_IMAGE_UNITS)],
        ["Atributos de vértice", gl.getParameter(gl.MAX_VERTEX_ATTRIBS)],
        ["Renderização", "Aceleração por hardware (provável)"]
    ];
}
