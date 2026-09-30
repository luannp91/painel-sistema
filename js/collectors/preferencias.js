import { yesNo } from "../utils/format.js";

export async function collectPreferencias() {
    const mq = (q) => window.matchMedia(q).matches;

    return [
        ["Tema preferido", mq("(prefers-color-scheme: dark)") ? "Escuro" : "Claro"],
        ["Movimento reduzido", yesNo(mq("(prefers-reduced-motion: reduce)"))],
        ["Transparência reduzida", yesNo(mq("(prefers-reduced-transparency: reduce)"))],
        ["Contraste aumentado", yesNo(mq("(prefers-contrast: more)"))],
        ["Modo escuro forçado", yesNo(mq("(forced-colors: active)"))],
        ["Orientação retrato", yesNo(mq("(orientation: portrait)"))],
        ["Tela sensível ao toque", yesNo(mq("(pointer: coarse)"))],
        ["Mouse presente", yesNo(mq("(any-pointer: fine)"))]
    ];
}
