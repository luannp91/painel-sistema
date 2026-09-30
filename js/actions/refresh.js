import { state } from "../state.js";
import { $ } from "../utils/dom.js";
import { measureRefreshRate } from "../utils/perf.js";
import { SECTIONS_META } from "../config.js";
import { safe } from "../utils/safe.js";
import { esc } from "../utils/dom.js";
import { renderSections } from "../ui/render.js";

import {
    collectSistema,
    collectNavegador,
    collectTela,
    collectGPU,
    collectRede,
    collectBateria,
    collectArmazenamento,
    collectMidia,
    collectEntrada,
    collectPreferencias,
    collectTempo,
    collectPermissoes,
    collectRecursos
} from "../collectors/index.js";

/** Obtém valores de alta entropia do User-Agent Client Hints (Chrome/Edge). */
async function getHighEntropy() {
    const uaData = navigator.userAgentData;
    if (!uaData?.getHighEntropyValues) return {};

    return safe(
        () =>
            uaData.getHighEntropyValues([
                "architecture",
                "bitness",
                "model",
                "platform",
                "platformVersion",
                "uaFullVersion",
                "fullVersionList",
                "wow64"
            ]),
        {}
    );
}

/** Orquestra: coleta tudo, atualiza o estado e renderiza. */
export async function refresh() {
    if (state.collecting) return;
    state.collecting = true;

    const grid = $("#grid");
    const btnRefresh = $("#btnRefresh");

    grid.setAttribute("aria-busy", "true");
    grid.innerHTML = `
    <div class="loading">
      <div class="spinner"></div>
      <p>Coletando informações do sistema…</p>
    </div>
  `;

    btnRefresh.disabled = true;
    btnRefresh.style.opacity = ".6";

    try {
        const refreshRate = await measureRefreshRate();
        const high = await getHighEntropy();

        const [
            sistema,
            navegador,
            tela,
            gpu,
            rede,
            bateria,
            armazenamento,
            midia,
            entrada,
            prefs,
            tempo,
            permissoes,
            recursos
        ] = await Promise.all([
            collectSistema(high),
            collectNavegador(high),
            collectTela(refreshRate),
            collectGPU(),
            collectRede(),
            collectBateria(),
            collectArmazenamento(),
            collectMidia(),
            collectEntrada(),
            collectPreferencias(),
            collectTempo(),
            collectPermissoes(),
            collectRecursos()
        ]);

        const sections = [
            { id: "sistema", ...SECTIONS_META.sistema, rows: sistema },
            { id: "navegador", ...SECTIONS_META.navegador, rows: navegador },
            { id: "tela", ...SECTIONS_META.tela, rows: tela },
            { id: "gpu", ...SECTIONS_META.gpu, rows: gpu },
            { id: "rede", ...SECTIONS_META.rede, rows: rede },
            { id: "bateria", ...SECTIONS_META.bateria, rows: bateria },
            { id: "armazenamento", ...SECTIONS_META.armazenamento, rows: armazenamento },
            { id: "midia", ...SECTIONS_META.midia, rows: midia },
            { id: "entrada", ...SECTIONS_META.entrada, rows: entrada },
            { id: "preferencias", ...SECTIONS_META.preferencias, rows: prefs },
            { id: "tempo", ...SECTIONS_META.tempo, rows: tempo },
            { id: "permissoes", ...SECTIONS_META.permissoes, rows: permissoes },
            { id: "recursos", ...SECTIONS_META.recursos, rows: recursos }
        ];

        // Atualiza estado global
        state.sections = sections;
        state.json = {};
        for (const s of sections) {
            state.json[s.title] = Object.fromEntries(s.rows);
        }

        renderSections(sections, grid);

        $("#collectedAt").textContent = new Date().toLocaleString("pt-BR");
        $("#sectionCount").textContent = sections.length;
    } catch (err) {
        grid.innerHTML = `
      <div class="loading">
        <p style="color:var(--err)">Ocorreu um erro ao coletar os dados: ${esc(err.message)}</p>
      </div>
    `;
        console.error("[Painel do Sistema]", err);
    } finally {
        grid.setAttribute("aria-busy", "false");
        btnRefresh.disabled = false;
        btnRefresh.style.opacity = "1";
        state.collecting = false;
    }
}
