import { state } from "../state.js";
import { $, esc } from "../utils/dom.js";
import { safe } from "../utils/safe.js";
import { measureRefreshRate } from "../utils/perf.js";
import { renderDashboard } from "../ui/render.js";

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
import { collectFirefox } from "../collectors/firefox.js";
import { collectResumo } from "../collectors/resumo.js";

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
            summary,
            sistema,
            navegador,
            firefox,
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
            collectResumo(),
            collectSistema(high),
            collectNavegador(high),
            collectFirefox(),
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

        // Monta a lista de seções (firefox pode ser null)
        const sections = [
            { id: "sistema", rows: sistema },
            { id: "navegador", rows: navegador },
            firefox ? { id: "firefox", rows: firefox } : null,
            { id: "tela", rows: tela },
            { id: "gpu", rows: gpu },
            { id: "rede", rows: rede },
            { id: "bateria", rows: bateria },
            { id: "armazenamento", rows: armazenamento },
            { id: "midia", rows: midia },
            { id: "entrada", rows: entrada },
            { id: "preferencias", rows: prefs },
            { id: "tempo", rows: tempo },
            { id: "permissoes", rows: permissoes },
            { id: "recursos", rows: recursos }
        ].filter(Boolean);

        // Atualiza estado global
        state.sections = sections;
        state.json = { resumo: summary };
        for (const s of sections) {
            state.json[s.id] = Object.fromEntries(s.rows);
        }

        // Renderiza
        renderDashboard({ summary, sections }, grid);

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
