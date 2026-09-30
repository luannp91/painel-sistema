import { PERMISSION_NAMES } from "../config.js";
import { permissionLabel } from "../utils/format.js";

export async function collectPermissoes() {
    if (!navigator.permissions?.query) {
        return [["Permissions API", "Não suportada"]];
    }

    const rows = [];

    for (const name of PERMISSION_NAMES) {
        try {
            const status = await navigator.permissions.query({ name });
            rows.push([name, permissionLabel(status.state)]);
        } catch {
            /* nome não suportado — ignora */
        }
    }

    return rows.length ? rows : [["Permissões consultáveis", "Nenhuma disponível"]];
}
