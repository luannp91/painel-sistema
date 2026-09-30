/* =========================================================
   Medições de performance — taxa de atualização da tela
   ========================================================= */

import { NA } from "./safe.js";
import { REFRESH_RATE_SAMPLE_MS } from "../config.js";

/**
 * Mede a taxa de atualização da tela (Hz) amostrando requestAnimationFrame.
 * @param {number} duration Duração da amostra em ms.
 * @returns {Promise<number|string>}
 */
export function measureRefreshRate(duration = REFRESH_RATE_SAMPLE_MS) {
    return new Promise((resolve) => {
        let frames = 0;
        const start = performance.now();

        function loop(now) {
            frames++;
            const elapsed = now - start;
            if (elapsed >= duration) {
                const hz = Math.round(frames / (elapsed / 1000));
                resolve(hz > 0 && hz < 1000 ? hz : NA);
            } else {
                requestAnimationFrame(loop);
            }
        }
        requestAnimationFrame(loop);
    });
}
