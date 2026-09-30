import { NA, safe } from "../utils/safe.js";
import { yesNo } from "../utils/format.js";

export async function collectEntrada() {
    const gamepads = safe(() => navigator.getGamepads?.(), []) || [];
    const connected = Array.from(gamepads).filter(Boolean).length;

    return [
        ["Suporte a toque", yesNo("ontouchstart" in window || (navigator.maxTouchPoints || 0) > 0)],
        ["Pontos de toque máx.", navigator.maxTouchPoints ?? NA],
        ["Eventos de ponteiro", yesNo("PointerEvent" in window)],
        ["Gamepads conectados", connected],
        ["Vibração", yesNo(typeof navigator.vibrate === "function")],
        ["Sensor de luz ambiente", yesNo("AmbientLightSensor" in window)],
        ["Giroscópio", yesNo("Gyroscope" in window)],
        ["Acelerômetro", yesNo("Accelerometer" in window)],
        ["Magnetômetro", yesNo("Magnetometer" in window)]
    ];
}
