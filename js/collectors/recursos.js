import { CODECS } from "../config.js";
import { yesNo } from "../utils/format.js";

export async function collectRecursos() {
    const rows = [];

    for (const [label, type] of CODECS) {
        rows.push([label, yesNo(MediaSource.isTypeSupported?.(type))]);
    }

    rows.push(["WebAssembly", yesNo(typeof WebAssembly === "object")]);
    rows.push(["Service Worker", yesNo("serviceWorker" in navigator)]);
    rows.push(["WebRTC", yesNo(!!window.RTCPeerConnection)]);
    rows.push(["Notificações", yesNo("Notification" in window)]);
    rows.push(["Geolocalização", yesNo("geolocation" in navigator)]);
    rows.push(["Bluetooth", yesNo("bluetooth" in navigator)]);
    rows.push(["USB", yesNo("usb" in navigator)]);
    rows.push(["Serial", yesNo("serial" in navigator)]);
    rows.push(["Web Share", yesNo(!!navigator.share)]);

    return rows;
}
