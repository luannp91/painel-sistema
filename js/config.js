export const STORAGE_KEYS = {
    theme: "sysinfo-theme"
};

export const SECTIONS_META = {
    sistema: { icon: "🖥️", title: "Sistema Operacional", subtitle: "Plataforma e recursos do dispositivo" },
    navegador: { icon: "🌐", title: "Navegador", subtitle: "Aplicação que está executando o painel" },
    firefox: { icon: "🦊", title: "Firefox — Detalhes", subtitle: "Informações exclusivas do Firefox" }, // NOVO
    tela: { icon: "📺", title: "Tela & Display", subtitle: "Resolução, densidade e capacidades" },
    gpu: { icon: "🎮", title: "GPU & WebGL", subtitle: "Placa gráfica exposta pelo WebGL" },
    rede: { icon: "📡", title: "Rede & Conectividade", subtitle: "Estado e qualidade da conexão" },
    bateria: { icon: "🔋", title: "Bateria", subtitle: "Status de energia do dispositivo" },
    armazenamento: { icon: "💾", title: "Armazenamento & Memória", subtitle: "Cotas e uso de memória" },
    midia: { icon: "🎙️", title: "Mídia & Dispositivos", subtitle: "Câmeras, microfones e saídas" },
    entrada: { icon: "🖱️", title: "Sensores & Entrada", subtitle: "Toque, ponteiros e sensores" },
    preferencias: { icon: "🎨", title: "Preferências do Usuário", subtitle: "Acessibilidade e aparência" },
    tempo: { icon: "⏰", title: "Tempo & Localização", subtitle: "Fuso horário e formatos" },
    permissoes: { icon: "🔐", title: "Permissões", subtitle: "Estado das permissões do site" },
    recursos: { icon: "🧩", title: "Recursos & Codecs", subtitle: "APIs e formatos suportados" }
};

/* NOVO — Agrupamento visual dos cards */
export const GROUPS = [
    {
        id: "sistema",
        title: "Sistema & Hardware",
        icon: "🖥️",
        sections: ["sistema", "tela", "gpu", "armazenamento"]
    },
    {
        id: "conectividade",
        title: "Rede & Energia",
        icon: "📡",
        sections: ["rede", "bateria"]
    },
    {
        id: "software",
        title: "Navegador & Recursos",
        icon: "🌐",
        sections: ["navegador", "firefox", "recursos", "permissoes"]
    },
    {
        id: "ambiente",
        title: "Dispositivos & Ambiente",
        icon: "🎛️",
        sections: ["midia", "entrada", "preferencias", "tempo"]
    }
];

export const PERMISSION_NAMES = [
    "geolocation",
    "notifications",
    "camera",
    "microphone",
    "clipboard-read",
    "clipboard-write",
    "midi",
    "push",
    "screen-wake-lock",
    "persistent-storage",
    "background-sync",
    "accelerometer",
    "gyroscope",
    "magnetometer"
];

export const CODECS = [
    ["H.264 (MP4)", 'video/mp4; codecs="avc1.42E01E"'],
    ["VP9 (WebM)", 'video/webm; codecs="vp9"'],
    ["AV1", 'video/mp4; codecs="av01.0.05M.08"'],
    ["HEVC (H.265)", 'video/mp4; codecs="hvc1.1.6.L93.B0"'],
    ["Opus", 'audio/webm; codecs="opus"'],
    ["AAC", 'audio/mp4; codecs="mp4a.40.2"'],
    ["FLAC", "audio/flac"]
];

export const REFRESH_RATE_SAMPLE_MS = 420;
