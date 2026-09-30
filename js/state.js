/* =========================================================
   Estado global compartilhado entre os módulos
   ========================================================= */

export const state = {
    sections: [], // Array de { id, icon, title, subtitle, rows }
    json: {}, // Objeto serializável para exportação
    collecting: false
};
