"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const electron_1 = require("electron");
electron_1.contextBridge.exposeInMainWorld('electronAPI', {
    selectDirectory: () => electron_1.ipcRenderer.invoke('select-directory'),
    verifyPassword: (password) => electron_1.ipcRenderer.invoke('verify-password', password),
    encryptFiles: (directory, password, mainKey) => electron_1.ipcRenderer.invoke('encrypt-files', directory, password, mainKey),
    decryptFiles: (directory, password, mainKey) => electron_1.ipcRenderer.invoke('decrypt-files', directory, password, mainKey),
    getSecuritySettings: () => electron_1.ipcRenderer.invoke('get-security-settings'),
    updateSecuritySettings: (settings, adminPassword) => electron_1.ipcRenderer.invoke('update-security-settings', settings, adminPassword),
    generateKey: () => electron_1.ipcRenderer.invoke('generate-key'),
    setSuprSafePlusPassword: (password) => electron_1.ipcRenderer.invoke('set-suprsafe-plus-password', password),
    verifySuprSafePlusPassword: (password) => electron_1.ipcRenderer.invoke('verify-suprsafe-plus-password', password),
});
//# sourceMappingURL=preload.js.map