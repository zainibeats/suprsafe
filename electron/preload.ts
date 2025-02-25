import { contextBridge, ipcRenderer } from 'electron';

// Define a logger for debugging
const log = (message: string) => {
  console.log(`[Preload] ${message}`);
};

// Log when preload script starts
log('Preload script is loading...');

try {
  // Expose the electron API to the renderer process
  contextBridge.exposeInMainWorld('electronAPI', {
    selectDirectory: () => ipcRenderer.invoke('select-directory'),
    verifyPassword: (password: string) => ipcRenderer.invoke('verify-password', password),
    encryptFiles: (directory: string, password: string, mainKey: string) => 
      ipcRenderer.invoke('encrypt-files', directory, password, mainKey),
    decryptFiles: (directory: string, password: string, mainKey: string) => 
      ipcRenderer.invoke('decrypt-files', directory, password, mainKey),
    getSecuritySettings: () => ipcRenderer.invoke('get-security-settings'),
    updateSecuritySettings: (settings: any, adminPassword?: string) => 
      ipcRenderer.invoke('update-security-settings', settings, adminPassword),
    generateKey: () => ipcRenderer.invoke('generate-key'),
    setSuprSafePlusPassword: (password: string) => 
      ipcRenderer.invoke('set-suprsafe-plus-password', password),
    verifySuprSafePlusPassword: (password: string) => 
      ipcRenderer.invoke('verify-suprsafe-plus-password', password),
  });
  
  // Log success
  log('API successfully exposed');
} catch (error) {
  // Log any errors
  console.error('[Preload] Failed to expose API:', error);
}

// Log when preload script completes
log('Preload script completed'); 