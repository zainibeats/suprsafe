import { app, BrowserWindow, ipcMain, dialog, session } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as os from 'os';
import { CryptoUtils } from '../src/lib/crypto';
import { secureWipeBuffer, createTempState, cleanupTempState } from '../src/lib/secureMemory';
import { executePythonOperation } from '../src/lib/pythonBridge';

// Secure storage paths
const APP_DATA_DIR = path.join(os.homedir(), 'AppData', 'Roaming', 'SuprSafe', 'data');
const PASSWORD_HASH_PATH = path.join(APP_DATA_DIR, 'password_hash.bin');
const SECURITY_CONFIG_PATH = path.join(APP_DATA_DIR, 'security_config.bin');
const SALT_PATH = path.join(APP_DATA_DIR, 'salt.bin');
// Add path for SuprSafe+ admin password
const SUPRSAFE_PLUS_PASSWORD_PATH = path.join(APP_DATA_DIR, 'suprsafe_plus_password.bin');

// Ensure app data directory exists
if (!fs.existsSync(APP_DATA_DIR)) {
  fs.mkdirSync(APP_DATA_DIR, { recursive: true });
}

// Security settings interface
interface SecuritySettings {
  wipeFilesAfterMaxAttempts: boolean;
}

// Default security settings
const DEFAULT_SECURITY_SETTINGS: SecuritySettings = {
  wipeFilesAfterMaxAttempts: false,
};

// Track failed password attempts for security
const passwordAttempts = {
  count: 0,
  maxAttempts: 3,
  resetTimer: null as NodeJS.Timeout | null
};

let mainWindow: BrowserWindow | null = null;

// Add this function to check if the dev server is running
async function isDevServerRunning() {
  return new Promise<boolean>((resolve) => {
    const request = require('http').request(
      { method: 'HEAD', hostname: 'localhost', port: 3000, path: '/' },
      (response: { statusCode: number }) => {
        resolve(response.statusCode === 200);
      }
    );
    request.on('error', () => {
      resolve(false);
    });
    request.end();
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 700,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      // Add these security options
      webSecurity: true,
      allowRunningInsecureContent: false,
    },
  });

  // Set Content-Security-Policy
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
        ]
      }
    });
  });

  // In dev mode, check if the dev server is actually running
  if (!app.isPackaged) {
    isDevServerRunning().then(isRunning => {
      if (isRunning) {
        console.log('Loading from dev server at http://localhost:3000');
        mainWindow?.loadURL('http://localhost:3000');
        mainWindow?.webContents.openDevTools();
      } else {
        console.log('Dev server not running, loading from local build');
        mainWindow?.loadFile(path.join(__dirname, '../build/index.html'));
      }
    });
  } else {
    // In production
    mainWindow?.loadFile(path.join(__dirname, '../build/index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});

// IPC Handlers
ipcMain.handle('select-directory', async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({
    properties: ['openDirectory'],
  });
  if (canceled) {
    return null;
  } else {
    return filePaths[0];
  }
});

// Verify or set up password
ipcMain.handle('verify-password', async (event, password) => {
  // Check if password hash exists
  if (!fs.existsSync(PASSWORD_HASH_PATH) || !fs.existsSync(SALT_PATH)) {
    // First run, set up password
    const salt = crypto.randomBytes(16);
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
    
    fs.writeFileSync(PASSWORD_HASH_PATH, hash);
    fs.writeFileSync(SALT_PATH, salt);
    
    // Initialize security settings
    fs.writeFileSync(
      SECURITY_CONFIG_PATH,
      JSON.stringify(DEFAULT_SECURITY_SETTINGS)
    );
    
    passwordAttempts.count = 0;
    return true;
  }
  
  // Verify password
  const storedHash = fs.readFileSync(PASSWORD_HASH_PATH);
  const salt = fs.readFileSync(SALT_PATH);
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  
  const isValid = crypto.timingSafeEqual(hash, storedHash);
  
  // Manage failed attempts
  if (isValid) {
    passwordAttempts.count = 0;
  } else {
    passwordAttempts.count++;
    
    // Reset counter after 15 minutes if timer not already running
    if (!passwordAttempts.resetTimer) {
      passwordAttempts.resetTimer = setTimeout(() => {
        passwordAttempts.count = 0;
        passwordAttempts.resetTimer = null;
      }, 15 * 60 * 1000);
    }
    
    // Check if we need to wipe files after max attempts
    const settings = getSecuritySettings();
    if (settings.wipeFilesAfterMaxAttempts && 
        passwordAttempts.count >= passwordAttempts.maxAttempts) {
      // This would implement wiping encrypted files when SuprSafe+ mode is enabled
      console.log('Max password attempts reached with SuprSafe+ mode enabled');
      // The actual file wiping would be implemented when user tries to encrypt/decrypt
    }
  }
  
  return isValid;
});

// Encrypt files in directory
ipcMain.handle('encrypt-files', async (event, directory, password, mainKey) => {
  try {
    // Create temporary state file to track operation
    createTempState('encrypt', directory);
    
    // Generate AES key and IV
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    // Derive encryption key from main key
    const derivedMainKey = crypto.pbkdf2Sync(mainKey, Buffer.from('SuprSafe'), 100000, 32, 'sha256');
    
    // Encrypt AES key and IV with main key
    const combined = Buffer.concat([aesKey, iv]);
    const encryptedKeyResult = CryptoUtils.encryptData(combined, derivedMainKey);
    
    // Create keys_ivs directory
    const keysDir = path.join(directory, 'keys_ivs');
    if (!fs.existsSync(keysDir)) {
      fs.mkdirSync(keysDir, { recursive: true });
    }
    
    // Save encrypted keys
    const encryptedKeysPath = path.join(keysDir, 'encrypted_keys_ivs.bin');
    fs.writeFileSync(
      encryptedKeysPath,
      Buffer.concat([
        encryptedKeyResult.ciphertext,
        encryptedKeyResult.tag,
        encryptedKeyResult.nonce,
      ])
    );
    
    // Encrypt each file in directory
    const files = fs.readdirSync(directory);
    for (const file of files) {
      const filePath = path.join(directory, file);
      
      // Skip directories and program files
      if (
        fs.statSync(filePath).isDirectory() ||
        file.endsWith('.enc') ||
        file.endsWith('.enc.tag') ||
        file.endsWith('.enc.nonce')
      ) {
        continue;
      }
      
      // Read file data
      const fileData = fs.readFileSync(filePath);
      
      // Encrypt file data
      const encryptedFileResult = CryptoUtils.encryptData(fileData, aesKey);
      
      // Write encrypted file and metadata
      const encryptedFilePath = filePath + '.enc';
      const tagFilePath = filePath + '.enc.tag';
      const nonceFilePath = filePath + '.enc.nonce';
      
      fs.writeFileSync(encryptedFilePath, encryptedFileResult.ciphertext);
      fs.writeFileSync(tagFilePath, encryptedFileResult.tag);
      fs.writeFileSync(nonceFilePath, encryptedFileResult.nonce);
      
      // Securely delete original file
      await secureDelete(filePath);
    }
    
    // Securely wipe sensitive keys from memory
    secureWipeBuffer(aesKey);
    secureWipeBuffer(iv);
    secureWipeBuffer(derivedMainKey);
    
    // Clean up temporary state file
    cleanupTempState(directory);
    
    return true;
  } catch (error) {
    console.error('Encryption error:', error);
    // Clean up temporary state file even if an error occurs
    try {
      cleanupTempState(directory);
    } catch (cleanupError) {
      console.error('Error cleaning up:', cleanupError);
    }
    return false;
  }
});

// Decrypt files in directory
ipcMain.handle('decrypt-files', async (event, directory, password, mainKey) => {
  try {
    // Create temporary state file to track operation
    createTempState('decrypt', directory);
    
    // Derive decryption key from main key
    const derivedMainKey = crypto.pbkdf2Sync(mainKey, Buffer.from('SuprSafe'), 100000, 32, 'sha256');
    
    // Read encrypted keys
    const keysDir = path.join(directory, 'keys_ivs');
    const encryptedKeysPath = path.join(keysDir, 'encrypted_keys_ivs.bin');
    
    if (!fs.existsSync(encryptedKeysPath)) {
      throw new Error('Encrypted keys file not found');
    }
    
    const encryptedKeysData = fs.readFileSync(encryptedKeysPath);
    const ciphertext = encryptedKeysData.slice(0, -32);
    const tag = encryptedKeysData.slice(-32, -16);
    const nonce = encryptedKeysData.slice(-16);
    
    // Decrypt AES key and IV
    const decryptedData = CryptoUtils.decryptData(ciphertext, derivedMainKey, tag, nonce);
    if (!decryptedData) {
      throw new Error('Failed to decrypt keys');
    }
    
    const aesKey = decryptedData.slice(0, 32);
    const iv = decryptedData.slice(32);
    
    // Decrypt each encrypted file in directory
    const files = fs.readdirSync(directory);
    for (const file of files) {
      if (!file.endsWith('.enc')) {
        continue;
      }
      
      const encryptedFilePath = path.join(directory, file);
      const baseFilePath = encryptedFilePath.slice(0, -4); // Remove .enc
      const tagFilePath = baseFilePath + '.enc.tag';
      const nonceFilePath = baseFilePath + '.enc.nonce';
      
      // Verify tag and nonce files exist
      if (!fs.existsSync(tagFilePath) || !fs.existsSync(nonceFilePath)) {
        console.error(`Tag or nonce file missing for ${file}`);
        continue;
      }
      
      // Read encrypted data and metadata
      const encryptedData = fs.readFileSync(encryptedFilePath);
      const tag = fs.readFileSync(tagFilePath);
      const nonce = fs.readFileSync(nonceFilePath);
      
      // Decrypt file
      const decryptedData = CryptoUtils.decryptData(encryptedData, aesKey, tag, nonce);
      if (!decryptedData) {
        console.error(`Failed to decrypt ${file}`);
        continue;
      }
      
      // Write decrypted file
      fs.writeFileSync(baseFilePath, decryptedData);
      
      // Securely delete encrypted files
      await secureDelete(encryptedFilePath);
      await secureDelete(tagFilePath);
      await secureDelete(nonceFilePath);
    }
    
    // Securely wipe sensitive keys from memory
    secureWipeBuffer(aesKey);
    secureWipeBuffer(iv);
    secureWipeBuffer(derivedMainKey);
    
    // Clean up temporary state file
    cleanupTempState(directory);
    
    return true;
  } catch (error) {
    console.error('Decryption error:', error);
    // Clean up temporary state file even if an error occurs
    try {
      cleanupTempState(directory);
    } catch (cleanupError) {
      console.error('Error cleaning up:', cleanupError);
    }
    return false;
  }
});

// Security settings
ipcMain.handle('get-security-settings', async () => {
  return getSecuritySettings();
});

// Function to get security settings
function getSecuritySettings(): SecuritySettings {
  if (!fs.existsSync(SECURITY_CONFIG_PATH)) {
    fs.writeFileSync(
      SECURITY_CONFIG_PATH,
      JSON.stringify(DEFAULT_SECURITY_SETTINGS)
    );
    return DEFAULT_SECURITY_SETTINGS;
  }
  
  try {
    const settingsData = fs.readFileSync(SECURITY_CONFIG_PATH, 'utf8');
    
    // Check if the file is empty or contains only whitespace
    if (!settingsData || settingsData.trim() === '') {
      // Write default settings and return them
      fs.writeFileSync(
        SECURITY_CONFIG_PATH,
        JSON.stringify(DEFAULT_SECURITY_SETTINGS)
      );
      return DEFAULT_SECURITY_SETTINGS;
    }
    
    // Try to parse the JSON
    try {
      return JSON.parse(settingsData);
    } catch (parseError) {
      console.error('Failed to parse security settings JSON:', parseError);
      // Write default settings and return them
      fs.writeFileSync(
        SECURITY_CONFIG_PATH,
        JSON.stringify(DEFAULT_SECURITY_SETTINGS)
      );
      return DEFAULT_SECURITY_SETTINGS;
    }
  } catch (error) {
    console.error('Failed to read security settings:', error);
    return DEFAULT_SECURITY_SETTINGS;
  }
}

// Add new IPC handlers for SuprSafe+ admin password
ipcMain.handle('set-suprsafe-plus-password', async (event, password) => {
  try {
    const salt = crypto.randomBytes(16);
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
    
    // Store salt + hash
    const hashData = Buffer.concat([salt, hash]);
    fs.writeFileSync(SUPRSAFE_PLUS_PASSWORD_PATH, hashData);
    
    return true;
  } catch (error) {
    console.error('Failed to set SuprSafe+ password:', error);
    return false;
  }
});

ipcMain.handle('verify-suprsafe-plus-password', async (event, password) => {
  try {
    if (!fs.existsSync(SUPRSAFE_PLUS_PASSWORD_PATH)) {
      return false;
    }
    
    const hashData = fs.readFileSync(SUPRSAFE_PLUS_PASSWORD_PATH);
    const salt = hashData.slice(0, 16);
    const storedHash = hashData.slice(16);
    
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
    
    return crypto.timingSafeEqual(hash, storedHash);
  } catch (error) {
    console.error('Failed to verify SuprSafe+ password:', error);
    return false;
  }
});

ipcMain.handle('update-security-settings', async (event, settings, adminPassword) => {
  try {
    // Verify admin password first if one exists
    if (fs.existsSync(SUPRSAFE_PLUS_PASSWORD_PATH)) {
      if (!adminPassword) {
        return { success: false, reason: 'admin_password_required' };
      }
      
      const hashData = fs.readFileSync(SUPRSAFE_PLUS_PASSWORD_PATH);
      const salt = hashData.slice(0, 16);
      const storedHash = hashData.slice(16);
      
      const hash = crypto.pbkdf2Sync(adminPassword, salt, 100000, 32, 'sha256');
      
      if (!crypto.timingSafeEqual(hash, storedHash)) {
        return { success: false, reason: 'invalid_admin_password' };
      }
    }
    
    fs.writeFileSync(SECURITY_CONFIG_PATH, JSON.stringify(settings));
    return { success: true };
  } catch (error) {
    console.error('Failed to update security settings:', error);
    return { success: false, reason: 'unknown_error' };
  }
});

// Generate key
ipcMain.handle('generate-key', () => {
  return CryptoUtils.generateRandomKey();
});

// Secure deletion
async function secureDelete(filePath: string): Promise<void> {
  try {
    // Try using the Python implementation first for maximum security
    const result = await executePythonOperation('secure_delete', [filePath]);
    
    if (result.success) {
      return;
    } else {
      console.error('Python secure delete failed, falling back to Node.js implementation:', result.error);
      
      // Fallback to the Node.js implementation
      const fileSize = fs.statSync(filePath).size;
      const fd = fs.openSync(filePath, 'w');
      
      // Write random data 3 times
      for (let i = 0; i < 3; i++) {
        const buffer = crypto.randomBytes(fileSize);
        fs.writeSync(fd, buffer, 0, buffer.length, 0);
        fs.fsyncSync(fd);
      }
      
      fs.closeSync(fd);
      fs.unlinkSync(filePath);
    }
  } catch (error) {
    console.error('Secure delete error:', error);
    throw error;
  }
} 