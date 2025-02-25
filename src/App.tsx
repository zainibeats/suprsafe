import React, { useState, useEffect } from 'react';
import { Shield, Lock, Unlock, Settings } from 'lucide-react';

// Define types for our API
type SecuritySettings = {
  wipeFilesAfterMaxAttempts: boolean;
};

// Add type definitions for functions we need
interface SuprSafeAPI {
  selectDirectory: () => Promise<string | null>;
  verifyPassword: (password: string) => Promise<boolean>;
  encryptFiles: (directory: string, password: string, mainKey: string) => Promise<boolean>;
  decryptFiles: (directory: string, password: string, mainKey: string) => Promise<boolean>;
  getSecuritySettings: () => Promise<SecuritySettings>;
  updateSecuritySettings: (settings: SecuritySettings, adminPassword?: string) => Promise<{
    success: boolean;
    reason?: string;
  }>;
  generateKey: () => Promise<string>;
  setSuprSafePlusPassword: (password: string) => Promise<boolean>;
  verifySuprSafePlusPassword: (password: string) => Promise<boolean>;
}

function App() {
  // State
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [action, setAction] = useState<'encrypt' | 'decrypt' | null>(null);
  const [directory, setDirectory] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [mainKey, setMainKey] = useState('');
  const [showPasswordPrompt, setShowPasswordPrompt] = useState(false);
  const [securitySettings, setSecuritySettings] = useState<SecuritySettings>({
    wipeFilesAfterMaxAttempts: false,
  });
  const [showSettings, setShowSettings] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [showKeyGenerator, setShowKeyGenerator] = useState(false);
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  
  // Add state for SuprSafe+ admin password
  const [adminPassword, setAdminPassword] = useState('');
  const [confirmAdminPassword, setConfirmAdminPassword] = useState('');
  const [hasAdminPassword, setHasAdminPassword] = useState(false);
  const [showSetAdminPassword, setShowSetAdminPassword] = useState(false);

  // Get a typed reference to our API
  const api = window.electronAPI as unknown as SuprSafeAPI;

  // Load security settings on mount
  useEffect(() => {
    const loadSettings = async () => {
      try {
        const settings = await api.getSecuritySettings();
        setSecuritySettings(settings);
      } catch (error) {
        console.error("Failed to load settings:", error);
      }
    };
    loadSettings();
    
    // Check system preference for dark mode
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      setIsDarkMode(true);
      document.body.classList.add('dark');
    }
  }, []);

  // Check if SuprSafe+ admin password exists
  useEffect(() => {
    const checkAdminPassword = async () => {
      try {
        // We'll use a dummy verification to check if an admin password exists
        // This will fail if no password exists, which is expected
        const result = await api.verifySuprSafePlusPassword('check_existence_only');
        setHasAdminPassword(result || false);
      } catch (error) {
        console.error("Failed to check admin password status:", error);
        setHasAdminPassword(false);
      }
    };
    
    checkAdminPassword();
  }, []);

  // Toggle dark mode
  const toggleDarkMode = () => {
    setIsDarkMode(!isDarkMode);
    document.body.classList.toggle('dark', !isDarkMode);
  };

  // Handle directory selection
  const handleSelectDirectory = async () => {
    const selectedDir = await api.selectDirectory();
    if (selectedDir) {
      setDirectory(selectedDir);
      setShowPasswordPrompt(true);
    }
  };

  // Handle password submission
  const handlePasswordSubmit = async () => {
    if (!password) {
      setError('Please enter your password');
      return;
    }
    
    if (!mainKey) {
      setError('Please enter your main key');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const isVerified = await api.verifyPassword(password);
      
      if (isVerified) {
        if (action === 'encrypt') {
          const success = await api.encryptFiles(directory!, password, mainKey);
          if (success) {
            setSuccess('Files encrypted successfully!');
            resetForm();
          } else {
            setError('Failed to encrypt files');
          }
        } else if (action === 'decrypt') {
          const success = await api.decryptFiles(directory!, password, mainKey);
          if (success) {
            setSuccess('Files decrypted successfully!');
            resetForm();
          } else {
            setError('Failed to decrypt files');
          }
        }
      } else {
        setError('Invalid password');
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : 'An error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  // Generate a new key
  const handleGenerateKey = async () => {
    try {
      const key = await api.generateKey();
      setGeneratedKey(key);
    } catch (error) {
      setError('Failed to generate key');
    }
  };

  // Reset form
  const resetForm = () => {
    setAction(null);
    setDirectory(null);
    setPassword('');
    setMainKey('');
    setShowPasswordPrompt(false);
  };

  // Handle security settings update
  const handleUpdateSettings = async () => {
    setError(null);
    
    try {
      // If SuprSafe+ mode is being enabled, ensure we have an admin password
      if (securitySettings.wipeFilesAfterMaxAttempts && !hasAdminPassword) {
        setShowSetAdminPassword(true);
        return;
      }
      
      // Otherwise, update settings with the admin password
      const result = await api.updateSecuritySettings(
        securitySettings, 
        hasAdminPassword ? adminPassword : undefined
      );
      
      if (result.success) {
        setSuccess('Settings updated successfully!');
        setShowSettings(false);
        setAdminPassword('');
      } else {
        if (result.reason === 'admin_password_required') {
          setError('Admin password is required to change security settings.');
        } else if (result.reason === 'invalid_admin_password') {
          setError('Invalid admin password. Please try again.');
        } else {
          setError('Failed to update settings. Please try again.');
        }
      }
    } catch (error) {
      setError('Failed to update settings. Please try again.');
    }
  };
  
  // Handle setting the admin password
  const handleSetAdminPassword = async () => {
    setError(null);
    
    if (adminPassword.length < 8) {
      setError('Admin password must be at least 8 characters long.');
      return;
    }
    
    if (adminPassword !== confirmAdminPassword) {
      setError('Passwords do not match.');
      return;
    }
    
    try {
      const success = await api.setSuprSafePlusPassword(adminPassword);
      
      if (success) {
        setHasAdminPassword(true);
        setSuccess('Admin password set successfully!');
        setShowSetAdminPassword(false);
        
        // Continue with enabling SuprSafe+ mode
        const result = await api.updateSecuritySettings(securitySettings);
        
        if (result.success) {
          setSuccess('Settings updated successfully!');
          setShowSettings(false);
        } else {
          setError('Failed to update settings after setting admin password.');
        }
      } else {
        setError('Failed to set admin password. Please try again.');
      }
    } catch (error) {
      setError('Failed to set admin password. Please try again.');
    }
  };

  return (
    <div className={`min-h-screen ${isDarkMode ? 'dark bg-truefa-dark' : 'bg-truefa-light'}`}>
      {/* Header */}
      <header className={`fixed top-0 left-0 right-0 ${isDarkMode ? 'bg-gray-800' : 'bg-white'} shadow-sm z-10`}>
        <div className="container mx-auto px-4 h-12 flex items-center justify-between max-w-6xl">
          {/* Left side buttons */}
          <div className="flex items-center space-x-2 w-1/3">
            {/* Settings button */}
            <button
              onClick={() => setShowSettings(true)}
              className={`group relative p-2 rounded-md ${
                isDarkMode 
                  ? 'text-gray-300 hover:text-white hover:bg-gray-700' 
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
              }`}
              title="Security Settings"
            >
              <Settings className="w-5 h-5" />
              <span className="absolute left-0 top-full mt-1 px-2 py-1 bg-black/75 text-white text-xs rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none">
                Security Settings
              </span>
            </button>
            
            {/* Key Generator button */}
            <button
              onClick={() => setShowKeyGenerator(true)}
              className={`group relative p-2 rounded-md ${
                isDarkMode 
                  ? 'text-gray-300 hover:text-white hover:bg-gray-700' 
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
              }`}
              title="Key Generator"
            >
              <Shield className="w-5 h-5" />
              <span className="absolute left-0 top-full mt-1 px-2 py-1 bg-black/75 text-white text-xs rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none">
                Key Generator
              </span>
            </button>
          </div>

          {/* Center title */}
          <div className="flex-shrink-0">
            <h1 className={`text-lg font-bold px-4 py-1 rounded-lg ${
              isDarkMode 
                ? 'text-white bg-gray-700/50' 
                : 'text-truefa-dark bg-gray-100/50'
            }`}>
              SuprSafe
            </h1>
          </div>

          {/* Right side - Dark mode toggle */}
          <div className="flex items-center justify-end w-1/3">
            <button
              onClick={toggleDarkMode}
              className={`p-2 rounded-md ${
                isDarkMode 
                  ? 'text-gray-300 hover:text-white hover:bg-gray-700' 
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
              }`}
              title={isDarkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            >
              {isDarkMode ? '☀️' : '🌙'}
            </button>
          </div>
        </div>
      </header>

      {/* Success notification */}
      {success && (
        <div className="fixed top-14 right-4 flex items-center space-x-2 bg-green-500 text-white px-4 py-2 rounded-lg shadow-lg animate-fade-out z-50">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          <span>{success}</span>
        </div>
      )}

      {/* Main content */}
      <div className="pt-14 pb-2 px-2 min-h-screen max-w-7xl mx-auto flex items-center justify-center">
        {showPasswordPrompt ? (
          /* Password prompt */
          <div className={`${isDarkMode ? 'bg-gray-800 text-white' : 'bg-white'} rounded-lg shadow-xl max-w-md w-full p-6`}>
            <h2 className="text-xl font-bold mb-4">{action === 'encrypt' ? 'Encrypt Files' : 'Decrypt Files'}</h2>
            
            {error && (
              <div className="p-3 bg-red-50 text-red-700 rounded-lg text-sm mb-4">
                {error}
              </div>
            )}
            
            <div className="space-y-4">
              <div>
                <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-truefa-gray'} mb-1`}>
                  Selected Directory
                </label>
                <div className={`p-2 border rounded-lg ${isDarkMode ? 'bg-gray-700 border-gray-600 text-white' : 'border-gray-300'}`}>
                  {directory}
                </div>
              </div>
              
              <div>
                <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-truefa-gray'} mb-1`}>
                  Account Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={`w-full p-2 border rounded-lg focus:ring-2 focus:ring-[#C9E7F8] focus:border-transparent ${
                    isDarkMode ? 'bg-gray-700 border-gray-600 text-white' : 'border-gray-300'
                  }`}
                  placeholder="Enter your account password"
                />
              </div>
              
              <div>
                <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-truefa-gray'} mb-1`}>
                  Main Key
                </label>
                <input
                  type="password"
                  value={mainKey}
                  onChange={(e) => setMainKey(e.target.value)}
                  className={`w-full p-2 border rounded-lg focus:ring-2 focus:ring-[#C9E7F8] focus:border-transparent ${
                    isDarkMode ? 'bg-gray-700 border-gray-600 text-white' : 'border-gray-300'
                  }`}
                  placeholder="Enter your 32-character main key"
                />
              </div>
              
              <div className="flex space-x-2">
                <button
                  onClick={resetForm}
                  className={`py-2 px-4 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-300 focus:ring-offset-2 ${
                    isDarkMode ? 'bg-gray-600 text-white hover:bg-gray-500' : ''
                  }`}
                >
                  Cancel
                </button>
                <button
                  onClick={handlePasswordSubmit}
                  disabled={isLoading}
                  className={`flex-1 py-2 px-4 bg-truefa-blue text-white rounded-lg hover:bg-truefa-navy focus:outline-none focus:ring-2 focus:ring-truefa-blue focus:ring-offset-2 ${
                    isDarkMode ? 'bg-gray-700 hover:bg-gray-600' : ''
                  } ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
                >
                  {isLoading ? 'Processing...' : action === 'encrypt' ? 'Encrypt' : 'Decrypt'}
                </button>
              </div>
            </div>
          </div>
        ) : showSettings ? (
          /* Security settings */
          <div className={`${isDarkMode ? 'bg-gray-800 text-white' : 'bg-white'} rounded-lg shadow-xl max-w-md w-full p-6`}>
            <h2 className="text-xl font-bold mb-4">Security Settings</h2>
            
            {error && (
              <div className="p-3 bg-red-50 text-red-700 rounded-lg text-sm mb-4">
                {error}
              </div>
            )}
            
            <div className="space-y-4">
              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="wipeFiles"
                  checked={securitySettings.wipeFilesAfterMaxAttempts}
                  onChange={(e) => setSecuritySettings({
                    ...securitySettings,
                    wipeFilesAfterMaxAttempts: e.target.checked
                  })}
                  className="mr-2"
                />
                <label htmlFor="wipeFiles" className={`text-sm ${isDarkMode ? 'text-gray-300' : 'text-truefa-gray'}`}>
                  Enable SuprSafe+ Mode (wipe files after max attempts)
                </label>
              </div>
              
              <p className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                When enabled, SuprSafe will securely delete all encrypted files if the maximum number of password attempts is reached. This provides an additional layer of security but use with caution.
              </p>
              
              {/* Admin password field - only if we already have an admin password and SuprSafe+ is enabled */}
              {hasAdminPassword && securitySettings.wipeFilesAfterMaxAttempts && (
                <div>
                  <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-truefa-gray'} mb-1`}>
                    Admin Password
                  </label>
                  <input
                    type="password"
                    value={adminPassword}
                    onChange={(e) => setAdminPassword(e.target.value)}
                    placeholder="Enter admin password to confirm changes"
                    className={`w-full p-2 border rounded-lg focus:ring-2 focus:ring-[#C9E7F8] focus:border-transparent ${
                      isDarkMode ? 'bg-gray-700 border-gray-600 text-white' : 'border-gray-300'
                    }`}
                  />
                </div>
              )}
              
              <div className="flex space-x-2">
                <button
                  onClick={() => {
                    setShowSettings(false);
                    setError(null);
                    setAdminPassword('');
                  }}
                  className={`py-2 px-4 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-300 focus:ring-offset-2 ${
                    isDarkMode ? 'bg-gray-600 text-white hover:bg-gray-500' : ''
                  }`}
                >
                  Cancel
                </button>
                <button
                  onClick={handleUpdateSettings}
                  className={`flex-1 py-2 px-4 bg-truefa-blue text-white rounded-lg hover:bg-truefa-navy focus:outline-none focus:ring-2 focus:ring-truefa-blue focus:ring-offset-2 ${
                    isDarkMode ? 'bg-gray-700 hover:bg-gray-600' : ''
                  }`}
                >
                  Save Settings
                </button>
              </div>
            </div>
          </div>
        ) : showKeyGenerator ? (
          /* Key Generator */
          <div className={`${isDarkMode ? 'bg-gray-800 text-white' : 'bg-white'} rounded-lg shadow-xl max-w-md w-full p-6`}>
            <h2 className="text-xl font-bold mb-4">Main Key Generator</h2>
            
            <div className="space-y-4">
              <p className={`text-sm ${isDarkMode ? 'text-gray-300' : 'text-truefa-gray'}`}>
                Generate a secure 32-character key for encryption. Make sure to save this key in a safe place.
              </p>
              
              {generatedKey && (
                <div className={`p-3 ${isDarkMode ? 'bg-gray-700' : 'bg-gray-100'} rounded-lg break-all`}>
                  <p className="text-sm font-mono">{generatedKey}</p>
                </div>
              )}
              
              <div className="flex space-x-2">
                <button
                  onClick={() => setShowKeyGenerator(false)}
                  className={`py-2 px-4 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-300 focus:ring-offset-2 ${
                    isDarkMode ? 'bg-gray-600 text-white hover:bg-gray-500' : ''
                  }`}
                >
                  Close
                </button>
                <button
                  onClick={handleGenerateKey}
                  className={`flex-1 py-2 px-4 bg-truefa-blue text-white rounded-lg hover:bg-truefa-navy focus:outline-none focus:ring-2 focus:ring-truefa-blue focus:ring-offset-2 ${
                    isDarkMode ? 'bg-gray-700 hover:bg-gray-600' : ''
                  }`}
                >
                  Generate Key
                </button>
              </div>
            </div>
          </div>
        ) : (
          /* Main actions */
          <div className={`${isDarkMode ? 'bg-gray-800 text-white' : 'bg-white'} rounded-lg shadow-xl max-w-md w-full p-6`}>
            <div className="flex flex-col items-center mb-8">
              <img src="./assets/suprsafe_png.png" alt="SuprSafe" className="w-20 h-20 mb-4" />
              <h2 className="text-xl font-bold">Welcome to SuprSafe</h2>
              <p className={`text-sm ${isDarkMode ? 'text-gray-300' : 'text-truefa-gray'} mt-2 text-center`}>
                Secure your files with AES-256 encryption
              </p>
            </div>
            
            {error && (
              <div className="p-3 bg-red-50 text-red-700 rounded-lg text-sm mb-4">
                {error}
              </div>
            )}
            
            <div className="space-y-4">
              <button
                onClick={() => {
                  setAction('encrypt');
                  handleSelectDirectory();
                }}
                className={`w-full py-3 px-4 bg-truefa-blue text-white rounded-lg hover:bg-truefa-navy focus:outline-none focus:ring-2 focus:ring-truefa-blue focus:ring-offset-2 flex items-center justify-center space-x-2 ${
                  isDarkMode ? 'bg-gray-700 hover:bg-gray-600' : ''
                }`}
              >
                <Lock className="w-5 h-5" />
                <span>Encrypt Files</span>
              </button>
              
              <button
                onClick={() => {
                  setAction('decrypt');
                  handleSelectDirectory();
                }}
                className={`w-full py-3 px-4 bg-green-500 text-white rounded-lg hover:bg-green-600 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 flex items-center justify-center space-x-2 ${
                  isDarkMode ? 'bg-gray-600 hover:bg-gray-500' : ''
                }`}
              >
                <Unlock className="w-5 h-5" />
                <span>Decrypt Files</span>
              </button>
              
              <button
                onClick={() => setShowSettings(true)}
                className={`w-full py-3 px-4 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-300 focus:ring-offset-2 flex items-center justify-center space-x-2 ${
                  isDarkMode ? 'bg-gray-600 text-white hover:bg-gray-500' : ''
                }`}
              >
                <Settings className="w-5 h-5" />
                <span>Security Settings</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Set Admin Password UI */}
      {showSetAdminPassword && (
        <div className={`${isDarkMode ? 'bg-gray-800 text-white' : 'bg-white'} rounded-lg shadow-xl max-w-md w-full p-6`}>
          <h2 className="text-xl font-bold mb-4">Set SuprSafe+ Admin Password</h2>
          
          {error && (
            <div className="p-3 bg-red-50 text-red-700 rounded-lg text-sm mb-4">
              {error}
            </div>
          )}
          
          <div className="space-y-4">
            <p className={`text-sm ${isDarkMode ? 'text-gray-300' : 'text-truefa-gray'}`}>
              SuprSafe+ mode requires a separate administrator password. This password should be different from your account password for maximum security.
            </p>
            
            <div>
              <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-truefa-gray'} mb-1`}>
                Admin Password
              </label>
              <input
                type="password"
                value={adminPassword}
                onChange={(e) => setAdminPassword(e.target.value)}
                className={`w-full p-2 border rounded-lg focus:ring-2 focus:ring-[#C9E7F8] focus:border-transparent ${
                  isDarkMode ? 'bg-gray-700 border-gray-600 text-white' : 'border-gray-300'
                }`}
                placeholder="Enter admin password (min 8 characters)"
              />
            </div>
            
            <div>
              <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-truefa-gray'} mb-1`}>
                Confirm Admin Password
              </label>
              <input
                type="password"
                value={confirmAdminPassword}
                onChange={(e) => setConfirmAdminPassword(e.target.value)}
                className={`w-full p-2 border rounded-lg focus:ring-2 focus:ring-[#C9E7F8] focus:border-transparent ${
                  isDarkMode ? 'bg-gray-700 border-gray-600 text-white' : 'border-gray-300'
                }`}
                placeholder="Confirm admin password"
              />
            </div>
            
            <div className="flex space-x-2">
              <button
                onClick={() => {
                  setShowSetAdminPassword(false);
                  setShowSettings(true);
                  setError(null);
                  setAdminPassword('');
                  setConfirmAdminPassword('');
                  
                  // Revert the SuprSafe+ mode checkbox since we cancelled setting the password
                  setSecuritySettings({
                    ...securitySettings,
                    wipeFilesAfterMaxAttempts: false
                  });
                }}
                className={`py-2 px-4 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-300 focus:ring-offset-2 ${
                  isDarkMode ? 'bg-gray-600 text-white hover:bg-gray-500' : ''
                }`}
              >
                Cancel
              </button>
              <button
                onClick={handleSetAdminPassword}
                className={`flex-1 py-2 px-4 bg-truefa-blue text-white rounded-lg hover:bg-truefa-navy focus:outline-none focus:ring-2 focus:ring-truefa-blue focus:ring-offset-2 ${
                  isDarkMode ? 'bg-gray-700 hover:bg-gray-600' : ''
                }`}
              >
                Set Password
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App; 