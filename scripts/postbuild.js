/**
 * SuprSafe postbuild script
 * This script copies the compiled library files to the correct location
 * for Electron to find them.
 */
const fs = require('fs');
const path = require('path');

// Paths
const rootDir = path.resolve(__dirname, '..');
const sourceLibDir = path.join(rootDir, 'dist', 'electron', 'src', 'lib');
const targetLibDir = path.join(rootDir, 'dist', 'src', 'lib');
const publicDir = path.join(rootDir, 'public');
const buildDir = path.join(rootDir, 'build');
const distElectronDir = path.join(rootDir, 'dist', 'electron');

console.log('Running SuprSafe postbuild tasks...');

// Ensure target directories exist
if (!fs.existsSync(targetLibDir)) {
  console.log(`Creating directory: ${targetLibDir}`);
  fs.mkdirSync(targetLibDir, { recursive: true });
}

if (!fs.existsSync(buildDir)) {
  console.log(`Creating directory: ${buildDir}`);
  fs.mkdirSync(buildDir, { recursive: true });
}

// Copy lib files
if (fs.existsSync(sourceLibDir)) {
  console.log(`Copying lib files from ${sourceLibDir} to ${targetLibDir}`);
  
  // Read source directory
  const files = fs.readdirSync(sourceLibDir);
  
  // Copy each file
  for (const file of files) {
    const sourcePath = path.join(sourceLibDir, file);
    const targetPath = path.join(targetLibDir, file);
    
    fs.copyFileSync(sourcePath, targetPath);
    console.log(`Copied: ${file}`);
  }
  
  console.log('File copy complete!');
} else {
  console.error(`Source directory not found: ${sourceLibDir}`);
}

// Copy preload.js and its source map to both public and build directory
// This makes the source map available for DevTools in both dev and prod
const preloadJsSource = path.join(distElectronDir, 'preload.js');
const preloadMapSource = path.join(distElectronDir, 'preload.js.map');

function copyPreloadFiles(targetDir, label) {
  const preloadJsTarget = path.join(targetDir, 'preload.js');
  const preloadMapTarget = path.join(targetDir, 'preload.js.map');
  
  try {
    if (fs.existsSync(preloadJsSource) && fs.existsSync(preloadMapSource)) {
      console.log(`Copying preload files to ${label} directory...`);
      
      // Copy preload.js
      fs.copyFileSync(preloadJsSource, preloadJsTarget);
      
      // Copy and fix source map
      const sourceMapContent = fs.readFileSync(preloadMapSource, 'utf8');
      const sourceMap = JSON.parse(sourceMapContent);
      
      // Update the sources paths to be relative to where the map will be served from
      sourceMap.sources = sourceMap.sources.map(source => {
        return path.basename(source);
      });
      
      fs.writeFileSync(preloadMapTarget, JSON.stringify(sourceMap));
      console.log(`Preload files copied to ${label} directory successfully.`);
    } else {
      console.warn(`Preload source files not found, skipping copy to ${label} directory.`);
    }
  } catch (error) {
    console.error(`Error copying preload files to ${label} directory:`, error);
  }
}

// Copy to public directory (for dev mode)
copyPreloadFiles(publicDir, 'public');

// Copy to build directory (for production)
copyPreloadFiles(buildDir, 'build');

console.log('Postbuild tasks completed.'); 