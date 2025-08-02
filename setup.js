#!/usr/bin/env node

/**
 * Setup Script for Secure Web Authentication System
 * This script helps set up the project with proper configuration
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// Colors for console output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m'
};

function colorLog(message, color = 'reset') {
    console.log(`${colors[color]}${message}${colors.reset}`);
}

function generateSecretKey(length = 64) {
    return crypto.randomBytes(length).toString('hex');
}

function createDirectoryIfNotExists(dirPath) {
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
        colorLog(`✅ Created directory: ${dirPath}`, 'green');
    }
}

function copyFile(source, destination) {
    if (!fs.existsSync(destination)) {
        fs.copyFileSync(source, destination);
        colorLog(`✅ Created file: ${destination}`, 'green');
    } else {
        colorLog(`⚠️  File already exists: ${destination}`, 'yellow');
    }
}

async function askQuestion(question) {
    return new Promise((resolve) => {
        rl.question(question, (answer) => {
            resolve(answer.trim());
        });
    });
}

async function setupEnvironment() {
    colorLog('\n🔧 Setting up environment configuration...', 'cyan');
    
    const envPath = '.env';
    
    if (fs.existsSync(envPath)) {
        const overwrite = await askQuestion('⚠️  .env file already exists. Overwrite? (y/N): ');
        if (overwrite.toLowerCase() !== 'y') {
            colorLog('Skipping environment setup.', 'yellow');
            return;
        }
    }
    
    colorLog('\n📝 Please provide the following information:', 'blue');
    
    const config = {
        NODE_ENV: await askQuestion('Environment (development/production) [development]: ') || 'development',
        PORT: await askQuestion('Server port [3000]: ') || '3000',
        MONGODB_URI: await askQuestion('MongoDB URI [mongodb://localhost:27017/secure-auth]: ') || 'mongodb://localhost:27017/secure-auth',
        CLIENT_URL: '',
        JWT_SECRET: generateSecretKey(),
        SESSION_SECRET: generateSecretKey()
    };
    
    if (config.NODE_ENV === 'production') {
        config.CLIENT_URL = await askQuestion('Client URL (e.g., https://yourdomain.com): ');
    } else {
        config.CLIENT_URL = `http://localhost:${config.PORT}`;
    }
    
    const envContent = `# Environment Configuration
NODE_ENV=${config.NODE_ENV}

# Server Configuration
PORT=${config.PORT}
CLIENT_URL=${config.CLIENT_URL}

# Database Configuration
MONGODB_URI=${config.MONGODB_URI}

# Security Keys (Auto-generated - Keep these secure!)
JWT_SECRET=${config.JWT_SECRET}
SESSION_SECRET=${config.SESSION_SECRET}

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
AUTH_RATE_LIMIT_MAX=5

# Session Configuration
SESSION_MAX_AGE=86400000

# Security Headers
ENABLE_HTTPS_REDIRECT=${config.NODE_ENV === 'production'}
ENABLE_HSTS=true

# Logging
LOG_LEVEL=info
LOG_FILE=logs/app.log
`;
    
    fs.writeFileSync(envPath, envContent);
    colorLog(`✅ Created ${envPath} with your configuration`, 'green');
    colorLog('🔑 Generated secure JWT and Session secrets', 'green');
}

function createDirectories() {
    colorLog('\n📁 Creating project directories...', 'cyan');
    
    const directories = [
        'logs',
        'tests',
        'docs',
        'public',
        'uploads'
    ];
    
    directories.forEach(createDirectoryIfNotExists);
}

function createGitignore() {
    colorLog('\n📝 Creating .gitignore...', 'cyan');
    
    const gitignoreContent = `# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Logs
logs/
*.log

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/
*.lcov

# nyc test coverage
.nyc_output

# Dependency directories
node_modules/
jspm_packages/

# Optional npm cache directory
.npm

# Optional REPL history
.node_repl_history

# Output of 'npm pack'
*.tgz

# Yarn Integrity file
.yarn-integrity

# dotenv environment variables file
.env

# next.js build output
.next

# Nuxt.js build output
.nuxt

# vuepress build output
.vuepress/dist

# Serverless directories
.serverless

# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Uploads
uploads/*
!uploads/.gitkeep

# Build files
dist/
build/

# Database
*.sqlite
*.db
`;
    
    const gitignorePath = '.gitignore';
    if (!fs.existsSync(gitignorePath)) {
        fs.writeFileSync(gitignorePath, gitignoreContent);
        colorLog('✅ Created .gitignore', 'green');
    } else {
        colorLog('⚠️  .gitignore already exists', 'yellow');
    }
}

function createKeepFiles() {
    colorLog('\n📄 Creating .gitkeep files...', 'cyan');
    
    const keepFiles = [
        'logs/.gitkeep',
        'uploads/.gitkeep'
    ];
    
    keepFiles.forEach(file => {
        if (!fs.existsSync(file)) {
            fs.writeFileSync(file, '');
            colorLog(`✅ Created ${file}`, 'green');
        }
    });
}

function createStartScript() {
    colorLog('\n🚀 Creating start script...', 'cyan');
    
    const startScriptContent = `#!/bin/bash

# Secure Web Authentication System Start Script

echo "🔐 Starting Secure Web Authentication System..."

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ .env file not found. Please run 'npm run setup' first."
    exit 1
fi

# Check if MongoDB is running (optional check)
# Uncomment the following lines if you want to check MongoDB connection
# echo "🔍 Checking MongoDB connection..."
# mongosh --eval "db.runCommand('ping')" --quiet > /dev/null 2>&1
# if [ $? -ne 0 ]; then
#     echo "⚠️  Warning: Cannot connect to MongoDB. Make sure it's running."
# fi

# Start the application
if [ "$NODE_ENV" = "production" ]; then
    echo "🚀 Starting in production mode..."
    npm start
else
    echo "🛠️  Starting in development mode..."
    npm run dev
fi
`;
    
    const startScriptPath = 'start.sh';
    fs.writeFileSync(startScriptPath, startScriptContent);
    
    // Make script executable on Unix systems
    if (process.platform !== 'win32') {
        fs.chmodSync(startScriptPath, '755');
    }
    
    colorLog('✅ Created start.sh script', 'green');
}

function displayNextSteps() {
    colorLog('\n🎉 Setup completed successfully!', 'green');
    colorLog('\n📋 Next steps:', 'cyan');
    colorLog('1. Make sure MongoDB is running on your system', 'blue');
    colorLog('2. Install dependencies: npm install', 'blue');
    colorLog('3. Start the application: npm run dev', 'blue');
    colorLog('4. Open your browser and go to http://localhost:3000', 'blue');
    colorLog('\n🔧 Additional commands:', 'cyan');
    colorLog('• npm start          - Start in production mode', 'blue');
    colorLog('• npm run dev        - Start in development mode', 'blue');
    colorLog('• npm test           - Run tests', 'blue');
    colorLog('• npm run lint       - Run code linting', 'blue');
    colorLog('• npm run security-audit - Run security audit', 'blue');
    colorLog('\n📚 Documentation:', 'cyan');
    colorLog('• README.md contains detailed information', 'blue');
    colorLog('• Check the docs/ directory for additional guides', 'blue');
    colorLog('\n🔒 Security Notes:', 'yellow');
    colorLog('• Your JWT and Session secrets have been auto-generated', 'yellow');
    colorLog('• Keep your .env file secure and never commit it to version control', 'yellow');
    colorLog('• Review the security features in README.md', 'yellow');
    colorLog('\n🐛 Need help?', 'magenta');
    colorLog('• Check the troubleshooting section in README.md', 'magenta');
    colorLog('• Create an issue on GitHub if you encounter problems', 'magenta');
}

async function main() {
    try {
        colorLog('🔐 Secure Web Authentication System Setup', 'bright');
        colorLog('=========================================', 'bright');
        
        colorLog('\nThis setup script will help you configure your secure web application.', 'blue');
        colorLog('It will create necessary files and directories for the project.\n', 'blue');
        
        const proceed = await askQuestion('Do you want to continue with the setup? (Y/n): ');
        if (proceed.toLowerCase() === 'n') {
            colorLog('Setup cancelled.', 'yellow');
            rl.close();
            return;
        }
        
        // Run setup steps
        await setupEnvironment();
        createDirectories();
        createGitignore();
        createKeepFiles();
        createStartScript();
        
        displayNextSteps();
        
    } catch (error) {
        colorLog(`\n❌ Setup failed: ${error.message}`, 'red');
        console.error(error);
    } finally {
        rl.close();
    }
}

// Run the setup if this script is executed directly
if (require.main === module) {
    main();
}

module.exports = {
    generateSecretKey,
    createDirectoryIfNotExists,
    setupEnvironment
};