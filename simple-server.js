// Simple server for testing without MongoDB
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secure-jwt-secret-key';

// In-memory user storage (for testing only)
let users = [];

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// CORS for development
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    next();
});

// Password validation
const validatePassword = (password) => {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) {
        return 'Password must be at least 8 characters long';
    }
    if (!hasUpperCase || !hasLowerCase) {
        return 'Password must contain both uppercase and lowercase letters';
    }
    if (!hasNumbers) {
        return 'Password must contain at least one number';
    }
    if (!hasSpecialChar) {
        return 'Password must contain at least one special character';
    }
    return null;
};

// Email validation
const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

// JWT token generation
const generateToken = (userId) => {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '24h' });
};

// Debug endpoint to see all users
app.get('/api/debug/users', (req, res) => {
    res.json({
        totalUsers: users.length,
        users: users.map(u => ({ id: u.id, name: u.name, email: u.email, createdAt: u.createdAt }))
    });
});

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        console.log('📝 Registration attempt:', { name, email });
        console.log('📊 Current users count:', users.length);

        // Validation
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Please provide a valid email' });
        }

        const passwordError = validatePassword(password);
        if (passwordError) {
            return res.status(400).json({ error: passwordError });
        }

        // Check if user already exists
        const existingUser = users.find(u => u.email === email);
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists with this email' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        const newUser = {
            id: Date.now(),
            name,
            email,
            password: hashedPassword,
            isActive: true,
            createdAt: new Date()
        };

        users.push(newUser);
        console.log('✅ User registered successfully:', email);
        console.log('📊 Total users now:', users.length);
        console.log('📝 User details:', { id: newUser.id, name: newUser.name, email: newUser.email });

        // Generate token
        const token = generateToken(newUser.id);

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: newUser.id,
                name: newUser.name,
                email: newUser.email
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message
        });
    }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        console.log('🔑 Login attempt:', email);
        console.log('📊 Current users in system:', users.length);
        console.log('📝 Available emails:', users.map(u => u.email));

        // Validation
        if (!email || !password) {
            console.log('❌ Missing email or password');
            return res.status(400).json({ error: 'Email and password are required' });
        }

        if (!validateEmail(email)) {
            console.log('❌ Invalid email format:', email);
            return res.status(400).json({ error: 'Please provide a valid email' });
        }

        // Find user
        const user = users.find(u => u.email === email);
        if (!user) {
            console.log('❌ User not found:', email);
            console.log('📝 Available users:', users.map(u => ({ email: u.email, id: u.id })));
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        console.log('✅ User found:', { id: user.id, email: user.email, name: user.name });

        // Check if account is active
        if (!user.isActive) {
            return res.status(401).json({ error: 'Account is deactivated' });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Invalid password for user:', email);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        console.log('Login successful:', email);

        // Generate token
        const token = generateToken(user.id);

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        users: users.length
    });
});

// reCAPTCHA site key endpoint
app.get('/api/recaptcha-key', (req, res) => {
    res.json({
        siteKey: process.env.RECAPTCHA_SITE_KEY || 'development-mode'
    });
});

// Create a test user on startup
async function createTestUser() {
    try {
        const testEmail = 'aleenajomy4@gmail.com';
        const testPassword = 'Aleena@123';
        
        // Check if test user already exists
        const existingUser = users.find(u => u.email === testEmail);
        if (existingUser) {
            console.log('✅ Test user already exists');
            return;
        }

        // Hash password
        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(testPassword, salt);

        // Create test user
        const testUser = {
            id: 1,
            name: 'Aleena Jomy',
            email: testEmail,
            password: hashedPassword,
            isActive: true,
            createdAt: new Date()
        };

        users.push(testUser);
        console.log('✅ Test user created:');
        console.log('   Email:', testEmail);
        console.log('   Password:', testPassword);
    } catch (error) {
        console.error('❌ Error creating test user:', error);
    }
}

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ 
        error: 'Internal server error',
        details: error.message
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, async () => {
    console.log(`🚀 Simple server running on port ${PORT}`);
    console.log(`🔒 Security features enabled (simplified)`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`💾 Using in-memory storage (no MongoDB required)`);
    
    // Create test user
    await createTestUser();
    
    console.log(`🌐 Access the application at: http://localhost:${PORT}`);
});
