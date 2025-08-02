// Ultra-simple test server - guaranteed to work
const express = require('express');
const path = require('path');

const app = express();
const PORT = 3000;

// Simple in-memory users
const users = [
    { email: 'test@test.com', password: 'password123', name: 'Test User' },
    { email: 'admin@admin.com', password: 'admin123', name: 'Admin User' }
];

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Enable CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', '*');
    res.header('Access-Control-Allow-Methods', '*');
    next();
});

// Test endpoint
app.get('/api/test', (req, res) => {
    console.log('✅ Test endpoint called');
    res.json({ 
        message: 'Server is working!', 
        time: new Date().toISOString(),
        users: users.length
    });
});

// Simple login endpoint
app.post('/api/auth/login', (req, res) => {
    console.log('🔑 Login request received');
    console.log('📝 Request body:', req.body);
    
    const { email, password } = req.body;
    
    if (!email || !password) {
        console.log('❌ Missing email or password');
        return res.status(400).json({ error: 'Email and password required' });
    }
    
    // Find user
    const user = users.find(u => u.email === email && u.password === password);
    
    if (!user) {
        console.log('❌ Invalid credentials for:', email);
        console.log('📋 Available users:', users.map(u => u.email));
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    console.log('✅ Login successful for:', email);
    res.json({
        message: 'Login successful',
        user: { name: user.name, email: user.email }
    });
});

// Simple registration endpoint
app.post('/api/auth/register', (req, res) => {
    console.log('📝 Registration request received');
    console.log('📝 Request body:', req.body);
    
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'All fields required' });
    }
    
    // Check if user exists
    if (users.find(u => u.email === email)) {
        return res.status(400).json({ error: 'User already exists' });
    }
    
    // Add user
    const newUser = { name, email, password };
    users.push(newUser);
    
    console.log('✅ User registered:', email);
    console.log('📊 Total users:', users.length);
    
    res.json({
        message: 'Registration successful',
        user: { name, email }
    });
});

// List all users (for debugging)
app.get('/api/users', (req, res) => {
    res.json({
        total: users.length,
        users: users.map(u => ({ name: u.name, email: u.email }))
    });
});

// Start server
app.listen(PORT, () => {
    console.log('🚀 ULTRA-SIMPLE SERVER STARTED');
    console.log(`📍 URL: http://localhost:${PORT}`);
    console.log('🧪 Test users:');
    console.log('   Email: test@test.com, Password: password123');
    console.log('   Email: admin@admin.com, Password: admin123');
    console.log('');
    console.log('🔧 Test endpoints:');
    console.log(`   GET  http://localhost:${PORT}/api/test`);
    console.log(`   GET  http://localhost:${PORT}/api/users`);
    console.log(`   POST http://localhost:${PORT}/api/auth/login`);
    console.log(`   POST http://localhost:${PORT}/api/auth/register`);
    console.log('');
    console.log('✅ Server is ready!');
});
