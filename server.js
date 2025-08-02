// server.js - Secure Node.js Backend
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const path = require('path');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secure-jwt-secret-key';
const SESSION_SECRET = process.env.SESSION_SECRET || 'your-super-secure-session-secret';

// Security Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://www.google.com", "https://www.gstatic.com"],
            scriptSrc: ["'self'", "https://www.google.com", "https://www.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            frameSrc: ["'self'", "https://www.google.com"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// CORS configuration
app.use(cors({
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true,
    optionsSuccessStatus: 200
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs for auth routes
    message: 'Too many authentication attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

app.use(limiter);
app.use('/api/auth', authLimiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/secure-auth'
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'strict'
    }
}));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/secure-auth', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// User Schema
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true,
        minlength: [2, 'Name must be at least 2 characters'],
        maxlength: [50, 'Name cannot exceed 50 characters']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, 'Please provide a valid email']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [8, 'Password must be at least 8 characters']
    },
    isActive: {
        type: Boolean,
        default: true
    },
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: Date,
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Password hashing middleware
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Account locking methods
userSchema.virtual('isLocked').get(function() {
    return !!(this.lockUntil && this.lockUntil > Date.now());
});

userSchema.methods.incLoginAttempts = function() {
    if (this.lockUntil && this.lockUntil < Date.now()) {
        return this.updateOne({
            $unset: { loginAttempts: 1, lockUntil: 1 }
        });
    }
    
    const updates = { $inc: { loginAttempts: 1 } };
    
    if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
        updates.$set = {
            lockUntil: Date.now() + 2 * 60 * 60 * 1000 // 2 hours
        };
    }
    
    return this.updateOne(updates);
};

// Password comparison method
userSchema.methods.comparePassword = async function(candidatePassword) {
    if (this.isLocked) {
        throw new Error('Account is temporarily locked due to too many failed login attempts.');
    }
    
    const isMatch = await bcrypt.compare(candidatePassword, this.password);
    
    if (!isMatch) {
        await this.incLoginAttempts();
        throw new Error('Invalid credentials');
    }
    
    // Reset login attempts on successful login
    if (this.loginAttempts > 0) {
        await this.updateOne({
            $unset: { loginAttempts: 1, lockUntil: 1 }
        });
    }
    
    return isMatch;
};

const User = mongoose.model('User', userSchema);

// Input validation middleware
const validateInput = (req, res, next) => {
    const { body } = req;
    
    // Sanitize input
    for (let key in body) {
        if (typeof body[key] === 'string') {
            body[key] = validator.escape(body[key].trim());
        }
    }
    
    next();
};

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

// JWT token generation
const generateToken = (userId) => {
    return jwt.sign({ userId }, JWT_SECRET, { 
        expiresIn: '24h',
        issuer: 'secure-auth-app',
        audience: 'secure-auth-users'
    });
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password');
        
        if (!user || !user.isActive) {
            return res.status(401).json({ error: 'Invalid or inactive user' });
        }
        
        req.user = user;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

// Routes

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Register endpoint
app.post('/api/auth/register', validateInput, async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Validation
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ error: 'Please provide a valid email' });
        }

        const passwordError = validatePassword(password);
        if (passwordError) {
            return res.status(400).json({ error: passwordError });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists with this email' });
        }

        // Create new user
        const user = new User({ name, email, password });
        await user.save();

        // Generate token
        const token = generateToken(user._id);

        // Set session
        req.session.userId = user._id;

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login endpoint
app.post('/api/auth/login', validateInput, async (req, res) => {
    try {
        const { email, password, recaptchaResponse } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ error: 'Please provide a valid email' });
        }

        // Validate reCAPTCHA
        if (!recaptchaResponse) {
            return res.status(400).json({ error: 'reCAPTCHA verification is required' });
        }

        // Verify reCAPTCHA with Google
        try {
            const recaptchaVerifyUrl = 'https://www.google.com/recaptcha/api/siteverify';
            const recaptchaSecretKey = process.env.RECAPTCHA_SECRET_KEY || 'your-recaptcha-secret-key';
            
            const recaptchaVerification = await axios.post(
                recaptchaVerifyUrl,
                null,
                {
                    params: {
                        secret: recaptchaSecretKey,
                        response: recaptchaResponse
                    }
                }
            );

            if (!recaptchaVerification.data.success) {
                return res.status(400).json({ error: 'reCAPTCHA verification failed' });
            }
        } catch (recaptchaError) {
            console.error('reCAPTCHA verification error:', recaptchaError);
            return res.status(500).json({ error: 'reCAPTCHA verification failed' });
        }

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check if account is active
        if (!user.isActive) {
            return res.status(401).json({ error: 'Account is deactivated' });
        }

        // Compare password
        await user.comparePassword(password);

        // Generate token
        const token = generateToken(user._id);

        // Set session
        req.session.userId = user._id;

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        
        if (error.message === 'Invalid credentials' || 
            error.message.includes('Account is temporarily locked')) {
            return res.status(401).json({ error: error.message });
        }
        
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Logout endpoint
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Could not log out' });
        }
        res.clearCookie('connect.sid');
        res.json({ message: 'Logout successful' });
    });
});

// Protected profile endpoint
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password -loginAttempts -lockUntil');
        res.json({ user });
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update profile endpoint
app.put('/api/user/profile', authenticateToken, validateInput, async (req, res) => {
    try {
        const { name } = req.body;
        
        if (!name || name.length < 2) {
            return res.status(400).json({ error: 'Name must be at least 2 characters' });
        }

        const user = await User.findByIdAndUpdate(
            req.user._id,
            { name },
            { new: true, runValidators: true }
        ).select('-password');

        res.json({
            message: 'Profile updated successfully',
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Change password endpoint
app.put('/api/user/change-password', authenticateToken, validateInput, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current and new passwords are required' });
        }

        const passwordError = validatePassword(newPassword);
        if (passwordError) {
            return res.status(400).json({ error: passwordError });
        }

        const user = await User.findById(req.user._id);
        
        // Verify current password
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
        if (!isCurrentPasswordValid) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }

        // Update password
        user.password = newPassword;
        await user.save();

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// reCAPTCHA site key endpoint
app.get('/api/recaptcha-key', (req, res) => {
    res.json({
        siteKey: process.env.RECAPTCHA_SITE_KEY || 'your-recaptcha-site-key'
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    mongoose.connection.close(() => {
        console.log('MongoDB connection closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully');
    mongoose.connection.close(() => {
        console.log('MongoDB connection closed');
        process.exit(0);
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔒 Security features enabled`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
});