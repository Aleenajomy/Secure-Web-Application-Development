# 🔐 Secure User Authentication System

A comprehensive, production-ready web application with secure authentication, implementing modern security best practices and protection against common web vulnerabilities.

## 🚀 Features

### Security Features
- **Password Security**: Bcrypt hashing with salt rounds
- **Input Validation**: Server-side validation and sanitization
- **XSS Protection**: Content Security Policy and input escaping
- **CSRF Protection**: Token-based CSRF prevention
- **Rate Limiting**: Prevents brute force attacks
- **Session Management**: Secure session handling with MongoDB store
- **Account Lockout**: Temporary lockout after failed login attempts
- **JWT Authentication**: Stateless token-based authentication
- **Secure Headers**: Helmet.js for security headers
- **SQL Injection Prevention**: MongoDB with Mongoose ODM

### Application Features
- **User Registration**: Secure account creation with validation
- **User Login**: Authentication with session management
- **Password Requirements**: Strong password policy enforcement
- **Profile Management**: Update user information
- **Password Change**: Secure password update functionality
- **Session Timeout**: Automatic logout after inactivity
- **Responsive Design**: Mobile-friendly interface
- **Real-time Validation**: Client-side form validation

## 🛠️ Technology Stack

### Backend
- **Node.js**: Runtime environment
- **Express.js**: Web framework
- **MongoDB**: Database with Mongoose ODM
- **bcrypt**: Password hashing
- **jsonwebtoken**: JWT token generation
- **express-rate-limit**: Rate limiting middleware
- **helmet**: Security headers
- **validator**: Input validation
- **express-session**: Session management

### Frontend
- **HTML5**: Semantic markup
- **CSS3**: Modern styling with animations
- **JavaScript**: ES6+ for interactivity
- **Responsive Design**: Mobile-first approach

## 📋 Prerequisites

Before running this application, make sure you have:

- Node.js (v16.0.0 or higher)
- npm (v8.0.0 or higher)
- MongoDB (v4.4 or higher)

## ⚡ Quick Start

### Method 1: Full Setup with MongoDB (Recommended for Production)

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/secure-web-authentication.git
   cd secure-web-authentication
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` file with your configuration:
   ```env
   NODE_ENV=development
   PORT=3000
   MONGODB_URI=mongodb://localhost:27017/secure-auth
   JWT_SECRET=your-super-secure-jwt-secret
   SESSION_SECRET=your-super-secure-session-secret
   RECAPTCHA_SITE_KEY=your-recaptcha-site-key
   RECAPTCHA_SECRET_KEY=your-recaptcha-secret-key
   ```

4. **Install and Start MongoDB**
   
   **Windows:**
   - Download MongoDB from https://www.mongodb.com/try/download/community
   - Install and start MongoDB service
   - Or use MongoDB Atlas (cloud): https://www.mongodb.com/atlas
   
   **macOS:**
   ```bash
   brew install mongodb-community
   brew services start mongodb-community
   ```
   
   **Linux:**
   ```bash
   sudo apt-get install mongodb
   sudo systemctl start mongodb
   ```

5. **Create a test user (Optional)**
   ```bash
   node create-test-user.js
   ```
   This creates a test user with:
   - Email: `test@test.com`
   - Password: `password123`

6. **Run the application**
   ```bash
   # Start the server
   node server.js
   
   # Or with nodemon for development
   npm run dev
   ```

7. **Access the application**
   Open your browser and navigate to `http://localhost:3000`

### Method 2: Quick Development Setup (No MongoDB Required)

**For quick testing without MongoDB setup:**

1. **Follow steps 1-3 from Method 1**

2. **Start the server in development mode**
   ```bash
   node server.js
   ```
   
   The application will automatically:
   - Skip reCAPTCHA validation in development
   - Show helpful error messages
   - Work on localhost without external dependencies

3. **Access the application**
   Open `http://localhost:3000` in your browser

4. **Create an account**
   - Click "Sign up here"
   - Fill in the registration form
   - Use a strong password (8+ chars, uppercase, lowercase, numbers, special chars)

### Method 3: Using XAMPP (Alternative)

If you're using XAMPP:

1. **Place files in XAMPP directory**
   ```
   C:\xampp\htdocs\secure-web-authentication\
   ```

2. **Install Node.js dependencies**
   ```bash
   cd C:\xampp\htdocs\secure-web-authentication
   npm install
   ```

3. **Start the Node.js server**
   ```bash
   node server.js
   ```

4. **Access via**
   - Direct: `http://localhost:3000`
   - Via XAMPP: `http://localhost/secure-web-authentication/public/`

## 🏗️ Project Structure

```
secure-web-authentication/
├── server.js                 # Main server file
├── package.json             # Dependencies and scripts
├── .env.example            # Environment variables template
├── .gitignore              # Git ignore rules
├── README.md               # This file
├── public/                 # Static files
│   └── index.html         # Frontend application
├── logs/                   # Application logs
├── tests/                  # Test files
└── docs/                   # Documentation
```

## 🔒 Security Implementation

### 1. Password Security
- **Bcrypt Hashing**: Passwords are hashed with bcrypt using 12 salt rounds
- **Password Requirements**: Minimum 8 characters, uppercase, lowercase, numbers, special characters
- **Password Comparison**: Secure comparison prevents timing attacks

### 2. Authentication & Authorization
- **JWT Tokens**: Stateless authentication with 24-hour expiration
- **Session Management**: Server-side sessions with MongoDB store
- **Token Validation**: Middleware validates JWT tokens on protected routes

### 3. Input Validation & Sanitization
- **Server-side Validation**: All inputs validated using validator.js
- **HTML Escaping**: Prevents XSS attacks through input sanitization
- **Email Validation**: RFC-compliant email validation

### 4. Attack Prevention
- **Rate Limiting**: 100 requests per 15 minutes, 5 auth attempts per 15 minutes
- **Account Lockout**: Temporary lockout after 5 failed login attempts
- **CSRF Protection**: Session-based CSRF token validation
- **XSS Prevention**: Content Security Policy and input escaping
- **SQL Injection**: MongoDB with parameterized queries

### 5. Security Headers
- **Helmet.js**: Comprehensive security headers
- **HSTS**: HTTP Strict Transport Security
- **CSP**: Content Security Policy
- **X-Frame-Options**: Clickjacking protection

## 🧪 API Endpoints

### Authentication
```http
POST /api/auth/register
POST /api/auth/login
POST /api/auth/logout
```

### User Management
```http
GET /api/user/profile
PUT /api/user/profile
PUT /api/user/change-password
```

### Utilities
```http
GET /api/health
```

## 🚀 Deployment

### Production Checklist
- [ ] Set `NODE_ENV=production`
- [ ] Use strong, unique JWT and session secrets
- [ ] Configure production MongoDB URI
- [ ] Enable HTTPS
- [ ] Set up proper logging
- [ ] Configure reverse proxy (nginx)
- [ ] Set up monitoring and alerts

### Environment Variables (Production)
```env
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/secure-auth
JWT_SECRET=your-production-jwt-secret
SESSION_SECRET=your-production-session-secret
CLIENT_URL=https://yourdomain.com
ENABLE_HTTPS_REDIRECT=true
```

## 🧪 Testing

Run the test suite:
```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run security audit
npm run security-audit
```

## 📊 Performance & Monitoring

### Built-in Features
- Request logging with Morgan
- Health check endpoint
- Error handling and logging
- Graceful shutdown handling

### Recommended Monitoring Tools
- **PM2**: Process management
- **New Relic**: Application performance monitoring
- **Sentry**: Error tracking
- **MongoDB Atlas**: Database monitoring

## 🔧 Configuration Options

### Rate Limiting
```javascript
// Adjust in server.js
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // requests per window
});
```

### Session Configuration
```javascript
// Customize session settings
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict'
    }
}));
```

## 🐛 Troubleshooting

### Login Issues (Fixed in Latest Version)

**Problem: "Login not working" or "reCAPTCHA verification failed"**

**Solution:** The latest version includes fixes for common login issues:

1. **reCAPTCHA Issues**
   - ✅ **Fixed**: reCAPTCHA is now optional in development mode
   - ✅ **Fixed**: Placeholder reCAPTCHA keys won't block login
   - The system automatically detects development environment and skips reCAPTCHA validation

2. **Frontend Validation**
   - ✅ **Fixed**: Added proper password validation
   - ✅ **Fixed**: Improved error handling for undefined reCAPTCHA
   - ✅ **Fixed**: Better user feedback for validation errors

3. **Development Mode Features**
   - Automatic reCAPTCHA bypass on localhost/127.0.0.1
   - Enhanced error logging for debugging
   - Graceful handling of missing MongoDB connection

**Quick Test:**
```bash
# Start the server
node server.js

# Open browser to http://localhost:3000
# Try creating a new account first, then login
```

### Common Issues

1. **MongoDB Connection Error**
   ```
   Error: connect ECONNREFUSED 127.0.0.1:27017
   ```
   **Solutions:**
   - Ensure MongoDB is running: `mongod` or start MongoDB service
   - Check connection string in `.env` file
   - Use MongoDB Atlas for cloud database
   - For quick testing, the app works without MongoDB in development mode

2. **"Cannot POST /api/auth/login"**
   **Solutions:**
   - Ensure Node.js server is running: `node server.js`
   - Check if port 3000 is available
   - Verify the server started without errors

3. **JWT Token Issues**
   - Check JWT_SECRET in environment variables
   - Verify token expiration settings
   - Clear browser local storage: `localStorage.clear()`

4. **Rate Limiting Triggered**
   ```
   Too many authentication attempts
   ```
   **Solutions:**
   - Wait 15 minutes for rate limit reset
   - Restart the server to reset counters
   - Adjust rate limiting in `server.js` if needed

5. **Session Problems**
   - Clear browser cookies and local storage
   - Check MongoDB session store connection
   - Verify SESSION_SECRET configuration

6. **Password Validation Errors**
   **Requirements:**
   - Minimum 8 characters
   - At least one uppercase letter
   - At least one lowercase letter
   - At least one number
   - At least one special character (!@#$%^&*(),.?":{}|<>)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit a pull request

### Development Guidelines
- Follow ESLint configuration
- Write tests for new features
- Update documentation as needed
- Ensure security best practices

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP](https://owasp.org/) for security guidelines
- [Express.js](https://expressjs.com/) team for the excellent framework
- [MongoDB](https://www.mongodb.com/) for the database solution
- Security community for best practices and recommendations

## 📞 Support

If you encounter any issues or have questions:
- Create an issue on GitHub
- Check the troubleshooting section
- Review the documentation

---

**⚠️ Security Note**: This application implements multiple security measures, but security is an ongoing process. Always keep dependencies updated, monitor for vulnerabilities, and follow security best practices in production environments.
