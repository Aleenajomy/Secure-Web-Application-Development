const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../server');

// Test database
const MONGODB_TEST_URI = process.env.MONGODB_TEST_URI || 'mongodb://localhost:27017/secure-auth-test';

describe('Authentication System', () => {
    beforeAll(async () => {
        // Connect to test database
        await mongoose.connect(MONGODB_TEST_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
    });

    afterAll(async () => {
        // Clean up test database
        await mongoose.connection.db.dropDatabase();
        await mongoose.connection.close();
    });

    beforeEach(async () => {
        // Clean up before each test
        const collections = mongoose.connection.collections;
        for (const key in collections) {
            await collections[key].deleteMany({});
        }
    });

    describe('POST /api/auth/register', () => {
        test('should register a new user with valid data', async () => {
            const userData = {
                name: 'John Doe',
                email: 'john@example.com',
                password: 'SecurePass123!'
            };

            const response = await request(app)
                .post('/api/auth/register')
                .send(userData);

            expect(response.status).toBe(201);
            expect(response.body.message).toBe('User registered successfully');
            expect(response.body.token).toBeDefined();
            expect(response.body.user.email).toBe(userData.email);
            expect(response.body.user.name).toBe(userData.name);
        });

        test('should reject registration with weak password', async () => {
            const userData = {
                name: 'John Doe',
                email: 'john@example.com',
                password: 'weak'
            };

            const response = await request(app)
                .post('/api/auth/register')
                .send(userData);

            expect(response.status).toBe(400);
            expect(response.body.error).toContain('Password must be at least 8 characters');
        });

        test('should reject registration with invalid email', async () => {
            const userData = {
                name: 'John Doe',
                email: 'invalid-email',
                password: 'SecurePass123!'
            };

            const response = await request(app)
                .post('/api/auth/register')
                .send(userData);

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('Please provide a valid email');
        });

        test('should reject duplicate email registration', async () => {
            const userData = {
                name: 'John Doe',
                email: 'john@example.com',
                password: 'SecurePass123!'
            };

            // First registration
            await request(app)
                .post('/api/auth/register')
                .send(userData);

            // Duplicate registration
            const response = await request(app)
                .post('/api/auth/register')
                .send(userData);

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('User already exists with this email');
        });

        test('should sanitize input data', async () => {
            const userData = {
                name: '<script>alert("xss")</script>John',
                email: 'john@example.com',
                password: 'SecurePass123!'
            };

            const response = await request(app)
                .post('/api/auth/register')
                .send(userData);

            expect(response.status).toBe(201);
            expect(response.body.user.name).not.toContain('<script>');
            expect(response.body.user.name).toContain('&lt;script&gt;');
        });
    });

    describe('POST /api/auth/login', () => {
        beforeEach(async () => {
            // Register a test user
            await request(app)
                .post('/api/auth/register')
                .send({
                    name: 'Test User',
                    email: 'test@example.com',
                    password: 'SecurePass123!'
                });
        });

        test('should login with valid credentials', async () => {
            const loginData = {
                email: 'test@example.com',
                password: 'SecurePass123!'
            };

            const response = await request(app)
                .post('/api/auth/login')
                .send(loginData);

            expect(response.status).toBe(200);
            expect(response.body.message).toBe('Login successful');
            expect(response.body.token).toBeDefined();
            expect(response.body.user.email).toBe(loginData.email);
        });

        test('should reject login with invalid credentials', async () => {
            const loginData = {
                email: 'test@example.com',
                password: 'WrongPassword123!'
            };

            const response = await request(app)
                .post('/api/auth/login')
                .send(loginData);

            expect(response.status).toBe(401);
            expect(response.body.error).toBe('Invalid credentials');
        });

        test('should reject login with non-existent email', async () => {
            const loginData = {
                email: 'nonexistent@example.com',
                password: 'SecurePass123!'
            };

            const response = await request(app)
                .post('/api/auth/login')
                .send(loginData);

            expect(response.status).toBe(401);
            expect(response.body.error).toBe('Invalid credentials');
        });

        test('should validate email format', async () => {
            const loginData = {
                email: 'invalid-email',
                password: 'SecurePass123!'
            };

            const response = await request(app)
                .post('/api/auth/login')
                .send(loginData);

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('Please provide a valid email');
        });
    });

    describe('Protected Routes', () => {
        let authToken;
        let userId;

        beforeEach(async () => {
            // Register and login to get auth token
            const registerResponse = await request(app)
                .post('/api/auth/register')
                .send({
                    name: 'Test User',
                    email: 'test@example.com',
                    password: 'SecurePass123!'
                });

            authToken = registerResponse.body.token;
            userId = registerResponse.body.user.id;
        });

        test('should access protected route with valid token', async () => {
            const response = await request(app)
                .get('/api/user/profile')
                .set('Authorization', `Bearer ${authToken}`);

            expect(response.status).toBe(200);
            expect(response.body.user).toBeDefined();
            expect(response.body.user.email).toBe('test@example.com');
        });

        test('should reject access without token', async () => {
            const response = await request(app)
                .get('/api/user/profile');

            expect(response.status).toBe(401);
            expect(response.body.error).toBe('Access token required');
        });

        test('should reject access with invalid token', async () => {
            const response = await request(app)
                .get('/api/user/profile')
                .set('Authorization', 'Bearer invalid-token');

            expect(response.status).toBe(403);
            expect(response.body.error).toBe('Invalid or expired token');
        });
    });

    describe('Rate Limiting', () => {
        test('should enforce rate limits on auth routes', async () => {
            const requests = [];
            
            // Make multiple requests quickly
            for (let i = 0; i < 7; i++) {
                requests.push(
                    request(app)
                        .post('/api/auth/login')
                        .send({
                            email: 'test@example.com',
                            password: 'wrong-password'
                        })
                );
            }

            const responses = await Promise.all(requests);
            
            // Some requests should be rate limited
            const rateLimitedResponses = responses.filter(r => r.status === 429);
            expect(rateLimitedResponses.length).toBeGreaterThan(0);
        });
    });

    describe('Password Security', () => {
        test('should hash passwords before storing', async () => {
            const userData = {
                name: 'John Doe',
                email: 'john@example.com',
                password: 'SecurePass123!'
            };

            await request(app)
                .post('/api/auth/register')
                .send(userData);

            // Check that password is hashed in database
            const User = mongoose.model('User');
            const user = await User.findOne({ email: userData.email });
            
            expect(user.password).not.toBe(userData.password);
            expect(user.password).toMatch(/^\$2[aby]\$\d+\$/); // bcrypt hash pattern
        });

        test('should reject passwords without special characters', async () => {
            const userData = {
                name: 'John Doe',
                email: 'john@example.com',
                password: 'SecurePass123' // No special character
            };

            const response = await request(app)
                .post('/api/auth/register')
                .send(userData);

            expect(response.status).toBe(400);
            expect(response.body.error).toContain('special character');
        });

        test('should reject passwords without uppercase letters', async () => {
            const userData = {
                name: 'John Doe',
                email: 'john@example.com',
                password: 'securepass123!' // No uppercase
            };

            const response = await request(app)
                .post('/api/auth/register')
                .send(userData);

            expect(response.status).toBe(400);
            expect(response.body.error).toContain('uppercase and lowercase');
        });
    });

    describe('Input Validation', () => {
        test('should reject empty required fields', async () => {
            const userData = {
                name: '',
                email: '',
                password: ''
            };

            const response = await request(app)
                .post('/api/auth/register')
                .send(userData);

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('All fields are required');
        });

        test('should trim whitespace from inputs', async () => {
            const userData = {
                name: '  John Doe  ',
                email: '  john@example.com  ',
                password: 'SecurePass123!'
            };

            const response = await request(app)
                .post('/api/auth/register')
                .send(userData);

            expect(response.status).toBe(201);
            expect(response.body.user.name).toBe('John Doe');
            expect(response.body.user.email).toBe('john@example.com');
        });
    });

    describe('Security Headers', () => {
        test('should include security headers', async () => {
            const response = await request(app)
                .get('/api/health');

            expect(response.headers['x-content-type-options']).toBe('nosniff');
            expect(response.headers['x-frame-options']).toBe('DENY');
            expect(response.headers['x-xss-protection']).toBe('0');
        });
    });

    describe('Account Lockout', () => {
        beforeEach(async () => {
            // Register a test user
            await request(app)
                .post('/api/auth/register')
                .send({
                    name: 'Test User',
                    email: 'lockout@example.com',
                    password: 'SecurePass123!'
                });
        });

        test('should lock account after multiple failed attempts', async () => {
            const loginData = {
                email: 'lockout@example.com',
                password: 'WrongPassword123!'
            };

            // Make 5 failed login attempts
            for (let i = 0; i < 5; i++) {
                await request(app)
                    .post('/api/auth/login')
                    .send(loginData);
            }

            // 6th attempt should indicate account is locked
            const response = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'lockout@example.com',
                    password: 'SecurePass123!' // Correct password
                });

            expect(response.status).toBe(401);
            expect(response.body.error).toContain('temporarily locked');
        });
    });
});

describe('Health Check', () => {
    test('should return health status', async () => {
        const response = await request(app)
            .get('/api/health');

        expect(response.status).toBe(200);
        expect(response.body.status).toBe('OK');
        expect(response.body.timestamp).toBeDefined();
        expect(response.body.uptime).toBeDefined();
    });
});

describe('Error Handling', () => {
    test('should handle 404 for non-existent routes', async () => {
        const response = await request(app)
            .get('/api/non-existent-route');

        expect(response.status).toBe(404);
        expect(response.body.error).toBe('Route not found');
    });

    test('should handle malformed JSON', async () => {
        const response = await request(app)
            .post('/api/auth/login')
            .send('invalid-json')
            .set('Content-Type', 'application/json');

        expect(response.status).toBe(400);
    });
});