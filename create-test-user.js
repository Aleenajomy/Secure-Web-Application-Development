// Test user creation script
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/secure-auth', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// User Schema (same as in server.js)
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
        lowercase: true
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

const User = mongoose.model('User', userSchema);

async function createTestUser() {
    try {
        // Check if test user already exists
        const existingUser = await User.findOne({ email: 'aleenajomy4@gmail.com' });
        if (existingUser) {
            console.log('Test user already exists!');
            console.log('Email: aleenajomy4@gmail.com');
            console.log('Password: Aleena@123');
            return;
        }

        // Create test user
        const testUser = new User({
            name: 'Aleena Jomy',
            email: 'aleenajomy4@gmail.com',
            password: 'Aleena@123'
        });

        await testUser.save();
        console.log('✅ Test user created successfully!');
        console.log('Email: aleenajomy4@gmail.com');
        console.log('Password: Aleena@123');
        console.log('You can now use these credentials to login.');
        
    } catch (error) {
        console.error('❌ Error creating test user:', error.message);
    } finally {
        mongoose.connection.close();
    }
}

createTestUser();
