document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const showSignupLink = document.getElementById('showSignup');
    const showLoginLink = document.getElementById('showLogin');
    const forgotPasswordLink = document.getElementById('forgotPasswordLink');
    const forgotPasswordModal = document.getElementById('forgotPasswordModal');
    const closeForgotModal = document.getElementById('closeForgotModal');
    const forgotPasswordForm = document.getElementById('forgotPasswordForm');

    // Form switching
    showSignupLink.addEventListener('click', (e) => {
        e.preventDefault();
        loginForm.classList.add('hidden');
        signupForm.classList.remove('hidden');
    });

    showLoginLink.addEventListener('click', (e) => {
        e.preventDefault();
        signupForm.classList.add('hidden');
        loginForm.classList.remove('hidden');
    });

    // Helper functions
    function sanitizeInput(input) {
        return input.replace(/[<>]/g, ''); // Basic XSS prevention
    }

    function hashPassword(password) {
        // In production, use a proper hashing library
        return btoa(password); // This is just for demonstration
    }

    function validatePassword(password) {
        const regex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
        return regex.test(password);
    }

    // Signup Form Handler
    signupForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const username = sanitizeInput(document.getElementById('signupUsername').value);
        const email = sanitizeInput(document.getElementById('signupEmail').value);
        const password = document.getElementById('signupPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        if (password !== confirmPassword) {
            alert('Passwords do not match!');
            return;
        }

        if (!validatePassword(password)) {
            alert('Password must be at least 8 characters long and include letters and numbers');
            return;
        }

        const user = {
            username: username,
            email: email,
            password: hashPassword(password),
            createdAt: new Date().toISOString()
        };

        // Store user in localStorage (In production, use a secure backend)
        const users = JSON.parse(localStorage.getItem('users') || '[]');
        
        if (users.some(u => u.username === username)) {
            alert('Username already exists!');
            return;
        }

        users.push(user);
        localStorage.setItem('users', JSON.stringify(users));
        
        alert('Registration successful! Please login.');
        signupForm.reset();
        signupForm.classList.add('hidden');
        loginForm.classList.remove('hidden');
    });

    // Login Form Handler
    loginForm.addEventListener('submit', function(e) {
        e.preventDefault();

    // Only check reCAPTCHA if grecaptcha is loaded and the widget is visible
    if (typeof grecaptcha !== 'undefined' && loginForm.offsetParent !== null) {
        const recaptchaResponse = grecaptcha.getResponse();
        if (!recaptchaResponse) {
            alert('Please verify you are not a robot!');
            return;
        }
    }
        
        const username = sanitizeInput(document.getElementById('loginUsername').value);
        const password = document.getElementById('loginPassword').value;
        
        const users = JSON.parse(localStorage.getItem('users') || '[]');
        const user = users.find(u => u.username === username && u.password === hashPassword(password));
        
        if (user) {
            // Create session token (In production, use proper session management)
            const sessionToken = Math.random().toString(36).substring(2);
            sessionStorage.setItem('sessionToken', sessionToken);
            sessionStorage.setItem('currentUser', username);
            
            alert('Login successful!');
            loginForm.reset();
            if (typeof grecaptcha !== 'undefined') grecaptcha.reset();
            // Redirect to dashboard or home page
        } else {
            alert('Invalid credentials!');
            if (typeof grecaptcha !== 'undefined') grecaptcha.reset();
        }
    });

    // Forgot Password Modal Logic
    forgotPasswordLink.addEventListener('click', (e) => {
        e.preventDefault();
        forgotPasswordModal.classList.remove('hidden');
        document.getElementById('forgotEmail').focus();
    });

    closeForgotModal.addEventListener('click', () => {
        forgotPasswordModal.classList.add('hidden');
        forgotPasswordForm.reset();
    });

    forgotPasswordForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const email = document.getElementById('forgotEmail').value.trim();
        if (!email) {
            alert('Please enter your email.');
            return;
        }
        // Simulate sending reset link
        alert('If an account with that email exists, a reset link has been sent.');
        forgotPasswordModal.classList.add('hidden');
        forgotPasswordForm.reset();
    });

    // Implement session check
    function checkSession() {
        const sessionToken = sessionStorage.getItem('sessionToken');
        const currentUser = sessionStorage.getItem('currentUser');
        
        if (sessionToken && currentUser) {
            // User is logged in
            return true;
        }
        return false;
    }

    // Check session on page load
    if (checkSession()) {
        // Redirect to dashboard or home page
    }
});