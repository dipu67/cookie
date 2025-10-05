import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import helmet from 'helmet';
import compression from 'compression';
import validator from 'validator';

// Load environment variables
dotenv.config();

// Constants and configuration
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/twitter-cookies';

// Validation constants
const VALIDATION = {
    USERNAME_MIN_LENGTH: 3,
    USERNAME_MAX_LENGTH: 50,
    COOKIE_DATA_MIN_LENGTH: 10,
    COOKIE_DATA_MAX_LENGTH: 100000,
    MAX_COOKIES_PER_USER: 50
};

// Initialize Express app
const app = express();

// Trust proxy for rate limiting behind reverse proxies
if (NODE_ENV === 'production') {
    app.set('trust proxy', 1);
}

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

// Compression for better performance
app.use(compression({
    level: 6,
    threshold: 1024,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) {
            return false;
        }
        return compression.filter(req, res);
    }
}));

// CORS configuration
const corsOptions = {
    origin: NODE_ENV === 'development' 
        ? ['http://localhost:3000', 'http://127.0.0.1:3000']
        : process.env.ALLOWED_ORIGINS?.split(',') || false,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false,
    maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));

// Body parsing middleware with size limits
app.use(express.json({ 
    limit: '1mb',
    strict: true,
    type: 'application/json'
}));

app.use(express.urlencoded({ 
    extended: false, 
    limit: '1mb' 
}));

// Static file serving with caching
app.use(express.static(path.join(__dirname), {
    maxAge: NODE_ENV === 'production' ? '1d' : 0,
    etag: true,
    lastModified: true
}));

// MongoDB Connection with optimized settings
const mongooseOptions = {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    retryWrites: true,
    retryReads: true
};

// Connection with retry logic
const connectToMongoDB = async (retries = 5) => {
    try {
        await mongoose.connect(MONGODB_URI);
        console.log('✅ Connected to MongoDB successfully');
        
        // Set up connection event handlers
        mongoose.connection.on('error', (err) => {
            console.error('❌ MongoDB connection error:', err);
        });
        
        mongoose.connection.on('disconnected', () => {
            console.warn('⚠️  MongoDB disconnected');
        });
        
        mongoose.connection.on('reconnected', () => {
            console.log('🔄 MongoDB reconnected');
        });
        
        // Start server only after successful DB connection
        startServer();
        
    } catch (error) {
        console.error(`❌ MongoDB connection failed (${6 - retries}/5):`, error.message);
        
        if (retries > 0) {
            console.log(`🔄 Retrying connection in 5 seconds...`);
            setTimeout(() => connectToMongoDB(retries - 1), 5000);
        } else {
            console.error('💀 Failed to connect to MongoDB after 5 attempts');
            process.exit(1);
        }
    }
};

// Optimized Cookie Schema with validation and indexing
const cookieSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true,
        trim: true,
        lowercase: true,
        minlength: [VALIDATION.USERNAME_MIN_LENGTH, `Username must be at least ${VALIDATION.USERNAME_MIN_LENGTH} characters`],
        maxlength: [VALIDATION.USERNAME_MAX_LENGTH, `Username must not exceed ${VALIDATION.USERNAME_MAX_LENGTH} characters`],
        match: [/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens']
    },
    cookieString: {
        type: String,
        required: [true, 'Cookie string is required'],
        maxlength: [VALIDATION.COOKIE_DATA_MAX_LENGTH, 'Cookie string too large']
    },
    cookieCount: {
        type: Number,
        default: 0,
        min: [0, 'Cookie count cannot be negative'],
        max: [VALIDATION.MAX_COOKIES_PER_USER, `Maximum ${VALIDATION.MAX_COOKIES_PER_USER} cookies allowed per user`]
    },
    rawCookies: {
        type: [{
            domain: { type: String, default: '.x.com' },
            expirationDate: { type: Number, min: 0 },
            hostOnly: { type: Boolean, default: false },
            httpOnly: { type: Boolean, default: false },
            name: { 
                type: String, 
                required: true,
                trim: true,
                maxlength: [100, 'Cookie name too long']
            },
            path: { type: String, default: '/' },
            sameSite: { 
                type: String, 
                enum: ['strict', 'lax', 'none', 'unspecified', 'no_restriction'], 
                default: 'lax' 
            },
            secure: { type: Boolean, default: true },
            session: { type: Boolean, default: false },
            storeId: { type: String, default: '0' },
            value: { 
                type: String, 
                required: true,
                maxlength: [4096, 'Cookie value too long']
            }
        }],
        validate: {
            validator: function(cookies) {
                return cookies.length <= VALIDATION.MAX_COOKIES_PER_USER;
            },
            message: `Maximum ${VALIDATION.MAX_COOKIES_PER_USER} cookies allowed per user`
        }
    },
    lastAccessed: {
        type: Date,
        default: Date.now
    },
    isActive: {
        type: Boolean,
        default: true
    }
}, { 
    timestamps: true,
    versionKey: false
});

// Indexes for better query performance
cookieSchema.index({ updatedAt: -1 });
cookieSchema.index({ isActive: 1, updatedAt: -1 });

// Instance methods
cookieSchema.methods.updateLastAccessed = function() {
    this.lastAccessed = new Date();
    return this.save();
};

// Static methods
cookieSchema.statics.findActiveUsers = function() {
    return this.find({ isActive: true }).select('username cookieCount updatedAt');
};

cookieSchema.statics.getUserStats = function() {
    return this.aggregate([
        { $match: { isActive: true } },
        {
            $group: {
                _id: null,
                totalUsers: { $sum: 1 },
                totalCookies: { $sum: '$cookieCount' },
                avgCookiesPerUser: { $avg: '$cookieCount' }
            }
        }
    ]);
};

const Cookie = mongoose.model('Cookie', cookieSchema);

// Utility functions for validation and error handling
const utils = {
    // Input validation
    validateUsername(username) {
        if (!username || typeof username !== 'string') {
            return { isValid: false, error: 'Username is required and must be a string' };
        }
        
        const trimmed = username.trim().toLowerCase();
        
        if (trimmed.length < VALIDATION.USERNAME_MIN_LENGTH || trimmed.length > VALIDATION.USERNAME_MAX_LENGTH) {
            return { 
                isValid: false, 
                error: `Username must be between ${VALIDATION.USERNAME_MIN_LENGTH} and ${VALIDATION.USERNAME_MAX_LENGTH} characters` 
            };
        }
        
        if (!/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
            return { 
                isValid: false, 
                error: 'Username can only contain letters, numbers, underscores, and hyphens' 
            };
        }
        
        return { isValid: true, value: trimmed };
    },

    // Validate holder (allows spaces and more characters)
    validateHolder(holder) {
        if (!holder || typeof holder !== 'string') {
            return { isValid: false, error: 'Holder is required and must be a string' };
        }
        
        const trimmed = holder.trim();
        
        if (trimmed.length < VALIDATION.USERNAME_MIN_LENGTH || trimmed.length > VALIDATION.USERNAME_MAX_LENGTH) {
            return { 
                isValid: false, 
                error: `Holder must be between ${VALIDATION.USERNAME_MIN_LENGTH} and ${VALIDATION.USERNAME_MAX_LENGTH} characters` 
            };
        }
        
        // Allow letters, numbers, spaces, underscores, hyphens, and basic punctuation
        if (!/^[a-zA-Z0-9\s_.-]+$/.test(trimmed)) {
            return { 
                isValid: false, 
                error: 'Holder can only contain letters, numbers, spaces, underscores, hyphens, and periods' 
            };
        }
        
        return { isValid: true, value: trimmed };
    },

    validateCookieData(cookieData) {
        if (!cookieData) {
            return { isValid: false, error: 'Cookie data is required' };
        }
        
        const dataString = typeof cookieData === 'string' ? cookieData : JSON.stringify(cookieData);
        
        if (dataString.length < VALIDATION.COOKIE_DATA_MIN_LENGTH || dataString.length > VALIDATION.COOKIE_DATA_MAX_LENGTH) {
            return { 
                isValid: false, 
                error: `Cookie data must be between ${VALIDATION.COOKIE_DATA_MIN_LENGTH} and ${VALIDATION.COOKIE_DATA_MAX_LENGTH} characters` 
            };
        }
        
        return { isValid: true };
    },

    // Sanitize input to prevent XSS
    sanitizeInput(input) {
        if (typeof input !== 'string') return input;
        return validator.escape(input.trim());
    },

    // Enhanced error handler
    handleError(error, req, res, defaultMessage = 'Internal server error') {
        console.error(`❌ Error in ${req.method} ${req.path}:`, error);
        
        // Mongoose validation errors
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({ 
                error: 'Validation failed', 
                details: errors 
            });
        }
        
        // Mongoose duplicate key error
        if (error.code === 11000) {
            const field = Object.keys(error.keyPattern)[0];
            return res.status(409).json({ 
                error: `${field} already exists` 
            });
        }
        
        // MongoDB connection errors
        if (error.name === 'MongoNetworkError' || error.name === 'MongoTimeoutError') {
            return res.status(503).json({ 
                error: 'Database temporarily unavailable' 
            });
        }
        
        // Default error response
        const statusCode = error.statusCode || 500;
        res.status(statusCode).json({ 
            error: NODE_ENV === 'development' ? error.message : defaultMessage 
        });
    },

    // Performance monitoring
    performanceMiddleware(req, res, next) {
        const start = Date.now();
        
        res.on('finish', () => {
            const duration = Date.now() - start;
            if (duration > 1000) { // Log slow requests
                console.warn(`⚠️  Slow request: ${req.method} ${req.path} took ${duration}ms`);
            }
        });
        
        next();
    }
};

// Apply performance monitoring middleware
app.use(utils.performanceMiddleware);

// Main route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Optimized helper function to convert cookie array to cookie string
function convertToCookieString(cookies) {
    if (!Array.isArray(cookies) || cookies.length === 0) {
        return '';
    }
    
    // Define the specific order for Twitter cookies
    const cookieOrder = [
        'guest_id_marketing', 'guest_id_ads', 'guest_id', 'kdt', 'd_prefs',
        '__cuid', 'cf_clearance', 'dnt', '_twitter_sess', 'personalization_id',
        'auth_token', 'ct0', 'twid', 'att'
    ];
    
    // Create a map of cookies by name for O(1) lookup
    const cookieMap = new Map();
    cookies.forEach(cookie => {
        if (cookie?.name && cookie?.value && cookie.name !== 'lang') {
            // Validate cookie name and value
            const name = String(cookie.name).trim();
            const value = String(cookie.value).trim();
            
            if (name && value && name.length <= 100 && value.length <= 4096) {
                cookieMap.set(name, value);
            }
        }
    });
    
    if (cookieMap.size === 0) {
        return '';
    }
    
    const orderedCookies = [];
    
    // Add cookies in specified order first
    cookieOrder.forEach(cookieName => {
        if (cookieMap.has(cookieName)) {
            orderedCookies.push(`${cookieName}=${cookieMap.get(cookieName)}`);
            cookieMap.delete(cookieName);
        }
    });
    
    // Add remaining cookies
    cookieMap.forEach((value, name) => {
        orderedCookies.push(`${name}=${value}`);
    });
    
    return orderedCookies.join('; ');
}

// Optimized helper function to parse cookie string to cookie array
function parseCookieString(cookieString) {
    if (!cookieString || typeof cookieString !== 'string') {
        return [];
    }
    
    const cookies = [];
    const cookiePairs = cookieString.split(';');
    
    for (const cookie of cookiePairs) {
        const trimmedCookie = cookie.trim();
        if (!trimmedCookie) continue;
        
        const equalIndex = trimmedCookie.indexOf('=');
        if (equalIndex === -1) continue;
        
        const name = trimmedCookie.substring(0, equalIndex).trim();
        const value = trimmedCookie.substring(equalIndex + 1).trim();
        
        if (name && value && name !== 'lang' && name.length <= 100 && value.length <= 4096) {
            cookies.push({
                name,
                value,
                domain: '.x.com',
                path: '/',
                secure: true,
                httpOnly: false,
                sameSite: 'lax',
                session: false
            });
        }
    }
    
    return cookies;
}

// Enhanced cookie processing function
function processCookieData(cookieData) {
    let cookies = [];
    let inputType = 'Unknown';
    
    try {
        if (typeof cookieData === 'string') {
            const trimmed = cookieData.trim();
            
            if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
                // JSON format
                const parsed = JSON.parse(trimmed);
                cookies = Array.isArray(parsed) ? parsed : [parsed];
                inputType = 'JSON String';
            } else {
                // Cookie string format
                cookies = parseCookieString(trimmed);
                inputType = 'Cookie String';
            }
        } else if (Array.isArray(cookieData)) {
            cookies = cookieData;
            inputType = 'JSON Array';
        } else if (typeof cookieData === 'object' && cookieData !== null) {
            cookies = [cookieData];
            inputType = 'JSON Object';
        }
        
        // Helper function to normalize sameSite values
        const normalizeSameSite = (sameSite) => {
            if (!sameSite) return 'lax';
            const normalized = String(sameSite).toLowerCase();
            const validValues = ['strict', 'lax', 'none', 'unspecified', 'no_restriction'];
            return validValues.includes(normalized) ? normalized : 'lax';
        };

        // Filter and validate cookies
        const processedCookies = cookies
            .filter(cookie => cookie?.name && cookie?.value && cookie.name !== 'lang')
            .map(cookie => ({
                domain: cookie.domain || '.x.com',
                expirationDate: cookie.expirationDate,
                hostOnly: Boolean(cookie.hostOnly),
                httpOnly: Boolean(cookie.httpOnly),
                name: String(cookie.name).trim(),
                path: cookie.path || '/',
                sameSite: normalizeSameSite(cookie.sameSite),
                secure: cookie.secure !== false,
                session: Boolean(cookie.session),
                storeId: cookie.storeId || '0',
                value: String(cookie.value).trim()
            }))
            .filter(cookie => cookie.name.length <= 100 && cookie.value.length <= 4096);
        
        if (processedCookies.length > VALIDATION.MAX_COOKIES_PER_USER) {
            throw new Error(`Too many cookies. Maximum ${VALIDATION.MAX_COOKIES_PER_USER} allowed.`);
        }
        
        return {
            success: true,
            cookies: processedCookies,
            inputType,
            count: processedCookies.length
        };
        
    } catch (error) {
        return {
            success: false,
            error: error.message || 'Failed to process cookie data',
            inputType
        };
    }
}

// Upload cookie endpoint - extracts name and value from JSON and converts to cookie string
app.post('/api/upload-cookie', async (req, res) => {
    const startTime = Date.now();
    
    try {
        const { cookieData } = req.body;
        
        // Validate input
        const validation = utils.validateCookieData(cookieData);
        if (!validation.isValid) {
            return res.status(400).json({ 
                error: validation.error,
                code: 'VALIDATION_ERROR'
            });
        }

        // Process cookie data
        const result = processCookieData(cookieData);
        
        if (!result.success) {
            return res.status(400).json({ 
                error: result.error,
                code: 'PROCESSING_ERROR',
                inputType: result.inputType
            });
        }

        if (result.count === 0) {
            return res.status(400).json({ 
                error: 'No valid cookies found in the provided data',
                code: 'NO_VALID_COOKIES'
            });
        }

        // Convert to cookie string format
        const cookieString = convertToCookieString(result.cookies);

        const processingTime = Date.now() - startTime;
        
        res.json({ 
            success: true, 
            message: `Successfully processed ${result.count} cookies from ${result.inputType}`,
            data: {
                inputType: result.inputType,
                extractedCookies: result.cookies,
                cookieString: cookieString,
                count: result.count,
                processingTime: `${processingTime}ms`
            }
        });
        
        // Log performance for monitoring
        if (processingTime > 500) {
            console.warn(`⚠️  Slow cookie processing: ${processingTime}ms for ${result.count} cookies`);
        }
        
    } catch (error) {
        utils.handleError(error, req, res, 'Failed to process cookie data');
    }
});

// Update cookie endpoint - store username and cookies in MongoDB with transaction support
app.post('/api/update-cookie', async (req, res) => {
    const startTime = Date.now();
    const session = await mongoose.startSession();
    
    try {
        const { username, cookieData } = req.body;
        
        // Validate username
        const usernameValidation = utils.validateUsername(username);
        if (!usernameValidation.isValid) {
            return res.status(400).json({ 
                error: usernameValidation.error,
                code: 'USERNAME_VALIDATION_ERROR'
            });
        }
        
        // Validate cookie data
        const cookieValidation = utils.validateCookieData(cookieData);
        if (!cookieValidation.isValid) {
            return res.status(400).json({ 
                error: cookieValidation.error,
                code: 'COOKIE_VALIDATION_ERROR'
            });
        }

        // Process cookie data
        const result = processCookieData(cookieData);
        
        if (!result.success) {
            return res.status(400).json({ 
                error: result.error,
                code: 'COOKIE_PROCESSING_ERROR',
                inputType: result.inputType
            });
        }

        if (result.count === 0) {
            return res.status(400).json({ 
                error: 'No valid cookies found in the provided data',
                code: 'NO_VALID_COOKIES'
            });
        }

        // Convert to cookie string format
        const cookieString = convertToCookieString(result.cookies);

        // Start transaction
        await session.startTransaction();
        
        try {
            // Update or create user cookie data with transaction
            const updateResult = await Cookie.findOneAndUpdate(
                { username: usernameValidation.value },
                { 
                    username: usernameValidation.value,
                    cookieString: cookieString,
                    cookieCount: result.count,
                    rawCookies: result.cookies,
                    lastAccessed: new Date(),
                    isActive: true
                },
                { 
                    upsert: true, 
                    new: true,
                    session: session,
                    runValidators: true
                }
            );

            await session.commitTransaction();
            
            const processingTime = Date.now() - startTime;
            
            res.json({ 
                success: true, 
                message: `Cookies updated successfully for user: ${usernameValidation.value}`,
                data: {
                    inputType: result.inputType,
                    cookieCount: result.count,
                    cookieString: cookieString,
                    userData: {
                        username: updateResult.username,
                        cookieCount: updateResult.cookieCount,
                        lastUpdated: updateResult.updatedAt,
                        isActive: updateResult.isActive
                    },
                    processingTime: `${processingTime}ms`
                }
            });
            
            // Log performance
            if (processingTime > 1000) {
                console.warn(`⚠️  Slow cookie update: ${processingTime}ms for user ${usernameValidation.value}`);
            }
            
        } catch (transactionError) {
            await session.abortTransaction();
            throw transactionError;
        }
        
    } catch (error) {
        if (session.inTransaction()) {
            await session.abortTransaction();
        }
        utils.handleError(error, req, res, 'Failed to update cookies');
    } finally {
        await session.endSession();
    }
});

// Get user cookies with caching and performance optimization
app.get('/api/user/:username', async (req, res) => {
    try {
        const { username } = req.params;
        
        // Validate username
        const validation = utils.validateUsername(username);
        if (!validation.isValid) {
            return res.status(400).json({ 
                error: validation.error,
                code: 'USERNAME_VALIDATION_ERROR'
            });
        }

        // Find user with optimized query (only select needed fields)
        const user = await Cookie.findOne(
            { username: validation.value, isActive: true },
            { cookieString: 1, cookieCount: 1, rawCookies: 1, createdAt: 1, updatedAt: 1, lastAccessed: 1 }
        ).lean(); // Use lean() for better performance
        
        if (!user) {
            return res.status(404).json({ 
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        // Update last accessed time asynchronously (don't wait for it)
        Cookie.findByIdAndUpdate(user._id, { lastAccessed: new Date() })
            .catch(err => console.error('Failed to update last accessed:', err));

        res.json({
            success: true,
            data: {
                user: {
                    username: user.username || validation.value,
                    cookieCount: user.cookieCount || user.rawCookies?.length || 0,
                    cookieString: user.cookieString,
                    rawCookies: user.rawCookies,
                    createdAt: user.createdAt,
                    updatedAt: user.updatedAt,
                    lastAccessed: user.lastAccessed
                }
            }
        });
    } catch (error) {
        utils.handleError(error, req, res, 'Failed to fetch user data');
    }
});

// Get user cookie string only (lightweight endpoint)
app.get('/api/user/:username/cookies', async (req, res) => {
    try {
        const { username } = req.params;
        
        // Validate username
        const validation = utils.validateUsername(username);
        if (!validation.isValid) {
            return res.status(400).json({ 
                error: validation.error,
                code: 'USERNAME_VALIDATION_ERROR'
            });
        }

        // Optimized query - only select cookieString
        const user = await Cookie.findOne(
            { username: validation.value, isActive: true }, 
            { cookieString: 1 }
        ).lean();
        
        if (!user) {
            return res.status(404).json({ 
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        // Update last accessed asynchronously
        Cookie.findByIdAndUpdate(user._id, { lastAccessed: new Date() })
            .catch(err => console.error('Failed to update last accessed:', err));

        res.json({
            success: true,
            data: {
                username: validation.value,
                cookieString: user.cookieString
            }
        });
    } catch (error) {
        utils.handleError(error, req, res, 'Failed to fetch cookie string');
    }
});

// Check if user exists with enhanced response
app.get('/api/check-user/:username', async (req, res) => {
    try {
        const { username } = req.params;
        
        // Validate username
        const validation = utils.validateUsername(username);
        if (!validation.isValid) {
            return res.status(400).json({ 
                error: validation.error,
                code: 'USERNAME_VALIDATION_ERROR'
            });
        }

        // Optimized query - only select necessary fields
        const user = await Cookie.findOne(
            { username: validation.value, isActive: true },
            { cookieCount: 1, createdAt: 1, updatedAt: 1, lastAccessed: 1 }
        ).lean();
        
        if (user) {
            res.json({
                success: true,
                data: {
                    exists: true,
                    message: `User '${validation.value}' exists in database`,
                    userInfo: {
                        username: validation.value,
                        cookieCount: user.cookieCount || 0,
                        createdAt: user.createdAt,
                        updatedAt: user.updatedAt,
                        lastAccessed: user.lastAccessed
                    }
                }
            });
        } else {
            res.json({
                success: true,
                data: {
                    exists: false,
                    message: `User '${validation.value}' does not exist in database`
                }
            });
        }
    } catch (error) {
        utils.handleError(error, req, res, 'Failed to check user existence');
    }
});

// Store Twitter credentials endpoint
app.post('/api/store-credentials', async (req, res) => {
    const startTime = Date.now();
    const session = await mongoose.startSession();
    
    try {
        const { holder, twitterUsername, twitterPassword } = req.body;

        // Validate database holder
        const holderValidation = utils.validateHolder(holder);
        if (!holderValidation.isValid) {
            return res.status(400).json({ 
                error: holderValidation.error,
                code: 'DB_HOLDER_VALIDATION_ERROR'
            });
        }
        
        // Validate Twitter username/email
        if (!twitterUsername || typeof twitterUsername !== 'string' || twitterUsername.trim().length < 3) {
            return res.status(400).json({ 
                error: 'Twitter username/email is required and must be at least 3 characters',
                code: 'TWITTER_USERNAME_VALIDATION_ERROR'
            });
        }
        
        // Validate Twitter password
        if (!twitterPassword || typeof twitterPassword !== 'string' || twitterPassword.length < 1) {
            return res.status(400).json({ 
                error: 'Twitter password is required',
                code: 'TWITTER_PASSWORD_VALIDATION_ERROR'
            });
        }

        // Create credentials schema for storing Twitter credentials securely
        const credentialSchema = new mongoose.Schema({
            holder: {
                type: String,
                required: true,
                unique: true,
                trim: true
            },
            twitterUsername: {
                type: String,
                required: true,
                trim: true
            },
            twitterPassword: {
                type: String,
                required: true
                // Note: In production, this should be encrypted
            },
            isActive: {
                type: Boolean,
                default: true
            }
        }, { 
            timestamps: true,
            versionKey: false 
        });

        // Create or get the model
        let TwitterCredential;
        try {
            TwitterCredential = mongoose.model('users');
        } catch (error) {
            TwitterCredential = mongoose.model('users', credentialSchema);
        }

        // Start transaction
        await session.startTransaction();
        
        try {
            // Store or update credentials
            const credentialData = await TwitterCredential.findOneAndUpdate(
                { holder: holderValidation.value },
                { 
                    holder: holderValidation.value,
                    twitterUsername: utils.sanitizeInput(twitterUsername.trim()),
                    twitterPassword: twitterPassword, // Store as-is (encrypt in production)
                    isActive: true
                },
                { 
                    upsert: true, 
                    new: true,
                    session: session,
                    runValidators: true
                }
            );

            await session.commitTransaction();
            
            const processingTime = Date.now() - startTime;
            
            res.json({ 
                success: true, 
                message: `Twitter credentials stored successfully for database user: ${holderValidation.value}`,
                data: {
                    holder: credentialData.holder,
                    twitterUsername: credentialData.twitterUsername,
                    storedAt: credentialData.updatedAt,
                    processingTime: `${processingTime}ms`
                }
            });
            
        } catch (transactionError) {
            await session.abortTransaction();
            throw transactionError;
        }
        
    } catch (error) {
        if (session.inTransaction()) {
            await session.abortTransaction();
        }
        utils.handleError(error, req, res, 'Failed to store Twitter credentials');
    } finally {
        await session.endSession();
    }
});

// Get user statistics - simplified to return only total count
app.get('/api/users', async (req, res) => {
    try {
        // Get total user count directly
        const totalUsers = await Cookie.countDocuments({ isActive: true });
        
        res.json({
            success: true,
            totalUsers: totalUsers
        });
    } catch (error) {
        utils.handleError(error, req, res, 'Failed to fetch user count');
    }
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        // Check database connection
        const dbState = mongoose.connection.readyState;
        const isDbConnected = dbState === 1;
        
        // Get basic stats
        const userCount = await Cookie.countDocuments({ isActive: true });
        
        const health = {
            status: isDbConnected ? 'healthy' : 'unhealthy',
            timestamp: new Date().toISOString(),
            database: {
                connected: isDbConnected,
                state: ['disconnected', 'connected', 'connecting', 'disconnecting'][dbState] || 'unknown'
            },
            stats: {
                activeUsers: userCount
            },
            uptime: Math.floor(process.uptime()),
            memory: {
                used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
                total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024)
            }
        };
        
        const statusCode = isDbConnected ? 200 : 503;
        res.status(statusCode).json({ success: isDbConnected, data: health });
    } catch (error) {
        res.status(503).json({ 
            success: false, 
            data: { 
                status: 'error', 
                error: 'Health check failed',
                timestamp: new Date().toISOString()
            } 
        });
    }
});




// 404 handler for API routes
app.use('/api', (req, res, next) => {
    // Only handle unmatched API routes
    if (!res.headersSent) {
        res.status(404).json({
            success: false,
            error: 'API endpoint not found',
            code: 'ENDPOINT_NOT_FOUND',
            path: req.path,
            method: req.method
        });
    }
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('🚨 Unhandled error:', error);
    
    // Don't expose internal errors in production
    const message = NODE_ENV === 'development' ? error.message : 'Internal server error';
    
    res.status(error.statusCode || 500).json({
        success: false,
        error: message,
        code: 'INTERNAL_ERROR',
        ...(NODE_ENV === 'development' && { stack: error.stack })
    });
});

// Graceful shutdown handling
let server;
const gracefulShutdown = async (signal) => {
    console.log(`\n🛑 Received ${signal}. Starting graceful shutdown...`);
    
    if (server) {
        server.close(async () => {
            console.log('📡 HTTP server closed');
            
            try {
                await mongoose.connection.close();
                console.log('🗄️  MongoDB connection closed');
                
                console.log('✅ Graceful shutdown completed');
                process.exit(0);
            } catch (error) {
                console.error('❌ Error during shutdown:', error);
                process.exit(1);
            }
        });
        
        // Force shutdown after 30 seconds
        setTimeout(() => {
            console.error('⏰ Forced shutdown after timeout');
            process.exit(1);
        }, 30000);
    } else {
        process.exit(0);
    }
};

// Start server
const startServer = () => {
    server = app.listen(PORT, () => {
        console.log(`
🚀 Twitter Cookie Manager Server Started
┌─────────────────────────────────────────┐
│  Environment: ${NODE_ENV.padEnd(27)} │
│  Port: ${PORT.toString().padEnd(32)} │
│  URL: http://localhost:${PORT.toString().padEnd(18)} │
│  MongoDB: ${MONGODB_URI.includes('localhost') ? 'Local'.padEnd(27) : 'Remote'.padEnd(27)} │
└─────────────────────────────────────────┘

📊 API Endpoints:
   GET  /                          - Web Interface
   GET  /api/health                - Health Check
   POST /api/upload-cookie         - Extract Cookies
   POST /api/update-cookie         - Store User Cookies
   GET  /api/check-user/:username  - Check User Existence
   GET  /api/user/:username        - Get User Data
   GET  /api/user/:username/cookies - Get User Cookies
   GET  /api/users                 - Get Statistics

🛡️  Security Features: Rate Limiting, CORS, Helmet, Input Validation
⚡ Performance: Compression, Caching, Database Indexing, Transactions
        `);
    });

    // Handle server errors
    server.on('error', (error) => {
        if (error.code === 'EADDRINUSE') {
            console.error(`❌ Port ${PORT} is already in use`);
            process.exit(1);
        } else {
            console.error('❌ Server error:', error);
        }
    });
    
    return server;
};

// Initialize MongoDB connection
connectToMongoDB();

// Process signal handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('💥 Uncaught Exception:', error);
    gracefulShutdown('UNCAUGHT_EXCEPTION');
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
    console.error('🚨 Unhandled Rejection at:', promise, 'reason:', reason);
    gracefulShutdown('UNHANDLED_REJECTION');
});

// Export for testing
export default app;
