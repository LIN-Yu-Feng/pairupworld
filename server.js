const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const nodemailer = require('nodemailer');
require('dotenv').config({ path: './config.env' });

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'pairup_secret_key_change_in_production';

// Email configuration
const emailTransporter = nodemailer.createTransport({
    service: 'gmail', // You can change this to other email services
    auth: {
        user: process.env.EMAIL_USER || 'your-email@gmail.com',
        pass: process.env.EMAIL_PASS || 'your-app-password'
    }
});

// Verify email connection (optional)
emailTransporter.verify((error, success) => {
    if (error) {
        console.log('⚠️ Email service not configured properly:', error.message);
        console.log('📧 Email verification will be simulated (logged to console)');
    } else {
        console.log('✅ Email service configured and ready');
    }
});

// Helper functions for email verification
function generateVerificationCode() {
    return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
}

async function sendVerificationEmail(email, code, userName) {
    const mailOptions = {
        from: process.env.EMAIL_USER || 'noreply@pairup.world',
        to: email,
        subject: '🔐 PairUp - Email Verification Code',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
                <div style="background: linear-gradient(135deg, #ff7f00, #e66d00); padding: 30px; border-radius: 15px; text-align: center; margin-bottom: 20px;">
                    <h1 style="color: white; margin: 0; font-size: 2.5em;">PairUp</h1>
                    <p style="color: white; margin: 10px 0 0 0; font-size: 1.2em;">Welcome to the learning community!</p>
                </div>
                
                <div style="background: white; padding: 30px; border-radius: 15px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
                    <h2 style="color: #ff7f00; margin-top: 0;">Hi ${userName}! 👋</h2>
                    <p style="font-size: 1.1em; line-height: 1.6; color: #333;">
                        Thank you for registering with PairUp! To complete your account setup, please verify your email address using the verification code below:
                    </p>
                    
                    <div style="background: #f8f9fa; border: 2px dashed #ff7f00; border-radius: 10px; padding: 20px; text-align: center; margin: 25px 0;">
                        <p style="margin: 0; color: #666; font-size: 0.9em;">Your verification code is:</p>
                        <h1 style="font-size: 3em; color: #ff7f00; margin: 10px 0; letter-spacing: 5px; font-family: monospace;">${code}</h1>
                        <p style="margin: 0; color: #666; font-size: 0.9em;">This code expires in 15 minutes</p>
                    </div>
                    
                    <p style="color: #666; font-size: 0.95em; line-height: 1.5;">
                        <strong>Important:</strong> If you didn't create a PairUp account, please ignore this email. Your email address may have been entered by mistake.
                    </p>
                    
                    <div style="border-top: 1px solid #eee; margin-top: 25px; padding-top: 20px; text-align: center;">
                        <p style="color: #999; font-size: 0.85em; margin: 0;">
                            © 2024 PairUp - Connecting learners worldwide<br>
                            <a href="#" style="color: #ff7f00; text-decoration: none;">Privacy Policy</a> | 
                            <a href="#" style="color: #ff7f00; text-decoration: none;">Terms of Service</a>
                        </p>
                    </div>
                </div>
            </div>
        `
    };

    try {
        await emailTransporter.sendMail(mailOptions);
        console.log(`✅ Verification email sent to ${email}`);
        return true;
    } catch (error) {
        console.error('❌ Failed to send verification email:', error.message);
        // Fallback: log the code to console for development
        console.log(`📧 [EMAIL SIMULATION] Verification code for ${email}: ${code}`);
        return false;
    }
}

// 安全中间件
app.use(helmet({
    contentSecurityPolicy: false // 允许内联脚本用于开发
}));

// CORS配置
app.use(cors({
    origin: ['http://localhost:8000', 'http://127.0.0.1:8000', 'http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true
}));

// 请求限制
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15分钟
    max: 100, // 最多100个请求
    message: {
        error: '请求过于频繁，请稍后再试'
    }
});
app.use('/api/', limiter);

// 会话配置
app.use(session({
    secret: process.env.SESSION_SECRET || 'pairup_session_secret_change_in_production',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // 设置为true如果使用HTTPS
        maxAge: 24 * 60 * 60 * 1000 // 24小时
    }
}));

// 初始化Passport
app.use(passport.initialize());
app.use(passport.session());

// Google OAuth策略配置
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:3000/oauth2callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // 检查用户是否已存在
        db.get('SELECT * FROM users WHERE google_id = ?', [profile.id], async (err, user) => {
            if (err) {
                return done(err, null);
            }
            
            if (user) {
                // 用户已存在，更新最后登录时间
                db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
                return done(null, user);
            } else {
                // 检查是否已有相同邮箱的用户
                const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
                if (email) {
                    db.get('SELECT * FROM users WHERE email = ?', [email], (err, existingUser) => {
                        if (err) {
                            return done(err, null);
                        }
                        
                        if (existingUser) {
                            // 用户存在但没有Google ID，更新记录
                            db.run('UPDATE users SET google_id = ?, last_login = CURRENT_TIMESTAMP WHERE id = ?', 
                                [profile.id, existingUser.id], (err) => {
                                if (err) {
                                    return done(err, null);
                                }
                                existingUser.google_id = profile.id;
                                return done(null, existingUser);
                            });
                        } else {
                            // 创建新用户
                            const stmt = db.prepare(`
                                INSERT INTO users (email, name, google_id, user_type, profile_picture, is_verified) 
                                VALUES (?, ?, ?, ?, ?, ?)
                            `);
                            
                            const userData = [
                                email,
                                profile.displayName || profile.name?.givenName || 'Google User',
                                profile.id,
                                'student',
                                profile.photos && profile.photos[0] ? profile.photos[0].value : null,
                                1 // Google用户默认已验证
                            ];
                            
                            stmt.run(userData, function(err) {
                                if (err) {
                                    return done(err, null);
                                }
                                
                                const newUser = {
                                    id: this.lastID,
                                    email: email,
                                    name: profile.displayName || profile.name?.givenName || 'Google User',
                                    google_id: profile.id,
                                    user_type: 'student',
                                    profile_picture: profile.photos && profile.photos[0] ? profile.photos[0].value : null,
                                    is_verified: 1
                                };
                                
                                return done(null, newUser);
                            });
                            
                            stmt.finalize();
                        }
                    });
                } else {
                    return done(new Error('No email provided by Google'), null);
                }
            }
        });
    } catch (error) {
        return done(error, null);
    }
}));

// Passport序列化
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
        done(err, user);
    });
});

// 解析JSON
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// 静态文件服务
app.use(express.static(__dirname));

// 数据库连接
const db = new sqlite3.Database('./database/pairup.db', (err) => {
    if (err) {
        console.error('❌ 数据库连接失败:', err.message);
    } else {
        console.log('✅ 已连接到SQLite数据库');
        initializeDatabase();
    }
});

// 初始化数据库表
function initializeDatabase() {
    const createUsersTable = `
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT,
            name TEXT,
            profile_picture TEXT,
            user_type TEXT DEFAULT 'student',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            is_verified BOOLEAN DEFAULT 0,
            google_id TEXT UNIQUE,
            phone TEXT,
            bio TEXT,
            location TEXT,
            birth_date DATE,
            preferences TEXT,
            is_active BOOLEAN DEFAULT 1,
            verification_code TEXT,
            verification_expires DATETIME,
            email_verified BOOLEAN DEFAULT 0
        )
    `;
    
    const createSessionsTable = `
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    `;

    db.run(createUsersTable, (err) => {
        if (err) {
            console.error('❌ 创建用户表失败:', err.message);
        } else {
            console.log('✅ 用户表已创建/验证');
        }
    });

    db.run(createSessionsTable, (err) => {
        if (err) {
            console.error('❌ 创建会话表失败:', err.message);
        } else {
            console.log('✅ 会话表已创建/验证');
        }
    });
}

// JWT验证中间件
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: '需要访问令牌' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: '无效的令牌' });
        }

        // 检查会话是否在数据库中存在且未过期
        db.get('SELECT * FROM sessions WHERE token = ? AND expires_at > datetime("now")', [token], (dbErr, session) => {
            if (dbErr) {
                console.error('会话验证错误:', dbErr);
                return res.status(500).json({ error: '服务器内部错误' });
            }

            if (!session) {
                return res.status(403).json({ error: '会话已过期或无效' });
            }

            // 检查用户是否仍然活跃
            db.get('SELECT * FROM users WHERE id = ? AND is_active = 1', [user.id], (userErr, activeUser) => {
                if (userErr) {
                    console.error('用户验证错误:', userErr);
                    return res.status(500).json({ error: '服务器内部错误' });
                }

                if (!activeUser) {
                    return res.status(403).json({ error: '用户账户已停用' });
                }

                req.user = user;
                next();
            });
        });
    });
}

// API路由

// 用户注册
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, name, userType, phone, bio } = req.body;

        // 验证输入
        if (!email || !password || !name) {
            return res.status(400).json({ 
                error: '邮箱、密码和姓名都是必填项' 
            });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ 
                error: '请输入有效的邮箱地址' 
            });
        }

        if (password.length < 6) {
            return res.status(400).json({ 
                error: '密码长度至少6个字符' 
            });
        }

        // 检查用户是否已存在
        db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
            if (err) {
                console.error('数据库查询错误:', err);
                return res.status(500).json({ error: '服务器内部错误' });
            }

            if (row) {
                return res.status(400).json({ error: '该邮箱已被注册' });
            }

            try {
                // 加密密码
                const saltRounds = 12;
                const hashedPassword = await bcrypt.hash(password, saltRounds);

                // 生成验证码
                const verificationCode = generateVerificationCode();
                const verificationExpires = new Date(Date.now() + 15 * 60 * 1000); // 15分钟后过期

                // 创建用户
                const stmt = db.prepare(`
                    INSERT INTO users (email, password, name, user_type, phone, bio, verification_code, verification_expires) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                `);

                stmt.run([email, hashedPassword, name, userType || 'student', phone || null, bio || null, verificationCode, verificationExpires.toISOString()], function(err) {
                    if (err) {
                        console.error('用户创建错误:', err);
                        return res.status(500).json({ error: '用户创建失败' });
                    }

                    // 生成JWT令牌
                    const token = jwt.sign(
                        { 
                            id: this.lastID, 
                            email, 
                            name,
                            userType: userType || 'student'
                        },
                        JWT_SECRET,
                        { expiresIn: '7d' }
                    );

                    // 发送验证邮件
                    sendVerificationEmail(email, verificationCode, name).then(() => {
                        console.log(`📧 Verification email sent to ${email}`);
                    }).catch((emailError) => {
                        console.error('Email send error:', emailError);
                    });

                    // 注意：不立即创建会话，用户需要先验证邮箱
                    res.status(201).json({
                        success: true,
                        message: '注册成功！请查看您的邮箱并输入验证码以完成注册。',
                        user: {
                            id: this.lastID,
                            email,
                            name,
                            userType: userType || 'student',
                            phone: phone || null,
                            bio: bio || null,
                            emailVerified: false
                        },
                        requiresVerification: true
                    });
                });

                stmt.finalize();
            } catch (hashError) {
                console.error('密码加密错误:', hashError);
                res.status(500).json({ error: '服务器内部错误' });
            }
        });

    } catch (error) {
        console.error('注册错误:', error);
        res.status(500).json({ error: '服务器内部错误' });
    }
});

// 验证邮箱
app.post('/api/verify-email', async (req, res) => {
    try {
        const { email, verificationCode } = req.body;

        // 验证输入
        if (!email || !verificationCode) {
            return res.status(400).json({ 
                error: '邮箱和验证码都是必填项' 
            });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ 
                error: '请输入有效的邮箱地址' 
            });
        }

        // 查找用户和验证码
        db.get('SELECT * FROM users WHERE email = ? AND verification_code = ?', [email, verificationCode], (err, user) => {
            if (err) {
                console.error('数据库查询错误:', err);
                return res.status(500).json({ error: '服务器内部错误' });
            }

            if (!user) {
                return res.status(400).json({ error: '验证码无效或邮箱不存在' });
            }

            // 检查验证码是否过期
            const now = new Date();
            const expiresAt = new Date(user.verification_expires);
            
            if (now > expiresAt) {
                return res.status(400).json({ error: '验证码已过期，请重新申请' });
            }

            // 更新用户为已验证状态
            db.run('UPDATE users SET email_verified = 1, verification_code = NULL, verification_expires = NULL WHERE id = ?', 
                [user.id], (updateErr) => {
                    if (updateErr) {
                        console.error('用户验证更新错误:', updateErr);
                        return res.status(500).json({ error: '验证失败' });
                    }

                    // 生成JWT令牌
                    const token = jwt.sign(
                        { 
                            id: user.id, 
                            email: user.email, 
                            name: user.name,
                            userType: user.user_type
                        },
                        JWT_SECRET,
                        { expiresIn: '7d' }
                    );

                    // 存储会话到数据库
                    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7天后过期
                    db.run('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)', 
                        [user.id, token, expiresAt.toISOString()], (sessionErr) => {
                            if (sessionErr) {
                                console.error('会话存储错误:', sessionErr);
                            }
                        });

                    res.json({
                        success: true,
                        message: '邮箱验证成功！',
                        user: {
                            id: user.id,
                            email: user.email,
                            name: user.name,
                            userType: user.user_type,
                            profilePicture: user.profile_picture,
                            emailVerified: true
                        },
                        token
                    });
                });
        });

    } catch (error) {
        console.error('邮箱验证错误:', error);
        res.status(500).json({ error: '服务器内部错误' });
    }
});

// 重新发送验证码
app.post('/api/resend-verification', async (req, res) => {
    try {
        const { email } = req.body;

        // 验证输入
        if (!email) {
            return res.status(400).json({ 
                error: '邮箱是必填项' 
            });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ 
                error: '请输入有效的邮箱地址' 
            });
        }

        // 查找用户
        db.get('SELECT * FROM users WHERE email = ? AND email_verified = 0', [email], async (err, user) => {
            if (err) {
                console.error('数据库查询错误:', err);
                return res.status(500).json({ error: '服务器内部错误' });
            }

            if (!user) {
                return res.status(400).json({ error: '邮箱不存在或已验证' });
            }

            // 生成新的验证码
            const verificationCode = generateVerificationCode();
            const verificationExpires = new Date(Date.now() + 15 * 60 * 1000); // 15分钟后过期

            // 更新验证码
            db.run('UPDATE users SET verification_code = ?, verification_expires = ? WHERE id = ?', 
                [verificationCode, verificationExpires.toISOString(), user.id], async (updateErr) => {
                    if (updateErr) {
                        console.error('验证码更新错误:', updateErr);
                        return res.status(500).json({ error: '验证码生成失败' });
                    }

                    // 发送验证邮件
                    try {
                        await sendVerificationEmail(email, verificationCode, user.name);
                        res.json({
                            success: true,
                            message: '验证码已重新发送至您的邮箱'
                        });
                    } catch (emailError) {
                        console.error('邮件发送错误:', emailError);
                        res.status(500).json({ error: '验证码发送失败，请稍后重试' });
                    }
                });
        });

    } catch (error) {
        console.error('重新发送验证码错误:', error);
        res.status(500).json({ error: '服务器内部错误' });
    }
});

// 用户登录
app.post('/api/login', (req, res) => {
    try {
        const { email, password } = req.body;

        // 验证输入
        if (!email || !password) {
            return res.status(400).json({ 
                error: '邮箱和密码都是必填项' 
            });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ 
                error: '请输入有效的邮箱地址' 
            });
        }

        // 查找用户
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) {
                console.error('数据库查询错误:', err);
                return res.status(500).json({ error: '服务器内部错误' });
            }

            if (!user) {
                return res.status(401).json({ error: '邮箱或密码错误' });
            }

            // 检查邮箱是否已验证
            if (!user.email_verified) {
                return res.status(403).json({ 
                    error: '请先验证您的邮箱地址',
                    requiresVerification: true,
                    email: email
                });
            }

            try {
                // 验证密码
                const isValidPassword = await bcrypt.compare(password, user.password);
                
                if (!isValidPassword) {
                    return res.status(401).json({ error: '邮箱或密码错误' });
                }

                // 更新最后登录时间
                db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

                // 生成JWT令牌
                const token = jwt.sign(
                    { 
                        id: user.id, 
                        email: user.email, 
                        name: user.name,
                        userType: user.user_type
                    },
                    JWT_SECRET,
                    { expiresIn: '7d' }
                );

                // 存储会话到数据库
                const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7天后过期
                db.run('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)', 
                    [user.id, token, expiresAt.toISOString()], (sessionErr) => {
                        if (sessionErr) {
                            console.error('会话存储错误:', sessionErr);
                        }
                    });

                res.json({
                    success: true,
                    message: '登录成功',
                    user: {
                        id: user.id,
                        email: user.email,
                        name: user.name,
                        userType: user.user_type,
                        profilePicture: user.profile_picture
                    },
                    token
                });

            } catch (compareError) {
                console.error('密码验证错误:', compareError);
                res.status(500).json({ error: '服务器内部错误' });
            }
        });

    } catch (error) {
        console.error('登录错误:', error);
        res.status(500).json({ error: '服务器内部错误' });
    }
});

// 获取用户信息
app.get('/api/user/profile', authenticateToken, (req, res) => {
    db.get('SELECT id, email, name, user_type, profile_picture, created_at FROM users WHERE id = ?', 
        [req.user.id], (err, user) => {
            if (err) {
                console.error('数据库查询错误:', err);
                return res.status(500).json({ error: '服务器内部错误' });
            }

            if (!user) {
                return res.status(404).json({ error: '用户不存在' });
            }

            res.json({
                success: true,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    userType: user.user_type,
                    profilePicture: user.profile_picture,
                    memberSince: user.created_at
                }
            });
        });
});

// 更新用户信息
app.put('/api/user/profile', authenticateToken, (req, res) => {
    try {
        const { name, phone, bio, location, birth_date, preferences, user_type } = req.body;
        const userId = req.user.id;

        // 验证输入
        if (name && name.trim().length < 2) {
            return res.status(400).json({ error: '姓名至少需要2个字符' });
        }

        if (phone && !validator.isMobilePhone(phone, 'any')) {
            return res.status(400).json({ error: '请输入有效的手机号码' });
        }

        // 构建更新查询
        const updateFields = [];
        const updateValues = [];

        if (name !== undefined) {
            updateFields.push('name = ?');
            updateValues.push(name.trim());
        }
        if (phone !== undefined) {
            updateFields.push('phone = ?');
            updateValues.push(phone);
        }
        if (bio !== undefined) {
            updateFields.push('bio = ?');
            updateValues.push(bio);
        }
        if (location !== undefined) {
            updateFields.push('location = ?');
            updateValues.push(location);
        }
        if (birth_date !== undefined) {
            updateFields.push('birth_date = ?');
            updateValues.push(birth_date);
        }
        if (preferences !== undefined) {
            updateFields.push('preferences = ?');
            updateValues.push(typeof preferences === 'object' ? JSON.stringify(preferences) : preferences);
        }
        if (user_type !== undefined) {
            updateFields.push('user_type = ?');
            updateValues.push(user_type);
        }

        if (updateFields.length === 0) {
            return res.status(400).json({ error: '没有提供要更新的字段' });
        }

        updateValues.push(userId);
        const query = `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`;

        db.run(query, updateValues, function(err) {
            if (err) {
                console.error('用户信息更新错误:', err);
                return res.status(500).json({ error: '用户信息更新失败' });
            }

            // 获取更新后的用户信息
            db.get('SELECT id, email, name, user_type, profile_picture, phone, bio, location, birth_date, preferences, created_at FROM users WHERE id = ?', 
                [userId], (err, user) => {
                    if (err) {
                        console.error('数据库查询错误:', err);
                        return res.status(500).json({ error: '服务器内部错误' });
                    }

                    res.json({
                        success: true,
                        message: '用户信息更新成功',
                        user: {
                            id: user.id,
                            email: user.email,
                            name: user.name,
                            userType: user.user_type,
                            profilePicture: user.profile_picture,
                            phone: user.phone,
                            bio: user.bio,
                            location: user.location,
                            birthDate: user.birth_date,
                            preferences: user.preferences ? JSON.parse(user.preferences) : null,
                            memberSince: user.created_at
                        }
                    });
                });
        });

    } catch (error) {
        console.error('用户信息更新错误:', error);
        res.status(500).json({ error: '服务器内部错误' });
    }
});

// 删除用户账户
app.delete('/api/user/account', authenticateToken, (req, res) => {
    try {
        const userId = req.user.id;

        // 软删除 - 设置账户为不活跃
        db.run('UPDATE users SET is_active = 0, email = email || "_deleted_" || datetime("now") WHERE id = ?', 
            [userId], function(err) {
                if (err) {
                    console.error('账户删除错误:', err);
                    return res.status(500).json({ error: '账户删除失败' });
                }

                // 删除所有会话
                db.run('DELETE FROM sessions WHERE user_id = ?', [userId], (err) => {
                    if (err) {
                        console.error('会话清理错误:', err);
                    }
                });

                res.json({
                    success: true,
                    message: '账户已成功删除'
                });
            });

    } catch (error) {
        console.error('账户删除错误:', error);
        res.status(500).json({ error: '服务器内部错误' });
    }
});

// 获取所有用户（管理员功能）
app.get('/api/admin/users', authenticateToken, (req, res) => {
    // 简单的管理员检查 - 在生产环境中应该有更复杂的权限系统
    if (req.user.userType !== 'admin') {
        return res.status(403).json({ error: '权限不足' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    db.all('SELECT id, email, name, user_type, profile_picture, created_at, last_login, is_verified, is_active FROM users WHERE is_active = 1 ORDER BY created_at DESC LIMIT ? OFFSET ?', 
        [limit, offset], (err, users) => {
            if (err) {
                console.error('数据库查询错误:', err);
                return res.status(500).json({ error: '服务器内部错误' });
            }

            // 获取总用户数
            db.get('SELECT COUNT(*) as total FROM users WHERE is_active = 1', (err, count) => {
                if (err) {
                    console.error('数据库查询错误:', err);
                    return res.status(500).json({ error: '服务器内部错误' });
                }

                res.json({
                    success: true,
                    users: users.map(user => ({
                        id: user.id,
                        email: user.email,
                        name: user.name,
                        userType: user.user_type,
                        profilePicture: user.profile_picture,
                        memberSince: user.created_at,
                        lastLogin: user.last_login,
                        isVerified: !!user.is_verified
                    })),
                    pagination: {
                        currentPage: page,
                        totalPages: Math.ceil(count.total / limit),
                        totalUsers: count.total,
                        limit
                    }
                });
            });
        });
});

// 用户登出
app.post('/api/logout', authenticateToken, (req, res) => {
    // 在实际应用中，您可能想要将令牌加入黑名单
    // 或者从sessions表中删除相关会话
    const userId = req.user.id;
    
    // 清理该用户的所有会话
    db.run('DELETE FROM sessions WHERE user_id = ?', [userId], (err) => {
        if (err) {
            console.error('会话清理错误:', err);
        }
    });

    res.json({
        success: true,
        message: '登出成功'
            });
});

// 管理员专用 - 验证用户邮箱
app.put('/api/admin/users/:id/verify', authenticateToken, (req, res) => {
    if (req.user.userType !== 'admin') {
        return res.status(403).json({ error: '权限不足' });
    }

    const userId = req.params.id;

    db.run('UPDATE users SET email_verified = 1, verification_code = NULL, verification_expires = NULL WHERE id = ?', 
        [userId], function(err) {
            if (err) {
                console.error('管理员验证用户错误:', err);
                return res.status(500).json({ error: '验证用户失败' });
            }

            if (this.changes === 0) {
                return res.status(404).json({ error: '用户不存在' });
            }

            res.json({
                success: true,
                message: '用户邮箱已验证'
            });
        });
});

// 管理员专用 - 删除用户
app.delete('/api/admin/users/:id', authenticateToken, (req, res) => {
    if (req.user.userType !== 'admin') {
        return res.status(403).json({ error: '权限不足' });
    }

    const userId = req.params.id;

    // 软删除用户
    db.run('UPDATE users SET is_active = 0, email = email || "_deleted_" || datetime("now") WHERE id = ?', 
        [userId], function(err) {
            if (err) {
                console.error('管理员删除用户错误:', err);
                return res.status(500).json({ error: '删除用户失败' });
            }

            if (this.changes === 0) {
                return res.status(404).json({ error: '用户不存在' });
            }

            // 删除用户的所有会话
            db.run('DELETE FROM sessions WHERE user_id = ?', [userId], (sessionErr) => {
                if (sessionErr) {
                    console.error('删除用户会话错误:', sessionErr);
                }
            });

            res.json({
                success: true,
                message: '用户已删除'
            });
        });
});

// 管理员专用 - 更新用户信息
app.put('/api/admin/users/:id', authenticateToken, (req, res) => {
    if (req.user.userType !== 'admin') {
        return res.status(403).json({ error: '权限不足' });
    }

    const userId = req.params.id;
    const { name, email, user_type, phone, bio, is_active, email_verified } = req.body;

    const updateFields = [];
    const updateValues = [];

    if (name !== undefined) {
        updateFields.push('name = ?');
        updateValues.push(name);
    }
    if (email !== undefined) {
        updateFields.push('email = ?');
        updateValues.push(email);
    }
    if (user_type !== undefined) {
        updateFields.push('user_type = ?');
        updateValues.push(user_type);
    }
    if (phone !== undefined) {
        updateFields.push('phone = ?');
        updateValues.push(phone);
    }
    if (bio !== undefined) {
        updateFields.push('bio = ?');
        updateValues.push(bio);
    }
    if (is_active !== undefined) {
        updateFields.push('is_active = ?');
        updateValues.push(is_active ? 1 : 0);
    }
    if (email_verified !== undefined) {
        updateFields.push('email_verified = ?');
        updateValues.push(email_verified ? 1 : 0);
    }

    if (updateFields.length === 0) {
        return res.status(400).json({ error: '没有提供要更新的字段' });
    }

    updateValues.push(userId);
    const query = `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`;

    db.run(query, updateValues, function(err) {
        if (err) {
            console.error('管理员更新用户错误:', err);
            return res.status(500).json({ error: '更新用户失败' });
        }

        if (this.changes === 0) {
            return res.status(404).json({ error: '用户不存在' });
        }

        res.json({
            success: true,
            message: '用户信息已更新'
        });
    });
});

// 管理员专用 - 获取系统统计
app.get('/api/admin/stats', authenticateToken, (req, res) => {
    if (req.user.userType !== 'admin') {
        return res.status(403).json({ error: '权限不足' });
    }

    const stats = {};

    // 获取用户统计
    db.get('SELECT COUNT(*) as total FROM users WHERE is_active = 1', (err, totalUsers) => {
        if (err) {
            console.error('获取用户统计错误:', err);
            return res.status(500).json({ error: '获取统计失败' });
        }

        stats.totalUsers = totalUsers.total;

        db.get('SELECT COUNT(*) as verified FROM users WHERE is_active = 1 AND email_verified = 1', (err, verifiedUsers) => {
            if (err) {
                console.error('获取验证用户统计错误:', err);
                return res.status(500).json({ error: '获取统计失败' });
            }

            stats.verifiedUsers = verifiedUsers.verified;

            // 获取今日注册用户
            db.get('SELECT COUNT(*) as today FROM users WHERE is_active = 1 AND date(created_at) = date("now")', (err, todayUsers) => {
                if (err) {
                    console.error('获取今日用户统计错误:', err);
                    return res.status(500).json({ error: '获取统计失败' });
                }

                stats.todayRegistrations = todayUsers.today;

                // 获取活跃会话
                db.get('SELECT COUNT(*) as active FROM sessions WHERE expires_at > datetime("now")', (err, activeSessions) => {
                    if (err) {
                        console.error('获取会话统计错误:', err);
                        return res.status(500).json({ error: '获取统计失败' });
                    }

                    stats.activeSessions = activeSessions.active;
                    stats.serverUptime = process.uptime();

                    res.json({
                        success: true,
                        stats
                    });
                });
            });
        });
    });
});

// 管理员专用 - 清理过期会话
app.delete('/api/admin/sessions/expired', authenticateToken, (req, res) => {
    if (req.user.userType !== 'admin') {
        return res.status(403).json({ error: '权限不足' });
    }

    db.run('DELETE FROM sessions WHERE expires_at <= datetime("now")', function(err) {
        if (err) {
            console.error('清理过期会话错误:', err);
            return res.status(500).json({ error: '清理会话失败' });
        }

        res.json({
            success: true,
            message: `已清理 ${this.changes} 个过期会话`
        });
    });
});

// 管理员专用 - 获取单个用户信息
app.get('/api/admin/users/:id', authenticateToken, (req, res) => {
    if (req.user.userType !== 'admin') {
        return res.status(403).json({ error: '权限不足' });
    }

    const userId = req.params.id;

    db.get('SELECT id, email, name, user_type, profile_picture, phone, bio, location, birth_date, preferences, created_at, last_login, is_verified, email_verified, is_active FROM users WHERE id = ?', 
        [userId], (err, user) => {
            if (err) {
                console.error('获取用户信息错误:', err);
                return res.status(500).json({ error: '服务器内部错误' });
            }

            if (!user) {
                return res.status(404).json({ error: '用户不存在' });
            }

            res.json({
                success: true,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    userType: user.user_type,
                    profilePicture: user.profile_picture,
                    phone: user.phone,
                    bio: user.bio,
                    location: user.location,
                    birthDate: user.birth_date,
                    preferences: user.preferences ? JSON.parse(user.preferences) : null,
                    memberSince: user.created_at,
                    lastLogin: user.last_login,
                    isVerified: !!user.is_verified,
                    emailVerified: !!user.email_verified,
                    isActive: !!user.is_active
                }
            });
        });
});

// Google OAuth路由
app.get('/auth/google', 
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/oauth2callback',
    passport.authenticate('google', { failureRedirect: '/login.html?error=google_auth_failed' }),
    (req, res) => {
        // 成功登录，生成JWT token
        const token = jwt.sign(
            { 
                id: req.user.id, 
                email: req.user.email, 
                name: req.user.name,
                userType: req.user.user_type
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        // 重定向到前端，带上token
        res.redirect(`/login.html?token=${token}&user=${encodeURIComponent(JSON.stringify({
            id: req.user.id,
            email: req.user.email,
            name: req.user.name,
            userType: req.user.user_type,
            profilePicture: req.user.profile_picture
        }))}`);
    }
);

// Google Sign-In API endpoint for client-side authentication
app.post('/api/google-signin', async (req, res) => {
    try {
        const { idToken, profile } = req.body;
        
        if (!idToken || !profile) {
            return res.status(400).json({ 
                success: false, 
                error: '缺少必要的认证信息' 
            });
        }
        
        // In a production environment, you should verify the idToken with Google
        // For now, we'll trust the client-side authentication and use profile data
        
        const { id: googleId, email, name, imageUrl } = profile;
        
        if (!email || !googleId) {
            return res.status(400).json({ 
                success: false, 
                error: '无效的Google账户信息' 
            });
        }
        
        // Check if user already exists
        db.get('SELECT * FROM users WHERE google_id = ? OR email = ?', [googleId, email], (err, existingUser) => {
            if (err) {
                console.error('数据库查询错误:', err);
                return res.status(500).json({ 
                    success: false, 
                    error: '服务器内部错误' 
                });
            }
            
            if (existingUser) {
                // Update existing user
                const updateQuery = existingUser.google_id ? 
                    'UPDATE users SET last_login = CURRENT_TIMESTAMP, profile_picture = ? WHERE id = ?' :
                    'UPDATE users SET google_id = ?, last_login = CURRENT_TIMESTAMP, profile_picture = ?, is_verified = 1 WHERE id = ?';
                
                const updateParams = existingUser.google_id ? 
                    [imageUrl, existingUser.id] :
                    [googleId, imageUrl, existingUser.id];
                
                db.run(updateQuery, updateParams, (updateErr) => {
                    if (updateErr) {
                        console.error('用户更新错误:', updateErr);
                        return res.status(500).json({ 
                            success: false, 
                            error: '用户信息更新失败' 
                        });
                    }
                    
                    // Generate JWT token
                    const token = jwt.sign(
                        {
                            id: existingUser.id,
                            email: existingUser.email,
                            name: existingUser.name,
                            userType: existingUser.user_type
                        },
                        JWT_SECRET,
                        { expiresIn: '7d' }
                    );
                    
                    res.json({
                        success: true,
                        message: '登录成功',
                        user: {
                            id: existingUser.id,
                            email: existingUser.email,
                            name: existingUser.name,
                            userType: existingUser.user_type,
                            profilePicture: imageUrl
                        },
                        token
                    });
                });
            } else {
                // Create new user
                const stmt = db.prepare(`
                    INSERT INTO users (email, name, google_id, user_type, profile_picture, is_verified) 
                    VALUES (?, ?, ?, ?, ?, ?)
                `);
                
                stmt.run([email, name, googleId, 'student', imageUrl, 1], function(createErr) {
                    if (createErr) {
                        console.error('用户创建错误:', createErr);
                        return res.status(500).json({ 
                            success: false, 
                            error: '用户创建失败' 
                        });
                    }
                    
                    // Generate JWT token
                    const token = jwt.sign(
                        {
                            id: this.lastID,
                            email: email,
                            name: name,
                            userType: 'student'
                        },
                        JWT_SECRET,
                        { expiresIn: '7d' }
                    );
                    
                    res.json({
                        success: true,
                        message: '注册并登录成功',
                        user: {
                            id: this.lastID,
                            email: email,
                            name: name,
                            userType: 'student',
                            profilePicture: imageUrl
                        },
                        token
                    });
                });
                
                stmt.finalize();
            }
        });
        
    } catch (error) {
        console.error('Google Sign-In API错误:', error);
        res.status(500).json({ 
            success: false, 
            error: '服务器内部错误' 
        });
    }
});

// 健康检查
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// 主页路由
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 登录页路由
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// 个人资料页路由
app.get('/profile', (req, res) => {
    res.sendFile(path.join(__dirname, 'profile.html'));
});

// 管理员页面路由
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// 404处理
app.use((req, res) => {
    res.status(404).json({ error: '页面未找到' });
});

// 错误处理中间件
app.use((err, req, res, next) => {
    console.error('服务器错误:', err);
    res.status(500).json({ error: '服务器内部错误' });
});

// 优雅关闭
process.on('SIGINT', () => {
    console.log('\n正在关闭服务器...');
    db.close((err) => {
        if (err) {
            console.error('数据库关闭错误:', err.message);
        } else {
            console.log('✅ 数据库连接已关闭');
        }
        process.exit(0);
    });
});

// 定期清理过期会话
function cleanupExpiredSessions() {
    db.run('DELETE FROM sessions WHERE expires_at <= datetime("now")', (err) => {
        if (err) {
            console.error('过期会话清理错误:', err);
        } else {
            console.log('🧹 过期会话已清理');
        }
    });
}

// 每小时清理一次过期会话
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

// 启动服务器
app.listen(PORT, () => {
    console.log('🚀 PairUp服务器启动成功!');
    console.log(`📍 服务器地址: http://localhost:${PORT}`);
    console.log(`🌐 前端页面: http://localhost:${PORT}/index.html`);
    console.log(`🔐 登录页面: http://localhost:${PORT}/login.html`);
    console.log(`📊 API健康检查: http://localhost:${PORT}/api/health`);
    
    // 启动时清理一次过期会话
    cleanupExpiredSessions();
});

module.exports = app;