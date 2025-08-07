const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'pairup_secret_key_change_in_production';

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
            password TEXT NOT NULL,
            name TEXT,
            profile_picture TEXT,
            user_type TEXT DEFAULT 'student',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            is_verified BOOLEAN DEFAULT 0,
            google_id TEXT UNIQUE
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
        req.user = user;
        next();
    });
}

// API路由

// 用户注册
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, name, userType } = req.body;

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

                // 创建用户
                const stmt = db.prepare(`
                    INSERT INTO users (email, password, name, user_type) 
                    VALUES (?, ?, ?, ?)
                `);

                stmt.run([email, hashedPassword, name, userType || 'student'], function(err) {
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

                    res.status(201).json({
                        success: true,
                        message: '注册成功',
                        user: {
                            id: this.lastID,
                            email,
                            name,
                            userType: userType || 'student'
                        },
                        token
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

// 用户登出
app.post('/api/logout', authenticateToken, (req, res) => {
    // 在实际应用中，您可能想要将令牌加入黑名单
    res.json({
        success: true,
        message: '登出成功'
    });
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
    res.sendFile(path.join(__dirname, 'homepage.html'));
});

// 登录页路由
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
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

// 启动服务器
app.listen(PORT, () => {
    console.log('🚀 PairUp服务器启动成功!');
    console.log(`📍 服务器地址: http://localhost:${PORT}`);
    console.log(`🌐 前端页面: http://localhost:${PORT}/homepage.html`);
    console.log(`🔐 登录页面: http://localhost:${PORT}/login.html`);
    console.log(`📊 API健康检查: http://localhost:${PORT}/api/health`);
});

module.exports = app;