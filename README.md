# PairUp - 学生和导师配对平台

一个现代化的全栈Web应用，帮助学生找到合适的导师，实现个性化学习体验。

## 🚀 功能特性

### ✅ 已实现功能
- **用户认证系统**
  - 用户注册和登录
  - 密码加密存储 (bcrypt)
  - JWT令牌认证
  - 会话管理

- **安全特性**
  - 请求频率限制
  - CORS保护
  - SQL注入防护
  - XSS防护 (Helmet)

- **用户界面**
  - 响应式设计
  - 现代化UI/UX
  - 动画效果
  - 移动端适配

- **数据库**
  - SQLite数据库
  - 用户信息存储
  - 会话管理

### 🔄 计划功能
- Google OAuth登录
- 用户资料管理
- 导师匹配算法
- 实时消息系统
- 课程管理
- 支付集成

## 📋 技术栈

### 后端
- **Node.js** - 服务器运行时
- **Express.js** - Web框架
- **SQLite** - 数据库
- **bcryptjs** - 密码加密
- **jsonwebtoken** - JWT认证
- **helmet** - 安全中间件
- **cors** - 跨域处理

### 前端
- **HTML5** - 页面结构
- **CSS3** - 样式设计
- **JavaScript (ES6+)** - 交互逻辑
- **Fetch API** - HTTP请求

## 🛠️ 安装和运行

### 前置要求
- Node.js (版本 16 或更高)
- npm 或 yarn

### 安装步骤

1. **克隆项目**
   ```bash
   git clone <repository-url>
   cd pairup.world
   ```

2. **安装依赖**
   ```bash
   npm install
   ```

3. **启动服务器**
   ```bash
   npm start
   ```

   或者开发模式 (自动重启):
   ```bash
   npm run dev
   ```

4. **访问应用**
   - 前端界面: http://localhost:3000
   - API健康检查: http://localhost:3000/api/health

## 📁 项目结构

```
pairup.world/
├── server.js              # 主服务器文件
├── package.json           # 项目依赖配置
├── config.env            # 环境变量配置
├── database/             # 数据库文件
│   └── pairup.db        # SQLite数据库
├── homepage.html         # 主页
├── login.html           # 登录/注册页
├── pairuplogo.png       # 网站logo
└── README.md           # 项目说明文档
```

## 🔌 API 端点

### 认证相关
- `POST /api/register` - 用户注册
- `POST /api/login` - 用户登录
- `POST /api/logout` - 用户登出
- `GET /api/user/profile` - 获取用户信息

### 系统相关
- `GET /api/health` - 健康检查
- `GET /` - 主页
- `GET /login` - 登录页

## 📊 数据库结构

### 用户表 (users)
```sql
CREATE TABLE users (
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
);
```

### 会话表 (sessions)
```sql
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

## 🔐 环境配置

在 `config.env` 文件中配置以下变量：

```env
# 服务器配置
PORT=3000
NODE_ENV=development

# JWT密钥 (生产环境请更改)
JWT_SECRET=your_super_secret_jwt_key

# 数据库路径
DB_PATH=./database/pairup.db

# CORS配置
ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000
```

## 🚦 使用指南

### 注册新用户
1. 访问 http://localhost:3000/login.html
2. 填写邮箱和密码 (至少6位)
3. 点击 "Sign Up"
4. 注册成功后自动跳转到主页

### 用户登录
1. 在登录页面点击 "Login" 切换模式
2. 输入已注册的邮箱和密码
3. 点击 "Login"
4. 登录成功后跳转到主页

### API调用示例
```javascript
// 注册用户
const response = await fetch('http://localhost:3000/api/register', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        email: 'user@example.com',
        password: 'password123',
        name: 'John Doe'
    })
});

// 获取用户信息
const userResponse = await fetch('http://localhost:3000/api/user/profile', {
    headers: {
        'Authorization': `Bearer ${token}`
    }
});
```

## 🛡️ 安全特性

- **密码加密**: 使用bcrypt进行密码哈希
- **JWT认证**: 安全的令牌认证系统
- **请求限制**: 防止暴力破解攻击
- **输入验证**: 防止SQL注入和XSS攻击
- **CORS配置**: 控制跨域访问
- **Helmet保护**: 设置安全HTTP头

## 🐛 故障排除

### 常见问题

1. **无法连接数据库**
   - 确保 `database` 文件夹存在
   - 检查数据库权限

2. **端口被占用**
   - 更改 `config.env` 中的 `PORT` 值
   - 或终止占用端口的进程

3. **JWT错误**
   - 检查 `JWT_SECRET` 配置
   - 确保令牌格式正确

4. **CORS错误**
   - 检查 `ALLOWED_ORIGINS` 配置
   - 确保前端地址在允许列表中

## 📝 开发日志

### v1.0.0 (当前版本)
- ✅ 基础认证系统
- ✅ 用户注册和登录
- ✅ JWT令牌认证
- ✅ SQLite数据库集成
- ✅ 安全中间件
- ✅ 响应式前端界面

### 下一版本计划
- 🔄 Google OAuth集成
- 🔄 用户资料管理
- 🔄 导师匹配系统
- 🔄 实时聊天功能

## 📞 支持

如有问题或建议，请联系开发团队。

---

**PairUp Team** - 让学习更有效，让教育更个性化 🎓