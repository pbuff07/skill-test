---
name: sechecker
description: Sensitive information leakage detector. Scans project directories/files for hardcoded credentials, API keys, passwords, tokens, and other sensitive data. Outputs file paths and line numbers where issues are found.
license: MIT
---

# SEChecker - 敏感信息泄露检测工具

SEChecker 扫描项目目录或文件，检测硬编码的敏感信息，防止密钥泄露。

## 检测模式

### 高危模式 (必须报告)
- `password\s*=\s*['"]\w+` - 硬编码密码
- `api[_-]?key\s*[:=]\s*['"]\w+` - API密钥
- `secret[_-]?key\s*[:=]\s*['"]\w+` - 密钥
- `access[_-]?token\s*[:=]\s*['"]\w+` - 访问令牌
- `private[_-]?key\s*[:=]\s*['"]\w+` - 私钥片段
- `auth[_-]?token\s*[:=]\s*['"]\w+` - 认证令牌

### 中危模式 (需确认)
- `bearer\s+[a-zA-Z0-9_-]{20,}` - Bearer Token
- `sk-[a-zA-Z0-9]{20,}` - OpenAI/API风格密钥
- `['"][a-zA-Z0-9+/]{32,}['"]` - 可能的Base64密钥
- `mysql://.*:.*@` - 数据库连接字符串
- `mongodb://.*:.*@` - MongoDB连接串

### 常见密钥格式
- AWS: `AKIA[0-9A-Z]{16}`
- GitHub: `ghp_[a-zA-Z0-9]{36}`
- Slack: `xox[baprs]-[a-zA-Z0-9-]+`
- Firebase: `[a-zA-Z0-9:_-]{40}`

## 执行流程

1. **解析输入**
   - 单个文件 → 直接扫描
   - 目录 → 递归扫描（跳过 `node_modules/`, `.git/`, `venv/`, `__pycache__/`）

2. **运行检测脚本**
   ```bash
   python ~/.claude/skills/sechecker/scripts/sechecker.py <target_path>
   ```

3. **输出格式**
   ```
   🔴 [HIGH] path/to/file.py:42
      Found: password = "admin123"

   🟡 [MEDIUM] path/to/config.js:15
      Found: api_key: "sk-1234567890abcdef"

   ✅ Summary: 2 issues found in 1 file(s)
   ```

4. **修复建议**
   - 使用环境变量
   - 配置文件（加入 `.gitignore`）
   - 密钥管理服务（Vault、AWS Secrets Manager）

## 使用示例

```
/user: /sechecker /Users/pbuff/temp/myproject
/assistant: [扫描结果...]
```

## 注意事项

- 误报可能：测试代码、示例代码、注释中的假密钥
- 建议人工复核结果
- 不扫描二进制文件
