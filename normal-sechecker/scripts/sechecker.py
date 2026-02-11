#!/usr/bin/env python3
"""
SEChecker - Sensitive Information Leakage Detector
检测项目中的硬编码密钥、密码等敏感信息
"""

import os
import re
import sys
import argparse
from pathlib import Path
from typing import List, Tuple, Iterator

# ============ 配置 ============

# 跳过的目录
SKIP_DIRS = {
    'node_modules', '.git', '.svn', 'venv', 'venv3', '.venv',
    '__pycache__', '.pytest_cache', 'dist', 'build', 'target',
    'vendor', 'bower_components', '.idea', '.vscode',
    'ja3_env', 'site-packages',  # 虚拟环境特有
}

# 扫描的文件扩展名
INCLUDE_EXTS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs',
    '.c', '.cpp', '.h', '.cs', '.php', '.rb', '.sh', '.bash',
    '.yml', '.yaml', '.json', '.xml', '.conf', '.config',
    '.env', '.env.local', '.env.*', '.ini', '.cfg', '.toml',
    '.md', '.txt', '.sql',
}

# ============ 检测规则 ============

RULES = {
    'HIGH': [
        # 硬编码密码
        (r'password\s*[:=]\s*["\']([^"\']{4,})["\']', 'password assignment'),
        (r'passwd\s*[:=]\s*["\']([^"\']{4,})["\']', 'passwd assignment'),
        (r'pwd\s*[:=]\s*["\']([^"\']{4,})["\']', 'pwd assignment'),

        # API Key
        (r'api[_-]?key\s*[:=]\s*["\']([^"\']{16,})["\']', 'api_key'),
        (r'apikey\s*[:=]\s*["\']([^"\']{16,})["\']', 'apikey'),
        (r'API[_-]?KEY\s*[:=]\s*["\']([^"\']{16,})["\']', 'API_KEY'),

        # Secret
        (r'secret[_-]?key\s*[:=]\s*["\']([^"\']{16,})["\']', 'secret_key'),
        (r'secret\s*[:=]\s*["\']([^"\']{16,})["\']', 'secret'),
        (r'SECRET[_-]?KEY\s*[:=]\s*["\']([^"\']{16,})["\']', 'SECRET_KEY'),

        # Token
        (r'access[_-]?token\s*[:=]\s*["\']([^"\']{16,})["\']', 'access_token'),
        (r'auth[_-]?token\s*[:=]\s*["\']([^"\']{16,})["\']', 'auth_token'),
        (r'jwt\s*[:=]\s*["\']([^"\']{20,})["\']', 'jwt token'),
        (r'SESSION[_-]?SECRET\s*[:=]\s*["\']([^"\']{16,})["\']', 'SESSION_SECRET'),

        # 私钥片段
        (r'private[_-]?key\s*[:=]\s*["\']([^"\']{16,})["\']', 'private_key'),
        (r'PRIVATE[_-]?KEY\s*[:=]\s*["\']([^"\']{16,})["\']', 'PRIVATE_KEY'),
    ],

    'MEDIUM': [
        # Bearer Token
        (r'bearer\s+[a-zA-Z0-9_-]{20,}', 'bearer token'),
        (r'Bearer\s+[a-zA-Z0-9_-]{20,}', 'Bearer token'),

        # OpenAI 风格
        (r'sk-[a-zA-Z0-9]{20,}', 'OpenAI-style key'),

        # AWS Access Key
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),

        # GitHub Token
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub personal access token'),
        (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth token'),
        (r'ghu_[a-zA-Z0-9]{36}', 'GitHub user token'),
        (r'ghs_[a-zA-Z0-9]{36}', 'GitHub server token'),
        (r'ghr_[a-zA-Z0-9]{36}', 'GitHub refresh token'),

        # Slack
        (r'xox[baprs]-[a-zA-Z0-9-]{10,}', 'Slack token'),

        # 数据库连接字符串
        (r'mysql://\w+:\w+@\w+', 'MySQL connection string'),
        (r'postgresql://\w+:\w+@\w+', 'PostgreSQL connection string'),
        (r'mongodb://\w+:\w+@\w+', 'MongoDB connection string'),
        (r'redis://[:\w]+@', 'Redis connection string'),

        # 可能的密钥值（长字符串）
        (r'["\']([a-zA-Z0-9+/]{32,}={0,2})["\']', 'possible base64 key'),
    ],

    'LOW': [
        # IP 地址（可能是内网地址）
        (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'IP address'),
        # 邮箱
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'email address'),
    ],
}

# ============ 核心逻辑 ============

def should_skip_file(filepath: Path) -> bool:
    """判断是否跳过该文件"""
    # 检查扩展名
    if filepath.suffix.lower() not in INCLUDE_EXTS:
        return True

    # 检查是否在跳过目录中
    for part in filepath.parts:
        if part in SKIP_DIRS:
            return True

    return False


def scan_file(filepath: Path) -> List[Tuple[str, int, str, str, str]]:
    """扫描单个文件，返回 (severity, line_num, rule_type, matched_content, context)"""
    issues = []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return issues

    for line_num, line in enumerate(lines, 1):
        # 跳过注释行
        stripped = line.strip()
        if any(stripped.startswith(prefix) for prefix in ['#', '//', '/*', '*', '-']):
            continue

        for severity, rules in RULES.items():
            for pattern, rule_type in rules:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    matched = match.group(0)
                    # 获取上下文（前后各30字符）
                    start = max(0, match.start() - 30)
                    end = min(len(line), match.end() + 30)
                    context = line[start:end].strip()

                    issues.append((
                        severity,
                        line_num,
                        rule_type,
                        matched,
                        context
                    ))

    return issues


def scan_directory(root: Path) -> Iterator[Tuple[Path, List[Tuple]]]:
    """递归扫描目录"""
    for filepath in root.rglob('*'):
        if filepath.is_file() and not should_skip_file(filepath):
            issues = scan_file(filepath)
            if issues:
                yield filepath, issues


def format_output(results: List[Tuple[Path, List]], show_low: bool = False) -> str:
    """格式化输出结果"""
    if not results:
        return "✅ No sensitive information found!"

    lines = []
    total_issues = 0

    for filepath, issues in results:
        for severity, line_num, rule_type, matched, context in issues:
            if severity == 'LOW' and not show_low:
                continue

            total_issues += 1

            if severity == 'HIGH':
                icon = '🔴'
            elif severity == 'MEDIUM':
                icon = '🟡'
            else:
                icon = '🟢'

            lines.append(f"{icon} [{severity}] {filepath}:{line_num}")
            lines.append(f"   Rule: {rule_type}")
            lines.append(f"   Match: {matched[:80]}...")
            lines.append(f"   Context: ...{context[:100]}...")
            lines.append("")

    lines.append(f"✅ Summary: {total_issues} issue(s) found in {len(results)} file(s)")

    return '\n'.join(lines)


# ============ CLI 入口 ============

def main():
    parser = argparse.ArgumentParser(
        description='SEChecker - Scan for hardcoded sensitive information'
    )
    parser.add_argument(
        'target',
        type=str,
        help='Target file or directory to scan'
    )
    parser.add_argument(
        '--low',
        action='store_true',
        help='Also show LOW severity findings (IPs, emails)'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output in JSON format'
    )

    args = parser.parse_args()
    target = Path(args.target)

    if not target.exists():
        print(f"❌ Error: Path does not exist: {args.target}")
        sys.exit(1)

    # 扫描
    results = []
    if target.is_file():
        if not should_skip_file(target):
            issues = scan_file(target)
            if issues:
                results.append((target, issues))
    else:
        results = list(scan_directory(target))

    # 输出
    if args.json:
        import json
        output = []
        for filepath, issues in results:
            for severity, line_num, rule_type, matched, context in issues:
                if severity == 'LOW' and not args.low:
                    continue
                output.append({
                    'file': str(filepath),
                    'line': line_num,
                    'severity': severity,
                    'rule': rule_type,
                    'matched': matched[:100],
                })
        print(json.dumps(output, indent=2))
    else:
        print(format_output(results, show_low=args.low))


if __name__ == '__main__':
    main()
