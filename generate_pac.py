#!/usr/bin/env python3
import argparse
import re
from pathlib import Path

def load_lines(path: Path):
    if not path.exists():
        return []
    lines = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip()
        if not s or s.startswith("!") or s.startswith("["):
            continue
        lines.append(s)
    return lines

def rule_to_js_condition(rule: str):
    """把常见 AutoProxy 规则转成 PAC 判断条件。"""
    if rule.startswith("@@"):
        return None  # 例外规则这里先忽略，避免复杂化

    # ||example.com
    if rule.startswith("||"):
        host = rule[2:].split("/")[0].strip()
        if not host:
            return None
        if host.startswith("*."):
            return f'shExpMatch(host, "{host}") || dnsDomainIs(host, "{host[2:]}")'
        return f'dnsDomainIs(host, "{host}") || shExpMatch(host, "*.{host}")'

    # *.example.com 或 example.com
    if rule.startswith("*."):
        return f'shExpMatch(host, "{rule}") || dnsDomainIs(host, "{rule[2:]}")'

    # 纯域名
    if "/" not in rule and "*" not in rule and rule.replace(".", "").replace("-", "").isalnum():
        return f'dnsDomainIs(host, "{rule}") || shExpMatch(host, "*.{rule}")'

    # 其它通配
    if "*" in rule and "/" not in rule:
        return f'shExpMatch(host, "{rule}")'

    return None

def rules_to_conditions(rules):
    conds = []
    seen = set()
    for r in rules:
        c = rule_to_js_condition(r)
        if c and c not in seen:
            seen.add(c)
            conds.append(c)
    return conds

def parse_gfwlist(path: Path):
    """从解码后的 gfwlist 提取可代理域名规则。"""
    out = []
    for line in load_lines(path):
        if line.startswith("@@"):
            continue
        if line.startswith("||") or line.startswith("*.") or line.startswith("."):
            out.append(line.lstrip("."))
        elif re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", line):
            out.append("||" + line)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--direct", required=True)
    ap.add_argument("--hk", required=True)
    ap.add_argument("--vultr", required=True)
    ap.add_argument("--gfw", required=True)
    ap.add_argument("--hk-proxy", required=True)
    ap.add_argument("--vultr-proxy", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    direct_rules = load_lines(Path(args.direct))
    hk_rules = load_lines(Path(args.hk))
    vultr_rules = load_lines(Path(args.vultr)) + parse_gfwlist(Path(args.gfw))

    direct_conds = rules_to_conditions(direct_rules)
    hk_conds = rules_to_conditions(hk_rules)
    vultr_conds = rules_to_conditions(vultr_rules)

    def join_conds(conds):
        if not conds:
            return "false"
        # 每行一个条件，避免单行过长
        return "\n        || ".join(conds)

    pac = f"""// Auto-generated. Do not edit.
// direct -> DIRECT
// hongkong -> {args.hk_proxy}
// vultr + gfwlist -> {args.vultr_proxy}

function FindProxyForURL(url, host) {{
    host = host.toLowerCase();

    // 1) 强制直连
    if ({join_conds(direct_conds)}) {{
        return "DIRECT";
    }}

    // 2) 香港
    if ({join_conds(hk_conds)}) {{
        return "{args.hk_proxy}";
    }}

    // 3) Vultr + GFWList
    if ({join_conds(vultr_conds)}) {{
        return "{args.vultr_proxy}";
    }}

    // 默认直连
    return "DIRECT";
}}
"""
    Path(args.out).write_text(pac, encoding="utf-8")
    print(f"PAC written: {args.out}")
    print(f"direct={len(direct_conds)} hk={len(hk_conds)} vultr={len(vultr_conds)}")

if __name__ == "__main__":
    main()
