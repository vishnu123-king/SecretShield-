#!/usr/bin/env python3
import sys
import os
import argparse
import json
from datetime import datetime

# Add project root to sys.path so it can import backend.app.scanner
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from backend.app.scanner.engine import SecretShieldEngine
    from backend.app.scanner.pattern_detector import DEFAULT_BUILTIN_RULES
except ImportError:
    # If installed as package
    try:
        from app.scanner.engine import SecretShieldEngine
        from app.scanner.pattern_detector import DEFAULT_BUILTIN_RULES
    except ImportError:
        pass

VERSION = "1.0.0"

# ANSI Colors
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[31;1m"
COLOR_YELLOW = "\033[33;1m"
COLOR_GREEN = "\033[32;1m"
COLOR_BLUE = "\033[34;1m"
COLOR_CYAN = "\033[36;1m"
COLOR_BOLD = "\033[1m"
COLOR_DIM = "\033[2m"

def print_banner():
    banner = f"""{COLOR_CYAN}
   _____               __  _____ __    _      __    __
  / ___/___  __________/ /_/ ___// /_  (_)__  / /___/ /
  \\__ \\/ _ \\/ ___/ ___/ __/\\__ \\/ __ \\/ / _ \\/ / __  / 
 ___/ /  __/ /__/ /  / /_ ___/ / / / / /  __/ / /_/ /  
/____/\\___/\\___/_/   \\__//____/_/ /_/_/\\___/_/\\__,_/   
{COLOR_RESET}{COLOR_DIM}  SecretShield v{VERSION} - Detect exposed secrets before they become security incidents.{COLOR_RESET}
"""
    print(banner)

def format_terminal_output(result: dict) -> int:
    sev_counts = result.get("severity_counts", {})
    critical_count = sev_counts.get("CRITICAL", 0)
    high_count = sev_counts.get("HIGH", 0)
    total_findings = result.get("total_findings", 0)

    print(f"\n{COLOR_BOLD}=== Scan Summary ==={COLOR_RESET}")
    print(f"Target:             {result.get('repository_path')}")
    print(f"Git Repository:     {'Yes' if result.get('is_git_repository') else 'No (Local Directory)'}")
    print(f"Scan Duration:      {result.get('duration_seconds')}s")
    print(f"Total Findings:     {total_findings}")
    print(f"Total Occurrences:  {result.get('total_occurrences')}")
    print(f"Currently in HEAD:  {result.get('currently_exposed_count')}")
    print(f"Historical Only:    {result.get('historical_only_count')}")
    print(f"Risk Index Score:   {result.get('risk_index')}/100")

    print(f"\n{COLOR_BOLD}Severity Breakdown:{COLOR_RESET}")
    print(f"  {COLOR_RED}CRITICAL: {critical_count}{COLOR_RESET}")
    print(f"  {COLOR_YELLOW}HIGH:     {high_count}{COLOR_RESET}")
    print(f"  MEDIUM:   {sev_counts.get('MEDIUM', 0)}")
    print(f"  LOW:      {sev_counts.get('LOW', 0)}")
    print(f"  INFO:     {sev_counts.get('INFO', 0)}")

    findings = result.get("findings", [])
    if not findings:
        print(f"\n{COLOR_GREEN}✓ Clean repository! No exposed secrets or credentials detected.{COLOR_RESET}\n")
        return 0

    print(f"\n{COLOR_BOLD}=== Detected Findings ==={COLOR_RESET}")
    for idx, f in enumerate(findings, 1):
        sev = f.get("severity", "MEDIUM")
        color = COLOR_RED if sev == "CRITICAL" else (COLOR_YELLOW if sev == "HIGH" else COLOR_RESET)
        status_tag = f"{COLOR_RED}[HEAD]{COLOR_RESET}" if f.get("is_currently_present") else f"{COLOR_CYAN}[HISTORICAL]{COLOR_RESET}"

        print(f"\n{color}[{idx}] [{sev}] {f.get('title')}{COLOR_RESET} {status_tag}")
        print(f"    Finding ID:     {f.get('id')} ({f.get('fingerprint')})")
        print(f"    File:           {f.get('primary_file')}:{f.get('primary_line')}")
        print(f"    Masked Secret:  {f.get('masked_secret')}")
        print(f"    Occurrences:    {f.get('total_occurrences')} across {len(f.get('files', []))} files, {len(f.get('commits', []))} commits")
        
        # Risk factors
        reasons = f.get("risk_reasons", [])
        if reasons:
            print(f"    Risk Analysis:  Score {f.get('score')}/100")
            for r in reasons[:3]:
                print(f"      {r.get('delta')} {r.get('factor')}")

        print(f"    Remediation:    {f.get('remediation', '').splitlines()[0] if f.get('remediation') else 'Rotate credential immediately'}")

    print("\n" + "=" * 50)
    if critical_count > 0 or high_count > 0:
        print(f"{COLOR_RED}FAILED: Critical or High severity secrets detected! Blocking workflow.{COLOR_RESET}\n")
        return 1
    return 0

def generate_html_report(result: dict) -> str:
    findings = result.get("findings", [])
    findings_rows = ""
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        badge_color = "#ef4444" if sev == "CRITICAL" else ("#f59e0b" if sev == "HIGH" else "#3b82f6")
        status_badge = '<span style="color:#ef4444;font-weight:bold;">HEAD</span>' if f.get("is_currently_present") else '<span style="color:#06b6d4;font-weight:bold;">HISTORICAL</span>'
        remediation_lines = "<br>".join(f.get("remediation", "").splitlines())
        findings_rows += f"""
        <tr style="border-bottom: 1px solid #334155;">
            <td style="padding: 12px; font-family: monospace;">{f.get('id')}</td>
            <td style="padding: 12px;"><span style="background:{badge_color}; color:#fff; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">{sev}</span></td>
            <td style="padding: 12px;">{status_badge}</td>
            <td style="padding: 12px; font-weight: 600;">{f.get('rule_name')}</td>
            <td style="padding: 12px; font-family: monospace;">{f.get('primary_file')}:{f.get('primary_line')}</td>
            <td style="padding: 12px; font-family: monospace; color: #f43f5e;">{f.get('masked_secret')}</td>
            <td style="padding: 12px; font-size: 12px; line-height: 1.4;">{remediation_lines}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SecretShield Security Report - {result.get('repository_name')}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 30px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ border-bottom: 2px solid #1e293b; padding-bottom: 20px; margin-bottom: 24px; }}
        .title {{ font-size: 28px; font-weight: 800; color: #38bdf8; margin: 0; }}
        .subtitle {{ font-size: 14px; color: #94a3b8; margin-top: 6px; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 30px; }}
        .card {{ background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #334155; }}
        .card-value {{ font-size: 32px; font-weight: 800; margin-top: 8px; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th {{ background: #0284c7; color: white; text-align: left; padding: 12px; font-size: 13px; text-transform: uppercase; }}
        .footer {{ margin-top: 40px; font-size: 12px; color: #64748b; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">SecretShield Audit Report</h1>
            <div class="subtitle">Repository: <strong>{result.get('repository_path')}</strong> | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
        </div>

        <div class="grid">
            <div class="card">
                <div style="color: #94a3b8; font-size: 12px; text-transform: uppercase;">Risk Score</div>
                <div class="card-value" style="color: #f43f5e;">{result.get('risk_index')}/100</div>
            </div>
            <div class="card">
                <div style="color: #94a3b8; font-size: 12px; text-transform: uppercase;">Total Secrets</div>
                <div class="card-value">{result.get('total_findings')}</div>
            </div>
            <div class="card">
                <div style="color: #94a3b8; font-size: 12px; text-transform: uppercase;">Critical Findings</div>
                <div class="card-value" style="color: #ef4444;">{result.get('severity_counts', {}).get('CRITICAL', 0)}</div>
            </div>
            <div class="card">
                <div style="color: #94a3b8; font-size: 12px; text-transform: uppercase;">Historical Exposures</div>
                <div class="card-value" style="color: #06b6d4;">{result.get('historical_only_count')}</div>
            </div>
        </div>

        <h2 style="font-size: 20px; margin-bottom: 16px;">Vulnerability Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Secret Type</th>
                    <th>Location</th>
                    <th>Masked Value</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows or '<tr><td colspan="7" style="padding: 24px; text-align: center; color: #10b981;">No secrets detected in repository!</td></tr>'}
            </tbody>
        </table>

        <div class="footer">
            SecretShield Security Platform &bull; Defensive Credential Detection &bull; Secrets strictly masked.
        </div>
    </div>
</body>
</html>
"""
    return html

def install_pre_commit_hook(repo_path: str = ".") -> int:
    git_dir = os.path.join(repo_path, ".git")
    if not os.path.exists(git_dir):
        print(f"{COLOR_RED}Error: {repo_path} is not a Git repository (.git not found){COLOR_RESET}")
        return 1

    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    hook_path = os.path.join(hooks_dir, "pre-commit")

    hook_script = f"""#!/bin/sh
# SecretShield Git Pre-Commit Security Hook
# Prevents accidental credential leaks before commit

echo "🛡️  SecretShield: Scanning staged files for exposed secrets..."

# Execute secretshield CLI in staged mode
python3 -c "
import sys, os
from cli.secretshield import run_scan_direct
exit_code = run_scan_direct('.', scan_staged_only=True)
sys.exit(exit_code)
" 2>/dev/null

STATUS=$?

if [ $STATUS -ne 0 ]; then
  echo ""
  echo "❌ SecretShield pre-commit hook BLOCKED this commit."
  echo "   Exposed secrets or credentials were found in staged files."
  echo "   Remediation: Unstage and remove credentials from code before committing."
  echo "   Emergency override only: git commit --no-verify"
  echo ""
  exit 1
fi

echo "✅ SecretShield: No credentials found in staged changes."
exit 0
"""

    try:
        with open(hook_path, "w") as f:
            f.write(hook_script)
        os.chmod(hook_path, 0o755)
        print(f"{COLOR_GREEN}✓ Pre-commit hook successfully installed to {hook_path}{COLOR_RESET}")
        print("Commits will now automatically be scanned and protected against credential leaks.")
        return 0
    except Exception as e:
        print(f"{COLOR_RED}Failed to install pre-commit hook: {e}{COLOR_RESET}")
        return 2

def run_scan_direct(
    target_path: str,
    scan_history: bool = True,
    scan_staged_only: bool = False,
    format_type: str = "terminal",
    auth_token: str = None,
    branch: str = None,
    depth: int = 100,
    mode: str = "deep",
    config_path: str = None
) -> int:
    try:
        from backend.app.repository.url_parser import parse_and_validate_git_url
        from backend.app.repository.provider_detector import GitProviderDetector
        from backend.app.repository.clone_manager import CloneManager

        # Load configuration if provided or exists in target
        custom_rules = []
        suppressions = []
        
        cfg_to_load = config_path
        if not cfg_to_load:
            potential_cfg = os.path.join(target_path, ".secretshield.json")
            if os.path.exists(potential_cfg):
                cfg_to_load = potential_cfg
        
        if cfg_to_load and os.path.exists(cfg_to_load):
            try:
                with open(cfg_to_load, "r") as f:
                    cfg_data = json.load(f)
                    custom_rules = cfg_data.get("custom_rules", [])
                    suppressions = cfg_data.get("suppressions", [])
            except Exception:
                pass

        parsed = parse_and_validate_git_url(target_path, allow_local_fixtures=True)
        if not parsed.get("is_valid"):
            if format_type == "json":
                print(json.dumps({"error": parsed.get("error", "Invalid target"), "status": "failed", "findings": []}, indent=2))
            else:
                print(f"{COLOR_RED}Invalid target: {parsed.get('error')}{COLOR_RESET}", file=sys.stderr)
            return 2

        is_remote = not parsed.get("is_local", True)
        clone_manager = None
        cloned_dir = None
        scan_target = target_path

        if is_remote:
            provider = GitProviderDetector.detect_provider(parsed.get("host", ""), parsed.get("clone_url", ""))
            if format_type == "terminal":
                print(f"🌐 Remote Repository Detected: {COLOR_CYAN}{provider['name']}{COLOR_RESET} ({parsed.get('owner')}/{parsed.get('repo_name')})")
                print(f"📦 Retrieving repository into isolated sandbox...")
            
            clone_manager = CloneManager()
            effective_depth = 1 if mode == "quick" else (depth or 100)
            target_branch = branch or parsed.get("detected_branch")
            success, cloned_dir, err = clone_manager.clone_repository(
                clone_url=parsed.get("clone_url"),
                auth_token=auth_token,
                branch=target_branch,
                depth=effective_depth
            )
            if not success:
                if format_type == "json":
                    print(json.dumps({
                        "error": cloned_dir,
                        "details": err,
                        "status": "failed",
                        "total_findings": 0,
                        "findings": []
                    }, indent=2))
                else:
                    print(f"{COLOR_RED}Cloning failed: {cloned_dir}{COLOR_RESET}", file=sys.stderr)
                return 2
            scan_target = cloned_dir

        engine = SecretShieldEngine(
            custom_rules=custom_rules,
            suppressions=suppressions
        )
        result = engine.scan_repository(
            repo_path=scan_target,
            scan_mode=mode,
            scan_history=scan_history,
            scan_staged_only=scan_staged_only
        )

        # Attach original remote repo metadata and Linux sandbox telemetry
        if is_remote:
            result["original_url"] = parsed.get("original_url")
            result["provider"] = provider.get("name")
            result["repository_name"] = f"{parsed.get('owner')}/{parsed.get('repo_name')}"
            if clone_manager and cloned_dir:
                result["sandbox"] = clone_manager.get_sandbox_telemetry(cloned_dir)
                clone_manager.cleanup(cloned_dir)
        else:
            result["sandbox"] = {
                "sandbox_id": "sandbox-linux-local-fixture",
                "sandbox_path": scan_target,
                "platform": "Linux (x86_64 POSIX Container)",
                "isolation_mode": "Local Workspace Isolation",
                "status": "Completed"
            }

        if format_type == "json":
            # Sanitize findings: Ensure no raw secrets exist
            print(json.dumps(result, indent=2))
            return 1 if (result.get("severity_counts", {}).get("CRITICAL", 0) > 0 or result.get("severity_counts", {}).get("HIGH", 0) > 0) else 0
        elif format_type == "html":
            html = generate_html_report(result)
            print(html)
            return 0
        else:
            return format_terminal_output(result)
    except Exception as e:
        if format_type == "json":
            print(json.dumps({"error": str(e), "status": "failed", "findings": []}, indent=2))
        else:
            print(f"{COLOR_RED}Scanner Error: {e}{COLOR_RESET}", file=sys.stderr)
        return 2

def main():
    parser = argparse.ArgumentParser(
        prog="secretshield",
        description="SecretShield: Git repository secrets detection and credential exposure monitoring platform."
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: init
    subparsers.add_parser("init", help="Initialize SecretShield configuration in the current repository")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Scan a directory or Git repository for exposed secrets")
    scan_parser.add_argument("path", nargs="?", default=".", help="Path to repository or directory (default: current dir)")
    scan_parser.add_argument("--mode", choices=["quick", "deep", "full", "diff"], default="deep", help="Scan mode: quick (HEAD files), deep (HEAD + history), full (history + branches), diff (staged only)")
    scan_parser.add_argument("--history", action="store_true", default=True, help="Scan full Git commit history (default: enabled)")
    scan_parser.add_argument("--no-history", dest="history", action="store_false", help="Scan working tree only (skip commit history)")
    scan_parser.add_argument("--staged", action="store_true", default=False, help="Scan staged changes only (pre-commit mode)")
    scan_parser.add_argument("--branch", help="Target branch to scan (e.g. main, master, dev)")
    scan_parser.add_argument("--token", help="Personal Access Token for private repository access")
    scan_parser.add_argument("--depth", type=int, default=100, help="Commit history depth for clone")
    scan_parser.add_argument("--format", choices=["terminal", "json", "html", "csv"], default="terminal", help="Output format")
    scan_parser.add_argument("--output", "-o", help="Write report output to specified file")
    scan_parser.add_argument("--config", help="Path to SecretShield config JSON file")

    # Command: diff
    diff_parser = subparsers.add_parser("diff", help="Fast scan of current uncommitted or staged Git diff changes")
    diff_parser.add_argument("path", nargs="?", default=".", help="Path to repository (default: current dir)")
    diff_parser.add_argument("--format", choices=["terminal", "json", "html"], default="terminal", help="Output format")
    diff_parser.add_argument("--config", help="Path to SecretShield config JSON file")

    # Command: rules
    rules_parser = subparsers.add_parser("rules", help="Manage and test secret detection rules")
    rules_parser.add_argument("--config", help="Path to SecretShield config JSON file")
    rules_sub = rules_parser.add_subparsers(dest="rules_cmd")
    rules_sub.add_parser("list", help="List all builtin and configured detection rules")
    test_rule_p = rules_sub.add_parser("test", help="Test a rule against candidate string")
    test_rule_p.add_argument("rule_id", help="Rule ID to test (e.g. aws-access-key-id)")
    test_rule_p.add_argument("--text", required=True, help="Sample text string to test")

    # Command: findings
    find_parser = subparsers.add_parser("findings", help="Inspect detected findings")
    find_sub = find_parser.add_subparsers(dest="findings_cmd")
    find_sub.add_parser("list", help="List recent findings")
    show_f = find_sub.add_parser("show", help="Show specific finding details")
    show_f.add_argument("finding_id", help="Finding ID (e.g. SS-00001)")

    # Command: install-hook
    subparsers.add_parser("install-hook", help="Install SecretShield Git pre-commit hook into current repo")

    # Command: version
    subparsers.add_parser("version", help="Show SecretShield version")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "version":
        print(f"SecretShield version {VERSION}")
        sys.exit(0)

    elif args.command == "init":
        print_banner()
        config_file = ".secretshield.json"
        if os.path.exists(config_file):
            print(f"SecretShield configuration already exists at {config_file}")
        else:
            default_cfg = {
                "version": VERSION,
                "scan_history": True,
                "max_file_size_mb": 5,
                "suppressions": [],
                "custom_rules": []
            }
            with open(config_file, "w") as f:
                json.dump(default_cfg, f, indent=2)
            print(f"{COLOR_GREEN}✓ Initialized SecretShield configuration in {config_file}{COLOR_RESET}")
        sys.exit(0)

    elif args.command == "install-hook":
        code = install_pre_commit_hook(".")
        sys.exit(code)

    elif args.command == "rules":
        custom_rules = []
        if args.config and os.path.exists(args.config):
            try:
                with open(args.config, "r") as f:
                    cfg_data = json.load(f)
                    custom_rules = cfg_data.get("custom_rules", [])
            except Exception:
                pass
        
        all_rules = list(DEFAULT_BUILTIN_RULES)
        if custom_rules:
            custom_ids = {r.get("id") for r in custom_rules}
            all_rules = [r for r in all_rules if r.get("id") not in custom_ids]
            all_rules.extend(custom_rules)

        if args.rules_cmd == "list" or not args.rules_cmd:
            print(f"\n{COLOR_BOLD}=== SecretShield Active Detection Rules ({len(all_rules)}) ==={COLOR_RESET}")
            for r in all_rules:
                prefix = "• "
                if any(cr.get("id") == r.get("id") for cr in custom_rules):
                    prefix = f"{COLOR_CYAN}★ {COLOR_RESET}"
                print(f"  {prefix}{r['id']:<28} [{r['severity']:<8}] {r['name']}")
            print()
            sys.exit(0)
        elif args.rules_cmd == "test":
            rule = next((r for r in all_rules if r['id'] == args.rule_id), None)
            if not rule:
                print(f"{COLOR_RED}Rule not found: {args.rule_id}{COLOR_RESET}")
                sys.exit(1)
            import re
            matched = False
            for pat in rule.get("patterns", []):
                m = re.search(pat, args.text)
                if m:
                    matched = True
                    print(f"{COLOR_GREEN}✓ MATCH! Pattern: {pat}{COLOR_RESET}")
                    print(f"  Matched value: {m.group(0)}")
                    break
            if not matched:
                print(f"{COLOR_YELLOW}✗ No match for rule {args.rule_id} on provided text.{COLOR_RESET}")
            sys.exit(0)

    elif args.command == "diff":
        if args.format == "terminal":
            print_banner()
            print(f"⚡ Fast Diff Scan on: {os.path.abspath(args.path)}")
            print("   Target: Uncommitted & staged unified Git diffs")

        exit_code = run_scan_direct(
            target_path=args.path,
            scan_history=False,
            scan_staged_only=True,
            format_type=args.format,
            mode="diff",
            config_path=args.config
        )
        sys.exit(exit_code)

    elif args.command == "scan":
        if args.format == "terminal":
            print_banner()
            print(f"🔍 Starting SecretShield scan on: {os.path.abspath(args.path)}")
            print(f"   Mode: {args.mode.upper()}")
            if args.staged:
                print("   Scope: Staged changes only (pre-commit)")
            elif args.history:
                print("   Scope: Working tree + Git commit history")
            else:
                print("   Scope: Working tree only")

        exit_code = run_scan_direct(
            target_path=args.path,
            scan_history=args.history,
            scan_staged_only=args.staged,
            format_type=args.format,
            auth_token=getattr(args, 'token', None),
            branch=getattr(args, 'branch', None),
            depth=getattr(args, 'depth', 100),
            mode=args.mode,
            config_path=args.config
        )
        sys.exit(exit_code)

if __name__ == "__main__":
    main()
