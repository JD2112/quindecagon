import os
import sys
import subprocess
import argparse
from quindecagon.workflow import add_workflow_subparser, create_workflow


def get_script_path(script_name):
    """Finds a script bundled within the package."""
    base_dir = os.path.dirname(__file__)
    path = os.path.join(base_dir, "scripts", script_name)
    if not os.path.exists(path):
        print(f"❌ Internal error: Script {script_name} not found at {path}")
        sys.exit(1)
    return path


def run_script(script_name, args):
    """Executes a bundled shell script with the given arguments."""
    path = get_script_path(script_name)
    cmd = ["bash", path] + args
    try:
        result = subprocess.run(cmd, check=True)
        return result.returncode
    except subprocess.CalledProcessError as e:
        return e.returncode
    except KeyboardInterrupt:
        print("\n🛑 Audit cancelled by user.")
        sys.exit(1)


def main(argv=None):
    """Main entry point for quindecagon-audit."""
    parser = argparse.ArgumentParser(
        prog="quindecagon-audit",
        description="quindecagon: Unified Clinical Security Framework for Nextflow Pipelines",
    )
    parser.add_argument(
        "pipeline_dir", help="Path to the Nextflow pipeline directory to audit"
    )
    parser.add_argument(
        "-e", "--env", help="Path to a custom .env file (optional)", default=None
    )

    args = parser.parse_args(argv)

    script_args = [args.pipeline_dir]
    if args.env:
        script_args.extend(["--env-file", args.env])

    sys.exit(run_script("docker_run.sh", script_args))


def generate_local(argv=None):
    """Entry point for quindecagon-report."""
    args = argv if argv is not None else sys.argv[1:]
    sys.exit(run_script("generate_local.sh", args))


def cli_entry():
    """Unified entry point for the `quindecagon` CLI."""
    valid_subcmds = [
        "workflow",
        "init-ci",
        "audit",
        "report",
        "-h",
        "--help",
        "-v",
        "--version",
    ]
    if len(sys.argv) > 1 and sys.argv[1] not in valid_subcmds:
        if os.path.exists(sys.argv[1]):
            return main(sys.argv[1:])

    parser = argparse.ArgumentParser(
        prog="quindecagon",
        description="quindecagon: Unified Clinical Security Assurance & Verification Framework",
    )
    parser.add_argument(
        "-v", "--version", action="version", version="quindecagon 0.5.0"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1. Workflow / init-ci
    add_workflow_subparser(subparsers)

    # 2. Audit
    audit_parser = subparsers.add_parser(
        "audit",
        help="Run security and compliance audit on a Nextflow pipeline",
        description="Run security and compliance audit on a Nextflow pipeline",
    )
    audit_parser.add_argument(
        "pipeline_dir", help="Path to the Nextflow pipeline directory to audit"
    )
    audit_parser.add_argument(
        "-e", "--env", help="Path to a custom .env file (optional)", default=None
    )

    # 3. Report
    report_parser = subparsers.add_parser(
        "report",
        help="Generate local compliance report",
        description="Generate local compliance report",
    )
    report_parser.add_argument(
        "report_args", nargs="*", help="Arguments forwarded to generate_local.sh"
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.command in ["workflow", "init-ci"]:
        if args.command == "workflow" and getattr(
            args, "workflow_command", None
        ) not in ["create", "init"]:
            parser.parse_args(["workflow", "--help"])
            sys.exit(0)

        sys.exit(
            create_workflow(
                target_dir=args.target_dir,
                repo=args.repo,
                branch=args.branch,
                mode=args.mode,
                badges=not args.no_badges,
                force=args.force,
                dry_run=args.dry_run,
                workflow_file=args.workflow_file,
            )
        )
    elif args.command == "audit":
        script_args = [args.pipeline_dir]
        if args.env:
            script_args.extend(["--env-file", args.env])
        sys.exit(run_script("docker_run.sh", script_args))
    elif args.command == "report":
        sys.exit(run_script("generate_local.sh", args.report_args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    cli_entry()
