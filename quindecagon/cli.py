import os
import sys
import subprocess
import argparse


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
        # Forward everything to the shell script
        result = subprocess.run(cmd, check=True)
        return result.returncode
    except subprocess.CalledProcessError as e:
        return e.returncode
    except KeyboardInterrupt:
        print("\n🛑 Audit cancelled by user.")
        sys.exit(1)


def main():
    """Main entry point for quindecagon-audit."""
    parser = argparse.ArgumentParser(
        description="quindecagon: Unified Clinical Security Framework for Nextflow Pipelines"
    )
    parser.add_argument(
        "pipeline_dir", help="Path to the Nextflow pipeline directory to audit"
    )
    parser.add_argument(
        "-e", "--env", help="Path to a custom .env file (optional)", default=None
    )

    args = parser.parse_args()

    # Construct arguments for the shell script
    script_args = [args.pipeline_dir]
    if args.env:
        script_args.extend(["--env-file", args.env])

    sys.exit(run_script("docker_run.sh", script_args))


def generate_local():
    """Entry point for quindecagon-report."""
    # Forwards to generate_local.sh
    sys.exit(run_script("generate_local.sh", sys.argv[1:]))


if __name__ == "__main__":
    main()
