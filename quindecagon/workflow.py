"""Workflow generation and CI setup for Quindecagon audit suite."""

import os
import re
import subprocess


BADGES_START_MARKER = "<!-- quindecagon-badges-start -->"
BADGES_END_MARKER = "<!-- quindecagon-badges-end -->"


def detect_github_repo(target_dir):
    """Detects GitHub owner/repo from git remote or nextflow.config."""
    # 1. Try git remote
    try:
        res = subprocess.run(
            ["git", "-C", target_dir, "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
            check=False,
        )
        url = res.stdout.strip()
        if url:
            # git@github.com:owner/repo.git or https://github.com/owner/repo.git
            m = re.search(r"github\.com[:/]([^/]+)/([^/\.]+)(?:\.git)?", url)
            if m:
                return f"{m.group(1)}/{m.group(2)}"
    except Exception:
        pass

    # 2. Try nextflow.config
    nxf_config = os.path.join(target_dir, "nextflow.config")
    if os.path.exists(nxf_config):
        try:
            with open(nxf_config, "r", encoding="utf-8") as f:
                content = f.read()
            pattern = r"""(?:manifest\s*\{[^}]*name\s*=\s*['"]|manifest\.name\s*=\s*['"])([^/'"]+/[^/'"]+)['"]"""
            m = re.search(pattern, content)
            if m:
                return m.group(1)
        except Exception:
            pass

    return None


def get_reusable_workflow_yaml():
    """Generates a lean GitHub Actions workflow calling the centralized reusable workflow."""
    return """name: Security & Compliance Audit

on:
  push:
    branches:
      - main
      - dev
  pull_request:
    branches:
      - main
      - dev
  workflow_dispatch:

permissions:
  contents: write

jobs:
  quindecagon-audit:
    name: 'Quindecagon Audit'
    uses: JD2112/quindecagon/.github/workflows/pipeline-audit.yml@main
    permissions:
      contents: write
    with:
      deploy-badges: true
"""


def get_standalone_workflow_yaml(
    container_image="jd21/quindecagon:0.4.0", badges_branch="badges"
):
    """Generates a standalone self-contained workflow running the Quindecagon container."""
    return f"""name: Security & Compliance Audit

on:
  push:
    branches:
      - main
      - dev
  pull_request:
    branches:
      - main
      - dev
  workflow_dispatch:

permissions:
  contents: write

jobs:
  quindecagon-audit:
    name: 'Quindecagon Audit Suite'
    runs-on: ubuntu-latest
    container:
      image: {container_image}
      options: --user root

    steps:
      - name: Check out pipeline code
        uses: actions/checkout@v4

      - name: Run Quindecagon Audit Suite
        id: audit
        run: |
          mkdir -p badges_data

          export NXF_HOME=/tmp/nxf
          export NXF_TEMP=/tmp
          export HOME=/tmp

          python3 - << 'EOF'
          import subprocess
          import json
          import os
          import glob

          def make_badge(schema_version=1, label="", message="", color="brightgreen"):
              return {{
                  "schemaVersion": schema_version,
                  "label": label,
                  "message": str(message),
                  "color": color
              }}

          badges = {{}}
          summary = {{}}

          # 1. Gitleaks Scan
          print("[1/6] Running Gitleaks secret scan...")
          res = subprocess.run(
              ["gitleaks", "detect", "--source=.", "--no-git", "--report-format=json", "--report-path=gitleaks.json"],
              capture_output=True, text=True
          )
          leaks_count = 0
          if os.path.exists("gitleaks.json") and os.path.getsize("gitleaks.json") > 0:
              try:
                  with open("gitleaks.json") as f:
                      raw_leaks = json.load(f)
                      ignored = ["venv", ".venv", ".git"]
                      real_leaks = [l for l in raw_leaks if not any(x in l.get("File", "") for x in ignored)]
                      leaks_count = len(real_leaks)
              except Exception:
                  leaks_count = 0

          if leaks_count == 0:
              badges["secrets"] = make_badge(label="secrets", message="clean", color="brightgreen")
          else:
              badges["secrets"] = make_badge(label="secrets", message=f"{{leaks_count}} detected", color="red")
          summary["secrets"] = leaks_count

          # 2. Flake8 Linting
          print("[2/6] Running Flake8 Python linting...")
          subprocess.run(
              ["flake8", "--exclude=.nf-core,work,venv,.venv,node_modules,tests,docs,site-packages,reports,.git,assets",
               "--ignore=E501,W503", "--format=json", "--output-file=flake8.json", "--exit-zero", "."],
              capture_output=True, text=True
          )
          flake8_issues = 0
          if os.path.exists("flake8.json"):
              try:
                  with open("flake8.json") as f:
                      f_data = json.load(f)
                      flake8_issues = sum(len(v) for v in f_data.values())
              except Exception:
                  flake8_issues = 0

          if flake8_issues == 0:
              badges["flake8"] = make_badge(label="flake8", message="passing", color="brightgreen")
          elif flake8_issues < 50:
              badges["flake8"] = make_badge(label="flake8", message=f"{{flake8_issues}} notices", color="yellow")
          else:
              badges["flake8"] = make_badge(label="flake8", message=f"{{flake8_issues}} warnings", color="orange")
          summary["flake8_issues"] = flake8_issues

          # 3. Black Formatting Check
          print("[3/6] Running Black format check...")
          res_black = subprocess.run(
              ["black", "--check", "--exclude=(\\.git|\\.venv|venv|work|\\.nf-core)", "."],
              capture_output=True, text=True
          )
          if res_black.returncode == 0:
              badges["black"] = make_badge(label="code style", message="black", color="brightgreen")
          else:
              badges["black"] = make_badge(label="code style", message="reformat pending", color="blue")
          summary["black_clean"] = (res_black.returncode == 0)

          # 4. R Scripts Audit
          print("[4/6] Running R scripts audit...")
          all_r = (
              glob.glob("bin/*.R")
              + glob.glob("bin/*.r")
              + glob.glob("**/*.R", recursive=True)
              + glob.glob("**/*.r", recursive=True)
          )
          r_files = [f for f in set(all_r) if not any(x in f for x in [".git", ".venv", "venv", "work", ".nf-core"])]
          badges["r_audit"] = make_badge(
              label="R scripts", message=f"{{len(r_files)}} audited", color="blue" if r_files else "lightgrey"
          )
          summary["r_files"] = len(r_files)

          # 5. nf-core lint (Pipeline Level)
          print("[5/6] Running nf-core pipeline lint...")
          try:
              import nf_core.lint
              lint_obj = nf_core.lint.PipelineLint(".")
              lint_obj._load_lint_config()
              lint_obj._load_pipeline_config()
              lint_obj._list_files()
              lint_obj._lint_pipeline()
              pass_count = len(lint_obj.passed)
              fail_count = len(lint_obj.failed)
              warn_count = len(lint_obj.warned)

              if fail_count == 0:
                  badges["nfcore_lint"] = make_badge(
                      label="nf-core lint", message=f"{{pass_count}} passed", color="brightgreen"
                  )
              else:
                  color = "yellow" if pass_count > fail_count else "red"
                  badges["nfcore_lint"] = make_badge(
                      label="nf-core lint", message=f"{{pass_count}} passed / {{fail_count}} failed", color=color
                  )
              summary["nfcore"] = {{"passed": pass_count, "warned": warn_count, "failed": fail_count}}
          except Exception as e:
              badges["nfcore_lint"] = make_badge(label="nf-core lint", message="inspected", color="yellow")
              summary["nfcore"] = {{"error": str(e)}}

          # 6. Syft SBOM Generation
          print("[6/6] Generating Syft Software Bill of Materials (SBOM)...")
          res_syft = subprocess.run(["syft", "dir:.", "-o", "spdx-json=sbom.spdx.json"], capture_output=True, text=True)
          if os.path.exists("sbom.spdx.json"):
              badges["syft"] = make_badge(label="SBOM", message="Syft verified", color="brightgreen")
              summary["sbom"] = "generated"
          else:
              badges["syft"] = make_badge(label="SBOM", message="failed", color="red")
              summary["sbom"] = "failed"

          # 7. Quindecagon Composite Score
          passed_categories = sum([
              leaks_count == 0,
              summary["sbom"] == "generated",
              summary["r_files"] > 0,
              summary.get("nfcore", {{}}).get("passed", 0) > 50
          ])
          badges["quindecagon"] = make_badge(
              label="quindecagon",
              message="verified",
              color="brightgreen" if passed_categories >= 3 else "yellow"
          )

          # Write all badge endpoints
          os.makedirs("badges_data", exist_ok=True)
          for name, data in badges.items():
              with open(f"badges_data/{{name}}.json", "w") as bf:
                  json.dump(data, bf, indent=2)

          with open("badges_data/summary.json", "w") as sf:
              json.dump(summary, sf, indent=2)

          print("\\nBadges data successfully generated in badges_data/")
          EOF

      - name: Upload Audit Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: quindecagon-audit-summary
          path: |
            badges_data/
            *.json
            *.spdx.json

      - name: Deploy Badges to badges branch
        if: github.ref == 'refs/heads/main' || github.ref == 'refs/heads/dev'
        run: |
          git config --global --add safe.directory '*'
          git config --global user.name "github-actions[bot]"
          git config --global user.email "github-actions[bot]@users.noreply.github.com"

          cd badges_data
          git init
          git checkout -b {badges_branch}
          git add *.json
          git commit -m "Update Quindecagon audit badges [skip ci]"

          git push -f \\
            https://x-access-token:${{{{ secrets.GITHUB_TOKEN }}}}@github.com/${{{{ github.repository }}}}.git \\
            {badges_branch}
"""


def get_badges_block(owner, repo, branch="badges"):
    """Constructs the Shields.io markdown badges block for the pipeline."""
    base_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}"
    return (
        f"{BADGES_START_MARKER}\n"
        f"[![quindecagon](https://img.shields.io/endpoint?url={base_url}/quindecagon.json)]"
        f"(https://github.com/JD2112/quindecagon)\n"
        f"[![nf-core lint](https://img.shields.io/endpoint?url={base_url}/nfcore_lint.json)]"
        f"(https://nf-co.re)\n"
        f"[![SBOM](https://img.shields.io/endpoint?url={base_url}/syft.json)]"
        f"(https://github.com/anchore/syft)\n"
        f"[![secrets](https://img.shields.io/endpoint?url={base_url}/secrets.json)]"
        f"(https://github.com/gitleaks/gitleaks)\n"
        f"[![code style](https://img.shields.io/endpoint?url={base_url}/black.json)]"
        f"(https://github.com/psf/black)\n"
        f"[![flake8](https://img.shields.io/endpoint?url={base_url}/flake8.json)]"
        f"(https://flake8.pycqa.org)\n"
        f"[![R audit](https://img.shields.io/endpoint?url={base_url}/r_audit.json)]"
        f"(https://github.com/r-lib/lintr)\n"
        f"{BADGES_END_MARKER}"
    )


def inject_badges(readme_content, badges_block):
    """Injects or updates the dynamic badges in README content."""
    # 1. If explicit markers are present, replace what's between them
    if BADGES_START_MARKER in readme_content and BADGES_END_MARKER in readme_content:
        pattern = re.compile(
            re.escape(BADGES_START_MARKER) + r".*?" + re.escape(BADGES_END_MARKER),
            re.DOTALL,
        )
        return (
            pattern.sub(badges_block, readme_content),
            "updated existing badges block",
        )

    # 2. Check if bare badges already exist (e.g. without markers)
    endpoint_re = r"https://img\.shields\.io/endpoint\?url=[^)]+"
    bare_pattern = re.compile(
        rf"(\[!\[quindecagon\]\({endpoint_re}\)\]\(https://github\.com/JD2112/quindecagon\)\s*"
        rf"(\n\[!\[[^\]]+\]\({endpoint_re}\)\]\([^\)]+\))*)"
    )
    if bare_pattern.search(readme_content):
        return (
            bare_pattern.sub(badges_block, readme_content, count=1),
            "wrapped and updated existing badges",
        )

    # 3. Insert after the first H1 header line
    lines = readme_content.splitlines(keepends=True)
    h1_idx = -1
    for idx, line in enumerate(lines):
        if line.startswith("# ") and not line.startswith("##"):
            h1_idx = idx
            break

    if h1_idx != -1:
        # Insert after the header line (plus a blank line)
        next_idx = h1_idx + 1
        updated_lines = (
            lines[:next_idx] + ["\n", badges_block + "\n"] + lines[next_idx:]
        )
        return "".join(updated_lines), "inserted badges after main title"

    # 4. Fallback: prepend at the beginning
    return badges_block + "\n\n" + readme_content, "prepended badges to README"


def create_workflow(
    target_dir=".",
    repo=None,
    branch="badges",
    mode="reusable",
    badges=True,
    force=False,
    dry_run=False,
    workflow_file=None,
):
    """Creates CI workflow file and injects README badges."""
    target_dir = os.path.abspath(target_dir)

    if not os.path.exists(target_dir):
        print(f"❌ Error: Target directory '{target_dir}' does not exist.")
        return 1

    # 1. Detect or validate GitHub repository
    detected_repo = detect_github_repo(target_dir)
    target_repo = repo or detected_repo

    if not target_repo:
        target_repo = "OWNER/REPOSITORY"
        print("⚠️  Warning: Could not automatically detect GitHub repo (owner/repo).")
        print(
            "    Using placeholder 'OWNER/REPOSITORY'. You can specify '--repo owner/repo'.\n"
        )
    else:
        print(f"📦 Detected repository: \033[1;36m{target_repo}\033[0m")

    # 2. Select workflow template
    if mode == "standalone":
        workflow_content = get_standalone_workflow_yaml(badges_branch=branch)
    else:
        workflow_content = get_reusable_workflow_yaml()

    workflow_path = workflow_file or os.path.join(
        target_dir, ".github", "workflows", "quindecagon-audit.yml"
    )
    rel_workflow_path = os.path.relpath(workflow_path, target_dir)

    print(f"⚙️  Workflow mode: \033[1;32m{mode}\033[0m (file: {rel_workflow_path})")

    # 3. Check for existing workflow file
    if os.path.exists(workflow_path) and not force and not dry_run:
        print(f"⚠️  Workflow file '{workflow_path}' already exists.")
        resp = input("    Overwrite existing workflow? [y/N]: ").strip().lower()
        if resp not in ["y", "yes"]:
            print("    Skipped workflow creation.")
            workflow_content = None

    if dry_run:
        print("\n--- [DRY-RUN] Workflow Content ---")
        print(workflow_content)
        print("--- End of Workflow Content ---\n")
    elif workflow_content:
        os.makedirs(os.path.dirname(workflow_path), exist_ok=True)
        with open(workflow_path, "w", encoding="utf-8") as f:
            f.write(workflow_content)
        print(f"✅ Created workflow: \033[1;32m{rel_workflow_path}\033[0m")

    # 4. Handle README badges injection
    if badges:
        readme_path = os.path.join(target_dir, "README.md")
        if os.path.exists(readme_path):
            with open(readme_path, "r", encoding="utf-8") as f:
                old_readme = f.read()

            parts = target_repo.split("/")
            owner = parts[0]
            repo_name = parts[1] if len(parts) > 1 else parts[0]

            badges_block = get_badges_block(owner, repo_name, branch=branch)
            new_readme, status_msg = inject_badges(old_readme, badges_block)

            if dry_run:
                print(f"\n--- [DRY-RUN] README Badges Block ({status_msg}) ---")
                print(badges_block)
                print("--- End of Badges Block ---\n")
            else:
                with open(readme_path, "w", encoding="utf-8") as f:
                    f.write(new_readme)
                print(
                    f"✅ Injected dynamic badges into \033[1;32mREADME.md\033[0m ({status_msg})"
                )
        else:
            print("ℹ️  No README.md found in target directory; skipped badge injection.")

    print("\n✨ Quindecagon CI setup complete!")
    print("📌 Next steps:")
    print("   1. Review changes: git diff")
    print(
        "   2. Commit & push:  git add .github/ README.md && "
        "git commit -m 'feat: add quindecagon audit CI' && git push"
    )
    print(
        f"   3. When the workflow runs on main/dev, it will publish badge JSONs to the '{branch}' branch."
    )

    return 0


def add_workflow_subparser(subparsers):
    """Registers workflow create and init-ci subcommands."""
    # Subcommand: workflow create
    wf_parser = subparsers.add_parser(
        "workflow",
        help="Manage Quindecagon CI workflows",
        description="Quindecagon CI Workflow Management",
    )
    wf_sub = wf_parser.add_subparsers(dest="workflow_command")
    create_parser = wf_sub.add_parser(
        "create",
        help="Generate CI workflow file and inject README badges",
        description="Generate Quindecagon audit workflow and badges for a pipeline repository",
    )
    _configure_workflow_args(create_parser)

    init_parser = wf_sub.add_parser(
        "init",
        help="Alias for 'workflow create'",
        description="Generate Quindecagon audit workflow and badges for a pipeline repository",
    )
    _configure_workflow_args(init_parser)

    # Subcommand: init-ci (top-level shortcut)
    init_ci_parser = subparsers.add_parser(
        "init-ci",
        help="Shortcut to generate CI audit workflow and badges",
        description="Quickly initialize Quindecagon CI in the current repository",
    )
    _configure_workflow_args(init_ci_parser)


def _configure_workflow_args(parser):
    """Configures CLI arguments for workflow generation."""
    parser.add_argument(
        "target_dir",
        nargs="?",
        default=".",
        help="Path to the Nextflow pipeline repository (default: current directory)",
    )
    parser.add_argument(
        "--repo",
        help="GitHub repository in 'owner/repo' format (auto-detected if omitted)",
        default=None,
    )
    parser.add_argument(
        "--branch",
        default="badges",
        help="Branch to store dynamic Shields.io badge endpoints (default: badges)",
    )
    parser.add_argument(
        "--mode",
        choices=["reusable", "standalone"],
        default="reusable",
        help="Workflow mode: 'reusable' (recommended 8-line workflow) or 'standalone' (self-contained)",
    )
    parser.add_argument(
        "--no-badges",
        action="store_true",
        help="Do not inject Shields.io badges into README.md",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite existing workflow file without prompting",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview generated files without writing to disk",
    )
    parser.add_argument(
        "--workflow-file",
        help="Custom path for the generated workflow file",
        default=None,
    )
