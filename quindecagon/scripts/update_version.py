#!/usr/bin/env python3
import os
import re
import sys


def load_file(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def save_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    print("🔄 quindecagon Interactive Version Synchronization Utility")
    print("=========================================================")

    # 1. Paths
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    pyproject_path = os.path.join(base_dir, "pyproject.toml")
    init_path = os.path.join(base_dir, "quindecagon", "__init__.py")
    report_path = os.path.join(base_dir, "quindecagon", "report.qmd")
    dashboard_path = os.path.join(
        base_dir, "quindecagon", "scripts", "generate_html_dashboard.py"
    )
    changelog_path = os.path.join(base_dir, "CHANGELOG.md")

    # 2. Read current version from pyproject.toml
    pyproject_content = load_file(pyproject_path)
    if not pyproject_content:
        print(f"❌ Error: pyproject.toml not found at {pyproject_path}")
        sys.exit(1)

    m = re.search(r'version\s*=\s*"([^"]+)"', pyproject_content)
    if not m:
        print("❌ Error: Could not find version string in pyproject.toml")
        sys.exit(1)

    current_version = m.group(1)
    print(
        f"📦 Current package version (pyproject.toml): \033[1;32m{current_version}\033[0m"
    )

    # 3. Parse semver components
    try:
        parts = current_version.split(".")
        major = int(parts[0])
        minor = int(parts[1])
        patch = int(parts[2])
    except Exception:
        major, minor, patch = 0, 0, 0

    proposed_patch = f"{major}.{minor}.{patch + 1}"
    proposed_minor = f"{major}.{minor + 1}.0"
    proposed_major = f"{major + 1}.0.0"

    print("\nSelect the next version release level:")
    print(f" 1) Patch bump:  --> \033[1;36m{proposed_patch}\033[0m")
    print(f" 2) Minor bump:  --> \033[1;36m{proposed_minor}\033[0m")
    print(f" 3) Major bump:  --> \033[1;36m{proposed_major}\033[0m")
    print(" 4) Custom manual version string")

    choice = input("\nEnter choice (1-4): ").strip()
    if choice == "1":
        new_version = proposed_patch
    elif choice == "2":
        new_version = proposed_minor
    elif choice == "3":
        new_version = proposed_major
    elif choice == "4":
        new_version = input("Enter custom version (e.g. 0.3.2): ").strip()
        if not re.match(r"^\d+\.\d+\.\d+$", new_version):
            print("❌ Invalid version format. Must be x.y.z")
            sys.exit(1)
    else:
        print("❌ Invalid choice. Exiting.")
        sys.exit(1)

    print(f"\n🔄 Synchronizing all files to version \033[1;32mv{new_version}\033[0m...")

    # 1. Update pyproject.toml
    new_pyproject = re.sub(
        r'(version\s*=\s*")([^"]+)(")', rf"\g<1>{new_version}\g<3>", pyproject_content
    )
    save_file(pyproject_path, new_pyproject)
    print("  ✅ Updated pyproject.toml")

    # 2. Update quindecagon/__init__.py
    init_content = load_file(init_path)
    if init_content:
        new_init = re.sub(
            r'(__version__\s*=\s*")([^"]+)(")',
            rf"\g<1>{new_version}\g<3>",
            init_content,
        )
        save_file(init_path, new_init)
        print("  ✅ Updated quindecagon/__init__.py")

    # 3. Update quindecagon/report.qmd
    report_content = load_file(report_path)
    if report_content:
        # Update subtitle
        new_report = re.sub(
            r'(#subtitle:\s*"Clinical Pipeline Integrity & Security Framework \(v)([^)]+)(\)")',
            rf"\g<1>{new_version}\g<3>",
            report_content,
        )
        # Update header/footers (fancyfoot)
        new_report = re.sub(
            r"(\\fancyfoot\[L\]\{\\small quindecagon \| v)([^}]+)(\})",
            rf"\g<1>{new_version}\g<3>",
            new_report,
        )
        # Update text paragraph references
        new_report = re.sub(
            r"(Clinical Pipeline Integrity & Security Framework \(v)([^)]+)(\))",
            rf"\g<1>{new_version}\g<3>",
            new_report,
        )
        # Update footer copyrights
        new_report = re.sub(
            r"(Clinical Security Framework v)([^ ]+)( \| Generated)",
            rf"\g<1>{new_version}\g<3>",
            new_report,
        )
        new_report = re.sub(
            r"(Clinical Security Framework v)([^\s]+)( \\textbar)",
            rf"\g<1>{new_version}\g<3>",
            new_report,
        )
        save_file(report_path, new_report)
        print("  ✅ Updated quindecagon/report.qmd")

    # 4. Update generate_html_dashboard.py
    dashboard_content = load_file(dashboard_path)
    if dashboard_content:
        # Update "pipeline_version" key
        new_dash = re.sub(
            r'("pipeline_version":\s*")([^"]+)(")',
            rf"\g<1>v{new_version}\g<3>",
            dashboard_content,
        )
        # Update blue header description portal subtitle
        new_dash = re.sub(
            r"(Security Control Portal \| v)([^ ]+)( \| Path)",
            rf"\g<1>{new_version}\g<3>",
            new_dash,
        )
        # Update version pill in accreditation card
        new_dash = re.sub(
            r'(tracking-wider bg-slate-800/40 border-slate-700/50 text-slate-300">v)([^<]+)(</span>)',
            rf"\g<1>{new_version}\g<3>",
            new_dash,
        )
        # Update copyright footer version
        new_dash = re.sub(
            r"(quindecagon Clinical Security Framework \| v)([^<]+)(</div>)",
            rf"\g<1>{new_version}\g<3>",
            new_dash,
        )
        save_file(dashboard_path, new_dash)
        print("  ✅ Updated quindecagon/scripts/generate_html_dashboard.py")

    # 5. Update CHANGELOG.md latest release header
    changelog_content = load_file(changelog_path)
    if changelog_content:
        # If there's an exact match of the old version in the latest release header (e.g. ## [0.3.1])
        new_changelog = re.sub(
            rf"(## \[)({re.escape(current_version)})(\])",
            rf"\g<1>{new_version}\g<3>",
            changelog_content,
            count=1,
        )
        # Or if the user wants to keep the historical log, they can, but updating the top header makes sure it matches.
        save_file(changelog_path, new_changelog)
        print("  ✅ Updated CHANGELOG.md latest entry header")

    print("\n🎉 Version synchronization complete! All components are fully aligned.")


if __name__ == "__main__":
    main()
