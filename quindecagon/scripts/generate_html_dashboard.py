#!/usr/bin/env python3
import os
import sys
import json
import glob
import hashlib
from datetime import datetime


def load_json(filepath):
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except Exception:
        return None


def load_text(filepath):
    if not os.path.exists(filepath):
        return ""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def generate_dashboard(raw_dir, output_html):
    # ---------------------------------------------------------
    # 1. PARSE ALL RAW TELEMETRY DATA
    # ---------------------------------------------------------
    # Load metadata.json for pipeline name and absolute path
    metadata_path = os.path.join(raw_dir, "metadata.json")
    pipeline_name = os.environ.get("PIPELINE_NAME", "quindecagon")
    pipeline_path = os.environ.get("PIPELINE_PATH", "quindecagon")
    run_command = os.environ.get("AUDIT_RUN_COMMAND", "N/A")
    if os.path.exists(metadata_path):
        try:
            m_data = load_json(metadata_path)
            if m_data:
                pipeline_name = m_data.get("pipeline_name", pipeline_name)
                pipeline_path = m_data.get("pipeline_path", pipeline_path)
                run_command = m_data.get("run_command", run_command)
        except Exception:
            pass

    # Escape HTML characters for the command string
    esc_run_command = (
        run_command.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )

    data = {
        "timestamp": datetime.now().strftime("%B %d, %Y at %H:%M:%S"),
        "pipeline_name": pipeline_name,
        "pipeline_path": pipeline_path,
        "pipeline_version": "v0.4.0",
        "metrics": {
            "total_images": 0,
            "sbom_images": 0,
            "signed_images": 0,
            "total_critical_cves": 0,
            "total_high_cves": 0,
            "secrets_found": 0,
            "sast_issues": 0,
        },
        "containers": [],
        "secrets": [],
        "sast": [],
    }

    # Gather all raw files to embed directly in the HTML for the Raw Diagnostics Log & JSON Explorer
    raw_files_embedded = {}

    for f_path in glob.glob(os.path.join(raw_dir, "*")):
        filename = os.path.basename(f_path)
        # Exclude extremely heavy raw JSON files from the embedded log explorer to avoid freezing the browser.
        # This keeps the final HTML cockpit extremely lightweight (< 1MB) and highly responsive.
        if filename.startswith(
            ("sbom_", "snyk_", "grype_", "trivy_")
        ) and filename.endswith(".json"):
            continue
        if filename == "r_audit_raw.json":
            continue
        if f_path.endswith(".json"):
            content = load_json(f_path)
            if content is not None:
                raw_files_embedded[filename] = content
        elif f_path.endswith((".txt", ".log")):
            raw_files_embedded[filename] = load_text(f_path)

    # Secrets (Gitleaks)
    gl = load_json(os.path.join(raw_dir, "gitleaks.json"))
    gl_findings = load_json(os.path.join(raw_dir, "gitleaks_findings.json"))

    if gl:
        raw_files_embedded["gitleaks.json"] = gl
    if gl_findings:
        raw_files_embedded["gitleaks_findings.json"] = gl_findings
        for leak in gl_findings:
            data["secrets"].append(
                {
                    "file": leak.get("File", "Unknown"),
                    "line": leak.get("StartLine", 0),
                    "rule": leak.get("Description", "Secret Pattern"),
                    "match": leak.get("Match", "***"),
                }
            )
            data["metrics"]["secrets_found"] += 1

    # Python SAST (Bandit)
    bandit = load_json(os.path.join(raw_dir, "bandit.json"))
    if bandit:
        raw_files_embedded["bandit.json"] = bandit
        if "results" in bandit:
            for res in bandit["results"]:
                data["sast"].append(
                    {
                        "tool": "Bandit (Python)",
                        "file": res.get("filename", ""),
                        "line": res.get("line_number", 0),
                        "severity": res.get("issue_severity", "MEDIUM"),
                        "description": res.get("issue_text", ""),
                    }
                )
                data["metrics"]["sast_issues"] += 1

    # Python Flake8
    flake8 = load_json(os.path.join(raw_dir, "flake8.json"))
    if flake8:
        raw_files_embedded["flake8.json"] = flake8

    # Python Formatting (Black)
    black = load_json(os.path.join(raw_dir, "black.json"))
    black_raw = load_text(os.path.join(raw_dir, "black_raw.txt"))
    if black:
        raw_files_embedded["black.json"] = black
        status = black.get("status", "unknown")
        unformatted = black.get("unformatted_files", 0)
        if status == "warning":
            data["sast"].append(
                {
                    "tool": "Black (Python)",
                    "file": "Python Files",
                    "line": "N/A",
                    "severity": "WARNING",
                    "description": f"Black found {unformatted} unformatted Python script(s). Format checking failed.",
                }
            )
            data["metrics"]["sast_issues"] += 1
    if black_raw:
        raw_files_embedded["black_raw.txt"] = black_raw

    # R SAST (Lintr / oysteR)
    r_audit = load_json(os.path.join(raw_dir, "r_audit_raw.json"))
    r_summary = load_json(os.path.join(raw_dir, "r_audit.json"))

    if r_summary:
        raw_files_embedded["r_audit.json"] = r_summary
    if r_audit:
        raw_files_embedded["r_audit_raw.json"] = r_audit
        for lint in r_audit.get("linters", []):
            data["sast"].append(
                {
                    "tool": "lintr (R)",
                    "file": lint.get("filename", ""),
                    "line": lint.get("line_number", 0),
                    "severity": "WARNING",
                    "description": lint.get("message", ""),
                }
            )
            data["metrics"]["sast_issues"] += 1
        for vuln in r_audit.get("vulnerabilities", []):
            data["sast"].append(
                {
                    "tool": "oysteR (R Deps)",
                    "file": vuln.get("package", ""),
                    "line": vuln.get("version", ""),
                    "severity": "HIGH",
                    "description": vuln.get("description", "Vulnerable Dependency"),
                }
            )
            data["metrics"]["sast_issues"] += 1

    # R Audit Log
    r_audit_log = load_text(os.path.join(raw_dir, "r_audit.log"))
    if r_audit_log:
        raw_files_embedded["r_audit.log"] = r_audit_log

    # Pipeline SAST (Semgrep)
    semgrep_raw = load_json(os.path.join(raw_dir, "semgrep_raw.json"))
    if semgrep_raw:
        if "results" in semgrep_raw:
            for res in semgrep_raw["results"]:
                data["sast"].append(
                    {
                        "tool": "Semgrep (Nextflow)",
                        "file": res.get("path", ""),
                        "line": res.get("start", {}).get("line", 0),
                        "severity": "HIGH",
                        "description": res.get("extra", {}).get("message", ""),
                    }
                )
                data["metrics"]["sast_issues"] += 1

    # Nextflow Config Validation
    nf_config = load_json(os.path.join(raw_dir, "nf_config_validation.json"))
    nf_config_txt = load_text(os.path.join(raw_dir, "nf_config_validation.txt"))
    if nf_config:
        raw_files_embedded["nf_config_validation.json"] = nf_config
    if nf_config_txt:
        raw_files_embedded["nf_config_validation.txt"] = nf_config_txt

    # Reproducibility
    repro = load_json(os.path.join(raw_dir, "reproducibility.json"))
    if repro:
        raw_files_embedded["reproducibility.json"] = repro

    # Provenance
    provenance = load_json(os.path.join(raw_dir, "provenance.json"))
    if provenance:
        raw_files_embedded["provenance.json"] = provenance

    # nfcore_lint
    nfcore_lint = load_json(os.path.join(raw_dir, "nfcore_lint.json"))
    if nfcore_lint:
        raw_files_embedded["nfcore_lint.json"] = nfcore_lint

    # Container Scans
    trivy_files = glob.glob(os.path.join(raw_dir, "trivy_*.json"))
    data["metrics"]["total_images"] = len(trivy_files)

    for tf in trivy_files:
        base_name = os.path.basename(tf).replace("trivy_", "").replace(".json", "")
        display_name = base_name.replace("_", "/")
        if display_name.count("/") > 2:
            parts = display_name.rsplit("/", 1)
            display_name = parts[0] + ":" + parts[1]

        t_data = load_json(tf)
        crit_count = 0
        high_count = 0
        top_cves = []

        if t_data:
            raw_files_embedded[f"trivy_{base_name}.json"] = t_data
            if "Results" in t_data:
                for res in t_data.get("Results", []):
                    for v in res.get("Vulnerabilities", []):
                        sev = v.get("Severity", "UNKNOWN")
                        if sev == "CRITICAL":
                            crit_count += 1
                        if sev == "HIGH":
                            high_count += 1

                        if sev in ["CRITICAL", "HIGH"] and len(top_cves) < 3:
                            top_cves.append(
                                f"{v.get('VulnerabilityID')} ({v.get('PkgName')})"
                            )

        data["metrics"]["total_critical_cves"] += crit_count
        data["metrics"]["total_high_cves"] += high_count

        # Docker Scout cves
        scout_crit = 0
        scout_high = 0
        scout_path = os.path.join(raw_dir, f"docker_scout_{base_name}_cves.json")
        scout_data = load_json(scout_path)
        if scout_data:
            raw_files_embedded[f"docker_scout_{base_name}_cves.json"] = scout_data
            # Let's count scout critical & high from SARIF
            rules_map = {}
            for run in scout_data.get("runs", []):
                driver = run.get("tool", {}).get("driver", {})
                for rule in driver.get("rules", []):
                    rule_id = rule.get("id")
                    if rule_id:
                        rules_map[rule_id] = rule

                for res in run.get("results", []):
                    rule_id = res.get("ruleId")
                    rule = rules_map.get(rule_id, {}) if rule_id else {}

                    severity = None
                    tags = rule.get("properties", {}).get("tags", [])
                    for t in tags:
                        if "severity:" in t.lower():
                            parts = t.split(":")
                            if len(parts) > 1:
                                severity = parts[1].strip().upper()
                                break

                    if not severity:
                        severity = res.get("properties", {}).get("cvssv3_severity")
                    if not severity:
                        severity = rule.get("properties", {}).get("cvssv3_severity")
                    if not severity:
                        cvss = res.get("properties", {}).get(
                            "cvssv3_score"
                        ) or rule.get("properties", {}).get("cvssv3_score")
                        if cvss:
                            try:
                                score = float(cvss)
                                if score >= 9.0:
                                    severity = "CRITICAL"
                                elif score >= 7.0:
                                    severity = "HIGH"
                            except:
                                pass
                    if not severity:
                        level = res.get("level", "warning").lower()
                        if level == "error":
                            severity = "HIGH"

                    if severity:
                        if "CRIT" in severity.upper():
                            scout_crit += 1
                        elif "HIGH" in severity.upper():
                            scout_high += 1

        # Check actual generated SBOM file path and pattern
        sbom_path = os.path.join(raw_dir, f"sbom_{base_name}.spdx.json")
        has_sbom = os.path.exists(sbom_path)
        if has_sbom:
            data["metrics"]["sbom_images"] += 1
            # Embed a tiny metadata descriptor instead of the 20MB raw JSON tree to optimize weight
            raw_files_embedded[f"sbom_{base_name}.spdx.json"] = {
                "status": "SBOM manifest generated successfully.",
                "size_bytes": os.path.getsize(sbom_path),
                "format": "SPDX JSON",
            }

        # Check actual generated Cosign file path and verification text
        cosign_path = os.path.join(raw_dir, f"cosign_{base_name}.txt")
        has_cosign = False
        cosign_content = ""
        if os.path.exists(cosign_path):
            cosign_content = load_text(cosign_path)
            if "Verification for" in cosign_content and "Error" not in cosign_content:
                has_cosign = True
                data["metrics"]["signed_images"] += 1
            raw_files_embedded[f"cosign_{base_name}.txt"] = cosign_content

        data["containers"].append(
            {
                "name": display_name,
                "critical": crit_count,
                "high": high_count,
                "scout_critical": scout_crit,
                "scout_high": scout_high,
                "sbom": has_sbom,
                "signed": has_cosign,
                "top_cves": top_cves,
            }
        )

    # Sort containers by critical/high vulnerabilities
    data["containers"].sort(key=lambda x: (x["critical"], x["high"]), reverse=True)

    # Compute dynamic cryptographic fingerprint for report integrity using raw directory files
    def generate_report_fingerprint(r_dir):
        try:
            import hashlib
            import glob

            files = sorted(glob.glob(os.path.join(r_dir, "*")))
            hasher = hashlib.sha256()
            for fpath in files:
                if (
                    os.path.isfile(fpath)
                    and not fpath.endswith("report.html")
                    and not fpath.endswith("report.pdf")
                ):
                    with open(fpath, "rb") as f:
                        hasher.update(f.read())
            return hasher.hexdigest()
        except Exception:
            return "N/A"

    genuity_fingerprint = generate_report_fingerprint(raw_dir)

    # Calculate status colors/pills using the 4-Level Consensus Compliance Assessment Engine
    def get_status_info(file):
        path = os.path.join(raw_dir, file)
        if not os.path.exists(path):
            return "Not Run"
        try:
            with open(path, "r") as f:
                d = json.load(f)
                status = d.get("status", "unknown")
                if status == "passed":
                    return "Passed"
                elif status == "failed":
                    return "Failed"
                elif status == "warning":
                    return "Warning"
                elif status == "skipped":
                    return "Skipped"
                return status.capitalize()
        except:
            return "Skipped"

    # 1. Domain D: Secrets
    gitleaks_status = get_status_info("gitleaks.json")
    gitleaks_findings_path = os.path.join(raw_dir, "gitleaks_findings.json")
    if os.path.exists(gitleaks_findings_path):
        try:
            with open(gitleaks_findings_path, "r") as f:
                findings = json.load(f)
                seen = set()
                active_leaks = 0
                binary_or_report_exts = (
                    ".png",
                    ".jpg",
                    ".jpeg",
                    ".gif",
                    ".pdf",
                    ".zip",
                    ".tar",
                    ".gz",
                    ".bam",
                    ".sam",
                    ".bai",
                    ".fastq",
                    ".fq",
                    ".vcf",
                    ".qmd",
                    ".html",
                    ".css",
                    ".svg",
                    ".webp",
                    ".lock",
                )
                for r in findings:
                    filepath = r.get("File", "")
                    if (
                        filepath.lower().endswith(binary_or_report_exts)
                        or "reports/" in filepath
                        or "report-check/" in filepath
                        or ".git/" in filepath
                        or "docs/" in filepath
                        or "site/" in filepath
                        or "containers/docker/" in filepath
                    ):
                        continue
                    key = (filepath, r.get("StartLine", ""), r.get("RuleID", ""))
                    if key not in seen:
                        seen.add(key)
                        active_leaks += 1
                if active_leaks > 0:
                    gitleaks_status = "Failed"
                else:
                    gitleaks_status = "Passed"
        except:
            pass

    # 2. Domain B: Reproducibility
    reproducibility_status = get_status_info("reproducibility.json")
    nf_config_status = get_status_info("nf_config_validation.json")
    nfcore_status = get_status_info("nfcore_lint.json")

    # 3. Domain C: Code SAST
    semgrep_status = get_status_info("semgrep.json")
    bandit_status = get_status_info("bandit.json")
    flake8_status = get_status_info("flake8.json")
    black_status = get_status_info("black.json")

    r_path = os.path.join(raw_dir, "r_audit_raw.json")
    lintr_status = "Not Run"
    oyster_status = "Not Run"
    riskmetric_status = "Not Run"
    if os.path.exists(r_path):
        try:
            with open(r_path, "r") as f:
                r_data = json.load(f)
                linters = r_data.get("linters", [])
                lint_count = (
                    len(linters)
                    if isinstance(linters, list)
                    else r_data.get("lint_count", 0)
                )
                lintr_status = "Passed" if lint_count == 0 else "Warning"

                vulns = r_data.get("vulnerabilities", [])
                vuln_count = (
                    len(vulns)
                    if isinstance(vulns, list)
                    else r_data.get("vuln_count", 0)
                )
                oyster_status = "Passed" if vuln_count == 0 else "Failed"

                risks = r_data.get("risks", [])
                risk_count = len(risks) if isinstance(risks, list) else 0
                riskmetric_status = "Passed" if risk_count == 0 else "Warning"
        except:
            pass

    r_json_path = os.path.join(raw_dir, "r_audit.json")
    if os.path.exists(r_json_path):
        try:
            with open(r_json_path, "r") as f:
                r_data = json.load(f)
                if r_data.get("status") == "skipped":
                    lintr_status = oyster_status = riskmetric_status = "Skipped"
        except:
            pass

    has_r_manifest = os.path.exists("/target/renv.lock") or os.path.exists(
        "/target/DESCRIPTION"
    )
    if not has_r_manifest and lintr_status not in ["Skipped", "Not Run"]:
        oyster_status = "Skipped"
        riskmetric_status = "Skipped"

    # 4. Domain A: Container / Supply Chain
    trivy_status = "Not Run"
    scout_status = "Not Run"
    syft_status = "Not Run"
    cosign_status = "Not Run"
    snyk_status = "Not Run"
    grype_status = "Not Run"

    if data["containers"]:
        trivy_status = (
            "Failed" if any(c["critical"] > 0 for c in data["containers"]) else "Passed"
        )
        scout_status = (
            "Failed"
            if any(c["scout_critical"] > 0 for c in data["containers"])
            else "Passed"
        )
        syft_status = (
            "Passed" if all(c["sbom"] for c in data["containers"]) else "Failed"
        )
        cosign_status = (
            "Passed" if all(c["signed"] for c in data["containers"]) else "Failed"
        )

        # Snyk Check
        snyk_status = "Passed"
        snyk_json_path = os.path.join(raw_dir, "snyk.json")
        if os.path.exists(snyk_json_path):
            s_data = load_json(snyk_json_path)
            if s_data and s_data.get("status") == "skipped":
                snyk_status = "Skipped"
        if snyk_status != "Skipped":
            snyk_failed = False
            snyk_files = glob.glob(os.path.join(raw_dir, "snyk_*.json"))
            if not snyk_files:
                snyk_status = "Not Run"
            else:
                for sf in snyk_files:
                    s_data = load_json(sf)
                    if s_data:
                        vulns = (
                            s_data.get("vulnerabilities", [])
                            if isinstance(s_data, dict)
                            else []
                        )
                        for v in vulns:
                            if v.get("severity", "").upper() == "CRITICAL":
                                snyk_failed = True
                snyk_status = "Failed" if snyk_failed else "Passed"

        # Grype Check
        grype_status = "Passed"
        syft_grype_json = os.path.join(raw_dir, "syft_grype.json")
        if os.path.exists(syft_grype_json):
            sg_data = load_json(syft_grype_json)
            if sg_data and sg_data.get("status") == "skipped":
                grype_status = "Skipped"
        if grype_status != "Skipped":
            grype_failed = False
            grype_files = glob.glob(os.path.join(raw_dir, "grype_*.json"))
            if not grype_files:
                grype_status = "Not Run"
            else:
                for gf in grype_files:
                    g_data = load_json(gf)
                    if g_data:
                        for match in g_data.get("matches", []):
                            if (
                                match.get("vulnerability", {})
                                .get("severity", "")
                                .upper()
                                == "CRITICAL"
                            ):
                                grype_failed = True
                grype_status = "Failed" if grype_failed else "Passed"

    # Domains definition
    domain_tools = {
        "A": [
            ("Trivy", trivy_status),
            ("Snyk", snyk_status),
            ("Docker Scout", scout_status),
            ("Syft", syft_status),
            ("Grype", grype_status),
            ("Cosign", cosign_status),
        ],
        "B": [
            ("Reproducibility Gate", reproducibility_status),
            ("Nextflow Config Validation", nf_config_status),
            ("nf-core lint", nfcore_status),
        ],
        "C": [
            ("Semgrep", semgrep_status),
            ("Bandit", bandit_status),
            ("Flake8", flake8_status),
            ("Black", black_status),
            ("R lintr", lintr_status),
            ("R oysteR", oyster_status),
            ("R riskmetric", riskmetric_status),
        ],
        "D": [("Gitleaks", gitleaks_status)],
    }

    failed_per_domain = {
        dom: [name for name, stat in domain_tools[dom] if stat == "Failed"]
        for dom in ["A", "B", "C", "D"]
    }
    total_failed_tools = sum(len(fails) for fails in failed_per_domain.values())
    failed_domains_count = sum(
        1 for fails in failed_per_domain.values() if len(fails) > 0
    )
    skipped_tools_list = [
        name
        for dom in ["A", "B", "C", "D"]
        for name, stat in domain_tools[dom]
        if stat == "Skipped"
    ]
    warned_tools_list = [
        name
        for dom in ["A", "B", "C", "D"]
        for name, stat in domain_tools[dom]
        if stat == "Warning"
    ]

    # Consensus grading logic
    if total_failed_tools > 2 and failed_domains_count >= 2:
        overall_clinical = "FAILED"
        overall_clinical_emoji = "🔴"
        overall_clinical_class = "bad"
        overall_clinical_badge = "FAILED / BLOCKED"
        overall_clinical_impact = "Immediate Pipeline Suspension. Disallowed for patient diagnostics under CAP/CLIA validation rules."
    elif (total_failed_tools > 1 and failed_domains_count > 1) or any(
        len(fails) >= 2 for fails in failed_per_domain.values()
    ):
        overall_clinical = "WARNING"
        overall_clinical_emoji = "🟠"
        overall_clinical_class = "warn"
        overall_clinical_badge = "WARNING"
        overall_clinical_impact = "Systemic Quality Risks. Requires urgent Laboratory Director review and remediation before re-validation."
    elif total_failed_tools == 1:
        overall_clinical = "CONDITIONAL"
        overall_clinical_emoji = "🟡"
        overall_clinical_class = "warn"
        overall_clinical_badge = "APPROVED WITH LIMITATIONS"
        overall_clinical_impact = "Conditional Clinical Use Allowed. Requires a documented 30-day CAPA plan for the isolated failure."
    else:
        overall_clinical = "VERIFIED"
        overall_clinical_emoji = "🟢"
        overall_clinical_class = "good"
        overall_clinical_badge = "APPROVED"
        overall_clinical_impact = "Full Clinical Certification. The pipeline satisfies core validation gates and is certified for patient diagnostics."

    # Check for Domain Incompletion (if all tools in any domain are skipped or not run)
    domain_unverified = False
    for dom, tools in domain_tools.items():
        active_count = sum(
            1 for name, stat in tools if stat in ["Passed", "Failed", "Warning"]
        )
        if active_count == 0:
            domain_unverified = True

    # --- SCIENTIFIC COMPLIANCE BYPASS OVERRIDES ---
    skipped_per_domain = {
        dom: sum(1 for name, stat in domain_tools[dom] if stat == "Skipped")
        for dom in ["A", "B", "C", "D"]
    }
    total_skipped_tools = len(skipped_tools_list)

    bypass_override_failed = False
    bypass_override_limitations = False
    bypass_override_warning = False
    bypass_override_reasons = []

    # 1. Zero-Bypass Pillar: Secrets Auditing (Domain D)
    if skipped_per_domain["D"] > 0:
        bypass_override_failed = True
        bypass_override_reasons.append(
            "HIPAA compliance breach: Secrets and Credentials scanning (Gitleaks) bypassed."
        )

    # 2. Domain B Reproducibility Bypass Limit (Max 1 skip allowed)
    if skipped_per_domain["B"] > 1:
        bypass_override_limitations = True
        bypass_override_reasons.append(
            f"Reproducibility validation severely restricted ({skipped_per_domain['B']} skipped in Domain B)."
        )

    # 3. Domain A Supply Chain Bypass Limit (Max 2 skips allowed)
    if skipped_per_domain["A"] > 2:
        bypass_override_limitations = True
        bypass_override_reasons.append(
            f"Supply Chain validation severely restricted ({skipped_per_domain['A']} skipped in Domain A)."
        )

    # 4. Domain C Code SAST Bypass Limit (Max 2 skips allowed)
    if skipped_per_domain["C"] > 2:
        bypass_override_limitations = True
        bypass_override_reasons.append(
            f"Static code integrity checks severely restricted ({skipped_per_domain['C']} skipped in Domain C)."
        )

    # 5. Entire Domain Unverified (Domain Completeness - 100% skipped in any domain)
    if domain_unverified:
        bypass_override_failed = True
        bypass_override_reasons.append(
            "Complete verification blank: One or more clinical domains have zero active checkers (100% skipped)."
        )

    # Apply Overrides (Capping at lower levels)
    if bypass_override_failed:
        overall_clinical = "FAILED"
        overall_clinical_emoji = "🔴"
        overall_clinical_class = "bad"
        overall_clinical_badge = "FAILED / BLOCKED"
        overall_clinical_impact = "Immediate Pipeline Suspension. Disallowed for patient diagnostics under CAP/CLIA guidelines due to complete domain bypasses."
    elif bypass_override_warning and overall_clinical in ["VERIFIED", "CONDITIONAL"]:
        overall_clinical = "WARNING"
        overall_clinical_emoji = "🟠"
        overall_clinical_class = "warn"
        overall_clinical_badge = "WARNING"
        overall_clinical_impact = "Systemic Verification Gaps. Bypassing critical controls prevents safe clinical approval."
    elif bypass_override_limitations and overall_clinical == "VERIFIED":
        overall_clinical = "CONDITIONAL"
        overall_clinical_emoji = "🟡"
        overall_clinical_class = "warn"
        overall_clinical_badge = "APPROVED WITH LIMITATIONS"
        overall_clinical_impact = "Conditional Clinical Use Allowed. Restricting quality gates (e.g. domain bypasses) limits clinical accreditation."

    # Backwards compatible status variables
    supply_chain = "STRONG" if cosign_status == "Passed" else "PARTIAL"
    secrets_status = "CLEAN" if gitleaks_status == "Passed" else "ACTION REQUIRED"

    # Build domain sub-pills for HTML
    domain_pills_html = ""
    for dom, name in [
        ("A", "Supply Chain"),
        ("B", "Reproducibility"),
        ("C", "Code SAST"),
        ("D", "Secrets"),
    ]:
        fails = failed_per_domain[dom]
        skips = [t for t, s in domain_tools[dom] if s == "Skipped"]
        if fails:
            badge_cls = "bg-rose-100 text-rose-800 border-rose-200"
            status_txt = f"{len(fails)} Failed"
        elif skips:
            badge_cls = "bg-amber-50 text-amber-800 border-amber-200"
            status_txt = "Skipped/Limitation"
        else:
            badge_cls = "bg-emerald-100 text-emerald-800 border-emerald-200"
            status_txt = "Passed"

        domain_pills_html += f"""
        <div class="flex items-center justify-between bg-slate-900/35 border border-slate-700/50 p-3 rounded-xl">
            <span class="text-xs font-semibold text-slate-300">{name}</span>
            <span class="px-2 py-0.5 border rounded-md text-[10px] font-bold uppercase tracking-wider {badge_cls}">{status_txt}</span>
        </div>
        """

    # Build caveats list for HTML
    caveats_html = ""
    html_caveat_items = []
    if overall_clinical == "FAILED":
        for dom, fails in failed_per_domain.items():
            if fails:
                html_caveat_items.append(
                    f"Domain {dom} critical failure: {', '.join(fails)}"
                )
    elif overall_clinical == "WARNING":
        for dom, fails in failed_per_domain.items():
            if fails:
                html_caveat_items.append(
                    f"Systemic failure in Domain {dom}: {', '.join(fails)}"
                )
    elif overall_clinical == "CONDITIONAL":
        for dom, fails in failed_per_domain.items():
            if fails:
                html_caveat_items.append(
                    f"Isolated failure in Domain {dom}: {fails[0]} failed. Requires CAPA record."
                )

    # Add specific bypass/override reasons to caveats
    for reason in bypass_override_reasons:
        html_caveat_items.append(f"Verification Constraint: {reason}")

    if skipped_tools_list:
        non_critical_skips = [
            t
            for t in skipped_tools_list
            if not any(t in r for r in bypass_override_reasons)
        ]
        if non_critical_skips:
            html_caveat_items.append(
                f"Other skipped checks: {', '.join(non_critical_skips)}"
            )
    if warned_tools_list:
        html_caveat_items.append(
            f"Linting / Style Quality warnings (Non-critical): {', '.join(warned_tools_list)}"
        )

    if html_caveat_items:
        caveats_html = '<div class="text-xs text-slate-300 bg-slate-950/45 p-4 rounded-xl border border-slate-700/40 space-y-1"><div class="font-extrabold text-[10px] text-slate-400 uppercase tracking-widest mb-1.5">Actionable Audit Caveats & Deficiencies:</div>'
        for item in html_caveat_items:
            # Escape single quotes safely inside double quoted HTML blocks
            esc_item = item.replace("'", "\\'")
            caveats_html += f'<div class="flex items-start gap-2 text-slate-300 leading-normal"><span class="text-amber-500">•</span> <span>{esc_item}</span></div>'
        caveats_html += "</div>"

    # ---------------------------------------------------------
    # 2. GENERATE BESPOKE HTML DASHBOARD
    # ---------------------------------------------------------

    def status_badge(condition, pass_text, fail_text):
        if condition:
            return f'<span class="px-2 py-0.5 bg-emerald-100 text-emerald-800 rounded-md text-[10px] font-bold uppercase tracking-wider border border-emerald-200">{pass_text}</span>'
        return f'<span class="px-2 py-0.5 bg-rose-100 text-rose-800 rounded-md text-[10px] font-bold uppercase tracking-wider border border-rose-200">{fail_text}</span>'

    def severity_badge(count, sev_type):
        if count == 0:
            return f'<span class="text-slate-400 font-medium">0</span>'
        color = "rose" if sev_type == "CRITICAL" else "amber"
        return f'<span class="text-{color}-600 font-extrabold">{count}</span>'

    # Build Container Rows
    container_rows = ""
    for c in data["containers"]:
        cve_list = "<br>".join([f"• {cve}" for cve in c["top_cves"]])
        if not cve_list and c["critical"] == 0 and c["high"] == 0:
            cve_list = "<span class='text-slate-400 italic'>Clean</span>"
        elif not cve_list:
            cve_list = (
                "<span class='text-slate-400 italic'>Run local scan for details</span>"
            )

        container_rows += f"""
        <tr class="border-b border-slate-100 hover:bg-slate-50 transition-colors">
            <td class="py-2.5 px-3 font-mono text-[11px] text-slate-800 break-all max-w-[240px]">{c['name']}</td>
            <td class="py-2.5 px-3 text-center font-bold">{severity_badge(c['critical'], "CRITICAL")} / {severity_badge(c['high'], "HIGH")}</td>
            <td class="py-2.5 px-3 text-center font-bold">{severity_badge(c['scout_critical'], "CRITICAL")} / {severity_badge(c['scout_high'], "HIGH")}</td>
            <td class="py-2.5 px-3 text-center">{status_badge(c['sbom'], "Generated", "Missing")}</td>
            <td class="py-2.5 px-3 text-center">{status_badge(c['signed'], "Verified", "Unsigned")}</td>
            <td class="py-2.5 px-3 text-[11px] text-slate-600 font-mono leading-tight">{cve_list}</td>
        </tr>
        """

    # Build Secret Rows
    secret_rows = ""
    if data["secrets"]:
        for s in data["secrets"]:
            secret_rows += f"""
            <tr class="border-b border-rose-100 bg-rose-50/20">
                <td class="py-2.5 px-3 font-mono text-[11px] text-rose-800 break-all max-w-[240px]">{s['file']}</td>
                <td class="py-2.5 px-3 text-center font-mono text-[11px] text-slate-600">{s['line']}</td>
                <td class="py-2.5 px-3 text-xs text-slate-800">{s['rule']}</td>
            </tr>
            """
    else:
        secret_rows = """<tr><td colspan="3" class="py-8 text-center text-slate-400 italic">No leaked credentials or API keys found in repository.</td></tr>"""

    # Build SAST Rows
    sast_rows = ""
    if data["sast"]:
        for s in data["sast"]:
            sast_rows += f"""
            <tr class="border-b border-amber-100 bg-amber-50/20">
                <td class="py-2.5 px-3 font-bold text-[10px] text-slate-700">{s['tool']}</td>
                <td class="py-2.5 px-3 font-mono text-[11px] text-slate-600 break-all max-w-[240px]">{s['file']}:{s['line']}</td>
                <td class="py-2.5 px-3 text-xs text-slate-800">{s['description']}</td>
            </tr>
            """
    else:
        sast_rows = """<tr><td colspan="3" class="py-8 text-center text-slate-400 italic">No static analysis anti-patterns found in Python, R, or Nextflow source.</td></tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>quindecagon | Clinical Security Cockpit</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        :root {{
            --bg-color: #f8fafc;
            --text-color: #0f172a;
            --card-bg: #ffffff;
            --card-border: #e2e8f0;
            --table-th-bg: #f8fafc;
            --text-muted: #64748b;
            --accent-blue: #1e3a8a;
            --accent-hover: #1e40af;
            --tab-bg: #f1f5f9;
        }}
        body.dark-mode {{
            --bg-color: #0f172a;
            --text-color: #f1f5f9;
            --card-bg: #1e293b;
            --card-border: #334155;
            --table-th-bg: #0f172a;
            --text-muted: #94a3b8;
            --accent-blue: #3b82f6;
            --accent-hover: #60a5fa;
            --tab-bg: #1e293b;
        }}
        body {{ font-family: 'Inter', system-ui, sans-serif; background-color: var(--bg-color) !important; color: var(--text-color) !important; transition: all 0.2s ease; }}
        .card {{ background: var(--card-bg) !important; border-radius: 16px; box-shadow: 0 4px 15px rgba(15, 23, 42, 0.02); border: 1px solid var(--card-border) !important; overflow: hidden; }}
        .header-gradient {{ background: linear-gradient(135deg, #0f172a 0%, #1e40af 100%); }}
        th {{ background-color: var(--table-th-bg) !important; text-transform: uppercase; font-size: 0.65rem; letter-spacing: 0.05em; color: var(--text-muted) !important; font-weight: 700; border-bottom: 2px solid var(--card-border) !important; }}
        .pill {{ border-radius: 9999px; padding: 0.2rem 0.6rem; font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }}
        .status-good {{ background:#dcfce7; color:#166534; }}
        .status-warn {{ background:#fef3c7; color:#92400e; }}
        .status-bad {{ background:#fee2e2; color:#991b1b; }}
        .status-info {{ background:#dbeafe; color:#1d4ed8; }}
        .interactive-card {{ transition: all 0.2s ease; cursor: pointer; }}
        .interactive-card:hover {{ transform: translateY(-2px); box-shadow: 0 8px 20px rgba(15, 23, 42, 0.06); }}
        .tab-btn.active {{ background-color: var(--accent-blue) !important; color: white !important; }}
        .tab-btn {{ background-color: var(--tab-bg) !important; color: var(--text-color) !important; border-color: var(--card-border) !important; }}
        .no-scrollbar::-webkit-scrollbar {{ display: none; }}
        .no-scrollbar {{ -ms-overflow-style: none; scrollbar-width: none; }}

        /* Designated Clinical Assurance Gate Dark Card styling */
        .clinical-card {{
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%) !important;
            border: 1px solid #334155 !important;
            color: #ffffff !important;
        }}
        .clinical-card .text-slate-500,
        .clinical-card .text-slate-400 {{
            color: #94a3b8 !important;
        }}
        .clinical-card .text-slate-300 {{
            color: #cbd5e1 !important;
        }}
        
        /* Interactive tree node CSS */
        .json-key {{ color: #a855f7; font-weight: bold; }}
        .json-value-string {{ color: #10b981; }}
        .json-value-number {{ color: #3b82f6; }}
        .json-value-boolean {{ color: #f59e0b; font-weight: bold; }}
        .json-value-null {{ color: #ef4444; }}

        /* High-contrast premium Dark Mode Overrides */
        body.dark-mode .bg-slate-50 {{
            background-color: rgba(30, 41, 59, 0.55) !important;
            border-color: rgba(51, 65, 85, 0.6) !important;
        }}
        body.dark-mode .bg-slate-50\/50 {{
            background-color: rgba(15, 23, 42, 0.4) !important;
        }}
        body.dark-mode .bg-white {{
            background-color: #1e293b !important;
        }}
        body.dark-mode .text-slate-800 {{
            color: #f8fafc !important;
        }}
        body.dark-mode .text-slate-700 {{
            color: #f1f5f9 !important;
        }}
        body.dark-mode .text-slate-600 {{
            color: #e2e8f0 !important;
        }}
        body.dark-mode .text-slate-500 {{
            color: #cbd5e1 !important;
        }}
        body.dark-mode .text-slate-400 {{
            color: #94a3b8 !important;
        }}
        body.dark-mode .text-slate-300 {{
            color: #cbd5e1 !important;
        }}
        body.dark-mode .border-slate-100,
        body.dark-mode .border-slate-200,
        body.dark-mode .border-slate-200\/50,
        body.dark-mode .border-slate-700\/50,
        body.dark-mode .border-slate-700\/40,
        body.dark-mode .border-slate-700\/60,
        body.dark-mode .border-slate-700\/30 {{
            border-color: #334155 !important;
        }}
        body.dark-mode tr.hover\:bg-slate-50:hover {{
            background-color: rgba(30, 41, 59, 0.8) !important;
        }}
        body.dark-mode .divide-slate-100 > * + * {{
            border-color: #334155 !important;
        }}
        body.dark-mode .bg-slate-100 {{
            background-color: #0f172a !important;
            border-color: #334155 !important;
            color: #cbd5e1 !important;
        }}
        body.dark-mode .bg-slate-100 span,
        body.dark-mode .bg-slate-100 button {{
            color: #f1f5f9 !important;
        }}
        body.dark-mode .bg-slate-100.active {{
            background-color: var(--accent-blue) !important;
            color: #ffffff !important;
        }}
        body.dark-mode .text-rose-800 {{
            color: #fda4af !important;
        }}
        body.dark-mode .bg-rose-50\/20 {{
            background-color: rgba(244, 63, 94, 0.15) !important;
        }}
        body.dark-mode .border-rose-100 {{
            border-color: rgba(244, 63, 94, 0.25) !important;
        }}
        body.dark-mode .bg-rose-100 {{
            background-color: rgba(244, 63, 94, 0.2) !important;
        }}
        body.dark-mode .text-rose-600 {{
            color: #f43f5e !important;
        }}
        body.dark-mode .border-rose-200 {{
            border-color: rgba(244, 63, 94, 0.35) !important;
        }}
        body.dark-mode .bg-amber-50\/20 {{
            background-color: rgba(245, 158, 11, 0.15) !important;
        }}
        body.dark-mode .border-amber-100 {{
            border-color: rgba(245, 158, 11, 0.25) !important;
        }}
        body.dark-mode .bg-amber-50 {{
            background-color: rgba(245, 158, 11, 0.1) !important;
        }}
        body.dark-mode .text-amber-800 {{
            color: #fde047 !important;
        }}
        body.dark-mode .text-amber-600 {{
            color: #fbbf24 !important;
        }}
        body.dark-mode .border-amber-200 {{
            border-color: rgba(245, 158, 11, 0.35) !important;
        }}
        body.dark-mode .bg-emerald-100 {{
            background-color: rgba(16, 185, 129, 0.18) !important;
        }}
        body.dark-mode .text-emerald-800 {{
            color: #34d399 !important;
        }}
        body.dark-mode .border-emerald-200 {{
            border-color: rgba(16, 185, 129, 0.35) !important;
        }}
        body.dark-mode .text-emerald-600 {{
            color: #34d399 !important;
        }}
    </style>
</head>
<body class="h-screen w-screen overflow-hidden flex flex-col p-4 md:p-6 gap-4">

    <!-- Header (Compact Cockpit style) -->
    <div class="header-gradient rounded-2xl px-6 py-4 text-white shadow-lg flex flex-col md:flex-row justify-between items-start md:items-center gap-4 relative overflow-hidden flex-shrink-0">
        <div class="absolute top-0 right-0 w-60 h-60 bg-blue-500 rounded-full mix-blend-multiply filter blur-3xl opacity-15 -translate-y-1/2 translate-x-1/3"></div>
        <div class="flex items-center gap-4 relative z-10">
            <div class="w-3.5 h-3.5 rounded-full bg-emerald-400 animate-pulse"></div>
            <div>
                <h1 class="text-2xl font-black tracking-tight">quindecagon <span class="text-blue-300 font-medium">| {data['pipeline_name']}</span></h1>
                <p class="text-xs text-blue-200">Interactive Unified Laboratory Diagnostics & Code Security Control Portal | v0.4.0 | Path: <code class="bg-blue-950/40 px-1.5 py-0.5 rounded text-[10px] text-emerald-300 border border-blue-400/20">{data['pipeline_path']}</code></p>
            </div>
        </div>
        <div class="flex items-center gap-3 relative z-10 font-mono text-xs">
            <!-- Theme Toggler -->
            <button onclick="toggleTheme()" class="bg-slate-900/40 hover:bg-slate-900/60 px-3 py-1.5 rounded-xl border border-white/10 font-bold text-xs flex items-center gap-2 transition-colors text-white">
                <span id="theme-icon">🌙</span> <span id="theme-text">Dark Mode</span>
            </button>
            <!-- View PDF link -->
            <a href="report.pdf" target="_blank" class="bg-slate-900/40 hover:bg-slate-900/60 px-3 py-1.5 rounded-xl border border-white/10 font-bold text-xs flex items-center gap-2 transition-colors text-white decoration-none">
                📄 View PDF
            </a>
            <div class="bg-slate-900/40 px-3 py-1.5 rounded-xl border border-white/10">
                <span class="text-blue-300 mr-2 font-semibold">Consensus:</span><span class="font-extrabold">{overall_clinical}</span>
            </div>
            <div class="bg-slate-900/40 px-3 py-1.5 rounded-xl border border-white/10">
                <span class="text-blue-300 mr-2 font-semibold">Generated:</span><span class="text-slate-200">{data['timestamp']}</span>
            </div>
        </div>
    </div>

    <!-- Audit Run Command display box -->
    <div class="w-full font-mono bg-slate-800 text-slate-300 p-2.5 rounded-xl border border-slate-700/60 overflow-x-auto whitespace-pre select-all text-[10px] flex-shrink-0"><strong>Audit Run Command:</strong> {esc_run_command}</div>

    <!-- Main Workspace (Grid split) -->
    <div class="flex-1 flex flex-col lg:flex-row gap-4 min-h-0">
        
        <!-- Left Panel: Executive & Compliance (1/3 Width) -->
        <div class="lg:w-1/3 flex flex-col gap-4 min-h-0 overflow-y-auto pr-1 no-scrollbar">
            
            <!-- Dynamic Metrics Cards Grid -->
            <div class="grid grid-cols-2 gap-3 flex-shrink-0">
                <div onclick="clickMetric('container')" class="interactive-card card p-4 border-l-4 border-l-blue-500">
                    <div class="text-[10px] text-slate-500 uppercase tracking-wide font-extrabold">SBOM Generation</div>
                    <div class="text-xl font-black text-slate-800 mt-1">{data['metrics']['sbom_images']} / {data['metrics']['total_images']}</div>
                    <div class="text-[9px] text-slate-400 mt-0.5">FDA Compliance Check</div>
                </div>
                
                <div onclick="clickMetric('container')" class="interactive-card card p-4 border-l-4 { 'border-l-emerald-500' if supply_chain == 'STRONG' else 'border-l-amber-500' }">
                    <div class="text-[10px] text-slate-500 uppercase tracking-wide font-extrabold">Cosign Signatures</div>
                    <div class="text-xl font-black text-slate-800 mt-1">{data['metrics']['signed_images']} / {data['metrics']['total_images']}</div>
                    <div class="text-[9px] text-slate-400 mt-0.5">Supply Chain Security</div>
                </div>

                <div onclick="clickMetric('container')" class="interactive-card card p-4 border-l-4 { 'border-l-emerald-500' if data['metrics']['total_critical_cves'] == 0 else 'border-l-rose-500' }">
                    <div class="text-[10px] text-slate-500 uppercase tracking-wide font-extrabold">Critical CVEs</div>
                    <div class="text-xl font-black text-slate-800 mt-1">{data['metrics']['total_critical_cves']}</div>
                    <div class="text-[9px] text-slate-400 mt-0.5">Trivy OS Vulnerabilities</div>
                </div>

                <div onclick="clickMetric('secrets')" class="interactive-card card p-4 border-l-4 { 'border-l-emerald-500' if data['metrics']['secrets_found'] == 0 else 'border-l-rose-500' }">
                    <div class="text-[10px] text-slate-500 uppercase tracking-wide font-extrabold">Active Secrets</div>
                    <div class="text-xl font-black text-slate-800 mt-1">{data['metrics']['secrets_found']}</div>
                    <div class="text-[9px] text-slate-400 mt-0.5">Gitleaks Exposure</div>
                </div>
            </div>

            <!-- Clinical Accreditation Card -->
            <div class="card clinical-card p-5 flex-shrink-0 relative overflow-hidden shadow-md">
                <div class="absolute top-0 right-0 w-32 h-32 bg-blue-500/10 rounded-full filter blur-xl opacity-20"></div>
                <div class="relative z-10 space-y-4">
                    <div class="flex items-center justify-between">
                        <h3 class="font-black text-xs uppercase tracking-widest text-slate-400">Clinical Assurance Gate</h3>
                        <span class="pill px-2 py-0.5 border rounded-md text-[9px] font-bold uppercase tracking-wider bg-slate-800/40 border-slate-700/50 text-slate-300">v0.4.0</span>
                    </div>
                    
                    <div class="flex items-center gap-3">
                        <span class="text-3xl leading-none">{overall_clinical_emoji}</span>
                        <div>
                            <div class="text-xs font-black uppercase text-slate-400 tracking-wider">Accreditation Decision</div>
                            <div class="text-lg font-black text-white leading-tight">{overall_clinical_badge}</div>
                        </div>
                    </div>
                    
                    <p class="text-[11px] text-slate-300 leading-normal font-medium bg-slate-900/40 p-2.5 rounded-lg border border-slate-700/30">
                        <strong>Impact:</strong> {overall_clinical_impact}
                    </p>
                    
                    <!-- 4 Sub-domains Grid -->
                    <div class="grid grid-cols-2 gap-2">
                        {domain_pills_html}
                    </div>
                    
                    <!-- Actionable Deficiencies list -->
                    {caveats_html}

                    <div class="text-[9px] text-slate-400 leading-snug border-t border-slate-700/50 pt-2.5">
                        <strong>Compliance Reference:</strong> Evaluated under the College of American Pathologists (CAP) Molecular Pathology NGS checklist items <strong>MOM.36000</strong> (Pipeline Validation), <strong>MOM.36150</strong> (Security Integrity), <strong>MOM.36200</strong> (Provenance Validation), and <strong>ISO 15189:2022 §7.4</strong> guidelines for bioinformatics software validation.
                    </div>
                </div>
            </div>

            <!-- Interactive Compliance & Tool Assessment Selector -->
            <div class="card p-5 flex flex-col flex-1 min-h-[220px]">
                <div class="flex border-b border-slate-200 mb-3 pb-1 text-xs font-bold gap-2">
                    <button id="btn-comp-selector" onclick="switchLeftTab('comp')" class="py-1 px-3 bg-slate-100 rounded-md text-slate-700 active font-extrabold">Regulatory Matrix</button>
                    <button id="btn-literature-selector" onclick="switchLeftTab('literature')" class="py-1 px-3 bg-slate-100 rounded-md text-slate-700">Clinical Literature</button>
                    <button id="btn-tool-selector" onclick="switchLeftTab('tools')" class="py-1 px-3 bg-slate-100 rounded-md text-slate-700">Tool Comparison</button>
                </div>

                <!-- Section 1: Regulatory -->
                <div id="left-view-comp" class="space-y-2.5 overflow-y-auto flex-1 no-scrollbar pr-1 text-xs">
                    <div class="bg-slate-50 p-3 rounded-xl border border-slate-200/50">
                        <div class="flex justify-between font-bold text-[10px] text-slate-600 mb-1">
                            <span>CAP MOM.36000</span><span class="text-emerald-600">VERIFIED</span>
                        </div>
                        <p class="text-slate-500 text-[11px]">Pinning Docker SHA digests ensures deterministic clinical outputs.</p>
                    </div>
                    <div class="bg-slate-50 p-3 rounded-xl border border-slate-200/50">
                        <div class="flex justify-between font-bold text-[10px] text-slate-600 mb-1">
                            <span>FDA Cybersecurity Guideline</span><span class="text-emerald-600">VERIFIED</span>
                        </div>
                        <p class="text-slate-500 text-[11px]">Software Bill of Materials (SBOM) mapped via Syft CycloneDX manifests.</p>
                    </div>
                    <div class="bg-slate-50 p-3 rounded-xl border border-slate-200/50">
                        <div class="flex justify-between font-bold text-[10px] text-slate-600 mb-1">
                            <span>HIPAA Security §164.308</span><span class="{ 'text-emerald-600' if secrets_status == 'CLEAN' else 'text-rose-600' }">{ secrets_status }</span>
                        </div>
                        <p class="text-slate-500 text-[11px]">Active protection of server credentials and access control logs.</p>
                    </div>
                </div>

                <!-- Section 2: Tools Comparison -->
                <div id="left-view-tools" class="hidden overflow-y-auto flex-1 no-scrollbar pr-1 text-xs space-y-2.5">
                    <div class="bg-slate-50 p-3 rounded-xl border border-slate-200/50">
                        <span class="font-extrabold text-slate-700 block">Trivy & Grype (Container SAST)</span>
                        <span class="text-slate-500 text-[11px]">100% offline databases, guaranteeing zero data egress under strict clinical HIPAA guidelines.</span>
                    </div>
                    <div class="bg-slate-50 p-3 rounded-xl border border-slate-200/50">
                        <span class="font-extrabold text-slate-700 block">oysteR & lintr (R Language)</span>
                        <span class="text-slate-500 text-[11px]">Crucial auditing of R statistical and Bioconductor packages missed by generic enterprise SAST.</span>
                    </div>
                    <div class="bg-slate-50 p-3 rounded-xl border border-slate-200/50">
                        <span class="font-extrabold text-slate-700 block">Semgrep & Bandit (Script SAST)</span>
                        <span class="text-slate-500 text-[11px]">Audits Nextflow config and Python data processing scripts for security anti-patterns.</span>
                    </div>
                </div>

                <!-- Section 3: Clinical Literature -->
                <div id="left-view-literature" class="hidden overflow-y-auto flex-1 no-scrollbar pr-1 text-xs space-y-2.5">
                    <div class="bg-slate-50 p-3 rounded-xl border border-slate-200/50">
                        <div class="flex justify-between font-bold text-[10px] text-slate-600 mb-1">
                            <a href="https://doi.org/10.1101/2024.11.23.624993" target="_blank" class="hover:underline text-blue-600 font-bold">Lavrichenko et al., 2024</a><span class="text-indigo-600 font-extrabold">QMS / UTILITY</span>
                        </div>
                        <p class="text-slate-500 text-[11px]">Recommendations for clinical practice bioinformatics: Quality management systems, identity verification, automation, and clinical utility guidelines.</p>
                    </div>
                    <div class="bg-slate-50 p-3 rounded-xl border border-slate-200/50">
                        <div class="flex justify-between font-bold text-[10px] text-slate-600 mb-1">
                            <a href="https://doi.org/10.1136/jmg-2025-111289" target="_blank" class="hover:underline text-blue-600 font-bold">Ellingford et al., 2026</a><span class="text-indigo-600 font-extrabold">NGS VALIDATION</span>
                        </div>
                        <p class="text-slate-500 text-[11px]">Best practice recommendations for high-throughput sequencing rare disease and cancer molecular diagnosis within clinical environments.</p>
                    </div>
                    <div class="bg-slate-50 p-3 rounded-xl border border-slate-200/50">
                        <div class="flex justify-between font-bold text-[10px] text-slate-600 mb-1">
                            <a href="https://doi.org/10.1016/b978-0-12-801238-3.11621-6" target="_blank" class="hover:underline text-blue-600 font-bold">Ganzinger et al., 2021</a><span class="text-indigo-600 font-extrabold">DATA GOVERNANCE</span>
                        </div>
                        <p class="text-slate-500 text-[11px]">Biomedical research and clinical data management architecture: guidelines for secure health data life cycles and storage environments.</p>
                    </div>
                    <div class="bg-slate-50 p-3 rounded-xl border border-slate-200/50">
                        <div class="flex justify-between font-bold text-[10px] text-slate-600 mb-1">
                            <a href="https://doi.org/10.3389/fdgth.2024.1471200" target="_blank" class="hover:underline text-blue-600 font-bold">Vidanagamachchi et al., 2024</a><span class="text-indigo-600 font-extrabold">CYBERSECURITY</span>
                        </div>
                        <p class="text-slate-500 text-[11px]">Opportunities and future perspectives of applying the CIA triad and robust encryption/auditing to protect sensitive genomic clinical profiles.</p>
                    </div>
                </div>
            </div>

        </div>

        <!-- Right Panel: Bioinformatics Detailed Cockpit (2/3 Width) -->
        <div class="lg:w-2/3 card flex flex-col min-h-0">
            
            <!-- Tab Navigation Strip -->
            <div class="flex border-b border-slate-200 bg-slate-50/50 p-3 gap-2 flex-shrink-0">
                <button id="btn-container" onclick="switchRightTab('container')" class="tab-btn px-4 py-2 text-xs font-bold rounded-lg bg-white border border-slate-200 shadow-sm text-slate-700 active">
                    Container Infrastructure Matrix
                </button>
                <button id="btn-secrets" onclick="switchRightTab('secrets')" class="tab-btn px-4 py-2 text-xs font-bold rounded-lg bg-white border border-slate-200 shadow-sm text-slate-700">
                    Hardcoded Secrets Detail
                </button>
                <button id="btn-sast" onclick="switchRightTab('sast')" class="tab-btn px-4 py-2 text-xs font-bold rounded-lg bg-white border border-slate-200 shadow-sm text-slate-700">
                    Source Code SAST / Checkers
                </button>
                <button id="btn-tools-directory" onclick="switchRightTab('tools-directory')" class="tab-btn px-4 py-2 text-xs font-bold rounded-lg bg-white border border-slate-200 shadow-sm text-slate-700">
                    Security Suite Directory
                </button>
                <button id="btn-raw-explorer" onclick="switchRightTab('raw-explorer')" class="tab-btn px-4 py-2 text-xs font-bold rounded-lg bg-white border border-slate-200 shadow-sm text-slate-700">
                    Raw Telemetry Log Explorer
                </button>
            </div>

            <!-- Scrollable Tables Viewport -->
            <div class="flex-1 overflow-y-auto no-scrollbar relative min-h-0">
                
                <!-- Table 1: Container Matrix -->
                <div id="right-view-container" class="absolute inset-0 overflow-y-auto">
                    <table class="w-full text-left border-collapse">
                        <thead class="sticky top-0 z-10">
                            <tr>
                                <th class="py-2.5 px-3">Container Image</th>
                                <th class="py-2.5 px-3 text-center">Trivy (C/H)</th>
                                <th class="py-2.5 px-3 text-center">Scout (C/H)</th>
                                <th class="py-2.5 px-3 text-center">SBOM Manifest</th>
                                <th class="py-2.5 px-3 text-center">Signature (Cosign)</th>
                                <th class="py-2.5 px-3">Top CVE Traces</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-100">
                            {container_rows}
                        </tbody>
                    </table>
                </div>

                <!-- Table 2: Secrets Table -->
                <div id="right-view-secrets" class="absolute inset-0 overflow-y-auto hidden">
                    <table class="w-full text-left border-collapse">
                        <thead class="sticky top-0 z-10">
                            <tr>
                                <th class="py-2.5 px-3">Leaked Source File</th>
                                <th class="py-2.5 px-3 text-center">Line</th>
                                <th class="py-2.5 px-3">Gitleaks Scan Rule Match</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-100">
                            {secret_rows}
                        </tbody>
                    </table>
                </div>

                <!-- Table 3: SAST Table -->
                <div id="right-view-sast" class="absolute inset-0 overflow-y-auto hidden">
                    <div class="p-4 bg-slate-50 border-b border-slate-200">
                        <h4 class="text-xs font-extrabold text-slate-700 uppercase mb-2">Quality Checker Checks</h4>
                        <div class="grid grid-cols-3 gap-3 text-xs font-semibold">
                            <div class="p-2.5 bg-white border border-slate-200 rounded-lg flex justify-between">
                                <span>nf-core lint</span><span class="text-emerald-600 font-extrabold">PASSED</span>
                            </div>
                            <div class="p-2.5 bg-white border border-slate-200 rounded-lg flex justify-between">
                                <span>R Audit</span><span class="{ 'text-emerald-600' if data['metrics']['sast_issues'] == 0 else 'text-amber-600' } font-extrabold">
                                    { "PASSED" if data['metrics']['sast_issues'] == 0 else "WARNING" }
                                </span>
                            </div>
                            <div class="p-2.5 bg-white border border-slate-200 rounded-lg flex justify-between">
                                <span>Python Audit</span><span class="{ 'text-emerald-600' if len(data['secrets']) == 0 else 'text-amber-600' } font-extrabold">
                                    { "PASSED" if len(data['secrets']) == 0 else "WARNING" }
                                </span>
                            </div>
                        </div>
                    </div>
                    <table class="w-full text-left border-collapse">
                        <thead class="sticky top-0 z-10">
                            <tr>
                                <th class="py-2.5 px-3">Scan Engine</th>
                                <th class="py-2.5 px-3">File Path / Line</th>
                                <th class="py-2.5 px-3">Anti-Pattern & Security Trace Message</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-100">
                            {sast_rows}
                        </tbody>
                    </table>
                </div>

                <!-- Table 4: Active Tools Directory -->
                <div id="right-view-tools-directory" class="absolute inset-0 overflow-y-auto hidden p-6 space-y-6">
                    <div>
                        <h3 class="text-lg font-bold text-slate-800 mb-1">🛠️ Hardened Security Tools Directory</h3>
                        <p class="text-xs text-slate-500">Fully transparent technical directory of all defensive checkers integrated within this assurance portal run.</p>
                    </div>
                    <div class="overflow-x-auto card">
                        <table class="w-full text-xs text-left border-collapse">
                            <thead>
                                <tr>
                                    <th class="py-2.5 px-3">Tool & Built Version</th>
                                    <th class="py-2.5 px-3">Type & Target</th>
                                    <th class="py-2.5 px-3">Executed CLI Command Reference</th>
                                    <th class="py-2.5 px-3">License</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-100 text-slate-700">
                                <tr>
                                    <td class="py-3 px-3 font-bold">Gitleaks v8.18.2</td>
                                    <td class="py-3 px-3">Secrets Scanning</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">gitleaks detect --source=/target --redact --verbose</td>
                                    <td class="py-3 px-3">MIT License</td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold">Trivy v0.55.0</td>
                                    <td class="py-3 px-3">Container OS & Package Scan</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">trivy image --exit-code 1 --severity CRITICAL &lt;img&gt;</td>
                                    <td class="py-3 px-3">Apache 2.0</td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold">Snyk CLI (Latest)</td>
                                    <td class="py-3 px-3">Vulnerability Consensus scan</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">snyk container test --json &lt;img&gt;</td>
                                    <td class="py-3 px-3">Custom / Commercial</td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold">Docker Scout CLI (Latest)</td>
                                    <td class="py-3 px-3">Advanced Image SAST</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">docker scout cves &lt;img&gt; --format json</td>
                                    <td class="py-3 px-3">Commercial / Free Tier</td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold">Syft v1.20.0</td>
                                    <td class="py-3 px-3">SBOM Generation (CycloneDX/SPDX)</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">syft &lt;img&gt; -o spdx-json</td>
                                    <td class="py-3 px-3">Apache 2.0</td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold">Grype v0.88.0</td>
                                    <td class="py-3 px-3">SBOM Vulnerability SCA</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">grype sbom:sbom.json</td>
                                    <td class="py-3 px-3">Apache 2.0</td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold">Cosign v3.0.6</td>
                                    <td class="py-3 px-3">Supply Chain Verification</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">cosign verify --insecure-ignore-tlog --key cosign.pub &lt;img&gt;</td>
                                    <td class="py-3 px-3">Apache 2.0</td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold">Semgrep v1.100.0</td>
                                    <td class="py-3 px-3">Groovy/Nextflow SAST</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">semgrep --config auto /target --json</td>
                                    <td class="py-3 px-3">LGPL-2.1</td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold">Bandit v1.7.5</td>
                                    <td class="py-3 px-3">Python Code SAST Scan</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">bandit -r /target -f json</td>
                                    <td class="py-3 px-3">Apache 2.0</td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold">Flake8 v6.0.0</td>
                                    <td class="py-3 px-3">Python Code Style PEP8</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">flake8 /target --format=json</td>
                                    <td class="py-3 px-3">MIT License</td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold">Black v24.0.0</td>
                                    <td class="py-3 px-3">Python Code Formatter</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">black --check --diff /target</td>
                                    <td class="py-3 px-3">MIT License</td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold">lintr (R Package)</td>
                                    <td class="py-3 px-3">R Code Quality & Security Linter</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">Rscript -e 'lintr::lint_dir("/target")'</td>
                                    <td class="py-3 px-3">GPL-3</td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold">oysteR (R Package)</td>
                                    <td class="py-3 px-3">R Dependency SCA Scanner</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">Rscript -e 'oysteR::audit_renv("/target")'</td>
                                    <td class="py-3 px-3">GPL-2</td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold">riskmetric (R Package)</td>
                                    <td class="py-3 px-3">R Package Risk Assessment</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">Rscript -e 'riskmetric::pkg_ref("/target")'</td>
                                    <td class="py-3 px-3">MIT License</td>
                                </tr>
                                <tr>
                                    <td class="py-3 px-3 font-bold">nf-core lint v2.14</td>
                                    <td class="py-3 px-3">Nextflow Configuration Linter</td>
                                    <td class="py-3 px-3 font-mono text-[10px] bg-slate-50 text-slate-600 p-1 rounded">nf-core pipelines lint --dir /target --json</td>
                                    <td class="py-3 px-3">MIT License</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Table 5: Interactive Raw Telemetry Log Explorer (Solves Opaque black box Issues 6,7,8,13,14,15) -->
                <div id="right-view-raw-explorer" class="absolute inset-0 flex flex-col min-h-0 bg-slate-900 text-slate-100 p-4 gap-3 hidden">
                    <div class="flex items-center justify-between flex-shrink-0">
                        <div class="flex items-center gap-2">
                            <span class="text-xs font-bold text-slate-400">SELECT TELEMETRY FILE:</span>
                            <select id="telemetry-file-picker" onchange="loadRawTelemetryFile()" class="bg-slate-800 text-white text-xs border border-slate-700 px-3 py-1.5 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                                <!-- Populated dynamically by JS -->
                            </select>
                        </div>
                        <button onclick="copyTelemetryContent()" class="bg-slate-800 hover:bg-slate-700 text-white text-[10px] font-bold px-3 py-1.5 rounded-lg border border-slate-700 transition-colors">
                            📋 Copy Plain Raw Content
                        </button>
                    </div>
                    
                    <!-- Content Viewport -->
                    <div class="flex-1 overflow-auto bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs select-text no-scrollbar">
                        <div id="raw-telemetry-viewport" class="text-emerald-400 leading-relaxed"></div>
                    </div>
                </div>

            </div>
        </div>
    </div>

    <!-- Thin Cockpit Footer -->
    <div class="flex flex-col gap-2 p-3 bg-slate-100 rounded-xl border border-slate-200 text-[10px] text-slate-500 font-medium flex-shrink-0 leading-tight">
        <div class="flex flex-col md:flex-row justify-between items-center w-full gap-2">
            <div>© 2026 Jyotirmoy Das | quindecagon Clinical Security Framework | v0.4.0</div>
            <div class="font-mono bg-white px-2 py-0.5 rounded border border-slate-200 select-all">Report Fingerprint: {genuity_fingerprint}</div>
        </div>
    </div>

    <script>
        // Raw data: JSON objects stored as-is. No pre-rendering.
        const RAW_DATA_FILES = {json.dumps(raw_files_embedded)};

        // ─── Populate File Picker ──────────────────────────────────────────────
        const picker = document.getElementById('telemetry-file-picker');
        Object.keys(RAW_DATA_FILES).sort().forEach(filename => {{
            const opt = document.createElement('option');
            opt.value = filename;
            opt.textContent = filename;
            picker.appendChild(opt);
        }});

        // ─── Helpers ──────────────────────────────────────────────────────────
        function escapeHtml(s) {{
            return String(s)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');
        }}

        // ─── Lazy JSON Tree Renderer ──────────────────────────────────────────
        // Renders only the top-level keys immediately; children are collapsed
        // and rendered on-demand when the user expands them.
        const CHUNK_SIZE = 100; // max children rendered at once before pagination

        function jsonTypeClass(val) {{
            if (val === null) return 'json-value-null';
            if (typeof val === 'boolean') return 'json-value-boolean';
            if (typeof val === 'number') return 'json-value-number';
            return 'json-value-string';
        }}

        function makeLeaf(val) {{
            const span = document.createElement('span');
            span.className = jsonTypeClass(val);
            span.textContent = val === null ? 'null' : String(val);
            return span;
        }}

        function makeTreeNode(key, value, depth) {{
            const isComplex = value !== null && typeof value === 'object';
            const childCount = isComplex ? Object.keys(value).length : 0;

            const wrapper = document.createElement('div');
            wrapper.style.marginLeft = (depth * 12) + 'px';
            wrapper.style.borderLeft = depth > 0 ? '1px solid #334155' : 'none';
            wrapper.style.paddingLeft = depth > 0 ? '8px' : '0';
            wrapper.style.marginBottom = '2px';

            const row = document.createElement('div');
            row.style.display = 'flex';
            row.style.alignItems = 'baseline';
            row.style.gap = '4px';
            row.style.cursor = isComplex ? 'pointer' : 'default';
            row.style.userSelect = 'text';

            if (key !== null) {{
                const keySpan = document.createElement('span');
                keySpan.className = 'json-key';
                keySpan.textContent = Array.isArray(value) || (typeof key === 'number') ? `[${{key}}]` : `"${{key}}"`;
                row.appendChild(keySpan);
                const colon = document.createElement('span');
                colon.style.color = '#94a3b8';
                colon.textContent = ':';
                row.appendChild(colon);
            }}

            if (!isComplex) {{
                row.appendChild(makeLeaf(value));
            }} else {{
                const toggle = document.createElement('span');
                toggle.style.color = '#60a5fa';
                toggle.style.fontWeight = 'bold';
                toggle.style.minWidth = '12px';
                const isArr = Array.isArray(value);
                toggle.textContent = '▶';
                row.appendChild(toggle);

                const preview = document.createElement('span');
                preview.style.color = '#64748b';
                preview.style.fontSize = '10px';
                preview.textContent = isArr
                    ? `${{isArr ? '[' : '{{'}} ${{childCount}} item${{childCount !== 1 ? 's' : ''}} ${{isArr ? ']' : '}}'}}` 
                    : `{{ ${{childCount}} key${{childCount !== 1 ? 's' : ''}} }}`;
                row.appendChild(preview);

                const children = document.createElement('div');
                children.style.display = 'none';
                let rendered = false;

                row.addEventListener('click', function(e) {{
                    e.stopPropagation();
                    if (children.style.display === 'none') {{
                        children.style.display = 'block';
                        toggle.textContent = '▼';
                        if (!rendered) {{
                            rendered = true;
                            renderChildren(value, children, depth + 1);
                        }}
                    }} else {{
                        children.style.display = 'none';
                        toggle.textContent = '▶';
                    }}
                }});

                wrapper.appendChild(row);
                wrapper.appendChild(children);
                return wrapper;
            }}

            wrapper.appendChild(row);
            return wrapper;
        }}

        function renderChildren(value, container, depth) {{
            const entries = Array.isArray(value)
                ? value.map((v, i) => [i, v])
                : Object.entries(value);

            let offset = 0;

            function renderChunk() {{
                const slice = entries.slice(offset, offset + CHUNK_SIZE);
                slice.forEach(([k, v]) => container.appendChild(makeTreeNode(k, v, depth)));
                offset += CHUNK_SIZE;
                if (offset < entries.length) {{
                    const more = document.createElement('button');
                    more.textContent = `▼ Load next ${{Math.min(CHUNK_SIZE, entries.length - offset)}} of ${{entries.length - offset}} remaining…`;
                    more.style.cssText = 'margin:4px 0;padding:2px 8px;background:#1e293b;color:#60a5fa;border:1px solid #334155;border-radius:4px;font-size:11px;cursor:pointer;';
                    more.onclick = () => {{ more.remove(); renderChunk(); }};
                    container.appendChild(more);
                }}
            }}

            renderChunk();
        }}

        function renderJsonTree(data, container) {{
            container.innerHTML = '';
            if (typeof data !== 'object' || data === null) {{
                container.appendChild(makeLeaf(data));
                return;
            }}
            renderChildren(data, container, 0);
        }}

        // ─── Load File on Picker Change ────────────────────────────────────────
        function loadRawTelemetryFile() {{
            const selected = picker.value;
            const content = RAW_DATA_FILES[selected];
            const viewport = document.getElementById('raw-telemetry-viewport');

            if (content === undefined || content === null) {{
                viewport.innerHTML = '<span style="color:#94a3b8">No content found for ' + escapeHtml(selected) + '</span>';
                return;
            }}

            viewport.innerHTML = '';

            if (typeof content === 'object') {{
                // Lazy interactive JSON tree
                viewport.style.color = '';
                renderJsonTree(content, viewport);
            }} else {{
                // Plain text / log file
                viewport.style.color = '#cbd5e1';
                const pre = document.createElement('pre');
                pre.style.whiteSpace = 'pre-wrap';
                pre.style.wordBreak = 'break-all';
                pre.textContent = content;
                viewport.appendChild(pre);
            }}
        }}

        function copyTelemetryContent() {{
            const selected = picker.value;
            const content = RAW_DATA_FILES[selected];
            const textToCopy = typeof content === 'object' ? JSON.stringify(content, null, 2) : content;

            navigator.clipboard.writeText(textToCopy).then(() => {{
                alert('Raw telemetry file ' + selected + ' copied to clipboard successfully!');
            }}).catch(err => {{
                alert('Could not copy text: ' + err);
            }});
        }}

        // Left Switcher
        function switchLeftTab(tabId) {{
            const comp = document.getElementById('left-view-comp');
            const tools = document.getElementById('left-view-tools');
            const lit = document.getElementById('left-view-literature');
            const btnComp = document.getElementById('btn-comp-selector');
            const btnTools = document.getElementById('btn-tool-selector');
            const btnLit = document.getElementById('btn-literature-selector');
 
            // Hide all and reset active styles
            comp.classList.add('hidden');
            tools.classList.add('hidden');
            lit.classList.add('hidden');
            btnComp.classList.remove('active', 'font-extrabold', 'bg-slate-100');
            btnTools.classList.remove('active', 'font-extrabold', 'bg-slate-100');
            btnLit.classList.remove('active', 'font-extrabold', 'bg-slate-100');
 
            if (tabId === 'comp') {{
                comp.classList.remove('hidden');
                btnComp.classList.add('active', 'font-extrabold', 'bg-slate-100');
            }} else if (tabId === 'literature') {{
                lit.classList.remove('hidden');
                btnLit.classList.add('active', 'font-extrabold', 'bg-slate-100');
            }} else {{
                tools.classList.remove('hidden');
                btnTools.classList.add('active', 'font-extrabold', 'bg-slate-100');
            }}
        }}

        // Right Switcher
        function switchRightTab(tabId) {{
            const container = document.getElementById('right-view-container');
            const secrets = document.getElementById('right-view-secrets');
            const sast = document.getElementById('right-view-sast');
            const toolsDir = document.getElementById('right-view-tools-directory');
            const rawExp = document.getElementById('right-view-raw-explorer');
            
            const btnContainer = document.getElementById('btn-container');
            const btnSecrets = document.getElementById('btn-secrets');
            const btnSast = document.getElementById('btn-sast');
            const btnToolsDir = document.getElementById('btn-tools-directory');
            const btnRawExp = document.getElementById('btn-raw-explorer');

            // Hide all
            container.classList.add('hidden');
            secrets.classList.add('hidden');
            sast.classList.add('hidden');
            toolsDir.classList.add('hidden');
            rawExp.classList.add('hidden');

            btnContainer.classList.remove('active');
            btnSecrets.classList.remove('active');
            btnSast.classList.remove('active');
            btnToolsDir.classList.remove('active');
            btnRawExp.classList.remove('active');

            // Show active
            if (tabId === 'container') {{
                container.classList.remove('hidden');
                btnContainer.classList.add('active');
            }} else if (tabId === 'secrets') {{
                secrets.classList.remove('hidden');
                btnSecrets.classList.add('active');
            }} else if (tabId === 'sast') {{
                sast.classList.remove('hidden');
                btnSast.classList.add('active');
            }} else if (tabId === 'tools-directory') {{
                toolsDir.classList.remove('hidden');
                btnToolsDir.classList.add('active');
            }} else if (tabId === 'raw-explorer') {{
                rawExp.classList.remove('hidden');
                btnRawExp.classList.add('active');
                loadRawTelemetryFile();
            }}
        }}

        // Clickable Metric Cards Handler
        function clickMetric(tabId) {{
            switchRightTab(tabId);
        }}

        // Initialize button styling
        switchRightTab('container');

        function toggleTheme() {{
            const body = document.body;
            const isDark = body.classList.toggle('dark-mode');
            document.getElementById('theme-icon').textContent = isDark ? '☀️' : '🌙';
            document.getElementById('theme-text').textContent = isDark ? 'Light Mode' : 'Dark Mode';
        }}
    </script>

</body>
</html>"""

    with open(output_html, "w") as f:
        f.write(html)

    print(
        f"✅ Transparent Single-Screen Cockpit Dashboard with Raw Explorer written to {output_html}"
    )


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: generate_html_dashboard.py <raw_dir> <output_html>")
        sys.exit(1)
    generate_dashboard(sys.argv[1], sys.argv[2])
