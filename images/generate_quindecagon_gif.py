import os
from PIL import Image, ImageDraw, ImageFont

# Set up output path
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_GIF = os.path.join(OUTPUT_DIR, "quindecagon_demo.gif")

# Setup terminal dimensions and styling
WIDTH, HEIGHT = 760, 480
BG_COLOR = (24, 24, 24)  # Dark charcoal
TEXT_COLOR = (212, 212, 212)  # Light gray
GREEN = (78, 201, 176)  # Teal/Green
BLUE = (86, 156, 214)  # Sky blue
GRAY = (80, 80, 80)  # Muted gray
WHITE = (255, 255, 255)
RED = (244, 75, 75)
YELLOW = (255, 165, 0)

# Window decoration colors
W_BG = (30, 30, 30)
W_BORDER = (45, 45, 45)
W_DOT_RED = (255, 95, 86)
W_DOT_YELLOW = (255, 189, 46)
W_DOT_GREEN = (39, 201, 63)

# Find a monospaced font
font_paths = [
    "/System/Library/Fonts/Supplemental/Courier New.ttf",
    "/System/Library/Fonts/Supplemental/Andale Mono.ttf",
    "/System/Library/Fonts/Courier New.ttf",
    "/Library/Fonts/Courier New.ttf",
]
font = None
for fp in font_paths:
    if os.path.exists(fp):
        try:
            font = ImageFont.truetype(fp, 13)
            break
        except Exception:
            pass

if font is None:
    font = ImageFont.load_default()


# Helper to draw a single frame
def draw_frame(lines, active_cmd="", cursor_visible=True, progress_idx=-1):
    # Create image
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # 1. Draw Window Header Bar
    draw.rectangle([(0, 0), (WIDTH, 30)], fill=W_BG)
    draw.line([(0, 30), (WIDTH, 30)], fill=W_BORDER, width=1)

    # Window controls (three dots)
    draw.ellipse([(15, 9), (25, 19)], fill=W_DOT_RED)
    draw.ellipse([(31, 9), (41, 19)], fill=W_DOT_YELLOW)
    draw.ellipse([(47, 9), (57, 19)], fill=W_DOT_GREEN)

    # Window Title (using jyotirmoy@mac)
    title_text = "jyotirmoy@mac: ~ (quindecagon-audit)"
    w, h = (
        draw.textsize(title_text, font=font) if hasattr(draw, "textsize") else (200, 12)
    )
    draw.text(((WIDTH - w) // 2, 7), title_text, fill=GRAY, font=font)

    # 2. Draw Shell Prompt & Command (using jyotirmoy@mac)
    prompt = "jyotirmoy@mac:~/quindecagon$ "
    y_offset = 45
    draw.text((20, y_offset), prompt, fill=GREEN, font=font)
    prompt_w = (
        draw.textlength(prompt, font=font) if hasattr(draw, "textlength") else 195
    )

    cmd_text = active_cmd
    if cursor_visible:
        cmd_text += "▋"
    draw.text((20 + prompt_w, y_offset), cmd_text, fill=WHITE, font=font)

    y_offset += 25

    # 3. Draw Output Lines
    # Show only the last N lines that fit the screen
    max_visible_lines = 22
    visible_lines = lines[-max_visible_lines:]

    for idx, line in enumerate(visible_lines):
        line_y = y_offset + (idx * 17)
        # Determine styling
        if line.startswith("❌") or "failed" in line.lower():
            draw.text((20, line_y), line, fill=RED, font=font)
        elif (
            line.startswith("🎉")
            or line.startswith("✅")
            or "Passed" in line
            or "passed" in line.lower()
            or "verified" in line.lower()
        ):
            draw.text((20, line_y), line, fill=GREEN, font=font)
        elif (
            line.startswith("🎯")
            or line.startswith("📁")
            or line.startswith("🐳")
            or line.startswith("⚙️")
        ):
            draw.text((20, line_y), line, fill=BLUE, font=font)
        elif line.startswith("⏭️") or line.startswith("⚠️"):
            draw.text((20, line_y), line, fill=YELLOW, font=font)
        elif line.startswith("=================") or line.startswith(
            "-----------------"
        ):
            draw.text((20, line_y), line, fill=GRAY, font=font)
        else:
            draw.text((20, line_y), line, fill=TEXT_COLOR, font=font)

    return img


def main():
    frames = []
    lines = []

    # --- PHASE 1: Typing command ---
    command = "./quindecagon/scripts/docker_run.sh /target"
    for i in range(1, len(command) + 1):
        # Frame with cursor
        frames.append(draw_frame(lines, active_cmd=command[:i], cursor_visible=True))

    # A few blinking cursor frames at the end of typing
    for _ in range(3):
        frames.append(draw_frame(lines, active_cmd=command, cursor_visible=False))
        frames.append(draw_frame(lines, active_cmd=command, cursor_visible=True))

    # --- PHASE 2: Output generation ---
    # Add initial setup output (using jyotirmoy@mac path styling in logs if needed)
    initial_output = [
        "========================================",
        "🎯 Target pipeline:  /target",
        "📁 Reports saved to: /app/reports/your-pipeline_2026-06-08_11-30",
        "========================================",
        "🐳 Auto-discovered 15 container images:",
        "   • quay.io/biocontainers/multiqc:1.33--pyhdfd78af_0",
        "   • nextflow/nextflow:23.04.2",
        "   • jd21/milou:1.1.0",
        "========================================",
        "🧹 Removing stale reports/raw/ from previous runs...",
        "🧹 Removing stale reports/final/ from previous runs...",
        "⚙️  Initializing Nextflow environment...",
    ]

    for line in initial_output:
        lines.append(line)
        # 1 frame per line
        frames.append(draw_frame(lines, active_cmd=command, cursor_visible=False))

    # Add checks one by one
    checks = [
        ("🔍 Running nf-core lint...", "✅ nf-core lint passed"),
        ("🔍 Validating Nextflow Config...", "✅ Nextflow config is valid"),
        ("🔍 Running Semgrep...", "✅ Semgrep found 0 issues"),
        ("🔍 Running Gitleaks Secrets Audit...", "✅ Gitleaks found 0 secrets leaked"),
        ("🔍 Running Python Security Audit (Bandit)...", "✅ Bandit found 0 issues"),
        ("🔍 Running Python Code Quality Linter (Flake8)...", "✅ Flake8 passed"),
        ("🔍 Running Python Code Formatter (Black)...", "✅ Black check passed"),
        ("🔍 Running R Security Audit (lintr & oysteR)...", "✅ R audit passed"),
        ("🔍 Checking Reproducibility...", "✅ Reproducibility test passed"),
        ("🔍 Checking Provenance...", "✅ Provenance checks passed"),
        ("🔍 Running Trivy...", "✅ Trivy scan complete"),
        ("🔍 Running Snyk...", "✅ Snyk scan complete"),
        ("🔍 Running Docker Scout...", "✅ Docker Scout scan complete"),
        ("🔍 Running SBOM (Syft/Grype) scan...", "✅ SBOM generated and scanned"),
        ("🔍 Checking Cosign signatures...", "✅ Cosign signature verified"),
    ]

    for start_msg, success_msg in checks:
        lines.append("----------------------------------------")
        lines.append(start_msg)
        # Show checking frame
        frames.append(draw_frame(lines, active_cmd=command, cursor_visible=False))
        # Add success msg
        lines.append(success_msg)
        # Show success frame (repeat a bit to give pause)
        frames.append(draw_frame(lines, active_cmd=command, cursor_visible=False))
        frames.append(draw_frame(lines, active_cmd=command, cursor_visible=False))

    # --- PHASE 3: Wrap up output ---
    final_output = [
        "----------------------------------------",
        "📊 Attempting container-side report generation...",
        "✅ Container report generated.",
        "========================================",
        "🎉 All checks completed successfully!",
        "📄 Report: /app/reports/your-pipeline_2026-06-08_11-30/final/report_20260608_1130.html",
        "📝 Logs:   /app/reports/your-pipeline_2026-06-08_11-30/run.log",
    ]

    for line in final_output:
        lines.append(line)
        frames.append(draw_frame(lines, active_cmd=command, cursor_visible=False))

    # Hold the final screen for a few extra frames so the user can read the success state
    for _ in range(30):
        frames.append(draw_frame(lines, active_cmd=command, cursor_visible=False))

    # Save GIF
    frames[0].save(
        OUTPUT_GIF,
        save_all=True,
        append_images=frames[1:],
        optimize=True,
        duration=80,  # 80ms per frame
        loop=0,
    )
    print(f"Generated GIF containing {len(frames)} frames at: {OUTPUT_GIF}")


if __name__ == "__main__":
    main()
