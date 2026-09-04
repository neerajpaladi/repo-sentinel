# main.py

import argparse
import asyncio
import sys
import os
from agents.orchestrator import run_investigation
from compiler.pdf_builder import pdf_builder


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Autonomous OSINT Threat Intelligence Dossier Generator"
    )
    parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="Target GitHub repository (e.g., 'apache/struts' or 'owner/repo')",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=3,
        help="Maximum iterative recursion depth for gap analysis (default: 3)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output PDF path (default: 'threat_dossier_<clean_target>.pdf')",
    )

    args = parser.parse_args()
    target = args.target.strip()
    max_depth = args.depth

    # Standardize output filename if not specified
    if not args.output:
        safe_target = target.replace("/", "_").replace("\\", "_")
        output_filename = f"threat_dossier_{safe_target}.pdf"
    else:
        output_filename = args.output

    print("=" * 65)
    print("      OSINT THREAT INTELLIGENCE DOSSIER GENERATOR")
    print("=" * 65)
    print(f"[*] Target Repository:   {target}")
    print(f"[*] Iterative Depth Limit: {max_depth}")
    print(f"[*] Output Destination:   {output_filename}")
    print("-" * 65)

    print("\n[+] Starting LangGraph state machine & gap analysis loop...")
    
    try:
        # Execute investigation loop via orchestrator
        report_data = await run_investigation(target=target, max_depth=max_depth)
    except Exception as e:
        print(f"\n[!] Critical failure during orchestration: {e}")
        sys.exit(1)

    print("[+] Autonomous investigation complete.")
    print("[+] Compiling report payload into executive PDF via WeasyPrint...")

    try:
        pdf_path = pdf_builder.build_pdf(report_data, output_filename=output_filename)
        print(f"\n[✓] Dossier generated successfully: {os.path.abspath(pdf_path)}")
    except Exception as e:
        print(f"\n[!] Critical failure during PDF compilation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())