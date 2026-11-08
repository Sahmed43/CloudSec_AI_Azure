import argparse
from dotenv import load_dotenv
from .ai import summarize
from .detect import detect
from .ingest import load_events
from .report import save_report

def main() -> None:
    parser = argparse.ArgumentParser(description="CloudSec AI synthetic security triage")
    parser.add_argument("--input", default="data/synthetic_events.csv")
    parser.add_argument("--output", default="report.json")
    parser.add_argument("--ai", action="store_true", help="Call real Azure OpenAI deployment")
    args = parser.parse_args()
    load_dotenv()
    findings = detect(load_events(args.input))
    assessment = summarize(findings) if args.ai else None
    save_report(findings, args.output, assessment)
    print(f"Saved {len(findings)} findings to {args.output}")
    if assessment:
        print("\nAzure OpenAI assessment:\n" + assessment)

if __name__ == "__main__":
    main()
