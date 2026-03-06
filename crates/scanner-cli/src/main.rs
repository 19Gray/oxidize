use anyhow::Result;
use clap::{Parser, ValueEnum};
use scanner_core::finding::Severity;
use scanner_core::scan_target;
use scanner_report::{write_report, OutputFormat};
use std::process;

/// OWASP Static Vulnerability Scanner - A01, A02, A03, A04
#[derive(Parser, Debug)]
#[command(
    name = "purionX",
    version,
    about = "Scans source code and configs for OWASP Top-10 vulnerabilities"
)]
struct Cli {
    /// File or directory to scan
    #[arg(value_name = "TARGET")]
    target: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "console")]
    format: Format,

    /// Write output to FILE instead of stdout (for JSON, SARIF, HTML)
    #[arg(short, long, value_name = "FILE")]
    out: Option<String>,

    /// Only report findings at or above this severity level
    #[arg(short, long, value_enum, default_value = "info")]
    min_severity: SeverityArg,

    /// Exit with code 0 even when HIGH or CRITICAL findings are present
    #[arg(long, default_value_t = false)]
    no_fail: bool,
}

#[derive(ValueEnum, Debug, Clone)]
enum Format {
    Console,
    Json,
    Sarif,
    Html,
}

#[derive(ValueEnum, Debug, Clone)]
enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Info => Severity::Info,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

impl From<Format> for OutputFormat {
    fn from(f: Format) -> Self {
        match f {
            Format::Console => OutputFormat::Console,
            Format::Json => OutputFormat::Json,
            Format::Sarif => OutputFormat::Sarif,
            Format::Html => OutputFormat::Html,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let min_sev: Severity = cli.min_severity.into();
    let result = scan_target(&cli.target, &min_sev)?;
    let blocking = result.has_blocking();

    write_report(&result, &cli.format.into(), cli.out.as_deref())?;

    if blocking && !cli.no_fail {
        process::exit(1);
    }

    Ok(())
}
