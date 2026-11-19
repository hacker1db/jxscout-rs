//! URL lists from a file or stdin (SPEC R-12b, upstream #20).

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use url::Url;

use super::{IngestReport, IngestSource};
use crate::model::{Captured, Origin};
use crate::pipeline::Pipeline;

/// Reads one URL per line. Blank lines and `#` comments are skipped.
pub struct UrlListSource<R> {
    reader: R,
}

impl<R: AsyncRead + Unpin + Send> UrlListSource<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }
}

/// Parse one line of a URL list. `Ok(None)` for blank/comment lines.
pub fn parse_line(line: &str) -> Result<Option<Url>, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let shown = crate::text::clean(line);
    let url = Url::parse(line).map_err(|e| format!("`{shown}`: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("`{shown}`: only http(s) URLs are supported"));
    }
    Ok(Some(url))
}

impl<R: AsyncRead + Unpin + Send> IngestSource for UrlListSource<R> {
    fn name(&self) -> &'static str {
        "url-list"
    }

    async fn run(self, pipeline: Pipeline) -> anyhow::Result<IngestReport> {
        let mut report = IngestReport::default();
        let mut lines = BufReader::new(self.reader).lines();
        while let Some(line) = lines.next_line().await? {
            match parse_line(&line) {
                Ok(Some(url)) => {
                    if pipeline
                        .submit_wait(Captured::url_only(url, Origin::UrlList))
                        .await
                    {
                        report.submitted += 1;
                    } else {
                        report.rejected += 1;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("skipping invalid URL {e}");
                    report.rejected += 1;
                }
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines() {
        assert_eq!(parse_line("  # comment"), Ok(None));
        assert_eq!(parse_line(""), Ok(None));
        assert!(parse_line("https://a.test/x.js").unwrap().is_some());
        assert!(parse_line("ftp://a.test/").is_err());
        assert!(parse_line("not a url").is_err());
    }
}
