use core::fmt;
use std::{convert::Infallible, path::PathBuf};

use axum::{
    extract::{FromRequestParts, MatchedPath},
    http::request::Parts,
};
use percent_encoding::percent_decode_str;

/// A file or folder path from the URL, segment by segment. Each segment is
/// percent-decoded on its own, so an encoded `/` (`%2F`) splits a name in two
/// just as a plain one does, and empty segments are dropped. Names such as
/// `.hidden` are kept; names are checked when an entry is created instead.
#[derive(Debug)]
pub struct UnrestrictedPath(Vec<String>);

impl UnrestrictedPath {
    /// The segments of `raw`, the path as it appears in the URL (still
    /// percent-encoded). Bytes that don't decode to UTF-8 are replaced.
    pub fn parse(raw: &str) -> Self {
        UnrestrictedPath(
            raw.split('/')
                .filter(|segment| !segment.is_empty())
                .map(|segment| percent_decode_str(segment).decode_utf8_lossy().into_owned())
                .collect(),
        )
    }

    /// Convert to a PathBuf while sanitizing the path
    pub fn to_path_buf(&self) -> PathBuf {
        self.0.iter().fold(PathBuf::new(), |mut pb, segment| {
            pb.push(segment);
            pb
        })
    }
}

/// The part of the request path after the route's own prefix: everything the
/// route's `{*path}` wildcard matched, or nothing for a route without one.
impl<S: Send + Sync> FromRequestParts<S> for UnrestrictedPath {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let raw = parts.uri.path();
        let rest = parts
            .extensions
            .get::<MatchedPath>()
            .and_then(|matched| matched.as_str().split_once("{*"))
            .and_then(|(prefix, _)| raw.strip_prefix(prefix))
            .unwrap_or("");

        Ok(UnrestrictedPath::parse(rest))
    }
}

impl fmt::Display for UnrestrictedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/{}", self.0.join("/"))
    }
}
