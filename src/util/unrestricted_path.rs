use core::fmt;
use rocket::{http::uri::Segments, request::FromSegments};
use std::path::PathBuf;

#[derive(Debug)]
pub struct UnrestrictedPath(Vec<String>);

impl UnrestrictedPath {
    /// Convert to a PathBuf while sanitizing the path
    pub fn to_path_buf(&self) -> PathBuf {
        self.0.iter().fold(PathBuf::new(), |mut pb, segment| {
            pb.push(segment);
            pb
        })
    }
}

impl<'r> FromSegments<'r> for UnrestrictedPath {
    type Error = rocket::http::uri::Error<'r>;

    fn from_segments(
        segments: Segments<'r, rocket::http::uri::fmt::Path>,
    ) -> Result<Self, Self::Error> {
        Ok(UnrestrictedPath(
            segments.into_iter().map(|s| s.to_string()).collect(),
        ))
    }
}

impl fmt::Display for UnrestrictedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/{}", self.0.join("/"))
    }
}
