//! The interface is compiled into the binary. Nothing is read from disk at
//! run time, so no request can ever reach a local file.

pub struct Asset {
    pub content_type: &'static str,
    pub bytes: &'static [u8],
}

pub fn lookup(path: &str) -> Option<Asset> {
    let (content_type, bytes): (&'static str, &'static [u8]) = match path {
        "/" | "/index.html" => (
            "text/html; charset=utf-8",
            include_bytes!("../ui/index.html"),
        ),
        "/app.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../ui/app.js"),
        ),
        "/style.css" => ("text/css; charset=utf-8", include_bytes!("../ui/style.css")),
        "/favicon.svg" => ("image/svg+xml", include_bytes!("../ui/favicon.svg")),
        "/logo.svg" => ("image/svg+xml", include_bytes!("../ui/logo.svg")),
        "/fonts/plex-mono-400.woff2" => (
            "font/woff2",
            include_bytes!("../ui/fonts/IBMPlexMono-Regular.woff2"),
        ),
        "/fonts/plex-mono-600.woff2" => (
            "font/woff2",
            include_bytes!("../ui/fonts/IBMPlexMono-SemiBold.woff2"),
        ),
        _ => return None,
    };
    Some(Asset {
        content_type,
        bytes,
    })
}
