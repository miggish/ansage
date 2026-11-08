//! The read-only JSON API (`/api/...`): the control socket's answers over HTTP.

use crate::control::proto::{Family as RibFamily, Request};

pub(super) enum ApiError {
    NotFound,
    Bad(String),
}

/// The read-only control request behind `GET /api/NAME?QUERY`, with the
/// same JSON as the control socket (`ansage show ... --json`). Nothing
/// that changes state is reachable over HTTP.
pub(super) fn api_request(name: &str, query: &str) -> Result<Request, ApiError> {
    let params = parse_query(query).map_err(ApiError::Bad)?;
    let allow = |keys: &[&str]| match params.iter().find(|(k, _)| !keys.contains(&k.as_str())) {
        Some((k, _)) => Err(ApiError::Bad(format!("unknown parameter {k:?}"))),
        None => Ok(()),
    };
    let get = |key: &str| {
        params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };
    Ok(match name {
        "summary" => {
            allow(&[])?;
            Request::Summary
        }
        "peers" => {
            allow(&["peer"])?;
            Request::Peers { peer: get("peer") }
        }
        "rib" => {
            allow(&["prefix", "family", "limit"])?;
            let family = match get("family").as_deref() {
                None => None,
                Some("ipv4") => Some(RibFamily::Ipv4),
                Some("ipv6") => Some(RibFamily::Ipv6),
                Some(other) => {
                    return Err(ApiError::Bad(format!("family {other:?}: ipv4 or ipv6")));
                }
            };
            let limit = get("limit")
                .map(|l| l.parse::<usize>())
                .transpose()
                .map_err(|err| ApiError::Bad(format!("limit: {err}")))?;
            Request::Rib {
                prefix: get("prefix"),
                family,
                limit,
            }
        }
        "fib" => {
            allow(&[])?;
            Request::Fib
        }
        _ => return Err(ApiError::NotFound),
    })
}

/// `a=1&b=%2F`: pairs, percent-decoded.
fn parse_query(query: &str) -> Result<Vec<(String, String)>, String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            Ok((percent_decode(k)?, percent_decode(v)?))
        })
        .collect()
}

fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| format!("bad escape in {s:?}"))?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| format!("{s:?} is not UTF-8"))
}
