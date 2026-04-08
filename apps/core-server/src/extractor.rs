use axum::body::to_bytes;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http;
use axum::http::request::Parts;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use headers::{Error, Header, Mime};
use serde_qs::Config;

pub struct Qs<T>(pub T);

impl<S, T> FromRequestParts<S> for Qs<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let query = parts
            .uri
            .query()
            .ok_or((StatusCode::BAD_REQUEST, "Query missing".to_string()))?;
        Ok(Self(deserialize(query)?))
    }
}

pub struct QsOpt<T>(pub T);

impl<S, T> FromRequestParts<S> for QsOpt<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned + Default,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(query) = parts.uri.query() else {
            return Ok(Self(Default::default()));
        };
        Ok(Self(deserialize(query)?))
    }
}

pub struct QsOrForm<T>(pub T);

impl<S, T> FromRequest<S> for QsOrForm<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        const MB: usize = 1024 * 1024;

        let (parts, body) = req.into_parts();
        if let Some(query) = parts.uri.query() {
            Ok(Self(deserialize(query)?))
        } else {
            let bytes = to_bytes(body, 10 * MB)
                .await
                .map_err(|err| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read request body bytes: {err}"),
                    )
                })?
                .to_vec();
            if bytes.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Invalid request, query and body cannot be both empty".to_string(),
                ));
            };

            let request = serde_qs::from_bytes(bytes.as_slice()).map_err(|err| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Query extraction error: {err}"),
                )
            })?;
            Ok(Self(request))
        }
    }
}

fn deserialize<T>(query: &str) -> Result<T, (StatusCode, String)>
where
    T: serde::de::DeserializeOwned,
{
    Config::new(2, false)
        .deserialize_bytes(query.as_bytes())
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Query extraction error: {e}"),
            )
        })
}

#[derive(Clone, Debug, PartialEq)]
pub struct Accept(Vec<Mime>);

impl Accept {
    pub fn contains(&self, mime: &Mime) -> bool {
        self.0.contains(mime)
    }
}

impl Header for Accept {
    fn name() -> &'static HeaderName {
        &http::header::ACCEPT
    }

    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        values
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                let types = v
                    .split(',')
                    .map(|s| s.trim())
                    .flat_map(|s| s.parse::<Mime>().ok().into_iter())
                    .collect::<Vec<Mime>>();
                if types.is_empty() {
                    None
                } else {
                    Some(Accept(types))
                }
            })
            .ok_or_else(Error::invalid)
    }

    #[allow(clippy::expect_used)]
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let iter = self.0.iter().map(|m| {
            m.as_ref()
                .parse()
                .expect("Mime is always a valid HeaderValue")
        });
        values.extend(iter);
    }
}

impl From<Mime> for Accept {
    fn from(m: Mime) -> Accept {
        Accept(vec![m])
    }
}
