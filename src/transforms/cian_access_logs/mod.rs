use std::borrow::Cow;

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    config::{DataType, GenerateConfig, TransformConfig, TransformContext, TransformDescription},
    event::{Event, LogEvent, Value},
    internal_events::{CianDeleteLegacyField, CianRenameField},
    transforms::{FunctionTransform, Transform},
};

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CianAccessLogConfig {}

#[derive(Debug, Clone)]
pub struct CianAccessLog {}

inventory::submit! {
    TransformDescription::new::<CianAccessLogConfig>("cian_access_log")
}

impl GenerateConfig for CianAccessLogConfig {
    fn generate_config() -> toml::Value {
        toml::from_str(r#""#).unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "cian_access_log")]
impl TransformConfig for CianAccessLogConfig {
    async fn build(&self, _context: &TransformContext) -> crate::Result<Transform> {
        Ok(Transform::function(CianAccessLog::new()?))
    }

    fn input_type(&self) -> DataType {
        DataType::Any
    }

    fn output_type(&self) -> DataType {
        DataType::Any
    }

    fn transform_type(&self) -> &'static str {
        "cian_access_log"
    }
}

impl CianAccessLog {
    pub fn new() -> crate::Result<Self> {
        Ok(Self {})
    }
}

impl FunctionTransform for CianAccessLog {
    fn transform(&mut self, output: &mut Vec<Event>, mut event: Event) {
        match &mut event {
            Event::Log(log) => {
                process_nginx(log);
            }
            _ => {}
        };

        output.push(event);
    }
}

fn process_nginx(log: &mut LogEvent) {
    if !field_eq(log, "type", |v| v.eq("nginx")) {
        return;
    }


    process_http_request(log);

    rename(log, &NGINX_FIELDS_MAPPING);
    delete_legacy_fields(log, &NGINX_LEGACY_FIELDS);
}


fn process_http_request(log: &mut LogEvent) {
    enrich_by_url(log);
    unpack_x_headers(log);
}


/*
enrich_by_url = function (event)
    if event.log.url then
        local scheme, host, path, query_string = string.match(event.log.url, "^([a-z]+)://([^/?]*)([^?]*)%??(.*)$")
        if not event.log.scheme and scheme then
            event.log.scheme = scheme
        end
        if not event.log.host and host then
            event.log.host = host
        end
        if not event.log.path and path then
            if path == "" then
                path = "/"
            end
            event.log.path = path
        end
        if not event.log.query_string and query_string then
            event.log.query_string = query_string
        end
    end
    if event.log.path then
        event.log.path_simplified = get_path_simplified(event.log.path)
    end
end
*/
fn enrich_by_url(log: &mut LogEvent) {
    if let Some(url) = log.get("url") {
        let raw_url = url.to_string_lossy();
        if let Ok(url) = Url::parse(&raw_url) {
            log.try_insert("scheme", url.scheme());
            log.try_insert("host", url.host().map_or("".to_string(), |h| h.to_string()));
            log.try_insert("path", url.path());
            log.try_insert("query_string", url.query());
        }
    }

    if let Some(path) = log.get("path").clone() {
        let raw_path = path.to_string_lossy();
        log.try_insert("path_simplified", get_path_simplified(raw_path));
    }
}

/*
get_path_simplified = function (path)
    path = string.lower(string.gsub(path, "%d", ""))
    for _, prefix in ipairs(chpu_prefixes) do
        if starts_with(path, prefix) then
            return prefix .. "x"
        end
    end
    return path
end
*/
fn get_path_simplified(path: String) -> String {
    lazy_static::lazy_static! {
        static ref RE: Regex = Regex::new(r"\d*").unwrap();
    }

    let path = RE.replace_all(&path.to_lowercase(), "").to_string();

    for prefix in CHPU_PREFIXES {
        if path.starts_with(prefix) {
            return format!("{}-x", prefix);
        }
    }
    path
}


const NGINX_FIELDS_MAPPING: [(&'static str, &'static str); 18] = [
    ("request_method", "method"),
    ("http_referrer", "referer"),
    ("http_user_agent", "user_agent"),
    ("cookie__CIAN_GK", "guest_key"),
    ("headers", "request_headers"),
    ("X-Bot-Detected", "x_bot_detected"),
    ("X-Flavour", "x_flavour"),
    ("X_OperationId", "x_operationid"),
    ("X-ProfileSessionKey", "x_profilesessionkey"),
    ("X-ProfileSpanId", "x_profilespanid"),
    ("X-ProfileParentSpanId", "x_profileparentspanid"),
    ("X-Real-Email", "x_real_email"),
    ("X-Real-IP", "x_real_ip"),
    ("X-Real-UserId", "x_real_userid"),
    ("Subdomain", "x_subdomain"),
    ("X-Subdomain", "x_subdomain"),
    ("upstream_addr", "container_address"),
    ("body_bytes_sent", "response_size")
];

const CHPU_PREFIXES: [&'static str; 41] = [
    "/kupit-",
    "/snyat-",
    "/stati-",
    "/novosti-",
    "/oprosy-",
    "/blogs-",
    "/forum-rieltorov-",
    "/zhiloy-kompleks-",
    "/novostroyki-",
    "/zastroishchik-",
    "/mnogofunkcionalnyy-kompleks-",
    "/torgovo-ofisnyy-kompleks-",
    "/torgovyy-centr-",
    "/torgovo-razvlekatelnyy-centr-",
    "/torgovo-obshcestvennyy-centr-",
    "/autlet-",
    "/torgovo-delovoy-kompleks-",
    "/biznes-centr-",
    "/biznes-park-",
    "/ofisnoe-zdanie-",
    "/ofisno-proizvodstvennyy-kompleks-",
    "/ofisno-skladskoy-kompleks-",
    "/ofisno-zhiloy-kompleks-",
    "/ofisno-gostinichnyy-kompleks-",
    "/delovoy-centr-",
    "/osobnyak-",
    "/administrativnoe-zdanie-",
    "/tehnopark-",
    "/biznes-kvartal-",
    "/otdelno-stoyashcee-zdanie-",
    "/skladskoy-kompleks-",
    "/proizvodstvenno-skladskoy-kompleks-",
    "/industrialnyy-park-",
    "/logisticheskiy-kompleks-",
    "/proizvodstvennyy-kompleks-",
    "/proizvodstvennyy-ceh-",
    "/promploshcadka-",
    "/sklad-",
    "/images/",
    "/image-temp/",
    "/ajax/metrics/",
];


const NGINX_LEGACY_FIELDS: [&'static str; 41] = [
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Headers",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Origin",
    "Access-Control-Max-Age",
    "args",
    "Cache-Control",
    "cookie_DMIR_AUTH",
    "env",
    "Etag",
    "Expires",
    "facility",
    "facility_label",
    "function",
    "geo_locations",
    "input_type",
    "lenovo",
    "level",
    "logger",
    "msg",
    "priority",
    "profile_session_key",
    "http_host",
    "severity",
    "severity_label",
    "sitetype",
    "source",
    "thread_name",
    "time_local",
    "hostname",
    "upstream_status",
    "work_dir",
    "X-Autoprofiling-Force",
    "X-Debug",
    "X-Frontend-Entry",
    "X-Provided-By",
    "X-ProvidedBy",
    "X-Real-CianIP",
    "X-Request-Scheme",
    "message",
    "tags",
];

/*
rename = function(event, emit, old_name, new_name)
    local old = event.log[old_name]
    if old then
        event.log[new_name] = old
        event.log[old_name] = nil
        hacks.add(event, emit, "rename__" .. old_name .. "__" .. new_name)
    end
end
*/
fn rename(log: &mut LogEvent, mapping: &[(&str, &str)]) {
    for (old_key, new_key) in mapping {
        if let Some(v) = log.remove(&old_key) {
            if log.insert(&new_key, v).is_some() {
                emit!(&CianRenameField {
                    new_field: new_key,
                    old_field: old_key
                });
            }
        }
    }
}


/*
delete_legacy_fields = function(event, emit)
    for _, field in ipairs(legacy_fields) do
        if event.log[field] then
            event.log[field] = nil
            hacks.add(event, emit, "delete_legacy__" .. field)
        end
    end
end
*/

fn delete_legacy_fields(log: &mut LogEvent, fields: &[&str]) {
    for field in fields {
        if let Some(_) = log.remove(&field) {
            emit!(&CianDeleteLegacyField {
                field: field
            });
        }
    }
}

/*
unpack_x_headers = function (event)
    if not event.log.headers then
        return
    end
    for _, header in ipairs(event.log.headers) do
        if header.key:sub(1, 2):lower() == "x-" then
            key = header.key:lower():gsub("-", "_")
            event.log[key] = header.value
        end
    end
end
*/

fn unpack_x_headers(log: &mut LogEvent) {
    let x_headers: Vec<(String, Value)> = match &log.get("headers") {
        Some(Value::Array(headers)) => {
            headers.iter().filter_map(|header| {
                header.as_map().map(
                    |map| (
                        (&map).get("key").unwrap_or(&Value::Null).to_string_lossy(),
                        (&map).get("value").unwrap_or(&Value::Null)
                    )
                )
            }).filter_map(|(k, v)| {
                if k[..2].to_lowercase() == "x-" {
                    Some((k.to_lowercase().replace("-", "_"), v))
                } else { None }
            }).map(|(k, v)| (k, v.clone())).collect()
        }
        _ => vec![],
    };

    for (k, v) in x_headers {
        log.insert(k, v);
    };
}

fn field_eq<S, F>(log: &LogEvent, field: S, func: F) -> bool
    where
        S: Into<String>,
        F: Fn(Cow<str>) -> bool,
{
    let field = field.into();

    match log.get(&field) {
        Some(Value::Bytes(v)) => func(String::from_utf8_lossy(v)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::{event::LogEvent, transforms::test::transform_one};

    use super::*;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<CianAccessLogConfig>();
    }

    #[test]
    fn rename_fields() {
        let mut log = LogEvent::from("message");
        let mut expected = log.clone();
        log.insert("to_move", "some value");
        expected.insert("to_move", "some value");

        let mut transform = CianAccessLog::new().unwrap();

        let new_event = transform_one(&mut transform, log.into()).unwrap();

        assert_eq!(new_event.into_log(), expected);
    }
}
