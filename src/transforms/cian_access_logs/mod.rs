use std::borrow::Cow;
use std::net::Ipv4Addr;
use std::str::FromStr;

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

    let is_infra_nginx: bool = log.get("kubernetes.namespace").map_or(
        false,
        |v| v.to_string_lossy() == "front-infra-nginx",
    );

    remove_empty_fields(log);

    convert_time_format(
        log,
        vec![
            "request_time".to_string(),
            "upstream_connect_time".to_string(),
            "upstream_header_time".to_string(),
        ],
    );

    process_http_request(log);

    rename(log, &NGINX_FIELDS_MAPPING);
    delete_legacy_fields(log, &NGINX_LEGACY_FIELDS);

    if !is_infra_nginx {
        set_sla(log);
        set_sla_type(log);
    }

    set_x_real_ip(log);
}

/*
if type(event.log.request_time) == "string" then
    hacks.add(event, emit, "request_time_as_string")
    event.log.request_time = summarize_by_upstreams(event.log.request_time)
end
*/

fn convert_time_format(log: &mut LogEvent, fields: Vec<String>) {
    for field in fields {
        if let Some(val) = log.get(field.clone()) {
            match val.clone() {
                Value::Bytes(val) => {
                    // todo: hacks.add(event, emit, "request_time_as_string")
                    log.insert(field, summarize_by_upstreams(String::from_utf8_lossy(&val).into_owned()));
                }
                _ => ()
            }
        }
    }
}

/*
summarize_by_upstreams = function(data)
    local result = 0
    for resp_time in data:gmatch("[0-9%.]+") do
        result = result + tonumber(resp_time)
    end
    return math.floor(result * 1000 + 0.5)
end
*/
fn summarize_by_upstreams(text: String) -> i32 {
    lazy_static::lazy_static! {
        static ref RE: Regex = Regex::new(r"[\d\.]+").unwrap();
    }
    let mut result: f32 = 0.0;
    for cap in RE.captures_iter(&text) {
        result += cap.get(0).unwrap().as_str().parse::<f32>().unwrap();
    }

    (result * 1000.0 + 0.5).floor() as i32
}

/*
function remove_empty_fields(event)
    for key, val in pairs(event.log) do
        if val == "" or val == "-" then
            event.log[key] = nil
        end
    end
end
*/
fn remove_empty_fields(log: &mut LogEvent) {
    let map = log.as_map_mut();
    map.retain(|_, v | {
        match v {
            Value::Bytes(bytes) => {
                let val = String::from_utf8_lossy(bytes).into_owned();
                val != "" && val != "-"
            },
            _ => true
        }
    });
}

/*
get_sla_type = function(event)
    local host = event.log.host
    local path = event.log.path
    local user_agent = event.log.user_agent
    if not host or not path then
        return nil
    end
    host = host:lower()
    path = path:lower()
    if host == "metrics.cian.ru" or host == "service.cian.ru" or host == "fin.cian.ru" then
        return nil
    end
    if host == "my.cian.ru" then
        return "lk"
    end

    if host == "api.cian.ru" then
        if (
            path:find("^/moderation%-complaints/v%d+/get%-complaint%-types")
            or path:find("^/moderation%-complaints/v%d+/create%-complaint")
        ) then
            return "moderation"
        end
        if (
            path:find("^/1%.4/ios/offers")
            or path:find("^/1%.4/ios/search%-offers/")
            or path:find("^/search%-offers/v%d+/search%-offers%-for%-mobile%-apps")
            or path:find("^/search%-offers/v%d+/search%-offers%-mobile%-apps")
        ) then
            return "ios_offers"
        end
        if path:find("^/lk%-specialist/") then
            return "lk"
        end
        if (
            (
                path:find("^/search%-offers/v%d+/search%-offers%-desktop")
                or path:find("^/search%-offers/v%d+/search%-offers%-mobile%-site")
                or path:find("^/cian%-api/mobile%-site/v%d+/search%-offers")
            )
            and user_agent ~= "frontend-mobile-website"
            and user_agent ~= "mobile-search-frontend"
            and user_agent ~= "frontend-serp"
        ) then
            return "search_ajax"
        end
        return nil
    end
    if path == "/" and (host == "cian.ru" or host:find("^[a-z]+%.cian%.ru$")) then
        return "main"
    end
    if path == "/novostrojki/" or path == "/commercial/" or path == "/posutochno/" or path == "/snyat/" or path == "/kupit/" then
        return "vertical"
    end
    if starts_with(path, "/sale") or starts_with(path, "/rent") then
        return "card"
    end
    if starts_with(path, "/cat.php") or starts_with(path, "/snyat") or starts_with(path, "/kupit") then
        return "search"
    end
    if path:find("^/1%.0/data/") then
        return "lk"
    end
    if not path:find("draft") and (
        path:find("^/realty/add[1-4]%.aspx")
        or path:find("^/razmestit%-obyavlenie")
        or path:find("^/addform/v%d+/geocode")
        or path:find("^/addform/v%d+/offers")
        or path:find("^/addform/v%d+/publish%-terms")
    ) then
        return "add_form"
    end
    if path:find("favorites") then
        return "favorites"
    end
    return nil
end
*/

fn set_sla_type(log: &mut LogEvent) {
    if let Some(sla_type) = get_sla_type(log) {
        log.insert("sla_type", sla_type);
    };
}

fn get_sla_type(log: &LogEvent) -> Option<String> {
    let host = log.get("host").map(|v| v.to_string_lossy());
    let path = log.get("path").map(|v| v.to_string_lossy());
    let user_agent = log.get("user_agent").map(|v| v.to_string_lossy()).unwrap_or("".to_string());

    if host.is_none() || path.is_none() {
        return None;
    }

    let host = host.unwrap().to_lowercase();
    let path = path.unwrap().to_lowercase();

    if host == "metrics.cian.ru" || host == "service.cian.ru" || host == "fin.cian.ru" {
        return None;
    }

    if host == "my.cian.ru" {
        return Some("lk".to_string());
    }

    let path_match = |re| text_match(&path, re);
    let host_match = |re| text_match(&host, re);

    if host == "api.cian.ru" {
        if path_match(r"^/moderation-complaints/v\d+/get-complaint-types") ||
            path_match(r"^/moderation-complaints/v\d+/create-complaint")
        {
            return Some("moderation".to_string());
        }
        if path_match(r"^/1\.4/ios/offers") ||
            path_match(r"^/1\.4/ios/search-offers/") ||
            path_match(r"^/search-offers/v\d+/search-offers-for-mobile-apps") ||
            path_match(r"^/search-offers/v\d+/search-offers-mobile-apps")
        {
            return Some("ios_offers".to_string());
        }
        if path_match(r"^/lk-specialist/") {
            return Some("lk".to_string());
        }

        if (
            path_match(r"^/search-offers/v\d+/search-offers-desktop") ||
                path_match(r"^/search-offers/v\d+/search-offers-mobile-site") ||
                path_match(r"^/cian-api/mobile-site/v\d+/search-offers")
        ) && user_agent != "frontend-mobile-website"
            && user_agent != "mobile-search-frontend"
            && user_agent != "frontend-serp"
        {
            return Some("search_ajax".to_string());
        }
        return None;
    }

    if path == "/" && (host == "cian.ru" || host_match(r"^[a-z]+\.cian\.ru$")) {
        return Some("main".to_string());
    }

    if path == "/novostrojki/" || path == "/commercial/" || path == "/posutochno/" || path == "/snyat/" || path == "/kupit/" {
        return Some("vertical".to_string());
    }
    if path.starts_with("/sale") || path.starts_with("/rent") {
        return Some("card".to_string());
    }


    if path.starts_with("/cat.php") || path.starts_with("/snyat") || path.starts_with("/kupit") {
        return Some("search".to_string());
    }

    if path_match(r"^/1\.0/data/") {
        return Some("lk".to_string());
    }

    if !path_match("draft") && (
        path_match(r"^/realty/add[1-4]\.aspx")
            || path_match(r"^/razmestit-obyavlenie")
            || path_match(r"^/addform/v\d+/geocode")
            || path_match(r"^/addform/v\d+/offers")
            || path_match(r"^/addform/v\d+/publish-terms")
    ) {
        return Some("add_form".to_string());
    }
    if path_match("favorites") {
        return Some("favorites".to_string());
    }
    return None;
}

fn text_match(text: &str, pattern: &str) -> bool {
    // Todo: re cache
    let re: Regex = Regex::new(pattern).unwrap();
    re.is_match(text)
}

fn process_http_request(log: &mut LogEvent) {
    enrich_by_url(log);
    unpack_x_headers(log);
}


/*
get_sla = function(event)
    if not event.log.response or event.log.response_time == nil then
        return nil
    end
    if event.log.response >= 500 and event.log.response ~= 511 then
        return "fail"
    end
    if event.log.response_time >= 500 then
        return "timeout"
    end
    return "success"
end
*/

fn set_sla(log: &mut LogEvent) {
    let response = log.get("response");
    let response_time = log.get("response_time");

    if response.is_none() && response_time.is_none() {
        return;
    }


    if let Some(&Value::Integer(response)) = response {
        if response >= 500 && response != 511 {
            log.try_insert("sla", "fail");
            return;
        }
    }

    let sla = match response_time {
        Some(&Value::Float(time)) if time >= 500 as f64 => { "timeout" }
        Some(&Value::Integer(time)) if time >= 500 => { "timeout" }
        _ => { "success" }
    };

    log.try_insert("sla", sla);
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

    if let Some(path) = log.get("path") {
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
            return format!("{}x", prefix);
        }
    }
    path
}

/*
set_x_real_ip = function(event)
    if event.log.remote_addr and (
        not event.log.x_real_ip
        or not event.log.x_real_ip:find("^%d%d?%d?%.%d%d?%d?%.%d%d?%d?%.%d%d?%d?$") -- не IP-адрес
    ) then
        event.log.x_real_ip = event.log.remote_addr
    end
end
*/
fn set_x_real_ip(log: &mut LogEvent) {
    if let Some(remote_addr) = log.get("remote_addr") {
        let need_set = if let Some(x_real_ip) = log.get("x_real_ip") {
            if let Err(_) = Ipv4Addr::from_str(&x_real_ip.to_string_lossy()) { true } else { false }
        } else { true };

        if need_set {
            let remote_addr = remote_addr.to_string_lossy();
            log.insert("x_real_ip", remote_addr);
        }
    }
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
