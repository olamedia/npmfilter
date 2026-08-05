//! Unit tests for the pure parts of the request path: Accept negotiation, abbreviated
//! re-serialization, the `_npmfilter` summary, upstream path encoding and the TTL cache.
//!
//! The wired-up daemon is covered by `tests/proxy.rs`, which runs `serve` against a local
//! stub upstream. Nothing here touches the network.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{TimeZone, Utc};
use serde_json::{Value, json};

use super::*;
use axum::http::Method;

use crate::policy::{BlockReason, BlockRecord, PolicyConfig};

fn full_packument() -> Value {
    json!({
        "_id": "widget",
        "_rev": "42-abc",
        "name": "widget",
        "description": "a widget",
        "readme": "# widget\n",
        "maintainers": [{ "name": "someone", "email": "someone@example.test" }],
        "dist-tags": { "latest": "1.0.0" },
        "time": {
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2026-06-01T00:00:00.000Z",
            "1.0.0": "2020-01-01T00:00:00.000Z",
            "1.1.0": "2026-06-01T00:00:00.000Z"
        },
        "versions": {
            "1.0.0": {
                "_id": "widget@1.0.0",
                "_nodeVersion": "20.11.0",
                "_npmUser": { "name": "someone" },
                "name": "widget",
                "version": "1.0.0",
                "description": "a widget",
                "gitHead": "deadbeef",
                "maintainers": [{ "name": "someone" }],
                "readme": "# widget\n",
                "scripts": { "test": "mocha" },
                "dependencies": { "left-pad": "^1.0.0" },
                "devDependencies": { "mocha": "^10.0.0" },
                "engines": { "node": ">=18" },
                "os": ["linux"],
                "cpu": ["x64"],
                "bin": { "widget": "cli.js" },
                "funding": { "url": "https://example.test/fund" },
                "peerDependencies": { "react": "^18" },
                "peerDependenciesMeta": { "react": { "optional": true } },
                "deprecated": "use widget2",
                "dist": {
                    "integrity": "sha512-AAA==",
                    "shasum": "abc",
                    "tarball": "https://registry.npmjs.org/widget/-/widget-1.0.0.tgz",
                    "fileCount": 3,
                    "unpackedSize": 1234
                }
            },
            "1.1.0": {
                "name": "widget",
                "version": "1.1.0",
                "scripts": { "preinstall": "node setup.mjs", "test": "mocha" },
                "dist": {
                    "integrity": "sha512-BBB==",
                    "tarball": "https://registry.npmjs.org/widget/-/widget-1.1.0.tgz"
                }
            }
        }
    })
}

#[test]
fn npms_own_accept_header_asks_for_the_abbreviated_shape() {
    // Exactly what `npm install` sends.
    assert!(wants_abbreviated(Some(
        "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"
    )));
    assert!(wants_abbreviated(Some(
        "application/vnd.npm.install-v1+json"
    )));
    assert!(wants_abbreviated(Some(
        "APPLICATION/VND.NPM.INSTALL-V1+JSON"
    )));
}

#[test]
fn a_plain_json_accept_asks_for_the_full_shape() {
    assert!(!wants_abbreviated(Some("application/json")));
    assert!(!wants_abbreviated(Some("*/*")));
    assert!(!wants_abbreviated(Some("")));
    assert!(!wants_abbreviated(None));
}

#[test]
fn the_abbreviated_root_carries_exactly_npms_four_keys() {
    let abbreviated = abbreviate(&full_packument());
    let root = abbreviated.as_object().expect("object");
    let mut keys: Vec<&str> = root.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ABBREVIATED_ROOT_KEYS.to_vec());
    assert_eq!(root["modified"], json!("2026-06-01T00:00:00.000Z"));
    assert_eq!(root["name"], json!("widget"));
    assert_eq!(root["dist-tags"], json!({ "latest": "1.0.0" }));
}

#[test]
fn the_abbreviated_version_keeps_npms_fields_and_drops_the_rest() {
    let abbreviated = abbreviate(&full_packument());
    let meta = &abbreviated["versions"]["1.0.0"];
    let object = meta.as_object().expect("object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "bin",
            "cpu",
            "dependencies",
            "deprecated",
            "devDependencies",
            "dist",
            "engines",
            "funding",
            "name",
            "os",
            "peerDependencies",
            "peerDependenciesMeta",
            "version",
        ]
    );
    for dropped in [
        "scripts",
        "_id",
        "_nodeVersion",
        "_npmUser",
        "maintainers",
        "readme",
        "gitHead",
        "description",
    ] {
        assert!(object.get(dropped).is_none(), "{dropped} must be dropped");
    }
    // Every abbreviated key is one npm itself emits.
    for key in object.keys() {
        assert!(
            ABBREVIATED_VERSION_KEYS.contains(&key.as_str()),
            "{key} is not part of npm's abbreviated format"
        );
    }
}

#[test]
fn the_tarball_url_survives_re_serialization_untouched() {
    let full = full_packument();
    let abbreviated = abbreviate(&full);
    assert_eq!(
        abbreviated["versions"]["1.0.0"]["dist"], full["versions"]["1.0.0"]["dist"],
        "dist is copied verbatim, tarball included"
    );
    assert_eq!(
        abbreviated["versions"]["1.0.0"]["dist"]["tarball"],
        json!("https://registry.npmjs.org/widget/-/widget-1.0.0.tgz")
    );
}

#[test]
fn has_install_script_is_set_from_the_full_documents_scripts() {
    let full = full_packument();
    assert!(!has_install_script(&full["versions"]["1.0.0"]));
    assert!(has_install_script(&full["versions"]["1.1.0"]));

    let abbreviated = abbreviate(&full);
    assert!(
        abbreviated["versions"]["1.0.0"]
            .get("hasInstallScript")
            .is_none()
    );
    assert_eq!(
        abbreviated["versions"]["1.1.0"]["hasInstallScript"],
        json!(true)
    );
}

#[test]
fn an_upstream_has_install_script_flag_is_believed() {
    let meta = json!({ "name": "x", "version": "1.0.0", "hasInstallScript": true });
    assert!(has_install_script(&meta));
    assert_eq!(
        abbreviate_version(&meta)["hasInstallScript"],
        json!(true),
        "the flag survives even without a scripts object"
    );
}

#[test]
fn empty_fields_are_dropped_exactly_as_the_registry_drops_them() {
    // Checked against 3,836 abbreviated version objects fetched from registry.npmjs.org:
    // not one carried an empty object, empty array, empty string, null, or
    // `_hasShrinkwrap: false`.
    let meta = json!({
        "name": "lodash",
        "version": "0.1.0",
        "dependencies": {},
        "devDependencies": {},
        "optionalDependencies": {},
        "directories": {},
        "os": [],
        "deprecated": "",
        "bin": null,
        "_hasShrinkwrap": false,
        "dist": { "tarball": "https://registry.npmjs.org/lodash/-/lodash-0.1.0.tgz" }
    });
    let abbreviated = abbreviate_version(&meta);
    let object = abbreviated.as_object().expect("object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["dist", "name", "version"]);

    // A `_hasShrinkwrap: true` or a non-empty list is real information and survives.
    let meta = json!({
        "name": "lodash",
        "version": "0.1.0",
        "_hasShrinkwrap": true,
        "os": ["linux"],
        "deprecated": "use lodash-es"
    });
    let abbreviated = abbreviate_version(&meta);
    assert_eq!(abbreviated["_hasShrinkwrap"], json!(true));
    assert_eq!(abbreviated["os"], json!(["linux"]));
    assert_eq!(abbreviated["deprecated"], json!("use lodash-es"));
}

#[test]
fn the_abbreviated_shape_never_carries_the_summary_or_time() {
    let filtered = with_summary(
        full_packument(),
        &[block("1.1.0", BlockReason::InstallScript)],
        &PolicyConfig::default(),
        Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap(),
    );
    let abbreviated = abbreviate(&filtered);
    assert!(abbreviated.get(SUMMARY_KEY).is_none());
    assert!(abbreviated.get("time").is_none());
}

fn block(version: &str, reason: BlockReason) -> BlockRecord {
    BlockRecord::new(version, reason, format!("withheld: {reason}"))
}

#[test]
fn the_summary_lists_what_was_withheld_and_why() {
    let generated = Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap();
    let blocked = vec![
        block("1.1.0", BlockReason::InstallScript),
        block("2.0.0", BlockReason::TooNew),
    ];
    let config = PolicyConfig {
        min_age_days: 30,
        bypass_scopes: vec!["@olamedia".to_owned()],
        allow_dist_tag_downgrade: false,
    };
    let document = with_summary(full_packument(), &blocked, &config, generated);
    let summary = &document[SUMMARY_KEY];

    assert_eq!(summary["daemon"], json!("npmfilter"));
    assert_eq!(summary["version"], json!(env!("CARGO_PKG_VERSION")));
    assert_eq!(summary["withheld_count"], json!(2));
    assert_eq!(summary["policy"]["min_age_days"], json!(30));
    assert_eq!(summary["policy"]["bypass_scopes"], json!(["@olamedia"]));
    assert_eq!(summary["withheld"][0]["version"], json!("1.1.0"));
    assert_eq!(summary["withheld"][0]["reason"], json!("install_script"));
    assert_eq!(summary["withheld"][1]["reason"], json!("too_new"));
    // The rest of the document is untouched.
    assert_eq!(document["name"], json!("widget"));
    assert_eq!(
        document["versions"]["1.0.0"]["scripts"],
        json!({"test":"mocha"})
    );
}

#[test]
fn an_unfiltered_packument_still_states_that_nothing_was_withheld() {
    let document = with_summary(
        full_packument(),
        &[],
        &PolicyConfig::default(),
        Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap(),
    );
    assert_eq!(document[SUMMARY_KEY]["withheld_count"], json!(0));
    assert_eq!(document[SUMMARY_KEY]["withheld"], json!([]));
}

#[test]
fn a_non_object_document_is_left_alone() {
    let value = json!(["not", "a", "packument"]);
    assert_eq!(abbreviate(&value), value);
    assert_eq!(
        with_summary(
            value.clone(),
            &[],
            &PolicyConfig::default(),
            Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0).unwrap()
        ),
        value
    );
}

#[test]
fn scoped_names_are_encoded_as_a_single_upstream_segment() {
    assert_eq!(encode_package_path("lodash"), "lodash");
    assert_eq!(encode_package_path("@babel/core"), "@babel%2Fcore");
    assert_eq!(encode_package_path("is-odd.js"), "is-odd.js");
    assert_eq!(encode_package_path("a_b~c-d.e"), "a_b~c-d.e");
}

#[test]
fn a_traversal_attempt_cannot_escape_its_path_segment() {
    assert_eq!(
        encode_package_path("../../etc/passwd"),
        "..%2F..%2Fetc%2Fpasswd"
    );
    assert_eq!(encode_package_path("a b"), "a%20b");
    assert_eq!(encode_package_path("a?b#c"), "a%3Fb%23c");
    assert_eq!(encode_package_path("a\nb"), "a%0Ab");
}

#[test]
fn the_upstream_url_is_the_base_plus_the_encoded_name() {
    let upstream = Upstream::new("https://registry.npmjs.org/").expect("client builds");
    assert_eq!(upstream.base(), "https://registry.npmjs.org");
    assert_eq!(
        upstream.packument_url("@babel/core"),
        "https://registry.npmjs.org/@babel%2Fcore"
    );
    assert_eq!(
        upstream.packument_url("lodash"),
        "https://registry.npmjs.org/lodash"
    );
}

fn document() -> Arc<Value> {
    Arc::new(json!({ "name": "widget" }))
}

#[test]
fn a_cached_packument_is_returned_until_the_ttl_elapses() {
    let cache = PackumentCache::from_secs(60);
    let key = CacheKey::new("widget", None);
    let stored = Instant::now();

    cache.insert_at(key.clone(), document(), stored);
    assert!(cache.get_at(&key, stored).is_some());
    assert!(
        cache
            .get_at(&key, stored + Duration::from_secs(59))
            .is_some()
    );
    assert!(
        cache
            .get_at(&key, stored + Duration::from_secs(60))
            .is_none(),
        "an entry is stale the instant its TTL is reached"
    );
}

#[test]
fn a_zero_ttl_disables_the_cache_entirely() {
    let cache = PackumentCache::from_secs(0);
    let key = CacheKey::new("widget", None);
    cache.insert(key.clone(), document());
    assert!(cache.get(&key).is_none());
    assert!(cache.is_empty(), "nothing is even stored");
}

#[test]
fn packuments_fetched_with_one_credential_are_not_served_to_another() {
    let cache = PackumentCache::from_secs(60);
    let mine = CacheKey::new("widget", Some(b"Bearer mine"));
    let yours = CacheKey::new("widget", Some(b"Bearer yours"));
    let anonymous = CacheKey::new("widget", None);

    cache.insert(mine.clone(), document());
    assert!(cache.get(&mine).is_some());
    assert!(cache.get(&yours).is_none());
    assert!(cache.get(&anonymous).is_none());
    assert_eq!(cache.len(), 1);
}

#[test]
fn the_credential_is_fingerprinted_never_stored() {
    let key = CacheKey::new("widget", Some(b"Bearer npm_supersecret"));
    let fingerprint = key.credential().expect("a credential was supplied");
    assert_eq!(fingerprint.len(), 64, "sha-256, lowercase hex");
    assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!fingerprint.contains("supersecret"));
    assert_eq!(key.package(), "widget");
    assert_eq!(CacheKey::new("widget", None).credential(), None);
}

#[test]
fn a_cleared_cache_forgets_everything() {
    let cache = PackumentCache::from_secs(60);
    cache.insert(CacheKey::new("a", None), document());
    cache.insert(CacheKey::new("b", None), document());
    assert_eq!(cache.len(), 2);
    cache.clear();
    assert!(cache.is_empty());
    assert_eq!(cache.ttl(), Duration::from_secs(60));
}

#[test]
fn the_reason_summary_counts_each_gate() {
    let blocked = vec![
        block("1.0.0", BlockReason::TooNew),
        block("1.1.0", BlockReason::InstallScript),
        block("1.2.0", BlockReason::TooNew),
    ];
    assert_eq!(summarize(&blocked), "install_script=1 too_new=2");
    assert_eq!(summarize(&[]), "");
}

#[test]
fn every_error_answers_with_a_status_and_a_code() {
    let error = ProxyError::Policy(crate::policy::PolicyError::MissingVersions);
    assert_eq!(error.status(), axum::http::StatusCode::BAD_GATEWAY);
    assert_eq!(error.code(), "malformed_packument");
    assert!(error.chain().contains("malformed"), "{}", error.chain());

    let error = ProxyError::Serialize(serde_json::from_str::<Value>("{").unwrap_err());
    assert_eq!(
        error.status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(error.code(), "serialization_failed");

    let error = ProxyError::StoreUnavailable {
        detail: "database disk image is malformed".to_owned(),
    };
    assert_eq!(error.status(), axum::http::StatusCode::BAD_GATEWAY);
    assert_eq!(error.code(), "store_unavailable");
    assert!(error.chain().contains("malformed"), "{}", error.chain());

    let error = ProxyError::PackumentTooLarge {
        package: "aws-sdk".to_owned(),
        limit: MAX_PACKUMENT_BYTES,
    };
    assert_eq!(error.status(), axum::http::StatusCode::BAD_GATEWAY);
    assert_eq!(error.code(), "packument_too_large");
}

// -- path classification -----------------------------------------------------------------

/// A trailing or duplicated slash used to miss both package routes and be served by the
/// verbatim proxy — every withheld version, unfiltered and unaudited.
#[test]
fn a_trailing_or_duplicated_slash_still_resolves_to_the_packument() {
    for path in [
        "/widget",
        "/widget/",
        "//widget",
        "///widget//",
        "/widget//",
    ] {
        assert_eq!(
            classify(path),
            Route::Packument("widget".to_owned()),
            "GET {path}"
        );
    }
    for path in [
        "/@babel/core",
        "/@babel/core/",
        "//@babel//core",
        "/@babel%2Fcore",
        "/@babel%2fcore/",
    ] {
        assert_eq!(
            classify(path),
            Route::Packument("@babel/core".to_owned()),
            "GET {path}"
        );
    }
}

#[test]
fn the_single_version_endpoint_is_classified_in_both_scoped_forms() {
    assert_eq!(
        classify("/lodash/4.99.0"),
        Route::Version {
            package: "lodash".to_owned(),
            spec: "4.99.0".to_owned()
        }
    );
    assert_eq!(
        classify("/@babel/core/7.0.0/"),
        Route::Version {
            package: "@babel/core".to_owned(),
            spec: "7.0.0".to_owned()
        }
    );
    assert_eq!(
        classify("/@babel%2Fcore/latest"),
        Route::Version {
            package: "@babel/core".to_owned(),
            spec: "latest".to_owned()
        }
    );
    assert_eq!(
        classify("/-/package/lodash/dist-tags"),
        Route::DistTags("lodash".to_owned())
    );
    assert_eq!(
        classify("/-/package/@babel%2Fcore/dist-tags"),
        Route::DistTags("@babel/core".to_owned())
    );
}

#[test]
fn the_registry_service_endpoints_are_never_mistaken_for_packages() {
    for path in [
        "/-/v1/search",
        "/-/npm/v1/security/advisories/bulk",
        "/-/whoami",
        "/-/ping",
        "/-/user/org.couchdb.user:me",
        "/widget/-/widget-1.0.0.tgz",
        "/@babel/core/-/core-7.0.0.tgz",
        "/",
        "//",
    ] {
        assert_eq!(classify(path), Route::Passthrough, "GET {path}");
    }

    // A name that merely starts with `-` is still a package, not the reserved namespace.
    assert_eq!(
        classify("/-dash-lead"),
        Route::Packument("-dash-lead".to_owned())
    );
}

/// A dot segment used to classify as `Passthrough` and be relayed verbatim — and `reqwest`'s
/// URL parser then normalised it away, so upstream answered the packument for the real package
/// and the client got it unfiltered: every withheld version, no ledger observation, no audit
/// row. Both readings of the path have to agree or npmfilter must not forward it.
#[test]
fn a_dot_segment_is_refused_rather_than_left_to_a_url_parser() {
    for path in [
        "/./is-odd",
        "/foo/../is-odd",
        "/_x/../is-odd",
        "/%2e/is-odd",
        "/%2E%2E/is-odd",
        "/-/../is-odd",
        "/../etc/passwd",
        "/./widget",
        "/@babel/core/../../is-odd",
        "/is-odd/.",
        "/is-odd/1.0.0/..",
    ] {
        assert_eq!(classify(path), Route::Invalid, "{path}");
    }

    // A name that merely *contains* a dot is an ordinary package: `is-odd.js` is real.
    assert_eq!(
        classify("/is-odd.js"),
        Route::Packument("is-odd.js".to_owned())
    );
    assert_eq!(
        classify("/@types/node.js"),
        Route::Packument("@types/node.js".to_owned())
    );
}

/// The method policy is an allow-list. It was a deny-list, and every verb nobody had thought
/// of — `COPY`, `PROPFIND`, `FROB` — fell past both the mutation gate and the package filter
/// straight into the verbatim proxy, carrying the client's `Authorization` header.
#[test]
fn only_get_head_and_the_read_only_posts_are_reads() {
    let package = Route::Packument("lodash".to_owned());
    let version = Route::Version {
        package: "lodash".to_owned(),
        spec: "4.17.21".to_owned(),
    };

    for route in [&package, &version, &Route::Passthrough] {
        assert!(!is_mutating(&Method::GET, route));
        assert!(!is_mutating(&Method::HEAD, route));
        assert!(is_mutating(&Method::PUT, route));
        assert!(is_mutating(&Method::DELETE, route));
        assert!(is_mutating(&Method::PATCH, route));
        for verb in ["COPY", "PROPFIND", "OPTIONS", "TRACE", "FROB", "MKCOL"] {
            let method = Method::from_bytes(verb.as_bytes()).expect("a valid method token");
            assert!(
                is_mutating(&method, route),
                "{verb} must never be relayed verbatim"
            );
        }
    }

    // POST is the one method whose verdict depends on where it is aimed: the registry's own
    // read-only endpoints live under `/-/`, which never classifies as a package.
    assert!(is_mutating(&Method::POST, &package));
    assert!(is_mutating(&Method::POST, &version));
    assert!(!is_mutating(&Method::POST, &Route::Passthrough));
}

// -- cache bounds ------------------------------------------------------------------------

/// Expiry alone never bounds the cache: a working set larger than the cap inside one TTL
/// window would grow it without limit, holding full upstream packuments.
#[test]
fn the_cache_evicts_oldest_first_once_it_is_full() {
    let cache = PackumentCache::with_capacity(Duration::from_secs(60), 8);
    let start = Instant::now();

    for index in 0..64u32 {
        cache.insert_at(
            CacheKey::new(format!("package-{index}"), None),
            document(),
            start + Duration::from_millis(u64::from(index)),
        );
        assert!(
            cache.len() <= 8,
            "the cache grew past its cap at insert {index}: {}",
            cache.len()
        );
    }

    let now = start + Duration::from_millis(63);
    assert_eq!(cache.len(), 8);
    assert!(
        cache
            .get_at(&CacheKey::new("package-63", None), now)
            .is_some(),
        "the newest entry survives"
    );
    assert!(
        cache
            .get_at(&CacheKey::new("package-0", None), now)
            .is_none(),
        "the oldest entry was evicted even though it had not expired"
    );
}

/// The entry cap bounds nothing that matters on its own: a packument may be
/// `MAX_PACKUMENT_BYTES` on the wire, so 1024 of them is tens of gigabytes. 1024 distinct
/// package names from one unprivileged local process was an OOM.
#[test]
fn the_cache_is_bounded_by_bytes_as_well_as_by_entries() {
    let big = Arc::new(json!({ "name": "widget", "blob": "x".repeat(4096) }));
    let budget = 20 * 1024;
    let cache = PackumentCache::with_limits(Duration::from_secs(60), 1024, budget);
    let start = Instant::now();

    for index in 0..64u32 {
        cache.insert_at(
            CacheKey::new(format!("package-{index}"), None),
            Arc::clone(&big),
            start + Duration::from_millis(u64::from(index)),
        );
        assert!(
            cache.bytes() <= budget,
            "the cache went over its byte budget at insert {index}: {} > {budget}",
            cache.bytes()
        );
    }
    assert!(
        cache.len() < 64,
        "entries were evicted to stay inside the budget, {} held",
        cache.len()
    );
    assert_eq!(cache.max_bytes(), budget);

    // The credential fingerprint is part of the key, so the same package under many different
    // Authorization headers is many entries — and is bounded by the same budget.
    let cache = PackumentCache::with_limits(Duration::from_secs(60), 1024, budget);
    for index in 0..64u32 {
        cache.insert_at(
            CacheKey::new("widget", Some(format!("Bearer {index}").as_bytes())),
            Arc::clone(&big),
            start + Duration::from_millis(u64::from(index)),
        );
        assert!(cache.bytes() <= budget, "insert {index}");
    }

    // Dropping everything zeroes the accounting rather than leaking it.
    cache.clear();
    assert_eq!(cache.bytes(), 0);
    assert!(cache.is_empty());
}

#[test]
fn a_document_larger_than_the_whole_budget_is_served_but_never_held() {
    let cache = PackumentCache::with_limits(Duration::from_secs(60), 1024, 1024);
    let key = CacheKey::new("aws-sdk", None);
    cache.insert(key.clone(), Arc::new(json!({ "blob": "x".repeat(8192) })));
    assert!(cache.get(&key).is_none(), "it must not be retained");
    assert_eq!(cache.bytes(), 0);
    assert!(cache.is_empty());
}

#[test]
fn replacing_an_entry_frees_what_it_held() {
    let cache = PackumentCache::with_limits(Duration::from_secs(60), 8, 1024 * 1024);
    let key = CacheKey::new("widget", None);
    let start = Instant::now();
    cache.insert_at(
        key.clone(),
        Arc::new(json!({ "blob": "x".repeat(2048) })),
        start,
    );
    let big = cache.bytes();
    cache.insert_at(
        key.clone(),
        Arc::new(json!({ "blob": "x" })),
        start + Duration::from_millis(1),
    );
    assert_eq!(cache.len(), 1);
    assert!(
        cache.bytes() < big,
        "replacing a large document with a small one must free the difference: {} vs {big}",
        cache.bytes()
    );
}

#[test]
fn replacing_an_entry_in_a_full_cache_evicts_nothing() {
    let cache = PackumentCache::with_capacity(Duration::from_secs(60), 2);
    let start = Instant::now();
    let first = CacheKey::new("a", None);
    cache.insert_at(first.clone(), document(), start);
    cache.insert_at(CacheKey::new("b", None), document(), start);
    cache.insert_at(first.clone(), document(), start + Duration::from_millis(1));

    assert_eq!(cache.len(), 2);
    assert!(
        cache
            .get_at(&CacheKey::new("b", None), start + Duration::from_millis(1))
            .is_some()
    );
}

// -- reporting a withheld dist-tag --------------------------------------------------------

/// A withheld `latest` is the case a client cannot diagnose alone: it asked for the tag,
/// resolution failed, and its own error says only that no version matched. The summary must
/// name the tag and the tools that resolve it, and must not have moved the tag.
#[test]
fn a_withheld_dist_tag_is_named_with_an_action_in_the_summary() {
    let generated = Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 0).unwrap();
    let blocked = vec![block("2.0.0", BlockReason::InstallScript)];
    let config = PolicyConfig::default();

    // The filtered document: 2.0.0 withheld, but `latest` still names it.
    let filtered = json!({
        "name": "widget",
        "dist-tags": { "latest": "2.0.0" },
        "versions": { "1.0.0": { "name": "widget", "version": "1.0.0" } },
    });

    let tags = shape::withheld_dist_tags(&filtered, &blocked);
    assert_eq!(tags.len(), 1, "the withheld tag must be detected");
    assert_eq!(tags[0].tag, "latest");
    assert_eq!(tags[0].version, "2.0.0");
    assert_eq!(tags[0].reason, BlockReason::InstallScript);

    let document = with_summary(filtered, &blocked, &config, generated);
    let summary = &document[SUMMARY_KEY];

    assert_eq!(
        document["dist-tags"]["latest"],
        json!("2.0.0"),
        "the tag must NOT have been moved onto an older release"
    );
    assert_eq!(summary["withheld_dist_tags"][0]["tag"], json!("latest"));
    let action = summary["action_required"]
        .as_str()
        .expect("an action must be stated when a tag is withheld");
    assert!(
        action.contains("npmfilter_allow") && action.contains("npmfilter_inspect"),
        "the action must name the tools that resolve it: {action}"
    );
    assert!(
        action.contains("RESOLUTION WILL FAIL"),
        "the action must say resolution fails rather than leaving it implicit: {action}"
    );
}

/// Nothing withheld means nothing to report — no action, no tag list.
#[test]
fn a_clean_packument_carries_no_action() {
    let generated = Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 0).unwrap();
    let document = with_summary(full_packument(), &[], &PolicyConfig::default(), generated);
    let summary = &document[SUMMARY_KEY];

    assert_eq!(summary["withheld_count"], json!(0));
    assert!(summary.get("action_required").is_none());
    assert!(summary.get("withheld_dist_tags").is_none());
}
