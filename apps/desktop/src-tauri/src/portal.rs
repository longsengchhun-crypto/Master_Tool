//! Client for the SENTRIX console (device enrollment, policy, license, closed-set jobs).
//!
//! Principles enforced here:
//!  * The user explicitly enrolls with a one-time code; they can leave at any time, even offline.
//!  * The device credential is stored protected by DPAPI and only ever sent as a bearer token over HTTPS
//!    (plain http only for localhost development).
//!  * Only metadata is ever sent: engine status, counts, and per-finding hash + verdict. Never file contents.
//!    File names are sent only if the organization's policy allows it AND the user has telemetry switched on.
//!  * Remote requests are a fixed set of kinds that the app maps to local, user-visible actions. There is no
//!    command channel.

use chrono::{DateTime, Utc};
use sentrix_core::secret;
use sentrix_core::{ScanReport, Verdict};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseInfo {
    pub state: String,
    pub plan: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateOffer {
    pub version: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    portal_url: String,
    device_id: String,
    org_name: String,
    /// base64(DPAPI(token))
    token_protected: String,
    enrolled_at: DateTime<Utc>,
    last_sync_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    license: Option<LicenseInfo>,
    policy: Option<Value>,
    update: Option<UpdateOffer>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountStatus {
    pub enrolled: bool,
    pub portal_url: Option<String>,
    pub org_name: Option<String>,
    pub device_id: Option<String>,
    pub enrolled_at: Option<DateTime<Utc>>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub license: Option<LicenseInfo>,
    pub policy: Option<Value>,
    pub update: Option<UpdateOffer>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub id: String,
    pub kind: String,
}

#[derive(Debug, Clone)]
pub struct SyncData {
    pub policy: Value,
    pub jobs: Vec<Job>,
}

pub struct Portal {
    path: PathBuf,
    stored: Mutex<Option<Stored>>,
    token: Mutex<Option<String>>,
}

/// https only; plain http solely for loopback development. Rejects credentials in the URL and anything odd.
pub fn validate_portal_url(raw: &str) -> Result<String, String> {
    let s = raw.trim().trim_end_matches('/').to_string();
    if s.len() > 200 || s.contains('@') || s.contains(char::is_whitespace) || s.contains('?') || s.contains('#') {
        return Err("That console address is not valid.".into());
    }
    let ok = s.starts_with("https://") && s.len() > "https://".len()
        || ["http://localhost", "http://127.0.0.1"].iter().any(|p| s == *p || s.starts_with(&format!("{p}:")) || s.starts_with(&format!("{p}/")));
    if !ok {
        return Err("The console address must start with https://".into());
    }
    Ok(s)
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(25))).build().into()
}

fn msg(v: &Value, fallback: &str) -> String {
    v["error"]["message"].as_str().unwrap_or(fallback).to_string()
}

impl Portal {
    pub fn open(dir: &Path) -> Portal {
        let path = dir.join("enrollment.json");
        let stored: Option<Stored> = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok());
        let token = stored.as_ref().and_then(|s| {
            use base64::Engine;
            let blob = base64::engine::general_purpose::STANDARD.decode(&s.token_protected).ok()?;
            String::from_utf8(secret::unprotect(&blob).ok()?).ok()
        });
        // A credential that cannot be decrypted (different Windows user, corrupted file) is treated as not enrolled.
        let stored = if token.is_some() { stored } else { None };
        Portal { path, stored: Mutex::new(stored), token: Mutex::new(token) }
    }

    fn save(&self) {
        let g = self.stored.lock().unwrap();
        match g.as_ref() {
            Some(s) => {
                let tmp = self.path.with_extension("tmp");
                if std::fs::write(&tmp, serde_json::to_vec_pretty(s).unwrap()).is_ok() {
                    let _ = std::fs::rename(&tmp, &self.path);
                }
            }
            None => {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    pub fn is_enrolled(&self) -> bool {
        self.stored.lock().unwrap().is_some()
    }

    pub fn status(&self) -> AccountStatus {
        match self.stored.lock().unwrap().as_ref() {
            Some(s) => AccountStatus {
                enrolled: true,
                portal_url: Some(s.portal_url.clone()),
                org_name: Some(s.org_name.clone()),
                device_id: Some(s.device_id.clone()),
                enrolled_at: Some(s.enrolled_at),
                last_sync_at: s.last_sync_at,
                last_error: s.last_error.clone(),
                license: s.license.clone(),
                policy: s.policy.clone(),
                update: s.update.clone(),
            },
            None => AccountStatus { enrolled: false, portal_url: None, org_name: None, device_id: None, enrolled_at: None, last_sync_at: None, last_error: None, license: None, policy: None, update: None },
        }
    }

    pub fn org_name(&self) -> Option<String> {
        self.stored.lock().unwrap().as_ref().map(|s| s.org_name.clone())
    }

    pub fn allow_file_names(&self) -> bool {
        self.stored.lock().unwrap().as_ref().and_then(|s| s.policy.as_ref()).and_then(|p| p["allowFileNameTelemetry"].as_bool()).unwrap_or(false)
    }

    /// Exchange a one-time enrollment code for a device credential. Returns the policy to apply.
    pub fn enroll(&self, portal_url: &str, code: &str, hostname: &str, os_version: Option<&str>, app_version: &str) -> Result<Value, String> {
        if self.is_enrolled() {
            return Err("This device is already enrolled. Leave the current organization first.".into());
        }
        let base = validate_portal_url(portal_url)?;
        let body = json!({ "code": code.trim().to_uppercase(), "hostname": hostname, "os": "windows", "osVersion": os_version, "appVersion": app_version });
        let mut resp = agent().post(&format!("{base}/api/device/enroll")).send_json(&body).map_err(|e| format!("Could not reach the console: {e}"))?;
        let status = resp.status().as_u16();
        let v: Value = resp.body_mut().read_json().unwrap_or(Value::Null);
        if status != 200 {
            return Err(msg(&v, "Enrollment was refused."));
        }
        let token = v["token"].as_str().ok_or("The console returned an unexpected response.")?.to_string();
        let device_id = v["deviceId"].as_str().ok_or("The console returned an unexpected response.")?.to_string();
        let protected = secret::protect(token.as_bytes()).map_err(|e| e.to_string())?;
        use base64::Engine;
        let stored = Stored {
            portal_url: base,
            device_id,
            org_name: v["org"]["name"].as_str().unwrap_or("your organization").to_string(),
            token_protected: base64::engine::general_purpose::STANDARD.encode(protected),
            enrolled_at: Utc::now(),
            last_sync_at: Some(Utc::now()),
            last_error: None,
            license: serde_json::from_value(json!({ "state": "valid", "plan": v["license"]["plan"], "expiresAt": v["license"]["expiresAt"] })).ok(),
            policy: Some(v["policy"].clone()),
            update: None,
        };
        *self.token.lock().unwrap() = Some(token);
        *self.stored.lock().unwrap() = Some(stored);
        self.save();
        Ok(v["policy"].clone())
    }

    /// Leave management. Always succeeds locally; the console is told on a best-effort basis so the seat is freed.
    pub fn unenroll(&self) -> bool {
        let notified = self.authed_post("/api/device/unenroll", &json!({})).map(|(s, _)| s == 200).unwrap_or(false);
        *self.stored.lock().unwrap() = None;
        *self.token.lock().unwrap() = None;
        self.save();
        notified
    }

    fn authed_post(&self, path: &str, body: &Value) -> Result<(u16, Value), String> {
        let (base, token) = {
            let s = self.stored.lock().unwrap();
            let t = self.token.lock().unwrap();
            match (s.as_ref(), t.as_ref()) {
                (Some(s), Some(t)) => (s.portal_url.clone(), t.clone()),
                _ => return Err("This device is not enrolled.".into()),
            }
        };
        let mut resp = agent().post(&format!("{base}{path}")).header("Authorization", &format!("Bearer {token}")).send_json(body).map_err(|e| format!("Could not reach the console: {e}"))?;
        let status = resp.status().as_u16();
        let v: Value = resp.body_mut().read_json().unwrap_or(Value::Null);
        Ok((status, v))
    }

    fn note_error(&self, e: &str) {
        if let Some(s) = self.stored.lock().unwrap().as_mut() {
            s.last_error = Some(e.to_string());
        }
        self.save();
    }

    /// Check in. A 401 means the console revoked this device: we drop the credential and say so.
    pub fn heartbeat(&self, payload: &Value) -> Result<SyncData, String> {
        let (status, v) = match self.authed_post("/api/device/heartbeat", payload) {
            Ok(x) => x,
            Err(e) => {
                self.note_error(&e);
                return Err(e);
            }
        };
        if status == 401 {
            *self.stored.lock().unwrap() = None;
            *self.token.lock().unwrap() = None;
            self.save();
            return Err("Your organization removed this device from management.".into());
        }
        if status != 200 {
            let e = msg(&v, "The console rejected the check-in.");
            self.note_error(&e);
            return Err(e);
        }
        if let Some(s) = self.stored.lock().unwrap().as_mut() {
            s.last_sync_at = Some(Utc::now());
            s.last_error = None;
            s.license = serde_json::from_value(v["license"].clone()).ok();
            s.policy = Some(v["policy"].clone());
            s.update = serde_json::from_value(v["update"].clone()).ok();
        }
        self.save();
        let jobs: Vec<Job> = serde_json::from_value(v["jobs"].clone()).unwrap_or_default();
        Ok(SyncData { policy: v["policy"].clone(), jobs })
    }

    pub fn job_result(&self, id: &str, ok: bool, result: &str) {
        let _ = self.authed_post(&format!("/api/device/jobs/{id}/result"), &json!({ "state": if ok { "succeeded" } else { "failed" }, "result": result.chars().take(400).collect::<String>() }));
    }

    pub fn event(&self, kind: &str, severity: &str, detail: &str) {
        let _ = self.authed_post("/api/device/events", &json!({ "events": [{ "kind": kind, "severity": severity, "detail": detail.chars().take(400).collect::<String>() }] }));
    }

    /// Report scan results as metadata only. Clean files are never listed individually.
    pub fn report_scan(&self, kind: &str, started: DateTime<Utc>, total: usize, unreadable: usize, complete: bool, reports: &[ScanReport]) {
        let names = self.allow_file_names();
        let findings: Vec<Value> = reports
            .iter()
            .filter(|r| !r.file.sha256.is_empty() && r.verdict != Verdict::Clean)
            .take(500)
            .map(|r| {
                let src = r.findings.iter().find(|f| f.kind == sentrix_core::FindingKind::Signature).or_else(|| r.findings.first()).map(|f| f.source.clone()).unwrap_or_else(|| "scanner".into());
                let mut f = json!({ "sha256": r.file.sha256, "verdict": serde_json::to_value(r.verdict).unwrap(), "source": src.chars().take(100).collect::<String>(), "detail": r.verdict.label() });
                if names {
                    f["fileName"] = json!(r.file.name.chars().take(260).collect::<String>());
                }
                f
            })
            .collect();
        let body = json!({ "kind": kind, "startedAt": started.to_rfc3339(), "finishedAt": Utc::now().to_rfc3339(), "filesTotal": total, "filesFailed": unreadable, "complete": complete, "findings": findings });
        let _ = self.authed_post("/api/device/scans", &body);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_loopback_urls_are_accepted() {
        assert_eq!(validate_portal_url("https://console.example.com/").unwrap(), "https://console.example.com");
        assert!(validate_portal_url("http://console.example.com").is_err());
        assert!(validate_portal_url("ftp://x").is_err());
        assert!(validate_portal_url("https://user:pw@evil.example").is_err());
        assert!(validate_portal_url("https://").is_err());
        assert!(validate_portal_url("https://a.example/path?x=1").is_err());
        assert!(validate_portal_url("javascript:alert(1)").is_err());
        assert!(validate_portal_url("http://localhost:3100").is_ok());
        assert!(validate_portal_url("http://127.0.0.1:3199").is_ok());
        assert!(validate_portal_url("http://localhost.evil.example").is_err());
        assert!(validate_portal_url("http://127.0.0.1.evil.example").is_err());
    }

    #[test]
    fn enrollment_survives_restart_and_token_is_not_stored_in_clear() {
        let d = tempfile::tempdir().unwrap();
        let p = Portal::open(d.path());
        // Simulate a completed enrollment without a network call.
        let token = "dev_00000000-0000-4000-8000-000000000000.secretsecretsecretsecretsecretsecret";
        use base64::Engine;
        let protected = base64::engine::general_purpose::STANDARD.encode(secret::protect(token.as_bytes()).unwrap());
        *p.token.lock().unwrap() = Some(token.into());
        *p.stored.lock().unwrap() = Some(Stored { portal_url: "https://c.example".into(), device_id: "d".into(), org_name: "Acme".into(), token_protected: protected, enrolled_at: Utc::now(), last_sync_at: None, last_error: None, license: None, policy: None, update: None });
        p.save();
        let raw = std::fs::read_to_string(d.path().join("enrollment.json")).unwrap();
        assert!(!raw.contains("secretsecret"), "token must not be in the file in clear text");
        let again = Portal::open(d.path());
        assert!(again.is_enrolled());
        assert_eq!(again.org_name().as_deref(), Some("Acme"));
    }

    #[test]
    fn unreadable_credential_means_not_enrolled() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("enrollment.json"), br#"{"portalUrl":"https://c.example","deviceId":"d","orgName":"Acme","tokenProtected":"AAAA","enrolledAt":"2026-01-01T00:00:00Z","lastSyncAt":null,"lastError":null,"license":null,"policy":null,"update":null}"#).unwrap();
        assert!(!Portal::open(d.path()).is_enrolled());
    }

    #[test]
    fn leaving_works_even_when_the_console_is_unreachable() {
        let d = tempfile::tempdir().unwrap();
        let p = Portal::open(d.path());
        let token = "dev_x.y";
        use base64::Engine;
        let protected = base64::engine::general_purpose::STANDARD.encode(secret::protect(token.as_bytes()).unwrap());
        *p.token.lock().unwrap() = Some(token.into());
        *p.stored.lock().unwrap() = Some(Stored { portal_url: "http://127.0.0.1:9".into(), device_id: "d".into(), org_name: "Acme".into(), token_protected: protected, enrolled_at: Utc::now(), last_sync_at: None, last_error: None, license: None, policy: None, update: None });
        p.save();
        let notified = p.unenroll();
        assert!(!notified, "nothing is listening on port 9");
        assert!(!p.is_enrolled());
        assert!(!d.path().join("enrollment.json").exists());
    }
}
