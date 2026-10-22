//! Storage for the shared SENTRIX bot: people who pressed Start, one-time link codes, and desktop apps linked to a person.
//!
//! Everything is keyed by the Telegram user id, and every lookup that changes something takes the acting user's id, so one
//! person can never touch another person's groups, codes or linked apps.

use crate::queue::{JobStore, StoreError};
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TgUser {
    pub user_id: i64,
    pub first_name: String,
    pub blocked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub user_id: i64,
    pub name: String,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeKind {
    Group,
    Device,
}

impl CodeKind {
    fn as_str(self) -> &'static str {
        match self {
            CodeKind::Group => "group",
            CodeKind::Device => "device",
        }
    }
}

/// Only the hash of a device token is stored; the token itself exists once, on the person's computer.
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostedTotals {
    pub users: i64,
    pub devices: i64,
}

impl JobStore {
    /// Record that this person pressed Start (so the bot may write to them). Pressing Start again clears a block.
    pub fn user_started(&self, user_id: i64, first_name: &str, now: i64) -> Result<(), StoreError> {
        let name: String = first_name.chars().filter(|c| !crate::telegram::is_deceptive(*c)).take(40).collect();
        self.conn.lock().unwrap().execute(
            "INSERT INTO tg_users(user_id, first_name, started_at, blocked) VALUES (?1,?2,?3,0)
             ON CONFLICT(user_id) DO UPDATE SET first_name=?2, blocked=0",
            params![user_id, name, now],
        )?;
        Ok(())
    }

    pub fn user_get(&self, user_id: i64) -> Result<Option<TgUser>, StoreError> {
        Ok(self
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT user_id, first_name, blocked FROM tg_users WHERE user_id=?1", [user_id], |r| Ok(TgUser { user_id: r.get(0)?, first_name: r.get(1)?, blocked: r.get::<_, i64>(2)? != 0 }))
            .optional()?)
    }

    /// The bot can write to this person: they pressed Start and have not blocked the bot.
    pub fn user_reachable(&self, user_id: i64) -> bool {
        matches!(self.user_get(user_id), Ok(Some(u)) if !u.blocked)
    }

    pub fn user_set_blocked(&self, user_id: i64, blocked: bool) {
        let _ = self.conn.lock().unwrap().execute("UPDATE tg_users SET blocked=?2 WHERE user_id=?1", params![user_id, blocked as i64]);
    }

    /// Issue a one-time code. Older unused codes of the same kind for this person stop working.
    pub fn code_issue(&self, kind: CodeKind, user_id: i64, code: &str, expires_at: i64) -> Result<(), StoreError> {
        let c = self.conn.lock().unwrap();
        c.execute("DELETE FROM link_codes WHERE kind=?1 AND user_id=?2 AND used_at IS NULL", params![kind.as_str(), user_id])?;
        c.execute("INSERT INTO link_codes(code, kind, user_id, expires_at) VALUES (?1,?2,?3,?4)", params![code, kind.as_str(), user_id, expires_at])?;
        Ok(())
    }

    /// Look at a code without using it. `Some(user_id)` only while it is valid and unused.
    pub fn code_peek(&self, kind: CodeKind, code: &str, now: i64) -> Option<i64> {
        self.conn
            .lock()
            .unwrap()
            .query_row("SELECT user_id FROM link_codes WHERE code=?1 AND kind=?2 AND used_at IS NULL AND expires_at>?3", params![code, kind.as_str(), now], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
    }

    /// Use a code exactly once. Returns the person it belongs to; `None` if unknown, expired or already used.
    pub fn code_take(&self, kind: CodeKind, code: &str, now: i64) -> Option<i64> {
        let c = self.conn.lock().unwrap();
        let n = c.execute("UPDATE link_codes SET used_at=?3 WHERE code=?1 AND kind=?2 AND used_at IS NULL AND expires_at>?3", params![code, kind.as_str(), now]).ok()?;
        if n == 0 {
            return None;
        }
        c.query_row("SELECT user_id FROM link_codes WHERE code=?1", [code], |r| r.get(0)).optional().ok().flatten()
    }

    pub fn codes_prune(&self, now: i64) {
        let _ = self.conn.lock().unwrap().execute("DELETE FROM link_codes WHERE expires_at < ?1 OR used_at IS NOT NULL AND used_at < ?1 - 86400000", [now]);
    }

    pub fn device_create(&self, user_id: i64, name: &str, token_hash: &str, now: i64) -> Result<String, StoreError> {
        let id = uuid::Uuid::new_v4().to_string();
        let name: String = name.chars().filter(|c| !c.is_control()).take(60).collect();
        self.conn.lock().unwrap().execute("INSERT INTO relay_devices(id, user_id, token_hash, name, created_at) VALUES (?1,?2,?3,?4,?5)", params![id, user_id, token_hash, name, now])?;
        Ok(id)
    }

    /// The device that owns this token, if it has not been unlinked.
    pub fn device_by_token(&self, token: &str) -> Option<Device> {
        let h = token_hash(token);
        self.conn
            .lock()
            .unwrap()
            .query_row("SELECT id, user_id, name, created_at, last_seen_at FROM relay_devices WHERE token_hash=?1 AND revoked_at IS NULL", [h], |r| Ok(Device { id: r.get(0)?, user_id: r.get(1)?, name: r.get(2)?, created_at: r.get(3)?, last_seen_at: r.get(4)? }))
            .optional()
            .ok()
            .flatten()
    }

    pub fn device_touch(&self, id: &str, now: i64) {
        let _ = self.conn.lock().unwrap().execute("UPDATE relay_devices SET last_seen_at=?2 WHERE id=?1", params![id, now]);
    }

    pub fn devices_of(&self, user_id: i64) -> Vec<Device> {
        let c = self.conn.lock().unwrap();
        let Ok(mut st) = c.prepare("SELECT id, user_id, name, created_at, last_seen_at FROM relay_devices WHERE user_id=?1 AND revoked_at IS NULL ORDER BY created_at") else { return vec![] };
        st.query_map([user_id], |r| Ok(Device { id: r.get(0)?, user_id: r.get(1)?, name: r.get(2)?, created_at: r.get(3)?, last_seen_at: r.get(4)? }))
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }

    /// Unlink one app. It only works for the person who owns it.
    pub fn device_revoke(&self, user_id: i64, id: &str, now: i64) -> bool {
        self.conn.lock().unwrap().execute("UPDATE relay_devices SET revoked_at=?3 WHERE id=?1 AND user_id=?2 AND revoked_at IS NULL", params![id, user_id, now]).map(|n| n > 0).unwrap_or(false)
    }

    /// This person's reports now go to `chat`. Their private chat is the fallback when they have none.
    pub fn history_set(&self, user_id: i64, chat_id: i64, title: &str, now: i64) -> Result<(), StoreError> {
        let title: String = title.chars().filter(|c| !crate::telegram::is_deceptive(*c)).take(60).collect();
        self.conn.lock().unwrap().execute(
            "INSERT INTO user_history(user_id, chat_id, title, linked_at) VALUES (?1,?2,?3,?4)
             ON CONFLICT(user_id) DO UPDATE SET chat_id=?2, title=?3, linked_at=?4",
            params![user_id, chat_id, title, now],
        )?;
        Ok(())
    }

    pub fn history_get(&self, user_id: i64) -> Option<(i64, String)> {
        self.conn.lock().unwrap().query_row("SELECT chat_id, title FROM user_history WHERE user_id=?1", [user_id], |r| Ok((r.get(0)?, r.get(1)?))).optional().ok().flatten()
    }

    /// Is this chat somebody's Scan History group?
    pub fn history_chat_known(&self, chat_id: i64) -> bool {
        self.conn.lock().unwrap().query_row("SELECT 1 FROM user_history WHERE chat_id=?1 LIMIT 1", [chat_id], |_| Ok(())).optional().ok().flatten().is_some()
    }

    /// The bot left, was removed, or the group was renamed: nobody's reports go there any more.
    pub fn history_clear_chat(&self, chat_id: i64) -> usize {
        self.conn.lock().unwrap().execute("DELETE FROM user_history WHERE chat_id=?1", [chat_id]).unwrap_or(0)
    }

    pub fn hosted_totals(&self) -> HostedTotals {
        let c = self.conn.lock().unwrap();
        let n = |sql: &str| c.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap_or(0);
        HostedTotals { users: n("SELECT count(*) FROM tg_users"), devices: n("SELECT count(*) FROM relay_devices WHERE revoked_at IS NULL") }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_works_once_and_only_before_it_expires() {
        let s = JobStore::open_in_memory().unwrap();
        s.code_issue(CodeKind::Group, 7, "g_abc", 1_000).unwrap();
        assert_eq!(s.code_peek(CodeKind::Group, "g_abc", 500), Some(7));
        assert_eq!(s.code_peek(CodeKind::Device, "g_abc", 500), None, "a group code is not a device code");
        assert_eq!(s.code_take(CodeKind::Group, "g_abc", 500), Some(7));
        assert_eq!(s.code_take(CodeKind::Group, "g_abc", 501), None, "second use");
        s.code_issue(CodeKind::Device, 7, "ABCD2345", 1_000).unwrap();
        assert_eq!(s.code_take(CodeKind::Device, "ABCD2345", 1_000), None, "expired exactly at its limit");
    }

    #[test]
    fn a_new_code_replaces_the_previous_unused_one() {
        let s = JobStore::open_in_memory().unwrap();
        s.code_issue(CodeKind::Device, 7, "AAAA1111", 9_000).unwrap();
        s.code_issue(CodeKind::Device, 7, "BBBB2222", 9_000).unwrap();
        assert_eq!(s.code_peek(CodeKind::Device, "AAAA1111", 1), None);
        assert_eq!(s.code_peek(CodeKind::Device, "BBBB2222", 1), Some(7));
        s.code_issue(CodeKind::Device, 8, "CCCC3333", 9_000).unwrap();
        assert_eq!(s.code_peek(CodeKind::Device, "BBBB2222", 1), Some(7), "another person's code is untouched");
    }

    #[test]
    fn only_the_token_hash_is_stored_and_unlinking_is_owner_only() {
        let s = JobStore::open_in_memory().unwrap();
        let id = s.device_create(7, "Sam's laptop", &token_hash("secret-token"), 1).unwrap();
        let raw: String = s.conn.lock().unwrap().query_row("SELECT token_hash || name FROM relay_devices", [], |r| r.get(0)).unwrap();
        assert!(!raw.contains("secret-token"));
        assert_eq!(s.device_by_token("secret-token").unwrap().user_id, 7);
        assert!(s.device_by_token("another").is_none());
        assert!(!s.device_revoke(8, &id, 5), "someone else cannot unlink it");
        assert!(s.device_by_token("secret-token").is_some());
        assert!(s.device_revoke(7, &id, 5));
        assert!(s.device_by_token("secret-token").is_none(), "an unlinked app is refused");
    }

    #[test]
    fn each_person_has_their_own_history_group_and_losing_it_clears_only_that() {
        let s = JobStore::open_in_memory().unwrap();
        assert!(s.history_get(7).is_none());
        s.history_set(7, -100, "Scan History", 1).unwrap();
        s.history_set(8, -200, "Scan History", 1).unwrap();
        assert_eq!(s.history_get(7).unwrap().0, -100);
        assert_eq!(s.history_get(8).unwrap().0, -200, "another person's is separate");
        assert!(s.history_chat_known(-100) && !s.history_chat_known(-300));
        s.history_set(7, -150, "Scan History", 2).unwrap();
        assert_eq!(s.history_get(7).unwrap().0, -150, "a person has one, the newest");
        assert_eq!(s.history_clear_chat(-200), 1);
        assert!(s.history_get(8).is_none() && s.history_get(7).is_some());
    }

    #[test]
    fn people_are_reachable_only_after_start_and_until_they_block_the_bot() {
        let s = JobStore::open_in_memory().unwrap();
        assert!(!s.user_reachable(7));
        s.user_started(7, "Sam\u{202e}", 1).unwrap();
        assert!(s.user_reachable(7));
        assert!(!s.user_get(7).unwrap().unwrap().first_name.contains('\u{202e}'), "a name cannot disguise itself");
        s.user_set_blocked(7, true);
        assert!(!s.user_reachable(7));
        s.user_started(7, "Sam", 2).unwrap();
        assert!(s.user_reachable(7), "pressing Start again unblocks");
    }
}
