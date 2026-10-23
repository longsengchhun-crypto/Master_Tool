//! The server's half of edge scanning (see `edge.rs`): hand files over as jobs, and turn the owners' answers into reports.

use crate::edge::{report_from_result, EdgeJob, EdgeResult, Enqueued, EDGE_DEFAULT_WAIT_MS};
use crate::group::verdict_code;
use crate::queue::{now_ms, Group};
use crate::service::Inner;
use crate::telegram::{esc, safe_display_name, Document};

impl Inner {
    /// Shared bot, with files checked on the customers' computers.
    pub(crate) fn edge_on(&self) -> bool {
        self.cfg.read().unwrap().hosted.as_ref().is_some_and(|h| h.edge)
    }

    fn edge_wait_ms(&self) -> i64 {
        match self.cfg.read().unwrap().hosted.as_ref().map(|h| h.edge_wait_ms) {
            Some(ms) if ms > 0 => ms,
            _ => EDGE_DEFAULT_WAIT_MS,
        }
    }

    /// A file was posted in a protected group: record a job for the owner's app. The file is not touched.
    pub(crate) fn edge_submit(&self, g: &Group, mid: i64, doc: &Document, shown: &str, now: i64) {
        let uid = doc.file_unique_id.as_deref();
        let size = doc.file_size.unwrap_or(0);
        let name = doc.file_name.clone().unwrap_or_else(|| "file".into());
        let Some(owner) = g.enabled_by else { return };
        match self.store.edge_enqueue(owner, g.chat_id, mid, &doc.file_id, uid, &name, size, now) {
            Ok(Enqueued::Queued | Enqueued::Duplicate) => {}
            Ok(Enqueued::Full) => {
                let _ = self.store.group_record_scan(g.chat_id, mid, uid, "", size, "UNABLE_TO_VERIFY", false, "skipped_busy", None, now);
                if g.report_incomplete {
                    let _ = self.post_report(g, &format!("m{mid}"), format!("<b>{shown}</b> arrived while too many files were waiting for your computer. It was <b>not checked</b> and is not known to be safe."), false);
                }
            }
            Err(_) => {
                let _ = self.store.group_record_scan(g.chat_id, mid, uid, "", size, "UNABLE_TO_VERIFY", false, "error", None, now);
                if g.report_incomplete {
                    let _ = self.post_report(g, &format!("m{mid}"), format!("<b>{shown}</b> could not be handed to your computer. It was <b>not checked</b> and is not known to be safe."), false);
                }
            }
        }
    }

    /// Answers that came in from apps become reports; files nobody picked up in time are reported as not checked.
    pub(crate) fn edge_tick(&self) {
        let now = now_ms();
        let Some(bot) = self.bot.read().unwrap().clone() else { return };
        let Some(me) = self.bot_info(&bot) else { return };
        for j in self.store.edge_finished(20) {
            self.edge_answer(&bot, &me, &j, now);
            self.store.edge_close(&j.id, now);
        }
        for j in self.store.edge_expire(now, self.edge_wait_ms()) {
            let Ok(Some(g)) = self.store.group_get(j.group_chat) else { continue };
            let _ = self.store.group_record_scan(j.group_chat, j.message_id, j.file_unique_id.as_deref(), "", j.size, "UNABLE_TO_VERIFY", false, "skipped_expired", None, now);
            if g.report_incomplete {
                let _ = self.post_report(&g, &format!("m{}", j.message_id), format!("<b>{}</b> was <b>not checked</b>: your SENTRIX app did not pick it up in time. Keep the app running. It is not known to be safe.", safe_display_name(&j.name)), false);
            }
        }
    }

    fn edge_answer(&self, bot: &crate::telegram::BotClient, me: &crate::telegram::BotInfo, j: &EdgeJob, now: i64) {
        let Ok(Some(g)) = self.store.group_get(j.group_chat) else { return };
        let shown = safe_display_name(&j.name);
        let uid = j.file_unique_id.as_deref();
        if j.state == "done" {
            if let Some(res) = j.result.as_deref().and_then(|t| serde_json::from_str::<EdgeResult>(t).ok()) {
                let r = report_from_result(j, &res);
                self.finish_document(bot, me, j.group_chat, j.message_id, uid, &shown, &r);
                return;
            }
        }
        // The app could not fetch or check it (or sent something unreadable).
        let why = if j.state == "failed" { j.result.clone().unwrap_or_default() } else { "the answer could not be read".into() };
        let _ = self.store.group_record_scan(j.group_chat, j.message_id, uid, "", j.size, verdict_code(crate::types::Verdict::UnableToVerify), false, "error", None, now);
        if g.report_incomplete {
            let _ = self.post_report(&g, &format!("m{}", j.message_id), format!("<b>{shown}</b> could not be checked on your computer ({}). It was <b>not checked</b> and is not known to be safe.", esc(&why.chars().take(120).collect::<String>())), false);
        }
    }
}
