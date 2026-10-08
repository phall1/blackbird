//! The coordination contract, exercised through [`Desk`] rather than SQL.

#![allow(
    clippy::expect_used,
    reason = "integration tests fail the process when a fixture cannot be built"
)]

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use blackbird_kernel::{Desk, Error, SayRequest, Selector};

fn desk() -> (tempfile::TempDir, Desk) {
    let dir = tempfile::tempdir().expect("temp");
    let desk = Desk::open(dir.path().join("coord.sqlite")).expect("open");
    (dir, desk)
}

fn exact(path: &str) -> Selector {
    Selector {
        kind: "exact".to_owned(),
        path: path.to_owned(),
    }
}

fn subtree(path: &str) -> Selector {
    Selector {
        kind: "subtree".to_owned(),
        path: path.to_owned(),
    }
}

fn say(to: &[&str], subject: &str, body: &str) -> SayRequest {
    SayRequest {
        conversation_id: None,
        topic: "note".to_owned(),
        slug: String::new(),
        to: to.iter().map(|name| (*name).to_owned()).collect(),
        subject: subject.to_owned(),
        body: body.to_owned(),
        reply_to: None,
        acknowledgement_required: false,
        peer_project_key: None,
    }
}

#[test]
fn join_resume_keeps_one_token_and_does_not_store_it() {
    let (dir, desk) = desk();
    let first = desk
        .join("/workspace/repo", "alice", None)
        .expect("register");
    let token = first.registration_token.expect("issued once");
    assert!(token.starts_with("bbm_"));
    assert!(token.len() > 16);
    let err = desk
        .join("/workspace/repo", "alice", None)
        .expect_err("resume needs the token");
    assert_eq!(err.code(), "UNAUTHENTICATED");
    let again = desk
        .join("/workspace/repo", "alice", Some(&token))
        .expect("resume");
    assert!(again.registration_token.is_none());
    assert_eq!(again.actor_id, first.actor_id);
    assert_ne!(again.session_id, first.session_id);
    assert!(desk.join("/workspace/repo", "bob", Some(&token)).is_err());

    let hash: String = rusqlite::Connection::open(dir.path().join("coord.sqlite"))
        .expect("read")
        .query_row("SELECT token_hash FROM agent", [], |row| row.get(0))
        .expect("hash");
    assert_ne!(hash, token);
    assert!(!hash.contains(&token));
}

#[test]
fn leases_conflict_share_renew_and_release() {
    let (_dir, desk) = desk();
    let alice = desk
        .join("/workspace/repo", "alice", None)
        .expect("alice")
        .registration_token
        .expect("token");
    let bob = desk
        .join("/workspace/repo", "bob", None)
        .expect("bob")
        .registration_token
        .expect("token");
    let held = desk
        .claim(&alice, None, &[subtree("src")], None)
        .expect("claim");
    assert!(held.ok);
    assert_eq!(held.selectors[0].claim_generation, 1);
    let renewed = desk
        .claim(&alice, None, &[subtree("src")], Some(120))
        .expect("renew");
    assert!(renewed.ok);
    assert_eq!(renewed.selectors[0].claim_generation, 2);
    assert_ne!(renewed.lease_id, held.lease_id);

    let blocked = desk
        .claim(&bob, Some("exclusive"), &[exact("src/main.rs")], Some(60))
        .expect("conflict is not an error");
    assert!(!blocked.ok);
    let holder = blocked.blocked_by.expect("holder");
    assert_eq!(holder.holder_agent_name, "alice");
    assert_eq!(blocked.options, vec!["wait", "narrow", "message", "force"]);

    desk.claim(&alice, Some("shared"), &[subtree("docs")], Some(300))
        .expect("shared parent");
    let shared = desk
        .claim(&bob, Some("shared"), &[exact("docs/guide.md")], Some(300))
        .expect("shared child");
    assert!(shared.ok);

    let partial = desk.release(&alice, &[exact("src/lib.rs")]);
    assert_eq!(partial.expect_err("partial").code(), "NOT_FOUND");
    let released = desk.release(&alice, &[subtree("src")]).expect("release");
    assert!(!released.released_at.is_empty());
    let after = desk
        .claim(&bob, Some("exclusive"), &[exact("src/main.rs")], Some(60))
        .expect("free");
    assert!(after.ok);
    assert!(desk.claim(&alice, None, &[exact("a.rs")], Some(0)).is_err());
}

#[test]
fn mail_is_stored_only_when_addressed_and_ack_is_personal() {
    let (_dir, desk) = desk();
    let alice = desk
        .join("/workspace/repo", "alice", None)
        .expect("alice")
        .registration_token
        .expect("token");
    let bob = desk
        .join("/workspace/repo", "bob", None)
        .expect("bob")
        .registration_token
        .expect("token");
    let opened = desk
        .say(
            &alice,
            SayRequest {
                slug: "review".to_owned(),
                topic: "Review".to_owned(),
                ..say(&[], "", "")
            },
        )
        .expect("open");
    assert!(!opened.reused);
    assert!(opened.message_id.is_none());
    let reused = desk
        .say(
            &bob,
            SayRequest {
                slug: "review".to_owned(),
                ..say(&[], "", "")
            },
        )
        .expect("rejoin");
    assert!(reused.reused);
    assert_eq!(reused.conversation_id, opened.conversation_id);

    let err = desk
        .say(&alice, say(&[], "nope", "this must not land"))
        .expect_err("body without recipients");
    assert_eq!(err.code(), "INVALID");
    assert_eq!(
        desk.say(&alice, say(&["bob@other"], "x", "y"))
            .expect_err("remote")
            .code(),
        "REMOTE_UNSUPPORTED"
    );

    let mut sent = say(&["bob"], "hello", "durable payload");
    sent.conversation_id = Some(opened.conversation_id.clone());
    sent.acknowledgement_required = true;
    let message = desk.say(&alice, sent).expect("send");
    let message_id = message.message_id.expect("stored");
    let inbox = desk.read(&bob, None, true, 0, None).expect("inbox");
    assert_eq!(inbox.messages.len(), 1);
    assert_eq!(inbox.messages[0].body, "durable payload");
    let acked = desk.ack(&bob, &message_id, "acknowledged").expect("ack");
    assert!(acked.read && acked.acknowledged);
    assert_eq!(
        desk.ack(&alice, &message_id, "read")
            .expect_err("not hers")
            .code(),
        "NOT_FOUND"
    );
    assert!(
        desk.read(&bob, None, true, 0, None)
            .expect("unread")
            .messages
            .is_empty()
    );

    let resumed = desk
        .join("/workspace/repo", "alice", Some(&alice))
        .expect("resume");
    assert_eq!(resumed.inbox.unread, 0);
    assert!(resumed.open_conversations.iter().any(|c| c.messages == 1));
    assert!(resumed.other_agents.iter().any(|peer| peer.name == "bob"));
}

#[test]
fn wait_reports_path_mail_and_deadline() {
    let (_dir, desk) = desk();
    let desk = Arc::new(desk);
    let holder = desk
        .join("/workspace/repo", "holder", None)
        .expect("holder")
        .registration_token
        .expect("token");
    let waiter = desk
        .join("/workspace/repo", "waiter", None)
        .expect("waiter")
        .registration_token
        .expect("token");
    desk.claim(
        &holder,
        Some("exclusive"),
        &[exact("src/lib.rs")],
        Some(600),
    )
    .expect("hold");
    let immediate = desk
        .wait(&waiter, Some("other.rs"), Some("exclusive"), false, Some(2))
        .expect("free path");
    assert_eq!(immediate.reason, "path_free");

    let parked = Arc::clone(&desk);
    let releaser = holder.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        parked
            .release(&releaser, &[exact("src/lib.rs")])
            .expect("release");
    });
    let freed = desk
        .wait(
            &waiter,
            Some("src/lib.rs"),
            Some("exclusive"),
            false,
            Some(5),
        )
        .expect("wait");
    assert_eq!(freed.reason, "path_free");
    assert!(freed.waited_ms >= 100);

    desk.claim(
        &holder,
        Some("exclusive"),
        &[exact("blocked.rs")],
        Some(600),
    )
    .expect("block again");
    let deadline = desk
        .wait(&waiter, Some("blocked.rs"), None, false, Some(1))
        .expect("deadline");
    assert_eq!(deadline.reason, "deadline");
    assert_eq!(deadline.blockers[0].holder_agent_name, "holder");

    let writer = Arc::clone(&desk);
    let author = holder.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        writer
            .say(&author, say(&["waiter"], "ping", "awake"))
            .expect("mail");
    });
    let mail = desk
        .wait(&waiter, None, None, true, Some(5))
        .expect("mail wait");
    assert_eq!(mail.reason, "mail_arrived");
    assert!(mail.pending_deliveries >= 1);

    let stale = desk
        .wait(&waiter, None, None, true, Some(1))
        .expect("old mail does not wake");
    assert_eq!(stale.reason, "deadline");
    assert!(stale.pending_deliveries >= 1);
}

#[test]
fn status_refuses_observations_it_does_not_own() {
    let (_dir, desk) = desk();
    let token = desk
        .join("/workspace/repo", "alice", None)
        .expect("join")
        .registration_token
        .expect("token");
    desk.claim(&token, None, &[exact("README.md")], Some(30))
        .expect("claim");
    let status = desk
        .status(&token, Some("README.md"), None, false)
        .expect("status");
    assert_eq!(status.reservations.len(), 1);
    assert!(!status.truncated);
    let err = desk.status(&token, None, None, true).expect_err("spend");
    assert_eq!(err.code(), "DEPENDENCY_UNAVAILABLE");
    assert!(matches!(err, Error::DependencyUnavailable(_)));
    assert!(desk.read(&token, None, false, 0, Some(0)).is_err());
}
