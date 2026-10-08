//! Newline-delimited JSON-RPC for the eight coordination tools.
//!
//! Tool failures are `isError: true` results. A lease conflict is a normal
//! result with `ok: false`.

use std::io::{BufRead, Write};
use std::process::ExitCode;

use blackbird_kernel::{Desk, Error, SayRequest, Selector};
use serde_json::{Value, json};

const PROTOCOL: &str = "2024-11-05";

pub fn serve(desk: &Desk) -> std::io::Result<ExitCode> {
    let stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(response) = dispatch(desk, &line) {
            stdout.write_all(response.as_bytes())?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn dispatch(desk: &Desk, line: &str) -> Option<String> {
    let value: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(_) => return Some(rpc_error(Value::Null, -32700, "parse error")),
    };
    let id = value.get("id").cloned();
    let Some(method) = value.get("method").and_then(Value::as_str) else {
        return Some(rpc_error(
            id.unwrap_or(Value::Null),
            -32600,
            "invalid request",
        ));
    };
    let id = id?;
    let params = value.get("params").cloned().unwrap_or_else(|| json!({}));
    let result = match method {
        "initialize" => initialize(),
        "ping" => json!({}),
        "tools/list" => json!({ "tools": tools() }),
        "tools/call" => match call_tool(desk, &params) {
            Ok(body) => tool_result(&body, false),
            Err(err) => tool_result(&failure(&err), true),
        },
        _ => return Some(rpc_error(id, -32601, "method not found")),
    };
    Some(rpc_ok(id, result))
}

fn initialize() -> Value {
    json!({
        "protocolVersion": PROTOCOL,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "blackbird-rs", "version": env!("CARGO_PKG_VERSION") }
    })
}

fn call_tool(desk: &Desk, params: &Value) -> Result<Value, Error> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Invalid("tools/call requires a string name".to_owned()))?;
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    match name {
        "blackbird_join" => join(desk, &args),
        "blackbird_claim" => claim(desk, &args),
        "blackbird_release" => release(desk, &args),
        "blackbird_status" => status(desk, &args),
        "blackbird_say" => say(desk, &args),
        "blackbird_read" => read(desk, &args),
        "blackbird_ack" => ack(desk, &args),
        "blackbird_wait" => wait(desk, &args),
        _ => Err(Error::NotFound(format!("unknown tool {name}"))),
    }
}

fn join(desk: &Desk, args: &Value) -> Result<Value, Error> {
    let input: JoinIn = parse(args)?;
    let out = desk.join(
        &input.project_key,
        &input.agent_name,
        input.registration_token.as_deref(),
    )?;
    to_value(&out)
}

fn claim(desk: &Desk, args: &Value) -> Result<Value, Error> {
    let input: ClaimIn = parse(args)?;
    let selectors = selectors(&input.selectors);
    let out = desk.claim(
        &input.agent_token,
        input.mode.as_deref(),
        &selectors,
        input.ttl_seconds,
    )?;
    to_value(&out)
}

fn release(desk: &Desk, args: &Value) -> Result<Value, Error> {
    let input: ReleaseIn = parse(args)?;
    let out = desk.release(&input.agent_token, &selectors(&input.selectors))?;
    to_value(&out)
}

fn status(desk: &Desk, args: &Value) -> Result<Value, Error> {
    let input: StatusIn = parse(args)?;
    let _ignored = (&input.dimension, input.since_hours, input.mine_only);
    let external =
        input.spend || input.cost || input.object_id.as_deref().is_some_and(|id| !id.is_empty());
    let out = desk.status(
        &input.agent_token,
        input.path.as_deref(),
        input.limit,
        external,
    )?;
    to_value(&out)
}

fn say(desk: &Desk, args: &Value) -> Result<Value, Error> {
    let input: SayIn = parse(args)?;
    let out = desk.say(
        &input.agent_token,
        SayRequest {
            conversation_id: input.conversation_id,
            topic: input.topic,
            slug: input.slug,
            to: input.to,
            subject: input.subject,
            body: input.body,
            reply_to: input.reply_to_message_id,
            acknowledgement_required: input.acknowledgement_required,
            peer_project_key: input.peer_project_key,
        },
    )?;
    to_value(&out)
}

fn read(desk: &Desk, args: &Value) -> Result<Value, Error> {
    let input: ReadIn = parse(args)?;
    let out = desk.read(
        &input.agent_token,
        input.conversation_id.as_deref(),
        input.unread_only,
        input.after,
        input.limit,
    )?;
    to_value(&out)
}

fn ack(desk: &Desk, args: &Value) -> Result<Value, Error> {
    let input: AckIn = parse(args)?;
    let out = desk.ack(&input.agent_token, &input.message_id, &input.kind)?;
    to_value(&out)
}

fn wait(desk: &Desk, args: &Value) -> Result<Value, Error> {
    let input: WaitIn = parse(args)?;
    let out = desk.wait(
        &input.agent_token,
        input.path.as_deref(),
        input.mode.as_deref(),
        input.await_mail,
        input.timeout_seconds,
    )?;
    to_value(&out)
}

fn selectors(raw: &[SelectorIn]) -> Vec<Selector> {
    raw.iter()
        .map(|selector| {
            let _generation = selector.claim_generation;
            Selector {
                kind: selector.kind.clone(),
                path: selector.path.clone(),
            }
        })
        .collect()
}

fn parse<T: serde::de::DeserializeOwned>(args: &Value) -> Result<T, Error> {
    serde_json::from_value(args.clone()).map_err(|err| Error::Invalid(err.to_string()))
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, Error> {
    serde_json::to_value(value).map_err(|err| Error::Storage(err.to_string()))
}

fn failure(err: &Error) -> Value {
    json!({
        "code": err.code(),
        "category": err.category(),
        "message": err.to_string(),
        "retryable": err.retryable(),
    })
}

fn tool_result(value: &Value, is_error: bool) -> Value {
    let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_owned());
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": value,
        "isError": is_error,
    })
}

fn rpc_ok(id: Value, result: Value) -> String {
    serde_json::to_string(&json!({ "jsonrpc": "2.0", "id": id, "result": result })).unwrap_or_else(
        |_| {
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"serialize failed"}}"#
                .to_owned()
        },
    )
}

fn rpc_error(id: Value, code: i64, message: &str) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    }))
    .unwrap_or_else(|_| "{}".to_owned())
}

fn tools() -> Value {
    json!([
        schema(
            "blackbird_join",
            "Register or resume one agent in a project and return the token once, plus leases, inbox, conversations, and peers.",
            &[
                field(
                    "project_key",
                    Kind::String,
                    "Absolute project path that scopes this agent's mail and claims.",
                    true
                ),
                field(
                    "agent_name",
                    Kind::String,
                    "Stable name in that project.",
                    true
                ),
                field(
                    "registration_token",
                    Kind::String,
                    "Token from the first join. Required to resume. Omit when registering a new name.",
                    false
                ),
            ],
        ),
        schema(
            "blackbird_claim",
            "Acquire or renew an exact selector set. A conflict is ok=false with the holders and options wait, narrow, message, force. force does not steal.",
            &[
                field(
                    "agent_token",
                    Kind::String,
                    "Registration token from join.",
                    true
                ),
                field(
                    "selectors",
                    Kind::Selectors,
                    "Exact paths or subtrees to hold.",
                    true
                ),
                field(
                    "mode",
                    Kind::String,
                    "exclusive or shared. Defaults to exclusive.",
                    false
                ),
                field(
                    "ttl_seconds",
                    Kind::Integer,
                    "Lease lifetime. Defaults to 3600. Maximum is 86400.",
                    false
                ),
            ],
        ),
        schema(
            "blackbird_release",
            "Release one live claim by its exact selector set. A partial set is rejected.",
            &[
                field(
                    "agent_token",
                    Kind::String,
                    "Registration token from join.",
                    true
                ),
                field(
                    "selectors",
                    Kind::Selectors,
                    "The exact set returned by claim.",
                    true
                ),
            ],
        ),
        schema(
            "blackbird_status",
            "List peers seen in the last five minutes and live claims. Spend, cost, and tracker fields are refused.",
            &[
                field(
                    "agent_token",
                    Kind::String,
                    "Registration token from join.",
                    true
                ),
                field(
                    "path",
                    Kind::String,
                    "Repository-relative path used to filter live claims.",
                    false
                ),
                field("limit", Kind::Integer, "Maximum claims to return.", false),
                field(
                    "object_id",
                    Kind::String,
                    "Tracker id. Refused: this kernel does not observe trackers.",
                    false
                ),
                field(
                    "spend",
                    Kind::Boolean,
                    "Refused: this kernel does not report spend.",
                    false
                ),
                field(
                    "dimension",
                    Kind::String,
                    "Ignored. Spend is refused.",
                    false
                ),
                field(
                    "since_hours",
                    Kind::Integer,
                    "Ignored. Spend is refused.",
                    false
                ),
                field(
                    "mine_only",
                    Kind::Boolean,
                    "Ignored. Spend is refused.",
                    false
                ),
                field(
                    "cost",
                    Kind::Boolean,
                    "Refused: this kernel does not report contention cost.",
                    false
                ),
            ],
        ),
        schema(
            "blackbird_say",
            "Open or rejoin a thread by slug. A message is stored only when to names registered peers. name@host is refused.",
            &[
                field(
                    "agent_token",
                    Kind::String,
                    "Registration token from join.",
                    true
                ),
                field(
                    "conversation_id",
                    Kind::String,
                    "Existing thread. Omit to open or rejoin by slug.",
                    false
                ),
                field(
                    "topic",
                    Kind::String,
                    "Required when opening a thread.",
                    false
                ),
                field(
                    "slug",
                    Kind::String,
                    "Stable thread name. The same slug returns the same conversation.",
                    false
                ),
                field(
                    "to",
                    Kind::StringArray,
                    "Registered peer names. Omit, with no subject or body, to open a thread without sending.",
                    false
                ),
                field(
                    "subject",
                    Kind::String,
                    "One-line subject. Requires to.",
                    false
                ),
                field("body", Kind::String, "Message body. Requires to.", false),
                field(
                    "reply_to_message_id",
                    Kind::String,
                    "Message this answers, in the same conversation.",
                    false
                ),
                field(
                    "acknowledgement_required",
                    Kind::Boolean,
                    "Ask recipients to acknowledge the body.",
                    false
                ),
                field(
                    "peer_project_key",
                    Kind::String,
                    "Refused: this kernel does not deliver name@host mail.",
                    false
                ),
            ],
        ),
        schema(
            "blackbird_read",
            "Read the inbox, or one visible thread when conversation_id is set. Page with next.",
            &[
                field(
                    "agent_token",
                    Kind::String,
                    "Registration token from join.",
                    true
                ),
                field(
                    "conversation_id",
                    Kind::String,
                    "Thread to read. Omit for the inbox.",
                    false
                ),
                field(
                    "unread_only",
                    Kind::Boolean,
                    "Inbox only: return unread deliveries.",
                    false
                ),
                field(
                    "after",
                    Kind::Integer,
                    "Resume after this workspace-global position.",
                    false
                ),
                field("limit", Kind::Integer, "Maximum messages to return.", false),
            ],
        ),
        schema(
            "blackbird_ack",
            "Record read or acknowledged for a message delivered to the caller.",
            &[
                field(
                    "agent_token",
                    Kind::String,
                    "Registration token from join.",
                    true
                ),
                field(
                    "message_id",
                    Kind::String,
                    "Message in this agent's inbox.",
                    true
                ),
                field(
                    "kind",
                    Kind::String,
                    "read or acknowledged. acknowledged also marks the delivery read.",
                    true
                ),
            ],
        ),
        schema(
            "blackbird_wait",
            "Wait until a path is free, new mail arrives, or the deadline. Existing unread mail does not wake the call.",
            &[
                field(
                    "agent_token",
                    Kind::String,
                    "Registration token from join.",
                    true
                ),
                field(
                    "path",
                    Kind::String,
                    "Repository-relative path to wait on.",
                    false
                ),
                field(
                    "mode",
                    Kind::String,
                    "exclusive or shared. Shared waits only for exclusive holders.",
                    false
                ),
                field(
                    "await_mail",
                    Kind::Boolean,
                    "Wake when mail arrives after this call starts.",
                    false
                ),
                field(
                    "timeout_seconds",
                    Kind::Integer,
                    "Budget. Zero and values above 60 are clamped to 60.",
                    false
                ),
            ],
        ),
    ])
}

struct Field {
    name: &'static str,
    kind: Kind,
    description: &'static str,
    required: bool,
}

const fn field(name: &'static str, kind: Kind, description: &'static str, required: bool) -> Field {
    Field {
        name,
        kind,
        description,
        required,
    }
}

enum Kind {
    String,
    Integer,
    Boolean,
    StringArray,
    Selectors,
}

fn schema(name: &str, description: &str, fields: &[Field]) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for field in fields {
        if field.required {
            required.push(field.name);
        }
        properties.insert(field.name.to_owned(), field_schema(field));
    }
    json!({
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": properties,
            "required": required,
        }
    })
}

fn field_schema(field: &Field) -> Value {
    let mut value = match field.kind {
        Kind::String => json!({ "type": "string" }),
        Kind::Integer => json!({ "type": "integer" }),
        Kind::Boolean => json!({ "type": "boolean" }),
        Kind::StringArray => json!({ "type": "array", "items": { "type": "string" } }),
        Kind::Selectors => json!({
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "path"],
                "properties": {
                    "kind": { "type": "string", "description": "exact or subtree." },
                    "path": { "type": "string", "description": "Repository-relative path. No absolute path, empty segment, or .. ." },
                    "claim_generation": { "type": "integer", "description": "Ignored on input. Claim returns the current generation." }
                }
            }
        }),
    };
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "description".to_owned(),
            Value::String(field.description.to_owned()),
        );
    }
    value
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinIn {
    project_key: String,
    agent_name: String,
    #[serde(default)]
    registration_token: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectorIn {
    kind: String,
    path: String,
    #[serde(default)]
    claim_generation: u64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimIn {
    agent_token: String,
    #[serde(default)]
    mode: Option<String>,
    selectors: Vec<SelectorIn>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseIn {
    agent_token: String,
    selectors: Vec<SelectorIn>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusIn {
    agent_token: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    limit: Option<u16>,
    #[serde(default)]
    object_id: Option<String>,
    #[serde(default)]
    spend: bool,
    #[serde(default)]
    dimension: Option<String>,
    #[serde(default)]
    since_hours: Option<u32>,
    #[serde(default)]
    mine_only: bool,
    #[serde(default)]
    cost: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SayIn {
    agent_token: String,
    #[serde(default)]
    conversation_id: Option<String>,
    #[serde(default)]
    topic: String,
    #[serde(default)]
    slug: String,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    reply_to_message_id: Option<String>,
    #[serde(default)]
    acknowledgement_required: bool,
    #[serde(default)]
    peer_project_key: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadIn {
    agent_token: String,
    #[serde(default)]
    conversation_id: Option<String>,
    #[serde(default)]
    unread_only: bool,
    #[serde(default)]
    after: u64,
    #[serde(default)]
    limit: Option<u16>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AckIn {
    agent_token: String,
    message_id: String,
    kind: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitIn {
    agent_token: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    await_mail: bool,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::dispatch;
    use blackbird_kernel::Desk;

    #[test]
    fn stdio_dispatch_joins_and_rejects_unknown_release_fields() {
        let dir = tempfile::tempdir().expect("temp");
        let desk = Desk::open(dir.path().join("coord.sqlite")).expect("open");
        let init =
            dispatch(&desk, r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#).expect("response");
        assert!(init.contains("blackbird-rs"));
        let listed =
            dispatch(&desk, r#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#).expect("tools");
        assert!(listed.contains("\"project_key\""));
        assert!(listed.contains("\"additionalProperties\":false"));
        let joined = dispatch(
            &desk,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"blackbird_join","arguments":{"project_key":"/workspace/repo","agent_name":"alice"}}}"#,
        )
        .expect("join");
        assert!(joined.contains("bbm_"));
        assert!(joined.contains("\"isError\":false"));
        let rejected = dispatch(
            &desk,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"blackbird_release","arguments":{"agent_token":"bbm_nope","selectors":[],"ttl_seconds":1}}}"#,
        )
        .expect("release");
        assert!(rejected.contains("\"isError\":true"));
        assert!(
            dispatch(
                &desk,
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
            )
            .is_none()
        );
    }
}
