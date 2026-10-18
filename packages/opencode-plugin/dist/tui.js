// @bun
// src/tui.tsx
import { mergeProps as _$mergeProps } from "@opentui/solid";
import { insert as _$insert2 } from "@opentui/solid";
import { memo as _$memo2 } from "@opentui/solid";
import { createElement as _$createElement2 } from "@opentui/solid";
import { createComponent as _$createComponent2 } from "@opentui/solid";
import { Plugin } from "@opencode/plugin/tui";
import { Show as Show2, createResource } from "solid-js";

// src/rpc.ts
import { Rpc } from "@opencode/plugin/rpc";
import { z } from "zod";
var Agent = z.object({
  agent_name: z.string(),
  active: z.boolean(),
  unread_deliveries: z.number(),
  unacked_deliveries: z.number()
});
var AgentsPage = z.object({ agents: z.array(Agent), truncated: z.boolean() });
var Delivery = z.object({
  message_id: z.string(),
  conversation_id: z.string(),
  recipient_agent_name: z.string(),
  author_agent_name: z.string().default("Unknown author"),
  subject: z.string(),
  read: z.boolean(),
  acknowledged: z.boolean(),
  acknowledgement_required: z.boolean(),
  sent_at: z.string()
});
var InboxPage = z.object({ pending: z.array(Delivery), truncated: z.boolean() });
var ThreadMessage = z.object({
  message_id: z.string(),
  author_agent_name: z.string(),
  subject: z.string(),
  body: z.string(),
  sent_at: z.string(),
  position: z.number()
});
var ThreadPage = z.object({ messages: z.array(ThreadMessage), has_more: z.boolean(), next: z.number() });
var InboxQuery = z.object({ agent: z.string().min(1).max(256).optional(), unread: z.boolean().default(false) });
var ThreadQuery = z.object({ conversation_id: z.string().min(1).max(256), after: z.number().int().nonnegative().default(0) });
var errors = { unavailable: z.object({ message: z.string() }) };
var Mail = Rpc.define({
  id: "blackbird.mail",
  events: {},
  methods: {
    agents: { input: z.object({}), output: AgentsPage, errors },
    inbox: { input: InboxQuery, output: InboxPage, errors },
    thread: { input: ThreadQuery, output: ThreadPage, errors }
  }
});

// src/mailbox-view.tsx
import { effect as _$effect } from "@opentui/solid";
import { createComponent as _$createComponent } from "@opentui/solid";
import { insert as _$insert } from "@opentui/solid";
import { createTextNode as _$createTextNode } from "@opentui/solid";
import { insertNode as _$insertNode } from "@opentui/solid";
import { memo as _$memo } from "@opentui/solid";
import { setProp as _$setProp } from "@opentui/solid";
import { use as _$use } from "@opentui/solid";
import { createElement as _$createElement } from "@opentui/solid";
import { For, Show, createMemo, onCleanup as onCleanup2, onMount } from "solid-js";

// src/mailbox-model.tsx
import { createStore } from "solid-js/store";
function createMailbox(reader) {
  const [state, set] = createStore({
    mode: "agents",
    agent: "",
    unread: false,
    conversation: "",
    after: 0,
    loading: false,
    error: "",
    agents: {
      agents: [],
      truncated: false
    },
    inbox: {
      pending: [],
      truncated: false
    },
    thread: {
      messages: [],
      has_more: false,
      next: 0
    }
  });
  let active;
  async function refresh() {
    active?.abort();
    const controller = new AbortController;
    active = controller;
    set({
      loading: true,
      error: ""
    });
    try {
      const result = await load(controller.signal);
      if (!controller.signal.aborted)
        set(result);
    } catch {
      if (!controller.signal.aborted)
        set("error", "Mailbox unavailable. Check blackbird status on the server, then press r to retry.");
    } finally {
      if (!controller.signal.aborted)
        set("loading", false);
    }
  }
  async function load(signal) {
    if (state.mode === "agents")
      return {
        agents: await reader.agents(signal)
      };
    if (state.mode === "thread")
      return {
        thread: await reader.thread({
          conversation_id: state.conversation,
          after: state.after
        }, signal)
      };
    return {
      inbox: await reader.inbox({
        ...state.agent ? {
          agent: state.agent
        } : {},
        unread: state.unread
      }, signal)
    };
  }
  return {
    state,
    refresh,
    dispose: () => active?.abort(),
    inbox: (agent) => {
      set({
        mode: "inbox",
        agent
      });
      return refresh();
    },
    thread: (conversation) => {
      set({
        mode: "thread",
        conversation,
        after: 0
      });
      return refresh();
    },
    next: () => {
      if (!state.thread.has_more)
        return;
      set("after", state.thread.next);
      return refresh();
    },
    first: () => {
      set("after", 0);
      return refresh();
    },
    toggleUnread: () => {
      set("unread", !state.unread);
      return refresh();
    },
    back: () => {
      set("mode", state.mode === "thread" ? "inbox" : "agents");
      return refresh();
    }
  };
}
function mailText(value) {
  return value.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, "");
}

// src/mailbox-focus.tsx
import { CliRenderEvents } from "@opentui/core";
import { onCleanup } from "solid-js";
function restoreMailboxFocus(renderer, root, widget, enabled) {
  let disposed = false;
  function focused(node) {
    if (!node || !ancestor(node, root()))
      return;
    queueMicrotask(() => {
      if (disposed || !enabled() || renderer.currentFocusedRenderable !== node)
        return;
      root()?.findDescendantById(widget())?.focus();
    });
  }
  renderer.on(CliRenderEvents.FOCUSED_RENDERABLE, focused);
  onCleanup(() => {
    disposed = true;
    renderer.off(CliRenderEvents.FOCUSED_RENDERABLE, focused);
  });
}
function ancestor(node, child) {
  let parent = child?.parent;
  while (parent) {
    if (parent === node)
      return true;
    parent = parent.parent;
  }
  return false;
}

// src/mailbox-view.tsx
function MailboxView(props) {
  const model = createMailbox(props.reader);
  const state = model.state;
  const theme = props.context.theme;
  const accent = theme.text.action.primary.base;
  let root;
  restoreMailboxFocus(props.context.renderer, () => root, () => state.mode === "thread" ? "blackbird-thread" : "blackbird-list", () => props.focused);
  onMount(() => {
    model.refresh();
  });
  onCleanup2(model.dispose);
  const back = () => state.mode === "agents" ? props.close() : model.back();
  const options = createMemo(() => {
    if (state.mode === "agents")
      return [{
        name: "All mailboxes",
        description: "Browse every delivery in this workspace",
        value: ""
      }, ...state.agents.agents.map((agent) => ({
        name: mailText(agent.agent_name),
        value: agent.agent_name,
        description: `${String(agent.unread_deliveries)} unread \xB7 ${String(agent.unacked_deliveries)} awaiting ack \xB7 ${agent.active ? "active" : "offline"}`
      }))];
    return state.inbox.pending.map((mail) => ({
      name: `${mail.read ? "  " : "\u25CF "}${mailText(mail.subject)}`,
      value: mail.conversation_id,
      description: `${mailText(mail.author_agent_name)} \u2192 ${mailText(mail.recipient_agent_name)} \xB7 ${mailText(mail.sent_at)}${mail.acknowledgement_required && !mail.acknowledged ? " \xB7 ACK NEEDED" : ""}`
    }));
  });
  const truncated = () => state.mode === "agents" ? state.agents.truncated : state.inbox.truncated;
  props.context.keymap.layer(() => ({
    enabled: () => props.focused,
    commands: [{
      bind: "escape",
      run: back
    }, {
      bind: "r",
      run: model.refresh
    }, {
      bind: "u",
      enabled: () => state.mode === "inbox",
      run: model.toggleUnread
    }, {
      bind: "n",
      enabled: () => state.mode === "thread" && !state.loading,
      run: model.next
    }, {
      bind: "f",
      run: () => props.fullscreen?.()
    }]
  }));
  return (() => {
    var _el$ = _$createElement("box"), _el$2 = _$createElement("box"), _el$3 = _$createElement("text"), _el$4 = _$createTextNode(`BLACKBIRD / `), _el$5 = _$createElement("text"), _el$7 = _$createElement("text"), _el$8 = _$createElement("box"), _el$9 = _$createElement("text"), _el$19 = _$createElement("text");
    _$insertNode(_el$, _el$2);
    _$insertNode(_el$, _el$7);
    _$insertNode(_el$, _el$8);
    _$insertNode(_el$, _el$19);
    _$use((value) => {
      root = value;
    }, _el$);
    _$setProp(_el$, "id", "blackbird-mailbox");
    _$setProp(_el$, "flexDirection", "column");
    _$setProp(_el$, "flexGrow", 1);
    _$setProp(_el$, "minHeight", 0);
    _$setProp(_el$, "paddingX", 1);
    _$setProp(_el$, "border", true);
    _$insertNode(_el$2, _el$3);
    _$insertNode(_el$2, _el$5);
    _$setProp(_el$2, "flexDirection", "row");
    _$setProp(_el$2, "justifyContent", "space-between");
    _$setProp(_el$2, "paddingY", 1);
    _$insertNode(_el$3, _el$4);
    _$setProp(_el$3, "fg", accent);
    _$setProp(_el$3, "flexShrink", 1);
    _$setProp(_el$3, "wrapMode", "word");
    _$insert(_el$3, (() => {
      var _c$ = _$memo(() => state.mode === "agents");
      return () => _c$() ? "Mailboxes" : mailText(state.agent || "All mailboxes");
    })(), null);
    _$insertNode(_el$5, _$createTextNode(`[esc] Back`));
    _$setProp(_el$5, "id", "blackbird-back");
    _$setProp(_el$5, "onMouseUp", () => {
      back();
    });
    _$setProp(_el$7, "wrapMode", "word");
    _$insert(_el$7, () => mailText(props.directory));
    _$insertNode(_el$8, _el$9);
    _$setProp(_el$8, "flexDirection", "row");
    _$setProp(_el$8, "gap", 2);
    _$setProp(_el$8, "paddingY", 1);
    _$insertNode(_el$9, _$createTextNode(`[r] Refresh`));
    _$setProp(_el$9, "id", "blackbird-refresh");
    _$setProp(_el$9, "onMouseUp", () => {
      model.refresh();
    });
    _$setProp(_el$9, "fg", accent);
    _$insert(_el$8, _$createComponent(Show, {
      get when() {
        return state.mode === "inbox";
      },
      get children() {
        var _el$1 = _$createElement("text"), _el$10 = _$createTextNode(`[u] `);
        _$insertNode(_el$1, _el$10);
        _$setProp(_el$1, "id", "blackbird-unread");
        _$setProp(_el$1, "onMouseUp", () => {
          model.toggleUnread();
        });
        _$setProp(_el$1, "fg", accent);
        _$insert(_el$1, () => state.unread ? "Unread only" : "All mail", null);
        return _el$1;
      }
    }), null);
    _$insert(_el$8, _$createComponent(Show, {
      get when() {
        return props.fullscreen;
      },
      get children() {
        var _el$11 = _$createElement("text");
        _$insertNode(_el$11, _$createTextNode(`[f] Expand`));
        _$setProp(_el$11, "onMouseUp", () => props.fullscreen?.());
        _$setProp(_el$11, "fg", accent);
        return _el$11;
      }
    }), null);
    _$insert(_el$, _$createComponent(Show, {
      get when() {
        return _$memo(() => !!!state.loading)() && !state.error;
      },
      get fallback() {
        return (() => {
          var _el$21 = _$createElement("text");
          _$insert(_el$21, () => state.error || "Loading mail\u2026");
          _$effect((_$p) => _$setProp(_el$21, "fg", theme.text.muted, _$p));
          return _el$21;
        })();
      },
      get children() {
        return _$createComponent(Show, {
          get when() {
            return state.mode === "thread";
          },
          get fallback() {
            return [_$createComponent(Show, {
              get when() {
                return options().length > 0;
              },
              get fallback() {
                return (() => {
                  var _el$25 = _$createElement("text");
                  _$insertNode(_el$25, _$createTextNode(`No messages in this view.`));
                  _$effect((_$p) => _$setProp(_el$25, "fg", theme.text.muted, _$p));
                  return _el$25;
                })();
              },
              get children() {
                var _el$22 = _$createElement("select");
                _$setProp(_el$22, "id", "blackbird-list");
                _$setProp(_el$22, "flexGrow", 1);
                _$setProp(_el$22, "minHeight", 0);
                _$setProp(_el$22, "showDescription", true);
                _$setProp(_el$22, "selectedTextColor", accent);
                _$setProp(_el$22, "onSelect", (_index, option) => {
                  if (!option)
                    return;
                  const value = String(option.value);
                  state.mode === "agents" ? model.inbox(value) : model.thread(value);
                });
                _$effect((_p$) => {
                  var _v$6 = props.focused, _v$7 = options(), _v$8 = theme.background.base, _v$9 = theme.text.base, _v$0 = theme.background.raised.base;
                  _v$6 !== _p$.e && (_p$.e = _$setProp(_el$22, "focused", _v$6, _p$.e));
                  _v$7 !== _p$.t && (_p$.t = _$setProp(_el$22, "options", _v$7, _p$.t));
                  _v$8 !== _p$.a && (_p$.a = _$setProp(_el$22, "backgroundColor", _v$8, _p$.a));
                  _v$9 !== _p$.o && (_p$.o = _$setProp(_el$22, "textColor", _v$9, _p$.o));
                  _v$0 !== _p$.i && (_p$.i = _$setProp(_el$22, "selectedBackgroundColor", _v$0, _p$.i));
                  return _p$;
                }, {
                  e: undefined,
                  t: undefined,
                  a: undefined,
                  o: undefined,
                  i: undefined
                });
                return _el$22;
              }
            }), _$createComponent(Show, {
              get when() {
                return truncated();
              },
              get children() {
                var _el$23 = _$createElement("text");
                _$insertNode(_el$23, _$createTextNode(`Showing the newest 256 entries. Narrow to a mailbox or unread mail.`));
                _$effect((_$p) => _$setProp(_el$23, "fg", theme.text.muted, _$p));
                return _el$23;
              }
            })];
          },
          get children() {
            return [(() => {
              var _el$13 = _$createElement("scrollbox");
              _$setProp(_el$13, "id", "blackbird-thread");
              _$setProp(_el$13, "flexGrow", 1);
              _$setProp(_el$13, "minHeight", 0);
              _$insert(_el$13, _$createComponent(Show, {
                get when() {
                  return state.thread.messages.length;
                },
                get fallback() {
                  return (() => {
                    var _el$27 = _$createElement("text");
                    _$insertNode(_el$27, _$createTextNode(`No messages in this thread.`));
                    return _el$27;
                  })();
                },
                get children() {
                  return _$createComponent(For, {
                    get each() {
                      return state.thread.messages;
                    },
                    children: (mail) => (() => {
                      var _el$29 = _$createElement("box"), _el$30 = _$createElement("text"), _el$31 = _$createElement("text"), _el$32 = _$createTextNode(` \xB7 `), _el$33 = _$createElement("text");
                      _$insertNode(_el$29, _el$30);
                      _$insertNode(_el$29, _el$31);
                      _$insertNode(_el$29, _el$33);
                      _$setProp(_el$29, "flexDirection", "column");
                      _$setProp(_el$29, "paddingBottom", 2);
                      _$setProp(_el$30, "fg", accent);
                      _$setProp(_el$30, "wrapMode", "word");
                      _$insert(_el$30, () => mailText(mail.subject));
                      _$insertNode(_el$31, _el$32);
                      _$setProp(_el$31, "wrapMode", "word");
                      _$insert(_el$31, () => mailText(mail.author_agent_name), _el$32);
                      _$insert(_el$31, () => mailText(mail.sent_at), null);
                      _$setProp(_el$33, "wrapMode", "word");
                      _$insert(_el$33, () => mailText(mail.body));
                      _$effect((_p$) => {
                        var _v$1 = theme.text.muted, _v$10 = theme.text.base;
                        _v$1 !== _p$.e && (_p$.e = _$setProp(_el$31, "fg", _v$1, _p$.e));
                        _v$10 !== _p$.t && (_p$.t = _$setProp(_el$33, "fg", _v$10, _p$.t));
                        return _p$;
                      }, {
                        e: undefined,
                        t: undefined
                      });
                      return _el$29;
                    })()
                  });
                }
              }));
              _$effect((_$p) => _$setProp(_el$13, "focused", props.focused, _$p));
              return _el$13;
            })(), (() => {
              var _el$14 = _$createElement("box");
              _$setProp(_el$14, "flexDirection", "row");
              _$setProp(_el$14, "gap", 2);
              _$insert(_el$14, _$createComponent(Show, {
                get when() {
                  return state.after > 0;
                },
                get children() {
                  var _el$15 = _$createElement("text");
                  _$insertNode(_el$15, _$createTextNode(`First page`));
                  _$setProp(_el$15, "id", "blackbird-first");
                  _$setProp(_el$15, "onMouseUp", () => {
                    model.first();
                  });
                  _$setProp(_el$15, "fg", accent);
                  return _el$15;
                }
              }), null);
              _$insert(_el$14, _$createComponent(Show, {
                get when() {
                  return state.thread.has_more;
                },
                get children() {
                  var _el$17 = _$createElement("text");
                  _$insertNode(_el$17, _$createTextNode(`[n] Next page`));
                  _$setProp(_el$17, "id", "blackbird-next");
                  _$setProp(_el$17, "onMouseUp", () => {
                    model.next();
                  });
                  _$setProp(_el$17, "fg", accent);
                  return _el$17;
                }
              }), null);
              return _el$14;
            })()];
          }
        });
      }
    }), _el$19);
    _$insertNode(_el$19, _$createTextNode(`\u2191\u2193 Navigate \xB7 Enter Open \xB7 Browsing leaves receipts unchanged`));
    _$setProp(_el$19, "paddingY", 1);
    _$setProp(_el$19, "wrapMode", "word");
    _$effect((_p$) => {
      var _v$ = theme.border.base, _v$2 = theme.background.base, _v$3 = theme.text.muted, _v$4 = theme.text.muted, _v$5 = theme.text.muted;
      _v$ !== _p$.e && (_p$.e = _$setProp(_el$, "borderColor", _v$, _p$.e));
      _v$2 !== _p$.t && (_p$.t = _$setProp(_el$, "backgroundColor", _v$2, _p$.t));
      _v$3 !== _p$.a && (_p$.a = _$setProp(_el$5, "fg", _v$3, _p$.a));
      _v$4 !== _p$.o && (_p$.o = _$setProp(_el$7, "fg", _v$4, _p$.o));
      _v$5 !== _p$.i && (_p$.i = _$setProp(_el$19, "fg", _v$5, _p$.i));
      return _p$;
    }, {
      e: undefined,
      t: undefined,
      a: undefined,
      o: undefined,
      i: undefined
    });
    return _el$;
  })();
}

// src/tui.tsx
function connection(context, location = context.location ?? context.data.location.default()) {
  const rpc = context.client.rpc(Mail);
  return {
    directory: location.directory,
    reader: {
      agents: (signal) => rpc.agents({}, {
        location,
        signal
      }),
      inbox: (input, signal) => rpc.inbox(input, {
        location,
        signal
      }),
      thread: (input, signal) => rpc.thread(input, {
        location,
        signal
      })
    }
  };
}
function SessionMailbox(props) {
  const [synced, {
    refetch
  }] = createResource(() => props.panel.sessionID, (id) => props.context.data.session.sync(id));
  const location = () => props.context.data.session.get(props.panel.sessionID)?.location;
  props.context.keymap.layer(() => ({
    enabled: () => props.panel.focused && !location(),
    commands: [{
      bind: "r",
      run: () => {
        refetch();
      }
    }, {
      bind: "escape",
      run: props.panel.close
    }]
  }));
  return _$createComponent2(Show2, {
    get when() {
      return location();
    },
    keyed: true,
    get fallback() {
      return (() => {
        var _el$ = _$createElement2("text");
        _$insert2(_el$, () => synced.error ? "Session unavailable. Press r to retry." : "Loading workspace\u2026");
        return _el$;
      })();
    },
    children: (value) => _$createComponent2(MailboxView, _$mergeProps({
      get context() {
        return props.context;
      }
    }, () => connection(props.context, value), {
      get focused() {
        return props.panel.focused;
      },
      get close() {
        return props.panel.close;
      },
      get fullscreen() {
        return props.panel.toggleFullscreen;
      }
    }))
  });
}
function toggle(context) {
  if (context.ui.panel.current()?.name === "blackbird.mail") {
    context.ui.panel.close();
    return;
  }
  if (context.ui.panel.open("blackbird.mail"))
    return;
  const route = context.ui.router.current();
  if (route.type === "plugin" && route.name === "blackbird.mail") {
    context.ui.router.navigate({
      type: "home"
    });
    return;
  }
  context.ui.router.navigate({
    type: "plugin",
    name: "blackbird.mail"
  });
}
var tui_default = Plugin.define({
  id: "phall1.blackbird.tui",
  setup(context) {
    const page = context.ui.router.register({
      name: "blackbird.mail",
      render: () => _$createComponent2(MailboxView, _$mergeProps({
        context
      }, () => connection(context), {
        focused: true,
        close: () => context.ui.router.navigate({
          type: "home"
        })
      }))
    });
    const panel = context.ui.slot({
      append: "session.panel",
      render: (panel) => _$createComponent2(Show2, {
        get when() {
          return panel.name === "blackbird.mail";
        },
        get children() {
          return _$createComponent2(SessionMailbox, {
            context,
            panel
          });
        }
      })
    });
    const commands = context.ui.slot({
      append: "app",
      render: () => {
        context.keymap.layer(() => ({
          mode: "global",
          commands: [{
            id: "blackbird.mail",
            title: "Toggle Blackbird mailboxes",
            group: "Blackbird",
            palette: true,
            slash: {
              name: "blackbird",
              aliases: ["mail"]
            },
            run: () => toggle(context)
          }]
        }));
        return null;
      }
    });
    return () => {
      commands();
      panel();
      page();
    };
  }
});
export {
  tui_default as default
};
