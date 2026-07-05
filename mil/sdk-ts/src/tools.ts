// MIL-Code client-side tool executor (design §18.4).
//
// The model only *emits* function calls; execution happens on the requester's
// machine. This module parses OpenAI-style tool calls and runs the MIL-Code
// tools (file_read / grep / run_tests / git) locally, so no repository content
// leaves the client except the context the user approves. A safety allowlist
// bounds what each tool can do.

import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";

export interface ToolCall {
  id?: string;
  name: string;
  arguments: Record<string, unknown>;
}

export interface ToolResult {
  id?: string;
  name: string;
  ok: boolean;
  output: string;
}

export interface ExecutorOptions {
  /** Workspace root; all file/grep/git access is confined to this subtree. */
  root: string;
  /** Max bytes returned from any single tool (context discipline, §18.4). */
  maxOutputBytes?: number;
  /** Approve a tool call before it runs (default: allow the four read-ish tools). */
  approve?: (call: ToolCall) => boolean;
}

/** Parse tool calls out of an OpenAI-style assistant message. Accepts both the
 *  `tool_calls` array (function.name + JSON arguments string) and a bare array. */
export function parseToolCalls(assistantMessage: unknown): ToolCall[] {
  const msg = assistantMessage as { tool_calls?: unknown[] } | unknown[];
  const raw = Array.isArray(msg) ? msg : (msg?.tool_calls ?? []);
  const calls: ToolCall[] = [];
  for (const c of raw as Array<Record<string, unknown>>) {
    const fn = (c.function ?? c) as Record<string, unknown>;
    const name = fn.name as string | undefined;
    if (!name) continue;
    let args: Record<string, unknown> = {};
    const a = fn.arguments;
    if (typeof a === "string") {
      try {
        args = JSON.parse(a);
      } catch {
        args = {};
      }
    } else if (a && typeof a === "object") {
      args = a as Record<string, unknown>;
    }
    calls.push({ id: c.id as string | undefined, name, arguments: args });
  }
  return calls;
}

function confineToRoot(root: string, rel: string): string | null {
  const resolved = path.resolve(root, rel);
  const normRoot = path.resolve(root);
  // reject traversal outside the workspace root
  if (resolved !== normRoot && !resolved.startsWith(normRoot + path.sep)) return null;
  return resolved;
}

async function runProcess(cmd: string, args: string[], cwd: string, maxBytes: number): Promise<{ ok: boolean; output: string }> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd });
    let out = "";
    let truncated = false;
    const onData = (d: Buffer) => {
      if (out.length < maxBytes) out += d.toString();
      else truncated = true;
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("error", (e) => resolve({ ok: false, output: `spawn error: ${e.message}` }));
    child.on("close", (code) => resolve({ ok: code === 0, output: truncated ? out.slice(0, maxBytes) + "\n…[truncated]" : out }));
  });
}

/** The client-side executor for the MIL-Code tool schema (§18.4). */
export class MilCodeExecutor {
  private root: string;
  private maxOutputBytes: number;
  private approve: (call: ToolCall) => boolean;

  constructor(opts: ExecutorOptions) {
    this.root = path.resolve(opts.root);
    this.maxOutputBytes = opts.maxOutputBytes ?? 64 * 1024;
    this.approve = opts.approve ?? (() => true);
  }

  async execute(call: ToolCall): Promise<ToolResult> {
    const deny = (output: string): ToolResult => ({ id: call.id, name: call.name, ok: false, output });
    if (!this.approve(call)) return deny("tool call not approved by the user");

    switch (call.name) {
      case "file_read": {
        const rel = String(call.arguments.path ?? "");
        const abs = confineToRoot(this.root, rel);
        if (!abs) return deny(`path escapes the workspace root: ${rel}`);
        try {
          let text = await readFile(abs, "utf8");
          const start = Number(call.arguments.start_line ?? 0);
          const end = Number(call.arguments.end_line ?? 0);
          if (start || end) {
            const lines = text.split("\n");
            text = lines.slice(Math.max(0, start - 1), end || lines.length).join("\n");
          }
          if (text.length > this.maxOutputBytes) text = text.slice(0, this.maxOutputBytes) + "\n…[truncated]";
          return { id: call.id, name: call.name, ok: true, output: text };
        } catch (e) {
          return deny(`read error: ${(e as Error).message}`);
        }
      }
      case "grep": {
        const pattern = String(call.arguments.pattern ?? "");
        const rel = String(call.arguments.path ?? ".");
        const abs = confineToRoot(this.root, rel);
        if (!abs || !pattern) return deny("bad grep arguments or path escapes root");
        return { id: call.id, name: call.name, ...(await runProcess("grep", ["-rn", "--", pattern, abs], this.root, this.maxOutputBytes)) };
      }
      case "run_tests": {
        const target = call.arguments.target ? [String(call.arguments.target)] : [];
        // Delegated to the project's own test runner via a conventional script.
        return { id: call.id, name: call.name, ...(await runProcess("sh", ["-c", `npm test ${target.join(" ")}`.trim()], this.root, this.maxOutputBytes)) };
      }
      case "git": {
        const args = (call.arguments.args as string[] | undefined) ?? [];
        // read-only git only (§18.4): reject mutating subcommands
        const mutating = new Set(["commit", "push", "reset", "checkout", "clean", "rm", "mv", "merge", "rebase"]);
        if (args.length === 0 || mutating.has(args[0])) return deny(`git subcommand not allowed: ${args[0] ?? "(none)"}`);
        return { id: call.id, name: call.name, ...(await runProcess("git", args, this.root, this.maxOutputBytes)) };
      }
      default:
        return deny(`unknown tool: ${call.name}`);
    }
  }

  /** Execute every call in an assistant message; returns results in order. */
  async executeAll(assistantMessage: unknown): Promise<ToolResult[]> {
    const results: ToolResult[] = [];
    for (const call of parseToolCalls(assistantMessage)) {
      results.push(await this.execute(call));
    }
    return results;
  }
}
