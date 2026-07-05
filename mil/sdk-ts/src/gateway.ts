// Untrusted gateway router (design §14.2).
//
// A hosted entry point that does matching + ciphertext relay ONLY. Because the
// PQ channel terminates client↔enclave, the gateway holds no plaintext and no
// session keys — it is not a trust point (§14.2). Its value is NAT/mobile
// reachability and implementation convenience: a client that cannot dial a
// provider directly connects to the gateway, which splices the two TCP streams
// together verbatim. The gateway can also serve the provider offer board so a
// thin client need not read the chain itself.

import net from "node:net";
import { selectCheapest, type MatchCriteria, type ProviderOffer } from "./registry.ts";

export interface GatewayOptions {
  /** Port the gateway listens on. */
  port: number;
  host?: string;
  /** The provider offer board the gateway advertises (§6.2). */
  offers: ProviderOffer[];
}

// A tiny control-line framing the client sends first: one JSON line ending in
// '\n' selecting the target, then the raw MIL channel bytes flow through.
interface RouteRequest {
  // Either an explicit target or matching criteria for the gateway to choose.
  target?: { host: string; port: number };
  criteria?: MatchCriteria & { modelId: string };
}

/** The untrusted relay gateway. */
export class MilGateway {
  private server: net.Server | null = null;
  private opts: GatewayOptions;
  constructor(opts: GatewayOptions) {
    this.opts = opts;
  }

  /** Resolve the upstream provider for a route request (matching or explicit). */
  resolveTarget(req: RouteRequest): { host: string; port: number } | null {
    if (req.target) return req.target;
    if (req.criteria) {
      const chosen = selectCheapest(this.opts.offers, req.criteria);
      if (chosen) return { host: chosen.host, port: chosen.port };
    }
    return null;
  }

  start(): Promise<{ port: number }> {
    return new Promise((resolve, reject) => {
      const server = net.createServer((client) => this.onClient(client));
      server.on("error", reject);
      server.listen(this.opts.port, this.opts.host ?? "0.0.0.0", () => {
        const addr = server.address();
        resolve({ port: typeof addr === "object" && addr ? addr.port : this.opts.port });
      });
      this.server = server;
    });
  }

  stop(): void {
    this.server?.close();
    this.server = null;
  }

  private onClient(client: net.Socket): void {
    // Read exactly one newline-terminated JSON route line, then splice.
    let header = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      header = Buffer.concat([header, chunk]);
      const nl = header.indexOf(0x0a);
      if (nl < 0) {
        if (header.length > 64 * 1024) client.destroy(); // header too large
        return;
      }
      client.off("data", onData);
      const line = header.subarray(0, nl).toString("utf8");
      const rest = header.subarray(nl + 1); // any channel bytes already buffered

      let req: RouteRequest;
      try {
        req = JSON.parse(line);
      } catch {
        client.destroy();
        return;
      }
      const target = this.resolveTarget(req);
      if (!target) {
        client.destroy();
        return;
      }
      this.splice(client, target, rest);
    };
    client.on("data", onData);
    client.on("error", () => client.destroy());
  }

  // Open the upstream and pipe both directions verbatim. The gateway never
  // decodes frames — it moves opaque ciphertext (§14.2, no trust).
  private splice(client: net.Socket, target: { host: string; port: number }, prebuffered: Buffer): void {
    const upstream = net.connect(target, () => {
      if (prebuffered.length) upstream.write(prebuffered);
      client.pipe(upstream);
      upstream.pipe(client);
    });
    upstream.on("error", () => client.destroy());
    client.on("error", () => upstream.destroy());
    client.on("close", () => upstream.destroy());
    upstream.on("close", () => client.destroy());
  }
}

/** Encode the one-line route header a client sends before the channel bytes. */
export function encodeRouteHeader(req: RouteRequest): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(req) + "\n");
}
