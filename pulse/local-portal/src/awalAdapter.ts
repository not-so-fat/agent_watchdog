// Awal (Agentic Wallet) adapter.
// NOTE: Agent code must NEVER import or call this module. It is for Local Portal only.

import { spawn } from "child_process";
import fs from "fs";
import path from "path";

const DEBUG_LOG_DIR = path.resolve(__dirname, "..", "..", ".temporal", "logs");
const AWAL_PAY_DEBUG_LOG = path.join(DEBUG_LOG_DIR, "awal-x402-pay-debug.log");

export type X402Challenge = {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string | null;
};

export type X402PaymentResult = {
  success: boolean;
  status?: number;
  headers?: Record<string, string>;
  body?: string;
  tx_hash?: string;
  /** Amount paid in atomic units, if the wallet reports it (e.g. from 402 PAYMENT-REQUIRED) */
  amount_atomic?: number;
  error_code?: string;
  error_message?: string;
};

export type WalletStatusResult = {
  authenticated: boolean;
  code: number;
  stdout: string;
  stderr: string;
  /** Short message for the user when not authenticated */
  message?: string;
};

export type WalletInfo = {
  authenticated: boolean;
  email?: string;
  address?: string;
  balances?: {
    USDC: string;
    ETH: string;
    WETH: string;
  };
};

export interface AwalAdapter {
  ensureAuthenticated(): Promise<void>;
  getWalletStatus(): Promise<WalletStatusResult>;
  getAddress(): Promise<string>;
  getBalance(): Promise<{ USDC: string; ETH: string; WETH: string }>;
  getWalletInfo(): Promise<WalletInfo>;
  payX402Challenge(challenge: X402Challenge): Promise<X402PaymentResult>;
}

function runCommand(cmd: string, args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d.toString();
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });
    child.on("close", (code) => {
      resolve({ code: code ?? 0, stdout, stderr });
    });
  });
}

class AwalAdapterImpl implements AwalAdapter {
  async ensureAuthenticated(): Promise<void> {
    const status = await this.getWalletStatus();
    if (!status.authenticated) {
      throw new Error(status.message || "Wallet not authenticated");
    }
  }

  async getWalletStatus(): Promise<WalletStatusResult> {
    const { code, stdout, stderr } = await runCommand("npx", ["awal@latest", "status"]);
    const combined = `${stdout}\n${stderr}`;
    // "awal status" can exit 0 even when output says "Not authenticated" (it reports state, not auth).
    // Treat as unauthenticated when the CLI output says so, so we don't report ready-for-payment when we're not.
    const notAuthenticatedInOutput =
      /\bnot authenticated\b/i.test(combined) || /⚠\s*Not authenticated/i.test(combined);
    const authenticated = code === 0 && !notAuthenticatedInOutput;
    const result: WalletStatusResult = {
      authenticated,
      code,
      stdout,
      stderr,
    };
    if (!authenticated) {
      result.message =
        "Wallet is not authenticated. Please run 'npx awal@latest status' in a terminal and follow the prompts to sign in.";
    }
    return result;
  }

  async getAddress(): Promise<string> {
    const { code, stdout, stderr } = await runCommand("npx", ["awal@latest", "address"]);
    if (code !== 0) {
      throw new Error(`Failed to get address: ${stderr || stdout}`);
    }
    // Parse address from output (format: "0x...")
    const match = stdout.match(/0x[a-fA-F0-9]{40}/);
    if (!match) {
      throw new Error(`Could not parse address from output: ${stdout}`);
    }
    return match[0];
  }

  async getBalance(): Promise<{ USDC: string; ETH: string; WETH: string }> {
    const { code, stdout, stderr } = await runCommand("npx", ["awal@latest", "balance", "--chain", "base-sepolia", "--json"]);
    if (code !== 0) {
      throw new Error(`Failed to get balance: ${stderr || stdout}`);
    }
    try {
      const parsed = JSON.parse(stdout);
      // The actual structure is: { balances: { USDC: { formatted: "..." }, ... } }
      const balances = parsed.balances || {};
      return {
        USDC: balances.USDC?.formatted ?? "0.00",
        ETH: balances.ETH?.formatted ?? "0.00",
        WETH: balances.WETH?.formatted ?? "0.00",
      };
    } catch (e) {
      // Fallback: try parsing text output if JSON fails
      const usdcMatch = stdout.match(/USDC[:\s]+\$?([\d.]+)/i);
      const ethMatch = stdout.match(/ETH[:\s]+([\d.]+)/i);
      const wethMatch = stdout.match(/WETH[:\s]+([\d.]+)/i);
      return {
        USDC: usdcMatch?.[1] ?? "0.00",
        ETH: ethMatch?.[1] ?? "0.00",
        WETH: wethMatch?.[1] ?? "0.00",
      };
    }
  }

  async getWalletInfo(): Promise<WalletInfo> {
    const status = await this.getWalletStatus();
    if (!status.authenticated) {
      return { authenticated: false };
    }

    // Extract email from status output
    const emailMatch = status.stdout.match(/Logged in as:\s*([^\s\n]+)/i);
    const email = emailMatch ? emailMatch[1] : undefined;

    let address: string | undefined;
    let balances: { USDC: string; ETH: string; WETH: string } | undefined;

    try {
      address = await this.getAddress();
    } catch (e) {
      // Address fetch failed, continue without it
    }

    try {
      balances = await this.getBalance();
    } catch (e) {
      // Balance fetch failed, continue without it
    }

    const result: WalletInfo = {
      authenticated: true,
    };
    if (email) result.email = email;
    if (address) result.address = address;
    if (balances) result.balances = balances;
    return result;
  }

  async payX402Challenge(
    challenge: X402Challenge
  ): Promise<X402PaymentResult> {
    const args: string[] = ["awal@latest", "x402", "pay", challenge.url];

    const method = (challenge.method || "GET").toUpperCase();
    args.push("-X", method);

    if (challenge.body) {
      args.push("-d", challenge.body);
    }

    if (challenge.headers && Object.keys(challenge.headers).length > 0) {
      args.push(
        "-h",
        JSON.stringify(challenge.headers)
      );
    }

    // Ask Awal to emit JSON so we can parse status/body/headers/tx info.
    args.push("--json");

    const { code, stdout, stderr } = await runCommand("npx", args);

    if (code !== 0) {
      const errorMessage = stderr || stdout || "awal x402 pay failed";
      try {
        fs.mkdirSync(DEBUG_LOG_DIR, { recursive: true });
        fs.appendFileSync(
          AWAL_PAY_DEBUG_LOG,
          JSON.stringify(
            {
              ts: new Date().toISOString(),
              url: challenge.url,
              method: challenge.method,
              code,
              stdout: stdout.slice(0, 2000),
              stderr: stderr.slice(0, 2000),
            },
            null,
            2
          ) + "\n"
        );
      } catch {
        // ignore logging errors
      }
      return {
        success: false,
        error_code: "AWAL_ERROR",
        error_message: errorMessage,
      };
    }

    try {
      const parsed = JSON.parse(stdout);
      // Extract tx_hash from payment response header (x402 protocol) if present.
      // Spec: PAYMENT-RESPONSE (https://docs.x402.org/core-concepts/http-402). Also support X-PAYMENT-RESPONSE for interoperability (e.g. NickelJoke).
      let tx_hash: string | undefined = parsed.tx_hash;
      if (!tx_hash && parsed.headers && typeof parsed.headers === "object") {
        const paymentResponseHeader =
          parsed.headers["PAYMENT-RESPONSE"] ??
          parsed.headers["payment-response"] ??
          parsed.headers["X-PAYMENT-RESPONSE"] ??
          parsed.headers["x-payment-response"];
        if (paymentResponseHeader) {
          try {
            const paymentResponse = JSON.parse(
              Buffer.from(paymentResponseHeader, "base64").toString("utf-8")
            );
            tx_hash = paymentResponse.transaction;
          } catch {
            // Failed to parse payment response header, continue without tx_hash
          }
        }
      }
      
      // Shape here depends on Agentic Wallet JSON schema; we keep it generic.
      const result: X402PaymentResult = {
        success: true,
        status: parsed.status,
        headers: parsed.headers,
        body: parsed.data || parsed.body,
      };
      if (tx_hash) {
        result.tx_hash = tx_hash;
      }
      // Pass through amount from wallet if present (payee price from 402 PAYMENT-REQUIRED)
      const amount =
        parsed.amount_atomic ??
        parsed.amount;
      if (typeof amount === "number" && !isNaN(amount) && amount > 0) {
        result.amount_atomic = amount;
      }
      return result;
    } catch (e) {
      return {
        success: false,
        error_code: "AWAL_PARSE_ERROR",
        error_message: (e as Error).message,
      };
    }
  }
}

export const awalAdapter: AwalAdapter = new AwalAdapterImpl();


