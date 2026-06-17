/**
 * ============================================================
 *  mockRiskOracle.ts
 *  CyberSafe Escrow — Backend Risk Oracle Service
 *
 *  PURPOSE
 *  ───────
 *  This service simulates the off-chain risk-evaluation step of the
 *  CyberSafe Escrow protocol. In production it would be a hardened
 *  microservice running inside a TEE (Trusted Execution Environment)
 *  or behind a multisig relay, but for the prototype / accelerator
 *  demo it runs as a standalone Node.js script.
 *
 *  FLOW (matches smart contract lifecycle)
 *  ───────────────────────────────────────
 *  1. Frontend emits a "new trade" event with the buyer's wallet address.
 *  2. This service picks up the event (via Alchemy webhook / polling).
 *  3. It calls scanWalletRisk() to derive isRiskFlagged (boolean).
 *  4. It then calls setRiskFlag() on the smart contract with the result.
 *  5. The smart contract either:
 *       – stays ACTIVE (clean wallet) → normal trade proceeds
 *       – moves to HELD   (risky wallet) → 72-hour isolation hold begins
 *
 *  HEURISTICS USED (mockable → replace with real indexer in production)
 *  ───────────────────────────────────────────────────────────────────
 *  A. Tornado Cash interaction  → flag
 *  B. Sanctioned address (OFAC) → flag
 *  C. Wallet age < 7 days       → flag
 *  D. Rapid fund cycling (> 10 outbound txns in < 1 hour) → flag
 *  E. Zero on-chain history (dust wallet)  → flag
 *
 *  DEPENDENCIES
 *  ────────────
 *  npm install alchemy-sdk ethers dotenv
 * ============================================================
 */

import { Alchemy, Network, AssetTransfersCategory } from "alchemy-sdk";
import { ethers } from "ethers";
import * as dotenv from "dotenv";

dotenv.config();

// ─── Environment validation ───────────────────────────────────────────────────
const {
  ALCHEMY_API_KEY,
  ORACLE_PRIVATE_KEY,
  ESCROW_CONTRACT_ADDRESS,
  RPC_URL,
} = process.env;

if (!ALCHEMY_API_KEY || !ORACLE_PRIVATE_KEY || !ESCROW_CONTRACT_ADDRESS || !RPC_URL) {
  throw new Error(
    "Missing env vars: ALCHEMY_API_KEY, ORACLE_PRIVATE_KEY, ESCROW_CONTRACT_ADDRESS, RPC_URL"
  );
}

// ─── Alchemy SDK (used for wallet history queries) ────────────────────────────
const alchemy = new Alchemy({
  apiKey: ALCHEMY_API_KEY,
  network: Network.ARB_MAINNET, // Switch to ARB_SEPOLIA for testnet
});

// ─── Ethers provider + oracle signer (sends setRiskFlag tx) ──────────────────
const provider = new ethers.JsonRpcProvider(RPC_URL);
const oracleSigner = new ethers.Wallet(ORACLE_PRIVATE_KEY, provider);

// ─── Minimal ABI — only the functions the oracle calls ───────────────────────
const ESCROW_ABI = [
  "event TradeInitiated(uint256 indexed tradeId, address indexed buyer, address indexed seller, uint256 amount, uint256 fee)",
  "function setRiskFlag(uint256 tradeId, bool flagged) external",
  "function getTrade(uint256 tradeId) external view returns (tuple(address buyer, address seller, uint256 amount, uint256 fee, uint256 createdAt, uint256 holdExpiresAt, uint8 state, bool buyerConfirmed, bool riskFlagged))",
];

const escrowContract = new ethers.Contract(
  ESCROW_CONTRACT_ADDRESS,
  ESCROW_ABI,
  oracleSigner
);

// ─── Known risky addresses (MOCK — replace with live OFAC / Chainalysis feed) ─
const SANCTIONED_ADDRESSES = new Set<string>([
  "0x8589427373d6d84e98730d7795d8f6f8731fda16", // Tornado Cash router (example)
  "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b", // Example OFAC SDN address
]);

const TORNADO_CASH_CONTRACTS = new Set<string>([
  "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",
  "0xa160cdab225685da1d56aa342ad8841c3b53f291",
]);

// ══════════════════════════════════════════════════════════════════════════════
//  CORE RISK EVALUATION FUNCTION
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Scan a wallet address and return a risk assessment.
 *
 * @param walletAddress  The buyer's Ethereum address to evaluate
 * @returns              RiskResult object with boolean flag and human-readable reasons
 */
export interface RiskResult {
  isRiskFlagged: boolean;
  reasons: string[];
  walletAge: number;         // Days since first on-chain transaction
  totalTransactions: number;
}

export async function scanWalletRisk(walletAddress: string): Promise<RiskResult> {
  const normalizedAddress = walletAddress.toLowerCase();
  const reasons: string[] = [];

  console.log(`\n[Oracle] Scanning wallet: ${walletAddress}`);

  // ── Heuristic A: Sanctioned address check ─────────────────────────────────
  if (SANCTIONED_ADDRESSES.has(normalizedAddress)) {
    console.warn("  [!] SANCTIONED address detected");
    reasons.push("Address appears on sanctions list (OFAC/SDN mock)");
    // Short-circuit — no need to run further checks
    return { isRiskFlagged: true, reasons, walletAge: 0, totalTransactions: 0 };
  }

  // ── Fetch full transaction history via Alchemy ────────────────────────────
  // We use the Asset Transfers API because it gives us structured data
  // about both ERC-20 and native ETH transfers, which is faster than
  // parsing raw tx receipts.
  let allTransfers: Awaited<ReturnType<typeof alchemy.core.getAssetTransfers>>["transfers"] = [];

  try {
    const [inbound, outbound] = await Promise.all([
      alchemy.core.getAssetTransfers({
        toAddress:   walletAddress,
        category:    [AssetTransfersCategory.ERC20, AssetTransfersCategory.EXTERNAL],
        withMetadata: true,
        maxCount:    100,
      }),
      alchemy.core.getAssetTransfers({
        fromAddress: walletAddress,
        category:    [AssetTransfersCategory.ERC20, AssetTransfersCategory.EXTERNAL],
        withMetadata: true,
        maxCount:    100,
      }),
    ]);

    allTransfers = [...inbound.transfers, ...outbound.transfers];
  } catch (err) {
    // ── MOCK FALLBACK (when Alchemy key has no real data / testnet) ──────────
    // Simulate a wallet with 3 transactions and 30 days of age for demo purposes
    console.warn("  [!] Alchemy call failed — using mock data:", (err as Error).message);
    return _mockRiskEvaluation(walletAddress);
  }

  // ── Heuristic E: Zero on-chain history (dust wallet) ─────────────────────
  if (allTransfers.length === 0) {
    reasons.push("No on-chain history found (potential dust wallet)");
    return { isRiskFlagged: true, reasons, walletAge: 0, totalTransactions: 0 };
  }

  // ── Determine wallet age from earliest transaction ────────────────────────
  const timestamps = allTransfers
    .map((t) => new Date(t.metadata?.blockTimestamp ?? 0).getTime())
    .filter(Boolean)
    .sort((a, b) => a - b);

  const firstTxDate    = timestamps[0] ? new Date(timestamps[0]) : new Date();
  const walletAgeDays  = Math.floor(
    (Date.now() - firstTxDate.getTime()) / (1000 * 60 * 60 * 24)
  );

  console.log(`  Wallet age: ${walletAgeDays} days | Total transfers indexed: ${allTransfers.length}`);

  // ── Heuristic C: Wallet age < 7 days ─────────────────────────────────────
  if (walletAgeDays < 7) {
    reasons.push(`Wallet is very new (${walletAgeDays} days old — threshold: 7 days)`);
  }

  // ── Heuristic B: Tornado Cash interaction ─────────────────────────────────
  const hasTornadoInteraction = allTransfers.some(
    (t) =>
      TORNADO_CASH_CONTRACTS.has((t.to ?? "").toLowerCase()) ||
      TORNADO_CASH_CONTRACTS.has((t.from ?? "").toLowerCase())
  );
  if (hasTornadoInteraction) {
    reasons.push("Wallet has interacted with Tornado Cash mixing contracts");
  }

  // ── Heuristic D: Rapid fund cycling ──────────────────────────────────────
  // Count outbound transfers in the last 60 minutes
  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  const recentOutbound = allTransfers.filter(
    (t) =>
      t.from?.toLowerCase() === normalizedAddress &&
      new Date(t.metadata?.blockTimestamp ?? 0).getTime() > oneHourAgo
  );
  if (recentOutbound.length > 10) {
    reasons.push(
      `High-frequency cycling: ${recentOutbound.length} outbound txns in last 60 minutes`
    );
  }

  const isRiskFlagged = reasons.length > 0;

  if (isRiskFlagged) {
    console.warn(`  [FLAGGED] Reasons: ${reasons.join(" | ")}`);
  } else {
    console.log("  [CLEAN] No risk indicators found");
  }

  return {
    isRiskFlagged,
    reasons,
    walletAge:         walletAgeDays,
    totalTransactions: allTransfers.length,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  MOCK FALLBACK (for demos without live Alchemy data)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Returns deterministic mock results based on last byte of the address.
 * Addresses ending in 0–3 are flagged; 4–9 and a–f are clean.
 * This gives a ~25 % flag rate for demo variety.
 */
function _mockRiskEvaluation(walletAddress: string): RiskResult {
  const lastByte = parseInt(walletAddress.slice(-1), 16);
  const flagged  = lastByte <= 3;

  console.log(`  [MOCK] Deterministic result for demo: ${flagged ? "FLAGGED" : "CLEAN"}`);

  return {
    isRiskFlagged:     flagged,
    reasons:           flagged ? ["[MOCK] Simulated risk: address heuristic triggered"] : [],
    walletAge:         flagged ? 2 : 120,
    totalTransactions: flagged ? 5 : 87,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  ORACLE RELAY — posts result to smart contract
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Call setRiskFlag() on the escrow contract with the oracle result.
 *
 * @param tradeId        The escrow trade to flag
 * @param isRiskFlagged  Result from scanWalletRisk()
 */
async function submitFlagToContract(
  tradeId: number,
  isRiskFlagged: boolean
): Promise<string> {
  console.log(
    `\n[Oracle] Submitting flag to contract — tradeId=${tradeId}, flagged=${isRiskFlagged}`
  );

  try {
    const tx = await escrowContract.setRiskFlag(tradeId, isRiskFlagged);
    console.log(`  [Oracle] Tx submitted: ${tx.hash}`);
    const receipt = await tx.wait();
    console.log(`  [Oracle] Confirmed in block: ${receipt.blockNumber}`);
    return tx.hash;
  } catch (err) {
    console.error("  [Oracle] Contract call failed:", (err as Error).message);
    throw err;
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  EVENT LISTENER — watches for new TradeInitiated events
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Start listening for TradeInitiated events from the escrow contract and
 * automatically evaluate each new buyer wallet.
 *
 * In production: replace with a webhook from Alchemy Notify for reliability.
 */
export async function startOracleListener(): Promise<void> {
  console.log("═══════════════════════════════════════════════");
  console.log(" CyberSafe Risk Oracle — starting listener");
  console.log(`  Contract : ${ESCROW_CONTRACT_ADDRESS}`);
  console.log(`  Signer   : ${oracleSigner.address}`);
  console.log("═══════════════════════════════════════════════\n");

  escrowContract.on(
    "TradeInitiated",
    async (tradeId, buyer, seller, amount, fee, event) => {
      console.log(`\n[Event] TradeInitiated — tradeId=${tradeId.toString()}`);
      console.log(`  Buyer  : ${buyer}`);
      console.log(`  Seller : ${seller}`);
      console.log(`  Amount : ${ethers.formatUnits(amount, 6)} USDC`);

      try {
        // ── Off-chain evaluation ─────────────────────────────────────────────
        const riskResult = await scanWalletRisk(buyer);

        // ── On-chain submission ──────────────────────────────────────────────
        await submitFlagToContract(Number(tradeId), riskResult.isRiskFlagged);

        console.log(
          `[Oracle] Trade ${tradeId} processed. ` +
          `Risk: ${riskResult.isRiskFlagged ? "FLAGGED ⛔" : "CLEAN ✅"}`
        );
      } catch (err) {
        // Log but do not crash — the trade will remain in ACTIVE state
        // and can be manually reviewed via admin panel.
        console.error(
          `[Oracle] Failed to process tradeId=${tradeId}: ${(err as Error).message}`
        );
      }
    }
  );

  console.log("[Oracle] Listening for TradeInitiated events...\n");
}

// ══════════════════════════════════════════════════════════════════════════════
//  STANDALONE DEMO — run with: npx ts-node oracle/mockRiskOracle.ts
// ══════════════════════════════════════════════════════════════════════════════

async function runDemo(): Promise<void> {
  console.log("━━━ CyberSafe Oracle Demo (standalone scan) ━━━\n");

  const testWallets = [
    "0x8589427373d6d84e98730d7795d8f6f8731fda16", // Sanctioned → should flag
    "0xAbCdEf1234567890abcdef1234567890abcDEF12", // Random → mock result
    "0x000000000000000000000000000000000000dead", // Burn → should flag (no history)
  ];

  for (const wallet of testWallets) {
    const result = await scanWalletRisk(wallet);
    console.log("\nResult:", JSON.stringify(result, null, 2));
    console.log("─".repeat(50));
  }
}

// Entry point
if (require.main === module) {
  runDemo().catch(console.error);
}
