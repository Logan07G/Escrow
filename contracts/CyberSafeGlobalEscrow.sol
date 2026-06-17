// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
//  CyberSafeGlobalEscrow.sol
//  Network : EVM-compatible (primary target: Arbitrum One)
//  Token   : USDC (ERC-20, 6 decimals)
//
//  ARCHITECTURE OVERVIEW
//  ─────────────────────
//  1. Buyer calls initiateTrade() and deposits USDC into this contract.
//  2. The off-chain Risk Oracle evaluates the buyer's wallet history and
//     calls setRiskFlag() via a trusted ORACLE_ROLE address.
//  3. If flagged → a 72-hour programmatic isolation hold is activated.
//     If clean   → seller may call releaseFunds() immediately once
//                  the buyer marks the trade complete.
//  4. Either party may call disputeTrigger() to escalate to an arbiter.
//  5. The Arbiter (multisig in production) resolves disputes by calling
//     resolveDispute(), directing funds to buyer or seller.
//
//  ROLES
//  ─────
//  ADMIN_ROLE   – contract owner; can upgrade oracle address, pause, sweep stuck funds
//  ORACLE_ROLE  – backend risk service; only address allowed to set risk flags
//  ARBITER_ROLE – dispute resolver (DAO multisig in production)
// ============================================================

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

contract CyberSafeGlobalEscrow is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    // ─── Role constants ──────────────────────────────────────────────────────
    bytes32 public constant ORACLE_ROLE  = keccak256("ORACLE_ROLE");
    bytes32 public constant ARBITER_ROLE = keccak256("ARBITER_ROLE");

    // ─── Configurable constants ───────────────────────────────────────────────
    /// @notice Duration of the isolation hold when a risk flag is tripped (72 hours)
    uint256 public constant ISOLATION_HOLD_DURATION = 72 hours;

    /// @notice Platform fee in basis points (50 = 0.5%)
    uint256 public constant FEE_BPS = 50;
    uint256 private constant BPS_DENOMINATOR = 10_000;

    // ─── USDC token interface ─────────────────────────────────────────────────
    /// @notice The ERC-20 token accepted by this escrow (USDC on Arbitrum)
    IERC20 public immutable usdc;

    // ─── Trade state machine ──────────────────────────────────────────────────
    enum TradeState {
        NONE,       // Trade does not exist
        ACTIVE,     // Funds deposited; awaiting completion
        HELD,       // Risk flag triggered; 72-hour isolation hold active
        DISPUTED,   // Dispute raised; awaiting arbiter
        RELEASED,   // Funds released to seller — terminal state
        REFUNDED    // Funds returned to buyer — terminal state
    }

    // ─── Trade record ─────────────────────────────────────────────────────────
    struct Trade {
        address buyer;          // Depositor / payer
        address seller;         // Merchant / payee
        uint256 amount;         // Gross USDC amount deposited (6 decimals)
        uint256 fee;            // Platform fee deducted on release
        uint256 createdAt;      // Block timestamp of initiateTrade()
        uint256 holdExpiresAt;  // Non-zero only when state == HELD
        TradeState state;
        bool buyerConfirmed;    // Buyer has signalled delivery received
        bool riskFlagged;       // Oracle has flagged this trade
    }

    // ─── Storage ──────────────────────────────────────────────────────────────
    /// @dev tradeId → Trade; tradeId is a monotonically-increasing counter
    mapping(uint256 => Trade) public trades;
    uint256 public tradeCounter;

    /// @dev Accumulated platform fees claimable by ADMIN_ROLE
    uint256 public feeTreasury;

    // ─── Events ───────────────────────────────────────────────────────────────
    event TradeInitiated(
        uint256 indexed tradeId,
        address indexed buyer,
        address indexed seller,
        uint256 amount,
        uint256 fee
    );
    event RiskFlagSet(
        uint256 indexed tradeId,
        bool flagged,
        uint256 holdExpiresAt
    );
    event FundsReleased(
        uint256 indexed tradeId,
        address indexed seller,
        uint256 netAmount
    );
    event FundsRefunded(
        uint256 indexed tradeId,
        address indexed buyer,
        uint256 amount
    );
    event DisputeTriggered(
        uint256 indexed tradeId,
        address indexed raisedBy
    );
    event DisputeResolved(
        uint256 indexed tradeId,
        address indexed winner,
        uint256 amount
    );
    event FeesClaimed(address indexed admin, uint256 amount);

    // ─── Errors ───────────────────────────────────────────────────────────────
    error TradeNotFound(uint256 tradeId);
    error InvalidState(uint256 tradeId, TradeState current, TradeState required);
    error UnauthorizedCaller(address caller);
    error HoldNotExpired(uint256 tradeId, uint256 expiresAt);
    error ZeroAmount();
    error SelfTrade();

    // ─── Constructor ──────────────────────────────────────────────────────────
    /**
     * @param _usdc    USDC contract address on the target network
     *                 Arbitrum One: 0xaf88d065e77c8cC2239327C5EDb3A432268e5831
     * @param _oracle  Address of the backend risk oracle service
     * @param _arbiter Address of the dispute arbiter (multisig recommended)
     */
    constructor(address _usdc, address _oracle, address _arbiter) {
        require(_usdc    != address(0), "Zero USDC address");
        require(_oracle  != address(0), "Zero oracle address");
        require(_arbiter != address(0), "Zero arbiter address");

        usdc = IERC20(_usdc);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender); // ADMIN_ROLE = DEFAULT_ADMIN_ROLE
        _grantRole(ORACLE_ROLE,        _oracle);
        _grantRole(ARBITER_ROLE,       _arbiter);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  CORE TRADE LIFECYCLE
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Step 1 – Buyer initiates a trade by depositing USDC.
     *
     * @dev    The caller must have previously called usdc.approve(address(this), amount).
     *         The platform fee is reserved at this point; net amount is computed on release.
     *
     * @param  seller  Merchant wallet that will receive funds on successful completion
     * @param  amount  Gross USDC amount to deposit (minimum 1 USDC = 1_000_000 units)
     * @return tradeId Unique trade identifier for all subsequent calls
     *
     * FLOW:
     *   Buyer → approve(escrow, amount) → initiateTrade(seller, amount)
     *        → USDC locked in contract → Oracle evaluates wallet async
     */
    function initiateTrade(
        address seller,
        uint256 amount
    ) external nonReentrant whenNotPaused returns (uint256 tradeId) {
        if (amount == 0) revert ZeroAmount();
        if (seller == msg.sender) revert SelfTrade();
        if (seller == address(0)) revert UnauthorizedCaller(seller);

        // Calculate platform fee upfront so it is transparent at trade creation
        uint256 fee = (amount * FEE_BPS) / BPS_DENOMINATOR;

        // Pull USDC from buyer into escrow contract
        usdc.safeTransferFrom(msg.sender, address(this), amount);

        // Assign trade ID (pre-increment so IDs start at 1)
        tradeId = ++tradeCounter;

        trades[tradeId] = Trade({
            buyer:          msg.sender,
            seller:         seller,
            amount:         amount,
            fee:            fee,
            createdAt:      block.timestamp,
            holdExpiresAt:  0,
            state:          TradeState.ACTIVE,
            buyerConfirmed: false,
            riskFlagged:    false
        });

        emit TradeInitiated(tradeId, msg.sender, seller, amount, fee);
    }

    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Step 2 – Oracle sets the risk flag for a trade.
     *
     * @dev    Called by the backend risk service (ORACLE_ROLE) after scanning
     *         the buyer's wallet history off-chain.
     *         • If flagged=true  → state transitions to HELD; 72-hour clock starts.
     *         • If flagged=false → no state change; trade remains ACTIVE and can
     *           proceed to releaseFunds().
     *
     * @param  tradeId  The trade to evaluate
     * @param  flagged  true = risky wallet detected; false = wallet clean
     */
    function setRiskFlag(
        uint256 tradeId,
        bool flagged
    ) external onlyRole(ORACLE_ROLE) {
        Trade storage t = _requireTrade(tradeId);
        _requireState(tradeId, t.state, TradeState.ACTIVE);

        t.riskFlagged = flagged;

        if (flagged) {
            // ── ISOLATION HOLD: freeze funds for 72 hours ─────────────────────
            // During this period neither buyer nor seller can move funds.
            // Either party may call disputeTrigger() to escalate further.
            t.state          = TradeState.HELD;
            t.holdExpiresAt  = block.timestamp + ISOLATION_HOLD_DURATION;
        }

        emit RiskFlagSet(tradeId, flagged, t.holdExpiresAt);
    }

    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Step 3a – Buyer confirms delivery; then seller (or anyone) can
     *         call releaseFunds() to complete the trade.
     *
     * @dev    Separated from releaseFunds() so the seller cannot self-certify
     *         delivery. This mirrors real-world escrow acknowledgement.
     *
     * @param  tradeId  The active trade to confirm
     */
    function confirmDelivery(uint256 tradeId) external {
        Trade storage t = _requireTrade(tradeId);

        // Only buyer can confirm; only from ACTIVE state
        if (t.buyer != msg.sender) revert UnauthorizedCaller(msg.sender);
        _requireState(tradeId, t.state, TradeState.ACTIVE);

        t.buyerConfirmed = true;
    }

    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Step 3b – Release funds to seller after buyer confirmation.
     *
     * @dev    Callable by seller or ADMIN once buyerConfirmed == true.
     *         If the trade was held (HELD state), release is permitted after
     *         holdExpiresAt provided no dispute was raised.
     *
     *         Net amount = gross deposit − platform fee.
     *         Platform fee accumulates in feeTreasury for admin withdrawal.
     *
     * @param  tradeId  The trade to finalise
     */
    function releaseFunds(uint256 tradeId) external nonReentrant whenNotPaused {
        Trade storage t = _requireTrade(tradeId);

        // ── Authorization ─────────────────────────────────────────────────────
        bool isSellerOrAdmin = (msg.sender == t.seller ||
                                hasRole(DEFAULT_ADMIN_ROLE, msg.sender));
        if (!isSellerOrAdmin) revert UnauthorizedCaller(msg.sender);

        // ── State gate ────────────────────────────────────────────────────────
        if (t.state == TradeState.HELD) {
            // Allow release from HELD only after isolation hold expires
            if (block.timestamp < t.holdExpiresAt) {
                revert HoldNotExpired(tradeId, t.holdExpiresAt);
            }
            // Transition back to ACTIVE-equivalent for the release logic
            t.state = TradeState.ACTIVE;
        }
        _requireState(tradeId, t.state, TradeState.ACTIVE);

        // Buyer must have explicitly confirmed delivery
        require(t.buyerConfirmed, "Buyer has not confirmed delivery");

        // ── Fund disbursement ─────────────────────────────────────────────────
        uint256 netAmount = t.amount - t.fee;
        feeTreasury += t.fee;

        t.state = TradeState.RELEASED;

        // Transfer net USDC to seller (check-effects-interactions pattern)
        usdc.safeTransfer(t.seller, netAmount);

        emit FundsReleased(tradeId, t.seller, netAmount);
    }

    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Escalate a trade to dispute resolution.
     *
     * @dev    Either the buyer or seller may trigger a dispute from ACTIVE or
     *         HELD state. Once disputed, only ARBITER_ROLE can resolve.
     *         This is the primary consumer protection hook — a buyer can
     *         dispute during the 72-hour hold if they believe funds should
     *         be returned, or a seller can dispute if confirmDelivery is
     *         being withheld in bad faith.
     *
     * @param  tradeId  The trade to dispute
     */
    function disputeTrigger(uint256 tradeId) external {
        Trade storage t = _requireTrade(tradeId);

        // Only trade parties can raise a dispute
        if (msg.sender != t.buyer && msg.sender != t.seller) {
            revert UnauthorizedCaller(msg.sender);
        }

        // Disputes allowed from ACTIVE or HELD states only
        require(
            t.state == TradeState.ACTIVE || t.state == TradeState.HELD,
            "Trade not disputable in current state"
        );

        t.state = TradeState.DISPUTED;

        emit DisputeTriggered(tradeId, msg.sender);
    }

    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Arbiter resolves a disputed trade.
     *
     * @dev    ARBITER_ROLE directs the full escrowed amount (no fee on dispute
     *         resolution — good-faith gesture to affected party) to either
     *         the buyer or the seller.
     *
     *         In production: ARBITER_ROLE is a 3-of-5 Gnosis Safe multisig
     *         with off-chain deliberation process.
     *
     * @param  tradeId     The disputed trade
     * @param  favorSeller true → release to seller; false → refund to buyer
     */
    function resolveDispute(
        uint256 tradeId,
        bool favorSeller
    ) external nonReentrant onlyRole(ARBITER_ROLE) {
        Trade storage t = _requireTrade(tradeId);
        _requireState(tradeId, t.state, TradeState.DISPUTED);

        address winner;
        uint256 payout = t.amount; // Full amount returned; no fee on disputes

        if (favorSeller) {
            winner  = t.seller;
            t.state = TradeState.RELEASED;
            usdc.safeTransfer(t.seller, payout);
            emit FundsReleased(tradeId, t.seller, payout);
        } else {
            winner  = t.buyer;
            t.state = TradeState.REFUNDED;
            usdc.safeTransfer(t.buyer, payout);
            emit FundsRefunded(tradeId, t.buyer, payout);
        }

        emit DisputeResolved(tradeId, winner, payout);
    }

    // ──────────────────────────────────────────────────────────────────────────
    //  ADMIN FUNCTIONS
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * @notice Admin withdraws accumulated platform fees to treasury wallet.
     * @param  to  Destination address for fee USDC
     */
    function claimFees(address to) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        require(to != address(0), "Zero destination");
        uint256 amount = feeTreasury;
        require(amount > 0, "Nothing to claim");
        feeTreasury = 0;
        usdc.safeTransfer(to, amount);
        emit FeesClaimed(to, amount);
    }

    /// @notice Pause all state-changing operations (emergency circuit breaker)
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Resume operations after a pause
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ──────────────────────────────────────────────────────────────────────────
    //  VIEW HELPERS
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Fetch the full Trade record for a given tradeId
    function getTrade(uint256 tradeId) external view returns (Trade memory) {
        return trades[tradeId];
    }

    /**
     * @notice Check whether a HELD trade's isolation period has expired
     * @return expired  true if the 72-hour window has passed
     * @return remaining Seconds remaining on the hold (0 if expired)
     */
    function holdStatus(uint256 tradeId)
        external
        view
        returns (bool expired, uint256 remaining)
    {
        Trade storage t = _requireTrade(tradeId);
        if (t.state != TradeState.HELD) return (false, 0);
        if (block.timestamp >= t.holdExpiresAt) {
            return (true, 0);
        }
        return (false, t.holdExpiresAt - block.timestamp);
    }

    // ──────────────────────────────────────────────────────────────────────────
    //  INTERNAL HELPERS
    // ──────────────────────────────────────────────────────────────────────────

    function _requireTrade(uint256 tradeId)
        internal
        view
        returns (Trade storage t)
    {
        t = trades[tradeId];
        if (t.buyer == address(0)) revert TradeNotFound(tradeId);
    }

    function _requireState(
        uint256    tradeId,
        TradeState current,
        TradeState required
    ) internal pure {
        if (current != required) revert InvalidState(tradeId, current, required);
    }
}
