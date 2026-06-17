import { expect } from "chai";
import hre from "hardhat";

const { ethers } = await hre.network.create();

const TRADE_AMOUNT = 100_000_000n;

describe("CyberSafeGlobalEscrow", function () {
  async function deploy() {
    const [admin, oracle, arbiter, buyer, seller] = await ethers.getSigners();

    const usdc = await ethers.deployContract("MockERC20", ["USD Coin", "USDC", 6]);
    const escrow = await ethers.deployContract("CyberSafeGlobalEscrow", [
      await usdc.getAddress(),
      oracle.address,
      arbiter.address,
    ]);

    await usdc.mint(buyer.address, 1_000_000_000n);
    await usdc.connect(buyer).approve(await escrow.getAddress(), ethers.MaxUint256);

    return { escrow, usdc, admin, oracle, arbiter, buyer, seller };
  }

  it("locks USDC and emits TradeInitiated", async function () {
    const { escrow, usdc, buyer, seller } = await deploy();
    const before = await usdc.balanceOf(await escrow.getAddress());
    await expect(escrow.connect(buyer).initiateTrade(seller.address, TRADE_AMOUNT))
      .to.emit(escrow, "TradeInitiated");
    const after = await usdc.balanceOf(await escrow.getAddress());
    expect(after - before).to.equal(TRADE_AMOUNT);
  });

  it("oracle flags trade and activates 72hr hold", async function () {
    const { escrow, buyer, seller, oracle } = await deploy();
    await escrow.connect(buyer).initiateTrade(seller.address, TRADE_AMOUNT);
    await escrow.connect(oracle).setRiskFlag(1n, true);
    const trade = await escrow.getTrade(1n);
    expect(trade.state).to.equal(2n);
  });

  it("releases funds to seller after buyer confirms", async function () {
    const { escrow, usdc, buyer, seller, oracle } = await deploy();
    await escrow.connect(buyer).initiateTrade(seller.address, TRADE_AMOUNT);
    await escrow.connect(oracle).setRiskFlag(1n, false);
    await escrow.connect(buyer).confirmDelivery(1n);
    const before = await usdc.balanceOf(seller.address);
    await escrow.connect(seller).releaseFunds(1n);
    const after = await usdc.balanceOf(seller.address);
    expect(after).to.be.gt(before);
  });

  it("buyer can trigger dispute", async function () {
    const { escrow, buyer, seller, oracle } = await deploy();
    await escrow.connect(buyer).initiateTrade(seller.address, TRADE_AMOUNT);
    await escrow.connect(oracle).setRiskFlag(1n, false);
    await expect(escrow.connect(buyer).disputeTrigger(1n))
      .to.emit(escrow, "DisputeTriggered");
  });

  it("arbiter resolves dispute refunding buyer", async function () {
    const { escrow, usdc, buyer, seller, oracle, arbiter } = await deploy();
    await escrow.connect(buyer).initiateTrade(seller.address, TRADE_AMOUNT);
    await escrow.connect(oracle).setRiskFlag(1n, false);
    await escrow.connect(buyer).disputeTrigger(1n);
    const before = await usdc.balanceOf(buyer.address);
    await escrow.connect(arbiter).resolveDispute(1n, false);
    const after = await usdc.balanceOf(buyer.address);
    expect(after - before).to.equal(TRADE_AMOUNT);
  });
});