import "dotenv/config";
import { ContractFactory, JsonRpcProvider, Wallet } from "ethers";
import { readFileSync } from "node:fs";

async function main() {
  if (!process.env.DEPLOYER_PRIVATE_KEY) {
    throw new Error("Set DEPLOYER_PRIVATE_KEY to a local Hardhat node test key.");
  }
  const provider = new JsonRpcProvider(process.env.RPC_URL || "http://127.0.0.1:8545");
  const wallet = new Wallet(process.env.DEPLOYER_PRIVATE_KEY, provider);
  const artifactPath = new URL("../artifacts/contracts/FileSharing.sol/FileSharing.json", import.meta.url);
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
  const factory = new ContractFactory(artifact.abi, artifact.bytecode, wallet);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  console.log("FileSharing deployed to:", await contract.getAddress());
  await provider.destroy();
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

