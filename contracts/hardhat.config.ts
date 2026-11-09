import { defineConfig } from "hardhat/config";

export default defineConfig({
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks: {
    localhost: {
      type: "http",
      chainType: "l1",
      url: "http://127.0.0.1:8545",
    },
  },
});

