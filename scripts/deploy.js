const hre = require("hardhat");

async function main() {
  console.log("Deploying ThreatLogger to the blockchain...");

  const ThreatLogger = await hre.ethers.getContractFactory("ThreatLogger");
  const threatLogger = await ThreatLogger.deploy();
  await threatLogger.waitForDeployment();

  const address = await threatLogger.getAddress();
  console.log(`Success! ThreatLogger deployed to: ${address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});