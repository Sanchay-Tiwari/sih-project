import hre from "hardhat";

async function main() {
  console.log("Deploying ThreatLogger to the blockchain...");

  // 1. Grab the compiled contract
  const ThreatLogger = await hre.ethers.getContractFactory("ThreatLogger");
  
  // 2. Deploy it
  const threatLogger = await ThreatLogger.deploy();

  // 3. Wait for the transaction to be mined
  await threatLogger.waitForDeployment();

  // 4. Print the permanent address
  console.log(`Success! ThreatLogger deployed to: ${await threatLogger.getAddress()}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});