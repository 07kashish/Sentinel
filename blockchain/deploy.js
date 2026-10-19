const hre = require("hardhat");

async function main() {
    console.log("Deploying AgentTrustRegistry to Base Sepolia...");

    // Generate the Contract Factory
    const Registry = await hre.ethers.getContractFactory("AgentTrustRegistry");

    // Deploy the contract
    const registry = await Registry.deploy();

    // Wait for it to be mined
    await registry.waitForDeployment();

    const address = await registry.getAddress();

    console.log("✅ AgentTrustRegistry successfully deployed!");
    console.log("📜 Contract Address:", address);

    console.log(`\nNext Steps: Ensure you copy the Contract Address into your .env file as:`);
    console.log(`CONTRACT_ADDRESS=${address}`);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
