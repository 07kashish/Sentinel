require("@nomicfoundation/hardhat-toolbox");
require('dotenv').config({ path: '../.env' }); // Pull env vars from root .env

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
    solidity: "0.8.20",
    networks: {
        base_sepolia: {
            url: process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org",
            accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
        }
    }
};
