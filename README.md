
# Sense Points Marketplace contest details

- Join [Sherlock Discord](https://discord.gg/MABEWyASkp)
- Submit findings using the issue page in your private contest repo (label issues as med or high)
- [Read for more details](https://docs.sherlock.xyz/audits/watsons)

# Q&A

### Q: On what chains are the smart contracts going to be deployed?
Ethereum mainnet.
___

### Q: If you are integrating tokens, are you allowing only whitelisted tokens to work with the codebase or any complying with the standard? Are they assumed to have certain properties, e.g. be non-reentrant? Are there any types of [weird tokens](https://github.com/d-xo/weird-erc20) you want to integrate?
Yes, whitelisted tokens only. They're assumed to not be reentrant, but fee-on-transfer, pausable, and blocklist tokens are OK.
___

### Q: Are there any limitations on values set by admins (or other roles) in the codebase, including restrictions on array lengths?
No
___

### Q: Are there any limitations on values set by admins (or other roles) in protocols you integrate with, including restrictions on array lengths?
Only those already implemented in Safe (for example that threshold must be greater than 0)
___

### Q: For permissioned functions, please list all checks and requirements that will be made before calling the function.
Simply that the role is correct, and, if the root is being updated on the vault, that users will be able to claim pTokens as expected afterwards (via fork test).
___

### Q: Is the codebase expected to comply with any EIPs? Can there be/are there any deviations from the specification?
No
___

### Q: Are there any off-chain mechanisms or off-chain procedures for the protocol (keeper bots, arbitrage bots, etc.)?
Yes. 

1. There is an off-chain authorized responsibility to push merkle roots to the Vault on some interval. 

2. Once reward tokens are released from added external protocols, an authorized actor must send claim and sweep transactions to every Rumpel Wallet (Safe with the Rumpel Guard and Rumpel Module added). These transactions would claim tokens from the external protocol, and pull them into the vault for pToken redemption.
___

### Q: Are there any hardcoded values that you intend to change before (some) deployments?
Mainly just the role addresses in the forge deployment scripts.
___

### Q: If the codebase is to be deployed on an L2, what should be the behavior of the protocol in case of sequencer issues (if applicable)? Should Sherlock assume that the Sequencer won't misbehave, including going offline?
n/a
___

### Q: Should potential issues, like broken assumptions about function behavior, be reported if they could pose risks in future integrations, even if they might not be an issue in the context of the scope? If yes, can you elaborate on properties/invariants that should hold?
No
___

### Q: Please discuss any design choices you made.
We chose to build on top of Safe. 
We chose to block all user actions by default in the Rumpel Wallet, so that there's no chance they can claim and withdraw tokens that should be swept into the vault for pToken redemption. 
We chose a "fee on the borders" strategy in the vault where users are only charged for redemption if they redeem in excess of what they minted, pToken wise.
We chose to depend on an off-chain actor to push merkle roots with the right pToken distribution, according to what each address/wallet earned. In the future, we plan to decentralize this function via AVS.
___

### Q: Please list any known issues and explicitly state the acceptable risks for each known issue.
The authorized actor on the Rumpel module can execute arbitrary actions on behalf of Rumpel Wallets. Similar for the Vault. It is known that this is a risk, and that the management of privileged roles is crucial to the safe functioning of our system. 

In addition, signature-based reward claiming from external protocols is a risky with the Rumpel wallets, because we're dependent on them conforming to the erc 1271 standard, and if they accept owner-based signatures, we can't stop users from claiming themselves. 
___

### Q: We will report issues where the core protocol functionality is inaccessible for at least 7 days. Would you like to override this value?
No
___

### Q: Please provide links to previous audits (if any).
2024.04.25 FPS Points Vault Audit: https://github.com/sense-finance/point-tokenization-vault/blob/main/audits/2024.04.25%20FPS%20Points%20Tokenization.pdf

2024.05.02 Darklinear Vault Audit: https://github.com/sense-finance/point-tokenization-vault/blob/main/audits/2024.05.02%20Darklinear%20Points%20Tokenization.pdf

2024.07.15 FPS Rumpel Wallet Audit: https://github.com/sense-finance/rumpel-wallet/blob/main/audits/2024.07.15%20FPS%20Rumpel%20Wallet.pdf
___

### Q: Please list any relevant protocol resources.
The two READMEs are the best resources.

Vault: https://github.com/sense-finance/point-tokenization-vault/blob/dev/README.md

Wallet: https://github.com/sense-finance/rumpel-wallet/blob/main/README.md
___

### Q: Additional audit information.
The wallet is quite dependent on Safe, so familiarity with that system and its extensions is likely helpful. In addition, for the vault, while all of the code is in scope for the audit, this PR covers the changes since the most recent previous audit: https://github.com/sense-finance/point-tokenization-vault/pull/20/files
___



# Audit scope

[rumpel-wallet @ a9b3b72cb8500af34e931eba76a37183f297c6e2](https://github.com/sense-finance/rumpel-wallet/tree/a9b3b72cb8500af34e931eba76a37183f297c6e2)
- [rumpel-wallet/src/InitializationScript.sol](rumpel-wallet/src/InitializationScript.sol)
- [rumpel-wallet/src/RumpelGuard.sol](rumpel-wallet/src/RumpelGuard.sol)
- [rumpel-wallet/src/RumpelModule.sol](rumpel-wallet/src/RumpelModule.sol)
- [rumpel-wallet/src/RumpelWalletFactory.sol](rumpel-wallet/src/RumpelWalletFactory.sol)

[point-tokenization-vault @ 1865f69d1b32a1e4c06f9a85456336c4f6a99188](https://github.com/sense-finance/point-tokenization-vault/tree/1865f69d1b32a1e4c06f9a85456336c4f6a99188)
- [point-tokenization-vault/contracts/PToken.sol](point-tokenization-vault/contracts/PToken.sol)
- [point-tokenization-vault/contracts/PointTokenVault.sol](point-tokenization-vault/contracts/PointTokenVault.sol)

