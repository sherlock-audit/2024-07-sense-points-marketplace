# Point Tokenization Vault

Deposit points-earning tokens into the vault. Collect tokenized versions of your points, distributed at some cadence. These tokens can be traded or used in DeFi. Withdraw your points-earning tokens whenever you want and resume earning normal, illiquid points.

These contracts are only a piece of a larger decentralized system that will allow users to tokenize their points. Here is a UMD of the entire system:

<img src="./assets/point-tokenization-system.png" width="500" height="500">

### PToken

- PTokens are tokenized versions of points
- They will be redeemable for rewards after rewards have been distributed
- They will map 1:1 with the points earned by user assets deposited into the vault
- The vault has ownership and can grant minting/burning permissions to other contracts for future system expansion

### On The Off-Chain Dependencies

- The vault is highly dependent on trusted actors – namely, the merkle updator and the admin
- The trusted actors will slowly be replaced by a stake-validated network (e.g. an [Eigen AVS Oracle](https://docs.eigenlayer.xyz/eigenlayer/overview/key-terms))
- If you wish to make a merkle root from scratch, you must first

### Redemption Rights

- For most points programs, simple redemption where users redeem fungible PTokens for rewards will suffice
- For programs with vesting, we take a snapshot of PToken balances at the time of distribution and grant redemption rights
- This allows users to redeem only portions of their PTokens in a controlled manner
- Even if they sell their PTokens, they will keep the rights, and can buy back cheaply and redeem if the PTokens are mispriced on the market
- We assume that the exchange rate between points and rewards stays the same throughout the redemption period


## Installation

To install with [Foundry](https://github.com/gakonst/foundry):

```
forge install [user]/[repo]
```

## Local development

This project uses [Foundry](https://github.com/gakonst/foundry) as the development framework.

### Dependencies

```
forge install
```

### Compilation

```
forge build
```

### Testing

```
forge test
```

### Contract deployment

Please create a `.env` file before deployment.

#### Dryrun

```
forge script script/PointTokenVault.s.sol -f [network]
```

### Live

```
forge script script/PointTokenVault.s.sol -f [network] --verify --broadcast
```