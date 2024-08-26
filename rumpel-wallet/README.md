# Rumpel Wallet

Rumpel Wallet is an extension of the Rumpel Point Tokenization protocol that enables more points to be tokenized from a wider range of point-earning activities. Familiarity with the [Point Tokenization Vault](https://github.com/sense-finance/point-tokenization-vault) is recommended before proceeding.

Rumpel Wallet is built on top of [Safe](https://docs.gnosis.io/safe/latest/). Each user wallet is simply a standard Safe with a special Rumpel [Module](https://docs.safe.global/advanced/smart-account-modules) and Rumpel [Guard](https://docs.safe.global/advanced/smart-account-guards) added on.

Flow tl;dr
- Users create and manage unique positions using their Rumpel Wallets
- Points accrue as pTokens claimable with merkle proofs via the Point Tokenization Vault
- Users can sell their pTokens at any time
- After the point-generating protocol releases the reward tokens, Rumpel claims the rewards on users' behalf and sweeps them into the Vault
- All pToken holders can redeem their pTokens for rewards using the Vault as normal

Essentially, the redemption process for pTokens will be the same as it has been for the Point Tokenization Vault, but with an additional source for reward tokens.

Another way to think about the relationship between the Vault and Wallet is that the Point Tokenization Vault enables users to deposit tokenized positions that earn points, and because the points are accruing to the Vault, users are able to trade pTokens – rights to the eventual reward token distribution – freely. The Rumpel Wallet expands the size of Rumpel's network to individual user wallets, and because Rumpel is maintaining enough access to claim and sweep the eventual reward token distribution, users are able to mint pTokens just as if they had deposited a position in the Vault.

## Components

### Rumpel Module

Enables the admin to take actions on a user's behalf. Specifically to:
- Claim reward tokens after the external protocol releases them
- Transfer the reward tokens to the Point Tokenization Vault for pToken redemption

It's expected that both of these actions will generally be done atomically, so that reward tokens don't sit in the user's wallet. However, we need to be flexible to different claiming mechanisms.

The Rumpel Module also includes an irreversable blocklist that restricts which actions can be taken, e.g. USDC.transfer, to give guarantees around what can't be done on behalf of a user's Safe. 

### Rumpel Guard

Restricts wallet actions to specific admin-allowed `<address>.<functionSelector>` calls. 

Includes the ability to permanently allow a call, e.g. USDC.transfer, to give guarantees around which actions a user will always be able to take with their Safe.

### Rumpel Wallet Factory

Creates and initializes new Safe wallets with the Rumpel Module and Rumpel Guard.

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

Rename `.env.sample` to `.env` and set the correct environment variables. Then:

```
forge test
```
