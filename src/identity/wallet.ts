/**
 * Automaton Wallet Management
 *
 * Supports:
 * - EVM
 * - Solana
 * - Bitcoin Taproot (BIP86)
 *
 * Bitcoin derivation:
 *   BIP39 -> BIP32 -> BIP86
 *   m/86'/0'/0'/0/0
 *
 * Bitcoin mainnet addresses use bc1p...
 */

import type { PrivateKeyAccount } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import nacl from "tweetnacl";
import bs58 from "bs58";

import fs from "fs";
import path from "path";

import * as bip39 from "bip39";
import { BIP32Factory } from "bip32";
import * as ecc from "tiny-secp256k1";
import * as bitcoin from "bitcoinjs-lib";

import type { WalletData } from "../types.js";
import type { ChainType } from "./chain.js";
import {
  EvmChainIdentity,
  SolanaChainIdentity,
  BitcoinChainIdentity,
} from "./chain.js";
import type { ChainIdentity } from "./chain.js";

// Initialize Bitcoin ECC library.
bitcoin.initEccLib(ecc);

const bip32 = BIP32Factory(ecc);

/**
 * Bitcoin mainnet.
 */
const BITCOIN_NETWORK = bitcoin.networks.bitcoin;

/**
 * BIP86 Taproot derivation path.
 *
 * m/86'/0'/0'/0/0
 *
 * 86 = BIP86
 * 0  = Bitcoin mainnet
 * 0  = account 0
 * 0  = external/change branch
 * 0  = first address
 */
const BITCOIN_DERIVATION_PATH = "m/86'/0'/0'/0/0";

/**
 * Create a stub PrivateKeyAccount for Solana/Bitcoin wallets.
 *
 * This exists for backward compatibility with code that expects
 * an EVM PrivateKeyAccount.
 */
function createChainStubAccount(
  address: string,
  chainType: ChainType,
): PrivateKeyAccount {
  const throwSigning = () => {
    throw new Error(
      `Cannot use EVM signing methods on a ${chainType} wallet. ` +
        `Use chainIdentity instead.`,
    );
  };

  return {
    address: address as any,
    publicKey: "0x" as any,
    source: "custom",
    type: "local",
    signMessage: throwSigning as any,
    signTypedData: throwSigning as any,
    signTransaction: throwSigning as any,
    sign: throwSigning as any,
  } as unknown as PrivateKeyAccount;
}

const AUTOMATON_DIR = path.join(
  process.env.HOME || "/root",
  ".automaton",
);

const WALLET_FILE = path.join(
  AUTOMATON_DIR,
  "wallet.json",
);

export function getAutomatonDir(): string {
  return AUTOMATON_DIR;
}

export function getWalletPath(): string {
  return WALLET_FILE;
}

/**
 * Generate a Solana Ed25519 keypair.
 */
export function generateSolanaKeypair(): {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  address: string;
} {
  const keypair = nacl.sign.keyPair();

  return {
    secretKey: keypair.secretKey,
    publicKey: keypair.publicKey,
    address: bs58.encode(keypair.publicKey),
  };
}

/**
 * Generate a Bitcoin Taproot wallet using BIP39 + BIP32 + BIP86.
 *
 * Returns:
 * - mnemonic
 * - seed-derived wallet
 * - address
 * - derivation path
 * - private key
 */
export async function generateBitcoinWallet(): Promise<{
  mnemonic: string;
  privateKey: string;
  publicKey: string;
  address: string;
  derivationPath: string;
}> {
  const mnemonic = bip39.generateMnemonic(128);

  const seed = await bip39.mnemonicToSeed(mnemonic);

  const root = bip32.fromSeed(
    seed,
    BITCOIN_NETWORK,
  );

  const child = root.derivePath(
    BITCOIN_DERIVATION_PATH,
  );

  const internalPubkey = bitcoin.toXOnly(
    child.publicKey,
  );

  const payment = bitcoin.payments.p2tr({
    internalPubkey,
    network: BITCOIN_NETWORK,
  });

  if (!payment.address) {
    throw new Error(
      "Failed to generate Bitcoin Taproot address",
    );
  }

  if (!child.privateKey) {
    throw new Error(
      "Failed to derive Bitcoin private key",
    );
  }

  return {
    mnemonic,
    privateKey: Buffer.from(child.privateKey).toString("hex"),
    publicKey: Buffer.from(internalPubkey).toString("hex"),
    address: payment.address,
    derivationPath: BITCOIN_DERIVATION_PATH,
  };
}

/**
 * Get or create the automaton wallet.
 *
 * The chain is selected at genesis and remains fixed.
 */
export async function getWallet(
  chainType?: ChainType,
): Promise<{
  account: PrivateKeyAccount;
  chainIdentity: ChainIdentity;
  chainType: ChainType;
  isNew: boolean;
}> {
  if (!fs.existsSync(AUTOMATON_DIR)) {
    fs.mkdirSync(AUTOMATON_DIR, {
      recursive: true,
      mode: 0o700,
    });
  }

  /**
   * Existing wallet.
   */
  if (fs.existsSync(WALLET_FILE)) {
    const walletData: WalletData = JSON.parse(
      fs.readFileSync(WALLET_FILE, "utf-8"),
    );

    const resolvedChainType =
      walletData.chainType || "evm";

    /**
     * Solana wallet.
     */
    if (
      resolvedChainType === "solana" &&
      walletData.secretKey
    ) {
      const secretKey = bs58.decode(
        walletData.secretKey,
      );

      const solanaIdentity =
        new SolanaChainIdentity(secretKey);

      const account = createChainStubAccount(
        solanaIdentity.address,
        "solana",
      );

      return {
        account,
        chainIdentity: solanaIdentity,
        chainType: "solana",
        isNew: false,
      };
    }

    /**
     * Bitcoin wallet.
     */
    if (
      resolvedChainType === "bitcoin" &&
      walletData.mnemonic
    ) {
      const mnemonic = walletData.mnemonic;

      if (!bip39.validateMnemonic(mnemonic)) {
        throw new Error(
          "Invalid Bitcoin wallet mnemonic in wallet.json",
        );
      }

      const seed = await bip39.mnemonicToSeed(
        mnemonic,
      );

      const root = bip32.fromSeed(
        seed,
        BITCOIN_NETWORK,
      );

      const derivationPath =
        walletData.derivationPath ||
        BITCOIN_DERIVATION_PATH;

      const child = root.derivePath(
        derivationPath,
      );

      const internalPubkey = bitcoin.toXOnly(
        child.publicKey,
      );

      const payment = bitcoin.payments.p2tr({
        internalPubkey,
        network: BITCOIN_NETWORK,
      });

      if (!payment.address) {
        throw new Error(
          "Failed to reconstruct Bitcoin address",
        );
      }

      const bitcoinIdentity =
        new BitcoinChainIdentity(
          payment.address,
        );

      const account = createChainStubAccount(
        bitcoinIdentity.address,
        "bitcoin",
      );

      return {
        account,
        chainIdentity: bitcoinIdentity,
        chainType: "bitcoin",
        isNew: false,
      };
    }

    /**
     * EVM wallet.
     *
     * Existing behavior preserved.
     */
    if (!walletData.privateKey) {
      throw new Error(
        "Invalid EVM wallet: privateKey is missing",
      );
    }

    const account = privateKeyToAccount(
      walletData.privateKey,
    );

    return {
      account,
      chainIdentity: new EvmChainIdentity(
        account,
      ),
      chainType: "evm",
      isNew: false,
    };
  }

  /**
   * Create a new wallet.
   */
  const resolvedChain = chainType || "evm";

  /**
   * Bitcoin wallet.
   */
  if (resolvedChain === "bitcoin") {
    const btcWallet =
      await generateBitcoinWallet();

    const walletData: WalletData = {
      chainType: "bitcoin",
      mnemonic: btcWallet.mnemonic,
      derivationPath:
        btcWallet.derivationPath,
      bitcoinAddress: btcWallet.address,
      bitcoinPublicKey: btcWallet.publicKey,
      createdAt:
        new Date().toISOString(),
    };

    fs.writeFileSync(
      WALLET_FILE,
      JSON.stringify(walletData, null, 2),
      {
        mode: 0o600,
      },
    );

    const bitcoinIdentity =
      new BitcoinChainIdentity(
        btcWallet.address,
      );

    const account = createChainStubAccount(
      btcWallet.address,
      "bitcoin",
    );

    return {
      account,
      chainIdentity: bitcoinIdentity,
      chainType: "bitcoin",
      isNew: true,
    };
  }

  /**
   * Solana wallet.
   */
  if (resolvedChain === "solana") {
    const {
      secretKey,
      address,
    } = generateSolanaKeypair();

    const solanaIdentity =
      new SolanaChainIdentity(secretKey);

    const walletData: WalletData = {
      chainType: "solana",
      secretKey: bs58.encode(secretKey),
      createdAt:
        new Date().toISOString(),
    };

    fs.writeFileSync(
      WALLET_FILE,
      JSON.stringify(walletData, null, 2),
      {
        mode: 0o600,
      },
    );

    const account = createChainStubAccount(
      address,
      "solana",
    );

    return {
      account,
      chainIdentity: solanaIdentity,
      chainType: "solana",
      isNew: true,
    };
  }

  /**
   * EVM wallet.
   */
  const privateKey =
    generatePrivateKey();

  const account =
    privateKeyToAccount(privateKey);

  const walletData: WalletData = {
    chainType: "evm",
    privateKey,
    createdAt:
      new Date().toISOString(),
  };

  fs.writeFileSync(
    WALLET_FILE,
    JSON.stringify(walletData, null, 2),
    {
      mode: 0o600,
    },
  );

  return {
    account,
    chainIdentity:
      new EvmChainIdentity(account),
    chainType: "evm",
    isNew: true,
  };
}

/**
 * Get wallet address without loading signing account.
 */
export function getWalletAddress(): string | null {
  if (!fs.existsSync(WALLET_FILE)) {
    return null;
  }

  const walletData: WalletData =
    JSON.parse(
      fs.readFileSync(
        WALLET_FILE,
        "utf-8",
      ),
    );

  /**
   * Solana.
   */
  if (
    walletData.chainType === "solana" &&
    walletData.secretKey
  ) {
    const secretKey =
      bs58.decode(walletData.secretKey);

    const keypair =
      nacl.sign.keyPair.fromSecretKey(
        secretKey,
      );

    return bs58.encode(
      keypair.publicKey,
    );
  }

  /**
   * Bitcoin.
   */
  if (
    walletData.chainType === "bitcoin" &&
    walletData.mnemonic
  ) {
    const seed =
      bip39.mnemonicToSeedSync(
        walletData.mnemonic,
      );

    const root =
      bip32.fromSeed(
        seed,
        BITCOIN_NETWORK,
      );

    const child =
      root.derivePath(
        walletData.derivationPath ||
          BITCOIN_DERIVATION_PATH,
      );

    const internalPubkey =
      bitcoin.toXOnly(
        child.publicKey,
      );

    const payment =
      bitcoin.payments.p2tr({
        internalPubkey,
        network: BITCOIN_NETWORK,
      });

    return payment.address || null;
  }

  /**
   * EVM.
   */
  if (!walletData.privateKey) {
    return null;
  }

  const account =
    privateKeyToAccount(
      walletData.privateKey,
    );

  return account.address;
}

/**
 * Load the full EVM wallet account.
 *
 * Bitcoin and Solana use ChainIdentity instead.
 */
export function loadWalletAccount():
  | PrivateKeyAccount
  | null {
  if (!fs.existsSync(WALLET_FILE)) {
    return null;
  }

  const walletData: WalletData =
    JSON.parse(
      fs.readFileSync(
        WALLET_FILE,
        "utf-8",
      ),
    );

  if (
    walletData.chainType === "solana" ||
    walletData.chainType === "bitcoin"
  ) {
    return null;
  }

  if (!walletData.privateKey) {
    return null;
  }

  return privateKeyToAccount(
    walletData.privateKey,
  );
}

/**
 * Get wallet chain type.
 */
export function getWalletChainType():
  ChainType {
  if (!fs.existsSync(WALLET_FILE)) {
    return "evm";
  }

  try {
    const walletData: WalletData =
      JSON.parse(
        fs.readFileSync(
          WALLET_FILE,
          "utf-8",
        ),
      );

    return (
      walletData.chainType ||
      "evm"
    );
  } catch {
    return "evm";
  }
}

/**
 * Check whether a wallet exists.
 */
export function walletExists(): boolean {
  return fs.existsSync(WALLET_FILE);
}
