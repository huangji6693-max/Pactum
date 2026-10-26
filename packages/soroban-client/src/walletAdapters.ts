import {
  StrKey,
  TransactionBuilder,
  type Transaction,
  type FeeBumpTransaction,
} from '@stellar/stellar-sdk';
import { signTransaction } from '@stellar/freighter-api';

export type WalletProvider = 'freighter' | 'albedo' | 'ledger' | 'web3auth';

export interface WalletAdapter {
  name: string;
  id: string;
  icon: unknown;
  description: string;
  connect: () => Promise<string | null>;
  disconnect: () => Promise<void>;
  isAvailable: () => Promise<boolean>;
}

const LEDGER_STELLAR_PATH = "44'/148'/0'";

type LedgerTransport = any;
type StellarApp = any;

let transport: LedgerTransport | null = null;
let stellarApp: StellarApp | null = null;

function hasWebUSB(): boolean {
  return typeof navigator !== 'undefined' && Boolean((navigator as any).usb);
}

function hasWebBluetooth(): boolean {
  return typeof navigator !== 'undefined' && Boolean((navigator as any).bluetooth);
}

async function openTransport(): Promise<LedgerTransport> {
  if (transport) return transport;

  if (hasWebUSB()) {
    const TransportWebUSB = (await import('@ledgerhq/hw-transport-webusb')).default;
    transport = await TransportWebUSB.request();
  } else if (hasWebBluetooth()) {
    const BluetoothTransport = (await import('@ledgerhq/hw-transport-web-ble')).default;
    const descriptor = await new Promise<any>((resolve, reject) => {
      const sub = BluetoothTransport.listen({
        next: (e: any) => {
          sub.unsubscribe();
          resolve(e.descriptor);
        },
        error: (err: unknown) => reject(err),
        complete: () => {},
      });
    });
    transport = await BluetoothTransport.open(descriptor);
  } else {
    throw new Error(
      'This browser supports neither WebUSB nor WebBluetooth. Use a Chromium-based browser to connect a Ledger device.',
    );
  }

  transport!.on('disconnect', () => {
    transport = null;
    stellarApp = null;
  });

  return transport!;
}

async function getStellarApp(): Promise<StellarApp> {
  if (stellarApp) return stellarApp;
  const t = await openTransport();
  const Str = (await import('@ledgerhq/hw-app-str')).default;
  stellarApp = new Str(t);
  return stellarApp;
}

export const LedgerAdapter: WalletAdapter = {
  name: 'Ledger',
  id: 'ledger',
  icon: {},
  description: 'Ledger Nano hardware wallet (WebUSB/WebBluetooth, direct — no browser extension)',
  connect: async () => {
    const app = await getStellarApp();
    const { rawPublicKey } = await app.getPublicKey(LEDGER_STELLAR_PATH);
    return StrKey.encodeEd25519PublicKey(rawPublicKey);
  },
  disconnect: async () => {
    if (transport) {
      await transport.close();
    }
    transport = null;
    stellarApp = null;
  },
  isAvailable: async () => hasWebUSB() || hasWebBluetooth(),
};

export async function signTransactionWithLedger(
  unsignedXdr: string,
  networkPassphrase: string,
): Promise<string> {
  const app = await getStellarApp();
  const { rawPublicKey } = await app.getPublicKey(LEDGER_STELLAR_PATH);
  const publicKey = StrKey.encodeEd25519PublicKey(rawPublicKey);

  const tx = TransactionBuilder.fromXDR(unsignedXdr, networkPassphrase) as
    | Transaction
    | FeeBumpTransaction;

  const { signature } = await app.signTransaction(LEDGER_STELLAR_PATH, tx.signatureBase());
  tx.addSignature(publicKey, signature.toString('base64'));

  return tx.toXDR();
}

export async function signTransactionWithFreighter(
  unsignedXdr: string,
  networkPassphrase: string,
  address: string,
): Promise<string> {
  const signResult = await signTransaction(unsignedXdr, {
    networkPassphrase,
    address,
  });

  if (typeof signResult === 'string') {
    return signResult;
  }
  if (signResult && typeof signResult === 'object') {
    if ((signResult as any).error) {
      throw new Error(`Freighter signing rejected: ${(signResult as any).error}`);
    }
    return (
      (signResult as any).signedTxXdr ||
      (signResult as any).signedXdr ||
      (signResult as any).signedTransaction ||
      ''
    );
  }
  return '';
}

export async function signTransactionWithAlbedo(
  unsignedXdr: string,
  networkPassphrase: string,
): Promise<string> {
  const network = networkPassphrase.toLowerCase().includes('public') ? 'public' : 'testnet';
  const albedoMod = await import('@albedo-link/intent');
  const albedo = (albedoMod as any).default ?? albedoMod;
  const res = await albedo.tx({ xdr: unsignedXdr, network });
  return res?.signed_envelope_xdr ?? '';
}

export type Web3AuthSignerFn = (unsignedXdr: string, networkPassphrase: string) => string | Promise<string>;

let registeredWeb3AuthSigner: Web3AuthSignerFn | null = null;

export function registerWeb3AuthSigner(signer: Web3AuthSignerFn | null): void {
  registeredWeb3AuthSigner = signer;
}

export async function signTransactionWithWeb3AuthAdapter(
  unsignedXdr: string,
  networkPassphrase: string,
): Promise<string> {
  if (registeredWeb3AuthSigner) {
    return await registeredWeb3AuthSigner(unsignedXdr, networkPassphrase);
  }
  const globalSigner = (globalThis as Record<string, unknown>).__PACTUM_WEB3AUTH_SIGNER__ as
    | Web3AuthSignerFn
    | undefined;
  if (typeof globalSigner === 'function') {
    return await globalSigner(unsignedXdr, networkPassphrase);
  }
  throw new Error('Social-login wallet is not ready to sign. Please Login with Google again.');
}
