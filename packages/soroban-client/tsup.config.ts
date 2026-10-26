import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'es2022',
  external: [
    '@stellar/stellar-sdk',
    '@stellar/freighter-api',
    '@albedo-link/intent',
    '@ledgerhq/hw-app-str',
    '@ledgerhq/hw-transport-web-ble',
    '@ledgerhq/hw-transport-webusb',
  ],
});
