import { createConfig } from 'fuels';

export default createConfig({
  contracts: [
        '../sway-verifier',
  ],
  output: './src/sway-contracts-api',
});

/**
 * Check the docs:
 * https://docs.fuel.network/docs/fuels-ts/fuels-cli/config-file/
 */
