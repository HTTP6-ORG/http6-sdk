import {PilotClient} from '../packages/sdk/src/index.mjs';
const [pilotBinary, stateDir, pinnedLedgerKey] = process.argv.slice(2);
if (!pilotBinary || !stateDir || !pinnedLedgerKey) {
  throw new Error('Usage: node examples/pilot.mjs PILOT_BINARY EXISTING_STATE PINNED_LEDGER_KEY');
}
const client = await PilotClient.attach({stateDir, pilotBinary, expectedProfile:'http6-wasix-delegation-02'});
const result = await client.invoke({op:'example-1',audience:'wallet',resource:'merchant-payment',
  args:{network:'regtest',recipient:'merchant-a',satoshis:'250'},holdSeconds:4});
const ledger = await client.events({pinnedLedgerKey});
console.log(JSON.stringify({result,ledger:ledger.verification},null,2));
