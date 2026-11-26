import {PilotClient, Http6Error} from '../../../packages/sdk/src/index.mjs';
const [socket,op,mode]=process.argv.slice(2);
if (!socket || !/^[a-z0-9-]{1,48}$/.test(op||'') || !['allowed','denied'].includes(mode)) throw Error('Usage: client.mjs SOCKET OP allowed|denied');
const client=new PilotClient({agent:socket,ledger:socket,profile:'http6-wasix-delegation-02'});
const proposal={op,audience:'wallet',resource:'merchant-payment',args:{network:'regtest',recipient:'merchant-a',satoshis:mode==='allowed'?'100':'1100'},holdSeconds:4};
try { console.log(JSON.stringify({status:200,body:await client.invoke(proposal)})); }
catch(e) {if(!(e instanceof Http6Error) || !e.detail.response)throw e;console.log(JSON.stringify({status:e.detail.status,body:e.detail.response}));}
