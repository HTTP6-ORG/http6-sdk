import {readFile, writeFile, mkdir, rm} from 'node:fs/promises';
import {join} from 'node:path';
const root = new URL('../', import.meta.url);
const generated = new URL('../docs/generated/', import.meta.url);
await rm(generated, {recursive:true,force:true});
await mkdir(generated, {recursive:true});
await writeFile(new URL('_category_.json',generated),JSON.stringify({label:'Draft documents',position:4,link:{type:'generated-index'}},null,2)+'\n');
const linkMap={
 'http6-sdk-guide/schema.json':'https://www.http6.org/developers/sdk/artifacts/schema.json',
 'http6-sdk-guide/synthetic-vectors.json':'https://www.http6.org/developers/sdk/artifacts/synthetic-vectors.json',
 'http6-sdk-guide/build-vectors.mjs':'https://github.com/HTTP6-ORG/http6-sdk/blob/main/examples/build-vectors.mjs',
 'HTTP6-API-SDK-Guide-Proposal.md':'https://github.com/HTTP6-ORG/http6-sdk/blob/main/source/original-proposal.md',
 'README.md':'https://www.http6.org/',
 '01-ietf/draft-rosario-http6-authority-continuity-00.md':'https://www.http6.org/artifacts/drafts/draft-rosario-http6-authority-continuity-00.md',
 '01-ietf/draft-rosario-http6-w1-profile-00.md':'https://www.http6.org/artifacts/drafts/draft-rosario-http6-w1-profile-00.md',
 'HTTP6-WASIX-Delegation-Developer-Spec.md':'https://www.http6.org/developers/wallet-proof-report/',
 'HTTP6-WASIX-Delegation-Implementation-Plan.md':'https://www.http6.org/developers/wallet-proof-report/',
 'wasix-delegation/README.md':'https://www.http6.org/developers/wallet-proof-report/',
 'wasix-delegation/src/protocol.rs':'https://www.http6.org/developers/wallet-proof-report/',
 '02-nist-markdown/HTTP6_Per_Message_Proof_NIST_Review_White_Paper.md':'https://www.http6.org/read/docs/nist-markdown/HTTP6_Per_Message_Proof_NIST_Review_White_Paper/'
};
function rewrite(s) {return s.replace(/\]\(([^)#]+)(#[^)]*)?\)/g,(full,path,anchor='')=>linkMap[path]?`](${linkMap[path]}${anchor})`:full);}
async function split(source, dir, label) {
  const text=await readFile(new URL('../source/'+source,import.meta.url),'utf8');
  const chunks=text.split(/(?=^## \d+\. )/m);
  const folder=new URL(dir+'/',generated); await mkdir(folder,{recursive:true});
  await writeFile(new URL('_category_.json',folder),JSON.stringify({label,position:label==='Developer guide'?2:3,link:{type:'generated-index'}},null,2)+'\n');
  const opening=rewrite(chunks[0].replace(/^# .+$/m, '# Overview'));
  const openingNotice=label==='Original proposal' ? '> **Historical proposal:** This preserved draft predates the WASIX 01 response-proof pilot. See the SDK integration page for the current implementation. [Send feedback on GitHub](https://github.com/HTTP6-ORG/http6-sdk/issues).\n\n' : '> **Proposal:** This page describes experimental work for review. [Send feedback on GitHub](https://github.com/HTTP6-ORG/http6-sdk/issues).\n\n';
  await writeFile(new URL('00-overview.md',folder),`---\ntitle: Overview\nsidebar_label: Overview\nsidebar_position: 0\n---\n\n${openingNotice}${opening}`);
  let index=0;
  for (const chunk of chunks.slice(1)) {
    const match=chunk.match(/^## (\d+)\. (.+)$/m); if(!match) continue;
    const number=Number(match[1]), title=match[2];
    const slug=String(number).padStart(2,'0')+'-'+title.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/-$/,'');
    const content=rewrite(chunk.replace(match[0],`# ${title}`));
    const banner=label==='Original proposal' ? '> **Historical proposal:** This preserved draft predates the WASIX 01 response-proof pilot. See the SDK integration page for the current implementation. [Send feedback on GitHub](https://github.com/HTTP6-ORG/http6-sdk/issues).\n\n' : '> **Proposal:** This page describes experimental work for review. [Send feedback on GitHub](https://github.com/HTTP6-ORG/http6-sdk/issues).\n\n';
    await writeFile(new URL(slug+'.md',folder),`---\ntitle: ${JSON.stringify(title)}\nsidebar_label: ${JSON.stringify(title)}\nsidebar_position: ${number}\n---\n\n${banner}${content}`);
    index++;
  }
  if(!index) throw Error('No numbered sections in '+source);
}
await split('developer-guide.md','guide','Developer guide');
await split('original-proposal.md','proposal','Original proposal');
console.log('Prepared navigable guide and original proposal from repository source.');
