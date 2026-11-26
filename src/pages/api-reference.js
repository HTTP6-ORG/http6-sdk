import React, {useEffect, useRef, useState} from 'react';
import Layout from '@theme/Layout';
import useBaseUrl from '@docusaurus/useBaseUrl';
import 'swagger-ui-dist/swagger-ui.css';

export default function ApiReference() {
  const target=useRef(null);
  const [error,setError]=useState('');
  const spec=useBaseUrl('/artifacts/openapi.yaml');
  useEffect(()=>{
    let live=true, ui;
    import('swagger-ui-dist/swagger-ui-bundle.js').then(m=>{
      if (!live) return;
      const SwaggerUI=m.default || m;
      ui=SwaggerUI({domNode:target.current,url:spec,deepLinking:true,displayOperationId:true,
        docExpansion:'none',filter:true,supportedSubmitMethods:[],validatorUrl:null});
    }).catch(()=>{if(live)setError('The API navigator could not load. Open the schema link below.');});
    return ()=>{live=false; if(ui?.unmount)ui.unmount();};
  },[spec]);
  return <Layout title="Proposed API navigator" description="Read-only Swagger navigator for the proposed HTTP6 guide API">
    <main className="container margin-vert--lg">
      <h1>Proposed API navigator</h1>
      <p>This read-only contract describes <code>http6-guide-01</code>, a proposal. It is not the implemented WASIX pilot API. The example server is intentionally invalid and requests are disabled.</p>
      <p>ENI6MA circuits are patent pending and copyrighted. Commercial deployment requires a license through <a href="https://www.rosariocyber.com/contact">ENI6MA or Rosario Cybernetics</a>; contact President Frank Rosario about production and extended-use licensing.</p>
      <p><a href={spec}>Download the complete OpenAPI contract</a> · <a href="https://github.com/HTTP6-ORG/http6-sdk/issues">Provide feedback on GitHub</a></p>
      {error && <p role="alert">{error}</p>}
      <div ref={target}/>
    </main>
  </Layout>;
}
