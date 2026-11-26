export default {
  title: 'HTTP6',
  tagline: 'Proposed API and SDK',
  url: 'https://www.http6.org',
  baseUrl: '/developers/sdk/',
  organizationName: 'HTTP6-ORG',
  projectName: 'http6-sdk',
  trailingSlash: true,
  onBrokenLinks: 'throw',
  favicon: 'img/logo.svg',
  presets: [['classic', {
    docs: {routeBasePath: '/', sidebarPath: './sidebars.mjs', editUrl: ({docPath}) => 'https://github.com/HTTP6-ORG/http6-sdk/edit/main/' + (docPath.startsWith('generated/guide/') ? 'source/developer-guide.md' : docPath.startsWith('generated/proposal/') ? 'source/original-proposal.md' : 'docs/' + docPath)},
    blog: false,
    theme: {customCss: './website-src/css/custom.css'},
  }]],
  themeConfig: {
    colorMode: {defaultMode:'light', disableSwitch:true, respectPrefersColorScheme:false},
    announcementBar: {id:'proposal', content:'PROPOSAL: Experimental developer SDK and draft protocol. <a href="https://github.com/HTTP6-ORG/http6-sdk/issues">Share feedback on GitHub</a>.', isCloseable:false},
    navbar: {
      title: 'HTTP6',
      items: [
        {href:'https://www.http6.org/developers/',label:'Developers',position:'left'},
        {type:'docSidebar', sidebarId:'guide', label:'SDK guide', position:'left'},
        {to:'/api-reference/',label:'API navigator',position:'left'},
        {href:'https://github.com/HTTP6-ORG/http6-sdk',label:'GitHub and feedback',position:'right'},
      ],
    },
    footer: {style:'light', links:[{title:'HTTP6',items:[{label:'HTTP6.org',href:'https://www.http6.org/'},{label:'Developers',href:'https://www.http6.org/developers/'},{label:'Privacy',href:'https://www.http6.org/participate/privacy/'},{label:'Circuit copyright and licensing',href:'https://www.http6.org/participate/licensing/#circuit-notice'}]}, {title:'Contribute',items:[{label:'Repository',href:'https://github.com/HTTP6-ORG/http6-sdk'},{label:'Report an issue',href:'https://github.com/HTTP6-ORG/http6-sdk/issues'}]}], copyright:'HTTP6 API and SDK proposal. Experimental work for review.'},
    prism: {additionalLanguages:['typescript','json','bash','python']},
  },
};
