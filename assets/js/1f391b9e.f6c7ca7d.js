"use strict";(self.webpackChunkchristopher_nguyen_re=self.webpackChunkchristopher_nguyen_re||[]).push([[3085],{6416:(e,t,a)=>{a.r(t),a.d(t,{default:()=>o});var l=a(7294),n=a(6010),c=a(2600),s=a(7459),i=a(1575),m=a(1548);const r="mdxPageWrapper_zHyg";function o(e){const{content:t}=e,{metadata:{title:a,description:o,frontMatter:d}}=t,{wrapperClassName:v,hide_table_of_contents:g}=d;return l.createElement(m.FG,{className:(0,n.Z)(v??m.kM.wrapper.mdxPages,m.kM.page.mdxPage)},l.createElement(m.d,{title:a,description:o}),l.createElement(c.Z,null,l.createElement("main",{className:"container container--fluid margin-vert--lg"},l.createElement("div",{className:(0,n.Z)("row",r)},l.createElement("div",{className:(0,n.Z)("col",!g&&"col--8")},l.createElement(s.Z,null,l.createElement(t,null))),!g&&t.toc&&l.createElement("div",{className:"col col--2"},l.createElement(i.Z,{toc:t.toc,minHeadingLevel:d.toc_min_heading_level,maxHeadingLevel:d.toc_max_heading_level}))))))}},1575:(e,t,a)=>{a.d(t,{Z:()=>m});var l=a(7462),n=a(7294),c=a(6010),s=a(5002);const i="tableOfContents_cNA8";function m(e){let{className:t,...a}=e;return n.createElement("div",{className:(0,c.Z)(i,"thin-scrollbar",t)},n.createElement(s.Z,(0,l.Z)({},a,{linkClassName:"table-of-contents__link toc-highlight",linkActiveClassName:"table-of-contents__link--active"})))}},5002:(e,t,a)=>{a.d(t,{Z:()=>i});var l=a(7462),n=a(7294),c=a(1548);function s(e){let{toc:t,className:a,linkClassName:l,isChild:c}=e;return t.length?n.createElement("ul",{className:c?void 0:a},t.map((e=>n.createElement("li",{key:e.id},n.createElement("a",{href:`#${e.id}`,className:l??void 0,dangerouslySetInnerHTML:{__html:e.value}}),n.createElement(s,{isChild:!0,toc:e.children,className:a,linkClassName:l}))))):null}function i(e){let{toc:t,className:a="table-of-contents table-of-contents__left-border",linkClassName:i="table-of-contents__link",linkActiveClassName:m,minHeadingLevel:r,maxHeadingLevel:o,...d}=e;const v=(0,c.LU)(),g=r??v.tableOfContents.minHeadingLevel,u=o??v.tableOfContents.maxHeadingLevel,_=(0,c.b9)({toc:t,minHeadingLevel:g,maxHeadingLevel:u}),N=(0,n.useMemo)((()=>{if(i&&m)return{linkClassName:i,linkActiveClassName:m,minHeadingLevel:g,maxHeadingLevel:u}}),[i,m,g,u]);return(0,c.Si)(N),n.createElement(s,(0,l.Z)({toc:_,className:a,linkClassName:i},d))}}}]);