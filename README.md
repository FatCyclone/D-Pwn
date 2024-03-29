# D-Pwn
Code repository where I can practice AV/EDR evasion with D/Invoke. Since I am not a developer, this is a patchwork of code from different repositories (feel free to optimize it) :
- [Osep Code Snippets](https://github.com/chvancooten/OSEP-Code-Snippets)
- [Evasion Practice](https://github.com/cinzinga/Evasion-Practice)
- [SharpSploit](https://github.com/cobbr/SharpSploit)
- [DInjector](https://github.com/snovvcrash/DInjector)
- [RastaMouse](https://github.com/rasta-mouse/DInvoke)

When trying to load SharpSploit.dll to execute my shellcode with D/Invoke, my app was instantly flagged. Therefore I decided to make it stealthier and standalone.

## USAGE
- Generate a shellcode with your favorite C2
- XOR it
- Compile it with your favorite C# compiler
- Call main method with reflection, or launch the .exe
- You can scramble, and obfuscate the code with [ConfuserEx](https://github.com/mkaring/ConfuserEx)

![image](https://user-images.githubusercontent.com/18697868/140501678-936d8ca9-a20c-4829-beea-796ec6f746d3.png)

## drunner.cs
Simple shellcode runner with D/Invoke - Native API version done.

## dinject.cs
Process injection technique with D/Invoke

## dhollow.cs
Process hollowing with D/Invoke

## ddump.cs
MiniDumpWriteDump with D/Invoke

## TODO
- Process hollowing with no env (Token grab + Environment structure) in D/Invoke so it can launch without having a GUI (Perfect for lateral movement)
- Port other and more "stealthier" techniques
- Correct spelling and typos
- Use NT Functions and change DLLs loading technique (Partially Done)
- Use duplicate handle technique on MinuDumpWriteDump (I'll try to convert it to Nt functions in csharp, could be fun) and encrypt the dump (Partially Done)
- Convert all loaders to use "distant" shellcodes and files
- Add a simple tutorial

## DISCLAIMER
This code/project is only for educational/redteam operations purposes. I am not responsible for any illegal use of this code. 

!! DO NOT USE VIRUSTOTAL TO TEST THE COMPILED CODE  !!
