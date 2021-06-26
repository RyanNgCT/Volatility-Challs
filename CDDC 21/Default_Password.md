# Default Password

We are given a [memory dump](https://github.com/RyanNgCT/Volatility-Challs/blob/main/CDDC%2021/dependencies/dump.zip). The case scenario is shown below. For this I used my custom built FlareVM machine.

![img](https://github.com/RyanNgCT/Volatility-Challs/blob/main/CDDC%2021/dependencies/challenge.png)

## Approach

Memory dump... ok use volatility... but from my previous ctf experiences, is it a windows or linux dump? I'd better check, so I ran `imageinfo` on the file. Here's the results:

```
C:\Users\winmal\Desktop
λ volatility -f data imageinfo
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (C:\Users\winmal\Desktop\data)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002a2f130L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002a31000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2021-05-26 13:26:07 UTC+0000
     Image local date and time : 2021-05-26 06:26:07 -0700
```

Let's use the profile `Win7SP1x64` and conduct a `pslist` to find the list of common processes.

```
C:\Users\winmal\Desktop
λ volatility -f data --profile=Win7SP1x64 pslist
Volatility Foundation Volatility Framework 2.6
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0xfffffa80006bbb00 System                    4      0     84      512 ------      0 2021-05-26 23:25:35 UTC+0000
0xfffffa80016cd9c0 smss.exe                276      4      4       29 ------      0 2021-05-26 23:25:35 UTC+0000
0xfffffa800213b680 csrss.exe               360    344      8      452      0      0 2021-05-26 23:25:36 UTC+0000
0xfffffa8001763060 wininit.exe             412    344      7       90      0      0 2021-05-26 23:25:37 UTC+0000
0xfffffa80020cc060 csrss.exe               420    404      9      231      1      0 2021-05-26 23:25:37 UTC+0000
0xfffffa800221e670 winlogon.exe            476    404      6      123      1      0 2021-05-26 23:25:37 UTC+0000
0xfffffa800223cb00 services.exe            512    412     21      222      0      0 2021-05-26 23:25:37 UTC+0000
0xfffffa8002251060 lsass.exe               532    412     10      640      0      0 2021-05-26 23:25:37 UTC+0000
0xfffffa8002252060 lsm.exe                 540    412     10      158      0      0 2021-05-26 23:25:37 UTC+0000
0xfffffa800238f060 svchost.exe             644    512     15      361      0      0 2021-05-26 23:25:37 UTC+0000
0xfffffa80023a8b00 VBoxService.ex          712    512     12      126      0      0 2021-05-26 23:25:37 UTC+0000
0xfffffa80023b2b00 svchost.exe             768    512      9      274      0      0 2021-05-26 13:25:38 UTC+0000
0xfffffa80023e4b00 svchost.exe             820    512     23      434      0      0 2021-05-26 13:25:38 UTC+0000
0xfffffa800235c060 svchost.exe             928    512     24      438      0      0 2021-05-26 13:25:38 UTC+0000
0xfffffa8002453060 svchost.exe             980    512     36      495      0      0 2021-05-26 13:25:38 UTC+0000
0xfffffa800245b670 svchost.exe             100    512     40      756      0      0 2021-05-26 13:25:38 UTC+0000
0xfffffa800246b670 audiodg.exe             376    820      6      126      0      0 2021-05-26 13:25:38 UTC+0000
0xfffffa8002481b00 svchost.exe             500    512      7      125      0      0 2021-05-26 13:25:38 UTC+0000
0xfffffa80020419b0 svchost.exe            1084    512     22      402      0      0 2021-05-26 13:25:38 UTC+0000
0xfffffa8002091b00 spoolsv.exe            1188    512     16      300      0      0 2021-05-26 13:25:39 UTC+0000
0xfffffa80024fcb00 svchost.exe            1224    512     23      331      0      0 2021-05-26 13:25:39 UTC+0000
0xfffffa80010b75f0 taskhost.exe           1772    512     11      208      1      0 2021-05-26 13:25:44 UTC+0000
0xfffffa800265c060 userinit.exe           1820    476      3       46      1      0 2021-05-26 13:25:44 UTC+0000
0xfffffa800265cb00 dwm.exe                1828    928      3       92      1      0 2021-05-26 13:25:44 UTC+0000
0xfffffa8002683b00 taskeng.exe            1836    100      6       81      0      0 2021-05-26 13:25:44 UTC+0000
0xfffffa80026cd670 explorer.exe           1848   1820     35      834      1      0 2021-05-26 13:25:44 UTC+0000
0xfffffa8001a17a60 VBoxTray.exe           1340   1848     15      148      1      0 2021-05-26 13:25:45 UTC+0000
0xfffffa80015865f0 taskeng.exe            1892    100      6       87      1      0 2021-05-26 13:25:45 UTC+0000
0xfffffa80016b27e0 CCleaner64.exe         1312    192     20      524      1      0 2021-05-26 13:25:46 UTC+0000
0xfffffa8002419b00 WmiPrvSE.exe            924    644      8      119      0      0 2021-05-26 13:25:46 UTC+0000
0xfffffa80017af060 SearchIndexer.         2228    512     13      641      0      0 2021-05-26 13:25:51 UTC+0000
0xfffffa800189c530 SearchProtocol         2296   2228      7      226      1      0 2021-05-26 13:25:51 UTC+0000
0xfffffa8001788b00 SearchFilterHo         2316   2228      5       82      0      0 2021-05-26 13:25:51 UTC+0000
0xfffffa8001902b00 wmpnetwk.exe           2380    512     15      224      0      0 2021-05-26 13:25:51 UTC+0000
0xfffffa8001a50b00 svchost.exe            2476    512     21      228      0      0 2021-05-26 13:25:52 UTC+0000
0xfffffa8001b6c060 dllhost.exe            2936    644      6       84      1      0 2021-05-26 13:26:05 UTC+0000
0xfffffa80025e0610 dllhost.exe            2972    644      6       81      0      0 2021-05-26 13:26:06 UTC+0000
0xfffffa8002226270 DumpIt.exe             3004   1848      2       46      1      1 2021-05-26 13:26:06 UTC+0000
0xfffffa8001b0a6e0 conhost.exe            3016    420      2       51      1      0 2021-05-26 13:26:06 UTC+0000
```

Now to perform a `netscan`.
```
C:\Users\winmal\Desktop
λ volatility -f data --profile=Win7SP1x64 netscan
Volatility Foundation Volatility Framework 2.6
Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0x1de419c0         UDPv4    0.0.0.0:0                      *:*                                   1084     svchost.exe    2021-05-26 13:25:43 UTC+0000
0x1de419c0         UDPv6    :::0                           *:*                                   1084     svchost.exe    2021-05-26 13:25:43 UTC+0000
0x1de0bd90         TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        512      services.exe
0x1de0bd90         TCPv6    :::49155                       :::0                 LISTENING        512      services.exe
0x1de10ba0         TCPv4    192.168.10.101:139             0.0.0.0:0            LISTENING        4        System
0x1de62010         TCPv4    192.168.10.101:49158           69.94.77.206:443     ESTABLISHED      -1
0x1e067590         UDPv4    0.0.0.0:5355                   *:*                                   1084     svchost.exe    2021-05-26 13:25:43 UTC+0000
0x1e067590         UDPv6    :::5355                        *:*                                   1084     svchost.exe    2021-05-26 13:25:43 UTC+0000
0x1e37a010         UDPv4    192.168.10.101:137             *:*                                   4        System         2021-05-26 13:25:43 UTC+0000
0x1e451960         UDPv4    0.0.0.0:5355                   *:*                                   1084     svchost.exe    2021-05-26 13:25:43 UTC+0000
0x1e0055d0         TCPv4    0.0.0.0:49153                  0.0.0.0:0            LISTENING        820      svchost.exe
0x1e0055d0         TCPv6    :::49153                       :::0                 LISTENING        820      svchost.exe
0x1e1fbee0         TCPv4    0.0.0.0:445                    0.0.0.0:0            LISTENING        4        System
0x1e1fbee0         TCPv6    :::445                         :::0                 LISTENING        4        System
0x1e1fc380         TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        512      services.exe
0x1e3c9aa0         TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        412      wininit.exe
0x1e3ca3e0         TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        768      svchost.exe
0x1e3ca3e0         TCPv6    :::135                         :::0                 LISTENING        768      svchost.exe
0x1e3cd010         TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        768      svchost.exe
0x1e3de690         TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        412      wininit.exe
0x1e3de690         TCPv6    :::49152                       :::0                 LISTENING        412      wininit.exe
0x1e3e9ee0         TCPv4    0.0.0.0:49160                  0.0.0.0:0            LISTENING        532      lsass.exe
0x1e3ffee0         TCPv4    0.0.0.0:49153                  0.0.0.0:0            LISTENING        820      svchost.exe
0x1e466010         TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        100      svchost.exe
0x1e489400         TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        100      svchost.exe
0x1e489400         TCPv6    :::49154                       :::0                 LISTENING        100      svchost.exe
0x1ea05ad0         UDPv4    0.0.0.0:3702                   *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ea05ad0         UDPv6    :::3702                        *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ea05cb0         UDPv4    0.0.0.0:3702                   *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ea54010         UDPv6    ::1:52785                      *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ea543c0         UDPv6    fe80::39a1:2720:3093:4c46:52784 *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ea59010         UDPv4    0.0.0.0:3702                   *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ea59010         UDPv6    :::3702                        *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ea59bb0         UDPv4    0.0.0.0:52780                  *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ea70730         UDPv4    0.0.0.0:52781                  *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ea70730         UDPv6    :::52781                       *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ea86bb0         UDPv6    fe80::39a1:2720:3093:4c46:1900 *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1eab37b0         UDPv4    192.168.10.101:1900            *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1eab4250         UDPv4    0.0.0.0:3702                   *:*                                   980      svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1eab4250         UDPv6    :::3702                        *:*                                   980      svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1eab49a0         UDPv6    ::1:1900                       *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1eabeec0         UDPv4    127.0.0.1:52787                *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1eaeaec0         UDPv6    fe80::39a1:2720:3093:4c46:546  *:*                                   820      svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ecc9bc0         UDPv4    0.0.0.0:52783                  *:*                                   980      svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ecc9bc0         UDPv6    :::52783                       *:*                                   980      svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ecdc010         UDPv4    0.0.0.0:3702                   *:*                                   980      svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ece4100         UDPv4    0.0.0.0:3702                   *:*                                   980      svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ece4100         UDPv6    :::3702                        *:*                                   980      svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ece8630         UDPv4    0.0.0.0:52788                  *:*                                   980      svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ecea9b0         UDPv4    127.0.0.1:1900                 *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ecebcc0         UDPv4    0.0.0.0:52782                  *:*                                   980      svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ecfa5b0         UDPv4    0.0.0.0:3702                   *:*                                   980      svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ecfad00         UDPv4    0.0.0.0:52789                  *:*                                   980      svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ecfad00         UDPv6    :::52789                       *:*                                   980      svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ecffd00         UDPv4    192.168.10.101:52786           *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1ed21aa0         UDPv4    0.0.0.0:3702                   *:*                                   2476     svchost.exe    2021-05-26 13:25:52 UTC+0000
0x1efd8570         UDPv4    192.168.10.101:138             *:*                                   4        System         2021-05-26 13:25:43 UTC+0000
0x1eec9a50         TCPv4    0.0.0.0:5357                   0.0.0.0:0            LISTENING        4        System
0x1eec9a50         TCPv6    :::5357                        :::0                 LISTENING        4        System
0x1ef5a5b0         TCPv4    0.0.0.0:49160                  0.0.0.0:0            LISTENING        532      lsass.exe
0x1ef5a5b0         TCPv6    :::49160                       :::0                 LISTENING        532      lsass.exe
0x1ed04810         TCPv4    127.0.0.1:5357                 127.0.0.1:49162      CLOSED           -1
0x1eec93c0         TCPv4    127.0.0.1:49162                127.0.0.1:5357       CLOSED           -1
0x1ef7fcd0         TCPv4    192.168.10.101:49159           5.62.48.213:443      ESTABLISHED      -1
```

Ok... `svchost.exe` looks pretty normal and the other suspicious tasks include [`lsass.exe`](https://www.lifewire.com/lsass-exe-4587503) and [`WmiPrvSE.exe`](https://answers.microsoft.com/en-us/protect/forum/protect_defender-protect_scanning-windows_10/wmiprvseexe/167d3136-3668-47e3-a59a-aff720587091) based on the results of both scans... I dumped the processes and tried to grep for the strings but no luck there...

Then I came across [this article](https://www.aldeid.com/wiki/Volatility/Retrieve-password) on extracting the passwords from the SAM registry hive. Worth a try...

```
C:\Users\winmal\Desktop
λ volatility -f data --profile=Win7SP1x64 hivelist
Volatility Foundation Volatility Framework 2.6
Virtual            Physical           Name
------------------ ------------------ ----
0xfffff8a00000f010 0x0000000019a69010 [no name]
0xfffff8a000024010 0x00000000199f4010 \REGISTRY\MACHINE\SYSTEM
0xfffff8a000063010 0x0000000019a35010 \REGISTRY\MACHINE\HARDWARE
0xfffff8a00046b010 0x000000000e864010 \Device\HarddiskVolume1\Boot\BCD
0xfffff8a0004da410 0x000000000e66a410 \SystemRoot\System32\Config\SOFTWARE
0xfffff8a000a43010 0x000000000c57e010 \SystemRoot\System32\Config\SECURITY
0xfffff8a000abd010 0x000000000b428010 \SystemRoot\System32\Config\SAM
0xfffff8a000bc1410 0x000000000b4cd410 \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT
0xfffff8a000c6b010 0x000000000b3dc010 \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT
0xfffff8a000eb9010 0x0000000005741010 \??\C:\Users\User\ntuser.dat
0xfffff8a001057010 0x0000000001eaf010 \??\C:\Users\User\AppData\Local\Microsoft\Windows\UsrClass.dat
0xfffff8a0040dc010 0x000000001b101010 \SystemRoot\System32\Config\DEFAULT

C:\Users\winmal\Desktop
λ volatility -f data --profile=Win7SP1x64 hashdump -y 0xfffff8a000024010 -s 0xfffff8a000abd010 > hashes.txt
Volatility Foundation Volatility Framework 2.6

C:\Users\winmal\Desktop
λ cat hashes.txt
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
User:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
cddc:1001:aad3b435b51404eeaad3b435b51404ee:ed40df9fe82b74a509a2d11280a11fe8:::
```

Since the NT and NTLM hashes were the same for the first 3 accounts, I attempted to use Crackstation to crack them. _(Spoiler: the NTLM hash for the last account was not NTLM as I was expecting!)_

![img](https://github.com/RyanNgCT/Volatility-Challs/blob/main/CDDC%2021/dependencies/crackstation.png)

Unfortunately, the NTLM hash for user `cddc` turned out to not be a hash... ok...

After a bit of digging, I came across [a set of slides](https://www.slideshare.net/mooyix/sans-forensics-2009-memory-forensics-and-registry-analysis)... Hmm ok `lsadump` could be an option. Then referring to the docs, I extracted the flag!

![img](https://github.com/RyanNgCT/Volatility-Challs/blob/main/CDDC%2021/dependencies/slide.jpg)

![img](https://github.com/RyanNgCT/Volatility-Challs/blob/main/CDDC%2021/dependencies/lsa_dump_docs.jpg)

![img](https://github.com/RyanNgCT/Volatility-Challs/blob/main/CDDC%2021/dependencies/flag.jpg)

The flag is `CDDC21{Th1s_i$_A_L0ng_p@s$w0rd}`!

## Reflections

So this challenge taught me that some research beforehand could potentially save me a lot more time when attempting the challenge and that doing forensics requires persistence!
