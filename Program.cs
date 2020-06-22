using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Net.Sockets;
using System.Net;

namespace Remap_Memory_Region
{
    class Program : NativeMethods
    {
        static void Main(string[] args)
        {
            //analyseStack();
            //FormatGMRCode("H:\\test_dump.txt");
            ////quickSplit();
            //return;

            //Console.WriteLine("Hello nigger");
            //Console.ReadKey();

            //Process[] processes = Process.GetProcessesByName("WowClassic");
            Process[] processes = Process.GetProcessesByName("Wow");
            for(int i = 0; i < processes.Length; i++)
            {
                Console.WriteLine($"{i}: WowClassic.exe - {processes[i].Id.ToString("X")}");
            }
            Console.Write("select: ");
            int target = Convert.ToInt32(Console.ReadLine());
            Process process = processes[target];
            //Process process = Process.GetProcessesByName("WowClassic").FirstOrDefault();
            IntPtr hProcess = OpenProcess(ProcessAccessFlags.PROCESS_ALL_ACCESS, false, process.Id);

            //byte[] buffer = new byte[0xd5d1];
            //IntPtr dread;
            //ReadProcessMemory(hProcess, (IntPtr)0x0197AFAE21E0, buffer, buffer.Length, out dread);
            //File.WriteAllText("luabox_1.lua", Encoding.UTF8.GetString(buffer));

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("Failed on OpenProcess. Handle is invalid.");
                return;
            }

            if (VirtualQueryEx(hProcess, process.MainModule.BaseAddress, out MEMORY_BASIC_INFORMATION basicInformation, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0)
            {
                Console.WriteLine("Failed on VirtualQueryEx. Return is 0 bytes.");
                return;
            }
            IntPtr regionBase = basicInformation.baseAddress;
            IntPtr regionSize = basicInformation.regionSize;
            NtSuspendProcess(hProcess);
            RemapMemoryRegion2(hProcess, regionBase, regionSize.ToInt32(), MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);            //MISSING VIRTUALALLOC
            NtResumeProcess(hProcess);
            CloseHandle(hProcess);

            string[] argss = new string[1];
            //argss[0] = "Wow";
            //ThreadHijack.Main2(argss);
            //Console.ReadKey();

            while(true)
            {
                testRead();
                Console.WriteLine("done");
            }
            

        }
        public static bool RemapMemoryRegion2(IntPtr processHandle, IntPtr baseAddress, int regionSize, MemoryProtectionConstraints mapProtection)
        {
            IntPtr addr = VirtualAllocEx(processHandle, IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            if (addr == IntPtr.Zero)
                return false;

            IntPtr copyBuf = VirtualAlloc(IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            IntPtr copyBufEx = VirtualAllocEx(processHandle, IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            byte[] copyBuf2 = new byte[regionSize];

            if (!ReadProcessMemory(processHandle, baseAddress, copyBuf, regionSize, out IntPtr bytes))
                return false;

            if (!ReadProcessMemory(processHandle, baseAddress, copyBuf2, regionSize, out bytes))
                return false;

            IntPtr sectionHandle = default;
            long sectionMaxSize = regionSize;


            Ntstatus status = NtCreateSection(ref sectionHandle, AccessMask.SECTION_ALL_ACCESS, IntPtr.Zero, ref sectionMaxSize, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE, SectionProtectionConstraints.SEC_COMMIT, IntPtr.Zero);

            if (status != Ntstatus.STATUS_SUCCESS)
                return false;

            status = NtUnmapViewOfSection(processHandle, baseAddress);

            if (status != Ntstatus.STATUS_SUCCESS)
                return false;



            IntPtr viewBase = baseAddress;
            long sectionOffset = default;
            uint viewSize = 0;
            status = NtMapViewOfSection(sectionHandle,
                                               processHandle,
                                               ref viewBase,
                                               UIntPtr.Zero,
                                               regionSize,
                                               ref sectionOffset,
                                               ref viewSize,
                                               2,
                                               0,
                                               MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);


            if (status != Ntstatus.STATUS_SUCCESS)
                return false;

            if (!WriteProcessMemory(processHandle, viewBase, copyBuf, (int)viewSize, out bytes))
                return false;

            if (!WriteProcessMemory(processHandle, copyBufEx, copyBuf, (int)viewSize, out bytes))
                return false;

            MemoryProtectionConstraints old = MemoryProtectionConstraints.PAGE_NOACCESS;

            if (!VirtualProtectEx(processHandle, copyBufEx, (int)viewSize, MemoryProtectionConstraints.PAGE_EXECUTE_READ, out old))
                return false;

            if (!VirtualFree(copyBuf, 0, MemFree.MEM_RELEASE))
                return false;

            //crc32 bypass

            //search for F2 ?? 0F 38 F1 - F2 REX.W 0F 38 F1 /r CRC32 r64, r/m64	RM	Valid	N.E.	Accumulate CRC32 on r/m64.
            byte[] AoBpattern = { 0xF2, 0x42, 0x0F, 0x38, 0xF1 };
            for (long i = 0; i < regionSize; i++)
            {
                bool isMatch = true;
                for (long j = 0; j < AoBpattern.Length; j++)
                {
                    if (!(copyBuf2[i + j] == AoBpattern[j] || j == 1))
                    {
                        isMatch = false;
                        break;
                    }
                }
                if (isMatch)
                {
                    Console.WriteLine(((long)baseAddress + i).ToString("X"));
                    detourCRC(processHandle, (long)baseAddress + i, (long)baseAddress, (long)copyBufEx);
                }
            }

            return true;

        }

        public static bool detourCRC(IntPtr processHandle, long crcLocation, long wowBase, long wowCopyBase)
        {
            #region asmCave

            //stuff that goes in the .text section
            byte[] crcDetour =
            {
                0x50,                                                               //push rax
                0x48, 0xB8, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov rax, CaveAddr (0x03)
                0xFF, 0xD0,                                                         //call rax
                0x58,                                                               //pop rax
                0x90                                                                //nop
            };
            byte[] crcDetourRegOffsets = { 0x00, 0x02, 0x0C, 0x0D }; //regiser offsets (may need to change when register is used in code)

            //stuff that goes in new allocated section
            byte[] crcCave =
            {
                0x51,                                                               //push rcx
                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov rcx, wowBase (0x03)
                0x48, 0x39, 0xCF,                                                   //cmp r2, rcx - 0x0B
                0x7C, 0x38,                                                         //jl crc
                0x50,                                                               //push rax
                0x48, 0x8B, 0xC1,                                                   //mov rax, rcx
                0x8B, 0x89, 0x78, 0x02, 0x00, 0x00,                                 //mov ecx, [r1+0x278]
                0x90,
                0x48, 0x01, 0xC1,                                                   //add rcx,rax
                0x8B, 0x80, 0x74, 0x02, 0x00, 0x00,                                 //mov eax,[rax+0x274]
                0x90,
                0x48, 0x01, 0xC1,                                                   //add rcx,rax
                0x58,                                                               //pop rax
                0x48, 0x39, 0xCF,                                                   //cmp r2, rcx - 0x29
                0x7F, 0x1A,                                                         //jg crc
                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov rcx, Wowbase (0x30)
                0x48, 0x29, 0xCF,                                                   //sub r2, rcx - 0x38
                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov rcx, wowCopyBase (0x3D)
                0x48, 0x01, 0xCF,                                                   //add r2, rcx - 0x45
                0x59,                                                               //pop rcx
                //crc:                                                              //crc location start
                0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,                           //+ 0x47 
                0x90, 0x90, 0x90,
                0x90, 0x90, 0x90, 0x90, 0x90,                                       // NOP's as placeholder for the 15-19 bytes
                0x90, 0x90, 0x90,                                                   
                //crc                                                               //crc location end
                0xC3                                                                //ret
            };
            byte[] crcCaveRegInstructOffsets = { 0x0B, 0x29, 0x38, 0x45 }; //register offsets (may need to change when register is used in code)
            #endregion asmCave

            IntPtr CaveAddr = VirtualAllocEx(processHandle, IntPtr.Zero, crcCave.Length, MemoryAllocationType.MEM_COMMIT, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            if(CaveAddr == IntPtr.Zero)
            {
                Console.WriteLine("VirtualAlloxEx error");
                return false;
            }

            byte[] splitCaveAddr = BitConverter.GetBytes(CaveAddr.ToInt64());                       //write CaveAddr to crcDetour buffer
            byte[] splitWowBase = BitConverter.GetBytes(wowBase);                                   //write wowBase to crcCave buffer
            byte[] splitWowCopyBase = BitConverter.GetBytes(wowCopyBase);                           //write wowCopyBase to crcCave buffer

            //replace the beef (placeholders)
            for (int i = 0; i < 8; i++)
            {
                crcDetour[0x03 + i] = splitCaveAddr[i];         //CaveAdr
                crcCave[0x03 + i] = splitWowBase[i];            //WowBase
                crcCave[0x30 + i] = splitWowBase[i];            //WowBase
                crcCave[0x3D + i] = splitWowCopyBase[i];        //WowCopyBase (aka wow_2.exe)
            }

            //obtain crc instructions
            byte[] crcBuffer = new byte[88];
            if (!ReadProcessMemory(processHandle, (IntPtr)crcLocation, crcBuffer, crcBuffer.Length, out IntPtr bRead))
            {
                Console.WriteLine("Reading CRC location failed");
                return false;
            }

            bool isJmpFound = false;
            int origCrcInstructionLength = -1;
            for (int i = 0; i < crcCave.Length - 0x49; i++)
            {
                //jb is the last instruction and starts with 0x72 (2 bytes long)
                crcCave[0x49 + i] = crcBuffer[i];                   //write byte to codecave
                if(crcBuffer[i] == 0x72)
                {
                    crcCave[0x49 + i + 1] = crcBuffer[i + 1];       //include last byte of JB instruction before breaking
                    origCrcInstructionLength = i + 2;               //Keep track of bytes used to NOP later
                    isJmpFound = true;
                    break;
                }
            }

            if(!isJmpFound)
            {
                Console.WriteLine("NOPE");
                return false;
            }

            //list used registers rax,   rcx,   rdx,   rbx,   rsp,   rbp,   rsi,   rdi
            bool[] usedRegs = { false, false, false, false, false, false, false, false };     //rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi
             

            //check byte code to find used stuff
            usedRegs[(crcBuffer[0x05]-0x04)/8] = true;              //x,[reg+reg*8]
            usedRegs[(crcBuffer[0x09]-0xC0)] = true;                //inc x

            if(crcBuffer[0x0C] >= 0xC0 && crcBuffer[0x0C] < 0xC8)
                usedRegs[(crcBuffer[0x0C]-0xC0)] = true;            // cmp ?, x

            byte selectReg = 0;
            for(byte r = 0; r < usedRegs.Length; r++)
            {
                if (usedRegs[r] == false)
                {
                    selectReg = r;
                    break;
                }
            }

            //change Detour register to non-used register
            for(int i = 0; i < crcDetourRegOffsets.Length; i++)
            {
                crcDetour[crcDetourRegOffsets[i]] += selectReg;      //increase byte to set selected register
            }

            //Change the register(r2) used to calc crc32
            for (int i = 0; i < crcCaveRegInstructOffsets.Length; i++)
            {
                crcCave[crcCaveRegInstructOffsets[i] + 0] = crcBuffer[0x01]; //copy
                crcCave[crcCaveRegInstructOffsets[i] + 2] = crcBuffer[0x06]; //copy
                if (crcCave[crcCaveRegInstructOffsets[i] + 0] != 0x48) //check if register is extra register (r8 - r15)
                {
                    crcCave[crcCaveRegInstructOffsets[i] + 0] = 0x49; //set to extra register type
                    crcCave[crcCaveRegInstructOffsets[i] + 2] = (byte)(0xC8 + (crcBuffer[0x06] - 0xC0) % 8); //set second reg to rcx and fix first reg
                }
                else
                    crcCave[crcCaveRegInstructOffsets[i] + 2] += 8; //inc to fix basic registers
            }

            //add nops to end of the detour buffer
            byte[] crcDetourFixed = new byte[origCrcInstructionLength];
            for(int i = 0; i < origCrcInstructionLength; i++)
            {
                if(i < crcDetour.Length)
                {
                    //Copy byte from crcDetour to fixed crcDetour
                    crcDetourFixed[i] = crcDetour[i];
                }
                else
                {
                    //add NOPs
                    crcDetourFixed[i] = 0x90;
                }
            }

            if (!WriteProcessMemory(processHandle, (IntPtr)(crcLocation), crcDetourFixed, crcDetourFixed.Length, out IntPtr bWrite))
            {
                Console.WriteLine("Writing CRC detour failed");
                return false;
            }
            if(!WriteProcessMemory(processHandle, CaveAddr, crcCave, crcCave.Length, out bWrite))
            {
                Console.WriteLine("Writing CRC CodeCave failed");
                return false;
            }

            Console.WriteLine($"Bypassed CRC at {crcLocation.ToString("X")}"); // to {CaveAddr.ToString("X")}");
            return true;
        }

        public static void FormatGMRCode(string gmr)
        {
            //split gmr code

            //string gmr = @"E\dump.txt";
            string gmr_content = File.ReadAllText(gmr);


            string[] gmr_contentSplit = gmr_content.Split('\x00');
            for (int i = 0; i < gmr_contentSplit.Length; i++)
            {

                int offset = 6;
                int nameStart = gmr_contentSplit[i].IndexOf("local "); //local XXX
                if (nameStart == -1)
                {
                    var endLinei = gmr_contentSplit[i].IndexOf('\n');
                    if (endLinei != -1 && gmr_contentSplit[i].Substring(0, endLinei).Contains("GMR") && !gmr_contentSplit[i].Substring(0, endLinei).Contains("=") && !gmr_contentSplit[i].Substring(0, endLinei).Contains("("))
                    {
                        nameStart = gmr_contentSplit[i].IndexOf("GMR");
                        offset = 0;
                    }
                    else
                        continue;
                }
                    

                int nameEnd = gmr_contentSplit[i].IndexOf("\n", nameStart + offset); //local XXX
                if (nameEnd == -1)
                    continue;

                string fname = gmr_contentSplit[i].Substring(nameStart + offset, nameEnd - (nameStart + offset));

                if (!fname.Contains("GMR"))
                    continue;

                //TODO: add patcher?

                File.WriteAllText(@"M:\Projects\GMR_Copy\GMR_Retail\dumps\2\" + fname + ".lua", gmr_contentSplit[i]);
            }
        }

        private static void testRead()
        {
            String data = null;
            bool HasLogin = false;
            bool HasLogin2 = false;
            bool HasPassword = false;
            TcpListener server = null;
            Int32 port = 8080;
            IPAddress localAddr = IPAddress.Parse("127.0.0.1");
            server = new TcpListener(localAddr, port);
            server.Start();

            Console.WriteLine("Waiting for connection...");
            TcpClient client = server.AcceptTcpClient();

            Byte[] bytes = new Byte[0xFFFF];

            NetworkStream stream = client.GetStream();
            List<string> CriticalData = new List<string>();
            int i;
            bool isLoggedIn = false;

            int index = 0;

            DateTime start = DateTime.MaxValue;
            string fname = "H:\\test_dump.txt";
            bool isHit = false;

            StreamWriter writer = new StreamWriter(fname);
            while ((i = stream.Read(bytes, 0, bytes.Length)) != 0)
            {
                
                if(start != DateTime.MaxValue)    
                    if (start.AddSeconds(15) < DateTime.Now)
                        break;
                data = System.Text.Encoding.UTF8.GetString(bytes, 0, i);

                //if(data.Length > 29 && data.Substring(0,3) == "if " && !data.Substring(3, 20).Contains(' '))
                //{
                //    Console.WriteLine(data.Substring(3, 35).Split(' ')[0]);
                    isHit = true;
                //}

                if (isHit && start == DateTime.MaxValue)
                {
                    start = DateTime.Now;
                    Console.WriteLine("LuaBox Detected");
                    ///break;
                }
                //if(isHit)
                    writer.Write(data);
            }
            writer.Close();
            client.Close();
            server.Stop();

            FormatGMRCode(fname);
        }

        private static void quickSplit()
        {
            string[] content = File.ReadAllText("H:/test_dump_squids.txt").Split('\x00');
            for (int i = 0; i < content.Length; i++)
            {
                if(content[i].Length > 0x1000)
                    File.WriteAllText($"H:/split/file{i.ToString().PadLeft(2, '0')}.lua", content[i]);
            }
                

            
        }

        private static void analyseStack()
        {
            //loading in data
            int stackLen = 0;
            string[] dump = File.ReadAllText("H:/pkt_stack_trace.txt").Split("RIP: ");
            List<StackTrace> TheStack = new List<StackTrace>();
            for (int i = 1; i < dump.Length; i ++)
            {
                string[] split = dump[i].Split("\r\n");
                StackTrace s = new StackTrace();
                s.Rip = Convert.ToInt64(split[0], 16);
                stackLen = split.Length - 1;
                s.stack = new long[stackLen];
                for (int j = 1; j < split.Length; j++)
                {
                    if (split[j] == "")
                    {
                        stackLen--;
                        continue;
                    }

                    long rsp = Convert.ToInt64(split[j], 16);
                    s.stack[j - 1] = rsp;
                }
                TheStack.Add(s);
            }

            //doing math on the data
            Dictionary<long, int> callerCount = new Dictionary<long, int>();
            foreach(StackTrace s in TheStack)
            {
                foreach(var ss in s.stack)
                {
                    if (ss > 0x00007fffffffffff || ss < 0) //blacklist since we only need usermode
                        continue;

                    if (callerCount.ContainsKey(ss))
                        callerCount[ss]++;
                    else
                        callerCount.Add(ss, 1);
                }
            }

            //display result
            Console.WriteLine($"> {"Address".PadRight(18)} - {"i".PadRight(2)} <");
            foreach(var cc in callerCount.ToList())
            {
                //Only show 25% ore more used
                if(cc.Value > (dump.Length * 0.25))
                    Console.WriteLine($"wow.exe+{cc.Key.ToString("X12")} - {cc.Value.ToString().PadLeft(4, '0')}");
            }
            Console.WriteLine($"Sample Count: {dump.Length}, Stack Length: {stackLen}");
            Console.ReadKey();
        }

        public static bool RemapMemoryRegion(IntPtr processHandle, IntPtr baseAddress, int regionSize, MemoryProtectionConstraints mapProtection)
        {
            IntPtr addr = VirtualAlloc(IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            if (addr == IntPtr.Zero)
                return false;

            IntPtr copyBuf = VirtualAlloc(IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);

            if (!ReadProcessMemory(processHandle, baseAddress, copyBuf, regionSize, out IntPtr bytes))
                return false;
            
            IntPtr sectionHandle = default;
            long sectionMaxSize = regionSize;

            
            Ntstatus status = NtCreateSection(ref sectionHandle, AccessMask.SECTION_ALL_ACCESS, IntPtr.Zero, ref sectionMaxSize, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE, SectionProtectionConstraints.SEC_COMMIT, IntPtr.Zero);
            
            if (status != Ntstatus.STATUS_SUCCESS)
                return false;

            status = NtUnmapViewOfSection(processHandle, baseAddress);

            if (status != Ntstatus.STATUS_SUCCESS)
                return false;



            IntPtr viewBase = baseAddress;
            long sectionOffset = default;
            uint viewSize = 0;
            status = NtMapViewOfSection(sectionHandle,
                                               processHandle,
                                               ref viewBase,
                                               UIntPtr.Zero,
                                               regionSize,
                                               ref sectionOffset,
                                               ref viewSize,
                                               2,
                                               0,
                                               MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);

            if (status != Ntstatus.STATUS_SUCCESS)
                return false;

            if (!WriteProcessMemory(processHandle, viewBase, copyBuf, (int)viewSize, out bytes))
                return false;

            if(!VirtualFree(copyBuf, 0, MemFree.MEM_RELEASE))
                return false;

            return true;

        }
    }
    class StackTrace
    {
        public long Rip { get; set; }
        public long[] stack { get; set; }
    }
}
