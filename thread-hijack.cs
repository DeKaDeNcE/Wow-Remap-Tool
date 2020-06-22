// A thread hijacking/injection example written in C# by @pwndizzle
//
// To run:
// 1. Compile code - C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe threadhijack.cs
// 2. Start target process
// 3. Execute binary and specify target e.g. threadhijack.exe notepad
// 4. Either wait for thread to execute or interact with process to see calc!
//
// References:
// http://www.pinvoke.net/default.aspx/kernel32.GetThreadContext
// http://www.rohitab.com/discuss/topic/40579-dll-injection-via-thread-hijacking/
// http://www.codingvision.net/miscellaneous/c-inject-a-dll-into-a-process-w-createremotethread

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.ComponentModel;
using System.Linq;


public class ThreadHijack
{
    // Import API Functions 
	[DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
	
	[DllImport("kernel32.dll")]
    static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
    
	[DllImport("kernel32.dll")]
    static extern uint SuspendThread(IntPtr hThread);
	
	[DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);	
	
	[DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);
	
	[DllImport("kernel32.dll")]
    static extern int ResumeThread(IntPtr hThread);
    
	[DllImport("kernel32", CharSet = CharSet.Auto,SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
	
	[DllImport("kernel32.dll")]
	static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);


    // Process privileges
    const int PROCESS_CREATE_THREAD = 0x0002;
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_OPERATION = 0x0008;
    const int PROCESS_VM_WRITE = 0x0020;
    const int PROCESS_VM_READ = 0x0010;

    // Memory permissions
    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_READWRITE = 4;
	const uint PAGE_EXECUTE_READWRITE = 0x40;
    
	[Flags]
    public enum ThreadAccess : int
    {
      TERMINATE = (0x0001),
      SUSPEND_RESUME = (0x0002),
      GET_CONTEXT = (0x0008),
      SET_CONTEXT = (0x0010),
      SET_INFORMATION = (0x0020),
      QUERY_INFORMATION = (0x0040),
      SET_THREAD_TOKEN = (0x0080),
      IMPERSONATE = (0x0100),
      DIRECT_IMPERSONATION = (0x0200),
	  THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
	  THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
    }
	
	public enum CONTEXT_FLAGS : uint
	{
	   CONTEXT_i386 = 0x10000,
	   CONTEXT_i486 = 0x10000,   //  same as i386
	   CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
	   CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
	   CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
	   CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
	   CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
	   CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
	   CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
	   CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |  CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS |  CONTEXT_EXTENDED_REGISTERS
	}

	// x86 float save
	[StructLayout(LayoutKind.Sequential)]
	public struct FLOATING_SAVE_AREA
	{
		 public uint ControlWord; 
		 public uint StatusWord; 
		 public uint TagWord; 
		 public uint ErrorOffset; 
		 public uint ErrorSelector; 
		 public uint DataOffset;
		 public uint DataSelector; 
		 [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)] 
		 public byte[] RegisterArea; 
		 public uint Cr0NpxState; 
	}

	// x86 context structure (not used in this example)
	[StructLayout(LayoutKind.Sequential)]
	public struct CONTEXT
	{
		 public uint ContextFlags; //set this to an appropriate value 
		 // Retrieved by CONTEXT_DEBUG_REGISTERS 
		 public uint Dr0;  
		 public uint Dr1; 
		 public uint Dr2; 
		 public uint Dr3; 
		 public uint Dr6; 
		 public uint Dr7; 
		 // Retrieved by CONTEXT_FLOATING_POINT 
		 public FLOATING_SAVE_AREA FloatSave; 
		 // Retrieved by CONTEXT_SEGMENTS 
		 public uint SegGs; 
		 public uint SegFs; 
		 public uint SegEs; 
		 public uint SegDs; 
		 // Retrieved by CONTEXT_INTEGER 
		 public uint Edi; 
		 public uint Esi; 
		 public uint Ebx; 
		 public uint Edx; 
		 public uint Ecx; 
		 public uint Eax; 
		 // Retrieved by CONTEXT_CONTROL 
		 public uint Ebp; 
		 public uint Eip; 
		 public uint SegCs; 
		 public uint EFlags; 
		 public uint Esp; 
		 public uint SegSs;
		 // Retrieved by CONTEXT_EXTENDED_REGISTERS 
		 [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)] 
		 public byte[] ExtendedRegisters;
	} 

	// x64 m128a
	[StructLayout(LayoutKind.Sequential)]
	public struct M128A
	{
		 public ulong High;
		 public long Low;

		 public override string ToString()
		 {
		return string.Format("High:{0}, Low:{1}", this.High, this.Low);
		 }
	}

	// x64 save format
	[StructLayout(LayoutKind.Sequential, Pack = 16)]
	public struct XSAVE_FORMAT64
	{
		public ushort ControlWord;
		public ushort StatusWord;
		public byte TagWord;
		public byte Reserved1;
		public ushort ErrorOpcode;
		public uint ErrorOffset;
		public ushort ErrorSelector;
		public ushort Reserved2;
		public uint DataOffset;
		public ushort DataSelector;
		public ushort Reserved3;
		public uint MxCsr;
		public uint MxCsr_Mask;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
		public M128A[] FloatRegisters;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
		public M128A[] XmmRegisters;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
		public byte[] Reserved4;
	}

	// x64 context structure
	[StructLayout(LayoutKind.Sequential, Pack = 16)]
	public struct CONTEXT64
	{
		public ulong P1Home;
		public ulong P2Home;
		public ulong P3Home;
		public ulong P4Home;
		public ulong P5Home;
		public ulong P6Home;

		public CONTEXT_FLAGS ContextFlags;
		public uint MxCsr;

		public ushort SegCs;
		public ushort SegDs;
		public ushort SegEs;
		public ushort SegFs;
		public ushort SegGs;
		public ushort SegSs;
		public uint EFlags;

		public ulong Dr0;
		public ulong Dr1;
		public ulong Dr2;
		public ulong Dr3;
		public ulong Dr6;
		public ulong Dr7;

		public ulong Rax;
		public ulong Rcx;
		public ulong Rdx;
		public ulong Rbx;
		public ulong Rsp;
		public ulong Rbp;
		public ulong Rsi;
		public ulong Rdi;
		public ulong R8;
		public ulong R9;
		public ulong R10;
		public ulong R11;
		public ulong R12;
		public ulong R13;
		public ulong R14;
		public ulong R15;
		public ulong Rip;

		public XSAVE_FORMAT64 DUMMYUNIONNAME;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
		public M128A[] VectorRegister;
		public ulong VectorControl;

		public ulong DebugControl;
		public ulong LastBranchToRip;
		public ulong LastBranchFromRip;
		public ulong LastExceptionToRip;
		public ulong LastExceptionFromRip;
		} 
	
    public static int Main2(string[] args)
    {
		// Get target process by name
		if(args.Length == 0){Console.WriteLine("Please enter a process name");System.Environment.Exit(1);}
		Process targetProcess = Process.GetProcessesByName(args[0])[0];
		Console.WriteLine("ProcessId: " + targetProcess.Id);

		// Open and Suspend first thread
		ProcessThread pT = targetProcess.Threads[0];
		for(int i = 0; i < targetProcess.Threads.Count;i++)
		{
			if (pT.TotalProcessorTime < targetProcess.Threads[i].TotalProcessorTime);
		}

		Console.WriteLine("ThreadId: " + pT.Id);		
		IntPtr pOpenThread = OpenThread(ThreadAccess.THREAD_HIJACK, false, (uint)pT.Id);
		SuspendThread(pOpenThread);
		
		// Get thread context
		CONTEXT64 tContext = new CONTEXT64();
		tContext.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;
		if (GetThreadContext(pOpenThread, ref tContext))
		{
			Console.WriteLine("CurrentEip    : {0}", tContext.Rip.ToString("X12"));
		}

		// WinExec shellcode from: https://github.com/peterferrie/win-exec-calc-shellcode
		// Compiled with: 
		// nasm w64-exec-calc-shellcode.asm -DSTACK_ALIGN=TRUE -DFUNC=TRUE -DCLEAN=TRUE -o w64-exec-calc-shellcode.bin
		//byte[] payload = new byte[112] {
		//	0x50,0x51,0x52,0x53,0x56,0x57,0x55,0x54,0x58,0x66,0x83,0xe4,0xf0,0x50,0x6a,0x60,0x5a,0x68,0x63,0x61,0x6c,0x63,0x54,0x59,0x48,0x29,0xd4,0x65,0x48,0x8b,0x32,0x48,0x8b,0x76,0x18,0x48,0x8b,0x76,0x10,0x48,0xad,0x48,0x8b,0x30,0x48,0x8b,0x7e,0x30,0x03,0x57,0x3c,0x8b,0x5c,0x17,0x28,0x8b,0x74,0x1f,0x20,0x48,0x01,0xfe,0x8b,0x54,0x1f,0x24,0x0f,0xb7,0x2c,0x17,0x8d,0x52,0x02,0xad,0x81,0x3c,0x07,0x57,0x69,0x6e,0x45,0x75,0xef,0x8b,0x74,0x1f,0x1c,0x48,0x01,0xfe,0x8b,0x34,0xae,0x48,0x01,0xf7,0x99,0xff,0xd7,0x48,0x83,0xc4,0x68,0x5c,0x5d,0x5f,0x5e,0x5b,0x5a,0x59,0x58,0xc3
		//};

		//0x18
		//0x28
		byte[] payload = {
			0x50,														//push rax
			0x51,														//push rcx
			0x52,														//push rdx
			0x53,														//push rbx
			0x54,							
			0x55, 
			0x56, 
			0x57, 
			0x41, 0x50,													//push r8
			0x41, 0x51,													//push r9
			0x41, 0x52,													//push r10
			0x41, 0x53,													//push r11
			0x41, 0x54,													//push r12
			0x41, 0x55,													//push r13
			0x41, 0x56,													//push r14
			0x41, 0x57,													//push r15
			0x55,														//push rbp
			0x48, 0x8B, 0xEC,											//mob rbp,rsp
			0x48, 0xB9, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, //mov rcx, &lua_buffer
			0x48, 0x8B, 0xD1,											//mov rdx, rcx
			0x4D, 0x31, 0xC0,											//xor r8,r8 -- r8 is luaIsTainted
			0x49, 0xBF, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, //mov r15, FrameScript_Execute
			0x41, 0xFF, 0xD7,											//call r15
			
			0x48, 0x8B, 0xE5,											//mov rsp, rbp
			0x5D,														//pop rbp
			0x41, 0x5F,													//pop r15
			0x41, 0x5E,													//pop r14
			0x41, 0x5D,													//pop r13
			0x41, 0x5C,													//pop r12
			0x41, 0x5B,													//pop r11
			0x41, 0x5A,													//pop r10
			0x41, 0x59,													//pop r9
			0x41, 0x58, 												//pop r8
			0x5F, 														//pop rdi
			0x5E, 														//pop rsi
			0x5D, 														//pop rbp
			0x5C, 														//pop rsp
			0x5B, 														//pop rbx
			0x5A, 														//pop rdx
			0x59, 														//pop rcx
			0x58,														//pop rax
			0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00 //jmp RIP
		};

		// OpenProcess to allocate memory
		IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);


		string luaScript = "print(\"ferib is awesome\")";
		IntPtr allocMemAddress2 = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)(luaScript.Length), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		long luacall = (long)targetProcess.MainModule.BaseAddress + 0x522280;
		byte[] luacalls = BitConverter.GetBytes(luacall);
		byte[] luacodes = BitConverter.GetBytes((long)allocMemAddress2);
		byte[] rips = BitConverter.GetBytes(tContext.Rip);

		for(int i = 0; i < 8; i++)
		{
			payload[0x2E + i] = luacalls[i];
			payload[0x1E + i] = luacodes[i];
			payload[payload.Length - 0x08 + i] = rips[i];
		}
		
		
		// Allocate memory for shellcode within process
		IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((payload.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		
		// Write shellcode within process
		UIntPtr bytesWritten;
        bool resp1 = WriteProcessMemory(procHandle, allocMemAddress, payload, (uint)((payload.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);
        WriteProcessMemory(procHandle, allocMemAddress2, Encoding.UTF8.GetBytes(luaScript), (uint)(luaScript.Length), out bytesWritten);
		
		// Read memory to view shellcode
		int bytesRead = 0;
        byte[] buffer = new byte[payload.Length];
		ReadProcessMemory(procHandle, allocMemAddress, buffer, buffer.Length, ref bytesRead);
		
		// Set context EIP to location of shellcode
		tContext.Rip=(ulong)allocMemAddress.ToInt64();
		
		// Apply new context to suspended thread
		if(!SetThreadContext(pOpenThread, ref tContext))
		{
			Console.WriteLine("Error setting context");
		}
		if (GetThreadContext(pOpenThread, ref tContext))
		{
		Console.WriteLine("ShellcodeAddress: " + allocMemAddress.ToString("X"));
        Console.WriteLine("NewEip          : {0}", tContext.Rip.ToString("X"));
		}
		// Resume the thread, redirecting execution to shellcode, then back to original process
		Console.WriteLine("Redirecting execution!");
		ResumeThread(pOpenThread);
	
        return 0;
    }
}
//wow.exe+522280