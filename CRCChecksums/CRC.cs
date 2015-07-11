using System;

namespace Free.Crypto.CRCChecksums
{
	/// <summary>
	/// <para>Creates instances of the CRC algorithms with the parameter as described in
	/// "A Painless Guide to CRC Error Detection Algorithms" (see crc_v3.txt) by Ross Williams.</para>
	/// <para>Also, supplies methods for combining CRCs (see remarks).</para>
	/// </summary>
	/// <remarks>
	/// <para>Combining of CRCs - Basic idea:</para>
	/// <para>With a matrix operation we can perform a 1 Zero-Bit-Add-to-CRC-operation as matrix mutiplication.</para>
	/// <para>Instead of calculating <c>Register=(Register&lt;&lt;1)^(WasTopBitSet?Polynomial:0)</c> we calculate <c>Register=Matrix*Register</c>.</para>
	/// <para>This might seem slower since the multiplication is more complex and done bit by bit,
	/// but with multiplication we can square something. "And this is good why?" you might ask.</para>
	/// <para>Let's take a look at the operation for more than just one bit:
	/// <code>Register=Matrix*Register; Register=Matrix*Register; Register=Matrix*Register; ... Register=Matrix*Register; // Length times</code></para>
	/// <para>or better:
	/// <code>Register=Matrix*(Matrix*(Matrix*(Matrix*...*(Matrix*Register)...))); // Length times</code></para>
	/// <para>Not much help either? How about a little bit cleaner:
	/// <code>Register=Matrix*Matrix*Matrix*Matrix*...*Matrix*Register; // Length times</code></para>
	/// <para>Still don't get it? How about:
	/// <code>
	/// // Pseudo-code where ^ is the power operator not xor
	/// Register=((Matrix^0x80000000)^a31*(Matrix^0x40000000)^a30...*(Matrix^4)^a2*(Matrix^2)^a1*(Matrix^1)^a0)*Register;
	/// // with a31, a30 ... a2, a1 and a0 set to 1 or 0 depending on the bits of Length</code>
	/// </para>
	/// <para>Instead of multiplying our register 'Length' times with the matrix, we multiply the
	/// power-of-twos of the matrix with the register for all power-of-twos that are present
	/// in 'Length'. So at most we multiply the register 32 times with whatever POT we need
	/// and 31+3 (2^3=8 bits per byte) times the matrix/POT with itself (square) to get the
	/// power-of-twos.</para>
	/// <para>Basically: We calculate <c>Register=(Matrix^Length)*Register</c> with a very fast way to calculate <c>Matrix^Length</c>.</para>
	/// <para>Performance (for a CRC-32):</para>
	/// <para>The length (number of zero-bytes) at which this method gets faster then the actual
	/// adding of zero-bytes to crc1 (to account for the bytes accumulated into crc2),
	/// was in test at about 38000. Tenfolding the number tenfolded the time needed when
	/// actual adding of zero-bytes, but just increased about 20% with this method.</para>
	/// </remarks>
	/// <threadsafety static="true" instance="true"/>
	[CLSCompliant(false)]
	public static partial class CRC
	{
		/// <summary>
		/// Catalog of CRC algorithm definitions.
		/// </summary>
		public static readonly CRCDescriptor[] CRCs=
		{
			CRC3_ROHC, CRC4_ITU, CRC5_EPC, CRC5_ITU, CRC5_USB, CRC6_CDMA2000A, CRC6_CDMA2000B,
			CRC6_DARC, CRC6_ITU, CRC7, CRC7_ROHC,
			CRC8, CRC8_CDMA2000, CRC8_DARC, CRC8_DVBS2, CRC8_EBU, CRC8_ICODE, CRC8_J1850,
			CRC8_ITU, CRC8_MAXIM, CRC8_ROHC, CRC8_WCDMA,
			CRC10, CRC10_CDMA2000, CRC11, CRC12_3GPP, CRC12_CDMA2000, CRC12_DECT, CRC13_BBC,
			CRC14_DARC, CRC15, CRC15_MPT1327,
			CRC16_ARC, CRC16_AUG_CCITT, CRC16_BUYPASS, CRC16_CCITT_FALSE, CRC16_CDMA2000,
			CRC16_DDS110, CRC16_DECTR, CRC16_DECTX, CRC16_DNP, CRC16_EN13757, CRC16_GENIBUS,
			CRC16_MAXIM, CRC16_MCRF4XX, CRC16_RIELLO, CRC16_T10DIF, CRC16_TELEDISK,
			CRC16_TMS37157, CRC16_USB, CRCA, KERMIT, MODBUS, X_25, XMODEM,
			CRC17, CRC21, CRC24_OPENPGP, CRC24_FLEXRAYA, CRC24_FLEXRAYB, CRC30, CRC31_PHILIPS,
			CRC32, CRC32_BZIP2, CRC32C, CRC32D, CRC32_MPEG2, CRC32_POSIX, CRC32Q, JAMCRC, XFER,
			CRC40_GSM,
			CRC64, CRC64_WE, CRC64_XZ, CRC64_1B, CRC64_Jones,
			CRC82_DARC
		};

		#region < 8-bit CRCs
		/// <summary>
		/// Decriptor for CRC-3/ROHC.
		/// </summary>
		public static readonly CRCDescriptor CRC3_ROHC=new CRCDescriptor { Name="CRC-3/ROHC", Width=3, Polynomial=0x3, Init=0x7, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-4/ITU.
		/// </summary>
		public static readonly CRCDescriptor CRC4_ITU=new CRCDescriptor { Name="CRC-4/ITU", Width=4, Polynomial=0x3, Init=0, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-5/EPC.
		/// </summary>
		public static readonly CRCDescriptor CRC5_EPC=new CRCDescriptor { Name="CRC-5/EPC", Width=5, Polynomial=0x09, Init=0x09, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-5/ITU.
		/// </summary>
		public static readonly CRCDescriptor CRC5_ITU=new CRCDescriptor { Name="CRC-5/ITU", Width=5, Polynomial=0x15, Init=0, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-5/USB.
		/// </summary>
		public static readonly CRCDescriptor CRC5_USB=new CRCDescriptor { Name="CRC-5/USB", Width=5, Polynomial=0x05, Init=0x1f, RefIn=true, RefOut=true, XorOut=0x1f };

		/// <summary>
		/// Decriptor for CRC-6/CDMA2000-A.
		/// </summary>
		public static readonly CRCDescriptor CRC6_CDMA2000A=new CRCDescriptor { Name="CRC-6/CDMA2000-A", Width=6, Polynomial=0x27, Init=0x3f, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-6/CDMA2000-B.
		/// </summary>
		public static readonly CRCDescriptor CRC6_CDMA2000B=new CRCDescriptor { Name="CRC-6/CDMA2000-B", Width=6, Polynomial=0x07, Init=0x3f, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-6/DARC.
		/// </summary>
		public static readonly CRCDescriptor CRC6_DARC=new CRCDescriptor { Name="CRC-6/DARC", Width=6, Polynomial=0x19, Init=0, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-6/ITU.
		/// </summary>
		public static readonly CRCDescriptor CRC6_ITU=new CRCDescriptor { Name="CRC-6/ITU", Width=6, Polynomial=0x03, Init=0, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-7.
		/// </summary>
		public static readonly CRCDescriptor CRC7=new CRCDescriptor { Name="CRC-7", Width=7, Polynomial=0x09, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-7/ROHC.
		/// </summary>
		public static readonly CRCDescriptor CRC7_ROHC=new CRCDescriptor { Name="CRC-7/ROHC", Width=7, Polynomial=0x4f, Init=0x7f, RefIn=true, RefOut=true, XorOut=0 };
		#endregion

		#region 8-bit CRCs
		/// <summary>
		/// Decriptor for CRC-8.
		/// </summary>
		public static readonly CRCDescriptor CRC8=new CRCDescriptor { Name="CRC-8", Width=8, Polynomial=0x07, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-8/CDMA2000.
		/// </summary>
		public static readonly CRCDescriptor CRC8_CDMA2000=new CRCDescriptor { Name="CRC-8/CDMA2000", Width=8, Polynomial=0x9b, Init=0xff, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-8/DARC.
		/// </summary>
		public static readonly CRCDescriptor CRC8_DARC=new CRCDescriptor { Name="CRC-8/DARC", Width=8, Polynomial=0x39, Init=0, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-8/DVB-S2.
		/// </summary>
		public static readonly CRCDescriptor CRC8_DVBS2=new CRCDescriptor { Name="CRC-8/DVB-S2", Width=8, Polynomial=0xd5, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-8/EBU (AKA CRC-8/AES).
		/// </summary>
		public static readonly CRCDescriptor CRC8_EBU=new CRCDescriptor { Name="CRC-8/EBU", Aliases=new string[] { "CRC-8/AES" }, Width=8, Polynomial=0x1d, Init=0xff, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-8/I-CODE.
		/// </summary>
		public static readonly CRCDescriptor CRC8_ICODE=new CRCDescriptor { Name="CRC-8/I-CODE", Width=8, Polynomial=0x1d, Init=0xfd, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-8/J1850 (AKA CRC-8/SAEJ1850 AKA CRC-8/SAE-J1850).
		/// </summary>
		public static readonly CRCDescriptor CRC8_J1850=new CRCDescriptor { Name="CRC-8/J1850", Aliases=new string[] { "CRC-8/SAEJ1850", "CRC-8/SAE-J1850" }, Width=8, Polynomial=0x1d, Init=0xff, RefIn=false, RefOut=false, XorOut=0xff };

		/// <summary>
		/// Decriptor for CRC-8/ITU.
		/// </summary>
		public static readonly CRCDescriptor CRC8_ITU=new CRCDescriptor { Name="CRC-8/ITU", Width=8, Polynomial=0x07, Init=0, RefIn=false, RefOut=false, XorOut=0x55 };

		/// <summary>
		/// Decriptor for CRC-8/MAXIM (AKA DOW-CRC AKA CRC-8/DALLAS).
		/// </summary>
		public static readonly CRCDescriptor CRC8_MAXIM=new CRCDescriptor { Name="CRC-8/MAXIM", Aliases=new string[] { "DOW-CRC", "CRC-8/DALLAS" }, Width=8, Polynomial=0x31, Init=0, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-8/ROHC.
		/// </summary>
		public static readonly CRCDescriptor CRC8_ROHC=new CRCDescriptor { Name="CRC-8/ROHC", Width=8, Polynomial=0x07, Init=0xff, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-8/WCDMA.
		/// </summary>
		public static readonly CRCDescriptor CRC8_WCDMA=new CRCDescriptor { Name="CRC-8/WCDMA", Width=8, Polynomial=0x9b, Init=0, RefIn=true, RefOut=true, XorOut=0 };
		#endregion

		#region 10-bit - 15-bit CRCs
		/// <summary>
		/// Decriptor for CRC-10.
		/// </summary>
		public static readonly CRCDescriptor CRC10=new CRCDescriptor { Name="CRC-10", Width=10, Polynomial=0x233, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-10/CDMA2000.
		/// </summary>
		public static readonly CRCDescriptor CRC10_CDMA2000=new CRCDescriptor { Name="CRC-10/CDMA2000", Width=10, Polynomial=0x3d9, Init=0x3ff, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-11.
		/// </summary>
		public static readonly CRCDescriptor CRC11=new CRCDescriptor { Name="CRC-11", Width=11, Polynomial=0x385, Init=0x01a, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-12/3GPP.
		/// </summary>
		public static readonly CRCDescriptor CRC12_3GPP=new CRCDescriptor { Name="CRC-12/3GPP", Width=12, Polynomial=0x80f, Init=0, RefIn=false, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-12/CDMA2000.
		/// </summary>
		public static readonly CRCDescriptor CRC12_CDMA2000=new CRCDescriptor { Name="CRC-12/CDMA2000", Width=12, Polynomial=0xf13, Init=0xfff, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-12/DECT (AKA X-CRC-12).
		/// </summary>
		public static readonly CRCDescriptor CRC12_DECT=new CRCDescriptor { Name="CRC-12/DECT", Aliases=new string[] { "X-CRC-12" }, Width=12, Polynomial=0x80f, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-13/BBC.
		/// </summary>
		public static readonly CRCDescriptor CRC13_BBC=new CRCDescriptor { Name="CRC-13/BBC", Width=13, Polynomial=0x1cf5, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-14/DARC.
		/// </summary>
		public static readonly CRCDescriptor CRC14_DARC=new CRCDescriptor { Name="CRC-14/DARC", Width=14, Polynomial=0x0805, Init=0, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-15 (AKA CRC-15/CAN AKA CRC-15/CAN-FD).
		/// </summary>
		public static readonly CRCDescriptor CRC15=new CRCDescriptor { Name="CRC-15", Aliases=new string[] { "CRC-15/CAN", "CRC-15/CAN-FD" }, Width=15, Polynomial=0x4599, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-15/MPT1327.
		/// </summary>
		public static readonly CRCDescriptor CRC15_MPT1327=new CRCDescriptor { Name="CRC-15/MPT1327", Width=15, Polynomial=0x6815, Init=0, RefIn=false, RefOut=false, XorOut=1 };
		#endregion

		#region 16-bit CRCs
		/// <summary>
		/// Decriptor for CRC-16 (AKA ARC AKA CRC-IBM AKA CRC-16/LHA).
		/// </summary>
		public static readonly CRCDescriptor CRC16_ARC=new CRCDescriptor { Name="CRC-16", Aliases=new string[] { "ARC", "CRC-IBM", "CRC-16/ARC", "CRC-16/LHA" }, Width=16, Polynomial=0x8005, Init=0, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-16/AUG-CCITT (AKA CRC-16/SPI-FUJITSU).
		/// </summary>
		public static readonly CRCDescriptor CRC16_AUG_CCITT=new CRCDescriptor { Name="CRC-16/AUG-CCITT", Aliases=new string[] { "CRC-16/SPI-FUJITSU" }, Width=16, Polynomial=0x1021, Init=0x1d0f, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-16/BUYPASS (AKA CRC-16/VERIFONE).
		/// </summary>
		public static readonly CRCDescriptor CRC16_BUYPASS=new CRCDescriptor { Name="CRC-16/BUYPASS", Aliases=new string[] { "CRC-16/VERIFONE" }, Width=16, Polynomial=0x8005, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-16/CCITT-FALSE.
		/// </summary>
		/// <remarks>
		/// An algorithm commonly misidentified as <see cref="KERMIT">CRC-CCITT</see>. For the true CCITT algorithm see <see cref="KERMIT"/>. For the later ITU-T algorithm see <see cref="X_25">X.25</see>.
		/// </remarks>
		public static readonly CRCDescriptor CRC16_CCITT_FALSE=new CRCDescriptor { Name="CRC-16/CCITT-FALSE", Width=16, Polynomial=0x1021, Init=0xffff, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-16/CDMA2000.
		/// </summary>
		public static readonly CRCDescriptor CRC16_CDMA2000=new CRCDescriptor { Name="CRC-16/CDMA2000", Width=16, Polynomial=0xc867, Init=0xffff, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-16/DDS-110.
		/// </summary>
		public static readonly CRCDescriptor CRC16_DDS110=new CRCDescriptor { Name="CRC-16/DDS-110", Width=16, Polynomial=0x8005, Init=0x800d, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-16/DECT-R (AKA R-CRC-16).
		/// </summary>
		public static readonly CRCDescriptor CRC16_DECTR=new CRCDescriptor { Name="CRC-16/DECT-R", Aliases=new string[] { "R-CRC-16" }, Width=16, Polynomial=0x0589, Init=0, RefIn=false, RefOut=false, XorOut=1 };

		/// <summary>
		/// Decriptor for CRC-16/DECT-X (AKA X-CRC-16).
		/// </summary>
		public static readonly CRCDescriptor CRC16_DECTX=new CRCDescriptor { Name="CRC-16/DECT-X", Aliases=new string[] { "X-CRC-16" }, Width=16, Polynomial=0x0589, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-16/DNP.
		/// </summary>
		public static readonly CRCDescriptor CRC16_DNP=new CRCDescriptor { Name="CRC-16/DNP", Width=16, Polynomial=0x3d65, Init=0, RefIn=true, RefOut=true, XorOut=0xffff };

		/// <summary>
		/// Decriptor for CRC-16/EN-13757.
		/// </summary>
		public static readonly CRCDescriptor CRC16_EN13757=new CRCDescriptor { Name="CRC-16/EN-13757", Width=16, Polynomial=0x3d65, Init=0, RefIn=false, RefOut=false, XorOut=0xffff };

		/// <summary>
		/// Decriptor for CRC-16/GENIBUS (AKA CRC-16/EPC AKA CRC-16/I-CODE AKA CRC-16/DARC).
		/// </summary>
		public static readonly CRCDescriptor CRC16_GENIBUS=new CRCDescriptor { Name="CRC-16/GENIBUS", Aliases=new string[] { "CRC-16/EPC", "CRC-16/I-CODE", "CRC-16/DARC" }, Width=16, Polynomial=0x1021, Init=0xffff, RefIn=false, RefOut=false, XorOut=0xffff };

		/// <summary>
		/// Decriptor for CRC-16/MAXIM.
		/// </summary>
		public static readonly CRCDescriptor CRC16_MAXIM=new CRCDescriptor { Name="CRC-16/MAXIM", Width=16, Polynomial=0x8005, Init=0, RefIn=true, RefOut=true, XorOut=0xffff };

		/// <summary>
		/// Decriptor for CRC-16/MCRF4XX.
		/// </summary>
		public static readonly CRCDescriptor CRC16_MCRF4XX=new CRCDescriptor { Name="CRC-16/MCRF4XX", Width=16, Polynomial=0x1021, Init=0xffff, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-16/RIELLO.
		/// </summary>
		public static readonly CRCDescriptor CRC16_RIELLO=new CRCDescriptor { Name="CRC-16/RIELLO", Width=16, Polynomial=0x1021, Init=0xb2aa, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-16/T10-DIF.
		/// </summary>
		public static readonly CRCDescriptor CRC16_T10DIF=new CRCDescriptor { Name="CRC-16/T10-DIF", Width=16, Polynomial=0x8bb7, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-16/TELEDISK.
		/// </summary>
		public static readonly CRCDescriptor CRC16_TELEDISK=new CRCDescriptor { Name="CRC-16/TELEDISK", Width=16, Polynomial=0xa097, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-16/TMS37157.
		/// </summary>
		public static readonly CRCDescriptor CRC16_TMS37157=new CRCDescriptor { Name="CRC-16/TMS37157", Width=16, Polynomial=0x1021, Init=0x89ec, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-16/USB.
		/// </summary>
		public static readonly CRCDescriptor CRC16_USB=new CRCDescriptor { Name="CRC-16/USB", Width=16, Polynomial=0x8005, Init=0xffff, RefIn=true, RefOut=true, XorOut=0xffff };

		/// <summary>
		/// Decriptor for CRC-A.
		/// </summary>
		public static readonly CRCDescriptor CRCA=new CRCDescriptor { Name="CRC-A", Width=16, Polynomial=0x1021, Init=0xc6c6, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for KERMIT (AKA CRC-16/CCITT AKA CRC-16/CCITT-TRUE AKA CRC-CCITT).
		/// </summary>
		/// <remarks>
		/// Press et al. identify the CCITT algorithm with the one implemented in Kermit. V.41 is endianness-agnostic, referring only to bit sequences, but the CRC appears reflected when used with LSB-first modems. Ironically, the unreflected form is used in <see cref="XMODEM"/>.
		/// For the later ITU-T algorithm see <see cref="X_25">X.25</see>.
		/// </remarks>
		public static readonly CRCDescriptor KERMIT=new CRCDescriptor { Name="KERMIT", Aliases=new string[] { "CRC-16/CCITT", "CRC-16/CCITT-TRUE", "CRC-CCITT" }, Width=16, Polynomial=0x1021, Init=0, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for MODBUS.
		/// </summary>
		public static readonly CRCDescriptor MODBUS=new CRCDescriptor { Name="MODBUS", Width=16, Polynomial=0x8005, Init=0xffff, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for X-25 (AKA CRC-16/IBM-SDLC AKA CRC-16/ISO-HDLC AKA CRC-B).
		/// </summary>
		public static readonly CRCDescriptor X_25=new CRCDescriptor { Name="X-25", Aliases=new string[] { "CRC-16/IBM-SDLC", "CRC-16/ISO-HDLC", "CRC-B" }, Width=16, Polynomial=0x1021, Init=0xffff, RefIn=true, RefOut=true, XorOut=0xffff };

		/// <summary>
		/// Decriptor for XMODEM (AKA ZMODEM AKA CRC-16/ACORN).
		/// </summary>
		public static readonly CRCDescriptor XMODEM=new CRCDescriptor { Name="XMODEM", Aliases=new string[] { "ZMODEM", "CRC-16/ACORN" }, Width=16, Polynomial=0x1021, Init=0, RefIn=false, RefOut=false, XorOut=0 };
		#endregion

		#region 17-bit - 31-bit CRCs
		/// <summary>
		/// Decriptor for CRC-17 (AKA CRC-17/CAN-FD).
		/// </summary>
		public static readonly CRCDescriptor CRC17=new CRCDescriptor { Name="CRC-17", Aliases=new string[] { "CRC-17/CAN-FD" }, Width=17, Polynomial=0x1685B, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-21 (AKA CRC-21/CAN-FD).
		/// </summary>
		public static readonly CRCDescriptor CRC21=new CRCDescriptor { Name="CRC-21", Aliases=new string[] { "CRC-21/CAN-FD" }, Width=21, Polynomial=0x102899, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-24 (AKA CRC-24/OPENPGP).
		/// </summary>
		public static readonly CRCDescriptor CRC24_OPENPGP=new CRCDescriptor { Name="CRC-24", Aliases=new string[] { "CRC-24/OPENPGP" }, Width=24, Polynomial=0x864cfb, Init=0xb704ce, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-24/FLEXRAY-A.
		/// </summary>
		public static readonly CRCDescriptor CRC24_FLEXRAYA=new CRCDescriptor { Name="CRC-24/FLEXRAY-A", Width=24, Polynomial=0x5d6dcb, Init=0xfedcba, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-24/FLEXRAY-B.
		/// </summary>
		public static readonly CRCDescriptor CRC24_FLEXRAYB=new CRCDescriptor { Name="CRC-24/FLEXRAY-B", Width=24, Polynomial=0x5d6dcb, Init=0xabcdef, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-30.
		/// </summary>
		public static readonly CRCDescriptor CRC30=new CRCDescriptor { Name="CRC-30", Width=30, Polynomial=0x2030B9C7, Init=0x3fffffff, RefIn=false, RefOut=false, XorOut=0x3fffffff };

		/// <summary>
		/// Decriptor for CRC-31/PHILIPS.
		/// </summary>
		public static readonly CRCDescriptor CRC31_PHILIPS=new CRCDescriptor { Name="CRC-31/PHILIPS", Width=31, Polynomial=0x04c11db7, Init=0x7fffffff, RefIn=false, RefOut=false, XorOut=0x7fffffff };
		#endregion

		#region 32-bit CRCs
		/// <summary>
		/// Decriptor for CRC-32 (IEEE, Ethernet) (AKA CRC-32/ADCCP AKA PKZIP).
		/// </summary>
		public static readonly CRCDescriptor CRC32=new CRCDescriptor { Name="CRC-32", Aliases=new string[] { "CRC-32/IEEE", "CRC-32/ETHERNET", "CRC-32/ADCCP", "PKZIP" }, Width=32, Polynomial=0x04c11db7, Init=0xffffffff, RefIn=true, RefOut=true, XorOut=0xffffffff };

		/// <summary>
		/// Decriptor for CRC-32/BZIP2 (AKA CRC-32/AAL5 AKA CRC-32/DECT-B AKA B-CRC-32).
		/// </summary>
		public static readonly CRCDescriptor CRC32_BZIP2=new CRCDescriptor { Name="CRC-32/BZIP2", Aliases=new string[] { "CRC-32/AAL5", "CRC-32/DECT-B", "B-CRC-32" }, Width=32, Polynomial=0x04c11db7, Init=0xffffffff, RefIn=false, RefOut=false, XorOut=0xffffffff };

		/// <summary>
		/// Decriptor for CRC-32C (AKA CRC-32/ISCSI AKA CRC-32/CASTAGNOLI).
		/// </summary>
		public static readonly CRCDescriptor CRC32C=new CRCDescriptor { Name="CRC-32C", Aliases=new string[] { "CRC-32/ISCSI", "CRC-32/CASTAGNOLI" }, Width=32, Polynomial=0x1edc6f41, Init=0xffffffff, RefIn=true, RefOut=true, XorOut=0xffffffff };

		/// <summary>
		/// Decriptor for CRC-32D.
		/// </summary>
		public static readonly CRCDescriptor CRC32D=new CRCDescriptor { Name="CRC-32D", Width=32, Polynomial=0xa833982b, Init=0xffffffff, RefIn=true, RefOut=true, XorOut=0xffffffff };

		/// <summary>
		/// Decriptor for CRC-32/MPEG-2.
		/// </summary>
		public static readonly CRCDescriptor CRC32_MPEG2=new CRCDescriptor { Name="CRC-32/MPEG-2", Width=32, Polynomial=0x04c11db7, Init=0xffffffff, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-32/POSIX (AKA CKSUM).
		/// </summary>
		public static readonly CRCDescriptor CRC32_POSIX=new CRCDescriptor { Name="CRC-32/POSIX", Aliases=new string[] { "CKSUM" }, Width=32, Polynomial=0x04c11db7, Init=0, RefIn=false, RefOut=false, XorOut=0xffffffff };

		/// <summary>
		/// Decriptor for CRC-32Q.
		/// </summary>
		public static readonly CRCDescriptor CRC32Q=new CRCDescriptor { Name="CRC-32Q", Width=32, Polynomial=0x814141ab, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for JAMCRC.
		/// </summary>
		public static readonly CRCDescriptor JAMCRC=new CRCDescriptor { Name="JAMCRC", Width=32, Polynomial=0x04c11db7, Init=0xffffffff, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for XFER.
		/// </summary>
		public static readonly CRCDescriptor XFER=new CRCDescriptor { Name="XFER", Width=32, Polynomial=0x000000af, Init=0, RefIn=false, RefOut=false, XorOut=0 };
		#endregion

		/// <summary>
		/// Decriptor for CRC-40/GSM.
		/// </summary>
		public static readonly CRCDescriptor CRC40_GSM=new CRCDescriptor { Name="CRC-40/GSM", Width=40, Polynomial=0x0004820009, Init=0, RefIn=false, RefOut=false, XorOut=0xffffffffff };

		#region 64-bit CRCs
		/// <summary>
		/// Decriptor for CRC-64 (AKA CRC-64/ECMA).
		/// </summary>
		public static readonly CRCDescriptor CRC64=new CRCDescriptor { Name="CRC-64", Aliases=new string[] { "CRC-64/ECMA"}, Width=64, Polynomial=0x42F0E1EBA9EA3693, Init=0, RefIn=false, RefOut=false, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-64/WE
		/// </summary>
		public static readonly CRCDescriptor CRC64_WE=new CRCDescriptor { Name="CRC-64/WE", Width=64, Polynomial=0x42F0E1EBA9EA3693, Init=0xFFFFFFFFFFFFFFFF, RefIn=false, RefOut=false, XorOut=0xFFFFFFFFFFFFFFFF };

		/// <summary>
		/// Decriptor for CRC-64/XZ.
		/// </summary>
		public static readonly CRCDescriptor CRC64_XZ=new CRCDescriptor { Name="CRC-64/XZ", Width=64, Polynomial=0x42F0E1EBA9EA3693, Init=0xFFFFFFFFFFFFFFFF, RefIn=true, RefOut=true, XorOut=0xFFFFFFFFFFFFFFFF };

		/// <summary>
		/// Decriptor for CRC-64/1B (AKA CRC-64/SWISSPROT AKA CRC-64/TrEMBL).
		/// </summary>
		public static readonly CRCDescriptor CRC64_1B=new CRCDescriptor { Name="CRC-64/1B", Aliases=new string[] { "CRC-64/SWISSPROT", "CRC-64/TrEMBL" }, Width=64, Polynomial=0x1B, Init=0, RefIn=true, RefOut=true, XorOut=0 };

		/// <summary>
		/// Decriptor for CRC-64/Jones.
		/// </summary>
		public static readonly CRCDescriptor CRC64_Jones=new CRCDescriptor { Name="CRC-64/Jones", Width=64, Polynomial=0xAD93D23594C935A9, Init=0xFFFFFFFFFFFFFFFF, RefIn=true, RefOut=true, XorOut=0 };
		#endregion

		/// <summary>
		/// Decriptor for CRC-82/DARC.
		/// </summary>
		public static readonly CRCDescriptor CRC82_DARC=new CRCDescriptor { Name="CRC-82/DARC", Width=82, PolynomialHigh=0x0308c, Polynomial=0x0111011401440411, InitHigh=0, Init=0, RefIn=true, RefOut=true, XorOutHigh=0, XorOut=0 };
	}
}
