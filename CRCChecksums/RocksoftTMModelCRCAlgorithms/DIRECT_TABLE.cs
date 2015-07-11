using System;
using System.Collections.Generic;

namespace Free.Crypto.CRCChecksums.RocksoftTMModelCRCAlgorithms
{
	/// <summary>
	/// Implements the DIRECT TABLE algorithm as described in
	/// "A Painless Guide to CRC Error Detection Algorithms" (see crc_v3.txt) by Ross Williams.
	/// </summary>
	/// <remarks>
	/// The functions in this class represent an implementation that could be defined via the
	/// "Rocksoft^tm Model CRC Algorithm" parameter:
	/// <list type="table">
	///  <listheader><term>Parameter</term><description>Value</description></listheader>
	///  <item><term>Name</term><description>Not needed.</description></item>
	///  <item><term>Width</term><description>1-64 (depending on the type of polynomial argument)</description></item>
	///  <item><term>Poly</term><description>Any 1-64 bit polynomial.</description></item>
	///  <item><term>Init</term><description>0</description></item>
	///  <item><term>RefIn</term><description>false</description></item>
	///  <item><term>RefOut</term><description>false</description></item>
	///  <item><term>XorOut</term><description>0</description></item>
	///  <item><term>Check</term><description>Depends on the polynomial.</description></item>
	/// </list>
	/// </remarks>
	/// <threadsafety static="true" instance="true"/>
	[CLSCompliant(false)]
	[Obsolete("This class is for educational purposes only. You should use the high-performance implementations in the class CRC.")]
	public static class DIRECT_TABLE
	{
		/// <summary>
		/// Calculates the CRC of bits stored in a <see cref="Byte"/>[].
		/// The "Slightly Mangled Table-Driven Implementation". (see chapter 10 for explantion)
		/// </summary>
		/// <param name="polynomial">The polynomial to use. Bits must be in the most significant bits.</param>
		/// <param name="data">The bits. (Most significant bit of the first byte first (starting at <paramref name="offset"/>.)</param>
		/// <param name="offset">Location in the array where to start in bytes.</param>
		/// <param name="count">Number of bytes.</param>
		/// <returns>The CRC value, filled in the most significant bits.</returns>
		public static byte Get(byte polynomial, IList<byte> data, int offset=0, int count=0)
		{
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");

			return Get(TABLE.GenerateTable(polynomial), data, offset, count);
		}

		/// <summary>
		/// Calculates the CRC of bits stored in a <see cref="Byte"/>[].
		/// The "Slightly Mangled Table-Driven Implementation". (see chapter 10 for explantion)
		/// </summary>
		/// <param name="table">The table generated from the polynomial to use.</param>
		/// <param name="data">The bits. (Most significant bit of the first byte first (starting at <paramref name="offset"/>.)</param>
		/// <param name="offset">Location in the array where to start in bytes.</param>
		/// <param name="count">Number of bytes.</param>
		/// <returns>The CRC value, filled in the most significant bits.</returns>
		public static byte Get(byte[] table, IList<byte> data, int offset=0, int count=0)
		{
			if(table==null) throw new ArgumentNullException("table");
			if(table.Length<256) throw new ArgumentOutOfRangeException("table", "Must have at least 256 elements.");

			if(data==null) throw new ArgumentNullException("data");
			if(offset<0||offset>data.Count)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data in bytes.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Count) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data in bytes minus the offset argument.");

			if(count==0)
			{
				count=data.Count-offset;
				if(count==0) return 0;
			}

			int endOfByteStream=offset+count;

			byte register=0;

			while(offset<endOfByteStream) register=table[(register^data[offset++])&0xFF];

			return register;
		}

		/// <summary>
		/// Calculates the CRC of bits stored in a <see cref="Byte"/>[].
		/// The "Slightly Mangled Table-Driven Implementation". (see chapter 10 for explantion)
		/// </summary>
		/// <param name="polynomial">The polynomial to use. Bits must be in the most significant bits.</param>
		/// <param name="data">The bits. (Most significant bit of the first byte first (starting at <paramref name="offset"/>.)</param>
		/// <param name="offset">Location in the array where to start in bytes.</param>
		/// <param name="count">Number of bytes.</param>
		/// <returns>The CRC value, filled in the most significant bits.</returns>
		public static ushort Get(ushort polynomial, IList<byte> data, int offset=0, int count=0)
		{
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");

			return Get(TABLE.GenerateTable(polynomial), data, offset, count);
		}

		/// <summary>
		/// Calculates the CRC of bits stored in a <see cref="Byte"/>[].
		/// The "Slightly Mangled Table-Driven Implementation". (see chapter 10 for explantion)
		/// </summary>
		/// <param name="table">The table generated from the polynomial to use.</param>
		/// <param name="data">The bits. (Most significant bit of the first byte first (starting at <paramref name="offset"/>.)</param>
		/// <param name="offset">Location in the array where to start in bytes.</param>
		/// <param name="count">Number of bytes.</param>
		/// <returns>The CRC value, filled in the most significant bits.</returns>
		public static ushort Get(ushort[] table, IList<byte> data, int offset=0, int count=0)
		{
			if(table==null) throw new ArgumentNullException("table");
			if(table.Length<256) throw new ArgumentOutOfRangeException("table", "Must have at least 256 elements.");

			if(data==null) throw new ArgumentNullException("data");
			if(offset<0||offset>data.Count)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data in bytes.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Count) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data in bytes minus the offset argument.");

			if(count==0)
			{
				count=data.Count-offset;
				if(count==0) return 0;
			}

			int endOfByteStream=offset+count;

			ushort register=0;

			while(offset<endOfByteStream) register=(ushort)((register<<8)^table[((register>>8)^data[offset++])&0xFF]);

			return register;
		}

		/// <summary>
		/// Calculates the CRC of bits stored in a <see cref="Byte"/>[].
		/// The "Slightly Mangled Table-Driven Implementation". (see chapter 10 for explantion)
		/// </summary>
		/// <param name="polynomial">The polynomial to use. Bits must be in the most significant bits.</param>
		/// <param name="data">The bits. (Most significant bit of the first byte first (starting at <paramref name="offset"/>.)</param>
		/// <param name="offset">Location in the array where to start in bytes.</param>
		/// <param name="count">Number of bytes.</param>
		/// <returns>The CRC value, filled in the most significant bits.</returns>
		public static uint Get(uint polynomial, IList<byte> data, int offset=0, int count=0)
		{
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");

			return Get(TABLE.GenerateTable(polynomial), data, offset, count);
		}

		/// <summary>
		/// Calculates the CRC of bits stored in a <see cref="Byte"/>[].
		/// The "Slightly Mangled Table-Driven Implementation". (see chapter 10 for explantion)
		/// </summary>
		/// <param name="table">The table generated from the polynomial to use.</param>
		/// <param name="data">The bits. (Most significant bit of the first byte first (starting at <paramref name="offset"/>.)</param>
		/// <param name="offset">Location in the array where to start in bytes.</param>
		/// <param name="count">Number of bytes.</param>
		/// <returns>The CRC value, filled in the most significant bits.</returns>
		public static uint Get(uint[] table, IList<byte> data, int offset=0, int count=0)
		{
			if(table==null) throw new ArgumentNullException("table");
			if(table.Length<256) throw new ArgumentOutOfRangeException("table", "Must have at least 256 elements.");

			if(data==null) throw new ArgumentNullException("data");
			if(offset<0||offset>data.Count)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data in bytes.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Count) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data in bytes minus the offset argument.");

			if(count==0)
			{
				count=data.Count-offset;
				if(count==0) return 0;
			}

			int endOfByteStream=offset+count;

			uint register=0;

			while(offset<endOfByteStream) register=(register<<8)^table[((register>>24)^data[offset++])&0xFF];

			return register;
		}

		/// <summary>
		/// Calculates the CRC of bits stored in a <see cref="Byte"/>[].
		/// The "Slightly Mangled Table-Driven Implementation". (see chapter 10 for explantion)
		/// </summary>
		/// <param name="polynomial">The polynomial to use. Bits must be in the most significant bits.</param>
		/// <param name="data">The bits. (Most significant bit of the first byte first (starting at <paramref name="offset"/>.)</param>
		/// <param name="offset">Location in the array where to start in bytes.</param>
		/// <param name="count">Number of bytes.</param>
		/// <returns>The CRC value, filled in the most significant bits.</returns>
		public static ulong Get(ulong polynomial, IList<byte> data, int offset=0, int count=0)
		{
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");

			return Get(TABLE.GenerateTable(polynomial), data, offset, count);
		}

		/// <summary>
		/// Calculates the CRC of bits stored in a <see cref="Byte"/>[].
		/// The "Slightly Mangled Table-Driven Implementation". (see chapter 10 for explantion)
		/// </summary>
		/// <param name="table">The table generated from the polynomial to use.</param>
		/// <param name="data">The bits. (Most significant bit of the first byte first (starting at <paramref name="offset"/>.)</param>
		/// <param name="offset">Location in the array where to start in bytes.</param>
		/// <param name="count">Number of bytes.</param>
		/// <returns>The CRC value, filled in the most significant bits.</returns>
		public static ulong Get(ulong[] table, IList<byte> data, int offset=0, int count=0)
		{
			if(table==null) throw new ArgumentNullException("table");
			if(table.Length<256) throw new ArgumentOutOfRangeException("table", "Must have at least 256 elements.");

			if(data==null) throw new ArgumentNullException("data");
			if(offset<0||offset>data.Count)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data in bytes.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Count) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data in bytes minus the offset argument.");

			if(count==0)
			{
				count=data.Count-offset;
				if(count==0) return 0;
			}

			int endOfByteStream=offset+count;

			ulong register=0;

			while(offset<endOfByteStream) register=(register<<8)^table[((register>>56)^data[offset++])&0xFF];

			return register;
		}
	}
}
