using System;

namespace Free.Crypto.PseudoCRCChecksums
{
	/// <summary>
	/// Contains a crc-like hash value calculation used in early SICK hardward.
	/// </summary>
	/// <remarks>
	/// Normally the top 8 bits off the current CRC (register) value are examined
	/// to calculate the new CRC for each imcoming byte. For reasons unknown, Sick
	/// decided to exam only the top bit per input byte. This makes this algorithm
	/// very fast, but also results in error detecion lower than that of a regular
	/// CRC algorithm.
	/// </remarks>
	/// <threadsafety static="true" instance="true"/>
	[CLSCompliant(false)]
	public static class SICK
	{
		/// <summary>
		/// The polynomial used by the algorithm in this class.
		/// </summary>
		public const ushort Polynomial=0x8005;

		/// <summary>
		/// It does NOT perform a CRC calculation, but does a rather bizarre hash value calculation.
		/// </summary>
		/// <param name="data">The data for which to calculate the hash value.</param>
		/// <param name="offset">Location in the array where to start in bytes.</param>
		/// <param name="count">Number of bytes.</param>
		/// <returns>The hash value.</returns>
		public static ushort Calc(byte[] data, int offset=0, int count=0)
		{
			if(data==null) throw new ArgumentNullException("data");
			if(offset<0||offset>data.Length)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data in bytes.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Length) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data in bytes minus the offset argument.");

			if(count==0)
			{
				count=data.Length-offset;
				if(count==0) return 0;
			}

			unsafe
			{
				fixed(byte* lDataFixed=data)
				{
					byte* lData=lDataFixed+offset;

					ushort hash=0;
					byte prev=0;

					for(int i=0; i<count; i++)
					{
						byte cur=*lData++;

						if((hash&0x8000)!=0) hash=(ushort)((hash<<1)^Polynomial);
						else hash<<=1;

						hash^=(ushort)((prev<<8)|cur);

						prev=cur;
					}

					return hash;
				}
			}
		}

		/// <summary>
		/// Updates a hash value (<paramref name="hash"/>) with a byte and the
		/// previous byte (zero if the first call).
		/// </summary>
		/// <param name="hash">The hash value to update. (Initial value is zero (0))</param>
		/// <param name="cur">The (current) byte with which to update the has value.</param>
		/// <param name="prev">The byte preceding <paramref name="cur"/> with which to update the has value.</param>
		/// <returns>The updated hash value.</returns>
		public static ushort Update(ushort hash, byte cur, byte prev)
		{
			if((hash&0x8000)!=0) hash=(ushort)((hash<<1)^Polynomial);
			else hash<<=1;

			hash^=(ushort)((prev<<8)|cur);
			return hash;
		}
	}
}
