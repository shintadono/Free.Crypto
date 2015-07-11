using System;

namespace Free.Crypto.PseudoCRCChecksums
{
	/// <summary>
	/// Contains a crc-like hash value calculation consistent with the algorithm used in the CP/M program (mis)named "CRCK".
	/// </summary>
	/// <threadsafety static="true" instance="true"/>
	[CLSCompliant(false)]
	public static class CRCK
	{
		/// <summary>
		/// It does NOT perform a CRC calculation, but does a rather bizarre hash value calculation.
		/// </summary>
		/// <param name="data">The data to 'add' to the hash value.</param>
		/// <param name="offset">Location in the array where to start in bytes.</param>
		/// <param name="count">Number of bytes.</param>
		/// <param name="init">The initialization value for the calculation. Can be the result of a previous hash value calculation.</param>
		/// <returns>The (new) hash value.</returns>
		public static ushort Calc(byte[] data, int offset=0, int count=0, ushort init=0)
		{
			if(data==null) throw new ArgumentNullException("data");
			if(offset<0||offset>data.Length)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data in bytes.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Length) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data in bytes minus the offset argument.");

			if(count==0)
			{
				count=data.Length-offset;
				if(count==0) return init;
			}

			unsafe
			{
				fixed(byte* lDataFixed=data)
				{
					byte* lData=lDataFixed+offset;

					ushort hash=init;

					for(int i=0; i<count; i++)
					{
						int topbit=hash&0x8000; // Remember the top bit
						hash<<=1; // Shift top bit out

						hash=(ushort)((hash&0xff00)|((hash+*lData++)&0xff)); // Add next byte to hash without the carry-over to the higher 8 bits.

						if(topbit!=0) hash^=0xA097; // If top bit was set => xor with polynomial
					}

					return hash;
				}
			}
		}
	}
}
