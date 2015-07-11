using System;
using System.Collections.Generic;

namespace Free.Crypto.FletcherChecksums
{
	/// <summary>
	/// Class for calculating <see cref="Fletcher64Checksum"/>s.
	/// </summary>
	/// <remarks>
	/// <para>For more information on the checksum itself see:</para>
	/// <para>Fletcher, J. G., "An Arithmetic Checksum for Serial Transmissions", IEEE Transactions on Communications, Vol. COM-30, No. 1, January 1982, pp. 247-252.</para>
	/// <para>For a formal specification of the checksum and the checkbytes see:</para>
	/// <para>ITU-T Recommendation X.224, Annex D, "Checksum Algorithms", November, 1993, pp. 144, 145. ITU-T X.244 is also the same as ISO 8073.</para>
	/// </remarks>
	/// <threadsafety static="true" instance="true"/>
	[CLSCompliant(false)]
	public static class Fletcher64
	{
		/// <summary>
		/// Calculates the <see cref="Fletcher64Checksum"/> of a <see cref="UInt64"/>[]. This method implements the slow but straightforward way.
		/// This algorithm is also known as the "32-bit Fletcher Checksum", since it consumes the data word in 32-bit chunks.
		/// </summary>
		/// <param name="data">The list whose elements shall be added to the checksum.</param>
		/// <param name="offset">Location in the array.</param>
		/// <param name="count">Number of elements.</param>
		/// <param name="fletcher64">The <see cref="Fletcher64Checksum"/> to start from.</param>
		/// <returns>A <see cref="Fletcher64Checksum"/>.</returns>
		public static Fletcher64Checksum GetSlow(IList<uint> data, int offset=0, int count=0, Fletcher64Checksum fletcher64=new Fletcher64Checksum())
		{
			if(data==null) throw new ArgumentNullException("data");

			if(offset<0||offset>data.Count)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Count) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data minus the offset argument.");

			if(count==0)
			{
				count=data.Count-offset;
				if(count==0) return fletcher64;
			}

			long c0=fletcher64.C0;
			long c1=fletcher64.C1;

			for(int i=offset; i<count; i++)
			{
				c0=(c0+data[i])%uint.MaxValue;
				c1=(c1+c0)%uint.MaxValue;
			}

			return new Fletcher64Checksum() { C0=(uint)c0, C1=(uint)c1 };
		}

		/// <summary>
		/// Calculates the <see cref="Fletcher64Checksum"/> of a <see cref="IEnumerable{UInt32}"/>. This method implements the slow but straightforward way.
		/// This algorithm is also known as the "32-bit Fletcher Checksum", since it consumes the data word in 32-bit chunks.
		/// </summary>
		/// <param name="data">The collection whose elements shall be added to the checksum.</param>
		/// <param name="fletcher64">The <see cref="Fletcher64Checksum"/> to start from.</param>
		/// <returns>A <see cref="Fletcher64Checksum"/>.</returns>
		public static Fletcher64Checksum GetSlow(IEnumerable<uint> data, Fletcher64Checksum fletcher64=new Fletcher64Checksum())
		{
			if(data==null) throw new ArgumentNullException("data");

			long c0=fletcher64.C0;
			long c1=fletcher64.C1;

			foreach(uint value in data)
			{
				c0=(c0+value)%uint.MaxValue;
				c1=(c1+c0)%uint.MaxValue;
			}

			return new Fletcher64Checksum() { C0=(uint)c0, C1=(uint)c1 };
		}

		/// <summary>
		/// Calculates the <see cref="Fletcher64Checksum"/> of a <see cref="UInt64"/>[].
		/// This algorithm is also known as the "32-bit Fletcher Checksum", since it consumes the data word in 32-bit chunks.
		/// </summary>
		/// <param name="data">An array of <see cref="UInt64"/>s.</param>
		/// <param name="offset">Location in the array.</param>
		/// <param name="count">Number of elements.</param>
		/// <param name="fletcher64">The <see cref="Fletcher64Checksum"/> to start from.</param>
		/// <returns>A <see cref="Fletcher64Checksum"/>.</returns>
		public static Fletcher64Checksum Get(uint[] data, int offset=0, int count=0, Fletcher64Checksum fletcher64=new Fletcher64Checksum())
		{
			if(data==null) throw new ArgumentNullException("data");

			if(offset<0||offset>data.Length)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Length) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data minus the offset argument.");

			if(count==0)
			{
				count=data.Length-offset;
				if(count==0) return fletcher64;
			}

			ulong c0=fletcher64.C0;
			ulong c1=fletcher64.C1;

			unsafe
			{
				// local copies of values and references make the code much faster
				int lCount=count;

				fixed(uint* lDataFixed=data)
				{
					uint* lData=lDataFixed+offset;

					while(lCount>0)
					{
						int c=lCount>92679?92679:lCount;
						lCount-=c;
						do
						{
							c0+=*lData++;
							c1+=c0;
						}
						while(--c>0);

						c1=(c1&0xffffffff)+(c1>>32);
						c0=(c0&0xffffffff)+(c0>>32);
					}
				}
			}

			// once again, to reduce the sums to 32 bits, each
			c1=(c1&0xffffffff)+(c1>>32);
			c0=(c0&0xffffffff)+(c0>>32);

			return new Fletcher64Checksum() { C0=(uint)c0, C1=(uint)c1 };
		}

		/// <summary>
		/// Calculates the <see cref="Fletcher64Checksum"/> of a <see cref="IEnumerable{UInt32}"/>.
		/// This algorithm is also known as the "32-bit Fletcher Checksum", since it consumes the data word in 32-bit chunks.
		/// </summary>
		/// <param name="data">The collection whose elements shall be added to the checksum.</param>
		/// <param name="fletcher64">The <see cref="Fletcher64Checksum"/> to start from.</param>
		/// <returns>A <see cref="Fletcher64Checksum"/>.</returns>
		public static Fletcher64Checksum Get(IEnumerable<uint> data, Fletcher64Checksum fletcher64=new Fletcher64Checksum())
		{
			if(data==null) throw new ArgumentNullException("data");

			ulong c0=fletcher64.C0;
			ulong c1=fletcher64.C1;

			// local copies of values and references make the code much faster
			IEnumerable<uint> lData=data;

			int c=0;
			foreach(uint value in lData)
			{
				c0+=value;
				c1+=c0;

				if((++c)<=92679) continue;

				c=0;

				c1=(c1&0xffffffff)+(c1>>32);
				c0=(c0&0xffffffff)+(c0>>32);
			}

			if(c!=0)
			{
				c1=(c1&0xffffffff)+(c1>>32);
				c0=(c0&0xffffffff)+(c0>>32);
			}

			// once again, to reduce the sums to 32 bits, each
			c1=(c1&0xffffffff)+(c1>>32);
			c0=(c0&0xffffffff)+(c0>>32);

			return new Fletcher64Checksum() { C0=(uint)c0, C1=(uint)c1 };
		}
	}
}
