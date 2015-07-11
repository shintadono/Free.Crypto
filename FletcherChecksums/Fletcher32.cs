using System;
using System.Collections.Generic;

namespace Free.Crypto.FletcherChecksums
{
	/// <summary>
	/// Class for calculating <see cref="Fletcher32Checksum"/>s.
	/// </summary>
	/// <remarks>
	/// <para>For more information on the checksum itself see:</para>
	/// <para>Fletcher, J. G., "An Arithmetic Checksum for Serial Transmissions", IEEE Transactions on Communications, Vol. COM-30, No. 1, January 1982, pp. 247-252.</para>
	/// <para>For a formal specification of the checksum and the checkbytes see:</para>
	/// <para>ITU-T Recommendation X.224, Annex D, "Checksum Algorithms", November, 1993, pp. 144, 145. ITU-T X.244 is also the same as ISO 8073.</para>
	/// </remarks>
	/// <threadsafety static="true" instance="true"/> 
	[CLSCompliant(false)]
	public static class Fletcher32
	{
		/// <summary>
		/// Calculates the <see cref="Fletcher32Checksum"/> of a <see cref="UInt16"/>[]. This method implements the slow but straightforward way.
		/// This algorithm is also known as the "16-bit Fletcher Checksum", since it consumes the data word in 16-bit chunks.
		/// </summary>
		/// <param name="data">The list whose elements shall be added to the checksum.</param>
		/// <param name="offset">Location in the array.</param>
		/// <param name="count">Number of elements.</param>
		/// <param name="fletcher32">The <see cref="Fletcher32Checksum"/> to start from.</param>
		/// <returns>A <see cref="Fletcher32Checksum"/>.</returns>
		public static Fletcher32Checksum GetSlow(IList<ushort> data, int offset=0, int count=0, Fletcher32Checksum fletcher32=new Fletcher32Checksum())
		{
			if(data==null) throw new ArgumentNullException("data");

			if(offset<0||offset>data.Count)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Count) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data minus the offset argument.");

			if(count==0)
			{
				count=data.Count-offset;
				if(count==0) return fletcher32;
			}

			int c0=fletcher32.C0;
			int c1=fletcher32.C1;

			for(int i=offset; i<count; i++)
			{
				c0=(c0+data[i])%65535;
				c1=(c1+c0)%65535;
			}

			return new Fletcher32Checksum() { C0=(ushort)c0, C1=(ushort)c1 };
		}

		/// <summary>
		/// Calculates the <see cref="Fletcher32Checksum"/> of a <see cref="IEnumerable{UInt16}"/>. This method implements the slow but straightforward way.
		/// This algorithm is also known as the "16-bit Fletcher Checksum", since it consumes the data word in 16-bit chunks.
		/// </summary>
		/// <param name="data">The collection whose elements shall be added to the checksum.</param>
		/// <param name="fletcher32">The <see cref="Fletcher32Checksum"/> to start from.</param>
		/// <returns>A <see cref="Fletcher32Checksum"/>.</returns>
		public static Fletcher32Checksum GetSlow(IEnumerable<ushort> data, Fletcher32Checksum fletcher32=new Fletcher32Checksum())
		{
			if(data==null) throw new ArgumentNullException("data");

			int c0=fletcher32.C0;
			int c1=fletcher32.C1;

			foreach(ushort value in data)
			{
				c0=(c0+value)%65535;
				c1=(c1+c0)%65535;
			}

			return new Fletcher32Checksum() { C0=(ushort)c0, C1=(ushort)c1 };
		}

		/// <summary>
		/// Calculates the <see cref="Fletcher32Checksum"/> of a <see cref="UInt16"/>[].
		/// This algorithm is also known as the "16-bit Fletcher Checksum", since it consumes the data word in 16-bit chunks.
		/// </summary>
		/// <param name="data">An array of <see cref="UInt16"/>s.</param>
		/// <param name="offset">Location in the array.</param>
		/// <param name="count">Number of elements.</param>
		/// <param name="fletcher32">The <see cref="Fletcher32Checksum"/> to start from.</param>
		/// <returns>A <see cref="Fletcher32Checksum"/>.</returns>
		public static Fletcher32Checksum Get(ushort[] data, int offset=0, int count=0, Fletcher32Checksum fletcher32=new Fletcher32Checksum())
		{
			if(data==null) throw new ArgumentNullException("data");

			if(offset<0||offset>data.Length)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Length) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data minus the offset argument.");

			if(count==0)
			{
				count=data.Length-offset;
				if(count==0) return fletcher32;
			}

			uint c0=fletcher32.C0;
			uint c1=fletcher32.C1;

			unsafe
			{
				// local copies of values and references make the code much faster
				int lCount=count;

				fixed(ushort* lDataFixed=data)
				{
					ushort* lData=lDataFixed+offset;

					while(lCount>0)
					{
						int c=lCount>359?359:lCount;
						lCount-=c;
						do
						{
							c0+=*lData++;
							c1+=c0;
						}
						while(--c>0);

						c1=(c1&0xffff)+(c1>>16);
						c0=(c0&0xffff)+(c0>>16);
					}
				}
			}

			// once again, to reduce the sums to 16 bits, each
			c0=(c0&0xffff)+(c0>>16);
			c1=(c1&0xffff)+(c1>>16);

			return new Fletcher32Checksum() { C0=(ushort)c0, C1=(ushort)c1 };
		}

		/// <summary>
		/// Calculates the <see cref="Fletcher32Checksum"/> of a <see cref="IEnumerable{UInt16}"/>.
		/// This algorithm is also known as the "16-bit Fletcher Checksum", since it consumes the data word in 16-bit chunks.
		/// </summary>
		/// <param name="data">The collection whose elements shall be added to the checksum.</param>
		/// <param name="fletcher32">The <see cref="Fletcher32Checksum"/> to start from.</param>
		/// <returns>A <see cref="Fletcher32Checksum"/>.</returns>
		public static Fletcher32Checksum Get(IEnumerable<ushort> data, Fletcher32Checksum fletcher32=new Fletcher32Checksum())
		{
			if(data==null) throw new ArgumentNullException("data");

			uint c0=fletcher32.C0;
			uint c1=fletcher32.C1;

			// local copies of values and references make the code much faster
			IEnumerable<ushort> lData=data;

			int c=0;
			foreach(ushort value in lData)
			{
				c0+=value;
				c1+=c0;

				if((++c)<=359) continue;

				c=0;

				c1=(c1&0xffff)+(c1>>16);
				c0=(c0&0xffff)+(c0>>16);
			}

			if(c!=0)
			{
				c1=(c1&0xffff)+(c1>>16);
				c0=(c0&0xffff)+(c0>>16);
			}

			// once again, to reduce the sums to 16 bits, each
			c0=(c0&0xffff)+(c0>>16);
			c1=(c1&0xffff)+(c1>>16);

			return new Fletcher32Checksum() { C0=(ushort)c0, C1=(ushort)c1 };
		}
	}
}
