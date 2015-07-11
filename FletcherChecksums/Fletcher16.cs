using System;
using System.Collections.Generic;

namespace Free.Crypto.FletcherChecksums
{
	/// <summary>
	/// Class for calculating <see cref="Fletcher16Checksum"/>s.
	/// </summary>
	/// <remarks>
	/// <para>For more information on the checksum itself see:</para>
	/// <para>Fletcher, J. G., "An Arithmetic Checksum for Serial Transmissions", IEEE Transactions on Communications, Vol. COM-30, No. 1, January 1982, pp. 247-252.</para>
	/// <para>For a formal specification of the checksum and the checkbytes see:</para>
	/// <para>ITU-T Recommendation X.224, Annex D, "Checksum Algorithms", November, 1993, pp. 144, 145. ITU-T X.244 is also the same as ISO 8073.</para>
	/// </remarks>
	/// <threadsafety static="true" instance="true"/>
	public static class Fletcher16
	{
		/// <summary>
		/// Calculates the <see cref="Fletcher16Checksum"/> of a <see cref="Byte"/>[]. This method implements the slow but straightforward way.
		/// This algorithm is also known as the "8-bit Fletcher Checksum", since it consumes the data word in 8-bit chunks.
		/// </summary>
		/// <param name="data">The list whose elements shall be added to the checksum.</param>
		/// <param name="offset">Location in the array.</param>
		/// <param name="count">Number of elements.</param>
		/// <param name="fletcher16">The <see cref="Fletcher16Checksum"/> to start from.</param>
		/// <returns>A <see cref="Fletcher16Checksum"/>.</returns>
		public static Fletcher16Checksum GetSlow(IList<byte> data, int offset=0, int count=0, Fletcher16Checksum fletcher16=new Fletcher16Checksum())
		{
			if(data==null) throw new ArgumentNullException("data");

			if(offset<0||offset>data.Count)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Count) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data minus the offset argument.");

			if(count==0)
			{
				count=data.Count-offset;
				if(count==0) return fletcher16;
			}

			int c0=fletcher16.C0;
			int c1=fletcher16.C1;

			for(int i=offset; i<count; i++)
			{
				c0=(c0+data[i])%255;
				c1=(c1+c0)%255;
			}

			return new Fletcher16Checksum() { C0=(byte)c0, C1=(byte)c1 };
		}

		/// <summary>
		/// Calculates the <see cref="Fletcher16Checksum"/> of a <see cref="IEnumerable{Byte}"/>. This method implements the slow but straightforward way.
		/// This algorithm is also known as the "8-bit Fletcher Checksum", since it consumes the data word in 8-bit chunks.
		/// </summary>
		/// <param name="data">The collection whose elements shall be added to the checksum.</param>
		/// <param name="fletcher16">The <see cref="Fletcher16Checksum"/> to start from.</param>
		/// <returns>A <see cref="Fletcher16Checksum"/>.</returns>
		public static Fletcher16Checksum GetSlow(IEnumerable<byte> data, Fletcher16Checksum fletcher16=new Fletcher16Checksum())
		{
			if(data==null) throw new ArgumentNullException("data");

			int c0=fletcher16.C0;
			int c1=fletcher16.C1;

			foreach(byte value in data)
			{
				c0=(c0+value)%255;
				c1=(c1+c0)%255;
			}

			return new Fletcher16Checksum() { C0=(byte)c0, C1=(byte)c1 };
		}

		/// <summary>
		/// Calculates the <see cref="Fletcher16Checksum"/> of a <see cref="Byte"/>[].
		/// This algorithm is also known as the "8-bit Fletcher Checksum", since it consumes the data word in 8-bit chunks.
		/// </summary>
		/// <param name="data">An array of bytes.</param>
		/// <param name="offset">Location in the array.</param>
		/// <param name="count">Number of elements.</param>
		/// <param name="fletcher16">The <see cref="Fletcher16Checksum"/> to start from.</param>
		/// <returns>A <see cref="Fletcher16Checksum"/>.</returns>
		public static Fletcher16Checksum Get(byte[] data, int offset=0, int count=0, Fletcher16Checksum fletcher16=new Fletcher16Checksum())
		{
			if(data==null) throw new ArgumentNullException("data");

			if(offset<0||offset>data.Length)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Length) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data minus the offset argument.");

			if(count==0)
			{
				count=data.Length-offset;
				if(count==0) return fletcher16;
			}

			int c0=fletcher16.C0;
			int c1=fletcher16.C1;

			unsafe
			{
				// local copies of values and references make the code much faster
				int lCount=count;

				fixed(byte* lDataFixed=data)
				{
					byte* lData=lDataFixed+offset;

					while(lCount>0)
					{
						int c=lCount>4101?4101:lCount;
						lCount-=c;
						do
						{
							c0+=*lData++;
							c1+=c0;
						}
						while(--c>0);

						// 3 times, since we have to reduce it from 4 byte to 1 (with maybe one carry-over)
						c1=(c1&0xff)+(c1>>8);
						c0=(c0&0xff)+(c0>>8);
						c1=(c1&0xff)+(c1>>8);
						c0=(c0&0xff)+(c0>>8);
						c1=(c1&0xff)+(c1>>8);
						//c0=(c0&0xff)+(c0>>8); // not really needed. The 4101*255+0x1fd don't need the fourth byte.
					}
				}
			}

			// once again, to reduce the sums to 8 bits, each
			c0=(c0&0xff)+(c0>>8);
			c1=(c1&0xff)+(c1>>8);

			return new Fletcher16Checksum() { C0=(byte)c0, C1=(byte)c1 };
		}

		/// <summary>
		/// Calculates the <see cref="Fletcher16Checksum"/> of a <see cref="IEnumerable{Byte}"/>.
		/// This algorithm is also known as the "8-bit Fletcher Checksum", since it consumes the data word in 8-bit chunks.
		/// </summary>
		/// <param name="data">The collection whose elements shall be added to the checksum.</param>
		/// <param name="fletcher16">The <see cref="Fletcher16Checksum"/> to start from.</param>
		/// <returns>A <see cref="Fletcher16Checksum"/>.</returns>
		public static Fletcher16Checksum Get(IEnumerable<byte> data, Fletcher16Checksum fletcher16=new Fletcher16Checksum())
		{
			if(data==null) throw new ArgumentNullException("data");

			int c0=fletcher16.C0;
			int c1=fletcher16.C1;

			// local copies of values and references make the code much faster
			IEnumerable<byte> lData=data;

			int c=0;
			foreach(byte value in lData)
			{
				c0+=value;
				c1+=c0;

				if((++c)<=4101) continue;

				c=0;

				// 3 times, since we have to reduce it from 4 byte to 1 (with maybe one carry-over)
				c1=(c1&0xff)+(c1>>8);
				c0=(c0&0xff)+(c0>>8);
				c1=(c1&0xff)+(c1>>8);
				c0=(c0&0xff)+(c0>>8);
				c1=(c1&0xff)+(c1>>8);
				//c0=(c0&0xff)+(c0>>8); // not really needed. The 4101*255+0x1fd don't need the fourth byte.
			}

			if(c!=0)
			{
				// 3 times, since we have to reduce it from 4 byte to 1 (with maybe one carry-over)
				c1=(c1&0xff)+(c1>>8);
				c0=(c0&0xff)+(c0>>8);
				c1=(c1&0xff)+(c1>>8);
				c0=(c0&0xff)+(c0>>8);
				c1=(c1&0xff)+(c1>>8);
				//c0=(c0&0xff)+(c0>>8); // not really needed. The 4101*255+0x1fd don't need the fourth byte.
			}

			// once again, to reduce the sums to 8 bits, each
			c0=(c0&0xff)+(c0>>8);
			c1=(c1&0xff)+(c1>>8);

			return new Fletcher16Checksum() { C0=(byte)c0, C1=(byte)c1 };
		}
	}
}
