using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Free.Crypto
{
	/// <summary>
	/// This class provides implementations of the Adler-32 algorithm
	/// as defined in RFC1950 (http://www.ietf.org/rfc/rfc1950.txt).
	/// Adler-32 is an algorithm for calculating a checksum.
	/// </summary>
	/// <remarks>
	/// <para>
	/// Adler-32 calculates the 16-bit big moduli with the bigest prime
	/// number smaller than 65536 or 0x10000 or 2^16 (this prime number
	/// is 65521) of two sums:
	/// <list type="number">
	/// <item><description>
	/// The modulus of the sum of the values of all <see cref="Byte"/>s.
	/// Sum1 = (1 + ∑a[i]) mod 65521 (with i=0..Length of the data array -1)
	/// </description></item>
	/// <item><description>
	/// The modulus of the sum of the sums of values thus far.
	/// Sum2 = (L + ∑(L-i)*a[i]) mod 65521 (with L=Length of the data array and i=0..L-1)
	/// </description></item>
	/// </list>
	/// These 16-bit big moduli are then merged into one 32-bit value,
	/// the adler-32checksum. Adler32=Sum2*63356+Sum1.
	/// </para>
	/// <para>
	/// Developed by Mark Adler as an improvement and extension of the
	/// Fletcher algorithm.</para>
	/// <para>(For more information about the Fletcher algorithm see:
	/// <list type="bullet">
	/// <item><description>
	/// Fletcher, J. G., "An Arithmetic Checksum for Serial Transmissions", IEEE Transactions on Communications, Vol. COM-30, No. 1, January 1982, pp. 247-252.
	/// </description></item>
	/// <item><description>
	/// ITU-T Recommendation X.224, Annex D, "Checksum Algorithms", November, 1993, pp. 144, 145. ITU-T X.244 is also the same as ISO 8073.
	/// </description></item>
	/// </list>
	/// )
	/// </para>
	/// </remarks>
	/// <threadsafety static="true" instance="true"/>
	[CLSCompliant(false)]
	public static class Adler32
	{
		/// <summary>
		/// Calculates the Adler-32-Checksum of a <see cref="Byte"/>[]. This method implements the slow but straightforward way.
		/// </summary>
		/// <param name="data">The list whose elements shall be added to the checksum.</param>
		/// <param name="offset">Location in the array.</param>
		/// <param name="count">Number of elements.</param>
		/// <param name="adler32">The Adler-32-Checksum to start from. (Default is 1)</param>
		/// <returns>The Adler-32-Checksum as <see cref="UInt32"/>.</returns>
		public static uint GetSlow(IList<byte> data, int offset=0, int count=0, uint adler32=1)
		{
			if(data==null) throw new ArgumentNullException("data");

			if(offset<0||offset>data.Count)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Count) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data minus the offset argument.");

			if(count==0)
			{
				count=data.Count-offset;
				if(count==0) return adler32;
			}

			uint sum1=adler32&0xffff;
			uint sum2=adler32>>16;

			if(sum1>=65521||sum2>=65521) throw new ArgumentException("adler32", "Not a valid Adler-32-Checksum.");

			for(int i=offset; i<count; i++)
			{
				sum1=(sum1+data[i])%65521;
				sum2=(sum2+sum1)%65521;
			}

			return sum2<<16|sum1;
		}

		/// <summary>
		/// Calculates the Adler-32-Checksum of a <see cref="Byte"/>[]. This method implements the slow but straightforward way.
		/// </summary>
		/// <param name="data">The collection whose elements (<see cref="Byte"/>s) shall be added to the checksum.</param>
		/// <param name="adler32">The Adler-32-Checksum to start from. (Default is 1)</param>
		/// <returns>The Adler-32-Checksum as <see cref="UInt32"/>.</returns>
		public static uint GetSlow(IEnumerable<byte> data, uint adler32=1)
		{
			if(data==null) throw new ArgumentNullException("data");

			uint sum1=adler32&0xffff;
			uint sum2=adler32>>16;

			if(sum1>=65521||sum2>=65521) throw new ArgumentException("adler32", "Not a valid Adler-32-Checksum.");

			foreach(byte value in data)
			{
				sum1=(sum1+value)%65521;
				sum2=(sum2+sum1)%65521;
			}

			return sum2<<16|sum1;
		}

		/// <summary>
		/// Calculates the Adler-32-Checksum of a <see cref="Byte"/>[].
		/// </summary>
		/// <param name="data">An array of <see cref="Byte"/>s.</param>
		/// <param name="offset">Location in the array.</param>
		/// <param name="count">Number of elements.</param>
		/// <param name="adler32">The Adler-32-Checksum to start from. (Default is 1)</param>
		/// <returns>The Adler-32-Checksum as <see cref="UInt32"/>.</returns>
		public static uint Get(byte[] data, int offset=0, int count=0, uint adler32=1)
		{
			if(data==null) throw new ArgumentNullException("data");

			if(offset<0||offset>data.Length)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Length) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data minus the offset argument.");

			if(count==0)
			{
				count=data.Length-offset;
				if(count==0) return adler32;
			}

			uint sum1=adler32&0xffff;
			uint sum2=adler32>>16;

			if(sum1>=65521||sum2>=65521) throw new ArgumentException("adler32", "Not a valid Adler-32-Checksum.");

			// local copies of values and references make the code much faster
			int lCount=count;

			// if the user feeds us single bytes (check and substraction is faster than modulo)
			if(lCount==1)
			{
				sum1+=data[offset];
				if(sum1>=65521) sum1-=65521;
				sum2+=sum1;
				if(sum2>=65521) sum2-=65521;
				return sum2<<16|sum1;
			}

			unsafe
			{
				fixed(byte* lDataFixed=data)
				{
					byte* lData=lDataFixed+offset;

					// if number of bytes is still small enough that sum1 don't need a modulo (check and substraction is faster than modulo)
					if(lCount<=256)
					{
						int c=lCount;
						do
						{
							sum1+=*lData++;
							sum2+=sum1;
						}
						while(--c>0);
						if(sum1>=65521) sum1-=65521;
						sum2%=65521;
						return sum2<<16|sum1;
					}

					while(lCount>0)
					{
						int c=lCount>5552?5552:lCount;
						lCount-=c;
						do
						{
							sum1+=*lData++;
							sum2+=sum1;
						}
						while(--c>0);

						sum1%=65521;
						sum2%=65521;
					}
				}
			}

			return sum2<<16|sum1;
		}

		/// <summary>
		/// Calculates the Adler-32-Checksum of a <see cref="List{T}">List</see> of <see cref="Byte"/>s.
		/// </summary>
		/// <param name="data">A list of <see cref="Byte"/>s.</param>
		/// <param name="offset">Location in the list.</param>
		/// <param name="count">Number of elements.</param>
		/// <param name="adler32">The Adler-32-Checksum to start from. (Default is 1)</param>
		/// <returns>The Adler-32-Checksum as <see cref="UInt32"/>.</returns>
		public static uint Get(List<byte> data, int offset=0, int count=0, uint adler32=1)
		{
			if(data==null) throw new ArgumentNullException("data");

			if(offset<0||offset>data.Count)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Count) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data minus the offset argument.");

			if(count==0)
			{
				count=data.Count-offset;
				if(count==0) return adler32;
			}

			uint sum1=adler32&0xffff;
			uint sum2=adler32>>16;

			if(sum1>=65521||sum2>=65521) throw new ArgumentException("adler32", "Not a valid Adler-32-Checksum.");

			// local copies of values and references make the code much faster
			List<byte> lData=data;
			int lOffset=offset;
			int lCount=count;

			// if the user feeds us single bytes (check and substraction is faster than modulo)
			if(lCount==1)
			{
				sum1+=lData[lOffset];
				if(sum1>=65521) sum1-=65521;
				sum2+=sum1;
				if(sum2>=65521) sum2-=65521;
				return sum2<<16|sum1;
			}

			// if number of bytes is still small enough that sum1 don't need a modulo (check and substraction is faster than modulo)
			if(lCount<=256)
			{
				int c=lCount;
				do
				{
					sum1+=lData[lOffset++];
					sum2+=sum1;
				}
				while(--c>0);
				if(sum1>=65521) sum1-=65521;
				sum2%=65521;
				return sum2<<16|sum1;
			}

			while(lCount>0)
			{
				int c=lCount>5552?5552:lCount;
				lCount-=c;
				do
				{
					sum1+=lData[lOffset++];
					sum2+=sum1;
				}
				while(--c>0);

				sum1%=65521;
				sum2%=65521;
			}

			return sum2<<16|sum1;
		}

		/// <summary>
		/// Calculates the Adler-32-Checksum of a <see cref="IEnumerable{Byte}"/>.
		/// </summary>
		/// <param name="data">The collection whose elements (<see cref="Byte"/>s) shall be added to the checksum.</param>
		/// <param name="adler32">The Adler-32-Checksum to start from. (Default is 1)</param>
		/// <returns>The Adler-32-Checksum as <see cref="UInt32"/>.</returns>
		public static uint Get(IEnumerable<byte> data, uint adler32=1)
		{
			if(data==null) throw new ArgumentNullException("data");

			uint sum1=adler32&0xffff;
			uint sum2=adler32>>16;

			if(sum1>=65521||sum2>=65521) throw new ArgumentException("adler32", "Not a valid Adler-32-Checksum.");

			int c=0;
			foreach(byte value in data)
			{
				sum1+=value;
				sum2+=sum1;

				if((++c)<=5552) continue;

				c=0;

				sum1%=65521;
				sum2%=65521;
			}

			if(c!=0)
			{
				if(c==1&&sum2>=65521) sum2-=65521;
				else sum2%=65521;

				if(c<=256&&sum1>=65521) sum1-=65521;
				else sum1%=65521;
			}

			return sum2<<16|sum1;
		}

		/// <summary>
		/// Calculates the Adler-32-Checksum of a <see cref="Byte"/>. Or adds a <see cref="Byte"/> to an already calculated Adler-32-Checksum.
		/// </summary>
		/// <param name="data">A <see cref="Byte"/> that shall be added to the checksum.</param>
		/// <param name="adler32">The Adler-32-Checksum to start from. (Default is 1)</param>
		/// <returns>The Adler-32-Checksum as <see cref="UInt32"/>.</returns>
		public static uint Get(byte data, uint adler32=1)
		{
			uint sum1=adler32&0xffff;
			uint sum2=adler32>>16;

			if(sum1>=65521||sum2>=65521) throw new ArgumentException("adler32", "Not a valid Adler-32-Checksum.");

			sum1+=data;
			if(sum1>=65521) sum1-=65521;
			sum2+=sum1;
			if(sum2>=65521) sum2-=65521;

			return sum2<<16|sum1;
		}

		/// <summary>
		/// Calculates the Adler-32-Checksum for two consecutive data words (e.g. 
		/// <see cref="Byte"/>[]s), which Adler-32-Checksum have already been calculated,
		/// by combining the checksums and information about the length of the data words.
		/// This can be utilized when calculating checksum of (large) data words in parallel
		/// or distributed manner.
		/// </summary>
		/// <remarks>
		/// <para><b>How does this work?</b></para>
		/// <para>For simplicity lets ignore the moduli. Then the whole math becomes quite
		/// easy. Remember:
		/// <list type="bullet">
		/// <item><description>Sum1 = 1 + ∑a[i]</description></item>
		/// <item><description>Sum2 = L + ∑(L-i)*a[i] (or the sum of all Sum1-values after
		/// every added <see cref="Byte"/>)</description></item>
		/// </list>
		/// with <b>L</b> as the Length of the data word and <b>i</b> as the index into the
		/// data word. This two sums are then combine into the Adler-32-Checksum.</para>
		/// <para>Now we have two Adler-32-checksums, whick we can easily spilt up into there
		/// sums.
		/// <list type="bullet">
		/// <item><description>Sum1a = 1 + ∑a[i]</description></item>
		/// <item><description>Sum2a = La + ∑(La-i)*a[i]</description></item>
		/// <item><description>Sum1b = 1 + ∑b[j]</description></item>
		/// <item><description>Sum2b = Lb + ∑(Lb-j)*b[j]</description></item>
		/// </list>
		/// with <b>a</b> and <b>b</b> our consecutive data words.
		/// </para>
		/// <para>The combined sums (before combining them to the resulting Adler-32-Checksum)
		/// can be calculated, this way:
		/// <list type="bullet">
		/// <item><description>Sum1 = 1 + ∑a[i] + ∑b[j]</description></item>
		/// <item><description>Sum2 = (La+Lb)*1 + ∑(La-i+Lb)*a[i] + ∑(Lb-j)*b[j] =
		/// Lb*(1+∑a[i]) + (La + ∑(La-i)*a[i]) + ∑(Lb-j)*b[j]</description></item>
		/// </list>
		/// Sum1 is easy enough to understand. For Sum2 we need the add the Sum1a for every
		/// <see cref="Byte"/> in the <b>b</b> data word to Sum2a and Sum2b (w/o the summed up
		/// 1s that are already in Sum2a). By substituting some parts from above, the whole
		/// formular becomes:
		/// <list type="bullet">
		/// <item><description>Sum1 = Sum1a + ∑b[j]</description></item>
		/// <item><description>Sum2 = Sum1a * Lb + Sum2a + ∑(Lb-j)*b[j]</description></item></list>
		/// and even simpler by substituting ever more parts from above:
		/// <list type="bullet">
		/// <item><description>Sum1 = Sum1a + Sum1b - 1</description></item>
		/// <item><description>Sum2 = Sum1a * Lb + Sum2a + Sum2b - Lb</description></item></list>
		/// </para>
		/// <para>As you can see, only the (four) sums of the (two) Adler-32-Checksums and the
		/// length of the second data word is needed to calculate the Adler-32-Checksums of the
		/// combined data word.</para>
		/// <para>But don't forget the modulus!</para>
		/// </remarks>
		/// <param name="adler1">Adler-32-Checksum of the first data word.</param>
		/// <param name="adler2">Adler-32-Checksum of the second data word.</param>
		/// <param name="length2">Length of the second data word.</param>
		/// <returns>The combined Adler-32-Checksum as <see cref="UInt32"/>.</returns>
		public static uint Combine(uint adler1, uint adler2, ulong length2)
		{
			uint sum1a=adler1&0xffff;
			uint sum2a=adler1>>16;

			if(sum1a>=65521||sum2a>=65521) throw new ArgumentException("adler1", "Not a valid Adler-32-Checksum.");

			uint sum1b=adler2&0xffff;
			uint sum2b=adler2>>16;

			if(sum1b>=65521||sum2b>=65521) throw new ArgumentException("adler2", "Not a valid Adler-32-Checksum.");

			if(length2==0) throw new ArgumentException("length2", "Must not be zero.");

			// only the remainder needed, since it would be reduced later anyway, and here it makes the varible fitting into an int
			uint lb=(uint)(length2%65521);

			uint sum1=sum1a+sum1b-1+65521; // +65521 to keep the result positive
			uint sum2=(sum1a*lb)%65521+sum2a+sum2b-lb+65521; // +65521 to keep the result positive

			if(sum1>=65521) sum1-=65521;
			if(sum1>=65521) sum1-=65521;
			if(sum2>=(65521<<1)) sum2-=(65521<<1);
			if(sum2>=65521) sum2-=65521;

			return (sum2<<16)|sum1;
		}

		const int BytesPreThread=5*5552; // keep it multiple of 5552 so only the last block gets a partial processing units

		/// <summary>
		/// Calculates the Adler-32-Checksum of a <see cref="Byte"/>[] utilizing the Task Parallel Library (<see cref="O:System.Threading.Tasks.Parallel.For"/>).
		/// </summary>
		/// <param name="data">An array of <see cref="Byte"/>s.</param>
		/// <param name="offset">Location in the array.</param>
		/// <param name="count">Number of elements.</param>
		/// <param name="adler32">The Adler-32-Checksum to start from. (Default is 1)</param>
		/// <returns>The Adler-32-Checksum as <see cref="UInt32"/>.</returns>
		public static uint GetParallel(byte[] data, int offset=0, int count=0, uint adler32=1)
		{
			if(data==null) throw new ArgumentNullException("data");

			if(offset<0||offset>data.Length)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Length) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data minus the offset argument.");

			if(count==0)
			{
				count=data.Length-offset;
				if(count==0) return adler32;
			}

			// don't parallel for to small arrays
			if(count<2*BytesPreThread) return Get(data, offset, count, adler32);

			int threads=count/BytesPreThread;
			int lastcounts=count%BytesPreThread;
			if(lastcounts!=0) threads++;
			else lastcounts=BytesPreThread;

			int threadsMinus1=threads-1;
			uint[] adler32s=new uint[threads];

			unsafe
			{
				fixed(byte* lDataFixed=data)
				{
					byte* lData=lDataFixed+offset;

					Parallel.For(0, threads,
						(n) =>
						{
							int lCount=BytesPreThread;
							if(n==threadsMinus1) lCount=lastcounts;

							byte* i=lData+n*BytesPreThread;

							uint sum1=1;
							uint sum2=0;

							while(lCount>0)
							{
								int c=lCount>5552?5552:lCount;
								lCount-=c;
								do
								{
									sum1+=*i++;
									sum2+=sum1;
								}
								while(--c>0);

								sum1%=65521;
								sum2%=65521;
							}

							adler32s[n]=(sum2<<16)|sum1;
						}
					);
				}
			}

			uint ret=adler32;
			for(int i=0; i<threadsMinus1; i++) ret=Combine(ret, adler32s[i], BytesPreThread);
			return Combine(ret, adler32s[threadsMinus1], (ulong)lastcounts);
		}

		/// <summary>
		/// Calculates the Adler-32-Checksum of a <see cref="List{T}">List</see> of <see cref="Byte"/>s utilizing the Task Parallel Library (<see cref="O:System.Threading.Tasks.Parallel.For"/>).
		/// </summary>
		/// <param name="data">A list of <see cref="Byte"/>s.</param>
		/// <param name="offset">Location in the array.</param>
		/// <param name="count">Number of elements.</param>
		/// <param name="adler32">The Adler-32-Checksum to start from. (Default is 1)</param>
		/// <returns>The Adler-32-Checksum as <see cref="UInt32"/>.</returns>
		public static uint GetParallel(List<byte> data, int offset=0, int count=0, uint adler32=1)
		{
			if(data==null) throw new ArgumentNullException("data");

			if(offset<0||offset>data.Count)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Count) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data minus the offset argument.");

			if(count==0)
			{
				count=data.Count-offset;
				if(count==0) return adler32;
			}

			// don't parallel for to small arrays
			if(count<2*BytesPreThread) return Get(data, offset, count, adler32);

			int threads=count/BytesPreThread;
			int lastcounts=count%BytesPreThread;
			if(lastcounts!=0) threads++;
			else lastcounts=BytesPreThread;

			int threadsMinus1=threads-1;
			uint[] adler32s=new uint[threads];

			Parallel.For(0, threads,
				(n) =>
				{
					int lCount=BytesPreThread;
					if(n==threadsMinus1) lCount=lastcounts;

					int i=offset+n*BytesPreThread;

					uint sum1=1;
					uint sum2=0;

					while(lCount>0)
					{
						int c=lCount>5552?5552:lCount;
						lCount-=c;
						do
						{
							sum1+=data[i++];
							sum2+=sum1;
						}
						while(--c>0);

						sum1%=65521;
						sum2%=65521;
					}

					adler32s[n]=(sum2<<16)|sum1;
				}
			);

			uint ret=adler32;
			for(int i=0; i<threadsMinus1; i++) ret=Combine(ret, adler32s[i], BytesPreThread);
			return Combine(ret, adler32s[threadsMinus1], (ulong)lastcounts);
		}
	}
}
