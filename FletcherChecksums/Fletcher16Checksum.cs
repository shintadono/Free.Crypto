using System;
using System.Runtime.InteropServices;

namespace Free.Crypto.FletcherChecksums
{
	/// <summary>
	/// Result for the <see cref="O:Free.Crypto.FletcherChecksums.Fletcher16.Get">Fletcher16.Get</see> and <see cref="O:Free.Crypto.FletcherChecksums.Fletcher16.GetSlow">Fletcher16.GetSlow</see> methods.
	/// </summary>
	/// <remarks>
	/// <para>In 8-bit one's complement arithmetics the numbers 0x00 and 0xFF have the same value 0. This struct provides
	/// equals-checks that take this property into account. Fletcher checksums shall always be checked usings
	/// these methods.</para>
	/// <para>This struct also provides ways the generate so-called checkbytes:
	/// <list type="numbers">
	/// <item> 
	/// <description>Using the checksum of a data word (e.g. a <see cref="Byte"/>[]), you can get two blocks
	/// (<see cref="CB0"/> and <see cref="CB1"/>), which, appended to the data word, would generate a checksum of
	/// zero (or the same value, see above) for that data word.</description> 
	/// </item> 
	/// <item> 
	/// <description>Using the checksum of a data word (e.g. a <see cref="Byte"/>[]), the position of the checkbytes
	/// (two blocks) inside the data word, and the length of the data word, you can get the two blocks (<see cref="X"/>
	/// and <see cref="Y"/>), which, inserted at their positions inside the data word, would generate a checksum of
	/// zero (or the same value, see above) for that data word. The value of the two blocks must be zero (or the same
	/// value, see above), when calculating the original (unpatched) checksum.</description> 
	/// </item>
	/// </list>
	/// </para>
	/// <para>
	/// Attaching or inserting the checkbytes will produce a data word that conforms to ∑a[i-1] ≡ 0 (mod 255) and ∑i*a[i-1] ≡ 0 (mod 255) (with i=1..Length of the data word).
	/// </para>
	/// <para>For more information on the checksum itself see:</para>
	/// <para>Fletcher, J. G., "An Arithmetic Checksum for Serial Transmissions", IEEE Transactions on Communications, Vol. COM-30, No. 1, January 1982, pp. 247-252.</para>
	/// <para>For a formal specification of the checksum and the checkbytes see:</para>
	/// <para>ITU-T Recommendation X.224, Annex D, "Checksum Algorithms", November, 1993, pp. 144, 145. ITU-T X.244 is also the same as ISO 8073.</para>
	/// </remarks>
	/// <threadsafety static="false" instance="false"/>
	[StructLayout(LayoutKind.Sequential, Pack=1)]
	public struct Fletcher16Checksum : IEquatable<Fletcher16Checksum>
	{
		/// <summary>
		/// Const instance of <see cref="Fletcher16Checksum"/> representing a zero checksum.
		/// </summary>
		public static readonly Fletcher16Checksum Zero=new Fletcher16Checksum();

		/// <summary>
		/// C0 and C1 are the values of the Fletcher-16 checksum. (C0 is the lower half, C1 the upper half.)
		/// </summary>
		public byte C0, C1;

		/// <summary>
		/// Returns the hash code for this instance.
		/// </summary>
		/// <returns>A <see cref="UInt32"/> hashcode. (That is not the value of the checksum... well in a way it is.)</returns>
		public override int GetHashCode()
		{
			return ((C1%255)<<8)|(C0%255);
		}

		/// <summary>
		/// Indicates whether this instance and a specified object are equal.
		/// </summary>
		/// <param name="obj">The object to compare with the current instance.</param>
		/// <returns><c>true</c> if <paramref name="obj"/> and this instance are the same type and represent the same value; otherwise, <c>false</c>.</returns>
		public override bool Equals(object obj)
		{
			if(!(obj is Fletcher16Checksum)) return false;

			Fletcher16Checksum other=(Fletcher16Checksum)obj;
			return (C0%255)==(other.C0%255)&&(C1%255)==(other.C1%255);
		}

		/// <summary>
		/// Indicates whether this instance and a specified <see cref="Fletcher16Checksum"/> are equal.
		/// </summary>
		/// <param name="other">The <see cref="Fletcher16Checksum"/> to compare with the current instance.</param>
		/// <returns><c>true</c> if <paramref name="other"/> and this instance represent the same value; otherwise, <c>false</c>.</returns>
		public bool Equals(Fletcher16Checksum other)
		{
			return (C0%255)==(other.C0%255)&&(C1%255)==(other.C1%255);
		}

		/// <summary>
		/// Determines whether two specified <see cref="Fletcher16Checksum"/>s represent the same value.
		/// </summary>
		/// <param name="a">The first <see cref="Fletcher16Checksum"/> to compare.</param>
		/// <param name="b">The second <see cref="Fletcher16Checksum"/> to compare.</param>
		/// <returns><c>true</c> if <paramref name="a"/> represent the same value as <paramref name="b"/>; otherwise, <c>false</c>.</returns>
		public static bool operator==(Fletcher16Checksum a, Fletcher16Checksum b)
		{
			return (a.C0%255)==(b.C0%255)&&(a.C1%255)==(b.C1%255);
		}

		/// <summary>
		/// Determines whether two specified <see cref="Fletcher16Checksum"/>s represent different values.
		/// </summary>
		/// <param name="a">The first <see cref="Fletcher16Checksum"/> to compare.</param>
		/// <param name="b">The second <see cref="Fletcher16Checksum"/> to compare.</param>
		/// <returns><c>true</c> if <paramref name="a"/> represent not the same value as <paramref name="b"/>; otherwise, <c>false</c>.</returns>
		public static bool operator!=(Fletcher16Checksum a, Fletcher16Checksum b)
		{
			return (a.C0%255)!=(b.C0%255)||(a.C1%255)!=(b.C1%255);
		}

		/// <summary>
		/// Gets the first checkbyte to append to the data word (don't forget to append the <see cref="CB1"/> checkbyte as well) to generate a checksum of zero.
		/// </summary>
		public byte CB0 { get { return (byte)(255-((C0+C1)%255)); } }

		/// <summary>
		/// Gets the second checkbyte to append to the data word (after the <see cref="CB0"/> checkbyte) to generate a checksum of zero.
		/// </summary>
		public byte CB1 { get { return (byte)(255-((C0+CB0)%255)); } }

		/// <summary>
		/// Gets the first checkbyte to insert into the data word (don't forget to insert the <see cref="Y"/> checkbyte as well) to generate a checksum of zero.
		/// </summary>
		/// <param name="position">Position (numbered 1..<paramref name="length"/>) of the checkbytes (actually the first one) inside the data word.</param>
		/// <param name="length">Length of the data word.</param>
		/// <returns>The first checkbyte to insert into the data word.</returns>
		public byte X(int position, int length)
		{
			if(position<=0||position>length) throw new ArgumentOutOfRangeException("position", "Must be greater than zero and smaller or equal to length.");
			if(length<=0) throw new ArgumentOutOfRangeException("length", "Must be greater than zero.");
			return (byte)((((length-position)*(long)C0-C1)%255+255)%255);
		}

		/// <summary>
		/// Gets the second checkbyte to insert into the data word (don't forget to insert the <see cref="X"/> checkbyte as well) to generate a checksum of zero.
		/// </summary>
		/// <param name="position">Position (numbered 1..<paramref name="length"/>) of the checkbytes (actually the first one) inside the data word.</param>
		/// <param name="length">Length of the data word.</param>
		/// <returns>The second checkbyte to insert into the data word.</returns>
		public byte Y(int position, int length)
		{
			if(position<=0||position>length) throw new ArgumentOutOfRangeException("position", "Must be greater than zero and smaller or equal to length.");
			if(length<=0) throw new ArgumentOutOfRangeException("length", "Must be greater than zero.");
			return (byte)(((C1-(length-position+1)*(long)C0)%255+255)%255);
		}
	}
}
