using System;
using System.Runtime.InteropServices;

namespace Free.Crypto.FletcherChecksums
{
	/// <summary>
	/// Result for the <see cref="O:Free.Crypto.FletcherChecksums.Fletcher64.Get">Fletcher64.Get</see> and <see cref="O:Free.Crypto.FletcherChecksums.Fletcher64.GetSlow">Fletcher64.GetSlow</see> methods.
	/// </summary>
	/// <remarks>
	/// <para>In 32-bit one's complement arithmetics the numbers 0x00000000 and 0xFFFFFFFF have the same value 0. This struct provides
	/// equals-checks that take this property into account. Fletcher checksums shall always be checked usings
	/// these methods.</para>
	/// <para>This struct also provides ways the generate so-called checkblocks:
	/// <list type="numbers">
	/// <item> 
	/// <description>Using the checksum of a data word (e.g. a <see cref="UInt32"/>[]), you can get two blocks
	/// (<see cref="CB0"/> and <see cref="CB1"/>), which, appended to the data word, would generate a checksum of
	/// zero (or the same value, see above) for that data word.</description> 
	/// </item> 
	/// <item> 
	/// <description>Using the checksum of a data word (e.g. a <see cref="UInt32"/>[]), the position of the checkblocks
	/// (two blocks) inside the data word, and the length of the data word, you can get the two blocks (<see cref="X"/>
	/// and <see cref="Y"/>), which, inserted at their positions inside the data word, would generate a checksum of
	/// zero (or the same value, see above) for that data word. The value of the two blocks must be zero (or the same
	/// value, see above), when calculating the original (unpatched) checksum.</description> 
	/// </item>
	/// </list>
	/// </para>
	/// <para>
	/// Attaching or inserting the checkblocks will produce a data word that conforms to ∑a[i-1] ≡ 0 (mod 0xFFFFFFFF) and ∑i*a[i-1] ≡ 0 (mod 0xFFFFFFFF) (with i=1..Length of the data word).
	/// </para>
	/// <para>For more information on the checksum itself see:</para>
	/// <para>Fletcher, J. G., "An Arithmetic Checksum for Serial Transmissions", IEEE Transactions on Communications, Vol. COM-30, No. 1, January 1982, pp. 247-252.</para>
	/// <para>For a formal specification of the checksum and the checkblocks see:</para>
	/// <para>ITU-T Recommendation X.224, Annex D, "Checksum Algorithms", November, 1993, pp. 144, 145. ITU-T X.244 is also the same as ISO 8073.</para>
	/// </remarks>
	/// <threadsafety static="false" instance="false"/>
	[StructLayout(LayoutKind.Sequential, Pack=1)]
	[CLSCompliant(false)]
	public struct Fletcher64Checksum : IEquatable<Fletcher64Checksum>
	{
		/// <summary>
		/// Const instance of <see cref="Fletcher64Checksum"/> representing a zero checksum.
		/// </summary>
		public static readonly Fletcher64Checksum Zero=new Fletcher64Checksum();

		/// <summary>
		/// C0 and C1 are the values of the Fletcher-64 checksum. (C0 is the lower half, C1 the upper half.)
		/// </summary>
		public uint C0, C1;

		/// <summary>
		/// Returns the hash code for this instance.
		/// </summary>
		/// <returns>A <see cref="UInt32"/> hashcode. (That is not the value of the checksum! It won't even fit.)</returns>
		public override int GetHashCode()
		{
			return (((ushort)C1<<16)|(ushort)C0);
		}

		/// <summary>
		/// Indicates whether this instance and a specified object are equal.
		/// </summary>
		/// <param name="obj">The object to compare with the current instance.</param>
		/// <returns><c>true</c> if <paramref name="obj"/> and this instance are the same type and represent the same value; otherwise, <c>false</c>.</returns>
		public override bool Equals(object obj)
		{
			if(!(obj is Fletcher64Checksum)) return false;

			Fletcher64Checksum other=(Fletcher64Checksum)obj;
			return (C0%uint.MaxValue)==(other.C0%uint.MaxValue)&&(C1%uint.MaxValue)==(other.C1%uint.MaxValue);
		}

		/// <summary>
		/// Indicates whether this instance and a specified <see cref="Fletcher64Checksum"/> are equal.
		/// </summary>
		/// <param name="other">The <see cref="Fletcher64Checksum"/> to compare with the current instance.</param>
		/// <returns><c>true</c> if <paramref name="other"/> and this instance represent the same value; otherwise, <c>false</c>.</returns>
		public bool Equals(Fletcher64Checksum other)
		{
			return (C0%uint.MaxValue)==(other.C0%uint.MaxValue)&&(C1%uint.MaxValue)==(other.C1%uint.MaxValue);
		}

		/// <summary>
		/// Determines whether two specified <see cref="Fletcher64Checksum"/>s represent the same value.
		/// </summary>
		/// <param name="a">The first <see cref="Fletcher64Checksum"/> to compare.</param>
		/// <param name="b">The second <see cref="Fletcher64Checksum"/> to compare.</param>
		/// <returns><c>true</c> if <paramref name="a"/> represent the same value as <paramref name="b"/>; otherwise, <c>false</c>.</returns>
		public static bool operator==(Fletcher64Checksum a, Fletcher64Checksum b)
		{
			return (a.C0%uint.MaxValue)==(b.C0%uint.MaxValue)&&(a.C1%uint.MaxValue)==(b.C1%uint.MaxValue);
		}

		/// <summary>
		/// Determines whether two specified <see cref="Fletcher64Checksum"/>s represent different values.
		/// </summary>
		/// <param name="a">The first <see cref="Fletcher64Checksum"/> to compare.</param>
		/// <param name="b">The second <see cref="Fletcher64Checksum"/> to compare.</param>
		/// <returns><c>true</c> if <paramref name="a"/> represent not the same value as <paramref name="b"/>; otherwise, <c>false</c>.</returns>
		public static bool operator!=(Fletcher64Checksum a, Fletcher64Checksum b)
		{
			return (a.C0%uint.MaxValue)!=(b.C0%uint.MaxValue)||(a.C1%uint.MaxValue)!=(b.C1%uint.MaxValue);
		}

		/// <summary>
		/// Gets the first checkblock to append to the data word (don't forget to append the <see cref="CB1"/> checkblock as well) to generate a checksum of zero.
		/// </summary>
		public uint CB0 { get { return (uint)(uint.MaxValue-(((long)C0+C1)%uint.MaxValue)); } }

		/// <summary>
		/// Gets the second checkblock to append to the data word (after the <see cref="CB0"/> checkblock) to generate a checksum of zero.
		/// </summary>
		public uint CB1 { get { return (uint)(uint.MaxValue-(((long)C0+CB0)%uint.MaxValue)); } }

		/// <summary>
		/// Gets the first checkblock to insert into the data word (don't forget to insert the <see cref="Y"/> checkblock as well) to generate a checksum of zero.
		/// </summary>
		/// <param name="position">Position (numbered 1..<paramref name="length"/>) of the checkblocks (actually the first one) inside the data word.</param>
		/// <param name="length">Length of the data word.</param>
		/// <returns>The first checkblock to insert into the data word.</returns>
		public uint X(int position, int length)
		{
			if(position<=0||position>length) throw new ArgumentOutOfRangeException("position", "Must be greater than zero and smaller or equal to length.");
			if(length<=0) throw new ArgumentOutOfRangeException("length", "Must be greater than zero.");
			return (uint)((((length-position)*(long)C0-C1)%uint.MaxValue+uint.MaxValue)%uint.MaxValue);
		}

		/// <summary>
		/// Gets the second checkblock to insert into the data word (don't forget to insert the <see cref="X"/> checkblock as well) to generate a checksum of zero.
		/// </summary>
		/// <param name="position">Position (numbered 1..<paramref name="length"/>) of the checkblocks (actually the first one) inside the data word.</param>
		/// <param name="length">Length of the data word.</param>
		/// <returns>The second checkblock to insert into the data word.</returns>
		public uint Y(int position, int length)
		{
			if(position<=0||position>length) throw new ArgumentOutOfRangeException("position", "Must be greater than zero and smaller or equal to length.");
			if(length<=0) throw new ArgumentOutOfRangeException("length", "Must be greater than zero.");
			return (uint)(((C1-(length-position+1)*(long)C0)%uint.MaxValue+uint.MaxValue)%uint.MaxValue);
		}
	}
}
