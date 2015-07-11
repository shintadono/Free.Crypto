using System;

namespace Free.Crypto.CRCChecksums
{
	/// <summary>
	/// Describes the parameters of a CRC algorithm as described in
	/// "A Painless Guide to CRC Error Detection Algorithms" (see crc_v3.txt) by Ross Williams.
	/// </summary>
	[CLSCompliant(false)]
	public struct CRCDescriptor
	{
		/// <summary>
		/// The name of the CRC algorithm.
		/// </summary>
		public string Name;

		/// <summary>
		/// An array of names also used for the CRC algorithm.
		/// </summary>
		public string[] Aliases;

		/// <summary>
		/// The width of the polynomial in bits (the length of the polynomial w/o the leading 1).
		/// </summary>
		public int Width;

		/// <summary>
		/// The polynomial. Unreflected and filled in the least significant bits without the leading 1.
		/// </summary>
		public ulong Polynomial;

		/// <summary>
		/// The initial value of the register. Unreflected and filled in the least significant bits.
		/// </summary>
		public ulong Init;

		/// <summary>
		/// Set <b>true</b>, if input bits are reflected. Least significant bits first.
		/// </summary>
		public bool RefIn;

		/// <summary>
		/// Set <b>true</b>, if register is to be reflected before XORing with <see cref="XorOut"/> and output.
		/// </summary>
		public bool RefOut;

		/// <summary>
		/// Value to be XORed with the reflected or unreflected register depending on <see cref="RefOut"/> before output. Filled in the least significant bits.
		/// </summary>
		public ulong XorOut;

		/// <summary>
		/// Higher bits of the <see cref="Polynomial"/> with a <see cref="Width"/> greater 64 bits.
		/// </summary>
		public ulong PolynomialHigh;

		/// <summary>
		/// Higher bits of the <see cref="Init"/> value with a <see cref="Width"/> greater 64 bits.
		/// </summary>
		public ulong InitHigh;

		/// <summary>
		/// Higher bits of the <see cref="XorOut"/> value with a <see cref="Width"/> greater 64 bits.
		/// </summary>
		public ulong XorOutHigh;
	}
}
