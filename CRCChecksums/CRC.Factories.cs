using System;
using Free.Core;

namespace Free.Crypto.CRCChecksums
{
	public static partial class CRC
	{
		/// <summary>
		/// Creates an instance of a CRC algorithm with the behaviour according to the parameters.
		/// </summary>
		/// <param name="polynomial">The polynomial to use. Unreflected and filled in the least significant bits without the leading 1.</param>
		/// <param name="init">The initial value of the register. Unreflected and filled in the least significant bits.</param>
		/// <param name="refIn">Set <b>true</b>, if input bits are reflected. Least significant bits first.</param>
		/// <param name="refOut">Set <b>true</b>, if register is to be reflected before XORing with <paramref name="xorOut"/> and output.</param>
		/// <param name="xorOut">Value to be XORed with the reflected or unreflected register depending on <paramref name="refOut"/> before output. Filled in the least significant bits.</param>
		/// <param name="width">The width of the polynomial in bits. Must be greater than 0 and less than 9. Default is 8.</param>
		/// <returns>The created instance.</returns>
		public static ICRC<byte> Create(byte polynomial, byte init=0, bool refIn=false, bool refOut=false, byte xorOut=0, int width=8)
		{
			if(refIn) return new ReflectedByte(polynomial, init, refOut, xorOut, width);
			return new UnreflectedByte(polynomial, init, refOut, xorOut, width);
		}

		/// <summary>
		/// Creates an instance of a CRC algorithm with the behaviour according to the parameters.
		/// </summary>
		/// <param name="polynomial">The polynomial to use. Unreflected and filled in the least significant bits without the leading 1.</param>
		/// <param name="init">The initial value of the register. Unreflected and filled in the least significant bits.</param>
		/// <param name="refIn">Set <b>true</b>, if input bits are reflected. Least significant bits first.</param>
		/// <param name="refOut">Set <b>true</b>, if register is to be reflected before XORing with <paramref name="xorOut"/> and output.</param>
		/// <param name="xorOut">Value to be XORed with the reflected or unreflected register depending on <paramref name="refOut"/> before output. Filled in the least significant bits.</param>
		/// <param name="width">The width of the polynomial in bits. Must be greater than 0 and less than 17. Default is 16.</param>
		/// <returns>The created instance.</returns>
		public static ICRC<ushort> Create(ushort polynomial, ushort init=0, bool refIn=false, bool refOut=false, ushort xorOut=0, int width=16)
		{
			if(refIn) return new ReflectedUShort(polynomial, init, refOut, xorOut, width);
			return new UnreflectedUShort(polynomial, init, refOut, xorOut, width);
		}

		/// <summary>
		/// Creates an instance of a CRC algorithm with the behaviour according to the parameters.
		/// </summary>
		/// <param name="polynomial">The polynomial to use. Unreflected and filled in the least significant bits without the leading 1.</param>
		/// <param name="init">The initial value of the register. Unreflected and filled in the least significant bits.</param>
		/// <param name="refIn">Set <b>true</b>, if input bits are reflected. Least significant bits first.</param>
		/// <param name="refOut">Set <b>true</b>, if register is to be reflected before XORing with <paramref name="xorOut"/> and output.</param>
		/// <param name="xorOut">Value to be XORed with the reflected or unreflected register depending on <paramref name="refOut"/> before output. Filled in the least significant bits.</param>
		/// <param name="width">The width of the polynomial in bits. Must be greater than 0 and less than 33. Default is 32.</param>
		/// <returns>The created instance.</returns>
		public static ICRC<uint> Create(uint polynomial, uint init=0, bool refIn=false, bool refOut=false, uint xorOut=0, int width=32)
		{
			if(refIn)
			{
				if(width==32&&polynomial==0x04C11DB7) return new CRC32(init, refOut, xorOut);
				return new ReflectedUInt(polynomial, init, refOut, xorOut, width);
			}
			return new UnreflectedUInt(polynomial, init, refOut, xorOut, width);
		}

		/// <summary>
		/// Creates an instance of a CRC algorithm with the behaviour according to the parameters.
		/// </summary>
		/// <param name="polynomial">The polynomial to use. Unreflected and filled in the least significant bits without the leading 1.</param>
		/// <param name="init">The initial value of the register. Unreflected and filled in the least significant bits.</param>
		/// <param name="refIn">Set <b>true</b>, if input bits are reflected. Least significant bits first.</param>
		/// <param name="refOut">Set <b>true</b>, if register is to be reflected before XORing with <paramref name="xorOut"/> and output.</param>
		/// <param name="xorOut">Value to be XORed with the reflected or unreflected register depending on <paramref name="refOut"/> before output. Filled in the least significant bits.</param>
		/// <param name="width">The width of the polynomial in bits. Must be greater than 0 and less than 65. Default is 64.</param>
		/// <returns>The created instance.</returns>
		public static ICRC<ulong> Create(ulong polynomial, ulong init=0, bool refIn=false, bool refOut=false, ulong xorOut=0, int width=64)
		{
			if(refIn) return new ReflectedULong(polynomial, init, refOut, xorOut, width);
			return new UnreflectedULong(polynomial, init, refOut, xorOut, width);
		}

		/// <summary>
		/// Creates an instance of a CRC algorithm with the behaviour according to the parameters.
		/// </summary>
		/// <param name="polynomial">The polynomial to use. Unreflected and filled in the least significant bits without the leading 1.</param>
		/// <returns>The created instance.</returns>
		public static ICRC<UInt128> Create(UInt128 polynomial)
		{
			return new UnreflectedUInt128(polynomial, UInt128.Zero, false, UInt128.Zero, 128);
		}

		/// <summary>
		/// Creates an instance of a CRC algorithm with the behaviour according to the parameters.
		/// </summary>
		/// <param name="polynomial">The polynomial to use. Unreflected and filled in the least significant bits without the leading 1.</param>
		/// <param name="init">The initial value of the register. Unreflected and filled in the least significant bits.</param>
		/// <param name="refIn">Set <b>true</b>, if input bits are reflected. Least significant bits first.</param>
		/// <param name="refOut">Set <b>true</b>, if register is to be reflected before output.</param>
		/// <returns>The created instance.</returns>
		public static ICRC<UInt128> Create(UInt128 polynomial, UInt128 init, bool refIn=false, bool refOut=false)
		{
			if(refIn) return new ReflectedUInt128(polynomial, init, refOut, UInt128.Zero, 128);
			return new UnreflectedUInt128(polynomial, init, refOut, UInt128.Zero, 128);
		}

		/// <summary>
		/// Creates an instance of a CRC algorithm with the behaviour according to the parameters.
		/// </summary>
		/// <param name="polynomial">The polynomial to use. Unreflected and filled in the least significant bits without the leading 1.</param>
		/// <param name="init">The initial value of the register. Unreflected and filled in the least significant bits.</param>
		/// <param name="refIn">Set <b>true</b>, if input bits are reflected. Least significant bits first.</param>
		/// <param name="refOut">Set <b>true</b>, if register is to be reflected before XORing with <paramref name="xorOut"/> and output.</param>
		/// <param name="xorOut">Value to be XORed with the reflected or unreflected register depending on <paramref name="refOut"/> before output. Filled in the least significant bits.</param>
		/// <param name="width">The width of the polynomial in bits. Must be greater than 0 and less than 129. Default is 128.</param>
		/// <returns>The created instance.</returns>
		public static ICRC<UInt128> Create(UInt128 polynomial, UInt128 init, bool refIn, bool refOut, UInt128 xorOut, int width=128)
		{
			if(refIn) return new ReflectedUInt128(polynomial, init, refOut, xorOut, width);
			return new UnreflectedUInt128(polynomial, init, refOut, xorOut, width);
		}

		/// <summary>
		/// Creates an instance of a CRC algorithm with the behaviour according to the parameters.
		/// </summary>
		/// <param name="descriptor">A structure containing the parameters.</param>
		/// <returns>The created instance.</returns>
		public static ICRC Create(CRCDescriptor descriptor)
		{
			if(descriptor.Width<=0||descriptor.Width>128) throw new ArgumentOutOfRangeException("descriptor.Width", "Must be greater than 0 and less than 129.");

			if(descriptor.Width<=8) return Create((byte)descriptor.Polynomial, (byte)descriptor.Init, descriptor.RefIn, descriptor.RefOut, (byte)descriptor.XorOut, descriptor.Width);
			if(descriptor.Width<=16) return Create((ushort)descriptor.Polynomial, (ushort)descriptor.Init, descriptor.RefIn, descriptor.RefOut, (ushort)descriptor.XorOut, descriptor.Width);
			if(descriptor.Width<=32) return Create((uint)descriptor.Polynomial, (uint)descriptor.Init, descriptor.RefIn, descriptor.RefOut, (uint)descriptor.XorOut, descriptor.Width);
			if(descriptor.Width<=64) return Create((ulong)descriptor.Polynomial, (ulong)descriptor.Init, descriptor.RefIn, descriptor.RefOut, (ulong)descriptor.XorOut, descriptor.Width);
			
			return Create(new UInt128(descriptor.PolynomialHigh, descriptor.Polynomial), new UInt128(descriptor.InitHigh, descriptor.Init),
				descriptor.RefIn, descriptor.RefOut, new UInt128(descriptor.XorOutHigh, descriptor.XorOut), descriptor.Width);
		}
	}
}
