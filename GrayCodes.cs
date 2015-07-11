using System;

namespace Free.Crypto
{
	/// <summary>
	/// Implements the algorithm invented by Frank Gray, that
	/// procudes consecutive codes that differ in exactly 1 bit
	/// from code to the next.
	/// </summary>
	/// <threadsafety static="true" instance="true"/>
	public static class GrayCodes
	{
		/// <summary>
		/// Converts a value to it's Gray code counterpart.
		/// </summary>
		/// <param name="value">The value for which to return the Gray code.</param>
		/// <returns>The Gray code for <paramref name="value"/>.</returns>
		[CLSCompliant(false)]
		public static byte BinaryToGray(byte value)
		{
			return (byte)(value^(value>>1));
		}

		/// <summary>
		/// Converts a value to it's Gray code counterpart.
		/// </summary>
		/// <param name="value">The value for which to return the Gray code.</param>
		/// <returns>The Gray code for <paramref name="value"/>.</returns>
		[CLSCompliant(false)]
		public static ushort BinaryToGray(ushort value)
		{
			return (ushort)(value^(value>>1));
		}

		/// <summary>
		/// Converts a value to it's Gray code counterpart.
		/// </summary>
		/// <param name="value">The value for which to return the Gray code.</param>
		/// <returns>The Gray code for <paramref name="value"/>.</returns>
		public static int BinaryToGray(int value)
		{
			if(value<0) throw new ArgumentOutOfRangeException("value", "Must not be smaller than zero (0).");

			return value^(value>>1);
		}

		/// <summary>
		/// Converts a value to it's Gray code counterpart.
		/// </summary>
		/// <param name="value">The value for which to return the Gray code.</param>
		/// <returns>The Gray code for <paramref name="value"/>.</returns>
		[CLSCompliant(false)]
		public static uint BinaryToGray(uint value)
		{
			return value^(value>>1);
		}

		/// <summary>
		/// Converts a value to it's Gray code counterpart.
		/// </summary>
		/// <param name="value">The value for which to return the Gray code.</param>
		/// <returns>The Gray code for <paramref name="value"/>.</returns>
		[CLSCompliant(false)]
		public static ulong BinaryToGray(ulong value)
		{
			return value^(value>>1);
		}

		/// <summary>
		/// Converts Gray code value to it's binary code counterpart.
		/// </summary>
		/// <param name="gray">The Gray code value for which to return the binary code.</param>
		/// <returns>The binary code for the Gray code <paramref name="gray"/>.</returns>
		[CLSCompliant(false)]
		public static byte GrayToBinary(byte gray)
		{
			gray^=(byte)(gray>>4);
			gray^=(byte)(gray>>2);
			gray^=(byte)(gray>>1);
			return gray;
		}

		/// <summary>
		/// Converts Gray code value to it's binary code counterpart.
		/// </summary>
		/// <param name="gray">The Gray code value for which to return the binary code.</param>
		/// <returns>The binary code for the Gray code <paramref name="gray"/>.</returns>
		[CLSCompliant(false)]
		public static ushort GrayToBinary(ushort gray)
		{
			gray^=(ushort)(gray>>8);
			gray^=(ushort)(gray>>4);
			gray^=(ushort)(gray>>2);
			gray^=(ushort)(gray>>1);
			return gray;
		}

		/// <summary>
		/// Converts Gray code value to it's binary code counterpart.
		/// </summary>
		/// <param name="gray">The Gray code value for which to return the binary code.</param>
		/// <returns>The binary code for the Gray code <paramref name="gray"/>.</returns>
		public static int GrayToBinary(int gray)
		{
			if(gray<0) throw new ArgumentOutOfRangeException("gray", "Must not be smaller than zero (0).");

			gray^=(gray>>16);
			gray^=(gray>>8);
			gray^=(gray>>4);
			gray^=(gray>>2);
			gray^=(gray>>1);
			return gray;
		}

		/// <summary>
		/// Converts Gray code value to it's binary code counterpart.
		/// </summary>
		/// <param name="gray">The Gray code value for which to return the binary code.</param>
		/// <returns>The binary code for the Gray code <paramref name="gray"/>.</returns>
		[CLSCompliant(false)]
		public static uint GrayToBinary(uint gray)
		{
			gray^=(gray>>16);
			gray^=(gray>>8);
			gray^=(gray>>4);
			gray^=(gray>>2);
			gray^=(gray>>1);
			return gray;
		}

		/// <summary>
		/// Converts Gray code value to it's binary code counterpart.
		/// </summary>
		/// <param name="gray">The Gray code value for which to return the binary code.</param>
		/// <returns>The binary code for the Gray code <paramref name="gray"/>.</returns>
		[CLSCompliant(false)]
		public static ulong GrayToBinary(ulong gray)
		{
			gray^=(gray>>32);
			gray^=(gray>>16);
			gray^=(gray>>8);
			gray^=(gray>>4);
			gray^=(gray>>2);
			gray^=(gray>>1);
			return gray;
		}
	}
}
