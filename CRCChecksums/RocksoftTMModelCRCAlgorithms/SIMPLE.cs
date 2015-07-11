using System;
using System.Collections.Generic;

namespace Free.Crypto.CRCChecksums.RocksoftTMModelCRCAlgorithms
{
	/// <summary>
	/// Implements the SIMPLE algorithm as described in
	/// "A Painless Guide to CRC Error Detection Algorithms" (see crc_v3.txt) by Ross Williams.
	/// </summary>
	/// <remarks>
	/// The functions in this class represent an implementation that could be defined via the
	/// "Rocksoft^tm Model CRC Algorithm" parameter:
	/// <list type="table">
	///  <listheader><term>Parameter</term><description>Value</description></listheader>
	///  <item><term>Name</term><description>Not needed.</description></item>
	///  <item><term>Width</term><description>1-64 (depending on the type of polynomial argument)</description></item>
	///  <item><term>Poly</term><description>Any 1-64 bit polynomial.</description></item>
	///  <item><term>Init</term><description>0</description></item>
	///  <item><term>RefIn</term><description>false</description></item>
	///  <item><term>RefOut</term><description>false</description></item>
	///  <item><term>XorOut</term><description>0</description></item>
	///  <item><term>Check</term><description>Depends on the polynomial.</description></item>
	/// </list>
	/// </remarks>
	/// <threadsafety static="true" instance="true"/>
	[CLSCompliant(false)]
	[Obsolete("This class is for educational purposes only. You should use the high-performance implementations in the class CRC.")]
	public static class SIMPLE
	{
		/// <summary>
		/// Calculates the CRC of bits stored in a <see cref="Byte"/>[].
		/// The "absolutely straight-down-the-middle boring straightforward low-speed implementation". (see chapter 8, for pseudocode and explantion)
		/// </summary>
		/// <param name="width">The width of the polynomial in bits. Must be greater than 0 and less than 33.</param>
		/// <param name="polynomial">The polynomial to use.</param>
		/// <param name="data">The bits. (Most significant bit of the first byte first (starting at <paramref name="offset"/>.)</param>
		/// <param name="offset">Location in the array where to start in bits.</param>
		/// <param name="count">Number of bits.</param>
		/// <returns>The CRC value.</returns>
		public static uint Get(int width, uint polynomial, IList<byte> data, int offset=0, int count=0)
		{
			if(width<=0||width>32) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 33.");

			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");

			if(data==null) throw new ArgumentNullException("data");
			if(offset<0||offset>data.Count*8)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data in bits.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Count*8) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data in bits minus the offset argument.");

			if(count==0)
			{
				count=data.Count*8-offset;
				if(count==0) return 0;
			}

			uint popBitMask=1u<<(width-1);
			uint bitMask=0;
			for(int i=0; i<width; i++) bitMask|=1u<<i;

			polynomial&=bitMask;
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0 in the relevant bits.");

			byte bitRot=0x80;
			if(offset%8!=0) bitRot>>=offset%8;
			int byteInArray=offset/8;

			int endOfBitStream=offset+count;

			// Load the register with zero bits.
			uint register=0;

			// Augment the message by appending W zero bits to the end of it.
			int end=endOfBitStream+width;

			// While (more message bits)
			while(offset<end)
			{
				// (Testing the IF condition (needed later) by testing the top bit of register before performing the shift.
				bool pop=(register&popBitMask)!=0;

				// Shift the register left by one bit,
				register=(register<<1)&bitMask;

				// reading the next bit of the augmented message into register bit position 0.
				if(offset<endOfBitStream&&((data[byteInArray]&bitRot)!=0)) register|=1;

				// Prepair for the next bit in byte.
				if((bitRot>>=1)==0)
				{ // If next byte.
					bitRot=0x80;
					byteInArray++;
				}

				// If (a 1 bit popped out of the register during step 3)
				if(pop) register^=polynomial; // Register = Register XOR Poly.

				offset++;
			}

			// The register now contains the remainder.
			return register;
		}

		/// <summary>
		/// Calculates the CRC of bits stored in a <see cref="Byte"/>[].
		/// The "absolutely straight-down-the-middle boring straightforward low-speed implementation". (see chapter 8, for pseudocode and explantion)
		/// </summary>
		/// <param name="width">The width of the polynomial in bits. Must be greater than 0 and less than 65.</param>
		/// <param name="polynomial">The polynomial to use.</param>
		/// <param name="data">The bits. (Most significant bit of the first byte first (starting at <paramref name="offset"/>.)</param>
		/// <param name="offset">Location in the array where to start in bits.</param>
		/// <param name="count">Number of bits.</param>
		/// <returns>The CRC value.</returns>
		public static ulong Get(int width, ulong polynomial, IList<byte> data, int offset=0, int count=0)
		{
			if(width<=0||width>64) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 65.");

			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");

			if(data==null) throw new ArgumentNullException("data");
			if(offset<0||offset>data.Count*8)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data in bits.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Count*8) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data in bits minus the offset argument.");

			if(count==0)
			{
				count=data.Count*8-offset;
				if(count==0) return 0;
			}

			ulong popBitMask=1ul<<(width-1);
			ulong bitMask=0;
			for(int i=0; i<width; i++) bitMask|=1ul<<i;

			polynomial&=bitMask;
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0 in the relevant bits.");

			byte bitRot=0x80;
			if(offset%8!=0) bitRot>>=offset%8;
			int byteInArray=offset/8;

			int endOfBitStream=offset+count;

			// Load the register with zero bits.
			ulong register=0;

			// Augment the message by appending W zero bits to the end of it.
			int end=endOfBitStream+width;

			// While (more message bits)
			while(offset<end)
			{
				// (Testing the IF condition (needed later) by testing the top bit of register before performing the shift.
				bool pop=(register&popBitMask)!=0;

				// Shift the register left by one bit,
				register=(register<<1)&bitMask;

				// reading the next bit of the augmented message into register bit position 0.
				if(offset<endOfBitStream&&((data[byteInArray]&bitRot)!=0)) register|=1;

				// Prepair for the next bit in byte.
				if((bitRot>>=1)==0)
				{ // If next byte.
					bitRot=0x80;
					byteInArray++;
				}

				// If (a 1 bit popped out of the register during step 3)
				if(pop) register^=polynomial; // Register = Register XOR Poly.

				offset++;
			}

			// The register now contains the remainder.
			return register;
		}
	}
}
