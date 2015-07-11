using System;
using System.Collections.Generic;
using Free.Core;

namespace Free.Crypto.CRCChecksums.RocksoftTMModelCRCAlgorithms
{
	/// <summary>
	/// Implements the "Rocksoft^tm Model CRC Algorithm" as described in
	/// "A Painless Guide to CRC Error Detection Algorithms" (see crc_v3.txt) by Ross Williams.
	/// </summary>
	/// <threadsafety static="false" instance="false"/>
	[CLSCompliant(false)]
	public class RocksoftTMModelCRC
	{
		int width, offset;
		ulong register, polynomial, topbit, mask, xorOut;
		bool refIn, refOut;

		/// <summary>
		/// Creates an instance of the "Rocksoft^tm Model CRC Algorithm".
		/// </summary>
		/// <param name="width">The width of the polynomial in bits. Must be greater than 0 and less than 65.</param>
		/// <param name="polynomial">The polynomial to use. Unreflected and filled in the least significant bits without the leading 1.</param>
		/// <param name="init">The initial value of the register. Unreflected and filled in the least significant bits.</param>
		/// <param name="refIn">Set <b>true</b>, if input bits are reflected. Least significant bits first.</param>
		/// <param name="refOut">Set <b>true</b>, if register is to be reflected before XORing with <paramref name="xorOut"/> and output.</param>
		/// <param name="xorOut">Value to be XORed with the reflected or unreflected register depending on <paramref name="refOut"/> before output. Filled in the least significant bits.</param>
		public RocksoftTMModelCRC(int width, ulong polynomial, ulong init=0, bool refIn=false, bool refOut=false, ulong xorOut=0)
		{
			if(width<=0||width>64) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 65.");

			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");

			this.width=width;

			topbit=1ul<<(width-1);

			// Gets value (2^width)-1.
			mask=(((1ul<<(width-1))-1ul)<<1)|1ul;

			this.polynomial=polynomial&mask;
			register=init&mask;
			this.refIn=refIn;
			this.refOut=refOut;
			this.xorOut=xorOut&mask;

			if(width<8)
			{
				topbit=0x80;
				mask=0xFF;
				offset=8-width;
				this.polynomial<<=offset;
				register<<=offset;
			}
			else offset=0;
		}

		/// <summary>
		/// Processes a single message byte.
		/// </summary>
		/// <param name="value">The value to add to the CRC.</param>
		/// <returns>A reference to <b>this</b> instance.</returns>
		public RocksoftTMModelCRC Add(byte value)
		{
			ulong val=(ulong)value;

			if(refIn) val=BitOrder.Reflect(val, 8);
			register^=val<<(width+offset-8);
			for(int i=0; i<8; i++)
			{
				if((register&topbit)==0) register<<=1;
				else register=(register<<1)^polynomial;
				register&=mask;
			}

			return this;
		}

		/// <summary>
		/// Processes message bytes.
		/// </summary>
		/// <param name="data">The data to add to the CRC.</param>
		/// <param name="offset">Location in the array where to start in bytes.</param>
		/// <param name="count">Number of bytes.</param>
		/// <returns>A reference to <b>this</b> instance.</returns>
		public RocksoftTMModelCRC Add(IList<byte> data, int offset=0, int count=0)
		{
			if(data==null) throw new ArgumentNullException("data");
			if(offset<0||offset>data.Count)
				throw new ArgumentOutOfRangeException("offset", "Must be non-negative and less than or equal to the length of data in bytes.");

			if(count<0) throw new ArgumentOutOfRangeException("count", "Must be non-negative.");
			if(offset+count>data.Count) throw new ArgumentOutOfRangeException("count", "Must be less than or equal to the length of data in bytes minus the offset argument.");

			if(count==0)
			{
				count=data.Count-offset;
				if(count==0) return this;
			}

			int endOfByteStream=offset+count;

			for(int i=offset; i<endOfByteStream; i++) Add(data[i]);

			return this;
		}

		/// <summary>
		/// Gets the CRC value (not the register) for the message bytes processed so far.
		/// </summary>
		public ulong Value
		{
			get
			{
				if(!refOut) return xorOut^(register>>offset);
				return xorOut^BitOrder.Reflect(register>>offset, width);
			}
		}
	}
}
