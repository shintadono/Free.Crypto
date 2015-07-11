using System;
using Free.Core;

namespace Free.Crypto.CRCChecksums
{
	public static partial class CRC
	{
		#region Generate Table
		/// <summary>
		/// Generates the table for 1-8 bit (w/o the leading 1) polynomials.
		/// </summary>
		/// <param name="polynomial">The polynomial the table is to generate for. Bits must be in the least significant bits.</param>
		/// <param name="width">The width of the polynomial.</param>
		/// <returns>The table.</returns>
		public static byte[] GenerateTable(byte polynomial, int width=8)
		{
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");
			if(width<=0||width>8) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 9.");

			byte poly=polynomial;
			poly<<=8-width;

			byte[] ret=new byte[256];

			for(int i=0; i<256; i++)
			{
				byte register=(byte)i;

				for(int a=7; a>=0; a--)
				{
					bool pop=(register&0x80)!=0;
					register<<=1;
					if(pop) register^=poly;
				}

				ret[i]=register;
			}

			return ret;
		}

		/// <summary>
		/// Generates the table for 1-16 bit (w/o the leading 1) polynomials.
		/// </summary>
		/// <param name="polynomial">The polynomial the table is to generate for. Bits must be in the least significant bits.</param>
		/// <param name="width">The width of the polynomial.</param>
		/// <returns>The table.</returns>
		public static ushort[] GenerateTable(ushort polynomial, int width=16)
		{
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");
			if(width<=0||width>16) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 17.");

			ushort poly=polynomial;
			poly<<=16-width;

			ushort[] ret=new ushort[256];

			for(int i=0; i<256; i++)
			{
				ushort register=(ushort)(i<<8);

				for(int a=7; a>=0; a--)
				{
					bool pop=(register&0x8000)!=0;
					register<<=1;
					if(pop) register^=poly;
				}

				ret[i]=register;
			}

			return ret;
		}

		/// <summary>
		/// Generates the table for 1-32 bit (w/o the leading 1) polynomials.
		/// </summary>
		/// <param name="polynomial">The polynomial the table is to generate for. Bits must be in the least significant bits.</param>
		/// <param name="width">The width of the polynomial.</param>
		/// <returns>The table.</returns>
		public static uint[] GenerateTable(uint polynomial, int width=32)
		{
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");
			if(width<=0||width>32) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 33.");

			uint poly=polynomial;
			poly<<=32-width;

			uint[] ret=new uint[256];

			for(int i=0; i<256; i++)
			{
				uint register=(uint)i<<24;

				for(int a=7; a>=0; a--)
				{
					bool pop=(register&0x80000000)!=0;
					register<<=1;
					if(pop) register^=poly;
				}

				ret[i]=register;
			}

			return ret;
		}

		/// <summary>
		/// Generates the table for 1-64 bit (w/o the leading 1) polynomials.
		/// </summary>
		/// <param name="polynomial">The polynomial the table is to generate for. Bits must be in the least significant bits.</param>
		/// <param name="width">The width of the polynomial.</param>
		/// <returns>The table.</returns>
		public static ulong[] GenerateTable(ulong polynomial, int width=64)
		{
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");
			if(width<=0||width>64) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 65.");

			ulong poly=polynomial;
			poly<<=64-width;

			ulong[] ret=new ulong[256];

			for(int i=0; i<256; i++)
			{
				ulong register=(ulong)i<<56;

				for(int a=7; a>=0; a--)
				{
					bool pop=(register&0x8000000000000000ul)!=0;
					register<<=1;
					if(pop) register^=poly;
				}

				ret[i]=register;
			}

			return ret;
		}

		/// <summary>
		/// Generates the table for 1-128 bit (w/o the leading 1) polynomials.
		/// </summary>
		/// <param name="polynomial">The polynomial the table is to generate for. Bits must be in the least significant bits.</param>
		/// <param name="width">The width of the polynomial.</param>
		/// <returns>The table.</returns>
		public static UInt128[] GenerateTable(UInt128 polynomial, int width=128)
		{
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");
			if(width<=0||width>128) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 129.");

			UInt128 poly=polynomial;
			poly<<=128-width;

			UInt128[] ret=new UInt128[256];

			for(int i=0; i<256; i++)
			{
				UInt128 register=new UInt128((ulong)i<<56, 0);

				for(int a=7; a>=0; a--)
				{
					bool pop=(register.High&0x8000000000000000ul)!=0;
					register=register<<1;
					if(pop) register^=poly;
				}

				ret[i]=register;
			}

			return ret;
		}
		#endregion

		#region Generate Table Reflected
		/// <summary>
		/// Generates the table for 1-8 bit (w/o the leading 1) polynomials.
		/// </summary>
		/// <param name="polynomial">The polynomial the table is to generate for. Bits must be in the least significant bits.</param>
		/// <param name="width">The width of the polynomial.</param>
		/// <returns>The table.</returns>
		public static byte[] GenerateTableReflected(byte polynomial, int width=8)
		{
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");
			if(width<=0||width>8) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 9.");

			// Gets value (2^width)-1.
			uint mask=(1u<<width)-1u;

			byte poly=(byte)(BitOrder.Reflect(polynomial, width)&mask);

			byte[] ret=new byte[256];

			byte i=255;
			do
			{
				byte register=i;

				for(int a=7; a>=0; a--)
				{
					bool pop=(register&0x1)!=0;
					register>>=1;
					if(pop) register^=poly;
				}

				ret[i]=register;
			} while((i--)!=0);

			return ret;
		}

		/// <summary>
		/// Generates the table for 1-16 bit (w/o the leading 1) polynomials.
		/// </summary>
		/// <param name="polynomial">The polynomial the table is to generate for. Bits must be in the least significant bits.</param>
		/// <param name="width">The width of the polynomial.</param>
		/// <returns>The table.</returns>
		public static ushort[] GenerateTableReflected(ushort polynomial, int width=16)
		{
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");
			if(width<=0||width>16) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 17.");

			// Gets value (2^width)-1.
			uint mask=(1u<<width)-1u;

			ushort poly=(ushort)(BitOrder.Reflect(polynomial, width)&mask);

			ushort[] ret=new ushort[256];

			ushort i=255;
			do
			{
				ushort register=i;

				for(int a=7; a>=0; a--)
				{
					bool pop=(register&0x1)!=0;
					register>>=1;
					if(pop) register^=poly;
				}

				ret[i]=register;
			} while((i--)!=0);

			return ret;
		}

		/// <summary>
		/// Generates the table for 1-32 bit (w/o the leading 1) polynomials.
		/// </summary>
		/// <param name="polynomial">The polynomial the table is to generate for. Bits must be in the least significant bits.</param>
		/// <param name="width">The width of the polynomial.</param>
		/// <returns>The table.</returns>
		public static uint[] GenerateTableReflected(uint polynomial, int width=32)
		{
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");
			if(width<=0||width>32) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 33.");

			// Gets value (2^width)-1.
			uint mask=(((1u<<(width-1))-1u)<<1)|1u;

			uint poly=BitOrder.Reflect(polynomial, width)&mask;

			uint[] ret=new uint[256];

			uint i=255;
			do
			{
				uint register=i;

				for(int a=7; a>=0; a--)
				{
					bool pop=(register&0x1)!=0;
					register>>=1;
					if(pop) register^=poly;
				}

				ret[i]=register;
			} while((i--)!=0);

			return ret;
		}

		/// <summary>
		/// Generates the table for 1-64 bit (w/o the leading 1) polynomials.
		/// </summary>
		/// <param name="polynomial">The polynomial the table is to generate for. Bits must be in the least significant bits.</param>
		/// <param name="width">The width of the polynomial.</param>
		/// <returns>The table.</returns>
		public static ulong[] GenerateTableReflected(ulong polynomial, int width=64)
		{
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");
			if(width<=0||width>64) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 65.");

			// Gets value (2^width)-1.
			ulong mask=(((1ul<<(width-1))-1ul)<<1)|1ul;

			ulong poly=BitOrder.Reflect(polynomial, width)&mask;

			ulong[] ret=new ulong[256];

			uint i=255;
			do
			{
				ulong register=i;

				for(int a=7; a>=0; a--)
				{
					bool pop=(register&0x1)!=0;
					register>>=1;
					if(pop) register^=poly;
				}

				ret[i]=register;
			} while((i--)!=0);

			return ret;
		}

		/// <summary>
		/// Generates the table for 1-128 bit (w/o the leading 1) polynomials.
		/// </summary>
		/// <param name="polynomial">The polynomial the table is to generate for. Bits must be in the least significant bits.</param>
		/// <param name="width">The width of the polynomial.</param>
		/// <returns>The table.</returns>
		public static UInt128[] GenerateTableReflected(UInt128 polynomial, int width=128)
		{
			if(polynomial==0) throw new ArgumentOutOfRangeException("polynomial", "Must not be 0.");
			if(width<=0||width>128) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 129.");

			// Gets value (2^width)-1.
			UInt128 mask=UInt128.MaxValue>>(128-width);

			UInt128 poly=BitOrder.Reflect(polynomial, width)&mask;

			UInt128[] ret=new UInt128[256];

			uint i=255;
			do
			{
				UInt128 register=i;

				for(int a=7; a>=0; a--)
				{
					bool pop=(register.Low&0x1)!=0;
					register>>=1;
					if(pop) register^=poly;
				}

				ret[i]=register;
			} while((i--)!=0);

			return ret;
		}
		#endregion
	}
}
