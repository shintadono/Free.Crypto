using System;
using Free.Core;

namespace Free.Crypto.CRCChecksums
{
	public static partial class CRC
	{
		#region MatrixMult & MatrixSquare Helper
		/// <summary>
		/// Multiplication of matrix with vector (MOD 2). This method doesn't check the
		/// input arguments for performance reasons, so please make sure they are correct.
		/// </summary>
		/// <param name="matrix">The matrix to multiply with.</param>
		/// <param name="vector">The vector to be multiplied with the matrix.</param>
		/// <returns>The resulting vector.</returns>
		static byte MatrixMult(byte[] matrix, byte vector)
		{
			int index=0;
			byte[] mat=matrix;
			byte vec=vector;

			byte ret=0;

			while(vec!=0)
			{
				if((vec&1)!=0) ret^=mat[index];
				vec>>=1;
				index++;
			}

			return ret;
		}

		/// <summary>
		/// Multiplication of matrix with vector (MOD 2). This method doesn't check the
		/// input arguments for performance reasons, so please make sure they are correct.
		/// </summary>
		/// <param name="matrix">The matrix to multiply with.</param>
		/// <param name="vector">The vector to be multiplied with the matrix.</param>
		/// <returns>The resulting vector.</returns>
		static ushort MatrixMult(ushort[] matrix, ushort vector)
		{
			int index=0;
			ushort[] mat=matrix;
			ushort vec=vector;

			ushort ret=0;

			while(vec!=0)
			{
				if((vec&1)!=0) ret^=mat[index];
				vec>>=1;
				index++;
			}

			return ret;
		}

		/// <summary>
		/// Multiplication of matrix with vector (MOD 2). This method doesn't check the
		/// input arguments for performance reasons, so please make sure they are correct.
		/// </summary>
		/// <param name="matrix">The matrix to multiply with.</param>
		/// <param name="vector">The vector to be multiplied with the matrix.</param>
		/// <returns>The resulting vector.</returns>
		internal static uint MatrixMult(uint[] matrix, uint vector)
		{
			int index=0;
			uint[] mat=matrix;
			uint vec=vector;

			uint ret=0;

			while(vec!=0)
			{
				if((vec&1)!=0) ret^=mat[index];
				vec>>=1;
				index++;
			}

			return ret;
		}

		/// <summary>
		/// Multiplication of matrix with vector (MOD 2). This method doesn't check the
		/// input arguments for performance reasons, so please make sure they are correct.
		/// </summary>
		/// <param name="matrix">The matrix to multiply with.</param>
		/// <param name="vector">The vector to be multiplied with the matrix.</param>
		/// <returns>The resulting vector.</returns>
		static ulong MatrixMult(ulong[] matrix, ulong vector)
		{
			int index=0;
			ulong[] mat=matrix;
			ulong vec=vector;

			ulong ret=0;

			while(vec!=0)
			{
				if((vec&1)!=0) ret^=mat[index];
				vec>>=1;
				index++;
			}

			return ret;
		}

		/// <summary>
		/// Multiplication of matrix with vector (MOD 2). This method doesn't check the
		/// input arguments for performance reasons, so please make sure they are correct.
		/// </summary>
		/// <param name="matrix">The matrix to multiply with.</param>
		/// <param name="vector">The vector to be multiplied with the matrix.</param>
		/// <returns>The resulting vector.</returns>
		static UInt128 MatrixMult(UInt128[] matrix, UInt128 vector)
		{
			int index=0;
			UInt128[] mat=matrix;
			UInt128 vec=vector;

			UInt128 ret=0;

			while(vec!=0)
			{
				if((vec.Low&1)!=0) ret^=mat[index];
				vec>>=1;
				index++;
			}

			return ret;
		}

		/// <summary>
		/// Squares a matrix (MOD 2). This method doesn't check the input arguments for
		/// performance reasons, so please make sure they are correct.
		/// </summary>
		/// <param name="result">The matrix for the result. Must be at least <paramref name="width"/> long.</param>
		/// <param name="matrix">The matrix to be squared. Must be at least <paramref name="width"/> long.</param>
		/// <param name="width">The width of the matrix. Default is 8.</param>
		static void MatrixSquare(byte[] result, byte[] matrix, int width=8)
		{
			byte[] res=result;
			byte[] mat=matrix;
			for(int n=0; n<width; n++) res[n]=MatrixMult(mat, mat[n]);
		}

		/// <summary>
		/// Squares a matrix (MOD 2). This method doesn't check the input arguments for
		/// performance reasons, so please make sure they are correct.
		/// </summary>
		/// <param name="result">The matrix for the result. Must be at least <paramref name="width"/> long.</param>
		/// <param name="matrix">The matrix to be squared. Must be at least <paramref name="width"/> long.</param>
		/// <param name="width">The width of the matrix. Default is 16.</param>
		static void MatrixSquare(ushort[] result, ushort[] matrix, int width=16)
		{
			ushort[] res=result;
			ushort[] mat=matrix;
			for(int n=0; n<width; n++) res[n]=MatrixMult(mat, mat[n]);
		}

		/// <summary>
		/// Squares a matrix (MOD 2). This method doesn't check the input arguments for
		/// performance reasons, so please make sure they are correct.
		/// </summary>
		/// <param name="result">The matrix for the result. Must be at least <paramref name="width"/> long.</param>
		/// <param name="matrix">The matrix to be squared. Must be at least <paramref name="width"/> long.</param>
		/// <param name="width">The width of the matrix. Default is 32.</param>
		internal static void MatrixSquare(uint[] result, uint[] matrix, int width=32)
		{
			uint[] res=result;
			uint[] mat=matrix;
			for(int n=0; n<width; n++) res[n]=MatrixMult(mat, mat[n]);
		}

		/// <summary>
		/// Squares a matrix (MOD 2). This method doesn't check the input arguments for
		/// performance reasons, so please make sure they are correct.
		/// </summary>
		/// <param name="result">The matrix for the result. Must be at least <paramref name="width"/> long.</param>
		/// <param name="matrix">The matrix to be squared. Must be at least <paramref name="width"/> long.</param>
		/// <param name="width">The width of the matrix. Default is 64.</param>
		static void MatrixSquare(ulong[] result, ulong[] matrix, int width=64)
		{
			ulong[] res=result;
			ulong[] mat=matrix;
			for(int n=0; n<width; n++) res[n]=MatrixMult(mat, mat[n]);
		}

		/// <summary>
		/// Squares a matrix (MOD 2). This method doesn't check the input arguments for
		/// performance reasons, so please make sure they are correct.
		/// </summary>
		/// <param name="result">The matrix for the result. Must be at least <paramref name="width"/> long.</param>
		/// <param name="matrix">The matrix to be squared. Must be at least <paramref name="width"/> long.</param>
		/// <param name="width">The width of the matrix. Default is 128.</param>
		static void MatrixSquare(UInt128[] result, UInt128[] matrix, int width=128)
		{
			UInt128[] res=result;
			UInt128[] mat=matrix;
			for(int n=0; n<width; n++) res[n]=MatrixMult(mat, mat[n]);
		}
		#endregion

		#region Combine
		/// <summary>
		/// Combines the CRCs of two blocks to the CRC of the blocks concatenated.
		/// </summary>
		/// <param name="crc1">The CRC of the first block.</param>
		/// <param name="crc2">The CRC of the second block.</param>
		/// <param name="lengthOfCRC2">The length of the second block in bytes.</param>
		/// <param name="polynomial">The polynomial used to create the CRCs. Unreflected and filled in the least significant bits.</param>
		/// <param name="init">The initial value of the register. Unreflected and filled in the least significant bits.</param>
		/// <param name="refOut">Set <b>true</b>, if register is to be reflected before XORing with <paramref name="xorOut"/> and output.</param>
		/// <param name="xorOut">Value to be XORed with the reflected or unreflected register depending on <paramref name="refOut"/> before output. Filled in the least significant bits.</param>
		/// <param name="width">The width of the polynomial in bits. Must be greater than 0 and less than 9. Default is 8.</param>
		/// <returns>The combined CRC value.</returns>
		public static byte Combine(byte crc1, byte crc2, int lengthOfCRC2, byte polynomial, byte init=0, bool refOut=false, byte xorOut=0, int width=8)
		{
			if(lengthOfCRC2<0) throw new ArgumentOutOfRangeException("lengthOfCRC2", "Must not be less than zero (0).");
			if(width<=0||width>8) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 9.");

			// Nothing to combine
			if(lengthOfCRC2==0) return crc1;

			// Gets value (2^width)-1.
			uint mask=(1u<<width)-1u;

			crc1&=(byte)mask;
			crc2&=(byte)mask;
			polynomial&=(byte)mask;
			init&=(byte)mask;
			xorOut&=(byte)mask;

			crc1^=xorOut; // Remove xorOut from CRC1

			byte crc=refOut?BitOrder.Reflect(crc1, width):crc1; // If CRC is reflected against SIMPLE and thus against the polynomial

			crc^=init; // Remove CRC2's register initialization value by adding to CRC

			byte[] mat1=new byte[width], mat2=new byte[width]; // Create matrices (for inplace squaring operation)

			// Fill matrix with 1-bit-shift-operation (bit 0 of register becomes bit 1, bit 1 becomes bit 2 and so on, when multiplied with this matrix)
			for(byte n=0, row=2; n<width-1; n++, row<<=1) mat1[n]=row;
			mat1[width-1]=polynomial; // and the polynomial (will be multiplied(XORed) into the register if top-bit is 1, when multiplied with this matrix)

			// Square to create 2-bit-operation matrix
			MatrixSquare(mat2, mat1, width);

			// Square again to create 4-bit-operation matrix (the first MatrixSquare inside the loop below, creates the 8-bit-operation matrix needed for
			// our lengthOfCRC2 zero-byte-operations)
			MatrixSquare(mat1, mat2, width);

			int length=lengthOfCRC2;

			// 'Add' lengthOfCRC2 zero-bytes to crc1
			do
			{
				// Square to create the next power-of-two-operation matrix
				MatrixSquare(mat2, mat1, width);

				// 'Add' zero-bytes
				if((length&1)!=0) crc=MatrixMult(mat2, crc);
				length>>=1;

				// Already done?
				if(length==0) break;

				// Square to create the next power-of-two-operation matrix
				MatrixSquare(mat1, mat2, width);

				// 'Add' zero-bytes
				if((length&1)!=0) crc=MatrixMult(mat1, crc);
				length>>=1;
			} while(length!=0);

			if(refOut) crc=BitOrder.Reflect(crc, width); // If CRC was reflected against SIMPLE => undo

			// Return combined crc
			crc^=crc2; // CRC2 still contains xorOut
			return crc;
		}

		/// <summary>
		/// Combines the CRCs of two blocks to the CRC of the blocks concatenated.
		/// </summary>
		/// <param name="crc1">The CRC of the first block.</param>
		/// <param name="crc2">The CRC of the second block.</param>
		/// <param name="lengthOfCRC2">The length of the second block in bytes.</param>
		/// <param name="polynomial">The polynomial used to create the CRCs. Unreflected and filled in the least significant bits.</param>
		/// <param name="init">The initial value of the register. Unreflected and filled in the least significant bits.</param>
		/// <param name="refOut">Set <b>true</b>, if register is to be reflected before XORing with <paramref name="xorOut"/> and output.</param>
		/// <param name="xorOut">Value to be XORed with the reflected or unreflected register depending on <paramref name="refOut"/> before output. Filled in the least significant bits.</param>
		/// <param name="width">The width of the polynomial in bits. Must be greater than 0 and less than 17. Default is 16.</param>
		/// <returns>The combined CRC value.</returns>
		public static ushort Combine(ushort crc1, ushort crc2, int lengthOfCRC2, ushort polynomial, ushort init=0, bool refOut=false, ushort xorOut=0, int width=16)
		{
			if(lengthOfCRC2<0) throw new ArgumentOutOfRangeException("lengthOfCRC2", "Must not be less than zero (0).");
			if(width<=0||width>16) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 17.");

			// Nothing to combine
			if(lengthOfCRC2==0) return crc1;

			// Gets value (2^width)-1.
			uint mask=(1u<<width)-1u;

			crc1&=(ushort)mask;
			crc2&=(ushort)mask;
			polynomial&=(ushort)mask;
			init&=(ushort)mask;
			xorOut&=(ushort)mask;

			crc1^=xorOut; // Remove xorOut from CRC1

			ushort crc=refOut?BitOrder.Reflect(crc1, width):crc1; // If CRC is reflected against SIMPLE and thus against the polynomial

			crc^=init; // Remove CRC2's register initialization value by adding to CRC

			ushort[] mat1=new ushort[width], mat2=new ushort[width]; // Create matrices (for inplace squaring operation)

			// Fill matrix with 1-bit-shift-operation (bit 0 of register becomes bit 1, bit 1 becomes bit 2 and so on, when multiplied with this matrix)
			for(ushort n=0, row=2; n<width-1; n++, row<<=1) mat1[n]=row;
			mat1[width-1]=polynomial; // and the polynomial (will be multiplied(XORed) into the register if top-bit is 1, when multiplied with this matrix)

			// Square to create 2-bit-operation matrix
			MatrixSquare(mat2, mat1, width);

			// Square again to create 4-bit-operation matrix (the first MatrixSquare inside the loop below, creates the 8-bit-operation matrix needed for
			// our lengthOfCRC2 zero-byte-operations)
			MatrixSquare(mat1, mat2, width);

			int length=lengthOfCRC2;

			// 'Add' lengthOfCRC2 zero-bytes to crc1
			do
			{
				// Square to create the next power-of-two-operation matrix
				MatrixSquare(mat2, mat1, width);

				// 'Add' zero-bytes
				if((length&1)!=0) crc=MatrixMult(mat2, crc);
				length>>=1;

				// Already done?
				if(length==0) break;

				// Square to create the next power-of-two-operation matrix
				MatrixSquare(mat1, mat2, width);

				// 'Add' zero-bytes
				if((length&1)!=0) crc=MatrixMult(mat1, crc);
				length>>=1;
			} while(length!=0);

			if(refOut) crc=BitOrder.Reflect(crc, width); // If CRC was reflected against SIMPLE => undo

			// Return combined crc
			crc^=crc2; // CRC2 still contains xorOut
			return crc;
		}

		/// <summary>
		/// Combines the CRCs of two blocks to the CRC of the blocks concatenated.
		/// </summary>
		/// <param name="crc1">The CRC of the first block.</param>
		/// <param name="crc2">The CRC of the second block.</param>
		/// <param name="lengthOfCRC2">The length of the second block in bytes.</param>
		/// <param name="polynomial">The polynomial used to create the CRCs. Unreflected and filled in the least significant bits.</param>
		/// <param name="init">The initial value of the register. Unreflected and filled in the least significant bits.</param>
		/// <param name="refOut">Set <b>true</b>, if register is to be reflected before XORing with <paramref name="xorOut"/> and output.</param>
		/// <param name="xorOut">Value to be XORed with the reflected or unreflected register depending on <paramref name="refOut"/> before output. Filled in the least significant bits.</param>
		/// <param name="width">The width of the polynomial in bits. Must be greater than 0 and less than 33. Default is 32.</param>
		/// <returns>The combined CRC value.</returns>
		public static uint Combine(uint crc1, uint crc2, int lengthOfCRC2, uint polynomial, uint init=0, bool refOut=false, uint xorOut=0, int width=32)
		{
			if(lengthOfCRC2<0) throw new ArgumentOutOfRangeException("lengthOfCRC2", "Must not be less than zero (0).");
			if(width<=0||width>32) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 33.");

			// Nothing to combine
			if(lengthOfCRC2==0) return crc1;

			// Gets value (2^width)-1.
			uint mask=(((1u<<(width-1))-1u)<<1)|1u;

			crc1&=mask;
			crc2&=mask;
			polynomial&=mask;
			init&=mask;
			xorOut&=mask;

			crc1^=xorOut; // Remove xorOut from CRC1

			uint crc=refOut?BitOrder.Reflect(crc1, width):crc1; // If CRC is reflected against SIMPLE and thus against the polynomial

			crc^=init; // Remove CRC2's register initialization value by adding to CRC

			uint[] mat1=new uint[width], mat2=new uint[width]; // Create matrices (for inplace squaring operation)

			// Fill matrix with 1-bit-shift-operation (bit 0 of register becomes bit 1, bit 1 becomes bit 2 and so on, when multiplied with this matrix)
			for(uint n=0, row=2; n<width-1; n++, row<<=1) mat1[n]=row;
			mat1[width-1]=polynomial; // and the polynomial (will be multiplied(XORed) into the register if top-bit is 1, when multiplied with this matrix)

			// Square to create 2-bit-operation matrix
			MatrixSquare(mat2, mat1, width);

			// Square again to create 4-bit-operation matrix (the first MatrixSquare inside the loop below, creates the 8-bit-operation matrix needed for
			// our lengthOfCRC2 zero-byte-operations)
			MatrixSquare(mat1, mat2, width);

			int length=lengthOfCRC2;

			// 'Add' lengthOfCRC2 zero-bytes to crc1
			do
			{
				// Square to create the next power-of-two-operation matrix
				MatrixSquare(mat2, mat1, width);

				// 'Add' zero-bytes
				if((length&1)!=0) crc=MatrixMult(mat2, crc);
				length>>=1;

				// Already done?
				if(length==0) break;

				// Square to create the next power-of-two-operation matrix
				MatrixSquare(mat1, mat2, width);

				// 'Add' zero-bytes
				if((length&1)!=0) crc=MatrixMult(mat1, crc);
				length>>=1;
			} while(length!=0);

			if(refOut) crc=BitOrder.Reflect(crc, width); // If CRC was reflected against SIMPLE => undo

			// Return combined crc
			crc^=crc2; // CRC2 still contains xorOut
			return crc;
		}

		/// <summary>
		/// Combines the CRCs of two blocks to the CRC of the blocks concatenated.
		/// </summary>
		/// <param name="crc1">The CRC of the first block.</param>
		/// <param name="crc2">The CRC of the second block.</param>
		/// <param name="lengthOfCRC2">The length of the second block in bytes.</param>
		/// <param name="polynomial">The polynomial used to create the CRCs. Unreflected and filled in the least significant bits.</param>
		/// <param name="init">The initial value of the register. Unreflected and filled in the least significant bits.</param>
		/// <param name="refOut">Set <b>true</b>, if register is to be reflected before XORing with <paramref name="xorOut"/> and output.</param>
		/// <param name="xorOut">Value to be XORed with the reflected or unreflected register depending on <paramref name="refOut"/> before output. Filled in the least significant bits.</param>
		/// <param name="width">The width of the polynomial in bits. Must be greater than 0 and less than 65. Default is 64.</param>
		/// <returns>The combined CRC value.</returns>
		public static ulong Combine(ulong crc1, ulong crc2, int lengthOfCRC2, ulong polynomial, ulong init=0, bool refOut=false, ulong xorOut=0, int width=64)
		{
			if(lengthOfCRC2<0) throw new ArgumentOutOfRangeException("lengthOfCRC2", "Must not be less than zero (0).");
			if(width<=0||width>64) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 65.");

			// Nothing to combine
			if(lengthOfCRC2==0) return crc1;

			// Gets value (2^width)-1.
			ulong mask=(((1ul<<(width-1))-1ul)<<1)|1ul;

			crc1&=mask;
			crc2&=mask;
			polynomial&=mask;
			init&=mask;
			xorOut&=mask;

			crc1^=xorOut; // Remove xorOut from CRC1

			ulong crc=refOut?BitOrder.Reflect(crc1, width):crc1; // If CRC is reflected against SIMPLE and thus against the polynomial

			crc^=init; // Remove CRC2's register initialization value by adding to CRC

			ulong[] mat1=new ulong[width], mat2=new ulong[width]; // Create matrices (for inplace squaring operation)

			// Fill matrix with 1-bit-shift-operation (bit 0 of register becomes bit 1, bit 1 becomes bit 2 and so on, when multiplied with this matrix)
			for(ulong n=0, row=2; (int)n<width-1; n++, row<<=1) mat1[n]=row;
			mat1[width-1]=polynomial; // and the polynomial (will be multiplied(XORed) into the register if top-bit is 1, when multiplied with this matrix)

			// Square to create 2-bit-operation matrix
			MatrixSquare(mat2, mat1, width);

			// Square again to create 4-bit-operation matrix (the first MatrixSquare inside the loop below, creates the 8-bit-operation matrix needed for
			// our lengthOfCRC2 zero-byte-operations)
			MatrixSquare(mat1, mat2, width);

			int length=lengthOfCRC2;

			// 'Add' lengthOfCRC2 zero-bytes to crc1
			do
			{
				// Square to create the next power-of-two-operation matrix
				MatrixSquare(mat2, mat1, width);

				// 'Add' zero-bytes
				if((length&1)!=0) crc=MatrixMult(mat2, crc);
				length>>=1;

				// Already done?
				if(length==0) break;

				// Square to create the next power-of-two-operation matrix
				MatrixSquare(mat1, mat2, width);

				// 'Add' zero-bytes
				if((length&1)!=0) crc=MatrixMult(mat1, crc);
				length>>=1;
			} while(length!=0);

			if(refOut) crc=BitOrder.Reflect(crc, width); // If CRC was reflected against SIMPLE => undo

			// Return combined crc
			crc^=crc2; // CRC2 still contains xorOut
			return crc;
		}

		/// <summary>
		/// Combines the CRCs of two blocks to the CRC of the blocks concatenated.
		/// </summary>
		/// <param name="crc1">The CRC of the first block.</param>
		/// <param name="crc2">The CRC of the second block.</param>
		/// <param name="lengthOfCRC2">The length of the second block in bytes.</param>
		/// <param name="polynomial">The polynomial used to create the CRCs. Unreflected and filled in the least significant bits.</param>
		/// <returns>The combined CRC value.</returns>
		public static UInt128 Combine(UInt128 crc1, UInt128 crc2, int lengthOfCRC2, UInt128 polynomial)
		{
			return Combine(crc1, crc2, lengthOfCRC2, polynomial, UInt128.Zero, false, UInt128.Zero, 128);
		}

		/// <summary>
		/// Combines the CRCs of two blocks to the CRC of the blocks concatenated.
		/// </summary>
		/// <param name="crc1">The CRC of the first block.</param>
		/// <param name="crc2">The CRC of the second block.</param>
		/// <param name="lengthOfCRC2">The length of the second block in bytes.</param>
		/// <param name="polynomial">The polynomial used to create the CRCs. Unreflected and filled in the least significant bits.</param>
		/// <param name="init">The initial value of the register. Unreflected and filled in the least significant bits.</param>
		/// <param name="refOut">Set <b>true</b>, if register is to be reflected before output.</param>
		/// <returns>The combined CRC value.</returns>
		public static UInt128 Combine(UInt128 crc1, UInt128 crc2, int lengthOfCRC2, UInt128 polynomial, UInt128 init, bool refOut=false)
		{
			return Combine(crc1, crc2, lengthOfCRC2, polynomial, init, refOut, UInt128.Zero, 128);
		}

		/// <summary>
		/// Combines the CRCs of two blocks to the CRC of the blocks concatenated.
		/// </summary>
		/// <param name="crc1">The CRC of the first block.</param>
		/// <param name="crc2">The CRC of the second block.</param>
		/// <param name="lengthOfCRC2">The length of the second block in bytes.</param>
		/// <param name="polynomial">The polynomial used to create the CRCs. Unreflected and filled in the least significant bits.</param>
		/// <param name="init">The initial value of the register. Unreflected and filled in the least significant bits.</param>
		/// <param name="refOut">Set <b>true</b>, if register is to be reflected before XORing with <paramref name="xorOut"/> and output.</param>
		/// <param name="xorOut">Value to be XORed with the reflected or unreflected register depending on <paramref name="refOut"/> before output. Filled in the least significant bits.</param>
		/// <param name="width">The width of the polynomial in bits. Must be greater than 0 and less than 129. Default is 128.</param>
		/// <returns>The combined CRC value.</returns>
		public static UInt128 Combine(UInt128 crc1, UInt128 crc2, int lengthOfCRC2, UInt128 polynomial, UInt128 init, bool refOut, UInt128 xorOut, int width=128)
		{
			if(lengthOfCRC2<0) throw new ArgumentOutOfRangeException("lengthOfCRC2", "Must not be less than zero (0).");
			if(width<=0||width>128) throw new ArgumentOutOfRangeException("width", "Must be greater than 0 and less than 129.");

			// Nothing to combine
			if(lengthOfCRC2==0) return crc1;

			// Gets value (2^width)-1.
			UInt128 mask=UInt128.MaxValue>>(128-width);

			crc1&=mask;
			crc2&=mask;
			polynomial&=mask;
			init&=mask;
			xorOut&=mask;

			crc1^=xorOut; // Remove xorOut from CRC1

			UInt128 crc=refOut?BitOrder.Reflect(crc1, width):crc1; // If CRC is reflected against SIMPLE and thus against the polynomial

			crc^=init; // Remove CRC2's register initialization value by adding to CRC

			UInt128[] mat1=new UInt128[width], mat2=new UInt128[width]; // Create matrices (for inplace squaring operation)

			// Fill matrix with 1-bit-shift-operation (bit 0 of register becomes bit 1, bit 1 becomes bit 2 and so on, when multiplied with this matrix)
			UInt128 row=2;
			for(int n=0; n<width-1; n++, row<<=1) mat1[n]=row;
			mat1[width-1]=polynomial; // and the polynomial (will be multiplied(XORed) into the register if top-bit is 1, when multiplied with this matrix)

			// Square to create 2-bit-operation matrix
			MatrixSquare(mat2, mat1, width);

			// Square again to create 4-bit-operation matrix (the first MatrixSquare inside the loop below, creates the 8-bit-operation matrix needed for
			// our lengthOfCRC2 zero-byte-operations)
			MatrixSquare(mat1, mat2, width);

			int length=lengthOfCRC2;

			// 'Add' lengthOfCRC2 zero-bytes to crc1
			do
			{
				// Square to create the next power-of-two-operation matrix
				MatrixSquare(mat2, mat1, width);

				// 'Add' zero-bytes
				if((length&1)!=0) crc=MatrixMult(mat2, crc);
				length>>=1;

				// Already done?
				if(length==0) break;

				// Square to create the next power-of-two-operation matrix
				MatrixSquare(mat1, mat2, width);

				// 'Add' zero-bytes
				if((length&1)!=0) crc=MatrixMult(mat1, crc);
				length>>=1;
			} while(length!=0);

			if(refOut) crc=BitOrder.Reflect(crc, width); // If CRC was reflected against SIMPLE => undo

			// Return combined crc
			crc^=crc2; // CRC2 still contains xorOut
			return crc;
		}
		#endregion
	}
}
