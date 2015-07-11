using System;

namespace Free.Crypto.CheckDigits
{
	/// <summary>
	/// This class contains an implementation of the decimal check digit algorithm
	/// developed by Jacobus Verhoeff (http://en.wikipedia.org/wiki/Verhoeff_algorithm).
	/// It can detect all single-digit errors, and all transposition errors involving
	/// two adjacent digits.
	/// </summary>
	/// <threadsafety static="true" instance="true"/>
	public static class Verhoeff
	{
		#region Tables
		// The multiplication table.
		static int[,] mult=
			{
				{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
				{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
				{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
				{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
				{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
				{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
				{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
				{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
				{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
				{9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
			};

		// The permutation table.
		static int[,] perm=
			{
				{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
				{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
				{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
				{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
				{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
				{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
				{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
				{7, 0, 4, 6, 9, 1, 3, 2, 5, 8}
			};

		// The inverse table.
		static int[] inv= { 0, 4, 3, 2, 1, 5, 6, 7, 8, 9 };
		#endregion

		/// <summary>
		/// Calculates the check-digit for a given string of digits.
		/// </summary>
		/// <param name="digits">A string of digits. All non-digits will be ignored.</param>
		/// <returns>The check-digit as <b>char</b>.</returns>
		public static char GetCheckDigit(string digits)
		{
			if(digits==null) throw new ArgumentNullException("digits");

			int ret=0;
			for(int c=digits.Length-1, i=0; c>=0; c--)
			{
				char ch=digits[c];
				if(ch<'0'||ch>'9') continue;
				ret=mult[ret, perm[(i+1)%8, ch-'0']];
				i++;
			}

			return (char)('0'+inv[ret]);
		}

		/// <summary>
		/// Calculates the check-digit for a given array of digits.
		/// </summary>
		/// <param name="digits">An array of digits.</param>
		/// <returns>The check-digit as <b>int</b>.</returns>
		public static int GetCheckDigit(int[] digits)
		{
			if(digits==null) throw new ArgumentNullException("digits");

			int ret=0;
			for(int c=digits.Length-1, i=0; c>=0; c--)
			{
				int ch=digits[c];
				if(ch<0||ch>9) continue;
				ret=mult[ret, perm[(i+1)%8, ch]];
				i++;
			}

			return inv[ret];
		}

		/// <summary>
		/// Checks a string of digits (including the check-digit) for errors.
		/// </summary>
		/// <param name="digits">A string of digits including the check-digit (must be the last digit). All non-digits will be ignored.</param>
		/// <returns><b>true</b> if the string checks out, otherwise <b>false</b> is returned.</returns>
		public static bool CheckDigits(string digits)
		{
			if(digits==null) throw new ArgumentNullException("digits");

			int ret=0;
			for(int c=digits.Length-1, i=0; c>=0; c--)
			{
				char ch=digits[c];
				if(ch<'0'||ch>'9') continue;
				ret=mult[ret, perm[i%8, ch-'0']];
				i++;
			}

			return ret==0;
		}

		/// <summary>
		/// Checks an array of digits (including the check-digit) for errors.
		/// </summary>
		/// <param name="digits">An array of digits including the check-digit (must be the last digit).</param>
		/// <returns><b>true</b> if the array checks out, otherwise <b>false</b> is returned.</returns>
		public static bool CheckDigits(int[] digits)
		{
			if(digits==null) throw new ArgumentNullException("digits");

			int ret=0;
			for(int c=digits.Length-1, i=0; c>=0; c--)
			{
				int ch=digits[c];
				if(ch<0||ch>9) continue;
				ret=mult[ret, perm[i%8, ch]];
				i++;
			}

			return ret==0;
		}
	}
}
