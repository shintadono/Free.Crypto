using System;

namespace Free.Crypto.CheckDigits
{
	/// <summary>
	/// This class contains an implementation of a check digit algorithm for
	/// detecting single-digit errors and adjancent transposition errors, by
	/// H. Michael Damm (2004).
	/// </summary>
	/// <threadsafety static="true" instance="true"/>
	public static class Damm
	{
		#region Tables
		/// <summary>
		/// The (weak) totally anti-symmetric quasigroup used for this implementation.
		/// Optimized of detecting phonetical errors.
		/// </summary>
		public static readonly int[,] TAQ10a=
			{
				{0, 3, 1, 7, 5, 9, 8, 6, 4, 2},
				{7, 0, 9, 2, 1, 5, 4, 8, 6, 3},
				{4, 2, 0, 6, 8, 7, 1, 3, 5, 9},
				{1, 7, 5, 0, 9, 8, 3, 4, 2, 6},
				{6, 1, 2, 3, 0, 4, 5, 9, 7, 8},
				{3, 6, 7, 4, 2, 0, 9, 5, 8, 1},
				{5, 8, 6, 9, 7, 2, 0, 1, 3, 4},
				{8, 9, 4, 5, 3, 6, 2, 0, 1, 7},
				{9, 4, 3, 8, 6, 1, 7, 2, 0, 5},
				{2, 5, 8, 1, 4, 3, 6, 7, 9, 0}
			};

		/// <summary>
		/// Another (weak) totally anti-symmetric quasigroup.
		/// </summary>
		public static readonly int[,] TAQ10b=
			{
				{0, 2, 3, 4, 5, 6, 7, 8, 9, 1},
				{2, 0, 4, 1, 7, 9, 5, 3, 8, 6},
				{3, 7, 0, 5, 2, 8, 1, 6, 4, 9},
				{4, 1, 8, 0, 6, 3, 9, 2, 7, 5},
				{5, 6, 2, 9, 0, 7, 4, 1, 3, 8},
				{6, 9, 7, 3, 1, 0, 8, 5, 2, 4},
				{7, 5, 1, 8, 4, 2, 0, 9, 6, 3},
				{8, 4, 6, 2, 9, 5, 3, 0, 1, 7},
				{9, 8, 5, 7, 3, 1, 6, 4, 0, 2},
				{1, 3, 9, 6, 8, 4, 2, 7, 5, 0}
			};
		#endregion

		/// <summary>
		/// Calculates the check-digit for a given string of digits.
		/// </summary>
		/// <param name="digits">A string of digits. All non-digits will be ignored.</param>
		/// <param name="TAQ">The (weak) totally anti-symmetric quasigroup (TAQ) to use. Must be an 2D <b>int</b> array with both dimensions 10, or <b>null</b> for the default TAQ.</param>
		/// <returns>The check-digit as <b>char</b>.</returns>
		public static char GetCheckDigit(string digits, int[,] TAQ=null)
		{
			if(digits==null) throw new ArgumentNullException("digits");

			if(TAQ==null) TAQ=TAQ10a;
			else if(TAQ.GetLength(0)!=10||TAQ.GetLength(1)!=10) throw new ArgumentException("Must be an 2D int array with both dimensions 10, or null.", "TAQ");
			int ret=0;

			foreach(var ch in digits)
			{
				if(ch<'0'||ch>'9') continue;
				ret=TAQ[ret, ch-'0'];
			}

			return (char)('0'+ret);
		}

		/// <summary>
		/// Calculates the check-digit for a given array of digits.
		/// </summary>
		/// <param name="digits">An array of digits.</param>
		/// <param name="TAQ">The (weak) totally anti-symmetric quasigroup (TAQ) to use. Must be an 2D <b>int</b> array with both dimensions 10, or <b>null</b> for the default TAQ.</param>
		/// <returns>The check-digit as <b>int</b>.</returns>
		public static int GetCheckDigit(int[] digits, int[,] TAQ=null)
		{
			if(digits==null) throw new ArgumentNullException("digits");

			if(TAQ==null) TAQ=TAQ10a;
			else if(TAQ.GetLength(0)!=10||TAQ.GetLength(1)!=10) throw new ArgumentException("Must be an 2D int array with both dimensions 10, or null.", "TAQ");
			int ret=0;

			foreach(var ch in digits)
			{
				if(ch<0||ch>9) throw new ArgumentOutOfRangeException("digits", "Must be an array of single digit numbers");
				ret=TAQ[ret, ch];
			}

			return ret;
		}

		/// <summary>
		/// Checks a string of digits (including the check-digit) for errors.
		/// </summary>
		/// <param name="digits">A string of digits including the check-digit (must be the last digit). All non-digits will be ignored.</param>
		/// <param name="TAQ">The (weak) totally anti-symmetric quasigroup (TAQ) to use. Must be an 2D <b>int</b> array with both dimensions 10, or <b>null</b> for the default TAQ.</param>
		/// <returns><b>true</b> if the string checks out, otherwise <b>false</b> is returned.</returns>
		public static bool CheckDigits(string digits, int[,] TAQ=null)
		{
			if(digits==null) throw new ArgumentNullException("digits");

			if(TAQ==null) TAQ=TAQ10a;
			else if(TAQ.GetLength(0)!=10||TAQ.GetLength(1)!=10) throw new ArgumentException("Must be an 2D int array with both dimensions 10, or null.", "TAQ");

			return GetCheckDigit(digits, TAQ)=='0';
		}

		/// <summary>
		/// Checks an array of digits (including the check-digit) for errors.
		/// </summary>
		/// <param name="digits">An array of digits including the check-digit (must be the last digit).</param>
		/// <param name="TAQ">The (weak) totally anti-symmetric quasigroup (TAQ) to use. Must be an 2D <b>int</b> array with both dimensions 10, or <b>null</b> for the default TAQ.</param>
		/// <returns><b>true</b> if the array checks out, otherwise <b>false</b> is returned.</returns>
		public static bool CheckDigits(int[] digits, int[,] TAQ=null)
		{
			if(digits==null) throw new ArgumentNullException("digits");

			if(TAQ==null) TAQ=TAQ10a;
			else if(TAQ.GetLength(0)!=10||TAQ.GetLength(1)!=10) throw new ArgumentException("Must be an 2D int array with both dimensions 10, or null.", "TAQ");

			return GetCheckDigit(digits, TAQ)==0;
		}
	}
}
