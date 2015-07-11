using System;
using System.Collections.Generic;

namespace Free.Crypto.CheckDigits
{
	/// <summary>
	/// This class contains an implementation of the generalized extension of
	/// check digit/letter algorithm developed by the IBM scientist Hans Peter
	/// Luhn (http://en.wikipedia.org/wiki/Luhn_mod_N_algorithm).
	/// Designed to protect against accidental errors, not malicious attacks,
	/// most credit cards and many government identification numbers use the
	/// algorithm as a simple method of distinguishing valid numbers from
	/// mistyped or otherwise incorrect numbers.
	/// </summary>
	/// <threadsafety static="true" instance="true"/>
	public static class Luhn
	{
		/// <summary>
		/// Generates a lookup-table for an array of characters.
		/// </summary>
		/// <param name="alphabet">An array of <b>char</b>s. Each
		/// character must appear only once, at the (array)index of its
		/// code-point.</param>
		/// <returns>A <see cref="Dictionary{T1,T2}"/> for (fast) getting the
		/// index of a character in <paramref name="alphabet"/>.</returns>
		public static Dictionary<char, int> GenerateLookUpTable(char[] alphabet)
		{
			if(alphabet==null||alphabet.Length==0) throw new ArgumentNullException("alphabet", "Must not be null, or empty");

			Dictionary<char, int> ret=new Dictionary<char, int>();
			for(int i=0; i<alphabet.Length; i++)
			{
				char c=alphabet[i];
				if(ret.ContainsKey(c)) throw new ArgumentException("Each character must appear only once.", "alphabet");
				ret.Add(c, i);
			}

			return ret;
		}

		/// <summary>
		/// Calculates the check-digit for a given string of digits/letters.
		/// </summary>
		/// <param name="digits">A string of digits/letters. All digits/letters not in the <paramref name="alphabet"/> will be ignored.</param>
		/// <param name="alphabet">An array of <b>char</b>s that must contain
		/// all charaters allowed in the message/ID and check digit/letter.
		/// Each character must appear only once, at the (array)index of its
		/// code-point. The array must not be shorter or longer that the
		/// number of allowed digits/letters.</param>
		/// <returns>The check-digit/letter as <b>char</b>.</returns>
		public static char GetCheckDigit(string digits, params char[] alphabet)
		{
			return GetCheckDigit(digits, alphabet, GenerateLookUpTable(alphabet));
		}

		/// <summary>
		/// Calculates the check-digit for a given string of digits/letters.
		/// </summary>
		/// <param name="digits">A string of digits/letters including the
		/// check-digit/letter (must be the last digit/letter). All
		/// digits/letters not in the <paramref name="alphabet"/> will be
		/// ignored.</param>
		/// <param name="alphabet">An array of <b>char</b>s that must contain
		/// all charaters allowed in the message/ID and check digit/letter.
		/// Each character must appear only once, at the (array)index of its
		/// code-point. The array must not be shorter or longer that the
		/// number of allowed digits/letters.</param>
		/// <param name="lookUpTable">A lookup-table for <paramref name="alphabet"/>.
		/// (Can be generated with <see cref="GenerateLookUpTable"/>.)</param>
		/// <returns>The check-digit/letter as <b>char</b>.</returns>
		public static char GetCheckDigit(string digits, char[] alphabet, Dictionary<char, int> lookUpTable)
		{
			int sum=0, factor=1, alphabetLength=alphabet.Length;

			// Starting from the right and working leftwards is easier since
			// the initial 'factor' will always be '2' (or shift by 1).
			for(int i=digits.Length-1; i>=0; i--)
			{
				char c=digits[i];
				if(!lookUpTable.ContainsKey(c)) continue;
				int codePoint=lookUpTable[c];
				int addend=codePoint<<factor;

				// Alternate the 'factor' that each 'codePoint' is multiplied by (shift by 1 = multiple of 2).
				factor^=1;

				// Sum the digits of the 'addend' as expressed in base 'alphabetLength'.
				addend=(addend/alphabetLength)+(addend%alphabetLength);
				sum+=addend;
			}

			// Calculate the number that must be added to the 'sum'
			// to make it divisible by 'alphabetLength'.
			int remainder=sum%alphabetLength;
			int checkCodePoint=(alphabetLength-remainder)%alphabetLength;

			return alphabet[checkCodePoint];
		}

		/// <summary>
		/// Checks a string of digits (including the check-digit) for errors.
		/// </summary>
		/// <param name="digits">A string of digits/letters including the
		/// check-digit/letter (must be the last digit/letter). All
		/// digits/letters not in the <paramref name="alphabet"/> will be
		/// ignored.</param>
		/// <param name="alphabet">An array of <b>char</b>s that must contain
		/// all charaters allowed in the message/ID and check digit/letter.
		/// Each character must appear only once, at the (array)index of its
		/// code-point. The array must not be shorter or longer that the
		/// number of allowed digits/letters.</param>
		/// <returns><b>true</b> if the string checks out, otherwise <b>false</b> is returned.</returns>
		public static bool CheckDigits(string digits, params char[] alphabet)
		{
			return CheckDigits(digits, alphabet, GenerateLookUpTable(alphabet));
		}

		/// <summary>
		/// Checks a string of digits (including the check-digit) for errors.
		/// </summary>
		/// <param name="digits">A string of digits/letters including the check-digit/letter.
		/// All digits/letters not in the <paramref name="alphabet"/> will be ignored.</param>
		/// <param name="alphabet">An array of <b>char</b>s that must contain
		/// all charaters allowed in the message/ID and check digit/letter.
		/// Each character must appear only once, at the (array)index of its
		/// code-point. The array must not be shorter or longer that the
		/// number of allowed digits/letters.</param>
		/// <param name="lookUpTable">A lookup-table for <paramref name="alphabet"/>.
		/// (Can be generated with <see cref="GenerateLookUpTable"/>.)</param>
		/// <returns><b>true</b> if the string checks out, otherwise <b>false</b> is returned.</returns>
		public static bool CheckDigits(string digits, char[] alphabet, Dictionary<char, int> lookUpTable)
		{
			int sum=0, factor=0, alphabetLength=alphabet.Length;

			// Starting from the right, work leftwards.
			// The initial 'factor' will always be '1' (or shift by 0),
			// since the last character is the check character.
			for(int i=digits.Length-1; i>=0; i--)
			{
				char c=digits[i];
				if(!lookUpTable.ContainsKey(c)) continue;
				int codePoint=lookUpTable[c];
				int addend=codePoint<<factor;

				// Alternate the 'factor' that each 'codePoint' is multiplied by (shift by 1 = multiple of 2).
				factor^=1;

				// Sum the digits of the 'addend' as expressed in base 'alphabetLength'.
				addend=(addend/alphabetLength)+(addend%alphabetLength);
				sum+=addend;
			}

			return sum%alphabetLength==0;
		}
	}
}
