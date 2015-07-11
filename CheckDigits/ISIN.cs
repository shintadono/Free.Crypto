using System.Collections.Generic;
using System.Text;

namespace Free.Crypto.CheckDigits
{
	/// <summary>
	/// This class contains an implementation of the check digit algorithm
	/// needed to generate check digits for International Securities
	/// Identification Number (ISIN) or to validate them.
	/// (http://en.wikipedia.org/wiki/International_Securities_Identification_Number)
	/// </summary>
	/// <threadsafety static="true" instance="true"/>
	public static class ISIN
	{
		#region Tables
		static char[] luhnAlphabet= { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
		static readonly Dictionary<char, int> luhnLookUpTable=Luhn.GenerateLookUpTable(luhnAlphabet);
		#endregion

		static string ToDigits(string ISIN)
		{
			StringBuilder ret=new StringBuilder();
			for(int i=0; i<ISIN.Length; i++)
			{
				char c=ISIN[i];
				if(c>='0'&&c<='9')
				{
					ret.Append(c);
					continue;
				}
				else if(c<'A'||c>'Z') continue;

				ret.Append((c-'A')+10);
			}

			return ret.ToString();
		}

		/// <summary>
		/// Calculates the check-digit for a given partial ISIN.
		/// </summary>
		/// <param name="partialISIN">The partial ISIN (missing the last digit). All illegal characters will be ignored.</param>
		/// <returns>The check-digit as <b>char</b>.</returns>
		public static char GetCheckDigit(string partialISIN)
		{
			return Luhn.GetCheckDigit(ToDigits(partialISIN), luhnAlphabet, luhnLookUpTable);
		}

		/// <summary>
		/// Checks a ISIN including the check-digit for errors.
		/// </summary>
		/// <param name="ISIN">The ISIN including the check-digit (must be the last digit). All illegal characters will be ignored.</param>
		/// <returns><b>true</b> if the string checks out, otherwise <b>false</b> is returned.</returns>
		public static bool CheckDigits(string ISIN)
		{
			return Luhn.CheckDigits(ToDigits(ISIN), luhnAlphabet, luhnLookUpTable);
		}
	}
}
