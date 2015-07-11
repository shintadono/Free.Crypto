using System;
using System.Collections.Generic;
using Free.Core;

namespace Free.Crypto.CRCChecksums
{
	/// <summary>
	/// Interface for CRC algorithm implementations.
	/// </summary>
	[CLSCompliant(false)]
	public interface ICRC
	{
		/// <summary>
		/// Gets the CRC value (not the register) for the message bytes processed so far as a 32-bit value.
		/// </summary>
		/// <returns>The CRC value as <b>uint</b>.</returns>
		uint GetCRC();

		/// <summary>
		/// Gets the CRC value (not the register) for the message bytes processed so far as a 64-bit value.
		/// </summary>
		/// <returns>The CRC value as <b>ulong</b>.</returns>
		ulong GetCRCAsULong();

		/// <summary>
		/// Gets the CRC value (not the register) for the message bytes processed so far as a 128-bit value.
		/// </summary>
		/// <returns>The CRC value as <see cref="UInt128"/>.</returns>
		UInt128 GetCRCAsUInt128();

		/// <summary>
		/// Processes a single message byte.
		/// </summary>
		/// <param name="value">The value to add to the CRC.</param>
		/// <returns>A reference to <b>this</b> instance.</returns>
		ICRC Add(byte value);

		/// <summary>
		/// Processes message bytes.
		/// </summary>
		/// <param name="data">The data to add to the CRC.</param>
		/// <param name="offset">Location in the array where to start in bytes.</param>
		/// <param name="count">Number of bytes.</param>
		/// <returns>A reference to <b>this</b> instance.</returns>
		ICRC Add(byte[] data, int offset=0, int count=0);

		/// <summary>
		/// Processes message bytes.
		/// </summary>
		/// <param name="data">The data to add to the CRC.</param>
		/// <param name="offset">Location in the array where to start in bytes.</param>
		/// <param name="count">Number of bytes.</param>
		/// <returns>A reference to <b>this</b> instance.</returns>
		ICRC Add(List<byte> data, int offset=0, int count=0);

		/// <summary>
		/// Processes message bytes.
		/// </summary>
		/// <param name="data">The data to add to the CRC.</param>
		/// <returns>A reference to <b>this</b> instance.</returns>
		ICRC Add(IEnumerable<byte> data);

		/// <summary>
		/// Resets the instance to the 'no message bytes processed yet'-state.
		/// </summary>
		void Reset();
	}

	/// <summary>
	/// Typed interface CRC algorithm implementations.
	/// </summary>
	/// <typeparam name="T">Type in which to calculate the CRC. Width of the type defines the maximum width of the CRC and the polynomial.</typeparam>
	[CLSCompliant(false)]
	public interface ICRC<T> : ICRC where T : struct
	{
		/// <summary>
		/// Gets/sets the register (not necessarely the CRC value). Can be utilized to cache the value; useful in situations where a chain of blocks need to be checked, and reseting would need to reprocess the whole chain from the start.
		/// </summary>
		T Register { get; set; }

		/// <summary>
		/// Gets the CRC value (not the register) for the message bytes processed so far.
		/// </summary>
		T Value { get; }
	}
}
