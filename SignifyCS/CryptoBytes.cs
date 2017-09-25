/*
 * Taken from Chaos.NaCl by Christian Winnerlein (CodesInChaos).
 * Public Domain.
 */

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace SignifyCS {
	public static class CryptoBytes {
		/// <summary>
		/// Constant-time comparison of two arrays.
		/// </summary>
		/// <remarks>
		/// The runtime of this method does not depend on the contents of the arrays. Using constant time
		/// prevents timing attacks that allow an attacker to learn if the arrays have a common prefix.
		///
		/// It is important to use such a constant time comparison when verifying MACs.
		/// </remarks>
		/// <param name="x">A byte array</param>
		/// <param name="y">A byte array</param>
		/// <returns>True if arrays are equal; false otherwise</returns>
		public static bool ConstantTimeEquals(byte[] x, byte[] y) {
			//Contract.Requires<ArgumentNullException>(x != null && y != null);
			Trace.Assert(x != null && y != null);

			if (x.Length != y.Length) {
				return false;
			}
			return internalConstantTimeEquals(x, 0, y, 0, x.Length) != 0;
		}

		private static uint internalConstantTimeEquals(byte[] x, int xOffset, byte[] y, int yOffset, int length) {
			int differentbits = 0;
			for (int i = 0; i < length; i++) {
				differentbits |= x[xOffset + i] ^ y[yOffset + i];
			}
			return (1 & (unchecked((uint)differentbits - 1) >> 8));
		}

		/// <summary>
		/// Overwrite the contents of an array, erasing the previous content.
		/// </summary>
		/// <param name="data">A byte array</param>
		public static void Wipe(byte[] data) {
			//Contract.Requires<ArgumentNullException>(data != null);
			Trace.Assert(data != null);
			internalWipe(data, 0, data.Length);
		}

		// Secure wiping is hard...
		// * The GC can move around and copy memory. Perhaps this can be avoided by using
		//	 unmanaged memory or by fixing the position of the array in memory.
		// * Swap files and error dumps can contain secret information. It seems possible
		//	 to lock memory in RAM, no idea about error dumps...
		// * The compiler could optimize out the wiping if it knows that data won't be read
		//	 back. I hope suppressing inlining is enough, but perhaps `RtlSecureZeroMemory`
		//	 is needed.
		[MethodImpl(MethodImplOptions.NoInlining)]
		internal static void internalWipe(byte[] data, int offset, int count) {
			Array.Clear(data, offset, count);
		}
	}
}
