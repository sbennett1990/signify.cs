using System;
using NUnit.Framework;

namespace SignifyCS.Test {
	public class CryptoBytesTests {
		[TestCase(new byte[] { 1, 2, 3, 4, 5 }, new byte[] { 1, 2, 3, 4, 5 })]
		[TestCase(new byte[0], new byte[0])]
		public void ConstantTimeEquals_SameArrays_ReturnsTrue(byte[] x, byte[] y) {
			bool res = CryptoBytes.ConstantTimeEquals(x, y);

			Assert.That(res, Is.EqualTo(true));
		}

		[Test]
		public void ConstantTimeEquals_DifferentArrays_ReturnsFalse() {
			byte[] x = new byte[] { 1, 2, 3, 4, 5 };
			byte[] y = new byte[] { 0, 2, 3, 4, 5 };

			bool res = CryptoBytes.ConstantTimeEquals(x, y);

			Assert.That(res, Is.EqualTo(false));
		}

		[TestCase(new byte[] { 1, 2, 3 }, null)]
		[TestCase(null, new byte[] { 1, 2, 3 })]
		[TestCase(null, null)]
		public void ConstantTimeEquals_NullArray_Throws(byte[] x, byte[] y) {
			var e = Assert.Catch<ArgumentNullException>(() => CryptoBytes.ConstantTimeEquals(x, y));

			Assert.That(e, Is.TypeOf<ArgumentNullException>());
		}
	}
}
