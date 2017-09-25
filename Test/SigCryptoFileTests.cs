using NUnit.Framework;

namespace SignifyCS.Test {
	public class SigCryptoFileTests {
		[Test]
		public void CheckSigAlg_GoodSignature_ReturnsExpected() {
			string test_sig = getTestSignature();

			Signature res_sig = SigCryptoFile.CheckSig(test_sig);
			string res_alg = res_sig.Algorithm;

			Assert.That(res_alg, Is.EqualTo(CryptoAlg));
		}

		[Test]
		public void CheckSigKeyNum_GoodSignature_IsCorrectLength() {
			string test_sig = getTestSignature();

			Signature res_sig = SigCryptoFile.CheckSig(test_sig);
			byte[] res_key_num = res_sig.KeyNum;

			Assert.That(res_key_num.Length, Is.EqualTo(KeyNumLen));
		}

		[Test]
		public void CheckSigData_GoodSignature_IsCorrectLength() {
			string test_sig = getTestSignature();

			Signature res_sig = SigCryptoFile.CheckSig(test_sig);
			byte[] res_data = res_sig.SigData;

			Assert.That(res_data.Length, Is.EqualTo(SigDataLen));
		}

		private static string getTestSignature() {
			return "RWQpoQCvhBXwzIAflNibYx/9w5bDo5NqJ69RQDjQfLeh7uQvysloRT2t6P4D3vYK0Cv/0jTpBG/lU7N/4z+RtGYGMFjE+7jirgQ=";
		}

		private static string CryptoAlg {
			get {
				return BaseCryptoFile.PK_ALGORITHM;
			}
		}

		private static uint KeyNumLen {
			get {
				return BaseCryptoFile.KEY_NUM_LEN;
			}
		}

		private static uint SigDataLen {
			get {
				return BaseCryptoFile.crypto_sign_ed25519_BYTES;
			}
		}
	}
}
