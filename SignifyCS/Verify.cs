/*
 * Copyright (c) 2017 Scott Bennett <scottb@fastmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

using System;

using Sodium;

namespace SignifyCS {
	public class Verify {
		public static bool VerifyMessage(PubKey pub_key, Signature sig, byte[] message) {
			CheckAlgorithms(pub_key, sig);
			CheckKeys(pub_key, sig);
			return VerifyCrypto(sig, message, pub_key);
		}

		public static void CheckAlgorithms(PubKey pub_key, Signature sig) {
			if (!pub_key.Algorithm.Equals(BaseCryptoFile.PK_ALGORITHM)) {
				throw new Exception($"unsupported public key; unexpected algorithm '{pub_key.Algorithm}'");
			}
			if (!sig.Algorithm.Equals(BaseCryptoFile.PK_ALGORITHM)) {
				throw new Exception($"unsupported signature; unexpected algorithm '{sig.Algorithm}'");
			}
		}

		public static void CheckKeys(PubKey pub_key, Signature sig) {
			if (!CryptoBytes.ConstantTimeEquals(pub_key.KeyNum, sig.KeyNum)) {
				throw new Exception("verification failed: checked against wrong key");
			}
		}

		public static bool VerifyCrypto(Signature sig, byte[] message, PubKey pub_key) {
			return PublicKeyAuth.VerifyDetached(sig.SigData, message, pub_key.PubKeyData);
		}
	}
}
