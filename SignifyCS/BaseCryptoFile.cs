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
using System.Text;

namespace SignifyCS {
	public struct PubKey {
		public string Algorithm;
		public byte[] KeyNum;
		public byte[] PubKeyData;
	}

	public struct Signature {
		public string Algorithm;
		public byte[] KeyNum;
		public byte[] SigData;
	}

	public class BaseCryptoFile {
		public const uint crypto_sign_ed25519_BYTES = 64;
		public const uint crypto_sign_ed25519_PUBLICKEYBYTES = 32;
		public const uint crypto_sign_ed25519_SECRETKEYBYTES = 64; /* not used for verify */

		public const string COMMENT_HEADER = "untrusted comment: ";
		public const uint COMMENT_MAX_LEN = 1024;
		public const string PK_ALGORITHM = "Ed";
		public const uint KEY_NUM_LEN = 8;

		/// <summary>
		/// Check the comment line of a signiture or public key file.
		/// </summary>
		/// <param name="comment_line">The comment string (full line of text from the file) to check</param>
		/// <returns>The untrusted comment string from the file, minus the header text</returns>
		public static string CheckComment(string comment_line) {
			if (string.IsNullOrEmpty(comment_line))
				throw new ArgumentNullException(nameof(comment_line));

			if (comment_line.Length < COMMENT_HEADER.Length)
				throw new Exception($"invalid comment line; must start with '{COMMENT_HEADER}'");

			int index = comment_line.IndexOf(COMMENT_HEADER);
			if (index != 0)
				throw new Exception($"invalid comment line; must start with '{COMMENT_HEADER}'");

			if (comment_line.Length > (COMMENT_HEADER.Length + COMMENT_MAX_LEN))
				throw new Exception("comment too long");

			return comment_line.Remove(index, COMMENT_HEADER.Length);
		}

		/// <summary>
		///
		/// </summary>
		/// <param name="sig_line"></param>
		/// <param name="sig"></param>
		/// <returns></returns>
		public static int CheckKeyData(string sig_line, FileType file_type) {
			//sig = new Sig();

			if (sig_line.Length <= 1)
				return 1;

			byte[] data = Convert.FromBase64String(sig_line);

			if (data.Length != (PK_ALGORITHM.Length + KEY_NUM_LEN))
				return 1;

			string algorithm = Encoding.UTF8.GetString(data, 0, PK_ALGORITHM.Length);
			if (!string.Equals(algorithm, PK_ALGORITHM))
				return 2;
			//sig.Algorithm = algorithm;

			byte[] key_num = new byte[KEY_NUM_LEN];
			Array.ConstrainedCopy(data, PK_ALGORITHM.Length, key_num, 0,
				(int)KEY_NUM_LEN);
			//sig.KeyNum = key_num;

			return 0;
		}
	}
}
