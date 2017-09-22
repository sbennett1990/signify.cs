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
using System.IO;
using System.Text;

namespace SignifyCS {
	public class PubKeyCryptoFile {
		private const uint PUB_KEY_DATA_LEN = BaseCryptoFile.crypto_sign_ed25519_PUBLICKEYBYTES;

		public static int ParsePubKeyFile(FileStream file) {
			PubKey pub_key;
			return ParsePubKeyFile(file, out pub_key);
		}

		public static int ParsePubKeyFile(FileStream file, out PubKey pub_key) {
			string comment;
			return ParsePubKeyFile(file, out pub_key, out comment);
		}

		public static int ParsePubKeyFile(FileStream file, out PubKey pub_key, out string comment) {
			pub_key = default(PubKey);
			comment = string.Empty;

			if (file == null || !file.CanRead)
				return -1;

			using (StreamReader reader = new StreamReader(file, Encoding.UTF8)) {
				/* check comment line */
				if (reader.Peek() == -1)
					return -1;

				string comment_line = reader.ReadLine();
				comment = BaseCryptoFile.CheckComment(comment_line);

				/* check public key line */
				if (reader.Peek() == -1)
					return -1;

				string pub_key_line = reader.ReadLine();
				pub_key = CheckPubKey(pub_key_line);
			}

			return 1;
		}

		/// <summary>
		///
		/// </summary>
		/// <param name="pub_key_line"></param>
		/// <param name="pub_key"></param>
		/// <returns></returns>
		public static PubKey CheckPubKey(string pub_key_line) {
			if (string.IsNullOrEmpty(pub_key_line))
				throw new ArgumentNullException(nameof(pub_key_line));

			if (pub_key_line.Length <= 1)
				throw new Exception("invalid base64 encoding in pub key");

			PubKey pub_key = new PubKey();
			byte[] data = Convert.FromBase64String(pub_key_line);

			if (data.Length != (BaseCryptoFile.PK_ALGORITHM.Length + BaseCryptoFile.KEY_NUM_LEN + PUB_KEY_DATA_LEN))
				throw new Exception("invalid base64 encoding in pub key");

			string algorithm = Encoding.UTF8.GetString(data, 0, BaseCryptoFile.PK_ALGORITHM.Length);
			if (!string.Equals(algorithm, BaseCryptoFile.PK_ALGORITHM))
				throw new Exception("unsupported pub key");
			pub_key.Algorithm = algorithm;

			byte[] key_num = new byte[BaseCryptoFile.KEY_NUM_LEN];
			Array.ConstrainedCopy(data, BaseCryptoFile.PK_ALGORITHM.Length, key_num, 0,
				(int)BaseCryptoFile.KEY_NUM_LEN);
			pub_key.KeyNum = key_num;

			byte[] sig_data = new byte[PUB_KEY_DATA_LEN];
			Array.ConstrainedCopy(data, (BaseCryptoFile.PK_ALGORITHM.Length + (int)BaseCryptoFile.KEY_NUM_LEN),
				sig_data, 0, (int)PUB_KEY_DATA_LEN);
			pub_key.PubKeyData = sig_data;

			return pub_key;
		}
	}
}
