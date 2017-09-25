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

		public static PubKey ParsePubKeyFile(FileStream file) {
			string comment;
			return ParsePubKeyFile(file, out comment);
		}

		public static PubKey ParsePubKeyFile(FileStream file, out string comment) {
			if (file == null) {
				throw new ArgumentNullException(nameof(file));
			}
			if (!file.CanRead) {
				throw new Exception("can't read pub key");
			}

			PubKey pub_key;
			comment = string.Empty;
			using (StreamReader reader = new StreamReader(file, Encoding.UTF8)) {
				/* check comment line */
				if (reader.Peek() == -1) {
					throw new Exception("empty pub key file");
				}

				string comment_line = reader.ReadLine();
				comment = BaseCryptoFile.CheckComment(comment_line);

				/* check public key line */
				if (reader.Peek() == -1) {
					throw new Exception("missing public key data");
				}

				string pub_key_line = reader.ReadLine();
				pub_key = CheckPubKey(pub_key_line);
			}

			return pub_key;
		}

		/// <summary>
		/// Check and parse the public key data in the pub key file.
		/// </summary>
		/// <param name="pub_key_line">The public key line (full line of text from the file) to check</param>
		/// <returns>A PubKey struct containing the decoded data from the file</returns>
		public static PubKey CheckPubKey(string pub_key_line) {
			if (string.IsNullOrEmpty(pub_key_line)) {
				throw new ArgumentNullException(nameof(pub_key_line));
			}
			if (pub_key_line.Length <= 1) {
				throw new Exception("invalid base64 encoding in pub key");
			}

			PubKey pub_key = new PubKey();
			byte[] data = Convert.FromBase64String(pub_key_line);

			if (data.Length != (BaseCryptoFile.PK_ALGORITHM.Length + BaseCryptoFile.KEY_NUM_LEN + PUB_KEY_DATA_LEN)) {
				throw new Exception("invalid base64 encoding in pub key");
			}

			string algorithm = Encoding.UTF8.GetString(data, 0, BaseCryptoFile.PK_ALGORITHM.Length);
			if (!string.Equals(algorithm, BaseCryptoFile.PK_ALGORITHM)) {
				throw new Exception("unsupported pub key");
			}
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
