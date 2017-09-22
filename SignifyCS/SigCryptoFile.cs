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
	public class SigCryptoFile {
		private const uint SIG_DATA_LEN = BaseCryptoFile.crypto_sign_ed25519_BYTES;

		public static int ParseSigFile(FileStream file) {
			Signature sig;
			return ParseSigFile(file, out sig);
		}

		public static int ParseSigFile(FileStream file, out Signature sig) {
			string comment;
			return ParseSigFile(file, out sig, out comment);
		}

		public static int ParseSigFile(FileStream file, out Signature sig, out string comment) {
			sig = default(Signature);
			comment = string.Empty;

			if (file == null || !file.CanRead)
				return -1;

			using (StreamReader reader = new StreamReader(file, Encoding.UTF8)) {
				/* check comment line */
				if (reader.Peek() == -1)
					return -1;

				string comment_line = reader.ReadLine();
				comment = BaseCryptoFile.CheckComment(comment_line);

				/* check signiture line */
				if (reader.Peek() == -1)
					return -1;

				string sig_line = reader.ReadLine();
				sig = CheckSig(sig_line);
			}

			return 1;
		}

		/// <summary>
		///
		/// </summary>
		/// <param name="sig_line"></param>
		/// <param name="sig"></param>
		/// <returns></returns>
		public static Signature CheckSig(string sig_line) {
			if (string.IsNullOrEmpty(sig_line))
				throw new ArgumentNullException(nameof(sig_line));

			if (sig_line.Length <= 1)
				throw new Exception("invalid base64 encoding in signature file");

			Signature sig = new Signature();
			byte[] data = Convert.FromBase64String(sig_line);

			if (data.Length != (BaseCryptoFile.PK_ALGORITHM.Length + BaseCryptoFile.KEY_NUM_LEN + SIG_DATA_LEN))
				throw new Exception("invalid base64 encoding in signature file");

			string algorithm = Encoding.UTF8.GetString(data, 0, BaseCryptoFile.PK_ALGORITHM.Length);
			if (!string.Equals(algorithm, BaseCryptoFile.PK_ALGORITHM))
				throw new Exception("unsupported signature");
			sig.Algorithm = algorithm;

			byte[] key_num = new byte[BaseCryptoFile.KEY_NUM_LEN];
			Array.ConstrainedCopy(data, BaseCryptoFile.PK_ALGORITHM.Length, key_num, 0,
				(int)BaseCryptoFile.KEY_NUM_LEN);
			sig.KeyNum = key_num;

			byte[] sig_data = new byte[SIG_DATA_LEN];
			Array.ConstrainedCopy(data, (BaseCryptoFile.PK_ALGORITHM.Length + (int)BaseCryptoFile.KEY_NUM_LEN),
				sig_data, 0, (int)SIG_DATA_LEN);
			sig.SigData = sig_data;

			return sig;
		}
	}
}
