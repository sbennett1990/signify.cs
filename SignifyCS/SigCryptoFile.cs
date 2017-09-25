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
	/// <summary>
	/// Functions for cheacking and parsing signature files.
	/// </summary>
	public class SigCryptoFile {
		private const uint SIG_DATA_LEN = BaseCryptoFile.crypto_sign_ed25519_BYTES;

		/// <summary>
		/// Parse a signature file.
		/// </summary>
		/// <param name="file">The stream of the signature to parse</param>
		/// <returns>A Signature struct containing the decoded data from the file</returns>
		public static Signature ParseSigFile(FileStream file) {
			string comment;
			return ParseSigFile(file, out comment);
		}

		/// <summary>
		/// Parse a signature file, and give the comment.
		/// </summary>
		/// <param name="file">The stream of the signature to parse</param>
		/// <param name="comment">The untrusted comment in the file</param>
		/// <returns>A Signature struct containing the decoded data from the file</returns>
		public static Signature ParseSigFile(FileStream file, out string comment) {
			if (file == null) {
				throw new ArgumentNullException(nameof(file));
			}
			if (!file.CanRead) {
				throw new Exception("can't read sig");
			}

			Signature sig;
			comment = string.Empty;
			using (StreamReader reader = new StreamReader(file, Encoding.UTF8)) {
				/* check comment line */
				if (reader.Peek() == -1) {
					throw new Exception("empty sig file");
				}

				string comment_line = reader.ReadLine();
				comment = BaseCryptoFile.CheckComment(comment_line);

				/* check signiture line */
				if (reader.Peek() == -1) {
					throw new Exception("missing sig data");
				}

				string sig_line = reader.ReadLine();
				sig = CheckSig(sig_line);
			}

			return sig;
		}

		/// <summary>
		/// Check and parse the signature data in the sig file.
		/// </summary>
		/// <param name="sig_line">The signature line (full line of text from the file) to check</param>
		/// <returns>A Signature struct containing the decoded data from the line</returns>
		public static Signature CheckSig(string sig_line) {
			if (string.IsNullOrEmpty(sig_line)) {
				throw new ArgumentNullException(nameof(sig_line));
			}
			if (sig_line.Length <= 1) {
				throw new Exception("invalid base64 encoding in signature file");
			}

			Signature sig = new Signature();
			byte[] data = Convert.FromBase64String(sig_line);

			if (data.Length != (BaseCryptoFile.PK_ALGORITHM.Length + BaseCryptoFile.KEY_NUM_LEN + SIG_DATA_LEN)) {
				throw new Exception("invalid base64 encoding in signature file");
			}

			string algorithm = Encoding.UTF8.GetString(data, 0, BaseCryptoFile.PK_ALGORITHM.Length);
			if (!string.Equals(algorithm, BaseCryptoFile.PK_ALGORITHM)) {
				throw new Exception("unsupported signature");
			}
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
