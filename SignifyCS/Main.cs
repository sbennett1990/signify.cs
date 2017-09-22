﻿/*
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

namespace SignifyCS {
	public enum FileType {
		Signiture,
		PublicKey
	};

	public class Signify {
		public static void Main(string[] args) {
			try {
				PubKey pub_key = checkPubFile();
				Console.WriteLine();
				Signature sig = checkSigFile();
				Console.WriteLine();
				byte[] message = getMessage();
				bool success = Verify.VerifyMessage(pub_key, sig, message);

				if (success) {
					Console.WriteLine("Signature Verified");
				} else {
					Console.WriteLine("signature verification failed");
				}
			} catch (Exception e) {
				Console.WriteLine(e.Message);
#if DEBUG
				Console.WriteLine(e.StackTrace);
#endif
			}

			Console.WriteLine();
		}

		private static PubKey checkPubFile() {
			Console.Write("Public Key: ");
			string file_name = Console.ReadLine().Trim();

			PubKey pub_key;
			string comment;
			using (FileStream pub_key_file = readFile(file_name)) {
				if (PubKeyCryptoFile.ParsePubKeyFile(pub_key_file, out pub_key, out comment) < 0
					|| pub_key.KeyNum == null
					|| pub_key.PubKeyData == null) {
					throw new Exception("Error reading public key file");
				}
			}

			Console.WriteLine($"Untrusted Comment: {comment}");
			Console.Write("Base64 Key Num: ");
			Array.ForEach(pub_key.KeyNum, x => Console.Write($"{x:x2}"));
			Console.Write("\nBase64 PubKey Data: ");
			Array.ForEach(pub_key.PubKeyData, x => Console.Write($"{x:x2}"));
			Console.WriteLine();

			return pub_key;
		}

		private static Signature checkSigFile() {
			Console.Write("Signature File: ");
			string file_name = Console.ReadLine().Trim();

			Signature sig;
			string comment;
			using (FileStream sig_file = readFile(file_name)) {
				if (SigCryptoFile.ParseSigFile(sig_file, out sig, out comment) < 0
					|| sig.KeyNum == null
					|| sig.SigData == null) {
					throw new Exception("Error reading signature file");
				}
			}

			Console.WriteLine($"Untrusted Comment: {comment}");
			Console.Write("Base64 Key Num: ");
			Array.ForEach(sig.KeyNum, x => Console.Write($"{x:x2}"));
			Console.Write("\nBase64 Sig Data: ");
			Array.ForEach(sig.SigData, x => Console.Write($"{x:x2}"));
			Console.WriteLine();

			return sig;
		}

		private static byte[] getMessage() {
			Console.Write("Message: ");
			string file_name = Console.ReadLine().Trim();
			return File.ReadAllBytes(file_name);
		}

		private static FileStream readFile(string file_name) {
			if (!File.Exists(file_name)) {
				throw new Exception($"File not found: {file_name}");
			}
			return new FileStream(file_name, FileMode.Open, FileAccess.Read, FileShare.Read);
		}
	}
}
