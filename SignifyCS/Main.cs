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
using libcmdline;

namespace SignifyCS {
	public enum FileType {
		Signiture,
		PublicKey
	};

	public class Signify {
		public static void Main(string[] args) {
			PubKey pub_key = default(PubKey);
			Signature sig = default(Signature);
			byte[] message = new byte[0];

			try {
				CommandLineArgs cmd_args = new CommandLineArgs();
				cmd_args.PrefixRegexPatternList.Add("-{1}");

				cmd_args.registerSpecificSwitchMatchHandler("p", (sender, e) => {
					pub_key = readPubFile(e.Value);
				});
				cmd_args.registerSpecificSwitchMatchHandler("x", (sender, e) => {
					sig = readSigFile(e.Value);
				});
				cmd_args.registerSpecificSwitchMatchHandler("m", (sender, e) => {
					message = File.ReadAllBytes(e.Value);
				});

				cmd_args.processCommandLineArgs(args);
				if (cmd_args.ArgCount < 3) {
					Console.WriteLine("usage: signify -p pubkey -x sigfile -m message");
					throw new Exception();
				}

				bool success = Verify.VerifyMessage(pub_key, sig, message);

				if (success) {
					Console.WriteLine("\nSignature Verified");
				} else {
					Console.WriteLine("\nsignature verification failed");
				}
			} catch (Exception e) {
				Console.WriteLine(e.Message);
#if DEBUG
				Console.WriteLine(e.StackTrace);
#endif
			}

			Console.WriteLine();
		}

		private static PubKey readPubFile(string file_name) {
			PubKey pub_key;
			string comment;
			using (FileStream pub_key_file = readFile(file_name)) {
				pub_key = PubKeyCryptoFile.ParsePubKeyFile(pub_key_file, out comment);
			}
#if DEBUG
			Console.WriteLine($"Untrusted Comment: {comment}");
			Console.Write("Base64 Key Num: ");
			Array.ForEach(pub_key.KeyNum, x => Console.Write($"{x:x2}"));
			Console.Write("\nBase64 PubKey Data: ");
			Array.ForEach(pub_key.PubKeyData, x => Console.Write($"{x:x2}"));
			Console.WriteLine();
#endif
			return pub_key;
		}

		private static Signature readSigFile(string file_name) {
			Signature sig;
			string comment;
			using (FileStream sig_file = readFile(file_name)) {
				sig = SigCryptoFile.ParseSigFile(sig_file, out comment);
			}
#if DEBUG
			Console.WriteLine($"Untrusted Comment: {comment}");
			Console.Write("Base64 Key Num: ");
			Array.ForEach(sig.KeyNum, x => Console.Write($"{x:x2}"));
			Console.Write("\nBase64 Sig Data: ");
			Array.ForEach(sig.SigData, x => Console.Write($"{x:x2}"));
			Console.WriteLine();
#endif
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
