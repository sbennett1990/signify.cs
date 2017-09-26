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
	public class Signify {
		public const string USAGE = "verify -p pubkey -x sigfile -m message";

		public static void Main(string[] args) {
			PubKey pub_key = default(PubKey);
			Signature sig = default(Signature);
			byte[] message = new byte[0];

			try {
				CommandLineArgs cmd_args = new CommandLineArgs();

				cmd_args.RegisterSpecificSwitchMatchHandler("p", (sender, e) => {
					using (FileStream pub_key_file = readFile(e.Value)) {
						pub_key = PubKeyCryptoFile.ParsePubKeyFile(pub_key_file);
					}
				});
				cmd_args.RegisterSpecificSwitchMatchHandler("x", (sender, e) => {
					using (FileStream sig_file = readFile(e.Value)) {
						sig = SigCryptoFile.ParseSigFile(sig_file);
					}
				});
				cmd_args.RegisterSpecificSwitchMatchHandler("m", (sender, e) => {
					message = File.ReadAllBytes(e.Value);
				});
				/* invalid arguments shouldn't be allowed to proceed */
				cmd_args.RegisterSpecificSwitchMatchHandler(CommandLineArgs.InvalidSwitchIdentifier, (sender, e) => {
					usage();
					Environment.Exit(1);
				});

				cmd_args.ProcessCommandLineArgs(args);
				if (cmd_args.ArgCount < 3) {
					usage();
					Environment.Exit(1);
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
		}

		private static void usage() {
			Console.WriteLine("\nusage: " + USAGE);
		}

		private static FileStream readFile(string file_name) {
			if (!File.Exists(file_name)) {
				throw new Exception($"File not found: {file_name}");
			}
			return new FileStream(file_name, FileMode.Open, FileAccess.Read, FileShare.Read);
		}
	}
}
