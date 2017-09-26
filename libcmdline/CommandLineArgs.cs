﻿/*
 * Copyright (c) 2015 Scott Bennett
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *	 list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *	 this list of conditions and the following disclaimer in the documentation
 *	 and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace libcmdline {
	/// <summary>
	/// Command line arguments processor.
	/// </summary>
	/// <example>
	/// <code>
	/// static class Program {
	///		static void Main(string[] args) {
	///			CommandLineArgs cmdArgs = new CommandLineArgs();
	///			cmdArgs.IgnoreCase = true;
	///			cmdArgs.PrefixRegexPatternList.Add("/{1}");
	///			cmdArgs.PrefixRegexPatternList.Add("-{1,2}");
	///			cmdArgs.RegisterSpecificSwitchMatchHandler("foo", (sender, e) => {
	///				// handle the /foo -foo or --foo switch logic here.
	///				// this method will only be called for the foo switch.
	///				// get the value given with the switch with e.Value
	///			});
	///			cmdArgs.ProcessCommandLineArgs(args);
	///		}
	/// }
	/// </code>
	/// </example>
	/// <remarks>
	/// See http://sanity-free.org/144/csharp_command_line_args_processing_class.html for more information.
	/// </remarks>
	public class CommandLineArgs {
		public const string InvalidSwitchIdentifier = "INVALID";

		private IList<string> prefixRegexPatternList;
		private IList<string> invalidArgs;
		private IDictionary<string, string> arguments;
		private IDictionary<string, EventHandler<CommandLineArgsMatchEventArgs>> handlers;

		private bool ignoreCase;

		public event EventHandler<CommandLineArgsMatchEventArgs> SwitchMatch;

		/// <summary>
		/// Create a new command line argument processor.
		/// </summary>
		public CommandLineArgs() {
			prefixRegexPatternList = new List<string>();
			invalidArgs = new List<string>();
			arguments = new Dictionary<string, string>();
			handlers = new Dictionary<string, EventHandler<CommandLineArgsMatchEventArgs>>();
			ignoreCase = false;
		}

		/// <summary>
		/// The number of arguments given on the command line.
		/// </summary>
		public int ArgCount {
			get {
				return arguments.Keys.Count;
			}
		}

		/// <summary>
		/// Ignore the case of the command line switches. Default is false.
		/// </summary>
		public bool IgnoreCase {
			get {
				return this.ignoreCase;
			}
			set {
				this.ignoreCase = value;
			}
		}

		/// <summary>
		/// List of all the invalid arguments given.
		/// </summary>
		public IList<string> InvalidArgs {
			get {
				return invalidArgs;
			}
		}

		/// <summary>
		///
		/// </summary>
		public IList<string> PrefixRegexPatternList {
			get {
				return prefixRegexPatternList;
			}
		}

		/// <summary>
		///
		/// </summary>
		/// <param name="switchName"></param>
		/// <param name="handler"></param>
		public void RegisterSpecificSwitchMatchHandler(
			string switchName,
			EventHandler<CommandLineArgsMatchEventArgs> handler
		) {
			if (handlers.ContainsKey(switchName)) {
				handlers[switchName] = handler;
			}
			else {
				handlers.Add(switchName, handler);
			}
		}

		/// <summary>
		/// Take the command line arguments and attempt to execute the handlers.
		/// </summary>
		/// <param name="args">The arguments array</param>
		public void ProcessCommandLineArgs(string[] args) {
			for (int i = 0; i < args.Length; i++) {
				string cmdLineValue = ignoreCase ? args[i].ToLower() : args[i];

				foreach (string prefix in prefixRegexPatternList) {
					string switchPattern = string.Format("^{0}", prefix);

					if (Regex.IsMatch(cmdLineValue, switchPattern, RegexOptions.Compiled)) {
						cmdLineValue = Regex.Replace(cmdLineValue, switchPattern, "", RegexOptions.Compiled);

						if (cmdLineValue.Contains("=")) {
							/* switch style: "<prefix>Param=Value" */
							int idx = cmdLineValue.IndexOf('=');
							string n = cmdLineValue.Substring(0, idx);
							string v = cmdLineValue.Substring(idx + 1, cmdLineValue.Length - n.Length - 1);
							onSwitchMatch(new CommandLineArgsMatchEventArgs(n, v));
							arguments.Add(n, v);
						}
						else {
							/* switch style: "<prefix>Param Value" */
							if ((i + 1) < args.Length) {
								string @switch = cmdLineValue;
								string val = args[i + 1];
								onSwitchMatch(new CommandLineArgsMatchEventArgs(@switch, val));
								arguments.Add(cmdLineValue, val);

								i++;
							}
							else {
								onSwitchMatch(new CommandLineArgsMatchEventArgs(cmdLineValue, null));
								arguments.Add(cmdLineValue, null);
							}
						}
					}
					else {
						/* invalid argument */
						onSwitchMatch(new CommandLineArgsMatchEventArgs(InvalidSwitchIdentifier, cmdLineValue, false));
						invalidArgs.Add(cmdLineValue);
					}
				}
			}
		}

		/// <summary>
		/// Invoke the registered handler for the provided switch and value
		/// (in the form of a CommandLineArgsMatchEventArgs object).
		/// </summary>
		/// <param name="e"></param>
		protected virtual void onSwitchMatch(CommandLineArgsMatchEventArgs e) {
			if (handlers.ContainsKey(e.Switch) && handlers[e.Switch] != null) {
				handlers[e.Switch](this, e);
			}
			else if (SwitchMatch != null) {
				SwitchMatch(this, e);
			}
		}
	}
}
