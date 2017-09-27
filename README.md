# SignifyCS - A signify(1)-like tool written in C#

**SignifyCS** is capable of verifying files (messages) signed with signify(1).
At this time, it can't verify files signed with the embedded (`-e`) flag, nor
gzip files signed with the `-z` flag. It does not implement any of key generation
or message signing functionalities.

This is a command line tool (i.e. Console application) - there is no GUI. As
such, for best results run within PowerShell. It also works in Cygwin and
Command Prompt environments. "Double-clicking" the `.exe` will appear to do
nothing, since the program requires command line arguments, and fails without
them.

## Usage

`verify.exe -p pubkey -x sigfile -m messagefile`

Alternate:

`verify.exe /p pubkey /x sigfile /m messagefile`

**Note**: the **SignifyCS** binary is called `verify.exe` since it can only
verify. All flags are required, but **SignifyCS** can accept flags prefixed with
`-` or `/`.

## Dependencies

#### Run

* .NET Framework 4.5.2 or later

#### Build

* Visual Studio 2015 or later
* NuGet package manager
* [libsodium-net](https://github.com/adamcaudill/libsodium-net) v0.10.0

#### Test

* NUnit 3
* NUnit ConsoleRunner

## License

ISC licensed

## Resources

#### Man page

* http://man.openbsd.org/signify

#### Design of signify(1)

* https://www.tedunangst.com/flak/post/signify
* https://www.openbsd.org/papers/bsdcan-signify.html
