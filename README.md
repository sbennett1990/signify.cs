# SignifyCS - A signify(1)-like tool written in C#

SignifyCS is capable of verifying files (messages) signed with signify(1). At
this time, it can't verify files signed with the embedded (-e) flag, nor gzip
files signed with the -z flag. It does not implement any of key generation or
message signing functionalities.

## Usage

`verify.exe -p pubkey -x sigfile -m messagefile`

**Note**: the SignifyCS binary is called `verify.exe` since it can only verify.
All flags are required, but SignifyCS can accept flags prefixed with `-` or `/`.

## Dependencies

* .NET Framework 4.5.2 or later
* Visual Studio 2015 or later

## License

ISC licensed

## Resources

#### Design of signify(1)

* https://www.tedunangst.com/flak/post/signify
* https://www.openbsd.org/papers/bsdcan-signify.html

#### Man page

* http://man.openbsd.org/signify
