# PGP Encryption/Decryption using C`#`

This project was forked from an article written by Maruthi Pallamalli. Please read the credits section to see article's the URL.

## Features
I've implemented the following changes:
* Refactored some PGP properties to make the encryption/decryption classes easier to configure (ASCII-armoring, symmetric key algo, compression algo, etc)
* Implemented signature verification and literal data integrity protection checks
* Implemented ASCII-armor as an option during the encryption process
* Implemented public and secret key ring key search by ID during the encryption process
* Cleaned up some of the code to make it a little more readable

## Installation

Make sure to download the BouncyCastle.Crypto library via NuGet. Gpg4win is also required with the GNUPGHOME environment variable set to the location of where the PGP key rings can be found. Download Gpg4win from here (https://www.gpg4win.org/).

##System Requirements

* .NET 4.5
* Visual Studio 2012
* Gpg4win

## Credits

#####Special thanks go to Maruthi Pallamalli, who put together a sample article and project from which this project was forked.
######The article can be found here: https://code.msdn.microsoft.com/vstudio/Pretty-Good-Privacy-using-4f473c67/

## License

This project is licensed under the MIT license - see the [LICENSE.MD](./LICENSE) file for details