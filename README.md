# lsa-to-pwnedpasswords
LSASS Notification Package that verifies if proposed password is in TroyHunts haveibeenpwned database

WARNING:  I am not an expert at github, this code is provided so you can accelerate your own efforts to improve your own Windows Computers and Domain Controllers from accepting pwned passwords... Use the code at your own risk.

The code has a dependency on Cryptopp (someday i will learn to use Microsofts built in SHA1 libraries)
If you are compiling in Visual Studio you will need to:

Download Crypto++ from the following link (https://www.cryptopp.com/#download)

Build Crypto++ as a library in x64 mode – the following link is a good resource on compiling it for use in Visual Studio

Include the Crypto++ header directories through Project –> "your project name: Properties –> Configuration Properties –> VC++ Directories. Edit the Include Directories and add the include directory

Then, edit the Library Directories and add the Debug directory from the x64\Output directory.

Add cryptlib.lib to your Additional Dependencies list under Project –> "your project name" –> Configuration Properties –> Linker–>Input–> Additional Dependencies

As noted in the source code, this project was heavily influenced by the work of @JacksonVD and I am humbly thankful for his base code from his blog: https://jacksonvd.com/checking-for-breached-passwords-ad-using-k-anonymity/ and the code i adapted from: https://github.com/JacksonVD/PwnedPasswordsDLL-API

The difference in my code from Jacksons:
1) Heavily commented
2) Secure Deletion of Strings
3) JSON Logging
4) Log Only Mode

However if you would like to compile this code without creating your own solution, my cpp file is a direct replacement of https://github.com/JacksonVD/PwnedPasswordsDLL-API 's dllmain.cpp

(someday I will work with him to just push my proposals to his project, but at this time, i have some friends that would like to review the code, so I needed a way to get it out "as is")
