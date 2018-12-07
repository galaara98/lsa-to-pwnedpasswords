/*
* This code was adapted from JacksonVD
*     https://jacksonvd.com/checking-for-breached-passwords-ad-using-k-anonymity/
*
* PwnPasswordDLL is a Password Filter DLL for Microsoft Local Security Authority (LSA)
* both Local and Active Directory rely on LSA to decide of a password meets complexity requirements
* DLL must be in System32, and registered in 
*	HKEY_LOCAL_MACHINE
*		SYSTEM
*			CurrentControlSet
*				Control
*					Lsa
*						Notification Packages (no path, no extension)
* DLL must accept four parameters in a function called PasswordFilter (PUNICODE_STRING accountName,PUNICODE_STRING fullName,PUNICODE_STRING password,BOOLEAN operation)
* DLL must return true (allow password to proceed to other filters) or false (forbid password)
*
* May 2018
*     initial compile from JacksonVD code
* May 2018
*     removed dependency on cURL
* Jun 2018
*     added logging, error handling, secure cleanup
* Jul 2018
*     updated comments, prepared for production
* Aug 2018
*     code reviews, added max length of AccountName and Password from LSA, any longer than 256 and the funciton will return false.
* Sept 2018
*     added minimum password length (anything less than 1 just returns true [allow])
*
* SIMPLIFIED explanation of includes (AS I UNDESTOOD THEM):
*
* stdafx tell C compiler to use recompiled headers when possible
* windows is used to find other .h files string, fstream, ctime, and iomanip
* string is basic strings
* atlstr is needed for certain string functions related to CString
* stdlib is for all std:: objects
* SubAuth is for LSA
* Winhttp is for internet connection (i use for reading http streams)
* sha,filters, and hex come from cryptopp (used to turn string into SHA1 hash)
* fstream to talk to file system
* ctime to process time into strings
* iomanip to talk to file system (io streams)
* tchar (another string helper)
*
* pragma load objects from lib instead of .h ... these 3 are just needed to make things work, or else you get object not found errors
*/

#include "stdafx.h"
#include <windows.h>
#include <string>
#include <atlstr.h> 
#include <stdlib.h>
#include <stdio.h>
#include <SubAuth.h>
#include <Winhttp.h>
#include <sha.h>
#include <filters.h>
#include <hex.h>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <tchar.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Ws2_32.lib")

int Logtofile(std::string hits, std::string username, int logtype, BOOLEAN LogOnly) {
	//Logtofile is just to centralize logging to everything has same output format - Thanks Jim

	std::string logfile;
	logfile = "C:\\Windows\\System32\\pwndpasswords.log";
	//logfile = "C:\\Files\\BCIPasswordFilter\\pwndpasswords.log"; //needed to test when a console app (not DLL)

	time_t rawtime = time(NULL);
	struct tm timeinfo;
	gmtime_s(&timeinfo, &rawtime);

	char buffer[256];
	std::string computername;
	DWORD dwSize0 = sizeof(buffer);
	bool ok = GetComputerNameExA((COMPUTER_NAME_FORMAT)3, buffer, &dwSize0);
	if (ok) 
	{
		computername = buffer;
	}
	else 
	{
		computername = "UNKNOWN";
	}
	
	SecureZeroMemory(buffer, 256 * sizeof(char));

	int hitcount = std::stoi(hits);
	std::string hitrange = "";
	std::string hitsplain = "";
	std::string message = "";

	if (hitcount == -3)
	{
		hitrange = "EMPTYPASSWORD";
		hitsplain = "EMPTYPASSWORD (?)";
	}
	else if (hitcount == -2)
	{
		hitrange = "ABNORMALPASSWORD";
		hitsplain = "ABNORMALPASSWORD (?)";
	}
	else if (hitcount == -1)
	{
		hitrange = "APIFAIL";
		hitsplain = "APIFAIL (?)";
	}
	else if (hitcount == 0)
	{
		hitrange = "NONE";
		hitsplain = "NONE (0)";
	}
	else if (hitcount == 1)
	{
		hitrange = "UNIQUE";
		hitsplain = "UNIQUE (1)";
	}
	else if (hitcount >= 2 && hitcount <= 10)
	{
		hitrange = "RARE";
		hitsplain = "RARE (2-10)";
	}
	else if (hitcount >= 11 && hitcount <= 100)
	{
		hitrange = "COMMON";
		hitsplain = "COMMON (11-100)";
	}
	else
	{
		hitrange = "VERY COMMON";
		hitsplain = "VERY COMMON (> 100)";
	}

	std::string SuccessMessage;
	if (LogOnly || logtype == 3 || logtype == 4 || logtype == 5 || logtype == 7) { //if logonly it always succeeds
		SuccessMessage = "approved";
	}
	else {
		SuccessMessage = "denied";
	}

	std::string Description;
	std::string LogOnlyPrefix = "";
	std::string eID;

	std::string LogStyle;
	if (LogOnly)
	{
		LogStyle = "TRUE";
		LogOnlyPrefix = "LOGONLY:";
	}
	else
	{
		LogStyle = "FALSE";
	}

	if (logtype == 1 || logtype == 3) { //RESET
		Description = "\"" + LogOnlyPrefix + "This DLL " + SuccessMessage + " the proposed password RESET (generally admin action) [previously breached password count: " + hitsplain + "]\"";
		if (logtype == 1) {
			if (LogOnly) {
				eID = "10702";
			}
			else {
				eID = "10002";
			}

		}
		else { eID = "11002"; }
	}
	else if (logtype == 2 || logtype == 4) { //CHANGE
		Description = "\"" + LogOnlyPrefix + "This DLL " + SuccessMessage + " the proposed password CHANGE (generally the user's action) [previously breached password count: " + hitsplain + "]\"";
		if (logtype == 2) {
			if (LogOnly) {
				eID = "10701";
			}
			else {
				eID = "10001";
			}
		}
		else { eID = "11001"; }
	}
	else if (logtype == 5) { //failed to reach API, or other trap/catch
		Description = "\"" + LogOnlyPrefix + "This DLL " + SuccessMessage + " the proposed password because it failed to query api.pwnedpassword.com\"";
		eID = "11888";
	}
	else if (logtype == 6) { //LSA sorruption
		Description = "\"" + LogOnlyPrefix + "This DLL " + SuccessMessage + " the proposed password because corruption detected in the LSA Call to this DLL\"";
		if (LogOnly) {
			eID = "10799";
		}
		else {
			eID = "10999";
		}

	}
	else if (logtype == 7) { //password was blank
		Description = "\"" + LogOnlyPrefix + "This DLL " + SuccessMessage + " the proposed password because the password was blank (this DLL does not dictate length requirements)\"";
		eID = "11999";
	}

	try {
		std::ofstream fout(logfile, std::ios_base::app);
		fout << "{\"host\":\"" << computername << "\",\"destination_user\":\"" << username << "\",\"source_user\":\"\",\"description\":" << Description << ",\"breachcount\":\"" << hitrange << "\",\"LOGONLY\":\"" << LogStyle << "\",\"application\":\"PWNEDPASSDLL\",\"eventid\":\"" << eID << "\",\"TIME\":\"" << std::put_time(&timeinfo, "%FT%T") << "Z\"}" << std::endl;
		fout.close();
	}
	catch (...) //C has a very very rebust try catch, but i dumbed it down to catch (...) which is catch anything
	{
		SecureZeroMemory(&message, sizeof(message));
		return false;
	}
	SecureZeroMemory(&message, sizeof(message));
	return true;
}

/*
* This function will be called by LSA - the function imports calling account information, including the prospective password
* and exports a Boolean value (either TRUE or FALSE). This return value is then used by LSA in determining whether or not
* the password has passed the in-place password policy.
*/

extern "C" __declspec(dllexport) BOOLEAN __stdcall PasswordFilter(PUNICODE_STRING accountName,
	PUNICODE_STRING fullName,
	PUNICODE_STRING password,
	BOOLEAN operation) {
	
	
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;

	BOOLEAN LogOnly = FALSE; // if compiled with TRUE, then all return codes will be TRUE (Allow to proceed) 

	// FIRST sanity check incoming length... we are going to deny the whole thing if the any of the strings are abnormally long 
	//
	// according to technet, in 2018, max length for samaccountname is 256 wchars, max length of a UPN is 1024 wchars
	// however the GUIs from microsoft only accept 20 (36 if including Domain) for samaccountname and 128 for UPN
	//
	// max length for the password field is 256 wchars (the GUIs dont support this, however group Managed Service Account (gMSA) passwords do)
	//
	// NOTE: we are not going to deny on when the content looks like code etc.  select * where user='blah' ... is a valid password

	// check length of accountname

	if (accountName->Length / sizeof(WCHAR) > 256)
	{ 

		Logtofile("-2", "NotProcessed", 6, LogOnly);
		return LogOnly; //if LogOnly, then never fail; if not Logonly, Disallow password because accountnmame looks corrupt
	}

	//convert accountName from a PUNICODE (Pointer to UNICODE, but only one that LSA uses) to WideString called username
	std::wstring wStrBuffer(accountName->Buffer, accountName->Length / sizeof(WCHAR));
	const wchar_t *wideChar = wStrBuffer.c_str();
	std::wstring wStr(wideChar);
	std::string username(wStr.begin(), wStr.end());

	// check length of password 
	if (password->Length / sizeof(WCHAR) > 256)
	{

		Logtofile("-2", username, 6, LogOnly);
		return LogOnly; //if LogOnly, then never fail; if not Logonly, then Disallow password because password looks corrupt
	}
	else if (password->Length / sizeof(WCHAR) <= 0)
	{
		Logtofile("-3", username, 7, LogOnly);
		return TRUE; //THIS DLL doesnt care about Zero length passwords
	}

	// check length of fullname 
	if (fullName->Length / sizeof(WCHAR) > 256)
	{
		Logtofile("-2", username, 6, LogOnly);
		return LogOnly; //if LogOnly, then never fail; if not Logonly, then Disallow password because fullname looks corrupt
	}

	//convert password from a PUNICODE (Pointer to UNICODE, but only one that LSA uses) to WideString called str
	std::wstring wStrBuffer2(password->Buffer, password->Length / sizeof(WCHAR));
	const wchar_t *wideChar2 = wStrBuffer2.c_str();
	std::wstring wStr2(wideChar2);
	std::string str(wStr2.begin(), wStr2.end());

	//destroy all reference to LSA's password and intermediates for username
	//SecureZeroMemory(password, sizeof(password)); //*** on advice from Microsoft, I stopped attempting to Zero out the buffer to data in LSA

	SecureZeroMemory(&wStrBuffer, sizeof(wStrBuffer));
	SecureZeroMemory(&wStr, sizeof(wStr));
	SecureZeroMemory(&wideChar, sizeof(wideChar));


	SecureZeroMemory(&wStrBuffer2, sizeof(wStrBuffer2));
	SecureZeroMemory(&wStr2, sizeof(wStr2));
	SecureZeroMemory(&wideChar2, sizeof(wideChar2));

	//str holds plaintext password!!

	// Declare the String to hold the SHA1 hash
	std::string hash = "";
	// Generate an SHA1 hash of the requesting password string through Crypto++
	CryptoPP::SHA1 sha1;
	CryptoPP::StringSource(str, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));

	SecureZeroMemory(&str, sizeof(str));
	// NO VARIABLES in DLL hold plaintext password anymore, hash holds SHA1 of password

	std::string hashfirstfive = hash.substr(0, 5);

	std::wstring wsURL = L"/range/";
	wsURL.append(hashfirstfive.begin(), hashfirstfive.end());
	LPCWSTR URL = wsURL.c_str();

	//URL holds "/range/" and the first five characters of the SHA1 password

	try {
		hSession = WinHttpOpen(L"API Scraper/1.0.1", //the API webserver REQUIRES a USERAGENT string, i borrowed this one from JacksonVD (and set to 1.0.1 instead of 1.0.0)
			WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
			WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS, 0);
	}
	catch (...)  //if WinHttpOpen Fails, we log error and return true (allow password because we dont know)
	{
		Logtofile("-1", username, 5,LogOnly);
		return TRUE; //because of issues getting accurate/timely data from pwnedpasswords.com, allow password (technically dont vote against it, other complexity rules can still stop it)
	}


	// Specify an HTTP server.
	if (hSession)
	{
		try
		{
			hConnect = WinHttpConnect(hSession, L"api.pwnedpasswords.com",  //this is the host for this connection
				INTERNET_DEFAULT_HTTPS_PORT, 0);
		}
		catch (...)  //if connect fails, we log error and return true (allow password because we dont know)
		{
			Logtofile("-1", username, 5,LogOnly);
			return TRUE; //because of issues getting accurate/timely data from pwnedpasswords.com, allow password (technically dont vote against it, other complexity rules can still stop it)
		}
	}
	else //if winhttp session fails, we log error and return true (allow password because we dont know)
	{
		Logtofile("-1", username, 5,LogOnly);
		return TRUE; //because of issues getting accurate/timely data from pwnedpasswords.com, allow password (technically dont vote against it, other complexity rules can still stop it)
	}

	// Create an HTTP request handle.
	if (hConnect)
	{
		try
		{
			hRequest = WinHttpOpenRequest(hConnect, L"GET", URL,  //send a get to the host with the URL
				NULL, WINHTTP_NO_REFERER,
				WINHTTP_DEFAULT_ACCEPT_TYPES,
				WINHTTP_FLAG_SECURE);
		}
		catch (...)
		{
			Logtofile("-1", username, 5, LogOnly);
			return TRUE; //because of issues getting accurate/timely data from pwnedpasswords.com, allow password (technically dont vote against it, other complexity rules can still stop it)
		}
	}
	else
	{
		Logtofile("-1", username, 5, LogOnly);
		return TRUE; //because of issues getting accurate/timely data from pwnedpasswords.com, allow password (technically dont vote against it, other complexity rules can still stop it)
	}

	// Send a request.
	if (hRequest)
	{
		try
		{
			bResults = WinHttpSendRequest(hRequest,
				WINHTTP_NO_ADDITIONAL_HEADERS,
				0, WINHTTP_NO_REQUEST_DATA, 0,
				0, 0);
		}
		catch (...)
		{
			Logtofile("-1", username, 5, LogOnly);
			return TRUE; //because of issues getting accurate/timely data from pwnedpasswords.com, allow password (technically dont vote against it, other complexity rules can still stop it)
		}

	}
	else
	{
		Logtofile("-1", username, 5, LogOnly);
		return TRUE; //because of issues getting accurate/timely data from pwnedpasswords.com, allow password (technically dont vote against it, other complexity rules can still stop it)
	}


	std::string APIResponse;

	// End the request.
	if (bResults)
	{
		try
		{
			bResults = WinHttpReceiveResponse(hRequest, NULL);
		}
		catch (...)
		{
			Logtofile("-1", username, 5, LogOnly);
			return TRUE; //because of issues getting accurate/timely data from pwnedpasswords.com, allow password (technically dont vote against it, other complexity rules can still stop it)
		}
	}
	else
	{
		Logtofile("-1", username, 5, LogOnly);
		return TRUE; //because of issues getting accurate/timely data from pwnedpasswords.com, allow password (technically dont vote against it, other complexity rules can still stop it)
	}

	// Keep checking for data until there is nothing left.
	if (bResults)
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) { //Stream cut off abruptly (we knew how big the stream was, but we got an END beofre the size was reached)
				Logtofile("-1", username, 5, LogOnly);
				return TRUE; //because of issues getting accurate/timely data from pwnedpasswords.com, allow password (technically dont vote against it, other complexity rules can still stop it)
			}


			// Allocate space for the buffer.
			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer)
			{
				dwSize = 0;
			}
			else
			{
				// Read the Data.
				ZeroMemory(pszOutBuffer, dwSize + 1);

				if (WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
					dwSize, &dwDownloaded))
					APIResponse += pszOutBuffer;

				// Free the memory allocated to the buffer.
				delete[] pszOutBuffer;
			}

		} while (dwSize > 0);

		// Close any open handles.
		if (hRequest) WinHttpCloseHandle(hRequest);
		if (hConnect) WinHttpCloseHandle(hConnect);
		if (hSession) WinHttpCloseHandle(hSession);

		// APIResponse now has the raw text of the response

		std::size_t found = APIResponse.find(hash.substr(5));  //TEST for the REST of the SHA1 (6th character to the end), anywhere in the response
		std::string hits = "0";
		BOOLEAN returnValue = TRUE;
		if (found != std::string::npos) // The find function will return string::npos if the requested string was no found
		{
			//if we are here, the hash of password was somewhere in the data
			std::size_t start = APIResponse.find(":", found);
			std::size_t finish = APIResponse.find("\n", start);
			std::size_t length = finish - start;
			hits = APIResponse.substr(start + 1, length - 2);  //the data returns text hashes, with a : and then a number indicating how many hits (each hash has its own : #)
			returnValue = LogOnly; //if LogOnly, then never fail; if not Logonly, then Disallow password because password has been in a breach

		}
		SecureZeroMemory(&hash, sizeof(hash));
		SecureZeroMemory(&APIResponse, sizeof(APIResponse));
		// NO VARIABLE has the full hash or the API response! (hashfirstfive has first five letters of hash)

		if (hits == "0") {
			if (operation) {
				Logtofile(hits, username, 3, LogOnly); //Admin Successfully set
			}
			else
			{
				Logtofile(hits, username, 4, LogOnly); //User successfully changed
			}

		}
		else
		{
			if (operation) {
				Logtofile(hits, username, 1, LogOnly); //Admin Failed Set
			}
			else
			{
				Logtofile(hits, username, 2, LogOnly); //User Failed Change
			}
		}


		return returnValue;

}
