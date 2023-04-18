#include <chrono> // for timing
using std::chrono::steady_clock;
using std::chrono::duration_cast;
using std::chrono::microseconds;

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include <iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
using CryptoPP::CBC_Mode;
#include <cryptopp/modes.h>
#include<cryptopp/xts.h>
#include<cryptopp/ccm.h>
#include<cryptopp/gcm.h>
#include "assert.h"
#include <cryptopp/modes.h>
#include<cryptopp/xts.h>
#include<cryptopp/ccm.h>
#include<cryptopp/gcm.h>
using CryptoPP::CBC_CTS_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::CCM;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;
using CryptoPP::OFB_Mode;
using CryptoPP::XTS;
/* Set _setmode()*/
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;
wstring string_to_wstring(const std::string& str);
string wstring_to_string(const std::wstring& str);

#include <iostream>
#include <fstream>
string Input_plaintext();
string Input_ciphertext();
string Input_key(int);
string Input_IV(int);
void Encrypt_CTR();
void Decrypt_CTR();
void Encrypt_OFB();
void Decrypt_OFB();
void Encrypt_CFB();
void Decrypt_CFB();
void Encrypt_CBC();
void Decrypt_CBC();
void Encrypt_ECB();
void Decrypt_ECB();
void Encrypt_CTR();
void Decrypt_CTR();
void Encrypt_XTS();
void Decrypt_XTS();
void Encrypt_CCM();
void Decrypt_CCM();
int main(int argc, char* argv[])
{
#ifdef __linux__
	setlocale(LC_ALL, "");
#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif
	wcout << "Mode:\n";
	wcout << "1.CBC\n2.ECB\n3.OFB\n4.CFB\n5.CTR\n6.XTS\n7.CCM\n";
	wcout << "Select your mode: ";
	int selection;
	wcin >> selection;
	wcin.ignore();
	if (selection == 1)
	{
		Encrypt_CBC();
		Decrypt_CBC();
	}
	else if (selection == 2) {
		Encrypt_ECB();
		Decrypt_ECB();
	}
	else if (selection == 3) {
		Encrypt_OFB();
		Decrypt_OFB();
	}
	else if (selection == 4) {
		Encrypt_CFB();
		Decrypt_CFB();
	}
	else if (selection == 5) {
		Encrypt_CTR();
		Decrypt_CTR();
	}
	else if (selection == 6) {
		Encrypt_XTS();
		Decrypt_XTS();
	}
	else if (selection == 7) {
		Encrypt_CCM();
		Decrypt_CCM();
	}


	system("pause");
	return 0;
}

/* convert string to wstring */
wstring string_to_wstring(const std::string& str)
{
	wstring_convert<codecvt_utf8<wchar_t> > towstring;
	return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string(const std::wstring& str)
{
	wstring_convert<codecvt_utf8<wchar_t> > tostring;
	return tostring.to_bytes(str);
}

string Input_plaintext()
{
	wstring wplain;
	int select;
	wcout << "Which option you want to choose to input plaintext:\n1. From keyboard\n2. From file\n";
	wcout << "Your selection: ";
	wcin >> select;
	wcin.ignore();
	if (select == 1) {
		wcout << "Input plain text:";
		getline(wcin, wplain);
		string plain = wstring_to_string(wplain);
	}
	else {
		std::wifstream plain_file("plaintext_file.txt");
		if (plain_file.is_open()) {
			plain_file >> wplain;
			plain_file.close();
		}
		else {
			wcout << "Error opening key file" << endl;

		}

	}

	string plain = wstring_to_string(wplain);
	return plain;
}
string Input_key(int select) {
	wstring wkey_input_hex;

	//wcin.ignore();
	if (select == 1) {
		wcout << "Input key from keyboard:";
		getline(wcin, wkey_input_hex);
		//		string cipher= wstring_to_string(wcipher);
	}
	else {
		std::wifstream k_file("key_file.txt");
		if (k_file.is_open()) {
			k_file >> wkey_input_hex;
			k_file.close();
		}
		else {
			wcout << "Error opening key file" << endl;

		}

	}

	string key_hex = wstring_to_string(wkey_input_hex);
	string key;
	StringSource ss(key_hex, true, new HexDecoder(new StringSink(key)));
	return key;
}

string Input_IV(int select) {
	wstring wiv_input_hex;

	if (select == 1) {
		wcout << "Input iv from keyboard:";
		getline(wcin, wiv_input_hex);

	}
	else {
		std::wifstream iv_file("iv_file.txt");
		if (iv_file.is_open()) {
			iv_file >> wiv_input_hex;
			iv_file.close();
		}
		else {
			wcout << "Error opening key file" << endl;

		}

	}

	string wiv_input = wstring_to_string(wiv_input_hex);
	string iv;
	StringSource s(wiv_input, true, new HexDecoder(new StringSink(iv)));
	return iv;
}
string Input_ciphertext()
{
	wstring wcipher;
	int select;
	wcout << "Which option you want to choose to input ciphertext:\n1. From keyboard\n2. From file\n";
	wcout << "Your selection: ";
	wcin >> select;
	wcin.ignore();
	if (select == 1) {
		wcout << "Input cipher text:";
		getline(wcin, wcipher);

	}
	else {
		std::wifstream cp_file("ciphertext_file.txt");
		if (cp_file.is_open()) {
			cp_file >> wcipher;
			cp_file.close();
		}
		else {
			wcout << "Error opening key file" << endl;

		}

	}

	string cipher = wstring_to_string(wcipher);
	return cipher;
}
/// <summary>
/// CBC mode
/// </summary>
void Encrypt_CBC()
{
	AutoSeededRandomPool prng;
	byte key[32] = { 0 };
	byte fkey[32] = { 0 };
	byte iv[AES::BLOCKSIZE] = { 0 };

	int selection;
	wcout << "Which option do you want to input key and iv for encryption?\n1.Input from keyboard\n2.Input from file\n3.Input from random generator\n";
	wcout << "Your selection: ";
	wcin >> selection;
	wcin.ignore();

	if (selection != 3)
	{
		string keyy = Input_key(selection);
		string ivv = Input_IV(selection);

		for (int i = 0; i < (int)keyy.length(); i++)
		{

			if (keyy[i] >= L'0' && keyy[i] <= L'9')
				key[i] = keyy[i] - L'0';
			else
				key[i] = keyy[i];
		}
		StringSource s(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));


		for (int i = 0; i < (int)ivv.length();i++) {
			if (ivv[i] >= L'0' && ivv[i] <= L'9')
				iv[i] = ivv[i] - L'0';
			else
				iv[i] = ivv[i];
		}


	}

	else
	{
		/* Create random key and write to file*/
		prng.GenerateBlock(key, sizeof(key));
		StringSource ss(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));
		prng.GenerateBlock(iv, sizeof(iv));
	}

	string plain = Input_plaintext();
	//string plain = "123";
	string cipher, encoded, recovered;

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	try
	{
		auto start = steady_clock::now();
		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource
		auto end = steady_clock::now();
		auto enc_time = duration_cast<microseconds>(end - start).count();
		encoded.clear();
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource
		wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		wcout << "Encryption time: " << enc_time << " ms\n";
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}


}
void Decrypt_CBC()
{
	byte key[32] = { 0 };
	byte fkey[32] = { 0 };
	byte iv[AES::BLOCKSIZE] = { 0 };

	string cipher_hex = Input_ciphertext();
	string cipher;
	StringSource ss(cipher_hex, true, new HexDecoder(new StringSink(cipher)));


	int selection;
	wcout << "Which option do you wnat to input key and iv for decryption? \n1.Input from keyboard\n2.Input from file\n";
	wcout << "Your selection: ";
	wcin >> selection;
	wcin.ignore();


	string keyy = Input_key(selection);
	string ivv = Input_IV(selection);


	for (int i = 0; i < (int)keyy.length(); i++)
	{
		/*if (keyy[i] >= L'0' && keyy[i] <= L'9')
			key[i] = keyy[i] - L'0';
		else*/
		key[i] = keyy[i];
	}
	StringSource s(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));



	for (int i = 0; i < (int)ivv.length(); i++)
	{

		/*if (ivv[i] >= L'0' && ivv[i] <= L'9')
			iv[i] = ivv[i] - L'0';
		else*/
		iv[i] = ivv[i];
	}

	string encoded, recovered;
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	try
	{
		auto start = steady_clock::now();
		CryptoPP::CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
		auto end = steady_clock::now();
		auto dec_time = duration_cast<microseconds>(end - start).count();

		wcout << "recovered text: " << string_to_wstring(recovered) << endl;
		wcout << "Decryption time: " << dec_time << " ms\n";
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

/// <summary>
/// ECB mode
/// </summary>
void Encrypt_ECB()
{
	AutoSeededRandomPool prng;
	byte key[32] = { 0 };
	byte fkey[32] = { 0 };
	//byte iv[AES::BLOCKSIZE] = { 0 };

	int selection;
	wcout << "Which option do you want to input key and iv for encryption?\n1.Input from keyboard\n2.Input from file\n3.Input from random generator\n";
	wcout << "Your selection: ";
	wcin >> selection;
	wcin.ignore();

	if (selection != 3)
	{
		string keyy = Input_key(selection);
		//string ivv = Input_IV(selection);

		for (int i = 0; i < (int)keyy.length(); i++)
		{

			if (keyy[i] >= L'0' && keyy[i] <= L'9')
				key[i] = keyy[i] - L'0';
			else
				key[i] = keyy[i];
		}
		StringSource s(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));


		/*for (int i = 0; i < (int)ivv.length();i++) {
			if (ivv[i] >= L'0' && ivv[i] <= L'9')
				iv[i] = ivv[i] - L'0';
			else
				iv[i] = ivv[i];
		}*/


	}

	else
	{
		/* Create random key and write to file*/
		prng.GenerateBlock(key, sizeof(key));
		StringSource ss(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));
		//prng.GenerateBlock(iv, sizeof(iv));
	}

	string plain = Input_plaintext();
	//string plain = "123";
	string cipher, encoded, recovered;

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	//encoded.clear();
	//StringSource(iv, sizeof(iv), true,
	//	new HexEncoder(
	//		new StringSink(encoded)
	//	) // HexEncoder
	//); // StringSource
	//wcout << "iv: " << string_to_wstring(encoded) << endl;

	try
	{
		auto start = steady_clock::now();
		ECB_Mode< AES >::Encryption e;
		e.SetKey(key, sizeof(key));

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource
		auto end = steady_clock::now();
		auto enc_time = duration_cast<microseconds>(end - start).count();
		encoded.clear();
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource
		wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		wcout << "Encryption time: " << enc_time << " ms\n";
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}


}
void Decrypt_ECB()
{
	byte key[32] = { 0 };
	byte fkey[32] = { 0 };
	//byte iv[AES::BLOCKSIZE] = { 0 };

	string cipher_hex = Input_ciphertext();
	string cipher;
	StringSource ss(cipher_hex, true, new HexDecoder(new StringSink(cipher)));


	int selection;
	wcout << "Which option do you wnat to input key and iv for decryption? \n1.Input from keyboard\n2.Input from file\n";
	wcout << "Your selection: ";
	wcin >> selection;
	wcin.ignore();


	string keyy = Input_key(selection);
	//string ivv = Input_IV(selection);


	for (int i = 0; i < (int)keyy.length(); i++)
	{
		/*if (keyy[i] >= L'0' && keyy[i] <= L'9')
			key[i] = keyy[i] - L'0';
		else*/
		key[i] = keyy[i];
	}
	StringSource s(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));



	//for (int i = 0; i < (int)ivv.length(); i++)
	//{

	//	/*if (ivv[i] >= L'0' && ivv[i] <= L'9')
	//		iv[i] = ivv[i] - L'0';
	//	else*/
	//	iv[i] = ivv[i];
	//}

	string encoded, recovered;
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	//encoded.clear();
	//StringSource(iv, sizeof(iv), true,
	//	new HexEncoder(
	//		new StringSink(encoded)
	//	) // HexEncoder
	//); // StringSource
	//wcout << "iv: " << string_to_wstring(encoded) << endl;

	try
	{
		auto start = steady_clock::now();
		CryptoPP::ECB_Mode< AES >::Decryption d;
		d.SetKey(key, sizeof(key));

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
		auto end = steady_clock::now();
		auto dec_time = duration_cast<microseconds>(end - start).count();

		wcout << "recovered text: " << string_to_wstring(recovered) << endl;
		wcout << "Decryption time: " << dec_time << " ms\n";
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}
/// <summary>
/// CFB mode
/// </summary>
void Encrypt_CFB()
{
	AutoSeededRandomPool prng;
	byte key[32] = { 0 };
	byte fkey[32] = { 0 };
	byte iv[AES::BLOCKSIZE] = { 0 };

	int selection;
	wcout << "Which option do you want to input key and iv for encryption?\n1.Input from keyboard\n2.Input from file\n3.Input from random generator\n";
	wcout << "Your selection: ";
	wcin >> selection;
	wcin.ignore();

	if (selection != 3)
	{
		string keyy = Input_key(selection);
		string ivv = Input_IV(selection);

		for (int i = 0; i < (int)keyy.length(); i++)
		{

			if (keyy[i] >= L'0' && keyy[i] <= L'9')
				key[i] = keyy[i] - L'0';
			else
				key[i] = keyy[i];
		}
		StringSource s(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));


		for (int i = 0; i < (int)ivv.length();i++) {
			if (ivv[i] >= L'0' && ivv[i] <= L'9')
				iv[i] = ivv[i] - L'0';
			else
				iv[i] = ivv[i];
		}


	}

	else
	{
		/* Create random key and write to file*/
		prng.GenerateBlock(key, sizeof(key));
		StringSource ss(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));
		prng.GenerateBlock(iv, sizeof(iv));
	}

	string plain = Input_plaintext();
	//string plain = "123";
	string cipher, encoded, recovered;

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	try
	{
		auto start = steady_clock::now();
		CFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource
		auto end = steady_clock::now();
		auto enc_time = duration_cast<microseconds>(end - start).count();
		encoded.clear();
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource
		wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		wcout << "Encryption time: " << enc_time << " ms\n";
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}


}
void Decrypt_CFB()
{
	byte key[32] = { 0 };
	byte fkey[32] = { 0 };
	byte iv[AES::BLOCKSIZE] = { 0 };

	string cipher_hex = Input_ciphertext();
	string cipher;
	StringSource ss(cipher_hex, true, new HexDecoder(new StringSink(cipher)));


	int selection;
	wcout << "Which option do you wnat to input key and iv for decryption? \n1.Input from keyboard\n2.Input from file\n";
	wcout << "Your selection: ";
	wcin >> selection;
	wcin.ignore();


	string keyy = Input_key(selection);
	string ivv = Input_IV(selection);


	for (int i = 0; i < (int)keyy.length(); i++)
	{
		/*if (keyy[i] >= L'0' && keyy[i] <= L'9')
			key[i] = keyy[i] - L'0';
		else*/
		key[i] = keyy[i];
	}
	StringSource s(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));



	for (int i = 0; i < (int)ivv.length(); i++)
	{

		/*if (ivv[i] >= L'0' && ivv[i] <= L'9')
			iv[i] = ivv[i] - L'0';
		else*/
		iv[i] = ivv[i];
	}

	string encoded, recovered;
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	try
	{
		auto start = steady_clock::now();
		CryptoPP::CFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
		auto end = steady_clock::now();
		auto dec_time = duration_cast<microseconds>(end - start).count();

		wcout << "recovered text: " << string_to_wstring(recovered) << endl;
		wcout << "Decryption time: " << dec_time << " ms\n";
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

///
///OFB mode
///
void Encrypt_OFB()
{
	AutoSeededRandomPool prng;
	byte key[32] = { 0 };
	byte fkey[32] = { 0 };
	byte iv[AES::BLOCKSIZE] = { 0 };

	int selection;
	wcout << "Which option do you want to input key and iv for encryption?\n1.Input from keyboard\n2.Input from file\n3.Input from random generator\n";
	wcout << "Your selection: ";
	wcin >> selection;
	wcin.ignore();

	if (selection != 3)
	{
		string keyy = Input_key(selection);
		string ivv = Input_IV(selection);

		for (int i = 0; i < (int)keyy.length(); i++)
		{

			if (keyy[i] >= L'0' && keyy[i] <= L'9')
				key[i] = keyy[i] - L'0';
			else
				key[i] = keyy[i];
		}
		StringSource s(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));


		for (int i = 0; i < (int)ivv.length();i++) {
			if (ivv[i] >= L'0' && ivv[i] <= L'9')
				iv[i] = ivv[i] - L'0';
			else
				iv[i] = ivv[i];
		}


	}

	else
	{
		/* Create random key and write to file*/
		prng.GenerateBlock(key, sizeof(key));
		StringSource ss(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));
		prng.GenerateBlock(iv, sizeof(iv));
	}

	string plain = Input_plaintext();
	//string plain = "123";
	string cipher, encoded, recovered;

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	try
	{
		auto start = steady_clock::now();
		OFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource
		auto end = steady_clock::now();
		auto enc_time = duration_cast<microseconds>(end - start).count();
		encoded.clear();
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource
		wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		wcout << "Encryption time: " << enc_time << " ms\n";
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}


}
void Decrypt_OFB()
{
	byte key[32] = { 0 };
	byte fkey[32] = { 0 };
	byte iv[AES::BLOCKSIZE] = { 0 };

	string cipher_hex = Input_ciphertext();
	string cipher;
	StringSource ss(cipher_hex, true, new HexDecoder(new StringSink(cipher)));


	int selection;
	wcout << "Which option do you wnat to input key and iv for decryption? \n1.Input from keyboard\n2.Input from file\n";
	wcout << "Your selection: ";
	wcin >> selection;
	wcin.ignore();


	string keyy = Input_key(selection);
	string ivv = Input_IV(selection);


	for (int i = 0; i < (int)keyy.length(); i++)
	{
		/*if (keyy[i] >= L'0' && keyy[i] <= L'9')
			key[i] = keyy[i] - L'0';
		else*/
			key[i] = keyy[i];
	}
	StringSource s(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));



	for (int i = 0; i < (int)ivv.length(); i++)
	{

		/*if (ivv[i] >= L'0' && ivv[i] <= L'9')
			iv[i] = ivv[i] - L'0';
		else*/
			iv[i] = ivv[i];
	}

	string encoded, recovered;
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	try
	{
		auto start = steady_clock::now();
		CryptoPP::OFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
		auto end = steady_clock::now();
		auto dec_time = duration_cast<microseconds>(end - start).count();

		wcout << "recovered text: " << string_to_wstring(recovered) << endl;
		wcout << "Decryption time: " << dec_time << " ms\n";
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}
///
///CTR
///
void Encrypt_CTR()
{
	AutoSeededRandomPool prng;
	byte key[32] = { 0 };
	byte fkey[32] = { 0 };
	byte ctr[AES::BLOCKSIZE] = { 0 };

	int selection;
	wcout << "Which option do you want to input key and iv for encryption?\n1.Input from keyboard\n2.Input from file\n3.Input from random generator\n";
	wcout << "Your selection: ";
	wcin >> selection;
	wcin.ignore();

	if (selection != 3)
	{
		string keyy = Input_key(selection);
		string ctr_input = Input_IV(selection);

		for (int i = 0; i < (int)keyy.length(); i++)
		{

			/*if (keyy[i] >= L'0' && keyy[i] <= L'9')
				key[i] = keyy[i] - L'0';
			else*/
				key[i] = keyy[i];
		}
		StringSource s(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));


		for (int i = 0; i < (int)ctr_input.length();i++) {
			/*if (ctr_input[i] >= L'0' && ctr_input[i] <= L'9')
				iv[i] = ctr_input[i] - L'0';
			else*/
				ctr[i] = ctr_input[i];
		}


	}

	else
	{
		/* Create random key and write to file*/
		prng.GenerateBlock(key, sizeof(key));
		StringSource ss(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));
		prng.GenerateBlock(ctr, sizeof(ctr));
	}

	string plain = Input_plaintext();
	//string plain = "123";
	string cipher, encoded, recovered;

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(ctr, sizeof(ctr), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "ctr: " << string_to_wstring(encoded) << endl;

	try
	{
		auto start = steady_clock::now();
		CTR_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), ctr);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource
		auto end = steady_clock::now();
		auto enc_time = duration_cast<microseconds>(end - start).count();
		encoded.clear();
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource
		wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		wcout << "Encryption time: " << enc_time << " ms\n";
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}


}
void Decrypt_CTR()
{
	byte key[32] = { 0 };
	byte fkey[32] = { 0 };
	byte ctr[AES::BLOCKSIZE] = { 0 };

	string cipher_hex = Input_ciphertext();
	string cipher;
	StringSource ss(cipher_hex, true, new HexDecoder(new StringSink(cipher)));


	int selection;
	wcout << "Which option do you wnat to input key and iv for decryption? \n1.Input from keyboard\n2.Input from file\n";
	wcout << "Your selection: ";
	wcin >> selection;
	wcin.ignore();


	string keyy = Input_key(selection);
	string ctr_input = Input_IV(selection);


	for (int i = 0; i < (int)keyy.length(); i++)
	{
		/*if (keyy[i] >= L'0' && keyy[i] <= L'9')
			key[i] = keyy[i] - L'0';
		else*/
		key[i] = keyy[i];
	}
	StringSource s(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));



	for (int i = 0; i < (int)ctr_input.length(); i++)
	{

		/*if (ivv[i] >= L'0' && ivv[i] <= L'9')
			iv[i] = ivv[i] - L'0';
		else*/
		ctr[i] = ctr_input[i];
	}

	string encoded, recovered;
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(ctr, sizeof(ctr), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "ctr: " << string_to_wstring(encoded) << endl;

	try
	{
		auto start = steady_clock::now();
		CryptoPP::CTR_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), ctr);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
		auto end = steady_clock::now();
		auto dec_time = duration_cast<microseconds>(end - start).count();

		wcout << "recovered text: " << string_to_wstring(recovered) << endl;
		wcout << "Decryption time: " << dec_time << " ms\n";
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

///
///XTS mode
///
void Encrypt_XTS()
{
	AutoSeededRandomPool prng;
	byte key[32] = { 0 };
	byte fkey[32] = { 0 };
	byte iv[AES::BLOCKSIZE] = { 0 };

	int selection;
	wcout << "Which option do you want to input key and iv for encryption?\n1.Input from keyboard\n2.Input from file\n3.Input from random generator\n";
	wcout << "Your selection: ";
	wcin >> selection;
	wcin.ignore();

	if (selection != 3)
	{
		string keyy = Input_key(selection);
		string ivv = Input_IV(selection);

		for (int i = 0; i < (int)keyy.length(); i++)
		{

			/*if (keyy[i] >= L'0' && keyy[i] <= L'9')
				key[i] = keyy[i] - L'0';
			else*/
			key[i] = keyy[i];
		}
		StringSource s(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));


		for (int i = 0; i < (int)ivv.length();i++) {
			/*if (ctr_input[i] >= L'0' && ctr_input[i] <= L'9')
				iv[i] = ctr_input[i] - L'0';
			else*/
			iv[i] = ivv[i];
		}


	}

	else
	{
		/* Create random key and write to file*/
		prng.GenerateBlock(key, sizeof(key));
		StringSource ss(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));
		prng.GenerateBlock(iv, sizeof(iv));
	}

	string plain = Input_plaintext();
	//string plain = "123";
	string cipher, encoded, recovered;

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	try
	{
		auto start = steady_clock::now();
		XTS_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher),
				StreamTransformationFilter::NO_PADDING
			) // StreamTransformationFilter
		); // StringSource
		auto end = steady_clock::now();
		auto enc_time = duration_cast<microseconds>(end - start).count();
		encoded.clear();
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource
		wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		wcout << "Encryption time: " << enc_time << " ms\n";
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}


}
void Decrypt_XTS()
{
	byte key[32] = { 0 };
	byte fkey[32] = { 0 };
	byte iv[AES::BLOCKSIZE] = { 0 };

	string cipher_hex = Input_ciphertext();
	string cipher;
	StringSource ss(cipher_hex, true, new HexDecoder(new StringSink(cipher)));


	int selection;
	wcout << "Which option do you wnat to input key and iv for decryption? \n1.Input from keyboard\n2.Input from file\n";
	wcout << "Your selection: ";
	wcin >> selection;
	wcin.ignore();


	string keyy = Input_key(selection);
	string ivv = Input_IV(selection);


	for (int i = 0; i < (int)keyy.length(); i++)
	{
		/*if (keyy[i] >= L'0' && keyy[i] <= L'9')
			key[i] = keyy[i] - L'0';
		else*/
		key[i] = keyy[i];
	}
	StringSource s(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));



	for (int i = 0; i < (int)ivv.length(); i++)
	{

		/*if (ivv[i] >= L'0' && ivv[i] <= L'9')
			iv[i] = ivv[i] - L'0';
		else*/
		iv[i] = ivv[i];
	}

	string encoded, recovered;
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	try
	{
		auto start = steady_clock::now();
		CryptoPP::XTS_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered),
				StreamTransformationFilter::NO_PADDING
			) // StreamTransformationFilter
		); // StringSource
		auto end = steady_clock::now();
		auto dec_time = duration_cast<microseconds>(end - start).count();

		wcout << "recovered text: " << string_to_wstring(recovered) << endl;
		wcout << "Decryption time: " << dec_time << " ms\n";
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

///
///CCM mode
///
void Encrypt_CCM()
{
	AutoSeededRandomPool prng;
	byte key[AES::DEFAULT_KEYLENGTH] = { 0 };
	byte fkey[32] = { 0 };
	byte iv[12] = { 0 };


	int selection;
	wcout << "Which option do you want to input key and iv for encryption?\n1.Input from keyboard\n2.Input from file\n3.Input from random generator\n";
	wcout << "Your selection: ";
	wcin >> selection;
	wcin.ignore();

	if (selection != 3)
	{
		string keyy = Input_key(selection);
		string ivv = Input_IV(selection);

		for (int i = 0; i < (int)keyy.length(); i++)
		{

			if (keyy[i] >= L'0' && keyy[i] <= L'9')
				key[i] = keyy[i] - L'0';
			else
				key[i] = keyy[i];
		}
		StringSource s(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));


		for (int i = 0; i < (int)ivv.length();i++) {
			if (ivv[i] >= L'0' && ivv[i] <= L'9')
				iv[i] = ivv[i] - L'0';
			else
				iv[i] = ivv[i];
		}


	}

	else
	{
		/* Create random key and write to file*/
		prng.GenerateBlock(key, sizeof(key));
		StringSource ss(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));
		prng.GenerateBlock(iv, sizeof(iv));
	}

	string plain = Input_plaintext();
	//string plain = "123";
	string cipher, encoded, recovered;
	const int TAG_SIZE = 8;
	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	try
	{
		auto start = steady_clock::now();
		CCM< AES, TAG_SIZE >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);
		e.SpecifyDataLengths(0, plain.size(), 0);

		StringSource ss1(plain, true,
			new AuthenticatedEncryptionFilter(e,
				new StringSink(cipher)
			) // AuthenticatedEncryptionFilter
		); // StringSource

		auto end = steady_clock::now();
		auto enc_time = duration_cast<microseconds>(end - start).count();
		encoded.clear();
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource
		wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		wcout << "Encryption time: " << enc_time << " ms\n";
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}


}
void Decrypt_CCM()
{
	byte key[AES::DEFAULT_KEYLENGTH] = { 0 };
	byte fkey[32] = { 0 };
	byte iv[12] = { 0 };

	string cipher_hex = Input_ciphertext();
	string cipher;
	StringSource ss(cipher_hex, true, new HexDecoder(new StringSink(cipher)));


	int selection;
	wcout << "Which option do you wnat to input key and iv for decryption? \n1.Input from keyboard\n2.Input from file\n";
	wcout << "Your selection: ";
	wcin >> selection;
	wcin.ignore();


	string keyy = Input_key(selection);
	string ivv = Input_IV(selection);


	for (int i = 0; i < (int)keyy.length(); i++)
	{
		/*if (keyy[i] >= L'0' && keyy[i] <= L'9')
			key[i] = keyy[i] - L'0';
		else*/
		key[i] = keyy[i];
	}
	StringSource s(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));



	for (int i = 0; i < (int)ivv.length(); i++)
	{

		/*if (ivv[i] >= L'0' && ivv[i] <= L'9')
			iv[i] = ivv[i] - L'0';
		else*/
		iv[i] = ivv[i];
	}

	string encoded, recovered;
	const int TAG_SIZE = 8;
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	try
	{
		auto start = steady_clock::now();
		CCM< AES, TAG_SIZE >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);
		d.SpecifyDataLengths(0, cipher.size() - TAG_SIZE, 0);

		AuthenticatedDecryptionFilter df(d,
			new StringSink(recovered)
		); // AuthenticatedDecryptionFilter

		// The StringSource dtor will be called immediately
		//  after construction below. This will cause the
		//  destruction of objects it owns. To stop the
		//  behavior so we can get the decoding result from
		//  the DecryptionFilter, we must use a redirector
		//  or manually Put(...) into the filter without
		//  using a StringSource.
		StringSource ss2(cipher, true,
			new Redirector(df)
		); // StringSource


		auto end = steady_clock::now();
		auto dec_time = duration_cast<microseconds>(start - end).count();
		// If the object does not throw, here's the only
		//  opportunity to check the data's integrity
		if (true == df.GetLastResult()) {
			wcout << "recovered text: " << string_to_wstring(recovered) << endl;
			wcout << "Decryption time: " << dec_time << " ms\n";
		}
	}



	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}
