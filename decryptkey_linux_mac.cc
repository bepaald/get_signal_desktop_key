/*
  Copyright (C) 2024  Selwin van Dijk

  This file is part of get_signal_desktop_key.

  get_signal_desktop_key is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  get_signal_desktop_key is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with get_signal_desktop_key.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "main.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <iostream>
#include <memory>
#include <algorithm>
#include <cstring>

#include <sstream>
#include <iomanip>
namespace bepaald
{
  inline std::string bytesToPrintableString(unsigned char const *data, unsigned int length)
  {
    bool prevwashex = false;
    std::ostringstream oss;
    for (uint i = 0; i < length; ++i)
    {
      bool curishex = !std::isprint(static_cast<char>(data[i]));

      if (curishex != prevwashex && i > 0)
        oss << " ";

      if (curishex)
        oss << "0x" << std::hex << std::setfill('0') << std::setw(2)
            << (static_cast<int32_t>(data[i]) & 0xFF)
            << (i == length - 1 ? "" : " ");
      else
        oss << static_cast<char>(data[i]);

      prevwashex = curishex;
    }
    return oss.str();
  }

  inline bool hexStringToBytes(unsigned char const *in, uint64_t insize, unsigned char *out, uint64_t outsize)
  {
    if (insize % 2 ||
        outsize != insize / 2)
    {
      std::cout << "Invalid size for hex string or output array too small" << std::endl;
      return false;
    }

    auto charToInt = [] (char c)
    {
      if (c <= '9' && c >= '0')
        return c - '0';
      if (c <= 'F' && c >= 'A')
        return c - 'A' + 10;
      // if (c <= 'f' && c >= 'a') // lets assume input is valid...
      return c - 'a' + 10;
    };

    uint64_t outpos = 0;
    for (uint i = 0; i < insize - 1; i += 2)
      out[outpos++] = charToInt(in[i]) * 16 + charToInt(in[i + 1]);

    return true;
  }

  inline bool hexStringToBytes(std::string const &in, unsigned char *out, uint64_t outsize)
  {
    // sanitize input;
    std::string input = in;
    auto newend = std::remove_if(input.begin(), input.end(), [](char c) {
      return (c > '9' || c < '0') && (c > 'F' || c < 'A') && (c > 'f' || c < 'a'); });
    input.erase(newend, input.end());

    return hexStringToBytes(reinterpret_cast<unsigned char const *>(input.c_str()), input.size(), out, outsize);
  }

  inline std::string bytesToHexString(unsigned char const *data, unsigned int length)
  {
    std::ostringstream oss;
    oss << "(hex:) ";
    for (uint i = 0; i < length; ++i)
      oss << std::hex << std::setfill('0') << std::setw(2)
          << (static_cast<int32_t>(data[i]) & 0xFF)
          << ((i == length - 1) ? "" : " ");
    return oss.str();
  }
}



std::string decryptKey_linux_mac(std::string const &secret, std::string const &encryptedkeystr)
{

  //g_verbose = true;

  std::string decryptedkey;

  // secret -> gotten from kwallet or secretservice dbus session eg: c1nTCJlU5p//wEOI/qVNOg==
  if (g_verbose) std::cout << "Password: '" << secret << "'" << std::endl;






  // derive decryption key from secret:
  ////
  ////  crypto::SymmetricKey::DeriveKeyFromPasswordUsingPbkdf2(
  ////    crypto::SymmetricKey::AES, password, salt /* = "saltysalt" */, kEncryptionIterations /* = 1*/, kDerivedKeySizeInBits /* = 128 NOTE BITS NOT BYTES */));

  // set the salt
  uint64_t salt_length = 9;
  unsigned char salt[] = "saltysalt";
  if (g_verbose) std::cout << "Salt: " << bepaald::bytesToHexString(salt, salt_length) << std::endl;

  // perform the KDF
  uint64_t key_length = 16;
  std::unique_ptr<unsigned char []> key(new unsigned char[key_length]);
#if defined (__APPLE__) && defined (__MACH__)
  int iterations = 1003;
#else // linux
  int iterations = 1;
#endif
  if (PKCS5_PBKDF2_HMAC_SHA1(reinterpret_cast<char const *>(secret.data()), secret.size(), salt, salt_length, iterations, key_length, key.get()) != 1)
  {
    std::cout << "Error deriving key from password" << std::endl;
    return decryptedkey;
  }
  if (g_verbose) std::cout << "Derived key: " << bepaald::bytesToHexString(key.get(), key_length) << std::endl;




  // set encrypted key data
  uint64_t data_length = encryptedkeystr.size() / 2;
  std::unique_ptr<unsigned char []> data(new unsigned char[data_length]);
  bepaald::hexStringToBytes(encryptedkeystr, data.get(), data_length);
  if (g_verbose) std::cout << "Data: " << bepaald::bytesToHexString(data.get(), data_length) << std::endl;

  // check header
#if defined (__APPLE__) && defined (__MACH__)
  unsigned char version_header[3] = {'v', '1', '0'};
#else // linux
  unsigned char version_header[3] = {'v', '1', '1'};
#endif
  if (std::memcmp(data.get(), version_header, 3) != 0) [[unlikely]]
    std::cout << "WARNING: Unexpected header value: " << bepaald::bytesToHexString(data.get(), 3) << std::endl;


  // set iv
  uint64_t iv_length = 16;
  unsigned char iv[] = "                "; // 16 spaces...
  if (g_verbose) std::cout << "IV: " << bepaald::bytesToHexString(iv, iv_length) << std::endl;




  // init cipher and context
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), &::EVP_CIPHER_CTX_free);
  if (!ctx)
  {
    std::cout << "Failed to create decryption context" << std::endl;
    return decryptedkey;
  }

  // init decrypt
  if (!EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr, key.get(), iv)) [[unlikely]]
  {
    std::cout << "Failed to initialize decryption operation" << std::endl;
    return decryptedkey;
  }

  // disable padding ?
  EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

  // decrypt update
  int out_len = 0;
  int output_length = data_length - 3;
  std::unique_ptr<unsigned char[]> output(new unsigned char[output_length]);
  if (EVP_DecryptUpdate(ctx.get(), output.get(), &out_len, data.get() + 3, output_length) != 1)
  {
    std::cout << "error update" << std::endl;
    return decryptedkey;
  }

  // decrypt final
  int tail_len = 0;
  int err = 0;
  if ((err = EVP_DecryptFinal_ex(ctx.get(), output.get() + out_len, &tail_len)) != 1)
  {
    std::cout << "error final" << std::endl;
    std::cout << err << std::endl;
    return decryptedkey;
  }
  out_len += tail_len;
  //std::cout << out_len << std::endl;

  if (g_verbose) std::cout << "Decrypted: " << bepaald::bytesToHexString(output.get(), output_length) << std::endl;

  // maybe check the tail
  // all input is always padding to the _next_ mutliple of 16 (64 in this case to 80)
  // the padding bytes are always the size of the padding (see below)
  int padding = output_length % 16;
  int realsize = output_length - (padding ? padding : 16);

  //std::cout << output_length << std::endl;
  //std::cout << padding << std::endl;
  //std::cout << realsize << std::endl;
  for (int i = 0; i < (padding ? padding : 16); ++i)
    if ((int)output[realsize + i] != (padding ? padding : 16))
    {
      std::cout << "Decryption appears to have failed (padding bytes have unexpected value)" << std::endl;
      return std::string();
    }

  decryptedkey = bepaald::bytesToPrintableString(output.get(), realsize);
  if (decryptedkey.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789") != std::string::npos)
  {
    std::cout << "Failed to decrypt key correctly" << std::endl;
    return std::string();
  }

  return decryptedkey;
}

/*
  (spaces added in output before the padding)

[~] $ echo -ne "exactly 32 bytes exactly 32 byte" > input.txt ; openssl enc -aes-128-cbc -nosalt -e -in input.txt -K '2222233333232323' -iv '5a04ec902686fb05a6b7a338b6e07760' > output.txt ; openssl enc -nopad -aes-128-cbc -nosalt -d -in output.txt -K '2222233333232323' -iv '5a04ec902686fb05a6b7a338b6e07760' | xxd -ps -g 1 -c 64
65786163746c792033322062797465732065786163746c792033322062797465 10101010101010101010101010101010
[~] $ echo -ne "exactly 33 bytes exactly 33 bytes" > input.txt ; openssl enc -aes-128-cbc -nosalt -e -in input.txt -K '2222233333232323' -iv '5a04ec902686fb05a6b7a338b6e07760' > output.txt ; openssl enc -nopad -aes-128-cbc -nosalt -d -in output.txt -K '2222233333232323' -iv '5a04ec902686fb05a6b7a338b6e07760' | xxd -ps -g 1 -c 64
65786163746c792033332062797465732065786163746c79203333206279746573 0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
[~] $ echo -ne "exactly 34 bytes exactly 34 bytes " > input.txt ; openssl enc -aes-128-cbc -nosalt -e -in input.txt -K '2222233333232323' -iv '5a04ec902686fb05a6b7a338b6e07760' > output.txt ; openssl enc -nopad -aes-128-cbc -nosalt -d -in output.txt -K '2222233333232323' -iv '5a04ec902686fb05a6b7a338b6e07760' | xxd -ps -g 1 -c 64
65786163746c792033342062797465732065786163746c7920333420627974657320 0e0e0e0e0e0e0e0e0e0e0e0e0e0e
[~] $ echo -ne "exactly 35 bytes exactly 35 bytes e" > input.txt ; openssl enc -aes-128-cbc -nosalt -e -in input.txt -K '2222233333232323' -iv '5a04ec902686fb05a6b7a338b6e07760' > output.txt ; openssl enc -nopad -aes-128-cbc -nosalt -d -in output.txt -K '2222233333232323' -iv '5a04ec902686fb05a6b7a338b6e07760' | xxd -ps -g 1 -c 64
65786163746c792033352062797465732065786163746c792033352062797465732065 0d0d0d0d0d0d0d0d0d0d0d0d0d
[...]

[~] $ echo -ne "exactly 46 bytes exactly 46 bytes exactly 46 b" > input.txt ; openssl enc -aes-128-cbc -nosalt -e -in input.txt -K '2222233333232323' -iv '5a04ec902686fb05a6b7a338b6e07760' > output.txt ; openssl enc -nopad -aes-128-cbc -nosalt -d -in output.txt -K '2222233333232323' -iv '5a04ec902686fb05a6b7a338b6e07760' | xxd -ps -g 1 -c 64
65786163746c792034362062797465732065786163746c792034362062797465732065786163746c792034362062 0202
[~] $ echo -ne "exactly 47 bytes exactly 47 bytes exactly 47 by" > input.txt ; openssl enc -aes-128-cbc -nosalt -e -in input.txt -K '2222233333232323' -iv '5a04ec902686fb05a6b7a338b6e07760' > output.txt ; openssl enc -nopad -aes-128-cbc -nosalt -d -in output.txt -K '2222233333232323' -iv '5a04ec902686fb05a6b7a338b6e07760' | xxd -ps -g 1 -c 64
65786163746c792034372062797465732065786163746c792034372062797465732065786163746c79203437206279 01
[~] $ echo -ne "exactly 48 bytes exactly 48 bytes exactly 48 byt" > input.txt ; openssl enc -aes-128-cbc -nosalt -e -in input.txt -K '2222233333232323' -iv '5a04ec902686fb05a6b7a338b6e07760' > output.txt ; openssl enc -nopad -aes-128-cbc -nosalt -d -in output.txt -K '2222233333232323' -iv '5a04ec902686fb05a6b7a338b6e07760' | xxd -ps -g 1 -c 64
65786163746c792034382062797465732065786163746c792034382062797465732065786163746c7920343820627974 10101010101010101010101010101010

*/
