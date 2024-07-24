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

#include <iostream>
#include <cstdlib>

#include "main.h"
#include "dbuscon.h"

bool g_verbose;

int main(int argc, char *argv[])
{
  // arg handling
  g_verbose = false;
  std::string signal_config_file(std::getenv("HOME"));
  signal_config_file += "/.config/Signal/config.json";
  for (int i = 1; i < argc; ++i)
  {
    if (argv[i] == "-v"s)
      g_verbose = true;
    else
      signal_config_file = argv[i];
  }

  // get encrypted key from Signal Desktop config
  std::string encryptedkey = getEncryptedKey(signal_config_file);
  if (encryptedkey.empty())
  {
    std::cout << "Failed to get encrypted key" << std::endl;
    return 1;
  }
  std::cout << "(Encrypted key: " << encryptedkey << ")" << std::endl;

  // get secret
  std::string secret = getSecret_SecretService();
  if (secret.empty())
    secret = getSecret_Kwallet(6);
  if (secret.empty())
    secret = getSecret_Kwallet(5);
  if (secret.empty())
  {
    std::cout << "Failed to get secret" << std::endl;
    return 1;
  }
  std::cout << "(Got secret: " << secret << ")" << std::endl;

  std::string decrypted = decryptKey_linux(secret, encryptedkey);
  if (decrypted.empty())
  {
    std::cout << "Failed to decrypt key" << std::endl;
    return 1;
  }

  std::cout << "Decrypted: " << decrypted << std::endl;
  return 0;
}
