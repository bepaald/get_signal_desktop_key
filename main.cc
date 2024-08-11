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
  auto getKey = [](std::set<std::string> const &secrets, std::string const &encryptedkey, std::string &decrypted)
  {
    if (g_verbose) [[unlikely]]
      for (auto const &s : secrets)
        std::cout << "(Got secrets: " << s << ")" << std::endl;
    for (auto const &s : secrets)
    {
      decrypted = decryptKey_linux(s, encryptedkey);
      if (!decrypted.empty())
        return true;
    }
    return false;
  };

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
  if (g_verbose) [[unlikely]] std::cout << "(Encrypted key: " << encryptedkey << ")" << std::endl;

  std::set<std::string> secrets;
  std::string decrypted;

  // get secret from libsecret (should work on Gnome and KDE 6)
  getSecret_SecretService(&secrets);
  if (getKey(secrets, encryptedkey, decrypted)) // try what we got now (maybe we dont need to check kwallet)...
  {
    std::cout << " *** Decrypted key : " << decrypted << " ***" << std::endl;
    return 0;
  }

  // get secret from kwallet (should work on KDE 6)
  getSecret_Kwallet(6, &secrets);
  if (getKey(secrets, encryptedkey, decrypted))
  {
    std::cout << " *** Decrypted key : " << decrypted << " ***" << std::endl;
    return 0;
  }

  // get secret from kwallet (should work on KDE 5)
  getSecret_Kwallet(5, &secrets);
  if (getKey(secrets, encryptedkey, decrypted))
  {
    std::cout << " *** Decrypted key : " << decrypted << " ***" << std::endl;
    return 0;
  }

  if (secrets.empty())
  {
    std::cout << "Failed to get any secrets" << std::endl;
    return 1;
  }

  if (decrypted.empty())
  {
    std::cout << "Failed to decrypt valid key. :(" << std::endl;
    return 1;
  }

  return 1;
}
