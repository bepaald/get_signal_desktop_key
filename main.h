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

#ifndef MAIN_H_
#define MAIN_H_

#include "globals.h"

#include <set>
#include <string>

using std::literals::string_literals::operator""s;

std::string getEncryptedKey(std::string const &configfile);

void getSecret_SecretService(std::set<std::string> *secrets);
void getSecret_Kwallet(int version, std::set<std::string> *secrets);

std::string decryptKey_linux_mac(std::string const &secret, std::string const &encrypted_key);

#endif
