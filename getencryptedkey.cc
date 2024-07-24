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

#include <iostream>
#include <fstream>
#include <regex>

std::string getEncryptedKey(std::string const &configfile)
{
  //g_verbose = true;

  std::string ekey;

  std::ifstream config(configfile);
  if (!config.is_open())
  {
    std::cout << "Failed to open file '" << configfile << "' for reading" << std::endl;
    return ekey;
  }

  std::string line;
  std::regex keyregex("^\\s*\"encryptedKey\":\\s*\"([a-zA-Z0-9]+)\",?$");
  std::smatch m;
  bool found = false;
  while (std::getline(config, line))
  {
    if (g_verbose) std::cout << "Checking line: \"" << line << "\"... " << std::endl;
    if (std::regex_match(line, m, keyregex))
    {
      if (m.size() == 2) // m[0] is full match, m[1] is first submatch (which we want)
      {
        if (g_verbose) std::cout << "Matched!" << std::endl;
        found = true;
        break;
      }
      if (g_verbose) std::cout << std::endl;
    }
  }

  if (!found)
  {
    std::cout << "Failed to find encrypted key in config.json" << std::endl;
    return ekey;
  }

  ekey = m[1].str();
  if (g_verbose) std::cout << "Found encrypted key: " << ekey << std::endl;

  return ekey;
}
