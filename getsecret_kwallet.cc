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

#include "dbuscon.h"

void getSecret_Kwallet(int version, std::set<std::string> *secrets)
{
  if (!secrets)
    return;

  DBusCon dbuscon;
  if (!dbuscon.ok())
  {
    std::cout << "Error connecting to dbus session" << std::endl;
    return;
  }

  std::string destination("org.kde.kwalletd" + std::to_string(version));
  std::string path("/modules/kwalletd" + std::to_string(version));
  std::string interface("org.kde.KWallet");

  /* GET WALLET */
  if (g_verbose) std::cout << "[networkWallet]" << std::endl;
  dbuscon.callMethod(destination.c_str(),
                     path.c_str(),
                     interface.c_str(),
                     "networkWallet");
  std::string walletname = dbuscon.get<std::string>("s", 0);
  if (walletname.empty())
  {
    std::cout << "Failed to get wallet name" << std::endl;
    return;
  }
  if (g_verbose) std::cout << " *** Wallet name: " << walletname << std::endl;

  // ON KDE THE 'open' METHOD SEEMS TO BLOCK FOR PASSWORD PROMPT BY ITSELF...
  // /* Register to wait for opening wallet */
  // if (!matchSignal("member='walletOpened'"))
  //   std::cout << "WARN: Failed to register for signal" << std::endl;

  /* OPEN WALLET */
  if (g_verbose) std::cout << "[open]" << std::endl;
  dbuscon.callMethod(destination.c_str(),
                     path.c_str(),
                     interface.c_str(),
                     "open",
                     {walletname, 0ll /*(int64) window id*/, "signalbackup-tools"});
  int32_t handle = dbuscon.get<int32_t>("i", 0 - 1);
  if (handle < 0)
  {
    std::cout << "Failed to open wallet" << std::endl;
    return;
  }
  if (g_verbose) std::cout << " *** Handle: " << handle << std::endl;



  /* GET FOLDERS */
  if (g_verbose) std::cout << "[folderList]" << std::endl;
  dbuscon.callMethod(destination.c_str(),
                     path.c_str(),
                     interface.c_str(),
                     "folderList",
                     {handle, "signalbackup-tools"});
  std::vector<std::string> folders = dbuscon.get<std::vector<std::string>>("as", 0);
  if (folders.empty())
  {
    std::cout << "Failed to get any folders from wallet" << std::endl;
    return;
  }

  for (auto const &folder : folders)
  {
#if __cpp_lib_string_contains >= 202011L
    if ((folder.contains("Chrome") || folder.contains("Chromium")) &&
        (folder.contains("Safe Storage") || folder.contains("Keys")))
#else
    if ((folder.find("Chrome") != std::string::npos || folder.find("Chromium") != std::string::npos) &&
        (folder.find("Safe Storage") != std::string::npos || folder.find("Keys") != std::string::npos))
#endif
    {
      /* GET PASSWORD */
      if (g_verbose) std::cout << "[passwordList]" << std::endl;
      dbuscon.callMethod(destination.c_str(),
                         path.c_str(),
                         interface.c_str(),
                         "passwordList",
                         {handle, folder, "signalbackup-tools"});
      /*
        The password list returns a dict (dicts are always (in) an array as per dbus spec)
        the signature is a{sv} -> the v in our case is a string again, pretty much a map<std::string, std::string>,

        The value we want seems to have the key "Chrom[e|ium] Safe Storage"...
      */
      std::map<std::string, std::string> passwordmap = dbuscon.get<std::map<std::string, std::string>>("a{sv}", 0);

      if (passwordmap.empty())
      {
        std::cout << "Failed to get password map" << std::endl;
        return;
      }

      for (auto const &e : passwordmap)
        if (e.first == "Chromium Safe Storage" || e.first == "Chrome Safe Storage")
          secrets->insert(e.second);
    }
  }


  /* CLOSE WALLET */
  if (g_verbose) std::cout << "[close (wallet)]" << std::endl;
  dbuscon.callMethod(destination.c_str(),
                     path.c_str(),
                     interface.c_str(),
                     "close",
                     {walletname, false});

  /* CLOSE SESSION */
  if (g_verbose) std::cout << "[close (session)]" << std::endl;
  dbuscon.callMethod(destination.c_str(),
                     path.c_str(),
                     interface.c_str(),
                     "close",
                     {handle, false, "signalbackup-tools"});



  return;
}
