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

std::string getSecret_SecretService()
{
  std::string secret;

  DBusCon dbuscon;
  if (!dbuscon.ok())
  {
    std::cout << "Error connecting to dbus session" << std::endl;
    return secret;
  }

  /* OPEN SESSION */
  if (g_verbose) std::cout << "[OpenSession]" << std::endl;
  dbuscon.callMethod("org.freedesktop.secrets",
                     "/org/freedesktop/secrets",
                     "org.freedesktop.Secret.Service",
                     "OpenSession",
                     {"plain",
                      DBusVariant{""}});
  std::string session_objectpath = dbuscon.get<std::string>("vo", 1);
  if (session_objectpath.empty())
  {
    std::cout << "Error getting session" << std::endl;
    return secret;
  }
  if (g_verbose) std::cout << " *** Session: " << session_objectpath << std::endl;

  // if constexpr (false)
  // {
  //   /* SEARCHITEMS */
  //   // note searching is of no use on KDE, the secret does not seem to have any attributes set.
  //   // so lets just get all items and inspect them
  //   std::cout << "[SearchItems(label:Chromium Keys/Chromium Safe Storage)]" << std::endl;
  //   dbuscon.callMethod("org.freedesktop.secrets",
  //                      "/org/freedesktop/secrets",
  //                      "org.freedesktop.Secret.Service",
  //                      "SearchItems",
  //                      {DBusDict{{"org.freedesktop.Secret.Collection.Label", "Chromium Keys/Chromium Safe Storage"},
  //                                {"Label", "Chromium Keys/Chromium Safe Storage"}}});
  // }

  // if constexpr (false)
  // {
  //   /* GET DEFAULT COLLECTION */
  //   // not necessary we can address the default directly (without knowing what it points to), through
  //   // the aliases/default path...
  //   std::cout << "[ReadAlias(default)]" << std::endl;
  //   dbuscon.callMethod("org.freedesktop.secrets",
  //                      "/org/freedesktop/secrets",
  //                      "org.freedesktop.Secret.Service",
  //                      "ReadAlias",
  //                      {"default"});
  // }

  /* UNLOCK THE DEFAULT COLLECTION */
  if (g_verbose) std::cout << "[Unlock]" << std::endl;
  dbuscon.callMethod("org.freedesktop.secrets",
                     "/org/freedesktop/secrets",
                     "org.freedesktop.Secret.Service",
                     "Unlock",
                     std::vector<DBusArg>{DBusArray{DBusObjectPath{"/org/freedesktop/secrets/aliases/default"}}});
  // This returns an array of already unlocked object paths (out of the input ones) and a prompt to unlock any locked ones.
  // if no collections need unlocking, the prompt is '/';
  std::string prompt = dbuscon.get<std::string>("aoo", 1);
  if (prompt.empty())
  {
    std::cout << "Error getting prompt" << std::endl;
    return secret;
  }
  if (g_verbose) std::cout << " *** Prompt: " << prompt << std::endl;

  if (prompt != "/")
  {
    /* REGISTER FOR SIGNAL */
    if (!dbuscon.matchSignal("member='Completed'"))
      std::cout << "WARN: Failed to register for prompt signal" << std::endl;

    /* PROMPT FOR UNLOCK */
    if (g_verbose) std::cout << "[Prompt]" << std::endl;
    dbuscon.callMethod("org.freedesktop.secrets",
                       prompt.c_str(),
                       "org.freedesktop.Secret.Prompt",
                       "Prompt",
                       {""}); // 'Platform specific window handle to use for showing the prompt.'

    /* WAIT FOR PROMPT COMPLETED SIGNAL */
    // note, we will not even check the signal contents (dismissed/result), since we check if we're
    // unlocked next anyway...
    if (!dbuscon.waitSignal(20, 2500, "org.freedesktop.Secret.Prompt", "Completed"))
      if (g_verbose) std::cout << "Failed to wait for unlock prompt..." << std::endl;
  }

  /* CHECK COLLECTION IS UNLOCKED NOW */
  dbuscon.callMethod("org.freedesktop.secrets",
                     "/org/freedesktop/secrets/aliases/default",
                     "org.freedesktop.DBus.Properties",
                     "Get",
                     {"org.freedesktop.Secret.Collection", "Locked"});
  bool islocked = dbuscon.get<bool>("v", 0, true);
  if (islocked)
  {
    std::cout << "Failed to unlock collection" << std::endl;
    return secret;
  }

  /* GET ITEMS */
  if (g_verbose) std::cout << "[GetItems]" << std::endl;
  dbuscon.callMethod("org.freedesktop.secrets",
                     "/org/freedesktop/secrets/aliases/default",
                     "org.freedesktop.DBus.Properties",
                     "Get",
                     {"org.freedesktop.Secret.Collection", "Items"});
  std::vector<std::string> items = dbuscon.get<std::vector<std::string>>("v", 0);
  if (items.empty())
  {
    std::cout << "Failed to get any items" << std::endl;
    return secret;
  }
  else
    if (g_verbose) std::cout << "Got " << items.size() << " items to check" << std::endl;

  std::vector<unsigned char> secret_bytes;
  for (auto const &item : items)
  {
    // check label
    dbuscon.callMethod("org.freedesktop.secrets",
                       item.c_str(),
                       "org.freedesktop.DBus.Properties",
                       "Get",
                       {"org.freedesktop.Secret.Item", "Label"});
    std::string label = dbuscon.get<std::string>("v", 0);
    if (g_verbose) std::cout << " *** Label: " << label << std::endl;

#if __cpp_lib_string_contains >= 202011L
    if ((label.contains("Chrome") || label.contains("Chromium")) &&
        (label.contains("Safe Storage") || label.contains("Keys")) &&
        (!label.contains("Control")))
#else
    if ((label.find("Chrome") != std::string::npos || label.find("Chromium") != std::string::npos) &&
        (label.find("Safe Storage") != std::string::npos || label.find("Keys") != std::string::npos) &&
        (label.find("Control") == std::string::npos))
#endif
    {
      /* GET SECRETS */
      if (g_verbose) std::cout << "[GetSecret]" << std::endl;
      dbuscon.callMethod("org.freedesktop.secrets",
                         item,
                         "org.freedesktop.Secret.Item",
                         "GetSecret",
                         {DBusObjectPath{session_objectpath}});
      /*
        The secret returned by SecretService is a struct:

          struct Secret {
            ObjectPath session ;
            Array<Byte> parameters ;
            Array<Byte> value ;
            String content_type ;
          };

        A struct has signature (oayays), the brackets meaning 'struct'. we want the 'value' (the second ay);
      */
      secret_bytes = dbuscon.get<std::vector<unsigned char>>("(oayays)", {0, 2});
      if (!secret_bytes.empty())
        break;
    }
  }

  if (secret_bytes.empty())
  {
    std::cout << "Failed to get secret..." << std::endl;
    return secret;
  }

  if (g_verbose)
  {
    std::cout << " *** SECRET: ";
    for (auto c : secret_bytes)
      std::cout << c;
    std::cout << std::endl;
  }

  /* LOCK COLLECTION */
  if (g_verbose) std::cout << "[Lock]" << std::endl;
  dbuscon.callMethod("org.freedesktop.secrets",
                     "/org/freedesktop/secrets",
                     "org.freedesktop.Secret.Service",
                     "Lock",
                     std::vector<DBusArg>{DBusArray{DBusObjectPath{"/org/freedesktop/secrets/aliases/default"}}});


  /* CLOSE SESSION */
  if (g_verbose) std::cout << "[Close]" << std::endl;
  dbuscon.callMethod("org.freedesktop.secrets",
                     session_objectpath.c_str(), //"/org/freedesktop/secrets",
                     "org.freedesktop.Secret.Session",
                     "Close");

  secret = {secret_bytes.begin(), secret_bytes.end()};
  return secret;
}
