// Copyright (c) 2017-2018 The NIX Core developers

#include "netbase.h"
#include "ghostnodeconfig.h"
#include "util.h"
#include "chainparams.h"
#include "utilstrencodings.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

CGhostnodeConfig ghostnodeConfig;

void CGhostnodeConfig::add(std::string alias, std::string ip, std::string privKey, std::string txHash, std::string outputIndex) {
    CGhostnodeEntry cme(alias, ip, privKey, txHash, outputIndex);
    entries.push_back(cme);
}

bool CGhostnodeConfig::read(std::string& strErr) {
    int linenumber = 1;
    boost::filesystem::path pathGhostnodeConfigFile = GetGhostnodeConfigFile();
    boost::filesystem::ifstream streamConfig(pathGhostnodeConfigFile);
    LogPrintf("pathGhostnodeConfigFile=%s\n", pathGhostnodeConfigFile);

    if (!streamConfig.good()) {
        FILE* configFile = fopen(pathGhostnodeConfigFile.string().c_str(), "a");
        if (configFile != NULL) {
            std::string strHeader = "# Ghostnode config file\n"
                          "# Format: alias IP:port ghostnode_privatekey collateral_output_txid collateral_output_index\n"
                          "# Example: ghostnode1 127.0.0.1:8255 7Cqyr4U7GU7qVo5TE1nrfA8XPVqh7GXBuEBPYzaWxEhiRRDLZ5c 2bcd3c84c84f87eaa86e4e56834c92927a07f9e18718810b92e0d0324456a67c 1\n";
            fwrite(strHeader.c_str(), std::strlen(strHeader.c_str()), 1, configFile);
            fclose(configFile);
        }
        return true; // Nothing to read, so just return
    }

    for(std::string line; std::getline(streamConfig, line); linenumber++)
    {
        if(line.empty()) continue;
        LogPrintf("Read line=%s\n", line);
        std::istringstream iss(line);
        std::string comment, alias, ip, privKey, txHash, outputIndex;

        if (iss >> comment) {
            if(comment.at(0) == '#') continue;
            iss.str(line);
            iss.clear();
        }
        if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex)) {
            iss.str(line);
            iss.clear();
            if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex)) {
                strErr = _("Could not parse ghostnode.conf") + "\n" +
                        strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"";
                streamConfig.close();
                return false;
            }
        }

        int port = 0;
        std::string hostname = "";
        SplitHostPort(ip, port, hostname);
        if(port == 0 || hostname == "") {
            strErr = _("Failed to parse host:port string") + "\n"+
                    strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"";
            streamConfig.close();
            return false;
        }
        int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
        LogPrintf("mainnetDefaultPort=%s\n", mainnetDefaultPort);
        LogPrintf("Params().NetworkIDString()=%s\n", Params().NetworkIDString());
        LogPrintf("CBaseChainParams::MAIN=%s\n", CBaseChainParams::MAIN);
        if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
            if(port != mainnetDefaultPort) {
                strErr = _("Invalid port detected in ghostnode.conf") + "\n" +
                        strprintf(_("Port: %d"), port) + "\n" +
                        strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"" + "\n" +
                        strprintf(_("(must be %d for mainnet)"), mainnetDefaultPort);
                streamConfig.close();
                return false;
            }
        } else if(port == mainnetDefaultPort) {
            strErr = _("Invalid port detected in ghostnode.conf") + "\n" +
                    strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"" + "\n" +
                    strprintf(_("(%d could be used only on mainnet)"), mainnetDefaultPort);
            streamConfig.close();
            return false;
        }


        add(alias, ip, privKey, txHash, outputIndex);
    }

    streamConfig.close();
    return true;
}
