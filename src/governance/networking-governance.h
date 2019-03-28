// Copyright (c) 2018-2019 The NIX Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NIX_GOV_H
#define NIX_GOV_H

#include <serialize.h>
#include <uint256.h>

#include <stdexcept>
#include <vector>


#include <boost/asio.hpp>
#include <boost/bind.hpp>

class CGovernance;

//static const std::string GOVERNANCE_URL = "www.governance.nixplatform.io";
static const std::string GOVERNANCE_URL = "134.209.47.211";

// amount of time in second for how often to refresh proposals
static const uint64_t REFRESH_TIME = 60;

extern CGovernance g_governance;
extern uint64_t last_refresh_time;

enum RequestTypes
{
    SUBMISSIONS = 1,
};

struct Proposals{
    std::string name;
    std::string details;
    std::string address;
    std::string amount;
    std::string txid;
};

class CGovernance
{
public:
    CGovernance();
    ~CGovernance();

    void GetRequests(RequestTypes rType);
    void PostRequest(RequestTypes rType, std::string json);
    bool ready;

    //Get data
    std::string g_data;
    //Post data
    std::string p_data;

    std::vector<Proposals> proposals;

};

using boost::asio::ip::tcp;

typedef void(*HTTPRequestDataReceived)(char*, size_t);
typedef void(*HTTPRequestComplete)();

class HTTPGetRequest
{
public:
 HTTPGetRequest(
  boost::asio::io_service& io_service,
  std::string host,
  std::string relativeURL,
  HTTPRequestDataReceived receivedCB,
  HTTPRequestComplete completeCB);

 ~HTTPGetRequest();

public:
 void sendRequest();
 void postRequest(std::string json);

private:
 HTTPRequestDataReceived m_receivedCB;
 HTTPRequestComplete m_completeCB;

 std::string m_host;
 std::string m_relativeURL;

 tcp::socket m_socket;
 boost::asio::io_service &m_io_service;
 tcp::resolver m_resolver;

 boost::asio::streambuf m_request;
 boost::asio::streambuf m_response;

 void ReadData();
};

#endif // NIX_GOV_H
