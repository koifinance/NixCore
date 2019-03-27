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

static const std::string GOVERNANCE_URL = "134.209.47.211";

extern CGovernance g_governance;

enum RequestTypes
{
    SUBMISSIONS = 1,
};

class CGovernance
{
    //Get data
    std::vector<char> g_data;
    //Post data
    std::vector<char> p_data;

public:
    CGovernance();
    ~CGovernance();

    void GetRequests(RequestTypes rType);

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
