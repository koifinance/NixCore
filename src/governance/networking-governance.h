// Copyright (c) 2018-2019 The NIX Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NIX_GOV_H
#define NIX_GOV_H

#include <serialize.h>
#include <uint256.h>
#include <amount.h>
#include <univalue.h>

#include <stdexcept>
#include <vector>


#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/asio/ssl.hpp>

//#define USING_SSL

class CGovernance;

static const std::string GOVERNANCE_URL = "gov.nixplatform.io";

// amount of time in second for how often to refresh proposals
static const uint64_t REFRESH_TIME = 5;

extern CGovernance g_governance;
extern uint64_t last_refresh_time;

enum RequestTypes
{
    GET_PROPOSALS = 1,
    GET_VOTES = 2,
    CAST_VOTE = 3
};

struct Proposals{
    std::string vote_id;
    std::string name;
    std::string details;
    std::string address;
    std::string amount;
    std::string txid;
    std::string start_time;
    std::string end_time;
    std::string votes_affirm;
    std::string votes_oppose;
    std::string weight;
    std::string signature;
    std::string vote;

    UniValue toJSONString()
    {
        UniValue result(UniValue::VOBJ);
        result.pushKV("vote_id", vote_id);
        result.pushKV("name", name);
        result.pushKV("details", details);
        result.pushKV("address", address);
        result.pushKV("amount", amount);
        result.pushKV("txid", txid);
        result.pushKV("start_time",start_time);
        result.pushKV("end_time", end_time);
        result.pushKV("votes_affirm", votes_affirm);
        result.pushKV("votes_oppose", votes_oppose);

        return result;
    }
};

struct Votes{
    std::string vote_id;
    std::string address;
    std::string signature;
    std::string vote;
    std::string weight;

    UniValue toJSONString()
    {
        UniValue result(UniValue::VOBJ);
        result.pushKV("vote_id", vote_id);
        result.pushKV("address", address);
        result.pushKV("signature", signature);
        result.pushKV("vote", vote);
        result.pushKV("weight", weight);

        return result;
    }
};

class CGovernance
{
private:
    bool ready;

public:
    CGovernance();
    ~CGovernance();

    void SendRequests(RequestTypes rType, std::string json = "");
    //data
    std::string g_data;
    bool statusOK;
    bool isPost;

    std::vector<Proposals> proposals;
    std::vector<Votes> votes;

    bool isReady(){return ready;}
    void setReady(){ready = true;}

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
  HTTPRequestComplete completeCB,
  boost::asio::ssl::context& context,
  std::string jsonPost = "");

 ~HTTPGetRequest();

public:
 void sendRequest(bool isGet);

private:
 HTTPRequestDataReceived m_receivedCB;
 HTTPRequestComplete m_completeCB;

 std::string m_host;
 std::string m_relativeURL;
 std::string m_postURL;
#ifdef USING_SSL
 boost::asio::ssl::stream<boost::asio::ip::tcp::socket> m_socket;
#else
 tcp::socket m_socket;
#endif
 boost::asio::io_service &m_io_service;
 tcp::resolver m_resolver;

 boost::asio::streambuf m_request;
 boost::asio::streambuf m_response;

 void HandleResolve(const boost::system::error_code& err,
                     tcp::resolver::iterator endpoint_iterator);
 bool VerifyCertificate(bool preverified,
                        boost::asio::ssl::verify_context& ctx);
 void HandleConnect(const boost::system::error_code& err);
 void HandleHandshake(const boost::system::error_code& error);
 void HandleWriteRequest(const boost::system::error_code& err);
 void HandleReadStatus(const boost::system::error_code& err);
 void HandleReadHeaders(const boost::system::error_code& err);
 void HandleReadContext(const boost::system::error_code& err);


};

class CGovernanceEntry
{
public:
    CAmount voteWeight;
    std::string voteID;

    CGovernanceEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        voteWeight = 0;
        voteID.clear();
    }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(voteWeight);
        READWRITE(voteID);
    }
};

#endif // NIX_GOV_H
