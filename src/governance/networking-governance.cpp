// Copyright (c) 2018-2019 The NIX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "networking-governance.h"
#include <utiltime.h>


CGovernance g_governance;
uint64_t last_refresh_time = 0;

std::vector<char> g_data;

void ParseProposals(){

    while(g_governance.g_data.find("{") != std::string::npos){
        // check first proposal
        unsigned first = g_governance.g_data.find("{");
        unsigned last = g_governance.g_data.find("}");
        std::string propStr = g_governance.g_data.substr (first,last-first);

        // delete first proposal
        g_governance.g_data = g_governance.g_data.substr(last + 1);

        //  parse proposal and place into proposal list
        Proposals prop;
        first = propStr.find("\"name\":") + 8;
        last = propStr.find(",\"details\"") - 1;
        prop.name = propStr.substr (first,last-first);
        first = propStr.find("\"details\":") + 11;
        last = propStr.find(",\"address\"") - 1;
        prop.details = propStr.substr (first,last-first);
        first = propStr.find("\"address\":") + 11;
        last = propStr.find(",\"amount\"") - 1;
        prop.address = propStr.substr (first,last-first);
        first = propStr.find("\"amount\":") + 9;
        last = propStr.find(",\"txid\"");
        prop.amount = propStr.substr (first,last-first);
        first = propStr.find("\"txid\":") + 8;
        last = propStr.find("}") - 4;
        prop.txid = propStr.substr (first,last-first);
        g_governance.proposals.push_back(prop);
    }

}

void OnDataReceived(char* data, size_t dataLen)
{
    unsigned int oldSize = g_data.size();
    g_data.resize(oldSize + dataLen);
    memcpy(&g_data[oldSize], data, dataLen);
}

void OnRequestCompleted()
{
    // print contents of data we received back...
    g_data.push_back('\0');
    g_governance.g_data = std::string(g_data.begin(), g_data.end());
    g_governance.proposals.clear();
    ParseProposals();
    g_data.clear();
    g_governance.ready = true;
}

CGovernance::CGovernance():
    proposals(),
    g_data(),
    p_data()
{
    ready = false;
}

CGovernance::~CGovernance(){

}

void CGovernance::GetRequests(RequestTypes rType){

    boost::asio::io_service io_service;

    if(GetTime() < (REFRESH_TIME + last_refresh_time))
        return;

    last_refresh_time = GetTime();
    ready = false;

    std::string urlRequest = "";

    switch (rType) {
        case SUBMISSIONS: urlRequest = "/submissions/?format=json";
        default: break;
    }

    HTTPGetRequest req(
     io_service,
     GOVERNANCE_URL.c_str(),
     urlRequest.c_str(),
     OnDataReceived,
     OnRequestCompleted);

    req.sendRequest();

    io_service.run();
}

void CGovernance::PostRequest(RequestTypes rType, std::string json){

    boost::asio::io_service io_service;

    std::string urlRequest = "";

    switch (rType) {
        case SUBMISSIONS: urlRequest = "/submissions";
        default: break;
    }

    HTTPGetRequest req(
     io_service,
     GOVERNANCE_URL.c_str(),
     urlRequest.c_str(),
     OnDataReceived,
     OnRequestCompleted);


    req.postRequest(json);

    io_service.run();
}

HTTPGetRequest::HTTPGetRequest(boost::asio::io_service& io_service, std::string host, std::string clipURL, HTTPRequestDataReceived receivedCB, HTTPRequestComplete completeCB) :
    m_host(host),
    m_relativeURL(clipURL),
    m_io_service(io_service),
    m_socket(io_service),
    m_resolver(m_io_service),
    m_receivedCB(receivedCB),
    m_completeCB(completeCB)
{

}

HTTPGetRequest::~HTTPGetRequest()
{

}

void HTTPGetRequest::sendRequest()
{
    tcp::resolver::query query(m_host, "http");

    m_resolver.async_resolve(query,
                             [this](const boost::system::error_code& ec, tcp::resolver::iterator endpoint_iterator)
    {
        boost::asio::async_connect(m_socket, endpoint_iterator,
                                   [this](boost::system::error_code ec, tcp::resolver::iterator)
        {
            if (!ec)
            {
                std::ostream request_stream(&m_request);
                request_stream << "GET " << m_relativeURL << " HTTP/1.1\r\n";
                request_stream << "Host: " << m_host << "\r\n";
                request_stream << "Accept: */*\r\n";
                request_stream << "Content-Type: application/json\r\n";
                request_stream << "Connection: close\r\n\r\n";

                boost::asio::async_write(m_socket, m_request,
                                         [this](boost::system::error_code ec, std::size_t /*length*/)
                {
                    boost::asio::async_read_until(m_socket, m_response, "\r\n\r\n",
                                                  [this](boost::system::error_code ec, std::size_t length)
                    {
                        ReadData();
                    });
                });
            }
        });
    });
}

void HTTPGetRequest::postRequest(std::string json)
{
    tcp::resolver::query query(m_host, "http");

    m_resolver.async_resolve(query,
                             [this](const boost::system::error_code& ec, tcp::resolver::iterator endpoint_iterator)
    {
        boost::asio::async_connect(m_socket, endpoint_iterator,
                                   [this](boost::system::error_code ec, tcp::resolver::iterator)
        {
            if (!ec)
            {
                std::ostream request_stream(&m_request);
                request_stream << "POST " << m_relativeURL << " HTTP/1.1\r\n";
                request_stream << "Host: " << m_host << "\r\n";
                request_stream << "Accept: */*\r\n";
                request_stream << "Content-Type: application/json\r\n";
                //request_stream << "Content-Length: " << json.length() << "\r\n";
                request_stream << "Connection: close\r\n\r\n";
                //request_stream << json;

                boost::asio::async_write(m_socket, m_request,
                                         [this](boost::system::error_code ec, std::size_t /*length*/)
                {
                    boost::asio::async_read_until(m_socket, m_response, "\r\n\r\n",
                                                  [this](boost::system::error_code ec, std::size_t length)
                    {
                        ReadData();
                    });
                });
            }
        });
    });
}

void HTTPGetRequest::ReadData()
{
    boost::asio::async_read(m_socket, m_response, boost::asio::transfer_at_least(1),
                            [this](boost::system::error_code ec, std::size_t /*length*/)
    {
        size_t size = m_response.size();
        if (size > 0)
        {
            std::unique_ptr<char> buf(new char[size]);
            m_response.sgetn(buf.get(), size);

            m_receivedCB(buf.get(), size);
        }

        if (ec != boost::asio::error::eof)
        {
            ReadData();
            return;
        }

        m_socket.close();

        m_completeCB();
    });
}
