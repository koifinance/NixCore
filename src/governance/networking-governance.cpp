// Copyright (c) 2018-2019 The NIX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <governance/networking-governance.h>
#include <utiltime.h>
#include <ostream>
#include <iostream>
#include <string>
#include <util.h>

CGovernance g_governance;
uint64_t last_refresh_time = 0;

std::vector<char> g_data;

void ParseProposals(){
    while(g_governance.g_data.find("{") != std::string::npos){
        bool isPost = g_governance.isPost;
        // check first proposal
        unsigned first = g_governance.g_data.find("{");
        unsigned last = g_governance.g_data.find("}");
        std::string propStr = g_governance.g_data.substr (first,last-first);

        // delete first proposal
        g_governance.g_data = g_governance.g_data.substr(last + 1);

        //  parse proposal and place into proposal list
        if(!isPost){
            Proposals prop;
            first = propStr.find("\"voteid\":") + 10;
            last = propStr.find(",\"name\"") - 1;
            prop.vote_id = propStr.substr (first,last-first);
            first = propStr.find("\"name\":") + 8;
            last = propStr.find(",\"date\"") - 1;
            prop.name = propStr.substr (first,last-first);
            first = propStr.find("\"date\":") + 7;
            last = propStr.find(",\"expiration\"");
            prop.start_time = propStr.substr (first,last-first);
            first = propStr.find("\"expiration\":") + 13;
            last = propStr.find(",\"details\"");
            prop.end_time = propStr.substr (first,last-first);
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
            last = propStr.find(",\"affirm\"") - 1;
            prop.txid = propStr.substr (first,last-first);
            first = propStr.find("\"affirm\":") + 9;
            last = propStr.find(",\"oppose\"");
            prop.votes_affirm = propStr.substr (first,last-first);
            first = propStr.find("\"oppose\":") + 9;
            last = propStr.find("}") - 3;
            prop.votes_oppose = propStr.substr (first,last-first);
            g_governance.proposals.push_back(prop);
        }
        else{
            Votes prop;
            first = propStr.find("\"voteid\":") + 10;
            last = propStr.find(",\"address\"") - 1;
            prop.vote_id = propStr.substr (first,last-first);
            first = propStr.find("\"address\":") + 11;
            last = propStr.find(",\"signature\"") - 1;
            prop.address = propStr.substr (first,last-first);
            first = propStr.find("\"signature\":") + 13;
            last = propStr.find(",\"ballot\"") - 1;
            prop.signature = propStr.substr (first,last-first);
            first = propStr.find("\"ballot\":") + 8;
            last = propStr.find(",\"weight\"");
            prop.vote = propStr.substr (first,last-first);
            first = propStr.find("\"weight\":") + 9;
            last = propStr.find("}") - 3;
            prop.weight = propStr.substr (first,last-first);
            g_governance.votes.push_back(prop);
        }
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
    if(g_governance.isPost)
        g_governance.votes.clear();
    else
        g_governance.proposals.clear();

    ParseProposals();
    g_data.clear();
    g_governance.setReady();
}


void OnRequestFailed()
{
    g_data.clear();
    g_governance.statusOK = false;
    g_governance.setReady();
}

CGovernance::CGovernance():
    proposals(),
    g_data()
{
    ready = false;
    isPost = false;
}

CGovernance::~CGovernance(){

}

void CGovernance::SendRequests(RequestTypes rType, std::string json){

    std::string urlRequest = "";
    bool isGet = true;

    isPost = false;
    switch (rType) {
        case GET_PROPOSALS: {
            urlRequest = "/proposals/?format=json";
            break;
        }
        case GET_VOTES: {
            urlRequest = "/votes/?format=json";
            break;
        }
        case CAST_VOTE: {
            urlRequest = "/cast/";
            isGet = false;
            isPost = true;
            break;
        }
        default: {
            urlRequest = "/proposals/?format=json";
            break;
        }
    }

    if(isGet){
        if(GetTime() < (REFRESH_TIME + last_refresh_time))
            return;

        last_refresh_time = GetTime();
    }

    ready = false;

    boost::asio::io_service io_service;
    boost::asio::ssl::context context(boost::asio::ssl::context::sslv23);
    context.set_verify_mode(boost::asio::ssl::verify_peer);
    context.set_default_verify_paths();

    HTTPGetRequest req(
     io_service,
     GOVERNANCE_URL.c_str(),
     urlRequest.c_str(),
     OnDataReceived,
     OnRequestCompleted,
     context,
     json);

    req.sendRequest(isGet);

    io_service.run();
}

HTTPGetRequest::HTTPGetRequest(boost::asio::io_service& io_service, std::string host, std::string clipURL,
                               HTTPRequestDataReceived receivedCB, HTTPRequestComplete completeCB,
                               boost::asio::ssl::context& context, std::string jsonPost) :
    m_host(host),
    m_relativeURL(clipURL),
    m_io_service(io_service),
    m_socket(io_service),
    m_resolver(m_io_service),
    m_receivedCB(receivedCB),
    m_completeCB(completeCB),
    m_postURL(jsonPost),
    m_ssl_socket(io_service, context)
{
}

HTTPGetRequest::~HTTPGetRequest()
{
}

void HTTPGetRequest::sendRequest(bool isGet)
{
    std::ostream request_stream(&m_request);
    if(isGet)
        request_stream << "GET " << m_relativeURL << " HTTP/1.1\r\n";
    else
        request_stream << "POST " << m_relativeURL << " HTTP/1.1\r\n";
    request_stream << "Host: " << m_host << "\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Content-Type: application/json\r\n";
    if(isGet)
        request_stream << "Connection: close\r\n\r\n";
    else{
        request_stream << "Content-Length: " << std::to_string(m_postURL.length()) << "\r\n\r\n";
        request_stream << m_postURL;
    }

    tcp::resolver::query query(m_host, "https");

    m_resolver.async_resolve(query,
                            boost::bind(&HTTPGetRequest::HandleResolve, this,
                                        boost::asio::placeholders::error,
                                        boost::asio::placeholders::iterator));
}

void HTTPGetRequest::HandleResolve(const boost::system::error_code& err,
                    tcp::resolver::iterator endpoint_iterator)
{
    if (!err)
    {
        //LogPrintf("HTTPGetRequest::HandleResolve(): Resolve OK \n");
        m_ssl_socket.set_verify_mode(boost::asio::ssl::verify_peer);
        m_ssl_socket.set_verify_callback(
                    boost::bind(&HTTPGetRequest::VerifyCertificate, this, _1, _2));

        boost::asio::async_connect(m_ssl_socket.lowest_layer(), endpoint_iterator,
                                   boost::bind(&HTTPGetRequest::HandleConnect, this,
                                               boost::asio::placeholders::error));
    }
    else
    {
        OnRequestFailed();
        LogPrintf("HTTPGetRequest::HandleResolve(): Error resolve: %s \n", err.message());
    }
}

bool HTTPGetRequest::VerifyCertificate(bool preverified,
                        boost::asio::ssl::verify_context& ctx)
{
    // The verify callback can be used to check whether the certificate that is
    // being presented is valid for the peer. For example, RFC 2818 describes
    // the steps involved in doing this for HTTPS. Consult the OpenSSL
    // documentation for more details. Note that the callback is called once
    // for each certificate in the certificate chain, starting from the root
    // certificate authority.

    // In this example we will simply print the certificate's subject name.
    char subject_name[256];
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
    //LogPrintf("HTTPGetRequest::VerifyCertificate(): Verifying: %s \n", std::string(subject_name));

    return preverified;
}

void HTTPGetRequest::HandleConnect(const boost::system::error_code& err)
{
    if (!err)
    {
        //LogPrintf("HTTPGetRequest::HandleConnect(): Connect OK \n");
        m_ssl_socket.async_handshake(boost::asio::ssl::stream_base::client,
                                boost::bind(&HTTPGetRequest::HandleHandshake, this,
                                            boost::asio::placeholders::error));
    }
    else
    {
        OnRequestFailed();
        LogPrintf("HTTPGetRequest::HandleConnect(): Connect failed: %s \n", err.message());
    }
}

void HTTPGetRequest::HandleHandshake(const boost::system::error_code& error)
{
    if (!error)
    {
        const char* header=boost::asio::buffer_cast<const char*>(m_request.data());

        //LogPrintf("HTTPGetRequest::HandleHandshake(): Handshake OK. Request = \n%s \n", std::string(header));

        // The handshake was successful. Send the request.
        boost::asio::async_write(m_ssl_socket, m_request,
                                 boost::bind(&HTTPGetRequest::HandleWriteRequest, this,
                                             boost::asio::placeholders::error));
    }
    else
    {
        OnRequestFailed();
        LogPrintf("HTTPGetRequest::HandleHandshake(): Handshake failed: %s \n", error.message());
    }
}

void HTTPGetRequest::HandleWriteRequest(const boost::system::error_code& err)
{
    if (!err)
    {
        //LogPrintf("HTTPGetRequest::HandleWriteRequest() \n");
        // Read the response status line. The response_ streambuf will
        // automatically grow to accommodate the entire line. The growth may be
        // limited by passing a maximum size to the streambuf constructor.
        boost::asio::async_read_until(m_ssl_socket, m_response, "\r\n",
                                      boost::bind(&HTTPGetRequest::HandleReadStatus, this,
                                                  boost::asio::placeholders::error));
    }
    else
    {
        OnRequestFailed();
        LogPrintf("HTTPGetRequest::HandleWriteRequest(): Error write req: %s \n", err.message());
    }
}

void HTTPGetRequest::HandleReadStatus(const boost::system::error_code& err)
{
    if (!err)
    {
        // Check that response is OK.
        std::istream response_stream(&m_response);
        std::string http_version;
        response_stream >> http_version;
        unsigned int status_code;
        response_stream >> status_code;
        std::string status_message;
        std::getline(response_stream, status_message);
        if (!response_stream || http_version.substr(0, 5) != "HTTP/")
        {
            LogPrintf("HTTPGetRequest::HandleReadStatus(): Invalid response \n");
            OnRequestFailed();
        }
        if (status_code != 200 && status_code != 201 && status_code != 202 && status_code != 400)
        {
            LogPrintf("HTTPGetRequest::HandleReadStatus(): status code error: %d \n", status_code);
            OnRequestFailed();
        }

        //LogPrintf("HTTPGetRequest::HandleReadStatus(): status code: %d \n", status_code);

        g_governance.statusOK = true;

        // Read the response headers, which are terminated by a blank line.
        boost::asio::async_read_until(m_ssl_socket, m_response, "\r\n\r\n",
                                      boost::bind(&HTTPGetRequest::HandleReadHeaders, this,
                                                  boost::asio::placeholders::error));
    }
    else
    {
        OnRequestFailed();
        LogPrintf("HTTPGetRequest::HandleReadStatus(): Error: %s \n", err.message());
    }
}

void HTTPGetRequest::HandleReadHeaders(const boost::system::error_code& err)
{
    if (!err)
    {
        // Process the response headers.
        std::istream response_stream(&m_response);
        std::string header;
        //LogPrintf("HTTPGetRequest::HandleReadHeaders(): \n");
        while (std::getline(response_stream, header) && header != "\r") {}

        // Start reading remaining data until EOF.
        boost::asio::async_read(m_ssl_socket, m_response,
                                boost::asio::transfer_at_least(1),
                                boost::bind(&HTTPGetRequest::HandleReadContext, this,
                                            boost::asio::placeholders::error));
    }
    else
    {
        OnRequestFailed();
        LogPrintf("HTTPGetRequest::HandleReadHeaders(): Error: %s \n", err.message());
    }
}

void HTTPGetRequest::HandleReadContext(const boost::system::error_code& err)
{
    if (!err)
    {
        size_t size = m_response.size();
        if (size > 0)
        {
            std::unique_ptr<char> buf(new char[size]);
            m_response.sgetn(buf.get(), size);

            OnDataReceived(buf.get(), size);
        }

        //LogPrintf("HTTPGetRequest::HandleReadContext(): reading context\n");

        // Continue reading remaining data until EOF.
        boost::asio::async_read(m_ssl_socket, m_response,
                                boost::asio::transfer_at_least(1),
                                boost::bind(&HTTPGetRequest::HandleReadContext, this,
                                            boost::asio::placeholders::error));
    }
    else if (err != boost::asio::error::eof)
    {
        LogPrintf("HTTPGetRequest::HandleReadContext(): Error: %s \n", err.message());
        OnRequestFailed();
    }
    // final loop
    else{
        //LogPrintf("HTTPGetRequest::HandleReadContext(): finished! \n");
        OnRequestCompleted();
    }
}
