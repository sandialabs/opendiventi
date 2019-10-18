#include "Server.h"
#include "diventi.h"

#include "QuerySession.h"

#include <boost/lexical_cast.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

//constructor for if a port is not specified
Server::Server(Control *_control, int numThreads){
	control = _control;

	ioserv = new boost::asio::io_service;
	acceptor = new boost::asio::ip::tcp::acceptor(*ioserv);
	workers = new boost::thread_group;
	work = new boost::asio::io_service::work( *ioserv );

	for (int i = 0; i < numThreads + 1; i++){
		workers->create_thread( boost::bind(&Server::startWorker, this) );
	}

	debug(50, "# of Threads: %lu\n", workers->size());
}

//constructor for if port is specified
Server::Server(uint port, Control *_control, int numThreads){
	control = _control;

	ioserv = new boost::asio::io_service();
	acceptor = new boost::asio::ip::tcp::acceptor(*ioserv, 
		boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("0.0.0.0"), port)
		);
	workers = new boost::thread_group;
	work = new boost::asio::io_service::work( *ioserv );

	for (int i = 0; i < numThreads + 1; i++){
		workers->create_thread( boost::bind(&Server::startWorker, this) );
	}
	debug(50, "# of Threads: %lu\n", workers->size());
}

//deconstructor which removes data and shuts down Server threads
Server::~Server(){
	ioserv->stop();
	workers->join_all();
	if (acceptor->is_open()){
		acceptor->close(); 
	}
	delete acceptor;
	delete work;
	delete workers;
	delete ioserv;
	// here we delete the most recently allocated socket
	// this one will not have been given to a QuerySession
	delete socket;
}

void Server::run(){
	startAccept();
}
/*
	Function to set up an acceptor for queries
	called by run() to get the first query, and handleAccept()
*/
void Server::startAccept(){
	socket = new boost::asio::ip::tcp::socket(*ioserv);
	acceptor->async_accept(*socket, 
		boost::bind(&Server::handleAccept, this, boost::asio::placeholders::error)
		);
}
/*
	HandleAccept is the necessary function for the async_accept
	It does what needs to be done once it recieves a query (calls querySession)
*/
void Server::handleAccept(const boost::system::error_code& ec){
	if (!ec) {
		debug(10, "Connection accepted\n");
		//call querySession constructor with an argument of the socket
		qs = new QuerySession(control, socket);
		ioserv->post( boost::bind(&QuerySession::run, qs) );
	}
	else {
		// if handleAccept fails then kill off the most recent socket
		// this is because it won't be tied to a qs and will leak
		delete socket;
	}
	//After query finishes, get ready to recieve another
	startAccept();
}
/*
	Function for taking requests from clients
*/
int Server::listen(const std::string& ip, uint port){
	try{
		boost::asio::ip::tcp::endpoint endpt( boost::asio::ip::address::from_string( ip ), port);
		acceptor->open(endpt.protocol());
		acceptor->set_option( boost::asio::ip::tcp::acceptor::reuse_address(false) );
		acceptor->bind( endpt );
		acceptor->listen( boost::asio::socket_base::max_connections );
		return 0;
	} catch(std::exception& e){
		return 1;
	}
}
//start up the io_service as needed by the constructors
void Server::startWorker(){
	ioserv->run();
}
