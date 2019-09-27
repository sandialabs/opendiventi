#ifndef SERVER_DIVENTI
#define SERVER_DIVENTI

#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>

class QuerySession;
class Control;

class Server{
public:
	Server(Control* _control, int numThreads = 1);
	Server(uint port, Control* _control, int numThreads = 1);
	~Server();

	void run();
	int listen(const std::string& ip, uint port);

private:
	boost::asio::io_service* ioserv;
	boost::asio::ip::tcp::acceptor* acceptor;
	boost::thread_group* workers;
	boost::asio::io_service::work* work;
	boost::asio::ip::tcp::socket* socket = nullptr;

	Control* control;
	QuerySession *qs = nullptr;

	void startWorker();
	void startAccept();
	void handleAccept(const boost::system::error_code& ec);
};

#endif