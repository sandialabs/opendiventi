/*
 * A query session.
 * Reads a (n expected) range of keys to query on, asks TokuHandler
 * to perform the query, and sends the results back.
 */

#ifndef QUERY_SESSION_DIVENTI
#define QUERY_SESSION_DIVENTI

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <map>
#include <string>

// uint32_t MAX_BODY_SIZE = 2 << 22;

/*
Basic setup of classes. QuerySession has public methods for:
	interactions with other classes
	QuerySession(Toku...) is a constuctor
	~QuerySession does is a deconstuctor
	run() checks if querysession is stopped. If so, it restarts it
and private methods support these public methods
*/

class TokuHandler;
class KeyValuePair;
class Control;

class QuerySession{
public:
	QuerySession(Control *_control, boost::asio::ip::tcp::socket *_sock);
	~QuerySession();

	void run();

private:
	/*
		Initialize variables
			+ tkhandler: a pointer to class TokuHandler
			+ sock: the tcp socket of the connection
			+ req: the request
			+ res: used for formulating the response to the user
	*/

	Control *control;
	boost::asio::ip::tcp::socket *sock;
	boost::beast::http::request<boost::beast::http::string_body> req;
	std::shared_ptr<boost::beast::http::response<boost::beast::http::string_body>> res;
	boost::beast::flat_buffer buff;
	bool running;

	int type(std::map<std::string, std::string> &args);
	bool statistics(std::map<std::string, std::string> &args);
	bool validateQuery(std::map<std::string, std::string> &args);
	void resolveQuery();
	std::string formatRes(std::vector <KeyValuePair> *, int);
	void handleRead(boost::system::error_code ec, std::size_t bytes_transferred);
	void handleWrite(boost::system::error_code ec, std::size_t bytes_transferred);
	void doRead();
	void send(boost::beast::http::response<boost::beast::http::string_body>& msg);
	void error(boost::beast::http::status s, std::string what);
	std::map<std::string, std::string> parseURLArgs(std::string url);
};

#endif // QUERY_SESSION_DIVENTI
