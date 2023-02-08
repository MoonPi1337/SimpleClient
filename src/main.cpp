#include <iostream>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/screen/string.hpp>
#include <ftxui/screen/color.hpp>
#include <ftxui/dom/node.hpp>
#include <ftxui/dom/canvas.hpp>
#include <ftxui/component/captured_mouse.hpp>  // for ftxui
#include <ftxui/component/component.hpp>  // for Slider, Checkbox, Vertical, Renderer, Button, Input, Menu, Radiobox, Toggle
#include <ftxui/component/component_base.hpp>  // for ComponentBase
#include <ftxui/component/screen_interactive.hpp>

#include "Message.hpp"

#include <json/json.hpp>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/steady_timer.hpp>

#include <thread>


class TcpClient : public std::enable_shared_from_this<TcpClient>{
	boost::asio::io_context context;
	boost::asio::ip::tcp::socket socket;

	std::deque<std::string> rx{},tx{};
public:
	TcpClient(const std::string& ip, const uint16_t& port = 1337):socket(context){
		socket.connect({boost::asio::ip::address::from_string(ip),port});
	}
	
	void disconnect(){
		socket.close();
	}

	void send(const std::string& msg){
		tx.push_back(msg+"\n");
	}

	bool hasPackets(){
		return !rx.empty();
	}

	std::string get(){
		if(hasPackets()){
			auto a = rx.front();
			rx.pop_front();
			return a;
		}
		return "";
	}

	bool is_open(){
		return socket.is_open();
	}

	void start(){
		if(socket.is_open()){
			std::thread t([self = shared_from_this()]{
				try{
				while(self->socket.is_open()){
					if(!self->tx.empty()){
						boost::asio::write(self->socket,boost::asio::buffer(self->tx.front()));
						self->tx.pop_front();
					}
				}
				}
				catch(std::exception& e){

				}
			});
			std::thread j([self = shared_from_this()]{
				try{
				while(self->socket.is_open()){
					std::string line;
					auto n = boost::asio::read_until(self->socket,boost::asio::dynamic_buffer(line,8192),'\n');
					self->rx.push_back(line.substr(0,n));
				}
				}
				catch(std::exception& e){

				}
			});
			t.detach();
			j.detach();
		}else{
			throw std::runtime_error("Failed to create connection!");
		}
	}

};

auto main() -> int{
	auto screen = ftxui::ScreenInteractive::TerminalOutput();

	std::string pKey, sKey, receiver, ip;
	static std::vector<std::string> strings = {""};
	static int selected = 0;

	std::string msg;
	std::string chat;

	std::unique_ptr<sEC> sender;
	std::unique_ptr<pEC> rec;

	std::shared_ptr<TcpClient> client;

	auto component = ftxui::Container::Vertical(
		{
			ftxui::Input(&pKey,""),
			ftxui::Input(&sKey,""),
			ftxui::Input(&receiver,""),
			ftxui::Input(&ip,""),
			ftxui::Button("Connect",[&]{

				try{
					sender = std::make_unique<sEC>(sKey,pKey);
				}
				catch(std::exception& ex){
					pKey = sKey = "Error in " + std::string(ex.what());
				}

				try{
					rec = std::make_unique<pEC>(receiver);
				}catch(std::exception& ex){
					receiver = "Error in " + std::string(ex.what());
				}
				try{
					if(client){
						if(client->is_open()){
							client->disconnect();
						}
					}
					client = std::make_shared<TcpClient>(ip);
					client->start();
				}
				catch(std::exception& ex){
					ip = ex.what();
				}
			}),
			ftxui::Input(&msg,""),
			ftxui::Button("Send",[&]{
				strings.push_back("You: " + msg);
				msg.resize(16*((msg.size()+15)/16));

				std::vector<unsigned char> info(msg.begin(),msg.end());
				const auto iv = GenerateIV();
				const auto key = sender->Exchange(*rec);
				auto data = aes256_cbc_enc(info,key,iv);
				Message _msg{sender->GetKey(),*rec,data,iv,std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())};
				auto sig = sender->Sign(_msg.GetHash());
				_msg.signature = sig;

				nlohmann::json response;
    			response["sender"] = sender->GetPkey();
    			response["receiver"] = rec->GetPkey();
    			response["data"] = data;
    			response["iv"] = iv;
    			response["timestamp"] = _msg.timestamp;
    			response["signature"] = sig;

				client->send(response.dump());
				msg = "";
			}),
			ftxui::Button("I don't have a key",[&]{
				sender = std::make_unique<sEC>();
				pKey = sender->GetPkey();
				sKey = sender->GetSKey();
			}),
			ftxui::Radiobox(&strings,&selected)
		}
	);

	auto renderer = ftxui::Renderer(component,[&]{
		if(strings.size()>10){
			strings.erase(strings.begin(),strings.begin()+5);
		}
		if(client){
			while(client->hasPackets()){
				//strings.push_back(client->get());
				auto j = nlohmann::json::parse(client->get());
				if(j.contains("sender") && j.contains("receiver") && j.contains("data") && j.contains("iv") && 
					j.contains("signature") && j.contains("timestamp") && 
					j["iv"].size()==16 && j["signature"].size()==2)
				{
					std::string _sender = j["sender"];
					std::string _receiver = j["receiver"];
					if(_sender == rec->GetPkey() && _receiver == sender->GetPkey()){
						std::vector<unsigned char> data = j["data"];
						std::array<unsigned char,16> iv = j["iv"];
						std::array<std::string,2> signature = j["signature"];
						time_t timestamp = j["timestamp"];

						Message myMsg{pEC(_sender),pEC(_receiver),data,iv,timestamp,signature};
						if(myMsg.Verify()){
							auto vec = myMsg.DecryptViaReceiver(*sender);
							std::string str(vec.begin(),vec.end());
							strings.push_back("companion: " + str);
						}
					}
					
				}
			}
		}
		return ftxui::vbox({
			ftxui::text("Welcome to SimpleClient!"),
			ftxui::separator(),
			ftxui::hbox(ftxui::text("Your public key: "), component->ChildAt(0)->Render()),
			ftxui::hbox(ftxui::text("Your secret key: "), component->ChildAt(1)->Render()),
			ftxui::hbox(ftxui::text("Receiver public key: "), component->ChildAt(2)->Render()),
			ftxui::hbox(ftxui::text("IP address: "), component->ChildAt(3)->Render()),
			ftxui::separator(),
			ftxui::hbox(component->ChildAt(4)->Render()),
			ftxui::hbox(component->ChildAt(7)->Render()),
			ftxui::separator(),
			ftxui::text("Chat"),
			ftxui::separator(),
			ftxui::hbox(component->ChildAt(8)->Render()),
			ftxui::hbox(ftxui::text("Write a message: "),component->ChildAt(5)->Render()),
			component->ChildAt(6)->Render()
		}) | ftxui::border;
	});

	screen.Loop(renderer);

	return 0;
}
