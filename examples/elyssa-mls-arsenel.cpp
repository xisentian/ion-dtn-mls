//standard includes
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <fstream>
#include <sstream>
#include <time.h>
#include <chrono>

// ROS Includes
#include "ros/ros.h"
#include "std_msgs/UInt16.h"

// ARSENL Includes
#include "arsenl_msgs/PackedNetworkMessage.h"

// MLS Includes
#include <mls/credential.h>
#include <mls/crypto.h>
#include <mls/messages.h>
#include <mls/session.h>
#include <iostream>
#include <stdexcept>
#include <string>

//Networking Includes
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <boost/asio/ip/udp.hpp>


#define BUFSIZE 65534
using namespace mls;

enum PacketType: unsigned char
{
	JOIN,
	COMMIT,
	MESSAGE,
	WELCOME,
	TEST,
	HANDSHAKE,
	COMMITNEW,
	PROPOSAL
}p_t;




class MLSGroup {


	public:
		std::vector<Client> UAV_client;
		std::vector<Session> UAV_session;
		std::vector<PendingJoin> UAV_join;
		

		//ROS Callback functions
		ros::Subscriber join_mls_sub;
		ros::Publisher recv_msg_pub;
		ros::Subscriber send_msg_sub;
		ros::Subscriber init_mls_sub;
		
		//constructor
		MLSGroup(ros::NodeHandle *nh, int id, std::string device, int port);
		
		//Handle joining the swarm
		void newUAV(); 

		//invoked when another UAV wants to join the group
		void receiveJoinMLSMsg(const std_msgs::UInt16::ConstPtr& msg);

		//used to issue a key update for a member
		void update();

		//used to remove member from group
		void removeMember();

		//creates a client object needed for MLS group
		mls::Client create_client(CipherSuite suite, const std::string& name);

		//invoked when a message needs to be encrypted and sent to the swarm
		void receiveMLSMsg(const arsenl_msgs::PackedNetworkMessage::ConstPtr& msg);

		//invoked when a UAV wants to initialize the group
		void initMLS(const std_msgs::UInt16::ConstPtr& msg);

		//creates the socket used to broadcast messages to the swarm
		int create_socket();

		//threaded message to have a blocking read on the socket
		void readThread();

		//Opens the log file for writing
		bool openLogFile();
		
	private:
		int id;
		int port;
		socklen_t len, recvLen;
		struct sockaddr_in address, address_other;
		int sock_fd, recv_fd;
		std::string device;
		int message_count;
		int enc_message_count;
		int dec_message_count;
		int bytes_enc;
		int bytes_dec;
		int cipher_enc;
		int cipher_dec;
		ros::NodeHandle *nh;
		std::fstream logfile;
		time_t t;
		int timer_dur;
		int update_freq;


		//flag used to determine if UAV is in a group
		bool inGroup = false;

		//flag to determine if UAV has sent a proposal
		bool sentJoin = false;

		//flag to determine if UAV should add member
		bool addFlag = false;
		
		//buffer for send/receive
		char buffer[BUFSIZE];

		//function to serialize data to send over the socket
		char * serialize(bytes data, unsigned char packetType);

		//function to deserialize data received over the socket
		std::vector<uint8_t> deserialize(char* array,int length);

		//function to print statistics every 3 seconds
		void testData();

};

MLSGroup::MLSGroup(ros::NodeHandle *nodeh, int i, std::string d, int p)
{
	//how many messages sent between updates
	update_freq = 250;

	this->nh = nodeh;

	// This publisher sends decrypted messages over to the ARSENL code
	recv_msg_pub = nh->advertise<arsenl_msgs::PackedNetworkMessage>("mls/recv_mls_msg", 50);

	//this subscriber starts the mls group when UAV in flight ready state
	init_mls_sub = nh->subscribe("mls/init_mls", 50, &MLSGroup::initMLS, this);

	//create client
	std::string s = std::to_string(id);
	const auto suite = CipherSuite{ CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 };
	UAV_client.push_back(create_client(suite, s));

	
    	try
    	{
		this->id = i;
		this->device = d; 
		this->port = p;

		//log every 3 seconds
		timer_dur = 3;
		
		this->len = sizeof(address);
		sock_fd = create_socket();	
		ROS_INFO("CREATED SOCKETS");
		int  n;
				
		//loop for ROS callbacks
		ros::spin();

	}
	catch(std::exception &e) {
		ROS_WARN_STREAM("Somewhere in group ");
		ROS_WARN_STREAM(e.what());
	}

}


void MLSGroup::newUAV() 
{
	int n;

	//wait for handshake (UAV - 1 received message)
	while(ros::ok())
	{
		ros::spinOnce();
		//read from socket
		int errnum;
		//ROS_INFO("waiting handshake");
		n = recvfrom(sock_fd, buffer, BUFSIZE, 0, ( struct sockaddr *) &address_other, (socklen_t*)&len);
		if (n == -1)
		{
			errnum = errno;
			ROS_WARN_STREAM("Issue waiting for handshake");
		}
		else{
			if(buffer[0] == HANDSHAKE)
			{
				if(static_cast<int>(buffer[1]) == id)
				{
					break;
				}
			}
		}
	}
	ROS_INFO("received handshake");
	UAV_join.push_back(UAV_client[0].start_join());
	p_t = JOIN;
	
	char * data = serialize(UAV_join[0].key_package(), p_t);

	int sent = sendto(sock_fd, data, UAV_join[0].key_package().size()+1, MSG_CONFIRM, (const struct sockaddr *) &address, len);
	if(sent < 0)
	{
		ROS_WARN_STREAM("issue sending key package");

	}
		
	//wait for welcome
	while(ros::ok())
	{
		ros::spinOnce();
		//read from socket
		int errnum;
		n = recvfrom(sock_fd, buffer, BUFSIZE, 0, ( struct sockaddr *) &address_other, (socklen_t*)&len);
		if (n == -1)
		{
			errnum = errno;
			ROS_WARN_STREAM("Issue waiting for welcome");
		}
		else{
			if(buffer[0] == WELCOME)
			{
				break;
			}
		}
	}

	if(buffer[0] == WELCOME)
	{
		//process welcome
		if(inGroup == false)
		{
			std::vector<uint8_t> welcome = deserialize(buffer, n);
			UAV_session.push_back(UAV_join[0].complete(welcome));
			inGroup = true;
			ROS_INFO("Processed Welcome");
		}
	}
}


void MLSGroup::initMLS(const std_msgs::UInt16::ConstPtr& msg)
{
	auto t1 = std::chrono::high_resolution_clock::now();
	openLogFile();
	if(msg->data == 0)
	{
		//initialize group needs to be in first UAV
		auto group_id = bytes{0,1,2,3};
		ROS_INFO("Starting group");
		UAV_session.push_back(UAV_client[0].begin_session(group_id));
	}	
	else
	{
		ROS_INFO("Joining group");
		newUAV();
	}
	auto t2 = std::chrono::high_resolution_clock::now();
	logfile << std::chrono::duration_cast<std::chrono::milliseconds>(t2-t1).count() << " milliseconds\n";
	//now can receive MLS messages since in group
	// Topic used by the network node when other vehicles request to join MLS
	join_mls_sub = nh->subscribe("mls/recv_join_mls_msg", 50, &MLSGroup::receiveJoinMLSMsg, this);
	// Topic used by the network node for unencrypted messages for MLS send
	send_msg_sub = nh->subscribe("mls/send_mls_msg", 50, &MLSGroup::receiveMLSMsg, this);

	//start thread to handle all socket reads
	boost::thread rts(&MLSGroup::readThread, this);

	//start timer for testing statistics
	message_count = 0;
	enc_message_count = 0;
	dec_message_count = 0;
	bytes_enc = 0;
	cipher_enc = 0;
	bytes_dec = 0;
	cipher_dec = 0;
	t = time(0);
	

}

void MLSGroup::receiveJoinMLSMsg(const std_msgs::UInt16::ConstPtr& msg) 
{
	ROS_INFO("MLS Logging Received Join in class");
	//send handshake 
	int len = sizeof(address);
	uint8_t UAVtoAdd = static_cast<char>(msg->data); 
	bytes empty;
	empty.push_back(UAVtoAdd);
	auto data = serialize(empty, HANDSHAKE);
	addFlag = true;
	int sent = sendto(sock_fd, data, 2, MSG_CONFIRM, (const struct sockaddr *) &address, len);
	ROS_INFO("SENT HANDSHAKE");
		
}

mls::Client MLSGroup::create_client(CipherSuite suite, const std::string& name)
{
  auto id = bytes(name.begin(), name.end());
  auto sig_priv = SignaturePrivateKey::generate(suite);
  auto cred = Credential::basic(id, suite, sig_priv.public_key);

  auto ext_list = ExtensionList{};
  ext_list.add(KeyIDExtension{ bytes(name.begin(), name.end()) });

  return Client(suite, sig_priv, cred, { { ext_list } });
}

//callback function for message to be sent via MLS
//automatically invoked when UAV wants to send traffic
void MLSGroup::receiveMLSMsg(const arsenl_msgs::PackedNetworkMessage::ConstPtr& msg) 
{
	auto encrypted = UAV_session[0].protect(msg->msg_bytes);

	//send message over the socket
	auto data = serialize(encrypted, MESSAGE);
	int sent = sendto(sock_fd, data, encrypted.size()+1, MSG_CONFIRM, (const struct sockaddr *) &address, len);
	if(sent > 0) {

		ROS_INFO("MLS Logging: Send Encrypted Message");

		//update key periodically 
		message_count++;
		
		if(message_count == update_freq)
		{
			message_count = 0;
			//update();
		}

		enc_message_count += 1;
		bytes_enc += msg->msg_bytes.size();
		cipher_enc += encrypted.size();
	}
	else {
		perror("Socket not sending encryption");
		ROS_WARN_STREAM("Socket failed");
	}
}

void MLSGroup::update()
{
	auto update = UAV_session[0].update();
	auto [_1, update_commit] = UAV_session[0].commit({update});
	silence_unused(_1);
	UAV_session[0].handle(update_commit);
	ROS_INFO("MLS Logging: Updated Key");

	//send message over the socket
	
	auto data = serialize(update, PROPOSAL);
	int sent = sendto(sock_fd, data, update.size()+1, MSG_CONFIRM, (const struct sockaddr *) &address, len);
	if(sent > 0) {

		ROS_INFO("MLS Logging: Send Update Message");
	}
	else {
		perror("Socket not sending update");
		ROS_WARN_STREAM("Socket failed");
	}

	data = serialize(update_commit, COMMIT);
	sent = sendto(sock_fd, data, update_commit.size()+1, MSG_CONFIRM, (const struct sockaddr *) &address, len);
	if(sent > 0) {

		ROS_INFO("MLS Logging: Send Update commit Message");
	}
	else {
		perror("Socket not sending update commit");
		ROS_WARN_STREAM("Socket failed");
	}
}

void MLSGroup::removeMember()
{
	auto remove = UAV_session[0].remove(1);
	auto [_2, remove_commit] = UAV_session[0].commit({remove});
	silence_unused(_2);
	UAV_session[0].handle(remove_commit);
	ROS_INFO("MLS Logging: Removed Member");

	//send message over the socket
	
	auto data = serialize(remove, PROPOSAL);
	int sent = sendto(sock_fd, data, remove.size()+1, MSG_CONFIRM, (const struct sockaddr *) &address, len);
	if(sent > 0) {

		ROS_INFO("MLS Logging: Send Remove Message");
	}
	else {
		perror("Socket not sending remove");
		ROS_WARN_STREAM("Socket failed");
	}

	data = serialize(remove_commit, COMMIT);
	sent = sendto(sock_fd, data, remove_commit.size()+1, MSG_CONFIRM, (const struct sockaddr *) &address, len);
	if(sent > 0) {

		ROS_INFO("MLS Logging: Send Remove Commit");
	}
	else {
		perror("Socket not sending remove commit");
		ROS_WARN_STREAM("Socket failed");
	}
}

bool MLSGroup::openLogFile()
{
	//open file for all mls logging
	t = time(0);
	struct tm * now = localtime( & t);
	std::stringstream ss;
	ss << "/home/arsenl/Desktop/mls_logs/UAV" << id << "-" << (now->tm_year+1900) << "-"
	       << (now->tm_mon+1) << "-" << (now->tm_mday)  
	       << "-" << (now->tm_hour%12) << "-" << (now->tm_min) << "-update"
	       << update_freq << ".csv";
	ROS_WARN_STREAM(ss.str());
	logfile.open(ss.str(), std::fstream::out);
	if(logfile.is_open())
	{
		ROS_INFO("log file created for test statistics");
		//logfile << "Writing to file test\n";
		return true;
	}
	else
	{
		ROS_WARN_STREAM("Log file not created");
		return false;
	}
	//logfile.close();		
}


int MLSGroup::create_socket()
{

	//create the socket needed to communicate between UAVs
	int sock_fd, new_socket, valread;
	struct ifreq ifr;
	
	//creating the socket file descriptor (IPV4, UDP, default protocol)
	if ((sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	//if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("Creating socket failed");
	}
	int i = 1;

	if(setsockopt(sock_fd, SOL_SOCKET, SO_BROADCAST, &i, sizeof(int)) <0)
	{
		perror("setsockopt(broadcast) failed");
	}

	//help with bind fail, address in use, but this makes it so large messages are not sent??????
	if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &i, sizeof(int)) <0)
	{
			perror("setsockopt(reuse port) failed");
	}

	//change port number for mls uses
	port += 11;
	

	try
	{
		memset(&address, 0, sizeof(address));
		address.sin_family = AF_INET;
		//assign port
		address.sin_port = htons(port);

		//assign ip (broadcast IP)
		int n = device.length();
		char iface[n+1];
		strcpy(iface, device.c_str());
		//want ipv4 address
		ifr.ifr_addr.sa_family = AF_INET;
		//want ip attached to this name
		strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
		ioctl(sock_fd, SIOCGIFBRDADDR, &ifr);
		
		address.sin_addr.s_addr = ((struct sockaddr_in *)&ifr.ifr_broadaddr)->sin_addr.s_addr;

		//sock addr to read
		address_other.sin_family = AF_INET;
    	address_other.sin_port = (in_port_t) htons(port);
    	address_other.sin_addr.s_addr = htonl(INADDR_ANY);

	}
	catch(std::exception &e) {
		ROS_WARN_STREAM("exception in socket");
	}


	if(bind(sock_fd, (struct sockaddr *)&address, (socklen_t)len) < 0)
	{
		//perror("binding failed");
		ROS_WARN_STREAM("ERROR EXITING");
		//exit(1);
	}

	return sock_fd;
}

char * MLSGroup::serialize(bytes data, unsigned char packetType)
{
	int size = data.size();
	size++;
	data.insert(data.begin(),packetType);
	char* array = (char*)malloc(size);
	for(int i = 0; i < size; i++) {
		array[i] = data[i];
		//printf("%u", array[i]);
	}
	
	return array;
}

std::vector<uint8_t> MLSGroup::deserialize(char* array,int length)
{
	std::vector<uint8_t> data(length);
	for(int i = 0; i < length; i++)
	{
		try
		{
			data[i] = array[i];
		}
		catch (...) {
			ROS_WARN_STREAM("Exception in deserialize");
		}
	}
	data.erase(data.begin());

	return data;
}

//function for blocking read thread
void MLSGroup::readThread()
{
	int n = 0;

	while(ros::ok())
	{
		ros::spinOnce();
		try
		{
			//check if 3 second passed to print statistics
			if(time(0)-t >= timer_dur)
			{
				testData();
				t = time(0);
			}


			//read from socket
			int errnum;
			n = recvfrom(sock_fd, buffer, BUFSIZE, 0, ( struct sockaddr *) &address_other, &len);

			if (n < 0)
			{
				errnum = errno;
				ROS_WARN_STREAM("WARNING RECEIVED");
			}

			if(buffer[0] == JOIN && addFlag == true) 
			{
				ROS_INFO("Added new member");
				bytes kp_data = deserialize(buffer, n);
			
				auto new_member = UAV_session[0].add(kp_data);
				auto [welcome, commit] = UAV_session[0].commit({new_member});
				UAV_session[0].handle(commit);

				ROS_INFO("Sending new member");
				auto data = serialize(new_member, COMMITNEW);
				int sent = sendto(sock_fd, data, new_member.size()+1, MSG_CONFIRM, (const struct sockaddr *) &address, len);

				ROS_INFO("Sending new member commit");
				data = serialize(commit, COMMIT);
				sent = sendto(sock_fd, data, commit.size()+1, MSG_CONFIRM, (const struct sockaddr *) &address, len);

				errnum = 0;
				data = serialize(welcome, WELCOME);
				sent = sendto(sock_fd, data, welcome.size()+1, MSG_CONFIRM, (const struct sockaddr *) &address, len);
				errnum = errno;
				ROS_INFO("Sent Welcome to New Member");
				//reset flag
				addFlag = false;
				
			}

			if(buffer[0] == MESSAGE) 
			{
				bytes encrypted_data = deserialize(buffer, n);
				auto decrypted = UAV_session[0].unprotect(encrypted_data);
				arsenl_msgs::PackedNetworkMessage msg;
				msg.msg_bytes = decrypted;
				recv_msg_pub.publish(msg);
				dec_message_count += 1;
				bytes_dec += decrypted.size();
				cipher_dec += encrypted_data.size();
				ROS_INFO("Decrypted message");
			}
			
			if(buffer[0] == COMMITNEW)
			{
				bytes new_member = deserialize(buffer, n);
				UAV_session[0].handle(new_member);
				ROS_INFO("Handle new member");
			}
			if(buffer[0] == COMMIT)
			{
				bytes commit_message = deserialize(buffer, n);
				UAV_session[0].handle(commit_message);
				ROS_INFO("Handle Commit");
			}
			if(buffer[0] == PROPOSAL)
			{
				bytes proposal = deserialize(buffer, n);
				UAV_session[0].handle(proposal);
				ROS_INFO("Handle Proposal");
			}
		}
	
		catch(std::exception &e) {
			ROS_WARN_STREAM("Error in Receiving Message");
			ROS_WARN_STREAM(e.what());
		}
	}
	ROS_WARN_STREAM("ROS is not okay");

			
}

void MLSGroup::testData()
{
	ROS_INFO("Printing testing statistics to file");
	//number of encryption operations
	logfile << enc_message_count << ", ";
	//Bytes of data to encrypt
	logfile << bytes_enc << ", ";
	//bytes of ciphertext sending
	logfile << cipher_enc << ", ";
	//Number of decryption operations
	logfile << dec_message_count << ", ";
	//Bytes of data to decrypted
	logfile << bytes_dec << ", ";
	//bytes of ciphertext received
	logfile << cipher_dec << std::endl;

	enc_message_count = 0;
	dec_message_count = 0;
	bytes_enc = 0;
	bytes_dec = 0;
	cipher_enc = 0;
	cipher_dec = 0;

}

int main(int argc, char** argv) // NOLINT(bugprone-exception-escape)
{
	
	int id, port;
	//argv[2] == id
	id = std::stoi(argv[2]);
	//argv[4] == network device
	std::string device = argv[4];
	//argv[6] == port 
	port = std::stoi(argv[6]);
	
	
	ros::init(argc, argv, "mls");
	ros::NodeHandle mls_node;

	MLSGroup uav(&mls_node, id, device, port);

    return 0;
}
