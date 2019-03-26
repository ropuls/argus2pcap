
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>

#include <string>
#include <string_view>
#include <vector>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <optional>
#include "pcap.hpp"

using namespace std;

inline std::string trim(const std::string &s) {
	auto  wsfront = std::find_if_not(s.begin(), s.end(), [](int c) {return std::isspace(c); });
	return std::string(wsfront, std::find_if_not(s.rbegin(), std::string::const_reverse_iterator(wsfront), [](int c) {return std::isspace(c); }).base());
}

// take a copy
string_view trim(string_view s) {	
	while (s.empty() == false && std::isspace(s.front())) { s.remove_prefix(1); }
	while (s.empty() == false && std::isspace(s.back())) { s.remove_suffix(1); }
	return s;
}

bool starts_with(const string_view& str, const string_view& prefix) {
    return ((prefix.size() <= str.size()) && std::equal(prefix.begin(), prefix.end(), str.begin()));
}

// expects german date / time settings: 20.02.2019 13:50:57:172
struct timeval to_timeval(const string_view& datestr, const string_view& timestr) {
	tm rv = { 0, 0, 0, 0, 0, 0, 0 };

	if (3 != sscanf(datestr.data(), "%02d.%02d.%04d", &rv.tm_mday, &rv.tm_mon, &rv.tm_year)) {
		std::cerr << "unable to parse date: '" << datestr << "'" << std::endl;
		std::abort();
	}

	rv.tm_year -= 1900;

	int msec = 0;
	if (4 != sscanf(timestr.data(), "%02d:%02d:%02d:%03d", &rv.tm_hour, &rv.tm_min, &rv.tm_sec, &msec)) {
		std::cerr << "unable to parse time: '" << timestr << "'" << std::endl;
		std::abort();
	}

	return { mktime(&rv), msec * 100 };
}

enum class lmode {
	skip,
	hex,
	isdn
};



struct record {
public:
	timeval timestamp;
	bool is_network;
	vector<uint8_t> data;
};


int main(int argc, char *argv[]) {
	

    if (argc == 2) {
    }

	if (argc != 3) {
		printf("usage: %s infile outfile\n", argv[0]);
		return EXIT_FAILURE;
	}


	lmode mode = lmode::skip;
	string timestamp;
	ifstream is(argv[1]);

	if (!is) {
		std::cerr << strerror(errno) << std::endl;
		return EXIT_FAILURE;
	}

	eyesdn trace(argv[2]);

	string str;

	optional<record> current;

	while (getline(is, str))
	{
		string_view line = trim(string_view(str));

//std::cout << line << std::endl;

		size_t direction_offset;
		switch (mode) {
			case lmode::skip:
				if (starts_with(line, "--- ISDN-D-Kanal ---")) {
					mode = lmode::isdn;
				} else if (starts_with(line, "--- HEX-Daten ---")) {
					mode = lmode::hex;
				} else {
					continue;
				}
				break;

			case lmode::isdn:
				// watch out for packet number and timestamp
				static const char* DIRECTION_STR = "Richtung: ";
				static const char* NET_STR = "-> Netz";
				static const char* USR_STR = "-> Tln";

				direction_offset = line.find(DIRECTION_STR, 0);
				if (direction_offset != string_view::npos) {
					auto next = direction_offset + strlen(DIRECTION_STR);
					
					if (line.find(NET_STR, next) != string_view::npos) {
						current->is_network = true;
					} else if (line.find(USR_STR, next) != string_view::npos) {
						current->is_network = false;
					} else {
						std::cerr << "line: '" << line << "', offset: " << next <<  std::endl;
						throw std::runtime_error("unable to detect message direction");
					}

					continue;
				};


				if (starts_with(line, "Nr.")) {
					// '  Nr.   : 8         Datum   : 20.02.2019      Zeit: 13:50:57:172'
					
					// parse datetime from Datum and Zeit parameters
					static const char* DATE_STR = "Datum   : ";
					static const char* TIME_STR = "Zeit: ";
					auto date_offset = line.find(DATE_STR, 0);
					auto time_offset = line.find(TIME_STR, date_offset);

					if (date_offset == 0 || time_offset == 0) {
						throw std::runtime_error("unable to parse date/time\n");
					}

					auto datestr = line.substr(date_offset + strlen(DATE_STR), 10);
					auto timestr = line.substr(time_offset + strlen(TIME_STR), 12);

					// re-create record
					current.emplace();
					current->timestamp = to_timeval(datestr, timestr);

				} else if (line.empty()) {
					mode = lmode::skip; 
				};
				break;
		
			case lmode::hex:
				if (line.empty()) {
					// write packet
					trace.write_trace(current->timestamp, current->data.data(), current->data.size(), current->is_network);

#if 0
					std::cout << "->" << std::hex << setfill('0');					
					for (auto it = current->data.begin(); it != current->data.end(); ++it) {
						std::cout << std::setw(2) << static_cast<unsigned>(*it);
					}
					std::cout << std::endl;
#endif

//std::cout << std::endl;

					// clear current and re-set mode
					current.reset();
					mode = lmode::skip;
					continue;
				} else {
					if (!line.empty()) {
						std::string data = string(line.begin(), line.end());
						std::istringstream hex_chars_stream(data);
						unsigned int c;
						while (hex_chars_stream >> std::hex >> c) {
    						current->data.push_back(c);
						}
					}
				}
				break;

		}; // switch
	




		//cout << str << endl;
	}
	return 0;
}
