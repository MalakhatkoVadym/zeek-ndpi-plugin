// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <iosource/PktDumper.h>
#include "zeek-compat.h"

#include <iostream>
#include <fstream>

#include <queue>
#include <mutex>
#include <atomic>
#include <thread>
#include <sys/types.h> // for u_char

namespace ZEEK_IOSOURCE_NS::ndpi {

class NdpiDumper : public ZEEK_IOSOURCE_NS::PktDumper {
public:
	NdpiDumper(const std::string& path, bool is_live)
		{
		props.path = path;
		first_packet_processed = false;
		}

	virtual ~NdpiDumper();

	static PktDumper* Instantiate(const std::string& path, bool is_live);

	void AddPacketsToTemporaryQueue();

protected:
	// PktSrc interface.
	void Open() override;
    void Close() override;
    bool Dump(const Packet* pkt) override;

private:
	std::ofstream myfile;
	Properties props;
	struct ndpi_flow* flow;
	bool first_packet_processed;
	int64_t count;
};

} //namespace iosource
