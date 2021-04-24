// See the file  in the main distribution directory for copyright.

#include <zeek/zeek-config.h>

#include "NdpiDumper.h"
#include <iosource/Packet.h>
#include <iosource/BPF_Program.h>

#include <unistd.h>
#include <string>

#include <Event.h>

extern "C" {
#include "ndpi-util/ndpiUtil.h"
}

using namespace ZEEK_IOSOURCE_NS::ndpi;

NdpiDumper::~NdpiDumper()
	{
	//ndpiFreeFlow(flow);
	//ndpiDestroy();
	Close();
	}

void NdpiDumper::Open()
	{
	std::string command = "ndpiReader -i enp0s3 -m 5 -p " +  props.path + " >> /var/logs/current/ndpi.log"; 
	system(command.c_str());
	//original_main();
	Opened(props);
	}

void NdpiDumper::Close()
	{
	myfile.close();
	Closed();
	}

bool NdpiDumper::Dump(const Packet* pkt) 
	{
	const struct pcap_pkthdr phdr = { .ts = pkt->ts, .caplen = pkt->cap_len, .len = pkt->len };
	
	if(!first_packet_processed) 
		{	
		//flow = (ndpi_flow *)ndpiGetFlow(&phdr, pkt->data);
		first_packet_processed = true;
		}
	//int proto = ndpiPacketProcess(&phdr, pkt->data, flow);
	//myfile << getProtocolName(proto) + "\n";
		/*
	result := godpi.ClassifyFlow(flow)
	if result.Protocol != types.Unknown {
		fmt.Print(result)
		idCount++
		protoCounts[result.Protocol]++
	} else {
		fmt.Print("Could not identify")
	}
	if isNew {
		fmt.Println(" (new flow)")
	} else {
		fmt.Println()
	}
*/
	count++;
	
	return true;
	}

ZEEK_IOSOURCE_NS::PktDumper* NdpiDumper::Instantiate(const std::string& path, bool is_live)
	{
	return new NdpiDumper(path, is_live);
	}
