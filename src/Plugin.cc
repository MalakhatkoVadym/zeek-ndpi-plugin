// See the file  in the main distribution directory for copyright.

#include "NdpiDumper.h"
#include "Plugin.h"
#include <zeek/plugin/Plugin.h>
#include <zeek/iosource/Component.h>

namespace ZEEK_PLUGIN_NS { namespace Zeek_Ndpi { Plugin plugin; } }

using namespace ZEEK_PLUGIN_NS::Zeek_Ndpi;
using namespace ZEEK_IOSOURCE_NS;


ZEEK_PLUGIN_NS::Configuration Plugin::Configure()
		{
		AddComponent(new PktDumperComponent("NdpiDumper", "ndpi", ndpi::NdpiDumper::Instantiate));

		ZEEK_PLUGIN_NS::Configuration config;
		config.name = "Zeek::Ndpi";
		config.description = "Packet dumping to ndpi for protocol analyzing";
		return config;
		}
