#include <string>

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/network/custom_tls_inspector/custom_tls_inspector.h"
#include "source/extensions/filters/network/custom_tls_inspector/config.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace CustomTlsInspector {

Network::FilterFactoryCb CustomTlsInspectorConfigFactory::createFilterFactoryFromProto(
    const Protobuf::Message&, Server::Configuration::FactoryContext& context) {

    ConfigSharedPtr config = std::make_shared<Config>(context.scope());
    return [config](Network::FilterManager& filter_manager) -> void {
    filter_manager.addReadFilter(std::make_shared<Filter>(config));
  };
}

ProtobufTypes::MessagePtr CustomTlsInspectorConfigFactory::createEmptyConfigProto() {
  return ProtobufTypes::MessagePtr{new Envoy::ProtobufWkt::Struct()};
}

/**
 * Static registration for the custom tls network filter. @see RegisterFactory.
 */
REGISTER_FACTORY(CustomTlsInspectorConfigFactory,
                 Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace CustomTlsInspector
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
