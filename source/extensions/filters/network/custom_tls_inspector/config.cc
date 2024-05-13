#include <string>

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/network/custom_tls_inspector/custom_tls_inspector.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace CustomTlsInspector {

Network::FilterFactoryCb CustomTlsInspectorConfigFactory::createFilterFactoryFromProto(
    const Protobuf::Message& message, Server::Configuration::FactoryContext& context) {

    // downcast it to the TLS inspector config
    const auto& proto_config = MessageUtil::downcastAndValidate<
    const envoy::extensions::filters::network::custom_tls_inspector::v3::CustomTlsInspector&>(
        message, context.messageValidationVisitor());

    ConfigSharedPtr config = std::make_shared<Config>(context.scope(), proto_config);
    return [config](Network::FilterManager& filter_manager) -> void {
    filter_manager.addReadFilter(std::make_shared<Filter>(config));
  };
}

ProtobufTypes::MessagePtr CustomTlsInspectorConfigFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::filters::network::custom_tls_inspector::v3::CustomTlsInspector>();
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
