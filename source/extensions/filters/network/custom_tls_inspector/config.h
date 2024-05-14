#pragma once

#include "source/extensions/filters/network/common/factory_base.h"
#include "source/extensions/filters/network/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace CustomTlsInspector {

/**
 * Config registration for the connection limit filter. @see NamedNetworkFilterConfigFactory.
 */
class CustomTlsInspectorConfigFactory
    : public Server::Configuration::NamedNetworkFilterConfigFactory {
public:
  Network::FilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message&,
                               Server::Configuration::FactoryContext&) override;
    ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  std::string name() const override { return NetworkFilterNames::get().CustomTlsInspector; }
};

} // namespace CustomTlsInspectorFilter
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
