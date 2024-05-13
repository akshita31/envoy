#pragma once

#include "envoy/extensions/filters/network/connection_limit/v3/connection_limit.pb.h"
#include "envoy/extensions/filters/network/connection_limit/v3/connection_limit.pb.validate.h"

#include "source/extensions/filters/network/common/factory_base.h"
#include "source/extensions/filters/network/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace CustomTlsInspectorFilter {

/**
 * Config registration for the connection limit filter. @see NamedNetworkFilterConfigFactory.
 */
class CustomTlsInspectorConfigFactory
    : public Common::FactoryBase<
          envoy::extensions::filters::network::custom_tls_inspector::v3::CustomTlsInspector> {
public:
  CustomTlsInspectorConfigFactory() : FactoryBase(NetworkFilterNames::get().CustomTlsInspector) {}

private:
  Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::custom_tls_inspector::v3::CustomTlsInspector& proto_config,
      Server::Configuration::FactoryContext& context) override;
};

} // namespace CustomTlsInspectorFilter
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
