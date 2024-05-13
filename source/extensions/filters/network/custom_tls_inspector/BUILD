load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

# Connection limit L4 network filter
# Public docs: https://envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/connection_limit_filter

envoy_extension_package()

envoy_cc_library(
    name = "custom_tls_inspector_lib",
    srcs = ["custom_tls_inspector.cc"],
    hdrs = ["custom_tls_inspector.h"],
    deps = [
        "//envoy/event:dispatcher_interface",
        "//envoy/network:filter_interface",
        "//envoy/runtime:runtime_interface",
        "//envoy/stats:stats_macros",
        "//source/common/protobuf:utility_lib",
        "//source/common/runtime:runtime_lib",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        "//source/extensions/filters/network:well_known_names",
        "//source/extensions/filters/network/common:factory_base_lib",
        "//source/extensions/filters/network/custom_tls_inspector:custom_tls_inspector_lib"
    ],
)
