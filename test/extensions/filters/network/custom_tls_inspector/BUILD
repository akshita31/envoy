load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
    "envoy_extension_cc_test_library",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_extension_cc_test(
    name = "custom_tls_inspector_test",
    srcs = ["custom_tls_inspector_test.cc"],
    extension_names = ["envoy.filters.network.custom_tls_inspector"],
    deps = [
        ":tls_utility_lib",
        "//source/common/http:utility_lib",
        "//source/common/network:default_socket_interface_lib",
        "//source/common/buffer:buffer_lib",
        "//source/extensions/filters/network/custom_tls_inspector:config",
        "//test/common/stats:stat_test_utility_lib",
        "//test/mocks/api:api_mocks",
        "//test/mocks/network:network_mocks",
        "//test/mocks/stats:stats_mocks",
        "//test/test_common:threadsafe_singleton_injector_lib",
    ],
)

envoy_extension_cc_test_library(
    name = "tls_utility_lib",
    srcs = ["custom_tls_utility.cc"],
    hdrs = ["custom_tls_utility.h"],
    external_deps = ["ssl"],
    extension_names = ["envoy.filters.network.custom_tls_inspector"],
    deps = [
        "//source/common/common:assert_lib",
    ],
)

envoy_extension_cc_test(
    name = "tls_inspector_integration_test",
    size = "large",
    extension_names = ["envoy.filters.network.custom_tls_inspector"],
    srcs = [
        "tls_inspector_integration_test.cc",
    ],
    data = [
        "//test/config/integration/certs",
    ],
    deps = [
        "//source/common/config:api_version_lib",
        "//source/common/event:dispatcher_includes",
        "//source/common/event:dispatcher_lib",
        "//source/common/network:utility_lib",
        "//source/extensions/access_loggers/file:config",
        "//source/extensions/filters/network/custom_tls_inspector:config",
       # "//source/extensions/filters/listener/tls_inspector:tls_inspector_lib",
        "//source/extensions/filters/network/echo:config",
        "//source/extensions/transport_sockets/tls:config",
        "//source/extensions/transport_sockets/tls:context_config_lib",
        "//source/extensions/transport_sockets/tls:context_lib",
        "//test/integration:integration_lib",
        "//test/mocks/runtime:runtime_mocks",
        "//test/mocks/secret:secret_mocks",
        "//test/test_common:utility_lib",
        "@envoy_api//envoy/config/bootstrap/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/cluster/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/access_loggers/file/v3:pkg_cc_proto",
    ],
)
