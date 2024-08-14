#pragma once

#include "envoy/event/file_event.h"
#include "envoy/event/timer.h"
#include "envoy/network/filter.h"
#include "envoy/stats/histogram.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"
#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace CustomTlsInspector {

/**
 * All stats for the TLS inspector. @see stats_macros.h
 */
#define ALL_TLS_INSPECTOR_STATS(COUNTER, HISTOGRAM)                                                \
  COUNTER(client_hello_too_large)                                                                  \
  COUNTER(tls_found)                                                                               \
  COUNTER(tls_not_found)                                                                           \
  COUNTER(alpn_found)                                                                              \
  COUNTER(alpn_not_found)                                                                          \
  COUNTER(sni_found)                                                                               \
  COUNTER(sni_not_found)                                                                           \
  HISTOGRAM(bytes_processed, Bytes)

/**
 * Definition of all stats for the TLS inspector. @see stats_macros.h
 */
struct TlsInspectorStats {
  ALL_TLS_INSPECTOR_STATS(GENERATE_COUNTER_STRUCT, GENERATE_HISTOGRAM_STRUCT)
};

enum class ParseState {
  // Parse result is out. It could be tls or not.
  Done,
  // Parser expects more data.
  Continue,
  // Parser reports unrecoverable error.
  Error
};
/**
 * Global configuration for TLS inspector.
 */
class Config {
public:
  Config(Stats::Scope& scope,
         uint32_t max_client_hello_size = TLS_MAX_CLIENT_HELLO);

  const TlsInspectorStats& stats() const { return stats_; }
  bssl::UniquePtr<SSL> newSsl();
  uint32_t maxClientHelloSize() const { return max_client_hello_size_; }
  uint32_t initialReadBufferSize() const { return initial_read_buffer_size_; }

  static constexpr size_t TLS_MAX_CLIENT_HELLO = 64 * 1024;
  static const unsigned TLS_MIN_SUPPORTED_VERSION;
  static const unsigned TLS_MAX_SUPPORTED_VERSION;

private:
  TlsInspectorStats stats_;
  bssl::UniquePtr<SSL_CTX> ssl_ctx_;
  const uint32_t max_client_hello_size_;
  const uint32_t initial_read_buffer_size_;
};

using ConfigSharedPtr = std::shared_ptr<Config>;

/**
 * TLS inspector listener filter.
 */
class Filter : public Network::ReadFilter, Logger::Loggable<Logger::Id::filter> {
public:
  Filter(const ConfigSharedPtr& config);

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance&, bool) override;
  Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks&) override;

private:
  ParseState parseClientHello(const void* data, size_t len, uint64_t bytes_already_processed);
  void onServername(absl::string_view name);
  uint32_t maxConfigReadBytes() const { return config_->maxClientHelloSize(); }

  ConfigSharedPtr config_;
  Network::ReadFilterCallbacks* cb_{};

  bssl::UniquePtr<SSL> ssl_;
  uint64_t read_{0};
  size_t index_of_last_slice_read{0};
  uint64_t bytes_processed_in_last_slice{0};
  bool clienthello_success_{false};
  // We dynamically adjust the number of bytes requested by the filter up to the
  // maxConfigReadBytes.
  uint32_t requested_read_bytes_;
  uint64_t bytes_already_processed_;


  // Allows callbacks on the SSL_CTX to set fields in this class.
  friend class Config;
};


} // namespace CustomTlsInspector
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
