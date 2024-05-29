#include "source/extensions/filters/network/custom_tls_inspector/custom_tls_inspector.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/common/platform.h"
#include "envoy/event/dispatcher.h"
#include "envoy/network/listen_socket.h"
#include "envoy/stats/scope.h"

#include "source/common/api/os_sys_calls_impl.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/protobuf/utility.h"

#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "openssl/md5.h"
#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace CustomTlsInspector {
namespace {

uint64_t computeClientHelloSize(const BIO* bio, uint64_t prior_bytes_read,
                                size_t original_bio_length) {
  const uint8_t* remaining_buffer;
  size_t remaining_bytes;
  const int rc = BIO_mem_contents(bio, &remaining_buffer, &remaining_bytes);
  ASSERT(rc == 1);
  ASSERT(original_bio_length >= remaining_bytes);
  const size_t processed_bio_bytes = original_bio_length - remaining_bytes;
  return processed_bio_bytes + prior_bytes_read;
}

} // namespace

// Min/max TLS version recognized by the underlying TLS/SSL library.
const unsigned Config::TLS_MIN_SUPPORTED_VERSION = TLS1_VERSION;
const unsigned Config::TLS_MAX_SUPPORTED_VERSION = TLS1_3_VERSION;

Config::Config(
    Stats::Scope& scope,
    uint32_t max_client_hello_size)
    : stats_{ALL_TLS_INSPECTOR_STATS(POOL_COUNTER_PREFIX(scope, "tls_inspector."),
                                     POOL_HISTOGRAM_PREFIX(scope, "tls_inspector."))},
      ssl_ctx_(SSL_CTX_new(TLS_with_buffers_method())),
      max_client_hello_size_(max_client_hello_size),
      initial_read_buffer_size_(
          std::min<uint32_t>(2, max_client_hello_size)) {
  if (max_client_hello_size_ > TLS_MAX_CLIENT_HELLO) {
    throw EnvoyException(fmt::format("max_client_hello_size of {} is greater than maximum of {}.",
                                     max_client_hello_size_, size_t(TLS_MAX_CLIENT_HELLO)));
  }

  SSL_CTX_set_min_proto_version(ssl_ctx_.get(), TLS_MIN_SUPPORTED_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx_.get(), TLS_MAX_SUPPORTED_VERSION);
  SSL_CTX_set_options(ssl_ctx_.get(), SSL_OP_NO_TICKET);
  SSL_CTX_set_session_cache_mode(ssl_ctx_.get(), SSL_SESS_CACHE_OFF);
  SSL_CTX_set_tlsext_servername_callback(
      ssl_ctx_.get(), [](SSL* ssl, int* out_alert, void*) -> int {
        Filter* filter = static_cast<Filter*>(SSL_get_app_data(ssl));
        filter->onServername(
            absl::NullSafeStringView(SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)));

        // Return an error to stop the handshake; we have what we wanted already.
        *out_alert = SSL_AD_USER_CANCELLED;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
      });
}

bssl::UniquePtr<SSL> Config::newSsl() { return bssl::UniquePtr<SSL>{SSL_new(ssl_ctx_.get())}; }

Filter::Filter(const ConfigSharedPtr& config)
    : config_(config), ssl_(config_->newSsl()),
      requested_read_bytes_(config->initialReadBufferSize()) {

  ENVOY_LOG(trace, "custom tls inspector: filter constructor");
  SSL_set_app_data(ssl_.get(), this);
  SSL_set_accept_state(ssl_.get());
}

Network::FilterStatus Filter::onNewConnection() {
  ENVOY_LOG(trace, "Custom TLS Inspector: on new connection");
  ENVOY_LOG(trace, "Custom TLS Inspector: Setting read enabled so that data can be read from the socket.");
  const Network::Connection::ReadDisableStatus read_disable_status =
      cb_->connection().readDisable(false);
  ASSERT(read_disable_status == Network::Connection::ReadDisableStatus::TransitionedToReadEnabled);
  ENVOY_LOG(trace, "Custom TLS Inspector: Read enabled successfully");
  ENVOY_LOG(trace, "Custom TLS Inspector: Returning StopIteration.");
  return Network::FilterStatus::StopIteration;
}

void Filter::onServername(absl::string_view name) {
  if (!name.empty()) {
    config_->stats().sni_found_.inc();
    cb_->connection().connectionInfoSetter().setRequestedServerName(name);
    ENVOY_LOG(debug, "tls:onServerName(), requestedServerName: {}", name);
  } else {
    config_->stats().sni_not_found_.inc();
  }
  clienthello_success_ = true;
}

Network::FilterStatus Filter::onData(Buffer::Instance& buffer, bool) {
  ENVOY_LOG(trace, "custom tls inspector: on data");

  if (clienthello_success_) {
    ENVOY_LOG(trace, "custom tls inspector: clienthello_success_");
    return Network::FilterStatus::Continue;
  }

  // from: https://sourcegraph.com/github.com/envoyproxy/envoy@c3b0ea0b6f9f7ff76c057e035433918fda4b8d9c/-/blob/source/common/buffer/buffer_impl.cc?L27#tab=references
  // It looks like data is always added at the end of the buffer.
  // new data can be simply added in the last slice or new slice can be created
  // and added to the buffer
  // We need to keep pointer to the last slice as well as the size of the last slice
  // So when the call comes, we can start reading from the last slice if it has more data
  // and then continue
  Buffer::RawSliceVector slices = buffer.getRawSlices();
  ENVOY_LOG(trace, "custom tls inspector: slices.size: {}", slices.size());
  //std::cout<<"custom tls inspector: slices.size: "<<slices.size()<<std::endl;
  // start reading the buffer after the last read slice
  uint64_t bytes_to_forward = bytes_processed_in_last_slice;
  for (auto i = index_of_last_slice_read; i < slices.size(); i++) {
    const Buffer::RawSlice& slice = slices[i];
    ENVOY_LOG(trace, "custom tls inspector: recv: {}", slice.len_);
    const uint8_t* slice_mem = static_cast<const uint8_t*>(slice.mem_) + bytes_to_forward;
    const size_t slice_len = slice.len_ - bytes_to_forward;
    ParseState parse_state = parseClientHello(slice_mem, slice_len, bytes_already_processed_);
    std::cout<<"custom tls inspector: recv: "<<slice.len_<<std::endl;
    std::cout<<"custom tls inspector: parse_state: "<<static_cast<typename std::underlying_type<ParseState>::type>(parse_state)<<std::endl;
    index_of_last_slice_read = i;
    bytes_processed_in_last_slice = slice.len_;
    bytes_to_forward = 0;
    bytes_already_processed_ += slice_len;
    switch (parse_state) {
    case ParseState::Error:
      cb_->connection().close(Network::ConnectionCloseType::NoFlush, "tls_error");
      return Network::FilterStatus::StopIteration;
    case ParseState::Done:
      // Finish the inspect.
      // todo(akshita): do we need to call continueReading() here?
      // cb_->continueReading();
      cb_->connection().readDisable(true);
      return Network::FilterStatus::Continue;
    case ParseState::Continue:
      // Wait before reading the current whole buffer.
      continue;
    }
    IS_ENVOY_BUG("unexpected tcp filter parse_state");
  }

  // Whole buffer is read but couldnt complete ClientHello, wait for next data
  // Somehow until the internal listener filter chain doesnt get initialized,
  // the next onData() call is not coming.
  // But if we continue reading here, then the RBAC filter will not be able
  // to execute based on the requestedServerName if this one doesnt set it.
  ENVOY_LOG(trace, "custom tls inspector: Stopped Iteration, waiting for more data");
  return Network::FilterStatus::StopIteration;
}

ParseState Filter::parseClientHello(const void* data, size_t len,
                                    uint64_t bytes_already_processed) {
  // Ownership remains here though we pass a reference to it in `SSL_set0_rbio()`.
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(data, len));

  // Make the mem-BIO return that there is more data
  // available beyond it's end.
  BIO_set_mem_eof_return(bio.get(), -1);

  // We only do reading as we abort the handshake early.
  // SSL_set0_rbio() connects the BIO rbio for the read operations of the ssl object.
  SSL_set0_rbio(ssl_.get(), bssl::UpRef(bio).release());

  int ret = SSL_do_handshake(ssl_.get());

  // This should never succeed because an error is always returned from the SNI callback.
  ASSERT(ret <= 0);
  ParseState state = [this, ret]() {
    switch (SSL_get_error(ssl_.get(), ret)) {
    case SSL_ERROR_WANT_READ:
      if (read_ == maxConfigReadBytes()) {
        // We've hit the specified size limit. This is an unreasonably large ClientHello;
        // indicate failure.
        config_->stats().client_hello_too_large_.inc();
        return ParseState::Error;
      }
      if (read_ == requested_read_bytes_) {
        // Double requested bytes up to the maximum configured.
        requested_read_bytes_ = std::min<uint32_t>(2 * requested_read_bytes_, maxConfigReadBytes());
      }
      return ParseState::Continue;
    case SSL_ERROR_SSL:
    std::cout<<"SSL_ERROR_SSL"<<std::endl;
      if (clienthello_success_) {
        std::cout<<"clienthello_success_"<<std::endl;
        config_->stats().tls_found_.inc();
        // todo(akshita): maybe this is not needed
        //cb_->socket().setDetectedTransportProtocol("tls");
      } else {
        config_->stats().tls_not_found_.inc();
      }
      return ParseState::Done;
    default:
      return ParseState::Error;
    }
  }();

  if (state != ParseState::Continue) {
    // Record bytes analyzed as we're done processing.
    config_->stats().bytes_processed_.recordValue(
        computeClientHelloSize(bio.get(), bytes_already_processed, len));
  }

  return state;
}


} // namespace TlsInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
