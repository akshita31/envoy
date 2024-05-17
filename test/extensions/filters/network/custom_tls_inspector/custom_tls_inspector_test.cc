#include "source/common/common/hex.h"
#include "source/common/http/utility.h"
#include "source/common/network/io_socket_handle_impl.h"
#include "source/extensions/filters/network/custom_tls_inspector/custom_tls_inspector.h"
#include "source/common/buffer/buffer_impl.h"

#include "test/common/stats/stat_test_utility.h"
#include "test/extensions/filters/network/custom_tls_inspector/custom_tls_utility.h"
#include "test/mocks/api/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/stats/mocks.h"
#include "test/test_common/threadsafe_singleton_injector.h"

#include "absl/strings/str_format.h"
#include "gtest/gtest.h"
#include "openssl/md5.h"
#include "openssl/ssl.h"

using testing::_;
using testing::Eq;
using testing::InSequence;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::NiceMock;
#ifdef WIN32
using testing::Return;
#endif
using testing::ReturnNew;
using testing::ReturnRef;
using testing::SaveArg;

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace CustomTlsInspector {
namespace {

class CustomTlsInspectorTest : public testing::TestWithParam<std::tuple<uint16_t, uint16_t>> {
public:
  CustomTlsInspectorTest()
      : cfg_(std::make_shared<Config>(
            *store_.rootScope())),
        io_handle_(
            Network::SocketInterfaceImpl::makePlatformSpecificSocket(42, false, absl::nullopt)) {}

  void init() {
    filter_ = std::make_shared<Filter>(cfg_);

    // EXPECT_CALL(cb_, socket()).WillRepeatedly(ReturnRef(socket_));
    // EXPECT_CALL(socket_, ioHandle()).WillRepeatedly(ReturnRef(*io_handle_));
    // EXPECT_CALL(dispatcher_,
    //             createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
    //                              Event::FileReadyType::Read | Event::FileReadyType::Closed))
    //     .WillOnce(
    //         DoAll(SaveArg<1>(&file_event_callback_), ReturnNew<NiceMock<Event::MockFileEvent>>()));
    buffer_ = std::make_unique<Buffer::OwnedImpl>();
        // *io_handle_, dispatcher_, [](bool) {}, [](Network::ListenerFilterBuffer&) {},
        // cfg_->initialReadBufferSize());
    filter_->initializeReadFilterCallbacks(cb_);
  }

  NiceMock<Api::MockOsSysCalls> os_sys_calls_;
  TestThreadsafeSingletonInjector<Api::OsSysCallsImpl> os_calls_{&os_sys_calls_};
  Stats::TestUtil::TestStore store_;
  ConfigSharedPtr cfg_;
  std::shared_ptr<Filter> filter_;
  Network::MockReadFilterCallbacks cb_;
  Network::MockConnectionSocket socket_;
  NiceMock<Event::MockDispatcher> dispatcher_;
  Event::FileReadyCb file_event_callback_;
  Network::IoHandlePtr io_handle_;
  std::unique_ptr<Buffer::Instance> buffer_;
};

TEST_F(CustomTlsInspectorTest, NoClientHelloPacket) {
  init();
  Buffer::OwnedImpl buffer("not a client hello");
  EXPECT_EQ(Network::FilterStatus::Continue, filter_->onNewConnection());
  EXPECT_EQ(Network::FilterStatus::Continue, filter_->onData(buffer, false));

  EXPECT_EQ(1, cfg_->stats().tls_not_found_.value());
}

TEST_F(CustomTlsInspectorTest, EntireClientHelloInFirstOnDataCall) {
  init();
  Buffer::OwnedImpl buffer("");
  const std::string servername("example.com");
  std::vector<uint8_t> client_hello = Tls::Test::generateClientHello(
       TLS1_VERSION, TLS1_3_VERSION, servername, "");
  // copy the entire client hello message into buffer
  buffer.add(client_hello.data(), client_hello.size());

  EXPECT_EQ(Network::FilterStatus::Continue, filter_->onNewConnection());
  EXPECT_EQ(Network::FilterStatus::Continue, filter_->onData(buffer, false));

  EXPECT_EQ(1, cfg_->stats().tls_found_.value());
  EXPECT_EQ(1, cfg_->stats().sni_found_.value());
  EXPECT_EQ(1, cfg_->stats().alpn_not_found_.value());

  // todo: Check the server name is set correctly
}

TEST_F(CustomTlsInspectorTest, ClientHelloInMultipleOnDataCalls) {
  init();
  Buffer::OwnedImpl buffer("");

  // Call with empty buffer should result in waiting for more data
  EXPECT_EQ(Network::FilterStatus::Continue, filter_->onNewConnection());
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(buffer, false));

  const std::string servername("example.com");
  std::vector<uint8_t> client_hello = Tls::Test::generateClientHello(
       TLS1_VERSION, TLS1_3_VERSION, servername, "");
  // copy the entire client hello message into buffer
  buffer.add(client_hello.data(), client_hello.size());

  // Call with buffer containing the entire client hello message should parse the server name
  // and allow the iteration to continue
  EXPECT_EQ(Network::FilterStatus::Continue, filter_->onData(buffer, false));
  EXPECT_EQ(1, cfg_->stats().tls_found_.value());
  EXPECT_EQ(1, cfg_->stats().sni_found_.value());
  EXPECT_EQ(1, cfg_->stats().alpn_not_found_.value());
  // todo: Check the server name is set correctly
}

//   void mockSysCallForPeek(std::vector<uint8_t>& client_hello, bool windows_recv = false) {
//     (void)windows_recv;
//     EXPECT_CALL(os_sys_calls_, recv(42, _, _, MSG_PEEK))
//         .WillOnce(Invoke(
//             [&client_hello](os_fd_t, void* buffer, size_t length, int) -> Api::SysCallSizeResult {
//               const size_t amount_to_copy = std::min(length, client_hello.size());
//               memcpy(buffer, client_hello.data(), amount_to_copy);
//               return Api::SysCallSizeResult{ssize_t(amount_to_copy), 0};
//             }));
// #endif
//   }



// INSTANTIATE_TEST_SUITE_P(TlsProtocolVersions, CustomTlsInspectorTest,
//                          testing::Values(std::make_tuple(Config::TLS_MIN_SUPPORTED_VERSION,
//                                                          Config::TLS_MAX_SUPPORTED_VERSION),
//                                          std::make_tuple(TLS1_VERSION, TLS1_VERSION),
//                                          std::make_tuple(TLS1_1_VERSION, TLS1_1_VERSION),
//                                          std::make_tuple(TLS1_2_VERSION, TLS1_2_VERSION),
//                                          std::make_tuple(TLS1_3_VERSION, TLS1_3_VERSION)));

// // Test that an exception is thrown for an invalid value for max_client_hello_size
// TEST_P(CustomTlsInspectorTest, MaxClientHelloSize) {
//   EXPECT_THROW_WITH_MESSAGE(
//       Config(*store_.rootScope(), Config::TLS_MAX_CLIENT_HELLO + 1), EnvoyException,
//       "max_client_hello_size of 65537 is greater than maximum of 65536.");
// }

// // Test that a ClientHello with an SNI value causes the correct name notification.
// TEST_P(CustomTlsInspectorTest, SniRegistered) {
//   init();
//   const std::string servername("example.com");
//   std::vector<uint8_t> client_hello = Tls::Test::generateClientHello(
//       std::get<0>(GetParam()), std::get<1>(GetParam()), servername, "");
//   mockSysCallForPeek(client_hello);
//   EXPECT_CALL(socket_, setRequestedServerName(Eq(servername)));
//   EXPECT_CALL(socket_, setRequestedApplicationProtocols(_)).Times(0);
//   EXPECT_CALL(socket_, setDetectedTransportProtocol(absl::string_view("tls")));
//   EXPECT_CALL(socket_, detectedTransportProtocol()).Times(::testing::AnyNumber());
//   // trigger the event to copy the client hello message into buffer
//   file_event_callback_(Event::FileReadyType::Read);
//   auto state = filter_->onData(*buffer_);
//   EXPECT_EQ(Network::FilterStatus::Continue, state);
//   EXPECT_EQ(1, cfg_->stats().tls_found_.value());
//   EXPECT_EQ(1, cfg_->stats().sni_found_.value());
//   EXPECT_EQ(1, cfg_->stats().alpn_not_found_.value());
// }

// // Test that a ClientHello with an ALPN value causes the correct name notification.
// TEST_P(CustomTlsInspectorTest, AlpnRegistered) {
//   init();
//   const auto alpn_protos = std::vector<absl::string_view>{Http::Utility::AlpnNames::get().Http2,
//                                                           Http::Utility::AlpnNames::get().Http11};
//   std::vector<uint8_t> client_hello = Tls::Test::generateClientHello(
//       std::get<0>(GetParam()), std::get<1>(GetParam()), "", "\x02h2\x08http/1.1");
//   mockSysCallForPeek(client_hello);
//   EXPECT_CALL(socket_, setRequestedServerName(_)).Times(0);
//   EXPECT_CALL(socket_, setRequestedApplicationProtocols(alpn_protos));
//   EXPECT_CALL(socket_, setDetectedTransportProtocol(absl::string_view("tls")));
//   EXPECT_CALL(socket_, detectedTransportProtocol()).Times(::testing::AnyNumber());
//   // trigger the event to copy the client hello message into buffer
//   file_event_callback_(Event::FileReadyType::Read);
//   auto state = filter_->onData(*buffer_);

//   EXPECT_EQ(Network::FilterStatus::Continue, state);
//   EXPECT_EQ(1, cfg_->stats().tls_found_.value());
//   EXPECT_EQ(1, cfg_->stats().sni_not_found_.value());
//   EXPECT_EQ(1, cfg_->stats().alpn_found_.value());
//   const std::vector<uint64_t> bytes_processed =
//       store_.histogramValues("tls_inspector.bytes_processed", false);
//   ASSERT_EQ(1, bytes_processed.size());
//   EXPECT_EQ(client_hello.size(), bytes_processed[0]);
// }

// // Test with the ClientHello spread over multiple socket reads.
// TEST_P(CustomTlsInspectorTest, MultipleReads) {
//   init();
//   const auto alpn_protos = std::vector<absl::string_view>{Http::Utility::AlpnNames::get().Http2};
//   const std::string servername("example.com");
//   std::vector<uint8_t> client_hello = Tls::Test::generateClientHello(
//       std::get<0>(GetParam()), std::get<1>(GetParam()), servername, "\x02h2");
// #ifdef WIN32
//   {
//     InSequence s;
//     EXPECT_CALL(os_sys_calls_, readv(_, _, _))
//         .WillOnce(Return(Api::SysCallSizeResult{ssize_t(-1), SOCKET_ERROR_AGAIN}));
//     for (size_t i = 0; i < client_hello.size(); i++) {
//       EXPECT_CALL(os_sys_calls_, readv(_, _, _))
//           .WillOnce(Invoke([&client_hello, i](os_fd_t fd, const iovec* iov,
//                                               int iovcnt) -> Api::SysCallSizeResult {
//             ASSERT(iov->iov_len >= client_hello.size());
//             memcpy(iov->iov_base, client_hello.data() + i, 1);
//             return Api::SysCallSizeResult{ssize_t(1), 0};
//           }))
//           .WillOnce(Return(Api::SysCallSizeResult{ssize_t(-1), SOCKET_ERROR_AGAIN}));
//     }
//   }
// #else
//   {
//     InSequence s;
//     EXPECT_CALL(os_sys_calls_, recv(42, _, _, MSG_PEEK))
//         .WillOnce(InvokeWithoutArgs([]() -> Api::SysCallSizeResult {
//           return Api::SysCallSizeResult{ssize_t(-1), SOCKET_ERROR_AGAIN};
//         }));
//     for (size_t i = 1; i <= client_hello.size(); i++) {
//       EXPECT_CALL(os_sys_calls_, recv(42, _, _, MSG_PEEK))
//           .WillOnce(Invoke([&client_hello, i](os_fd_t, void* buffer, size_t length,
//                                               int) -> Api::SysCallSizeResult {
//             ASSERT(length >= client_hello.size());
//             memcpy(buffer, client_hello.data(), client_hello.size());
//             return Api::SysCallSizeResult{ssize_t(i), 0};
//           }));
//     }
//   }
// #endif
//   bool got_continue = false;
//   EXPECT_CALL(socket_, setRequestedServerName(Eq(servername)));
//   EXPECT_CALL(socket_, setRequestedApplicationProtocols(alpn_protos));
//   EXPECT_CALL(socket_, setDetectedTransportProtocol(absl::string_view("tls")));
//   EXPECT_CALL(socket_, detectedTransportProtocol()).Times(::testing::AnyNumber());
//   while (!got_continue) {
//     // trigger the event to copy the client hello message into buffer
//     file_event_callback_(Event::FileReadyType::Read);
//     auto state = filter_->onData(*buffer_);
//     if (state == Network::FilterStatus::Continue) {
//       got_continue = true;
//     }
//   }
//   EXPECT_EQ(1, cfg_->stats().tls_found_.value());
//   EXPECT_EQ(1, cfg_->stats().sni_found_.value());
//   EXPECT_EQ(1, cfg_->stats().alpn_found_.value());
//   const std::vector<uint64_t> bytes_processed =
//       store_.histogramValues("tls_inspector.bytes_processed", false);
//   ASSERT_EQ(1, bytes_processed.size());
//   EXPECT_EQ(client_hello.size(), bytes_processed[0]);
// }

// // Test that the filter correctly handles a ClientHello with no extensions present.
// TEST_P(CustomTlsInspectorTest, NoExtensions) {
//   init();
//   std::vector<uint8_t> client_hello =
//       Tls::Test::generateClientHello(std::get<0>(GetParam()), std::get<1>(GetParam()), "", "");
//   mockSysCallForPeek(client_hello);
//   EXPECT_CALL(socket_, setRequestedServerName(_)).Times(0);
//   EXPECT_CALL(socket_, setRequestedApplicationProtocols(_)).Times(0);
//   EXPECT_CALL(socket_, setDetectedTransportProtocol(absl::string_view("tls")));
//   EXPECT_CALL(socket_, detectedTransportProtocol()).Times(::testing::AnyNumber());
//   // trigger the event to copy the client hello message into buffer
//   file_event_callback_(Event::FileReadyType::Read);
//   auto state = filter_->onData(*buffer_);
//   EXPECT_EQ(Network::FilterStatus::Continue, state);
//   EXPECT_EQ(1, cfg_->stats().tls_found_.value());
//   EXPECT_EQ(1, cfg_->stats().sni_not_found_.value());
//   EXPECT_EQ(1, cfg_->stats().alpn_not_found_.value());
// }

// // Test that the filter fails if the ClientHello is larger than the
// // maximum allowed size.
// TEST_P(CustomTlsInspectorTest, ClientHelloTooBig) {
//   const size_t max_size = 50;
//   cfg_ =
//       std::make_shared<Config>(*store_.rootScope(), static_cast<uint32_t>(max_size));
//   std::vector<uint8_t> client_hello = Tls::Test::generateClientHello(
//       std::get<0>(GetParam()), std::get<1>(GetParam()), "example.com", "");
//   ASSERT(client_hello.size() > max_size);

//   filter_ = std::make_unique<Filter>(cfg_);

//   EXPECT_CALL(cb_, socket()).WillRepeatedly(ReturnRef(socket_));
//   EXPECT_CALL(socket_, ioHandle()).WillRepeatedly(ReturnRef(*io_handle_));
//   EXPECT_CALL(dispatcher_,
//               createFileEvent_(_, _, Event::PlatformDefaultTriggerType,
//                                Event::FileReadyType::Read | Event::FileReadyType::Closed))
//       .WillOnce(
//           DoAll(SaveArg<1>(&file_event_callback_), ReturnNew<NiceMock<Event::MockFileEvent>>()));
//   buffer_ = std::make_unique<Buffer::OwnedImpl>();

//   filter_->initializeReadFilterCallbacks(cb_);
//   mockSysCallForPeek(client_hello, true);
//   EXPECT_CALL(socket_, detectedTransportProtocol()).Times(::testing::AnyNumber());
//   file_event_callback_(Event::FileReadyType::Read);
//   auto state = filter_->onData(*buffer_);
//   EXPECT_EQ(Network::FilterStatus::StopIteration, state);
//   EXPECT_EQ(1, cfg_->stats().client_hello_too_large_.value());
//   const std::vector<uint64_t> bytes_processed =
//       store_.histogramValues("tls_inspector.bytes_processed", false);
//   ASSERT_EQ(1, bytes_processed.size());
//   EXPECT_EQ(max_size, bytes_processed[0]);
// }


// // Test that the filter fails on non-SSL data
// TEST_P(CustomTlsInspectorTest, NotSsl) {
//   init();
//   std::vector<uint8_t> data;

//   // Use 100 bytes of zeroes. This is not valid as a ClientHello.
//   data.resize(100);
//   mockSysCallForPeek(data);
//   // trigger the event to copy the client hello message into buffer:q
//   file_event_callback_(Event::FileReadyType::Read);
//   auto state = filter_->onData(*buffer_);
//   EXPECT_EQ(Network::FilterStatus::Continue, state);
//   EXPECT_EQ(1, cfg_->stats().tls_not_found_.value());
//   const std::vector<uint64_t> bytes_processed =
//       store_.histogramValues("tls_inspector.bytes_processed", false);
//   ASSERT_EQ(1, bytes_processed.size());
//   EXPECT_EQ(5, bytes_processed[0]);
// }

// TEST_P(CustomTlsInspectorTest, EarlyTerminationShouldNotRecordBytesProcessed) {
//   cfg_ = std::make_shared<Config>(*store_.rootScope());
//   std::vector<uint8_t> client_hello = Tls::Test::generateClientHello(
//       std::get<0>(GetParam()), std::get<1>(GetParam()), "example.com", "");

//   // Clobber half of client_hello so we don't have sufficient bytes to finish inspection.
//   client_hello.resize(client_hello.size() / 2);

//   init();
//   mockSysCallForPeek(client_hello);
//   EXPECT_CALL(socket_, setRequestedServerName(_)).Times(0);
//   EXPECT_CALL(socket_, setRequestedApplicationProtocols(_)).Times(0);
//   EXPECT_CALL(socket_, detectedTransportProtocol()).Times(::testing::AnyNumber());
//   // Trigger the event to copy the client hello message into buffer
//   file_event_callback_(Event::FileReadyType::Read);
//   auto state = filter_->onData(*buffer_);
//   EXPECT_EQ(Network::FilterStatus::StopIteration, state);

//   // Terminate early.
//   filter_.reset();

//   ASSERT_FALSE(store_.histogramRecordedValues("tls_inspector.bytes_processed"));
// }

// TEST_P(CustomTlsInspectorTest, RequestedMaxReadSizeDoesNotGoBeyondMaxSize) {
//   const uint32_t initial_buffer_size = 15;
//   const size_t max_size = 50;
//   //proto_config.mutable_initial_read_buffer_size()->set_value(initial_buffer_size);
//   cfg_ = std::make_shared<Config>(*store_.rootScope(), max_size);
//   buffer_ = std::make_unique<Buffer::OwnedImpl>();
//   std::vector<uint8_t> client_hello = Tls::Test::generateClientHello(
//       std::get<0>(GetParam()), std::get<1>(GetParam()), "example.com", "\x02h2");

//   init();
//   EXPECT_CALL(socket_, setRequestedServerName(_)).Times(0);
//   EXPECT_CALL(socket_, setRequestedApplicationProtocols(_)).Times(0);
//   EXPECT_CALL(socket_, setDetectedTransportProtocol(_)).Times(0);

//   mockSysCallForPeek(client_hello, true);
//   file_event_callback_(Event::FileReadyType::Read);
//   auto state = filter_->onData(*buffer_);
//   EXPECT_EQ(Network::FilterStatus::StopIteration, state);
//   EXPECT_EQ(2 * initial_buffer_size, filter_->maxReadBytes());
//   buffer_->resetCapacity(2 * initial_buffer_size);

//   mockSysCallForPeek(client_hello, true);
//   file_event_callback_(Event::FileReadyType::Read);
//   state = filter_->onData(*buffer_);
//   EXPECT_EQ(Network::FilterStatus::StopIteration, state);
//   EXPECT_EQ(max_size, filter_->maxReadBytes());
//   buffer_->resetCapacity(max_size);

//   // The filter should not request a larger buffer as we've reached the max.
//   // It should close the connection.
//   mockSysCallForPeek(client_hello, true);
//   file_event_callback_(Event::FileReadyType::Read);
//   state = filter_->onData(*buffer_);
//   EXPECT_EQ(Network::FilterStatus::StopIteration, state);
//   EXPECT_EQ(max_size, filter_->maxReadBytes());
//   EXPECT_FALSE(io_handle_->isOpen());
// }

} // namespace
} // namespace TlsInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
