#include "CLIBridge.h"

#ifdef WITH_CLI_BRIDGE

CLIBridge::CLIBridge(NodePrefs *prefs, Stream &serial, mesh::PacketManager *mgr, mesh::RTCClock *rtc,
                     CommonCLIProxy* cli)
    : BridgeBase(prefs, mgr, rtc), _cli(cli), _serial(&serial) {}

void CLIBridge::begin() {
  BRIDGE_DEBUG_PRINTLN("Initializing...\n");

  // Update bridge state
  _initialized = true;
}

void CLIBridge::end() {
   BRIDGE_DEBUG_PRINTLN("Stopping...\n");

  // Update bridge state
  _initialized = false;
}

void CLIBridge::loop() {
  // Guard against uninitialized state
  if (_initialized == false) {
    return;
  }

  while (_serial->available()) {
    uint8_t b = _serial->read();

    if (_rx_buffer_pos < 2) {
      // Waiting for the magic word for either a bridge packet or a CLI packet
      if ((_rx_buffer_pos == 0 && b == ((BRIDGE_PACKET_MAGIC >> 8) & 0xFF)) ||
          (_rx_buffer_pos == 1 && b == (BRIDGE_PACKET_MAGIC & 0xFF))) {
        _cur_pkt_type = PACKET_TYPE_BRIDGE;
        _rx_buffer[_rx_buffer_pos++] = b;
      } else if ((_rx_buffer_pos == 0 && b == ((CLI_PACKET_MAGIC >> 8) & 0xFF)) ||
                 (_rx_buffer_pos == 1 && b == (CLI_PACKET_MAGIC & 0xFF))) {
        _cur_pkt_type = PACKET_TYPE_CLI;
        _rx_buffer[_rx_buffer_pos++] = b;
      } else {
        // Invalid magic byte, reset and start over
        _cur_pkt_type = PACKET_TYPE_UNKNOWN;
        _rx_buffer_pos = 0;
        // Check if this byte could be the start of a new magic word
        if (b == ((BRIDGE_PACKET_MAGIC >> 8) & 0xFF)) {
          _cur_pkt_type = PACKET_TYPE_BRIDGE;
          _rx_buffer[_rx_buffer_pos++] = b;
        } else if (b == ((CLI_PACKET_MAGIC >> 8) & 0xFF)) {
          _cur_pkt_type = PACKET_TYPE_CLI;
          _rx_buffer[_rx_buffer_pos++] = b;
        }
      }
    } else {
      // Reading length, payload, and checksum
      _rx_buffer[_rx_buffer_pos++] = b;

      if (_rx_buffer_pos >= 4) {
        uint16_t len = (_rx_buffer[2] << 8) | _rx_buffer[3];

        // Validate length field
        if (len > (MAX_TRANS_UNIT + 1)) {
          BRIDGE_DEBUG_PRINTLN("RX invalid length %d, resetting\n", len);
          _cur_pkt_type = PACKET_TYPE_UNKNOWN;
          _rx_buffer_pos = 0; // Invalid length, reset
          continue;
        }

        if (_rx_buffer_pos < len + SERIAL_OVERHEAD) {
          continue;
        }

        // Full packet received
        uint16_t received_checksum = (_rx_buffer[4 + len] << 8) | _rx_buffer[5 + len];

        if (validateChecksum(_rx_buffer + 4, len, received_checksum)) {
          BRIDGE_DEBUG_PRINTLN("RX, len=%d crc=0x%04x\n", len, received_checksum);
            
          mesh::Packet *pkt = _mgr->allocNew();
          if (pkt) {
            if (_cur_pkt_type == PACKET_TYPE_BRIDGE) {
              if (pkt->readFrom(_rx_buffer + 4, len)) {
                onPacketReceived(pkt);
              } else {
                BRIDGE_DEBUG_PRINTLN("RX failed to parse packet\n");
                _mgr->free(pkt);
              }
            } else if (_cur_pkt_type == PACKET_TYPE_CLI) {
              _rx_buffer[4 + len] = 0;
              _cli->handleCommand(0, ((char*)_rx_buffer) + 4, (char*)pkt->payload);
              pkt->payload_len = strlen((char*)pkt->payload);
              sendPacket(pkt, PACKET_TYPE_CLI);
            }
          } else {
            BRIDGE_DEBUG_PRINTLN("RX failed to allocate packet\n");
          }
        } else {
          BRIDGE_DEBUG_PRINTLN("RX checksum mismatch, rcv=0x%04x\n", received_checksum);
        }
        _rx_buffer_pos = 0; // Reset for next packet
        _cur_pkt_type = PACKET_TYPE_UNKNOWN;
      }
    }
  }
}

void CLIBridge::sendPacket(mesh::Packet *packet, PacketType type) {
  // Guard against uninitialized state
  if (_initialized == false) {
    return;
  }

  // First validate the packet pointer
  if (!packet) {
    BRIDGE_DEBUG_PRINTLN("TX invalid packet pointer\n");
    return;
  }

  if (type == PACKET_TYPE_BRIDGE && _seen_packets.hasSeen(packet)) {
    return;
  }

  uint8_t buffer[MAX_SERIAL_PACKET_SIZE];
  uint16_t len = 0;
  if (type == PACKET_TYPE_BRIDGE) {
    len = packet->writeTo(buffer + 4);
  } else if (type == PACKET_TYPE_CLI) {
    const char reply_prefix[] = "  -> ";
    uint16_t prefix_len = sizeof(reply_prefix) - 1;
    len = prefix_len + packet->payload_len;
    memcpy(buffer + 4, reply_prefix, prefix_len);
    memcpy(buffer + 4 + prefix_len, packet->payload, packet->payload_len);
  }

  // Check if packet fits within our maximum payload size
  if (len > (MAX_TRANS_UNIT + 1)) {
    BRIDGE_DEBUG_PRINTLN("TX packet too large (payload=%d, max=%d)\n", len, MAX_TRANS_UNIT + 1);
    return;
  }

  // Build packet header
  if (type == PACKET_TYPE_BRIDGE) {
    buffer[0] = (BRIDGE_PACKET_MAGIC >> 8) & 0xFF; // Magic high byte
    buffer[1] = BRIDGE_PACKET_MAGIC & 0xFF;        // Magic low byte
  } else if (type == PACKET_TYPE_CLI) {
    buffer[0] = (CLI_PACKET_MAGIC >> 8) & 0xFF; // Magic high byte
    buffer[1] = CLI_PACKET_MAGIC & 0xFF;        // Magic low byte
  }
  buffer[2] = (len >> 8) & 0xFF;                 // Length high byte
  buffer[3] = len & 0xFF;                        // Length low byte

  // Calculate checksum over the payload
  uint16_t checksum = fletcher16(buffer + 4, len);
  buffer[4 + len] = (checksum >> 8) & 0xFF; // Checksum high byte
  buffer[5 + len] = checksum & 0xFF;        // Checksum low byte

  // Send complete packet
  _serial->write(buffer, len + SERIAL_OVERHEAD);

  BRIDGE_DEBUG_PRINTLN("TX, len=%d crc=0x%04x\n", len, checksum);
}

void CLIBridge::sendPacket(mesh::Packet *packet) {
  sendPacket(packet, PACKET_TYPE_BRIDGE);
}

void CLIBridge::onPacketReceived(mesh::Packet *packet) {
  handleReceivedPacket(packet);
}

#endif
