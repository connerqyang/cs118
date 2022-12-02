/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
static const std::string broadcast_address = "FF:FF:FF:FF:FF:FF";
static const std::string lowercase_broadcast_address = "ff:ff:ff:ff:ff:ff";
static const uint8_t broadcast[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
void
SimpleRouter::processPacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
  print_hdrs(packet);

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  // Initialize packet type, source/destianation addresses from iface and packet
  std::string iface_addr = macToString(iface->addr);
  std::string packet_addr = macToString(packet);
  uint16_t ether_type = ethertype(packet.data());

  // Ignore Ethernet frames other than ARP and IPv4
  if (ether_type != ethertype_arp && ether_type != ethertype_ip) {
    std::cerr << "Received packet, but Ethernet frame is not ARP or IPv4, ignoring" << std::endl;
    return;
  }

  // Ignore Ethernet frames not destined to router (not corresponding MAC address or broadcast address)
  if (packet_addr != lowercase_broadcast_address && packet_addr != broadcast_address && packet_addr != iface_addr) {
    std::cerr << "Received packet, but destination is not the router, ignoring" << std::endl;
    return;
  }

  // Dispatch Ethernet frames (payload) carrying ARP and IPv4 packets
  if (ether_type == ethertype_arp) {  // ARP packets
    std::cerr << "Processing ARP packet" << std::endl;
    const arp_hdr* arp_header = reinterpret_cast<const arp_hdr*>(packet.data() + sizeof(ethernet_hdr));
    uint32_t target_ip = arp_header->arp_tip;
    uint16_t op_code = ntohs(arp_header->arp_op);

    // Check that packet is the correct size for a valid ARP message
    if (packet.size() < sizeof(ethernet_hdr) + sizeof(arp_hdr))
    {
      std::cerr << "Packet size is not larget enough for ARP, ignoring" << std::endl;
      return;
    }

    // Determine request or reply based on op code
    if (op_code == arp_op_request) {        // Handle ARP request
      std::cerr << "Processing ARP Request" << std::endl;
      // Ignore if request is not for MAC address for IP address of interface
      if (target_ip != iface->ip) {
        std::cerr << "Destination IP address doesn't match the interface's IP address, ignoring" << std::endl;
        return;
      }

      // Check if ARP cache contains corresponding MAC address

      // If valid entry found, proceed to handle IP packet
      // Otherwise, queue received packet and start sending ARP requests to discover IP-MAC mapping
        // Send once a second until ARP reply received, or request has been sent 5 times
        // If no ARP reply received, stop re-transmitting, remove pending request and any queued packets

      // Init variables for ARP response
      ethernet_hdr resp_eth_hdr;
      arp_hdr resp_arp_hdr;
      Buffer resp_packet(sizeof(ethernet_hdr) + sizeof(arp_hdr));

      // Construct response ethernet header
      memcpy(resp_eth_hdr.ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
      memcpy(resp_eth_hdr.ether_dhost, &(arp_header->arp_sha), ETHER_ADDR_LEN);
      resp_eth_hdr.ether_type = htons(ethertype_arp);

      // Construct response arp header
      resp_arp_hdr.arp_hrd = htons(arp_hrd_ethernet);
      resp_arp_hdr.arp_pro = htons(ethertype_ip);
      resp_arp_hdr.arp_hln = ETHER_ADDR_LEN;
      resp_arp_hdr.arp_pln = 4;
      resp_arp_hdr.arp_op = htons(arp_op_reply);

      // Configure sources and targets
      resp_arp_hdr.arp_sip = iface->ip;
      resp_arp_hdr.arp_tip = arp_header->arp_sip;
      memcpy(resp_arp_hdr.arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
      memcpy(resp_arp_hdr.arp_tha, &(arp_header->arp_sha), ETHER_ADDR_LEN);
      
      // Populate buffer with constructed headers
      memcpy(resp_packet.data(), &resp_eth_hdr, sizeof(ethernet_hdr));
      memcpy(resp_packet.data() + sizeof(ethernet_hdr), &resp_arp_hdr, sizeof(arp_hdr));

      // Send back the response/reply
      sendPacket(resp_packet, iface->name);

    } else if (op_code == arp_op_reply) {   // Handle ARP reply
      std::cerr << "Processing ARP Reply" << std::endl;

      // Retrieve IP<->MAC mapping from ARP response
      Buffer addr_mapping(ETHER_ADDR_LEN);
      memcpy(addr_mapping.data(), arp_header->arp_sha, ETHER_ADDR_LEN);

      // Record IP-MAC mapping in ARP cache (Source IP/Souce hardware address in ARP reply)
      if(m_arp.lookup(arp_header->arp_sip) == nullptr) {
        std::shared_ptr<ArpRequest> arp_request = m_arp.insertArpEntry(addr_mapping, arp_header->arp_sip);
        // Remove the pending request
        m_arp.removeArpRequest(arp_request);
        // Then, send out all corresponding enqueued packets
        if (arp_request != NULL)
        {
          for (std::list<PendingPacket>::iterator iter = arp_request->packets.begin(); iter != arp_request->packets.end(); iter++)
          {
            ethernet_hdr* eth_hdr = (ethernet_hdr*) iter->packet.data();

            // TODO: is the dhost right?
            memcpy(eth_hdr->ether_dhost, arp_header->arp_sha, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);

            sendPacket(iter->packet, iter->iface);
          }
        }
      } else {
        std::cerr << "ARP reply/response received is invalid, ignoring" << std::endl;
        return;
      }
    } else {  // OP code not recognized
      std::cerr << "ARP op code not recognized, ignoring" << std::endl;
      return;
    }
  } else if (ether_type == ethertype_ip) {  // IP packets
    std::cerr << "Processing IP packet" << std::endl;

    // Initialize variables to hold packet and header
    ip_hdr* ip_header = (ip_hdr*) (packet.data() + sizeof(ethernet_hdr));

    // Check that packet is the above the minimum size for a valid IP message
    if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr))
    {
      std::cerr << "Packet size is not larget enough for IP, ignoring" << std::endl;
      return;
    }

    // Check that the ip header is above the minimum size for a valid message
    if (ip_header->ip_len < sizeof(ip_hdr))
    {
      std::cerr << "Invalid packet size, too small for IPv4 header, ignoring" << std::endl;
    }

    // Verify checksum
    uint16_t checksum = ip_header->ip_sum;
    ip_header->ip_sum = 0;
    if (checksum != cksum(ip_header, sizeof(ip_hdr))) {
      std::cerr << "IP packet has incorrect checksum" << std::endl;
      return;
    }

    // Prepare port # for ACL rule lookup
    // uint32_t src_port = ;
    // uint32_t dst_port = ;

    // // Check ACL rules, take action accordingly
    // ACLTableEntry rule = m_aclTable.lookup();
    // if (rule != NULL) {
    //   // Log rule

    //   // Follow it: Deny -> return here, Allow -> proceed below
    // }

    // Classify datagrams into (1) destined to the router or (2) datagrams to be forwarded
    const Interface* iface = findIfaceByIp(ip_header->ip_dst);
    if (iface != nullptr) {
      // (1) discard packets
      std::cerr << "Packet discarded, since incoming IP packet's destination is the router" << std::endl;
      return;
    } else {
      // (2) Use longest prefix match alg. to find next-hop IP addr in routing table and attempt to forward it there
      //      For each forwarded packet:
      //          decrement TTL and recompute checksum
      std::cerr << "Routing packets" << std::endl;
      if (ip_header->ip_ttl == 0) {
        std::cerr << "The TTL is 0, dropping this packet" << std::endl;
        return;
      }
      ip_header->ip_ttl--;  // Decrement TTL
      ip_header->ip_sum = cksum(ip_header, sizeof(ip_hdr));   // Recompute checksum

      // Check routing table for longest prefix match with dest. IP address
      RoutingTableEntry next_hop = m_routingTable.lookup(ip_header->ip_dst);
      const Interface* ip_iface = findIfaceByName(next_hop.ifName);

      // Check ARP cache for next-hop MAC address corresponding to next-hop IP
      auto arp = m_arp.lookup(next_hop.gw);

      // If it's there, send it.
      if (arp != nullptr) {
        std::cerr << "Forwarding IP packet!" << std::endl;
        // Construct Ethernet header
        ethernet_hdr* eth_hdr = (ethernet_hdr*) packet.data();

        eth_hdr->ether_type = htons(ethertype_ip);
        memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);   // Old destination is new source
        memcpy(eth_hdr->ether_dhost, arp->mac.data(), ETHER_ADDR_LEN);

        // Send it!
        sendPacket(packet, ip_iface->name);
        std::cerr << "Forwarded!!!" << std::endl;
      } else {
        std::cerr << "Queuing ARP request!" << std::endl;
        // Add the packet to the queue of packets waiting on this ARP request
        m_arp.queueArpRequest(next_hop.gw, packet, iface->name);
        std::cerr << "ARP Request queued!" << std::endl;

        // Otherwise:
        //    Send an ARP request for the next-hop IP (if one hasn't been sent within the last second)

        // Init variables for ARP request
        ethernet_hdr req_eth_hdr;
        arp_hdr req_arp_hdr;
        Buffer req_packet(sizeof(ethernet_hdr) + sizeof(arp_hdr));

        // Construct request ethernet header
        req_eth_hdr.ether_type = htons(ethertype_arp);
        memcpy(req_eth_hdr.ether_shost, ip_iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(req_eth_hdr.ether_dhost, broadcast, ETHER_ADDR_LEN);

        // Construct request arp header
        req_arp_hdr.arp_hrd = htons(arp_hrd_ethernet);
        req_arp_hdr.arp_pro = htons(ethertype_ip);
        req_arp_hdr.arp_hln = ETHER_ADDR_LEN;
        req_arp_hdr.arp_pln = 4;
        req_arp_hdr.arp_op = htons(arp_op_request);

        // Configure sources and targets
        req_arp_hdr.arp_sip = ip_iface->ip;
        // req_arp_hdr.arp_tip = arp_header->arp_sip;
        req_arp_hdr.arp_tip = next_hop.gw;
        memcpy(req_arp_hdr.arp_sha, ip_iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(req_arp_hdr.arp_tha, broadcast, ETHER_ADDR_LEN);
        
        // Populate buffer with constructed headers
        memcpy(req_packet.data(), &req_eth_hdr, sizeof(ethernet_hdr));
        memcpy(req_packet.data() + sizeof(ethernet_hdr), &req_arp_hdr, sizeof(arp_hdr));

        // Send back the response/reply
        sendPacket(req_packet, ip_iface->name);
        std::cerr << "Sent ARP request packet!" << std::endl;
      }
    }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
  m_aclLogFile.open("router-acl.log");
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

bool
SimpleRouter::loadACLTable(const std::string& aclConfig)
{
  return m_aclTable.load(aclConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

} // namespace simple_router {
