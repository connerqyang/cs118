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
static const string broadcast_address = "FF:FF:FF:FF:FF:FF";
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
  if (packet_addr != broadcast_address && packet_addr != iface_addr) {
    std::cerr << "Received packet, but destination is not the router, ignoring" << std::endl;
    return;
  }

  // Dispatch Ethernet frames (payload) carrying ARP and IPv4 packets
  if (ether_type == ethertype_arp) {  // ARP packets
    const arp_hdr* arp_header = reinterpret_cast<const arp_hdr*>(packet.data() + sizeof(ethernet_hdr));
    uint32_t target_ip = arp_header->arp_tip;
    uint16_t op_code = ntohs(arp_header->arp_op);

    // Determine request or reply based on op code
    if (op_code == arp_op_request) {        // Handle ARP request
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

    } else if (op_code == arp_op_reply) {   // Handle ARP reply
      // Record IP-MAC mapping in ARP cache (Source IP/Souce hardware address in ARP reply)

      // Then, send out all corresponding enqueued packets

    } else {  // Op code not recognized
      std::cerr << "ARP op code not recognized, ignoring" << std::endl;
      return;
    }
    

    

  } else if (ether_type == ethertype_ip) {  // IP packets

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
