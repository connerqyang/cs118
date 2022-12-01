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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  // FILL THIS IN
  // If there is an ongoing traffic
  std::list<std::shared_ptr<ArpRequest>>::iterator req = m_arpRequests.begin();
  while (req != m_arpRequests.end()) {
    // If no ARP reply received and request transmitted >=5 times,
    if ((*req)->nTimesSent >= MAX_SENT_TIME) {
      // Remove packets queued for transmission associated with the request
      std::list<PendingPacket>::const_iterator packet = (*req)->packets.begin();
      while (packet != (*req)->packets.end()) {
        packet = (*req)->packets.erase(packet);
      }

      // Remove pending request
      m_arpRequests.erase(req);
    } else {    // Send ARP request once per second until ARP reply is received or request has been sent out >=5 times
      // Find interface
      const Interface* iface = m_router.findIfaceByName((*req)->packets.front().iface);

      // Init variables for ARP request
      ethernet_hdr req_eth_hdr;
      arp_hdr req_arp_hdr;
      Buffer req_packet(sizeof(ethernet_hdr) + sizeof(arp_hdr));

      // Construct request ethernet header
      req_eth_hdr.ether_type = htons(ethertype_arp);
      memcpy(req_eth_hdr.ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
      memcpy(req_eth_hdr.ether_dhost, 0xFF, ETHER_ADDR_LEN);
      
      // Construct request arp header
      req_arp_hdr.arp_hrd = htons(arp_hrd_ethernet);
      req_arp_hdr.arp_pro = htons(ethertype_ip);
      req_arp_hdr.arp_hln = ETHER_ADDR_LEN;
      req_arp_hdr.arp_pln = 4;
      req_arp_hdr.arp_op = htons(arp_op_request);

      // Configure sources and targets
      req_arp_hdr.arp_sip = iface->ip;
      req_arp_hdr.arp_tip = (*req)->ip;
      memcpy(req_arp_hdr.arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
      memcpy(req_arp_hdr.arp_tha, 0xFF, ETHER_ADDR_LEN);    // TODO
      
      // Populate buffer with constructed headers
      memcpy(req_packet.data(), &req_eth_hdr, sizeof(ethernet_hdr));
      memcpy(req_packet.data() + sizeof(ethernet_hdr), &req_arp_hdr, sizeof(arp_hdr));

      // Send the request
      sendPacket(req_packet, iface->name);

      // Update timers
      (*req)->timeSent = steady_clock.now();
      (*req)->nTimesSent++;

      // Cache response (done in simple-router.cpp)
    }

    req++;    // Move to next request
  }

  // Else, ARP cache should eventually become empty
  // Loop over all cache entries, mark invalid if it has been 30 seconds
  std::list<std::shared_ptr<ArpEntry>>::iterator arp_cache_entry = m_cacheEntries.begin()
  while (arp_cache_entry != m_cacheEntries.end()) {
    if ((*arp_cache_entry)->isValid) {
      arp_cache_entry++;    // Skip this one
    } else {
      m_cacheEntries.erase(arp_cache_entry);  // Else, delete it.
    }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueArpRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeArpRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
