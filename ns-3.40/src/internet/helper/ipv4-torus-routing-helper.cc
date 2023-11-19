/*
 * Copyright (c) 2023 Carnegie Mellon University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "ipv4-torus-routing-helper.h"

#include "ns3/assert.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-list-routing.h"
#include "ns3/ipv4-route.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4.h"
#include "ns3/log.h"
#include "ns3/names.h"
#include "ns3/node.h"
#include "ns3/ptr.h"

#include <vector>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("Ipv4TorusRoutingHelper");

Ipv4TorusRoutingHelper::Ipv4TorusRoutingHelper() {}

Ipv4TorusRoutingHelper::Ipv4TorusRoutingHelper(
    const Ipv4TorusRoutingHelper &o) {}

Ipv4TorusRoutingHelper *Ipv4TorusRoutingHelper::Copy() const {
  return new Ipv4TorusRoutingHelper(*this);
}

Ptr<Ipv4RoutingProtocol> Ipv4TorusRoutingHelper::Create(Ptr<Node> node) const {
  return CreateObject<Ipv4TorusRouting>();
}

Ptr<Ipv4TorusRouting>
Ipv4TorusRoutingHelper::GetTorusRouting(Ptr<Ipv4> ipv4) const {
  NS_LOG_FUNCTION(this);
  Ptr<Ipv4RoutingProtocol> ipv4rp = ipv4->GetRoutingProtocol();
  NS_ASSERT_MSG(ipv4rp, "No routing protocol associated with Ipv4");
  if (DynamicCast<Ipv4TorusRouting>(ipv4rp)) {
    NS_LOG_LOGIC("Torus routing found as the main IPv4 routing protocol.");
    return DynamicCast<Ipv4TorusRouting>(ipv4rp);
  }
  if (DynamicCast<Ipv4ListRouting>(ipv4rp)) {
    Ptr<Ipv4ListRouting> lrp = DynamicCast<Ipv4ListRouting>(ipv4rp);
    int16_t priority;
    for (uint32_t i = 0; i < lrp->GetNRoutingProtocols(); i++) {
      NS_LOG_LOGIC("Searching for Torus routing in list");
      Ptr<Ipv4RoutingProtocol> temp = lrp->GetRoutingProtocol(i, priority);
      if (DynamicCast<Ipv4TorusRouting>(temp)) {
        NS_LOG_LOGIC("Found Torus routing in list");
        return DynamicCast<Ipv4TorusRouting>(temp);
      }
    }
  }
  NS_LOG_LOGIC("Torus routing not found");
  return nullptr;
}

void Ipv4TorusRoutingHelper::AddMulticastRoute(Ptr<Node> n, Ipv4Address source,
                                               Ipv4Address group,
                                               Ptr<NetDevice> input,
                                               NetDeviceContainer output) {
  Ptr<Ipv4> ipv4 = n->GetObject<Ipv4>();

  // We need to convert the NetDeviceContainer to an array of interface
  // numbers
  std::vector<uint32_t> outputInterfaces;
  for (auto i = output.Begin(); i != output.End(); ++i) {
    Ptr<NetDevice> nd = *i;
    int32_t interface = ipv4->GetInterfaceForDevice(nd);
    NS_ASSERT_MSG(interface >= 0,
                  "Ipv4TorusRoutingHelper::AddMulticastRoute(): "
                  "Expected an interface associated with the device nd");
    outputInterfaces.push_back(interface);
  }

  int32_t inputInterface = ipv4->GetInterfaceForDevice(input);
  NS_ASSERT_MSG(inputInterface >= 0,
                "Ipv4TorusRoutingHelper::AddMulticastRoute(): "
                "Expected an interface associated with the device input");
  Ipv4TorusRoutingHelper helper;
  Ptr<Ipv4TorusRouting> ipv4TorusRouting = helper.GetTorusRouting(ipv4);
  if (!ipv4TorusRouting) {
    NS_ASSERT_MSG(ipv4TorusRouting,
                  "Ipv4TorusRoutingHelper::SetDefaultMulticastRoute(): "
                  "Expected an Ipv4TorusRouting associated with this node");
  }
  ipv4TorusRouting->AddMulticastRoute(source, group, inputInterface,
                                      outputInterfaces);
}

void Ipv4TorusRoutingHelper::AddMulticastRoute(Ptr<Node> n, Ipv4Address source,
                                               Ipv4Address group,
                                               std::string inputName,
                                               NetDeviceContainer output) {
  Ptr<NetDevice> input = Names::Find<NetDevice>(inputName);
  AddMulticastRoute(n, source, group, input, output);
}

void Ipv4TorusRoutingHelper::AddMulticastRoute(std::string nName,
                                               Ipv4Address source,
                                               Ipv4Address group,
                                               Ptr<NetDevice> input,
                                               NetDeviceContainer output) {
  Ptr<Node> n = Names::Find<Node>(nName);
  AddMulticastRoute(n, source, group, input, output);
}

void Ipv4TorusRoutingHelper::AddMulticastRoute(std::string nName,
                                               Ipv4Address source,
                                               Ipv4Address group,
                                               std::string inputName,
                                               NetDeviceContainer output) {
  Ptr<NetDevice> input = Names::Find<NetDevice>(inputName);
  Ptr<Node> n = Names::Find<Node>(nName);
  AddMulticastRoute(n, source, group, input, output);
}

void Ipv4TorusRoutingHelper::SetDefaultMulticastRoute(Ptr<Node> n,
                                                      Ptr<NetDevice> nd) {
  Ptr<Ipv4> ipv4 = n->GetObject<Ipv4>();
  int32_t interfaceSrc = ipv4->GetInterfaceForDevice(nd);
  NS_ASSERT_MSG(interfaceSrc >= 0,
                "Ipv4TorusRoutingHelper::SetDefaultMulticastRoute(): "
                "Expected an interface associated with the device");
  Ipv4TorusRoutingHelper helper;
  Ptr<Ipv4TorusRouting> ipv4TorusRouting = helper.GetTorusRouting(ipv4);
  if (!ipv4TorusRouting) {
    NS_ASSERT_MSG(ipv4TorusRouting,
                  "Ipv4TorusRoutingHelper::SetDefaultMulticastRoute(): "
                  "Expected an Ipv4TorusRouting associated with this node");
  }
  ipv4TorusRouting->SetDefaultMulticastRoute(interfaceSrc);
}

void Ipv4TorusRoutingHelper::SetDefaultMulticastRoute(Ptr<Node> n,
                                                      std::string ndName) {
  Ptr<NetDevice> nd = Names::Find<NetDevice>(ndName);
  SetDefaultMulticastRoute(n, nd);
}

void Ipv4TorusRoutingHelper::SetDefaultMulticastRoute(std::string nName,
                                                      Ptr<NetDevice> nd) {
  Ptr<Node> n = Names::Find<Node>(nName);
  SetDefaultMulticastRoute(n, nd);
}

void Ipv4TorusRoutingHelper::SetDefaultMulticastRoute(std::string nName,
                                                      std::string ndName) {
  Ptr<Node> n = Names::Find<Node>(nName);
  Ptr<NetDevice> nd = Names::Find<NetDevice>(ndName);
  SetDefaultMulticastRoute(n, nd);
}

} // namespace ns3
