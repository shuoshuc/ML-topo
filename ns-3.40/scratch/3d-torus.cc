/*
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

/**
 * This script creates a NxNxN 3D Torus network topology. The fabric simulates
 * the TPUv4 cluster.
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-torus-routing-helper.h"
#include "ns3/network-module.h"
#include "ns3/on-off-helper.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/point-to-point-helper.h"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <istream>
#include <map>
#include <numeric>
#include <queue>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

enum Direction_t {
  X_MINUS = 0,
  X_PLUS = 1,
  Y_MINUS = 2,
  Y_PLUS = 3,
  Z_MINUS = 4,
  Z_PLUS = 5,
};
static const Direction_t DIRECTION[] = {X_MINUS, X_PLUS,  Y_MINUS,
                                        Y_PLUS,  Z_MINUS, Z_PLUS};

using namespace ns3;
// Maps from a tuple-format coordinate <x, y, z> to a Node ptr.
// e.g., <0, 1, 0>: Ptr<node>
using CoordNodeMap =
    std::map<std::tuple<uint32_t, uint32_t, uint32_t>, Ptr<Node>>;
// Maps from a tuple-format coordinate <x, y, z, direction> to a NetDevice.
// e.g., <0, 1, 0, x+>: Ptr<dev1>
using CoordDeviceMap =
    std::map<std::tuple<uint32_t, uint32_t, uint32_t, Direction_t>,
             Ptr<NetDevice>>;
// Maps from a tuple-format coordinate <x, y, z, direction> to an
// Ipv4Interface. e.g., <0, 1, 0, x+>: {if1}
using CoordInterfaceMap =
    std::map<std::tuple<uint32_t, uint32_t, uint32_t, Direction_t>,
             std::pair<Ptr<Ipv4>, uint32_t>>;
// TM row format: <src_x, src_y, src_z, dst_x, dst_y, dst_z, demand, t_start>.
using TMRow = std::tuple<uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                         uint32_t, uint64_t, uint64_t>;
// Complete traffic matrix (not in actual matrix format).
using TrafficMatrix = std::vector<TMRow>;

NS_LOG_COMPONENT_DEFINE("3D-Torus");

// Returns the wrapped-around coordinate, e.g., 0 - 1 = -1 => 2 (when range=3).
int wrapCoord(int coord, int range) { return (range + coord % range) % range; }

// Converts a direction enum to a string.
std::string dir2str(Direction_t dir) {
  switch (dir) {
  case X_MINUS:
    return std::string("x-");
  case X_PLUS:
    return std::string("x+");
  case Y_MINUS:
    return std::string("y-");
  case Y_PLUS:
    return std::string("y+");
  case Z_MINUS:
    return std::string("z-");
  case Z_PLUS:
    return std::string("z+");
  default:
    return std::string("");
  }
}

// Builds an FQDN string out of coordinates.
std::string buildFQDN(std::string NET, uint32_t x, uint32_t y, uint32_t z,
                      Direction_t dir, bool appendDir) {
  // Device name is like "toy1-x0-y1-z0-z+".
  std::string fqdn = NET + "-x" + std::to_string(x) + "-y" + std::to_string(y) +
                     "-z" + std::to_string(z);
  if (appendDir) {
    fqdn += "-" + dir2str(dir);
  }
  return fqdn;
}

// Callback function to compute flow completion time.
void calcFCT(Ptr<OutputStreamWrapper> stream, bool filter, const Time &start,
             const Time &end) {
  auto dur = (end - start).ToInteger(Time::NS);
  if (filter && dur <= 0) {
    return;
  }
  NS_LOG_INFO("FCT " << dur << " nsec.");
  *stream->GetStream() << start.ToInteger(Time::NS) << ","
                       << end.ToInteger(Time::NS) << "," << dur << std::endl;
}

// Wipes the static routing table on the specified node.
void wipeStaticRoutingTable(Ptr<Node> node,
                            const Ipv4StaticRoutingHelper &ipv4RoutingHelper) {
  Ptr<Ipv4StaticRouting> routing =
      ipv4RoutingHelper.GetStaticRouting(node->GetObject<Ipv4>());
  while (routing->GetNRoutes()) {
    routing->RemoveRoute(0);
  }
}

int main(int argc, char *argv[]) {

  // ===========================
  // ==                       ==
  // == Fabric spec and flags ==
  // ==                       ==
  // ===========================

  // Fabric name.
  std::string NET = "toy1";
  // Number of nodes on each dimension.
  int N = 16;
  // The corrdinates of devices which should enable pcap trace on.
  std::set<std::tuple<uint32_t, uint32_t, uint32_t, Direction_t>> pcap_ifs{
      //{1, 0, 0, X_MINUS},
      //{0, 0, 0, X_PLUS},
  };
  // A vector of node names where the routing table of each should be dumped.
  std::vector<std::tuple<uint32_t, uint32_t, uint32_t>>
      subscribed_routing_tables{
          //{0, 0, 0},
      };

  // If true, filters out all negative FCT values.
  bool filterFct = true;
  bool tracing = false;
  bool verbose = false;
  // Folder to hold all output files.
  std::string outPrefix = "./3d-torus/";
  // Parse command line
  CommandLine cmd(__FILE__);
  cmd.AddValue("tracing", "Enable pcap tracing", tracing);
  cmd.AddValue("filterFct", "Filters negative FCT values", filterFct);
  cmd.AddValue("verbose", "verbose output", verbose);
  cmd.AddValue("outPrefix", "File path of the output files", outPrefix);
  cmd.Parse(argc, argv);

  // ===========================
  // ==                       ==
  // == Global configurations ==
  // ==                       ==
  // ===========================
  // Overrides default TCP MSS from 536B to 1448B to match Ethernet.
  Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1448));
  GlobalValue::Bind("ChecksumEnabled", BooleanValue(false));
  /*
  // Sets default CCA to CUBIC.
  Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                     StringValue("ns3::TcpCubic"));
  */
  // DCTCP with RED router.
  Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                     StringValue("ns3::TcpDctcp"));
  Config::SetDefault("ns3::RedQueueDisc::UseEcn", BooleanValue(true));
  Config::SetDefault("ns3::RedQueueDisc::QW", DoubleValue(1.0));
  Config::SetDefault("ns3::RedQueueDisc::MinTh", DoubleValue(16));
  Config::SetDefault("ns3::RedQueueDisc::MaxTh", DoubleValue(16));

  Time::SetResolution(Time::NS);
  LogComponentEnable("3D-Torus", (LogLevel)(LOG_LEVEL_INFO | LOG_PREFIX_TIME));

  if (verbose) {
    LogComponentEnable(
        "PacketSink",
        (LogLevel)(LOG_LEVEL_INFO | LOG_PREFIX_NODE | LOG_PREFIX_TIME));
  }

  // =====================
  // ==                 ==
  // == Create topology ==
  // ==                 ==
  // =====================
  NS_LOG_INFO("Create topology.");
  CoordNodeMap coordNodeMap;
  CoordDeviceMap coordDeviceMap;
  CoordInterfaceMap coordInterfaceMap;

  // Iterates over each node, tracks them separately using their FQDNs.
  for (int x = 0; x < N; ++x) {
    for (int y = 0; y < N; ++y) {
      for (int z = 0; z < N; ++z) {
        Ptr<Node> new_node = CreateObject<Node>(0);
        coordNodeMap[{x, y, z}] = new_node;
      }
    }
  }
  // Iterates over each node again and connects it to neighbors.
  PointToPointHelper link;
  link.SetDeviceAttribute("DataRate", StringValue("400Gbps"));
  link.SetChannelAttribute("Delay", StringValue("1us"));
  for (int x = 0; x < N; ++x) {
    for (int y = 0; y < N; ++y) {
      for (int z = 0; z < N; ++z) {
        Ptr<Node> node = coordNodeMap[{x, y, z}];
        // Ports on x-axis are "toy1-x0-y1-z0-x-", "toy1-x0-y1-z0-x+". We only
        // connect to the plus direction to avoid double connection.
        Ptr<Node> x_peer = coordNodeMap[{wrapCoord(x + 1, N), y, z}];
        NetDeviceContainer x_link = link.Install(node, x_peer);
        Ptr<NetDevice> self_if_x = x_link.Get(0);
        Ptr<NetDevice> peer_if_x = x_link.Get(1);
        coordDeviceMap[{x, y, z, X_PLUS}] = self_if_x;
        coordDeviceMap[{wrapCoord(x + 1, N), y, z, X_MINUS}] = peer_if_x;
        // Ports on y-axis are "toy1-x0-y1-z0-y-", "toy1-x0-y1-z0-y+". We only
        // connect to the plus direction to avoid double connection.
        Ptr<Node> y_peer = coordNodeMap[{x, wrapCoord(y + 1, N), z}];
        NetDeviceContainer y_link = link.Install(node, y_peer);
        Ptr<NetDevice> self_if_y = y_link.Get(0);
        Ptr<NetDevice> peer_if_y = y_link.Get(1);
        coordDeviceMap[{x, y, z, Y_PLUS}] = self_if_y;
        coordDeviceMap[{x, wrapCoord(y + 1, N), z, Y_MINUS}] = peer_if_y;
        // Ports on z-axis are "toy1-x0-y1-z0-z-", "toy1-x0-y1-z0-z+". We only
        // connect to the plus direction to avoid double connection.
        Ptr<Node> z_peer = coordNodeMap[{x, y, wrapCoord(z + 1, N)}];
        NetDeviceContainer z_link = link.Install(node, z_peer);
        Ptr<NetDevice> self_if_z = z_link.Get(0);
        Ptr<NetDevice> peer_if_z = z_link.Get(1);
        coordDeviceMap[{x, y, z, Z_PLUS}] = self_if_z;
        coordDeviceMap[{x, y, wrapCoord(z + 1, N), Z_MINUS}] = peer_if_z;
      }
    }
  }

  // Whether to enable pcap trace on ports specified in `pcap_ifs`.
  if (tracing) {
    for (auto &[x, y, z, dir] : pcap_ifs) {
      std::string fqdn = buildFQDN(NET, x, y, z, dir, true);
      if (!coordDeviceMap.count({x, y, z, dir})) {
        NS_LOG_ERROR(fqdn << " not found!");
        continue;
      }
      link.EnablePcap(outPrefix + fqdn + ".pcap",
                      coordDeviceMap[{x, y, z, dir}], true, true);
    }
  }

  NS_LOG_INFO(coordNodeMap.size() << " nodes created in total.");

  // =======================
  // ==                   ==
  // == Configure routing ==
  // ==                   ==
  // =======================

  NS_LOG_INFO("Configure routing.");
  // Sets up the network stacks and routing.
  InternetStackHelper stack;
  stack.InstallAll();

  // Assigns IP addresses to each interface.
  Ipv4AddressHelper ipv4Addr;
  for (int x = 0; x < N; ++x) {
    for (int y = 0; y < N; ++y) {
      for (int z = 0; z < N; ++z) {
        // Interface to IP mapping: 1xx.1yy.1zz.{if}, where 1 means x-, 2 means
        // x+, 3 means y-, 4 means y+, 5 means z-, 6 means z+. This is assuming
        // N of each dimension is no greater than 99.
        for (auto direction : DIRECTION) {
          std::string addr = std::to_string(x + 100) + "." +
                             std::to_string(y + 100) + "." +
                             std::to_string(z + 100) + "." +
                             std::to_string(static_cast<int>(direction) + 1);
          ipv4Addr.SetBase(addr.c_str(), "255.255.255.255", addr.c_str());
          Ipv4InterfaceContainer interface = ipv4Addr.Assign(
              NetDeviceContainer(coordDeviceMap[{x, y, z, direction}]));
          coordInterfaceMap[{x, y, z, direction}] = interface.Get(0);
        }
      }
    }
  }

  // Builds routes for all nodes.
  Ipv4TorusRoutingHelper torusRoutingHelper;
  Ipv4StaticRoutingHelper staticRoutingHelper;
  for (const auto &[tup, node_ptr] : coordNodeMap) {
    wipeStaticRoutingTable(node_ptr, staticRoutingHelper);
    Ptr<Ipv4TorusRouting> torusRouting =
        torusRoutingHelper.GetTorusRouting(node_ptr->GetObject<Ipv4>());
    torusRouting->AddNetworkRouteTo(Ipv4Address("0.0.0.0"), Ipv4Mask("/0"), 1);
    /*
    uint32_t x = std::get<0>(tup);
    uint32_t y = std::get<1>(tup);
    uint32_t z = std::get<2>(tup);
    for (const auto &dir : DIRECTION) {
      uint32_t egress_id = coordDeviceMap[{x, y, z, dir}]->GetIfIndex() + 1;
      Ipv4Address addr =
          coordInterfaceMap[{x, y, z, dir}]
              .first->GetAddress(coordInterfaceMap[{x, y, z, dir}].second, 0)
              .GetLocal();
      std::cout << "Coordinates (" << x << ", " << y << ", " << z << ", "
                << dir2str(dir) << "), egress id: " << egress_id << ", addr "
                << addr << std::endl;
    }
    */
  }

  // Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  // ======================
  // ==                  ==
  // == Generate traffic ==
  // ==                  ==
  // ======================

  NS_LOG_INFO("Generate traffic.");

  // Load in the TM file.
  TrafficMatrix TM{{0, 0, 0, 1, 0, 0, 1024000, 0}};
  NS_LOG_INFO("Trace entries: " << TM.size());

  // Creates a packet sink on all nodes.
  uint16_t port = 50000;
  PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), port));
  ApplicationContainer sinkApps;
  for (const auto &[tup, node_ptr] : coordNodeMap) {
    sinkApps.Add(sinkHelper.Install(node_ptr));
  }
  sinkApps.Start(MilliSeconds(0));

  // Creates the BulkSend applications to send. Who sends to who, how much and
  // when to send is determined by the TM.
  ApplicationContainer clientApps;
  // If MPI is enabled, every process should write to its dedicated file.
  Ptr<OutputStreamWrapper> stream =
      Create<OutputStreamWrapper>(outPrefix + "fct.csv", std::ios::app);
  for (const TMRow &row : TM) {
    uint32_t src_x = std::get<0>(row);
    uint32_t src_y = std::get<1>(row);
    uint32_t src_z = std::get<2>(row);
    uint32_t dst_x = std::get<3>(row);
    uint32_t dst_y = std::get<4>(row);
    uint32_t dst_z = std::get<5>(row);
    uint64_t flow_size = std::get<6>(row);
    uint64_t start_time = std::get<7>(row);
    // Each node in a 3D torus has 6 interfaces, each with different IP
    // address. We only need to know the node to reach, specific interface does
    // not matter, hence we just always hardcode it to "x-".
    Ipv4Address dstAddr =
        coordInterfaceMap[{dst_x, dst_y, dst_z, X_MINUS}]
            .first
            ->GetAddress(
                coordInterfaceMap[{dst_x, dst_y, dst_z, X_MINUS}].second, 0)
            .GetLocal();
    BulkSendHelper clientHelper("ns3::TcpSocketFactory",
                                InetSocketAddress(dstAddr, port));
    // Set the amount of data to send in bytes.  Zero is unlimited.
    clientHelper.SetAttribute("MaxBytes", UintegerValue(flow_size));
    ApplicationContainer client =
        clientHelper.Install(coordNodeMap[{src_x, src_y, src_z}]);
    // Register callback to measure FCT, there is supposed to be only one app
    // in this container.
    client.Get(0)->TraceConnectWithoutContext(
        "Fct", MakeBoundCallback(&calcFCT, stream, filterFct));
    client.Start(NanoSeconds(start_time));
    clientApps.Add(client);
  }

  // Dumps the routing table of requested nodes for debugging.
  Ipv4StaticRoutingHelper routing;
  for (const auto &[x, y, z] : subscribed_routing_tables) {
    // The direction argument is always hardcoded to be x-, but it does not
    // matter as we only want to construct the node name.
    std::string fqdn = buildFQDN(NET, x, y, z, X_MINUS, false);
    routing.PrintRoutingTableAt(
        MilliSeconds(0), coordNodeMap[{x, y, z}],
        Create<OutputStreamWrapper>(outPrefix + fqdn + ".route",
                                    std::ios::out));
  }

  NS_LOG_INFO("Run simulation.");
  Simulator::Stop(MilliSeconds(10));
  Simulator::Run();
  NS_LOG_INFO("Simulation done.");

  /*
  // Dump estimate FCT if simulation terminates early.
  Ptr<OutputStreamWrapper> fct_stream = Create<OutputStreamWrapper>(
      outPrefix + "fctEstimate-proc" + std::to_string(systemId) + ".csv",
      std::ios::app);
  for (ApplicationContainer::Iterator i = clientApps.Begin();
       i != clientApps.End(); i++) {
    Ptr<BulkSendApplication> app = DynamicCast<BulkSendApplication>(*i);
    auto fct = app->GetFctEstimate();
    if (filterFct && fct <= 0) {
      continue;
    }
    NS_LOG_INFO("FCT estimate " << fct << " nsec.");
    *fct_stream->GetStream() << fct << std::endl;
  }
  */

  Simulator::Destroy();

  return 0;
}
