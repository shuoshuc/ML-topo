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
#include "ns3/flow-monitor-helper.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/ipv4-static-routing-helper.h"
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

using namespace ns3;
// Maps from a tuple-format coordinate <x, y, z> to a NodeContainer with 1 node.
// e.g., <0, 1, 0>: {node}
using CoordNodeMap =
    std::map<std::tuple<uint32_t, uint32_t, uint32_t>, NodeContainer>;
// Maps from a tuple-format coordinate <x, y, z> to a NetDeviceContainer with 6
// devices. e.g., <0, 1, 0>: {'x+': {dev1}, 'x-': {dev2}, ...}
using CoordDeviceMap = std::map<std::tuple<uint32_t, uint32_t, uint32_t>,
                                std::map<std::string, NetDeviceContainer>>;
// Maps from a tuple-format coordinate <x, y, z> (with up/down facing) to an
// Ipv4InterfaceContainer filled with interfaces.
// e.g., 'tor-up': {if1, if2, ...}
using CoordInterfaceMap =
    std::map<std::tuple<uint32_t, uint32_t, uint32_t>,
             std::map<std::string, Ipv4InterfaceContainer>>;

NS_LOG_COMPONENT_DEFINE("3D-Torus");

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
  Ptr<Ipv4StaticRouting> staticRouting =
      ipv4RoutingHelper.GetStaticRouting(node->GetObject<Ipv4>());
  while (staticRouting->GetNRoutes()) {
    staticRouting->RemoveRoute(0);
  }
}

// Installs default route and localhost route on the specified node. The node
// must have at least one egress port. Aggregation block does not have to
// install default route.
void installLocalAndDefaultRoute(
    Ptr<Node> node, const Ipv4StaticRoutingHelper &ipv4RoutingHelper,
    bool defaultRoute = true) {
  Ptr<Ipv4StaticRouting> staticRouting =
      ipv4RoutingHelper.GetStaticRouting(node->GetObject<Ipv4>());
  if (defaultRoute) {
    staticRouting->AddNetworkRouteTo(Ipv4Address("0.0.0.0"), Ipv4Mask("/0"), 1);
  }
  staticRouting->AddNetworkRouteTo(Ipv4Address("127.0.0.0"), Ipv4Mask("/8"), 0);
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
  int N = 2;
  // For 3D Torus, the degree of each node is 6.
  int DEGREE = 6;
  // The FQDNs of devices which should enable pcap trace on.
  std::set<std::string> pcap_fqdn{
      //"toy1-x0-y1-z0-y+",
      //"toy1-x1-y1-z1-x-",
  };
  // A vector of node names where the routing table of each should be dumped.
  std::vector<std::string> subscribed_routing_tables{};

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
  GlobalValue::Bind("SimulatorImplementationType",
                    StringValue("ns3::DistributedSimulatorImpl"));
  // Overrides default TCP MSS from 536B to 1448B to match Ethernet.
  Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1448));
  Config::SetDefault("ns3::Ipv4StaticRouting::FlowEcmpRouting",
                     BooleanValue(flowEcmp));
  Config::SetDefault("ns3::Ipv4StaticRouting::UseWcmp", BooleanValue(useWcmp));
  Config::SetDefault("ns3::Ipv4StaticRouting::FlowletLB",
                     BooleanValue(flowlet));
  Config::SetDefault("ns3::Ipv4StaticRouting::FlowletTimeout",
                     TimeValue(MicroSeconds(500)));
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
  std::map<std::string, Ptr<Node>> globalNodeMap;
  std::map<std::string, Ptr<NetDevice>> globalDeviceMap;
  std::map<std::string, std::pair<Ptr<Ipv4>, uint32_t>> globalInterfaceMap;
  // This map maintains the AggrBlock port peering information. For each bi-di
  // link, the records exist in the map, e.g.,
  // f2-c1-ab1-p1: f2-c2-ab1-p1
  // f2-c2-ab1-p1: f2-c1-ab1-p1
  std::map<std::string, std::string> globalPeerMap;
  // Maintains the inter-cluster links between any given pair of aggregation
  // blocks, links are bi-di, so stored twice in both directions, e.g.,
  // <f2-c1-ab1, f2-c2-ab1>: {<f2-c1-ab1-p1, f2-c2-ab1-p1>}
  // <f2-c2-ab1, f2-c1-ab1>: {<f2-c2-ab1-p1, f2-c1-ab1-p1>}
  std::map<std::pair<std::string, std::string>, std::vector<Link>>
      globalDcnLinkMap;
  // All the nodes grouped by clusters.
  std::vector<StageNodeMap> cluster_nodes(NUM_CLUSTER);
  // All the devices grouped by clusters.
  std::vector<StageDeviceMap> cluster_devices(NUM_CLUSTER);
  // All the interfaces grouped by clusters.
  std::vector<StageInterfaceMap> cluster_ifs(NUM_CLUSTER);
  // The available DCN port index grouped by clusters.
  std::vector<std::queue<int>> cluster_dcn_ports(NUM_CLUSTER);

  // Iterates over each cluster, adds aggregation block and ToR nodes and tracks
  // them separately using their FQDNs.
  for (int i = 0; i < NUM_CLUSTER; ++i) {
    // Creates aggregation block. Assuming only 1 AggrBlock in each cluster.
    std::string aggr_name = NET + "-c" + std::to_string(i + 1) + "-ab1";
    // Node is created with system id = cluster id.
    Ptr<Node> aggr = CreateObject<Node>(useMpi ? i : 0);
    cluster_nodes[i]["aggr"].Add(aggr);
    globalNodeMap[aggr_name] = aggr;
    for (int p = 1; p <= NUM_AGGR_PORTS; p += 2) {
      cluster_dcn_ports[i].push(p);
    }

    // Creates ToR switches and connects them to AggrBlock.
    // Intra-cluster links all have the same speed and latency.
    PointToPointHelper intraClusterLink;
    int gen_id = getClusterGenByIndex(i + 1, GEN_VEC);
    // Invalid generation id, abort.
    if (gen_id < 0) {
      NS_LOG_ERROR("Invalid cluster index. Gen id " << gen_id);
      return -1;
    }
    intraClusterLink.SetDeviceAttribute(
        "DataRate", StringValue(std::to_string(SPEED_MAP[gen_id] *
                                               NUM_AGGR_PORTS / 2 / NUM_TOR) +
                                "Gbps"));
    intraClusterLink.SetChannelAttribute("Delay", StringValue("20us"));
    for (int idx = 0; idx < NUM_TOR; ++idx) {
      std::string tor_name =
          NET + "-c" + std::to_string(i + 1) + "-t" + std::to_string(idx + 1);
      // Node is created with system id = cluster id.
      Ptr<Node> tor = CreateObject<Node>(useMpi ? i : 0);
      cluster_nodes[i]["tor"].Add(tor);
      globalNodeMap[tor_name] = tor;
      // Establishes AggrBlock-ToR connectivity.
      NetDeviceContainer link = intraClusterLink.Install(tor, aggr);
      Ptr<NetDevice> tor_port = link.Get(0);
      Ptr<NetDevice> aggr_port = link.Get(1);
      std::string tor_dev_name = tor_name + "-p1";
      std::string aggr_dev_name =
          aggr_name + "-p" + std::to_string((idx + 1) * 2);
      cluster_devices[i]["tor-up"].Add(tor_port);
      cluster_devices[i]["aggr-down"].Add(aggr_port);
      globalDeviceMap[tor_dev_name] = tor_port;
      globalDeviceMap[aggr_dev_name] = aggr_port;
      globalPeerMap[tor_dev_name] = aggr_dev_name;
      globalPeerMap[aggr_dev_name] = tor_dev_name;
    }

    // Whether to enable pcap trace on ports specified in `pcap_intra_fqdn`.
    if (tracing && (!useMpi || systemId == i) && pcap_intra_fqdn.count(i + 1)) {
      for (auto &&fqdn : pcap_intra_fqdn[i + 1]) {
        if (!globalDeviceMap.count(fqdn)) {
          NS_LOG_ERROR(fqdn << " not found in globalDeviceMap!");
          continue;
        }
        intraClusterLink.EnablePcap(outPrefix + fqdn + ".pcap",
                                    globalDeviceMap[fqdn], true, true);
      }
    }
  }

  // Now that all clusters are constructed, inter-connects them as a full mesh.
  for (int i = 0; i < NUM_CLUSTER; ++i) {
    std::string aggr_name = NET + "-c" + std::to_string(i + 1) + "-ab1";
    Ptr<Node> aggr_sw = globalNodeMap[aggr_name];
    for (int j = i + 1; j < NUM_CLUSTER; ++j) {
      std::string peer_aggr_name = NET + "-c" + std::to_string(j + 1) + "-ab1";
      Ptr<Node> peer_aggr_sw = globalNodeMap[peer_aggr_name];

      // Inter-cluster links may not have the same speed, actual speed is
      // determined by auto-negotiation.
      PointToPointHelper interClusterLink;
      // Performs speed auto negotiation.
      int self_gen_id = getClusterGenByIndex(i + 1, GEN_VEC);
      int peer_gen_id = getClusterGenByIndex(j + 1, GEN_VEC);
      // Invalid generation id, abort.
      if (self_gen_id < 0 || peer_gen_id < 0) {
        NS_LOG_ERROR("Invalid cluster index. Self gen id "
                     << self_gen_id << ", peer gen id " << peer_gen_id);
        return -1;
      }
      interClusterLink.SetDeviceAttribute(
          "DataRate",
          StringValue(std::to_string(std::min(SPEED_MAP[self_gen_id],
                                              SPEED_MAP[peer_gen_id])) +
                      "Gbps"));
      interClusterLink.SetChannelAttribute("Delay", StringValue("20us"));

      NetDeviceContainer link = interClusterLink.Install(aggr_sw, peer_aggr_sw);
      Ptr<NetDevice> self_port = link.Get(0);
      Ptr<NetDevice> peer_port = link.Get(1);
      std::string self_port_name =
          aggr_name + "-p" + std::to_string(cluster_dcn_ports[i].front());
      cluster_dcn_ports[i].pop();
      std::string peer_port_name =
          peer_aggr_name + "-p" + std::to_string(cluster_dcn_ports[j].front());
      cluster_dcn_ports[j].pop();
      cluster_devices[i]["aggr-up"].Add(self_port);
      cluster_devices[j]["aggr-up"].Add(peer_port);
      globalDeviceMap[self_port_name] = self_port;
      globalDeviceMap[peer_port_name] = peer_port;
      globalPeerMap[self_port_name] = peer_port_name;
      globalPeerMap[peer_port_name] = self_port_name;
      globalDcnLinkMap[std::make_pair(aggr_name, peer_aggr_name)].push_back(
          std::make_pair(self_port_name, peer_port_name));
      globalDcnLinkMap[std::make_pair(peer_aggr_name, aggr_name)].push_back(
          std::make_pair(peer_port_name, self_port_name));

      // Whether to enable pcap trace on ports specified in `pcap_inter_fqdn`.
      if (tracing && (!useMpi || systemId == i)) {
        if (pcap_inter_fqdn.count(i + 1) &&
            pcap_inter_fqdn[i + 1].count(self_port_name)) {
          interClusterLink.EnablePcap(outPrefix + self_port_name + ".pcap",
                                      self_port, true, true);
        }
        if (pcap_inter_fqdn.count(j + 1) &&
            pcap_inter_fqdn[j + 1].count(peer_port_name)) {
          interClusterLink.EnablePcap(outPrefix + peer_port_name + ".pcap",
                                      peer_port, true, true);
        }
      }
    }
  }
  NS_LOG_INFO(globalNodeMap.size() << " nodes created in total.");

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
  for (int i = 0; i < NUM_CLUSTER; ++i) {
    // Intra-cluster interfaces are assigned base address 10.{cluster id}.1.0
    Ipv4AddressHelper intraClusterAddress;
    std::string intraBaseIP = "10." + std::to_string(i + 1) + ".1.0";
    // ToR up-facing interfaces are assigned address 10.{cluster id}.1.{tor id}
    intraClusterAddress.SetBase(intraBaseIP.c_str(), "255.255.255.0");
    Ipv4InterfaceContainer torUpIfs =
        intraClusterAddress.Assign(cluster_devices[i]["tor-up"]);
    cluster_ifs[i]["tor-up"].Add(torUpIfs);
    // AggrBlock down-facing interfaces are assigned address
    // 10.{cluster id}.1.{100 + tor id}
    intraClusterAddress.SetBase(intraBaseIP.c_str(), "255.255.255.0",
                                "0.0.0.101");
    Ipv4InterfaceContainer aggrDownIfs =
        intraClusterAddress.Assign(cluster_devices[i]["aggr-down"]);
    cluster_ifs[i]["aggr-down"].Add(aggrDownIfs);
    // Establishes global interface map.
    for (int idx = 0; idx < NUM_TOR; ++idx) {
      std::string tor_if_name = NET + "-c" + std::to_string(i + 1) + "-t" +
                                std::to_string(idx + 1) + "-p1";
      std::string aggr_if_name = NET + "-c" + std::to_string(i + 1) + "-ab1-p" +
                                 std::to_string((idx + 1) * 2);
      globalInterfaceMap[tor_if_name] = torUpIfs.Get(idx);
      globalInterfaceMap[aggr_if_name] = aggrDownIfs.Get(idx);
    }
    // Inter-cluster interfaces are assigned IP address:
    // 10.100.{cluster id}.{port id / 2 + 1}
    Ipv4AddressHelper dcnAddress;
    std::string startIP = "0.0." + std::to_string(i + 1) + ".1";
    dcnAddress.SetBase("10.100.0.0", "255.255.0.0", startIP.c_str());
    Ipv4InterfaceContainer dcnIfs =
        dcnAddress.Assign(cluster_devices[i]["aggr-up"]);
    cluster_ifs[i]["aggr-up"].Add(dcnIfs);
    // Establishes global interface map.
    for (int p = 0; p < NUM_AGGR_PORTS / 2; ++p) {
      std::string dcn_if_name = NET + "-c" + std::to_string(i + 1) + "-ab1-p" +
                                std::to_string(p * 2 + 1);
      globalInterfaceMap[dcn_if_name] = dcnIfs.Get(p);
    }
  }

  // Builds static host routes for all nodes.
  Ipv4StaticRoutingHelper ipv4RoutingHelper;
  for (int i = 0; i < NUM_CLUSTER; ++i) {
    Ptr<Node> aggr = cluster_nodes[i]["aggr"].Get(0);
    wipeStaticRoutingTable(aggr, ipv4RoutingHelper);
    installLocalAndDefaultRoute(aggr, ipv4RoutingHelper, false);
    // Builds intra-cluster routing, including routes on ToRs and host routes on
    // aggregation block.
    NodeContainer &tors = cluster_nodes[i]["tor"];
    for (uint32_t j = 0; j < tors.GetN(); ++j) {
      wipeStaticRoutingTable(tors.Get(j), ipv4RoutingHelper);
      installLocalAndDefaultRoute(tors.Get(j), ipv4RoutingHelper);
      // Finds the peer port of each ToR, this is the egress to reach that ToR.
      // Adds host routes on the aggregation block accordingly.
      std::string tor_egress_port = NET + "-c" + std::to_string(i + 1) + "-t" +
                                    std::to_string(j + 1) + "-p1";
      uint32_t aggr_if_id =
          globalDeviceMap[globalPeerMap[tor_egress_port]]->GetIfIndex() + 1;
      Ipv4Address torAddr =
          globalInterfaceMap[tor_egress_port]
              .first->GetAddress(globalInterfaceMap[tor_egress_port].second, 0)
              .GetLocal();
      Ptr<Ipv4StaticRouting> staticRouting =
          ipv4RoutingHelper.GetStaticRouting(aggr->GetObject<Ipv4>());
      // Host routes are always /32.
      staticRouting->AddNetworkRouteTo(torAddr, Ipv4Mask("/32"), aggr_if_id);
    }
  }

  // This part builds the inter-cluster TE implementation based on pre-reduced
  // group weights.
  TEImpl te = readTEImpl(teInput, NUM_TOR, NUM_AGGR_PORTS);
  for (const auto &te_row : te) {
    uint32_t group_type = std::get<0>(te_row);
    std::string src = std::get<1>(te_row);
    std::string dst = std::get<2>(te_row);
    Ipv4Address dst_prefix = std::get<3>(te_row);
    std::vector<int> group = std::get<4>(te_row);
    // Looks up the DCN egress port that directly connects the src and dst. If
    // there are more than 1 direct connects, simply use the first one. This
    // default egress port should really be a last resort in case the
    // installed group does not work.
    std::vector<Link> links = globalDcnLinkMap[std::make_pair(src, dst)];
    uint32_t direct_if_id = globalDeviceMap[links[0].first]->GetIfIndex() + 1;

    Ptr<Node> node = globalNodeMap[src];
    Ptr<Ipv4StaticRouting> staticRouting =
        ipv4RoutingHelper.GetStaticRouting(node->GetObject<Ipv4>());
    staticRouting->AddNetworkRouteTo(dst_prefix, Ipv4Mask("/24"), direct_if_id,
                                     group_type, group);
  }

  // Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  // ======================
  // ==                  ==
  // == Generate traffic ==
  // ==                  ==
  // ======================

  NS_LOG_INFO("Generate traffic.");

  // Load in the TM file.
  TrafficMatrix TM = readTM(trafficInput);
  NS_LOG_INFO("Trace entries: " << TM.size());

  // Creates a packet sink on all ToRs.
  uint16_t port = 50000;
  PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), port));
  ApplicationContainer sinkApps;
  for (int i = 0; i < NUM_CLUSTER; ++i) {
    // If MPI is enabled, only installs sink in the cluster with a matching
    // systemId.
    if (!useMpi || systemId == i) {
      sinkApps.Add(sinkHelper.Install(cluster_nodes[i]["tor"]));
    }
  }
  sinkApps.Start(MilliSeconds(0));

  // Creates the BulkSend applications to send. Who sends to who, how much and
  // when to send is determined by the rows in TM.
  ApplicationContainer clientApps;
  // If MPI is enabled, every process should write to its dedicated file.
  Ptr<OutputStreamWrapper> stream = Create<OutputStreamWrapper>(
      outPrefix + "fct-proc" + std::to_string(systemId) + ".csv",
      std::ios::app);
  for (const TMRow &row : TM) {
    std::string src = std::get<0>(row);
    int sidx = std::get<1>(row);
    std::string dst = std::get<2>(row);
    // int didx = std::get<3>(row);
    uint64_t flow_size = std::get<4>(row);
    uint64_t start_time = std::get<5>(row);
    // If MPI is enabled, only sets up senders in the cluster with a matching
    // systemId.
    if (useMpi && (systemId != sidx - 1)) {
      continue;
    }
    Ipv4Address dstAddr =
        globalInterfaceMap[dst + "-p1"]
            .first->GetAddress(globalInterfaceMap[dst + "-p1"].second, 0)
            .GetLocal();
    BulkSendHelper clientHelper("ns3::TcpSocketFactory",
                                InetSocketAddress(dstAddr, port));
    // Set the amount of data to send in bytes.  Zero is unlimited.
    clientHelper.SetAttribute("MaxBytes", UintegerValue(flow_size));
    ApplicationContainer client = clientHelper.Install(globalNodeMap[src]);
    // Register callback to measure FCT, there is supposed to be only one app
    // in this container.
    client.Get(0)->TraceConnectWithoutContext(
        "Fct", MakeBoundCallback(&calcFCT, stream, filterFct));
    client.Start(NanoSeconds(start_time));
    clientApps.Add(client);
  }

  // Flow monitor. Only install FlowMonitor if verbose is true.
  Ptr<FlowMonitor> flowMonitor;
  FlowMonitorHelper flowHelper;
  if (verbose) {
    flowMonitor = flowHelper.InstallAll();
  }

  // Dumps the routing table of requested nodes for debugging. In a distributed
  // (MPI) use case, only the process responsible for the node gets to dump the
  // routing table. This avoids file access contention.
  Ipv4GlobalRoutingHelper gRouting;
  for (const auto &node : subscribed_routing_tables) {
    if (useMpi && ((int)globalNodeMap[node]->GetSystemId() != systemId)) {
      continue;
    }
    gRouting.PrintRoutingTableAt(
        MilliSeconds(0), globalNodeMap[node],
        Create<OutputStreamWrapper>(outPrefix + node + ".route",
                                    std::ios::out));
  }

  NS_LOG_INFO("Run simulation.");
  Simulator::Stop(MilliSeconds(10));
  Simulator::Run();
  NS_LOG_INFO("Simulation done.");

  // Dump flowlet table usage.
  if (flowlet) {
    // If MPI is enabled, every process should write to its dedicated file.
    Ptr<OutputStreamWrapper> fstream = Create<OutputStreamWrapper>(
        outPrefix + "flowlet-proc" + std::to_string(systemId) + ".csv",
        std::ios::app);
    for (const auto &[name, node] : globalNodeMap) {
      Ptr<Ipv4StaticRouting> staticRouting =
          ipv4RoutingHelper.GetStaticRouting(node->GetObject<Ipv4>());
      *fstream->GetStream()
          << name << "," << staticRouting->GetFlowletTableSize() << std::endl;
    }
  }

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

  // Dump flow stats.
  if (verbose) {
    flowMonitor->SerializeToXmlFile(outPrefix + "3D-Torus.xml", true, true);
  }
  Simulator::Destroy();

  // Exit the MPI execution environment
  MpiInterface::Disable();
  return 0;
}
