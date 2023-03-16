package org.softwareheritage.swhosvcolorizer;

import it.unimi.dsi.big.webgraph.LazyLongIterator;
import java.io.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;
import org.softwareheritage.graph.*;

class Vulnerability {
  SWHID introduced;
  SWHID fixed;
  String id;

  public SWHID getIntroduced() { return introduced; }

  public void setIntroduced(SWHID introduced) { this.introduced = introduced; }

  public SWHID getFixed() { return fixed; }

  public void setFixed(SWHID fixed) { this.fixed = fixed; }

  public String getId() { return id; }

  public void setId(String id) { this.id = id; }

  public Vulnerability(ResultSet from_db) throws SQLException {
    this.fixed =
        new SWHID(String.format("swh:1:rev:%s", from_db.getString("end")));
    this.introduced =
        new SWHID(String.format("swh:1:rev:%s", from_db.getString("start")));
    this.id = from_db.getString("uid");
  }
}

class TopoSort {
  File source;
  Scanner scanner;

  public TopoSort(String path) throws FileNotFoundException {
    source = new File(path);
    scanner = new Scanner(source);
  }

  public boolean hasNext() { return scanner.hasNextLine(); }

  public SWHID next() { return new SWHID(scanner.nextLine()); }

  @Override
  protected void finalize() {
    scanner.close();
  }
}

public class Colorizer {
  Subgraph graph;

  HashMap<SWHID, HashSet<Vulnerability>> computed =
      new HashMap<>();
  HashMap<SWHID, HashSet<Vulnerability>> fixes =
      new HashMap<SWHID, HashSet<Vulnerability>>();
  HashMap<SWHID, HashSet<Vulnerability>> introductions =
      new HashMap<SWHID, HashSet<Vulnerability>>();

  SWHID zero_id = new SWHID("swh:1:rev:0");

  HashSet<Vulnerability> vulns;

  String toposort_path;
  String transposed_toposort_path;
  String graph_path;
  String db_url;

  public Colorizer(String[] args) throws IOException, ClassNotFoundException,
                                         FileNotFoundException, SQLException {
    graph_path = args[0];
    String db_path = args[1];
    toposort_path = args[2];
    transposed_toposort_path = args[3];
    db_url = String.format("jdbc:sqlite:%s", db_path);
    loadGraph();
    buildVulnsAndFixes();
    buildIntroductions();
    colorize();
  }

  void colorize() throws FileNotFoundException, SQLException {
    TopoSort toposort = new TopoSort(toposort_path);
    Connection db = DriverManager.getConnection(db_url);
    String result_table = "colorized";
    // Create table
    String create_query = "CREATE TABLE IF NOT EXISTS " + result_table
            + "(sha, uid)";
    Statement stmt = db.createStatement();
    stmt.executeQuery(create_query);
    String insert_query = String.format("insert into %s values (?, ?)", result_table);
    PreparedStatement statement = db.prepareStatement(insert_query);
    while (toposort.hasNext()) {
      SWHID swhid = toposort.next();
      long nodeId = graph.getNodeId(swhid);
      HashSet<Vulnerability> introduced_here =
          introductions.getOrDefault(swhid, new HashSet<Vulnerability>());
      HashSet<Vulnerability> fixed_here = fixes.getOrDefault(swhid, new HashSet<Vulnerability>());
      // Add introduced here
      HashSet<Vulnerability> affecting_here = introduced_here;

      // Add parent vulns
      long successor = 0;
      for (LazyLongIterator successors = graph.successors(nodeId);
           successor != -1; successor = successors.nextLong()) {
        SWHID successor_swhid = graph.getSWHID(successor);
        affecting_here.addAll(computed.get(successor));
      }
      // Remove fixes
      affecting_here.removeAll(fixed_here);
      computed.put(swhid, affecting_here);
      for (Vulnerability vuln: affecting_here) {
        statement.setString(1, vuln.getId());
        statement.setString(2, swhid.getSWHID());
        statement.addBatch();
      }
      statement.executeBatch();
    }
  }

  void buildVulnsAndFixes() throws SQLException {
    Connection db = DriverManager.getConnection(db_url);
    Statement stmt = db.createStatement();
    String vulns_query = "select start, end, id from OSV where type = 'GIT'";
    ResultSet raw_vulns = stmt.executeQuery(vulns_query);

    while (raw_vulns.next()) {
      Vulnerability vuln = new Vulnerability(raw_vulns);
      vulns.add(vuln);

      if (vuln.getFixed() != zero_id) {
        HashSet<Vulnerability> affecting =
            fixes.getOrDefault(vuln.getFixed(), new HashSet<Vulnerability>());
        affecting.add(vuln);
        fixes.put(vuln.getFixed(), affecting);
      }
    }
    db.close();
  }

  void buildIntroductions() throws FileNotFoundException {
    HashMap<Long, HashSet<Vulnerability>> affecting = new HashMap<>();
    TopoSort toposort = new TopoSort(transposed_toposort_path);
    while (toposort.hasNext()) {
      SWHID swhid = toposort.next();
      long nodeId = graph.getNodeId(swhid);
      long predecessor = 0;
      HashSet<Vulnerability> affecting_here =
          affecting.getOrDefault(nodeId, new HashSet<Vulnerability>());
      for (LazyLongIterator predecessors = graph.predecessors(nodeId);
           predecessor != -1; predecessor = predecessors.nextLong()) {
        SWHID predecessor_swhid = graph.getSWHID(predecessor);
        for (Vulnerability predecessor_vuln : affecting.get(predecessor)) {
          if (predecessor_vuln.getIntroduced() != predecessor_swhid) {
            affecting_here.add(predecessor_vuln);
          }
        }
      }

      long nbAncestors = graph.indegree(nodeId);
      if (nbAncestors == 0) {
        HashSet<Vulnerability> introduced_here = introductions.getOrDefault(swhid, new HashSet<Vulnerability>());
        introduced_here.addAll(affecting_here);
        introductions.put(swhid, introduced_here);
      } else {
        affecting.put(nodeId, affecting_here);
      }
    }
  }

  void loadGraph() throws IOException {
    System.err.println("loading graph " + graph_path + " ...");
    SwhBidirectionalGraph loaded = SwhBidirectionalGraph.loadMapped(graph_path);
    graph = new Subgraph(loaded, new AllowedNodes("rev"));
  }
}
