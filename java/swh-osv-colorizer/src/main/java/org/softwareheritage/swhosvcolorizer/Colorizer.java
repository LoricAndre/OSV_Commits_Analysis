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
    String introduced_sha = from_db.getString("start");
    String fixed_sha = from_db.getString("end");
    int length = SWHID.HASH_LENGTH;
    fixed_sha = String.format("%1$" + length + "s", fixed_sha)
                    .replace(' ', '0')
                    .replaceFirst(".*:", "");
    introduced_sha = String.format("%1$" + length + "s", introduced_sha)
                         .replace(' ', '0')
                         .replaceFirst(".*:", "");
    this.fixed = new SWHID(String.format("swh:1:rev:%s", fixed_sha));
    this.introduced = new SWHID(String.format("swh:1:rev:%s", introduced_sha));
    this.id = from_db.getString("id");
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

  HashMap<SWHID, HashSet<Integer>> computed = new HashMap<>();
  HashMap<SWHID, HashSet<Integer>> fixes = new HashMap<>();
  HashMap<SWHID, HashSet<Integer>> introductions = new HashMap<>();

  SWHID zero_id =
      new SWHID(String.format("swh:1:rev:%1$" + SWHID.HASH_LENGTH + "s", "")
                    .replace(' ', '0'));

  ArrayList<Vulnerability> vulnerabilities = new ArrayList<>();

  String toposort_path;
  String transposed_toposort_path;
  String graph_path;
  String db_url;

  public static void main(String[] args)
      throws IOException, ClassNotFoundException, FileNotFoundException,
             SQLException {
    String graph_path = args[0];
    String db_path = args[1];
    String toposort_path = args[2];
    String transposed_toposort_path = args[3];
    Colorizer c = new Colorizer(graph_path, db_path, toposort_path,
                                transposed_toposort_path);
    c.colorize();
  }

  public Colorizer(String graph_path, String db_path, String toposort_path,
                   String transposed_toposort_path)
      throws IOException, ClassNotFoundException, FileNotFoundException,
             SQLException {
    this.graph_path = graph_path;
    this.toposort_path = toposort_path;
    this.transposed_toposort_path = transposed_toposort_path;
    db_url = String.format("jdbc:sqlite:%s", db_path);
    loadGraph();
    buildVulnsAndFixes();
    buildIntroductions();
  }

  void colorize() throws FileNotFoundException, SQLException {
    TopoSort toposort = new TopoSort(toposort_path);
    Connection db = DriverManager.getConnection(db_url);
    String result_table = "colorized";
    // Create table
    String create_query =
        "CREATE TABLE IF NOT EXISTS " + result_table + "(sha, uid)";
    Statement stmt = db.createStatement();
    stmt.executeQuery(create_query);
    String insert_query =
        String.format("insert into %s values (?, ?)", result_table);
    PreparedStatement statement = db.prepareStatement(insert_query);
    long i = 0;
    System.out.println("Coloring the graph...");
    while (toposort.hasNext()) {
      SWHID swhid = toposort.next();
      long nodeId = graph.getNodeId(swhid);
      HashSet<Integer> introduced_here =
          introductions.getOrDefault(swhid, new HashSet<Integer>());
      HashSet<Integer> fixed_here =
          fixes.getOrDefault(swhid, new HashSet<Integer>());
      // Add introduced here
      HashSet<Integer> affecting_here = introduced_here;

      // Add parent vulns
      long successor = 0;
      for (LazyLongIterator successors = graph.successors(nodeId);
           successor != -1; successor = successors.nextLong()) {
        SWHID successor_swhid = graph.getSWHID(successor);
        affecting_here.addAll(computed.get(successor_swhid));
      }
      // Remove fixes
      affecting_here.removeAll(fixed_here);
      computed.put(swhid, affecting_here);
      for (Integer vuln_i : affecting_here) {
        statement.setString(1, vulnerabilities.get(vuln_i).getId());
        statement.setString(2, swhid.getSWHID());
        statement.addBatch();
      }
      statement.executeBatch();
      System.out.print("\r Node: " + (i++));
    }
  }

  void buildVulnsAndFixes() throws SQLException {
    System.out.println("Connecting to database at " + db_url + " ...");
    Connection db = DriverManager.getConnection(db_url);
    System.out.println("Connected.");
    System.out.println("Fetching vulnerabilities from database...");
    Statement stmt = db.createStatement();
    String vulns_query = "select start, end, id from OSV where type = 'GIT'";
    ResultSet raw_vulns = stmt.executeQuery(vulns_query);
    System.out.println("Done.");

    System.out.println("Storing vulnerabilities and fix commits...");
    while (raw_vulns.next()) {
      Vulnerability vuln = new Vulnerability(raw_vulns);
      Integer vuln_i = vulnerabilities.size();
      vulnerabilities.add(vuln);

      if (vuln.getFixed() != zero_id) {
        HashSet<Integer> affecting =
            fixes.getOrDefault(vuln.getFixed(), new HashSet<Integer>());
        affecting.add(vuln_i);
        fixes.put(vuln.getFixed(), affecting);
      }
    }
    db.close();
    System.out.println("Done.");
  }

  void buildIntroductions() throws FileNotFoundException {
    System.out.println("Computing introduction commits...");
    HashMap<Long, HashSet<Integer>> affecting = new HashMap<>();
    TopoSort toposort = new TopoSort(transposed_toposort_path);
    long i = 0;
    while (toposort.hasNext()) {
      SWHID swhid = toposort.next();
      long nodeId = graph.getNodeId(swhid);
      HashSet<Integer> affecting_here =
          affecting.getOrDefault(nodeId, new HashSet<Integer>());
      long predecessor = 0;
      for (LazyLongIterator predecessors = graph.predecessors(nodeId);
           predecessor != -1; predecessor = predecessors.nextLong()) {
        SWHID predecessor_swhid = graph.getSWHID(predecessor);
        if (predecessor_swhid.getType() != SwhType.REV) {
          continue;
        }
        for (Integer predecessor_vuln_i : affecting.get(predecessor)) {
          if (vulnerabilities.get(predecessor_vuln_i).getIntroduced() != predecessor_swhid) {
            affecting_here.add(predecessor_vuln_i);
          }
        }
      }

      long nbSuccessors = graph.outdegree(nodeId);
      if (nbSuccessors == 0) {
        HashSet<Integer> introduced_here =
            introductions.getOrDefault(swhid, new HashSet<Integer>());
        introduced_here.addAll(affecting_here);
        introductions.put(swhid, introduced_here);
      } else {
        affecting.put(nodeId, affecting_here);
      }
      System.out.print("\r Node: " + (i++));
    }
    System.out.println("Done.");
  }

  void loadGraph() throws IOException {
    System.out.println("Loading graph " + graph_path + " ...");
    SwhBidirectionalGraph loaded = SwhBidirectionalGraph.loadMapped(graph_path);
    graph = new Subgraph(loaded, new AllowedNodes("rev"));
    System.out.println("Graph loaded.");
  }
}
