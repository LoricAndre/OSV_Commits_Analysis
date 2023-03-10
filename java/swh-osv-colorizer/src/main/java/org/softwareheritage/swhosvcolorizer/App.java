package org.softwareheritage.swhosvcolorizer;

import java.io.IOException;
import java.util.*;
import org.softwareheritage.graph.utils.TopoSort;

public class App {
  public static void main(String[] args) throws IOException, ClassNotFoundException {
    TopoSort toposort = new TopoSort();
    toposort.loadGraph(args[0], "rel,rev,root");
    toposort.setDfs(true);
    toposort.setEndIndex(0);
    toposort.toposort();
  }
}
