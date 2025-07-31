# rbs_inline: enabled

require 'json'
require 'set'

module BuildFuzz
  # Graph describing dependencies between file paths.
  class Graph
    class Node
      attr_reader :path #: String
      attr_reader :edges #: Set[String]

      # @rbs path: String
      # @rbs @edges: Set[String]

      # @rbs path: String
      def initialize(path)
        @path = path
        @edges = Set.new
      end
    end

    attr_reader :nodes #: Hash[String, Node]
    attr_reader :rev_nodes #: Hash[String, Node]
    # @rbs @nodes: Hash[String, Node]
    # @rbs @rev_nodes: Hash[String, Node]

    def initialize
      @nodes = {}
      @rev_nodes = {}
    end

    # Iterate over all edges in the graph.
    # Yields the output and its dependency.
    #
    # @rbs &: (String, String) -> void
    def edges
      @nodes.each do |k, v|
        node_edges = v.edges.sort
        node_edges.each do |edge|
          yield edge, k
        end
      end
    end

    # @rbs src: String
    # @rbs dst: String
    def add_dependency(src, dst)
      @nodes[src] ||= Node.new(src)
      @rev_nodes[src] ||= Node.new(src)
      @nodes[dst] ||= Node.new(dst)
      @rev_nodes[dst] ||= Node.new(dst)
      @nodes[src].edges.add(dst)
      @rev_nodes[dst].edges.add(src)
    end

    # Find all recursive dependants of a node.
    # Returns a set of paths that depend on the given path.
    #
    # @rbs src: String
    # @rbs return: Set[String]
    def find_deps(src)
      # @type var deps: Set[String]
      deps = Set.new
      # @type var traverse: ^(String) -> void
      traverse = lambda do |name|
        if @nodes.key?(name)
          @nodes[name].edges.each do |edge|
            next if deps.include?(edge)
            deps.add(edge)
            traverse.call(edge)
          end
        end
      end
      traverse.call(src)
      deps
    end

    def find_rev_deps(src)
      deps = {}
      traverse = lambda do |name, parent, depth|
        return if parent.key?(name) || depth > 3
        parent[name] = {}
        if @rev_nodes.key?(name)
          @rev_nodes[name].edges.each { |edge| traverse.call(edge, parent[name], depth + 1) }
        end
      end
      traverse.call(src, deps, 0)
      deps
    end

    def is_direct?(src, dst)
      @nodes[src].edges.include?(dst)
    end

    def has_node?(node)
      @nodes.key?(node)
    end

    # @rbs nodes: Set[String]
    # @rbs return: Set[String]
    def prune_transitive(nodes)
      non_transitive = nodes
      nodes.each do |node|
        next unless non_transitive.include?(node)
        non_transitive -= find_deps(node) - [node]
      end
      non_transitive
    end

    def topo_order
      topo = []
      visited = Set.new
      topo_dfs = lambda do |node|
        return if visited.include?(node)
        visited.add(node)
        @nodes[node].edges.each { |next_node| topo_dfs.call(next_node) }
        topo << node
      end
      @nodes.keys.each { |node| topo_dfs.call(node) }
      topo.reverse
    end

    class Change
      attr_reader :type #: :add | :remove
      attr_reader :output #: String
      attr_reader :depends_on #: String

      # @rbs type: :add | :remove
      # @rbs output: String
      # @rbs depends_on: String
      def initialize(type:, output:, depends_on:)
        @type = type
        @output = output
        @depends_on = depends_on
      end

      def ==(other)
        @type == other.type && @output == other.output && @depends_on == other.depends_on
      end

      def inspect
        "Change(#{@type}, #{@output}, #{@depends_on})"
      end

      def to_h
        { type: @type, output: @output, depends_on: @depends_on }
      end
    end

    # Compute the difference between the current graph and the previous graph.
    #
    # The difference is defined as the set of changes in the edges.
    # If a node is present in the current graph but not in the previous graph,
    # it is considered as an addition. If a node is present in the previous graph
    # but not in the current graph, it is considered as a removal.
    #
    # @rbs previous: Graph -- the previous graph to compare against
    # @rbs return: Array[Change]
    def changes(previous)
      changes = [] #: Array[Change]
      @nodes.each do |node, data|
        node_added = !previous.has_node?(node)
        data.edges.each do |edge|
          if node_added or !previous.is_direct?(node, edge)
            changes << Change.new(type: :add, output: edge, depends_on: node)
          end
        end
      end
      previous.nodes.each do |node, data|
        node_removed = !self.has_node?(node)
        data.edges.each do |edge|
          if node_removed or !self.is_direct?(node, edge)
            changes << Change.new(type: :remove, output: edge, depends_on: node)
          end
        end
      end
      changes
    end
  end

  # @rbs path: String
  # @rbs ino_to_ignore: Set[Integer]
  # @rbs return [Set[String], Set[String], Hash[String, Set[[String, String]]], Graph]
  def self.parse_graph(path, ino_to_ignore = Set.new)
    files = {} #: Hash[String, untyped]
    inputs = Set.new #: Set[String]
    outputs = Set.new #: Set[String]
    built_by = {} #: Hash[String, Set[[String, String]]]

    data = JSON.parse(File.read(path))
    data['files'].each { |file| files[file['id']] = file }
    data['procs'].each do |proc|
      proc_in = proc['input'] || []
      proc_out = proc['output'] || []
      inputs.merge(proc_in)
      outputs.merge(proc_out)
      image = File.basename(files[proc['image']]['name'] || raise("image not found"))
      proc_out.each do |output|
        output_name = files[output]['name'] || raise("output not found")
        built_by[output_name] ||= Set.new
        built_by[output_name].add([image, proc['uid']])
      end
    end

    persisted = lambda do |uid|
      file = files[uid]
      next false if file['deleted'] || !file['exists']
      name = file['name'] || raise("file #{uid} has no name")
      next false if name.start_with?('/dev', '/proc')
      File.exist?(name) && !File.directory?(name)
    end

    inputs = inputs.select { |uid| persisted.call(uid) }.map { |uid| files[uid]['name'] }.to_set
    outputs = outputs.select { |uid| persisted.call(uid) }.map { |uid| files[uid]['name'] }.to_set

    gid = {}
    data['procs'].sort_by { |p| p['uid'] }.each do |proc|
      uid = proc['uid']
      gid[uid] = if proc['cow'] && gid.key?(proc['parent'])
                   gid[proc['parent']]
                 else
                   uid
                 end
    end

    # @type var groups: Hash[String, [Set[String], Set[String]]]
    groups = Hash.new { |hash, key| hash[key] = [Set.new, Set.new] }
    data['procs'].each do |proc|
      group_id = gid[proc['uid']]
      groups[group_id][0].merge(proc['input'] || [])
      groups[group_id][1].merge(proc['output'] || [])
    end

    # @type var edges: Hash[String, Array[String]]
    edges = Hash.new { |hash, key| hash[key] = [] }
    files.each do |uid, file|
      file['deps']&.each { |dep| edges[files[dep]['name']] << files[uid]['name'] }
    end

    # @type var should_ignore: ^(String) -> bool
    should_ignore = lambda do |name|
      next true if ['/dev/stderr', '/dev/stdout'].include?(name)
      next true if File.directory?(name)
      next true if name.end_with?('/[eventfd]')
      if name.start_with?('/inode:')
        ino = name.split(':')[1].to_i
        next ino_to_ignore.include?(ino)
      end
      false
    end
    groups.each_value do |ins, outs|
      ins.each do |input|
        next if should_ignore.call(files[input]['name'])
        outs.each do |output|
          next if should_ignore.call(files[output]['name'])
          edges[files[input]['name']] << files[output]['name']
        end
      end
    end

    nodes = inputs | outputs

    graph = Graph.new
    nodes.each do |src|
      # @type var visited: Set[String]
      visited = Set.new
      # @type var add_edges: ^(String) -> void
      add_edges = lambda do |to|
        next if visited.include?(to)
        visited.add(to)
        edges[to]&.each do |node|
          if nodes.include?(node)
            graph.add_dependency(src, node) unless src == node
          else
            add_edges.call(node)
          end
        end
      end
      add_edges.call(src)
    end

    [inputs, outputs, built_by, graph]
  end
end
