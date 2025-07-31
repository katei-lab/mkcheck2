# rbs_inline: enabled
module BuildFuzz
  RevisionRange = Struct.new(:start, :end)

  class RevisionRange
    def to_s = "#{self.start}..#{self.end}"
  end

  # Verifier for a revision history.
  #
  # This verifier checks if the given revision history contains any changes
  # that introduce potential build issues.
  # It builds the project for each revision and compares the dependency graph
  # between the revisions. If a revision cannot be built, it is skipped and
  # its parent revision is compared with the next revision.
  #
  # # Assumptions
  # - The project must have a sequential history of revisions without merge commits.
  class HistoryVerifier
    # @rbs @project: Project
    # @rbs @graph_builder: GraphBuilder
    # @rbs @sys: System
    # @rbs @diags: DiagnosticEngine

    # @rbs project: Project
    # @rbs graph_builder: GraphBuilder
    # @rbs sys: System
    # @rbs diags: DiagnosticEngine
    def initialize(project, graph_builder, sys, diags)
      @project = project
      @graph_builder = graph_builder
      @sys = sys
      @diags = diags
    end

    # Verify the given revision history.
    #
    # @rbs start_rev: String
    # @rbs end_rev: String
    def verify_between(start_rev, end_rev)
      git = Git.new(@sys.bare_repo_path(@project.name))
      @project.checkout(start_rev, @sys)

      revisions_to_check = git.revisions_between(start_rev, end_rev)
      if revisions_to_check.empty?
        puts "No revisions to check"
        exit 0
      end

      @sys.logger.info "Start checking revisions", project: @project.name, start_rev: start_rev, end_rev: end_rev, number_of_revisions: revisions_to_check.size

      begin
        self.check(start_rev, revisions_to_check)
      ensure
        @diags.report_summary()
      end
    end

    # @rbs revisions_to_check: Array[String] -- list of revisions to check (not including start_rev)
    def check(start_rev, revisions_to_check)
      project, sys, diags = @project, @sys, @diags
      base_rev = start_rev
      # @type var base_graph: Graph
      # @type var base_plan: _BuildPlan
      base_graph, base_plan = nil, nil
      @sys.span("Building initial graph", project: project.name, revision: start_rev) do
        @sys.logger(self).info("Building initial graph", project: project.name, revision: start_rev)
        base_graph, base_plan = @graph_builder.build(project, sys, start_rev)
      end

      revisions_to_check.each do |revision|
        @sys.span("Checking revision", project: project.name, revision: revision) do
          @sys.span("Cleaning build directory") do
            # Before starting the new revision, clean the previous build
            # directory to avoid any leftover files. Note that this has
            # to be done after building the graph and edge verification
            # because they both depend on the build directory state.
            base_plan.clean(sys)
          end

          # Build the actual dependency graph for the revision
          @sys.logger(self).info("Building graph", project: project.name, revision: revision)
          # @type var graph: Graph
          # @type var plan: _BuildPlan
          graph, plan = nil, nil
          @sys.span("Building graph") do
            begin
              graph, plan = @graph_builder.build(project, sys, revision)
            rescue => e
              @sys.logger.warn(self, "Failed to build revision", project: project.name, revision: revision, error: e)
              next
            end
          end
          @sys.logger(self).info("Built graph", project: project.name, revision: revision)
          changes = graph.changes(base_graph)

          rev_range = RevisionRange.new(base_rev, revision)

          # Update the base graph and plan for the next iteration
          base_graph = graph
          base_rev = revision
          base_plan = plan

          # Skip if no changes
          if changes.empty?
            @sys.logger(self).info("No changes found", project: project.name, revision: rev_range.to_h)
            next
          end

          @sys.span("Verifying changes", revision: rev_range.to_h) do
            # Check each change by touching files and rebuilding
            changes.each do |change|
              verifier = EdgeVerifier.new(sys, project)
              ok = verifier.verify_change(plan, change)
              unless ok
                diags.report_missing_dependency(project, rev_range, change)
              end
            end

            diags.report_revision_summary(project, rev_range)
          end
        end
      end
    end
  end

  class GraphBuilder
    # @rbs project: Project
    # @rbs sys: System
    # @rbs rev: String
    # @rbs return: [Graph, _BuildPlan]
    def build(project, sys, rev)
      plan = project.plan_build(rev, sys)
      trace_path = sys.artifact_path(project.name, rev)
      plan.clean(sys)
      plan.configure(sys)
      ino_to_ignore = plan.build(sys, Mkcheck2Tracer.new(trace_path))
      _, _, _, graph = BuildFuzz.parse_graph(trace_path, ino_to_ignore)
      [graph, plan]
    end
  end

  # Verifier for every edge in the graph.
  class EveryEdgeVerifier
    # @rbs @sys: System
    # @rbs @project: Project
    # @rbs @graph: Graph

    # @rbs sys: System
    # @rbs project: Project
    # @rbs graph: Graph
    def initialize(sys, project, graph)
      @sys = sys
      @project = project
      @graph = graph
    end

    # Verify the whole graph.
    #
    # @rbs plan: _BuildPlan
    def verify(plan)
      leaf_nodes = @graph.rev_nodes.filter_map {
        _1 if _2.edges.empty? && plan.should_verify(_1)
      }
      leaf_nodes.each_with_index do |input, i|
        @sys.span("Verifying an input", input: input, index: i, total: leaf_nodes.size) do
          @sys.logger(self).info("Verifying input [#{i + 1}/#{leaf_nodes.size}]", input: input, project: @project.name, total: leaf_nodes.size, index: i)
          expected_outputs = @graph.find_deps(input)
          expected_outputs_to_a = expected_outputs.to_a
          t0 = self.read_mtimes(expected_outputs)

          @sys.logger(self).info("Touching", file: input)
          FileUtils.touch input
          @sys.logger(self).info("Incremental build", expected_outputs: expected_outputs_to_a)
          begin
            plan.build(@sys, NoopTracer.new, log: false)
          rescue => e
            @sys.logger(self).warn(
              "Failed to build after touching", error: e, input: input,
              expected_outputs: expected_outputs_to_a, project: @project.name)
            next
          end

          t1 = self.read_mtimes(expected_outputs)
          modified_files = self.find_modified_files(t0, t1)

          # Check if the output files were updated.
          unless modified_files == expected_outputs
            redundant = @graph.prune_transitive(modified_files - expected_outputs)
            redundant.to_a.sort.each do |file|
              DiagnosticEngine.log_redundant_dependency(@sys, @project, file, input)
            end

            missing = @graph.prune_transitive(expected_outputs - modified_files)
            missing.to_a.sort.each do |file|
              DiagnosticEngine.log_missing_dependency(@sys, @project, file, input)
            end
          end
        end
      end
    end

    # @rbs files: Set[String]
    # @rbs return: Array[[String, Time]]
    private def read_mtimes(files)
      files.map { |file| [file, File.mtime(file)] }
    end

    # @rbs before_mtimes: Array[[String, Time]]
    # @rbs after_mtimes: Array[[String, Time]]
    # @rbs return: Set[String]
    private def find_modified_files(before_mtimes, after_mtimes)
      # @type var modified: Set[String]
      modified = Set.new
      before_mtimes.each_with_index do |(file, before_mtime), i|
        after_mtime = after_mtimes[i][1]
        modified.add(file) if before_mtime < after_mtime
      end
      modified
    end
  end

  # Verifier for an edge change between two traces.
  class EdgeVerifier
    # @rbs @sys: System
    # @rbs @project: Project

    # @rbs sys: System
    # @rbs project: Project
    def initialize(sys, project)
      @sys = sys
      @project = project
    end

    # @rbs plan: _BuildPlan
    # @rbs change: Graph::Change
    # @rbs return: bool
    def verify_change(plan, change)
      return true unless change.type == :add
      verify(plan, change.output, change.depends_on)
    end

    # Verify the edge change.
    # Precndition: The given build plan has already been built.
    #
    # @rbs plan: _BuildPlan
    # @rbs output: String
    # @rbs depends_on: String
    # @rbs return: bool
    def verify(plan, output, depends_on)
      @sys.span("Verifying an edge", output: output, depends_on: depends_on) do
        unless [output, depends_on].all? { plan.should_verify(_1) }
          @sys.logger(self).debug("Skipping edge verification", output: output, depends_on: depends_on, project: @project.name)
          return true
        end
        @sys.logger(self).info("Verifying edge", output: output, depends_on: depends_on, project: @project.name)
        before_mtime = File.mtime(output)
        @sys.logger(self).info("Touching", file: depends_on)
        FileUtils.touch depends_on
        @sys.logger(self).info("Incremental build", output: output)
        begin
          plan.build(@sys, NoopTracer.new, log: false)
        rescue => e
          @sys.logger(self).warn("Failed to build after touching", error: e, output: output, depends_on: depends_on, project: @project.name)
          return false
        end
        after_mtime = File.mtime(output)

        # Check if the output file was updated.
        ok = before_mtime < after_mtime
        unless ok
          @sys.logger(self).info("Output file #{output} was not updated", output: output, depends_on: depends_on, project: @project.name)
        end
        ok
      end
    end
  end
end
