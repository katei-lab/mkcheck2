# rbs_inline: enabled
module BuildFuzz
  class DiagnosticEngine
    # @rbs @io: IO
    # @rbs @sys: System
    # @rbs @missing_dependencies: Hash[Project, Hash[RevisionRange, [Graph::Change]]]

    # Initialize the diagnostic engine.
    # @rbs io: IO
    # @rbs sys: System
    def initialize(io, sys)
      @io = io
      @sys = sys
      @missing_dependencies = {}
    end

    class << self
      # Log a missing dependency.
      #
      # @rbs sys: System
      # @rbs project: Project
      # @rbs output: String
      # @rbs depends_on: String
      # @rbs kwargs: Hash[Symbol, Object] -- Additional tags to log
      def log_missing_dependency(sys, project, output, depends_on, **kwargs)
        sys.logger(self).info("Missing dependency", project: project.name, output: output, depends_on: depends_on, **kwargs)
      end

      # Log a redundant dependency.
      #
      # @rbs sys: System
      # @rbs project: Project
      # @rbs output: String
      # @rbs depends_on: String
      # @rbs kwargs: Hash[Symbol, Object] -- Additional tags to log
      def log_redundant_dependency(sys, project, output, depends_on, **kwargs)
        sys.logger(self).info("Redundant dependency", project: project.name, output: output, depends_on: depends_on, **kwargs)
      end
    end

    # Report a missing dependency.
    #
    # @rbs project: Project
    # @rbs revision: RevisionRange
    # @rbs change: Graph::Change
    def report_missing_dependency(project, revision, change)
      @missing_dependencies[project] ||= {}
      __skip__ = @missing_dependencies[project][revision] ||= []
      @missing_dependencies[project][revision] << change

      DiagnosticEngine.log_missing_dependency(@sys, project, change.output, change.depends_on, revision: revision.to_h)
    end

    # Report a summary of the diagnostic results in textual form.
    def report_summary
      @io.puts "============ Summary ============"
      if @missing_dependencies.empty?
        @io.puts "No missing dependencies found"
        return
      end
      @missing_dependencies.each do |project, revisions|
        @io.puts "Project #{project.name}:"
        if revisions.empty?
          @io.puts "  No missing dependencies found"
          next
        end
        revisions.each do |revision, changes|
          @io.puts "  Revision #{revision}:"
          changes.each do |change|
            @io.puts "    #{change.output} actually depends on #{change.depends_on}"
          end
        end
      end
    end

    # Report a summary of the diagnostic results for a specific project revision.
    # @rbs project: Project
    # @rbs revision: RevisionRange
    # @rbs io: IO
    def report_revision_summary(project, revision)
      @io.puts "============ Project #{project.name}@#{revision} ============"
      if @missing_dependencies.key?(project) && @missing_dependencies[project].key?(revision)
        @missing_dependencies[project][revision].each do |change|
          @io.puts "  #{change.output} actually depends on #{change.depends_on}"
        end
      else
        @io.puts "No missing dependencies found"
      end
    end
  end
end
