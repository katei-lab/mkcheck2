# rbs_inline: enabled
module BuildFuzz
  class CheckTraceCommand
    def self.run(args)
      sys_options = SystemOptions.new
      build_options = BuildOptions.new
      project_options = ProjectOptions.new
      OptionParser.new do |opts|
        opts.banner = "Usage: #{$0} check-trace <before.trace> <after.trace> [options]"

        sys_options.add_options(opts)
        project_options.add_options(opts)
        build_options.add_options(opts)
      end.parse!(args)

      sys = sys_options.sys
      project = project_options.project()
      plan = project.plan_build(build_options.revision, sys)
      plan.build(sys, NoopTracer.new)

      before_trace_path, after_trace_path = args
      if !before_trace_path || !after_trace_path
        $stderr.puts "Missing <before.trace> or <after.trace>"
        exit 1
      end

      _, _, _, before_graph = BuildFuzz.parse_graph(before_trace_path)
      _, _, _, after_graph = BuildFuzz.parse_graph(after_trace_path)
      changes = after_graph.changes(before_graph)

      if changes.empty?
        puts "No changes found in the traced dependency graph"
        exit 0
      end

      begin
        diags = DiagnosticEngine.new($stderr)
        changes.each do |change|
          verifier = EdgeVerifier.new(sys, change, project, build_options.revision)
          ok = verifier.verify(plan)
          unless ok
            diags.report_missing_dependency(project, build_options.revision, change)
          end
        end
      ensure
        diags.report_summary()
      end
    end
  end
end
