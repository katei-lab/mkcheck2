# rbs_inline: enabled

module BuildFuzz
  class BuildCommand
    # @rbs args: Array[String]
    def self.run(args)
      sys_options = SystemOptions.new
      build_options = BuildOptions.new
      project_options = ProjectOptions.new
      OptionParser.new do |opts|
        opts.banner = "Usage: #{$0} build [options]"
  
        sys_options.add_options(opts)
        build_options.add_options(opts)
        project_options.add_options(opts)

      end.parse!(args)
  
      sys = sys_options.sys
      project = project_options.project()

      trace_path = sys.artifact_path(project.name, build_options.revision)
      tracer = Mkcheck2Tracer.new(trace_path)

      plan = project.plan_build(build_options.revision, sys)
      plan.configure(sys)
      plan.build(sys, tracer)
    end
  end
end
