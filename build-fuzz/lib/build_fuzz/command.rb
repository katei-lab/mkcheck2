# rbs_inline: enabled

module BuildFuzz
  class SystemOptions
    DEFAULT_SYSTEM_OPTIONS = {
      verbose: true,
      cache_dir: nil,
      output_dir: nil,
      build_dir: '.build',
      ddtrace: ENV['BUILD_FUZZ_LOCAL'].nil?
    }.freeze

    # @rbs @options: system_options

    def initialize
      @options = DEFAULT_SYSTEM_OPTIONS.dup
      @options[:build_dir] = File.expand_path(@options[:build_dir])
    end

    # @rbs opts: OptionParser
    def add_options(opts)
      opts.on("--[no-]verbose", "Run verbosely") do |v|
        @options[:verbose] = v
      end

      opts.on("--cache-dir DIR", "Directory to store caches") do |dir|
        @options[:cache_dir] = dir
      end

      opts.on("-o", "--output-dir DIR", "Directory to store output") do |dir|
        @options[:output_dir] = dir
      end
    end

    def sys
      System.new(@options)
    end
  end

  class ProjectOptions
    # @rbs @project_name: String | nil

    def initialize
      @project_name = nil
    end

    def add_options(opts)
      opts.on("--project NAME", "Project name to build") do |project|
        @project_name = project
      end
    end

    # @rbs return: Project
    def project
      project = @project_name
      project_path = "projects/#{project}/project.yaml"
      if !File.exist?(project_path) or !project
        if !project
          $stderr.puts "--project <name> is required"
        else
          $stderr.puts "Project not found: #{project} (missing #{project_path})"
        end
        available_projects = Dir.glob('projects/*').map { |path| File.basename(path) }
        $stderr.puts "Available projects: #{available_projects.join(', ')}"
        exit 1
      end
      Project.from(project_path)
    end
  end

  class BuildOptions
    # @rbs @revision: String | nil

    def initialize
      @revision = nil
    end

    def add_options(opts)
      opts.on("--revision REV", "Git revision to build") do |revision|
        @revision = revision
      end
    end

    # @rbs return: String
    def revision
      @revision || raise("--revision <rev> is required")
    end
  end
end
