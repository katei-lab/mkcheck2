# rbs_inline: enabled

require 'json'
require 'net/http'
require 'uri'
require 'zip'

module BuildFuzz
  # Collects the build artifacts from GitHub Actions artifacts
  class Collector
    # @rbs @sys: System
    # @rbs @github: GitHub

    # @rbs sys: System
    # @rbs github: GitHub
    def initialize(sys, github)
      @sys = sys
      @github = github
    end

    # @rbs build_fuzz_rev: String
    # @rbs logger: Logger
    def download(build_fuzz_rev, logger)
      FileUtils.mkdir_p(@sys.output_dir)
      logger.info "Downloading artifacts info for build-fuzz@#{build_fuzz_rev}"
      runs = @github.list_runs('build.yaml', head_sha: build_fuzz_rev)
      logger.info "Found #{runs['total_count']} runs"

      works = runs['workflow_runs'].flat_map do |run|
        next [] unless run['status'] == 'completed'

        logger.info "Downloading artifacts for run #{run['id']}"
        artifacts = @github.list_artifacts(run['id'])
        artifacts['artifacts'].flat_map do |artifact|
          url = artifact['archive_download_url']
          th = Thread.new do
            zip_dest = File.join(@sys.output_dir, artifact['name'] + '.zip')
            logger.info "Downloading #{url} to #{zip_dest}"
            @github.download_artifact(url, dest: zip_dest)

            logger.info "Extracting #{zip_dest}"
            __skip__ = Zip::File.open(zip_dest) do |zip|
              zip.each do |entry|
                output_dir = @sys.output_dir
                dest = File.join(output_dir, entry.name)
                logger.info "Extracting #{entry.name} to #{dest}"
                FileUtils.mkdir_p(File.dirname(dest))
                if File.exist?(dest)
                  logger.warn "#{dest} already exists"
                  FileUtils.rm(dest)
                end
                entry.extract(dest)
              end
            end
          end
          th.abort_on_exception = true
          th
        end
      end

      # Wait for all threads
      works.each(&:join)
    end
  end

  class GitHub
    # @rbs @token: String
    # @rbs @repo: String

    # @rbs token: String
    # @rbs repo: String
    def initialize(token, repo)
      @token = token
      @repo = repo
    end

    # @rbs workflow: String -> Hash
    def list_runs(workflow, head_sha: nil)
      uri = URI("https://api.github.com/repos/#{@repo}/actions/workflows/#{workflow}/runs")
      uri.query = URI.encode_www_form(head_sha: head_sha) if head_sha

      __skip__ = req = Net::HTTP::Get.new(uri)
      req['Authorization'] = "token #{@token}"
      req['Accept'] = 'application/vnd.github.v3+json'

      __skip__ = res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
        http.request(req)
      end

      JSON.parse(res.body)
    end

    def list_artifacts(run_id)
      uri = URI("https://api.github.com/repos/#{@repo}/actions/runs/#{run_id}/artifacts")

      __skip__ = req = Net::HTTP::Get.new(uri)
      req['Authorization'] = "token #{@token}"
      req['Accept'] = 'application/vnd.github.v3+json'

      __skip__ = res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
        http.request(req)
      end

      JSON.parse(res.body)
    end

    # @rbs url: String
    # @rbs dest: String
    def download_artifact(url, dest:)
      # The request may be redirected
      redirect = 0
      last_res = nil
      uri = URI(url)
      __skip__ = req = Net::HTTP::Get.new(uri)
      req['Authorization'] = "token #{@token}"
      __skip__ = loop do
        __skip__ = res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
          http.request(req)
        end

        unless res.is_a?(Net::HTTPRedirection) && redirect < 10
          last_res = res
          break
        end

        uri = URI(res['location'])
        req = Net::HTTP::Get.new(uri)
        redirect += 1
      end

      raise "Failed to download #{url}: too many redirects" unless last_res
      raise "Failed to download #{url}: #{__skip__ = last_res.code}" unless last_res.is_a?(__skip__ = Net::HTTPSuccess)

      __skip__ = File.open(dest, 'wb') do |f|
        f.write(last_res.body)
      end
    end
  end
end

if $0 == __FILE__
  github = BuildFuzz::GitHub.new(ENV['GITHUB_TOKEN'] || raise('GITHUB_TOKEN is not set'), 'kateinoigakukun/build-fuzz')
  runs = github.list_runs('build.yaml')
  pp runs
end
